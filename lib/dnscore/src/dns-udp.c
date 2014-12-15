/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
* The YADIFA TM software product is provided under the BSD 3-clause license:
* 
* Redistribution and use in source and binary forms, with or without 
* modification, are permitted provided that the following conditions
* are met:
*
*        * Redistributions of source code must retain the above copyright 
*          notice, this list of conditions and the following disclaimer.
*        * Redistributions in binary form must reproduce the above copyright 
*          notice, this list of conditions and the following disclaimer in the 
*          documentation and/or other materials provided with the distribution.
*        * Neither the name of EURid nor the names of its contributors may be 
*          used to endorse or promote products derived from this software 
*          without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
*------------------------------------------------------------------------------
*
*/

//#include <pthread.h>

#include "dnscore-config.h"

#include <netinet/in.h>
#include <signal.h>

#include "dnscore/dns_resource_record.h"
#include "dnscore/thread_pool.h"
#include "dnscore/random.h"
#include "dnscore/message.h"
#include "dnscore/tcp_io_stream.h"
#include "dnscore/treeset.h"
#include "dnscore/pool.h"
#include "dnscore/service.h"
#include "dnscore/async.h"
#include "dnscore/mutex.h"
#include "dnscore/list-dl.h"
#include "dnscore/dns-udp.h"
#include "dnscore/fdtools.h"

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#define HAS_TC_FALLBACK_TO_TCP_SUPPORT 1

#define DNS_UDP_SIMPLE_QUERY 0

#define DNS_UDP_SIMPLE_MESSAGE_FLAG_NONE   0
#define DNS_UDP_SIMPLE_MESSAGE_FLAG_DNSSEC 1

#define DNS_SIMPLE_MESSAGE_RETRIES_DEFAULT 2 // 3 tries total

#define DNSSMAND_TAG 0x444e414d53534e44
#define DNSSMESG_TAG 0x4753454d53534e44

const u8 V4_WRAPPED_IN_V6[12] = {0,0,0,0,0,0,0,0,0,0,255,255};

static struct service_s dns_udp_send_handler = UNINITIALIZED_SERVICE;
static struct service_s dns_udp_receive_handler = UNINITIALIZED_SERVICE;
static struct service_s dns_udp_timeout_handler = UNINITIALIZED_SERVICE;

static async_queue_s dns_udp_send_handler_queue;

static bool dns_udp_handler_initialized = FALSE;

//static smp_int domain_test_count = SMP_INT_INITIALIZER;

static int dns_udp_send_service(struct service_worker_s *worker);
static int dns_udp_receive_service(struct service_worker_s *worker);
static int dns_udp_timeout_service(struct service_worker_s *worker);

static int *dns_udp_socket = NULL;
static list_dl_s *volatile dns_udp_high_priority = NULL;
static u32 dns_udp_socket_count = 0;

static pool_s dns_simple_message_pool;
static pool_s message_data_pool;
static pool_s dns_simple_message_async_node_pool;

static mutex_t sendto_statistics_mtx = MUTEX_INITIALIZER;
static mutex_t recvfrom_statistics_mtx = MUTEX_INITIALIZER;
static volatile u32 sendto_epoch = 0;
static volatile u32 sendto_total = 0;
static volatile u32 sendto_packets = 0;
static volatile u32 sendto_packets_aggregated = 0;
static volatile u32 recvfrom_epoch = 0;
static volatile u32 recvfrom_total = 0;
static volatile u32 recvfrom_packets = 0;

#if HAS_TC_FALLBACK_TO_TCP_SUPPORT
static struct thread_pool_s *tcp_query_thread_pool = NULL;
#endif

/*
 * accurate rate measurement tool
 */

#define RATE_WINDOW_SLOT_TIME 500000

struct rate_s
{
    mutex_t mtx;
    volatile u64 basetime;
    volatile u64 bytes_sent_window[2];
    volatile u64 rate_max;
    volatile u32 slot;
};

typedef struct rate_s rate_s;

void
rate_init(rate_s *r, u64 rate_max)
{
    ZEROMEMORY(r, sizeof(rate_s));
    mutex_init(&r->mtx);
    r->basetime = timeus();
    r->rate_max = rate_max;
}

void
rate_finalise(rate_s *r)
{
    mutex_destroy(&r->mtx);
}

void
rate_wait(rate_s *r, u32 bytes_to_add)
{
    for(;;)
    {
        mutex_lock(&r->mtx);
        
        u64 now = timeus();
        
        // d is the time elapsed since last measurement in us
        
        u64 delta_time_us = (now - r->basetime) | 1; // avoid divide by zero without a compare/jump is more important that high accuracy
        
        // slot WILL be the index in the bytes sent window
        // but first look where we are, where we were and
        // what needs to be cleaned
        
        u64 slot = delta_time_us / RATE_WINDOW_SLOT_TIME;
        u64 dslot = slot - r->slot;
        
        switch(dslot)
        {
            case 0: // same slot
            {
                log_debug6("rate: SAME: base=%llu, delta=%llu, slot=%llu, waitfor=%u, rate_max=%llu", r->basetime, delta_time_us, slot&1, bytes_to_add, r->rate_max);
                break;                
            }
            case 1: // slot moved
            {
                r->basetime = now - RATE_WINDOW_SLOT_TIME;
                log_debug6("rate: NEXT: base=%llu, delta=%llu, slot=%llu, waitfor=%u, rate_max=%llu", r->basetime, delta_time_us, slot&1, bytes_to_add, r->rate_max);
                r->bytes_sent_window[slot&1] = 0;
                break;
            }
            default: // both slots are too old
            {
                log_debug6("rate: BOTH: base=%llu, delta=%llu, slot=%llu, waitfor=%u, rate_max=%llu", r->basetime, delta_time_us, slot&1, bytes_to_add, r->rate_max);
                
                r->basetime = now;
                r->bytes_sent_window[0] = 0;
                r->bytes_sent_window[1] = 0;
                break;
            }
        }
        
        r->slot = slot;
        slot &= 1;
        
        // sum the windows to get the current bytes per second 
        
        u64 bytes_sent = r->bytes_sent_window[0] + r->bytes_sent_window[1];
        
        u64 new_total = bytes_sent + bytes_to_add;
        u64 new_rate = (1000000 * new_total) / delta_time_us;

        if(new_rate < r->rate_max)
        {
            r->bytes_sent_window[slot] += bytes_to_add;
            
            mutex_unlock(&r->mtx);
            
            log_debug6("rate: SENT: base=%llu, delta=%llu, slot=%llu, byte_sent=%llu, waitfor=%u, new_rate=%llu, rate_max=%llu", r->basetime, delta_time_us, slot&1, bytes_sent, bytes_to_add, new_rate, r->rate_max);
            
            break;
        }
        else
        {
            mutex_unlock(&r->mtx);
            
            log_debug6("rate: WAIT: base=%llu, delta=%llu, slot=%llu, byte_sent=%llu, waitfor=%u, new_rate=%llu, rate_max=%llu",
                    r->basetime, delta_time_us, slot&1,
                    bytes_sent, bytes_to_add, new_rate, r->rate_max);
            
            // it is possible to compute an accurate sleep time
            // right now I just do a 1ms pause (interruptable)
            usleep(1000);
        }
    }
}

static int dns_udp_send_simple_message_node_compare(const void *key_a, const void *key_b);

static treeset_tree message_collection = { NULL, dns_udp_send_simple_message_node_compare};
static mutex_t message_collection_mtx;
static rate_s dns_udp_send_rate;

static const dns_udp_settings_s default_dns_udp_settings =
{
    DNS_UDP_TIMEOUT_US,
    DNS_UDP_SEND_RATE,
    DNS_UDP_SEND_QUEUE,
    DNS_UDP_PORT_COUNT,
    DNS_UDP_RETRY_COUNT
};

static const dns_udp_settings_s *dns_udp_settings = &default_dns_udp_settings;

static void *
dns_simple_message_async_node_pool_alloc(void *_ignored_)
{
    dns_simple_message_async_node_s *sma;
    
    (void)_ignored_;
    
    MALLOC_OR_DIE(dns_simple_message_async_node_s*, sma, sizeof(dns_simple_message_async_node_s), DNSSMAND_TAG); // POOL
    ZEROMEMORY(sma, sizeof(dns_simple_message_async_node_s));
    return sma;
}

static void
dns_simple_message_async_node_pool_free(void *sma, void *_ignored_)
{
    (void)_ignored_;
    memset(sma, 0xd0, sizeof(dns_simple_message_async_node_s));
    free(sma); // POOL
}


static void *
dns_simple_message_pool_alloc(void *_ignored_)
{
    dns_simple_message_s *m;
    
    (void)_ignored_;
    
    MALLOC_OR_DIE(dns_simple_message_s*, m, sizeof(dns_simple_message_s), DNSSMESG_TAG); // POOL
    ZEROMEMORY(m, sizeof(dns_simple_message_s));
    
    return m;
}

static void
dns_simple_message_pool_free(void *p, void *_ignored_)
{
    (void)_ignored_;
    memset(p, 0xd1, sizeof(dns_simple_message_s));
#ifdef DEBUG
    dns_simple_message_s *msg =  (dns_simple_message_s*)p;
    msg->rc.value = 0;
#endif
    free(p); // POOL
}

static void *
message_data_pool_alloc(void *_ignored_)
{
    message_data *m;
    
    (void)_ignored_;
    
    MALLOC_OR_DIE(message_data*, m, sizeof(message_data), MESGDATA_TAG); // POOL
    ZEROMEMORY(m, sizeof(message_data));
    
    return m;
}

static void
message_data_pool_free(void *p, void *_ignored_)
{
    (void)_ignored_;
    
    memset(p, 0xd2, sizeof(message_data));
    free(p); // POOL
}


static void
dns_udp_handler_message_collection_free_node_callback(void *n)
{
    treeset_node *node = (treeset_node *)n;

    dns_simple_message_s *simple_message = (dns_simple_message_s*)node->key;
    dns_udp_simple_message_release(simple_message);
}

void dns_udp_handler_configure(const dns_udp_settings_s *settings)
{
    if(settings == NULL)
    {
        settings = &default_dns_udp_settings;
    }
    
    dns_udp_settings = settings;
}

int 
dns_udp_handler_init()
{
    int err = SUCCESS;

    if(!dns_udp_handler_initialized)
    {
        if(dns_udp_settings->port_count == 0)
        {
            return INVALID_ARGUMENT_ERROR; // invalid value
        }
        
        error_register(DNS_UDP_TIMEOUT, "query timed out");
        error_register(DNS_UDP_INTERNAL, "internal error");
        message_edns0_setmaxsize(4096);
        
        rate_init(&dns_udp_send_rate, dns_udp_settings->send_rate);   // bytes-per-second
        
        u32 worker_count = dns_udp_settings->port_count;
        
        // open "worker_count" udp sockets (V6)

        dns_udp_socket_count = worker_count;
        MALLOC_OR_DIE(int*, dns_udp_socket, sizeof(int) * dns_udp_socket_count, GENERIC_TAG); // DON'T POOL
        
        for(int i = 0; i < dns_udp_socket_count; i++) // dns_udp_socket_count is guaranteed > 0
        {
            int s;
            
            if( (s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)    
            {
                for(int j = 0; j < i; j++)
                {
                    if(dns_udp_socket[j] != ~0)
                    {
                        log_debug1("dns_udp_handler_init: closing socket %i", dns_udp_socket[j]);
                        close_ex(dns_udp_socket[j]);
                        dns_udp_socket[j] = ~0;
                    }
                }
                
                return ERRNO_ERROR;
            }
            
            //
            
            dns_udp_socket[i] = s;
            
            struct sockaddr_in6 sin6;
            ZEROMEMORY(&sin6, sizeof(sin6));
            sin6.sin6_family = AF_INET6;
            socklen_t sin6len = sizeof(sin6);

            if(bind(s, (struct sockaddr*)&sin6, sin6len) < 0)
            {
                err = ERRNO_ERROR;
                
                log_err("bind: %r", err);
                
                for(int j = 0; j < i; j++)
                {
                    if(dns_udp_socket[j] != ~0)
                    {
                        log_debug1("dns_udp_handler_init: closing socket %i", dns_udp_socket[j]);
                        close_ex(dns_udp_socket[j]);
                        dns_udp_socket[j] = ~0;
                    }
                }
                
                free(dns_udp_socket);
                dns_udp_socket = NULL;
                dns_udp_socket_count = 0;
                
                return err;
            }
        }
        // scan-build false positive: dns_udp_socket_count > 0
        MALLOC_OR_DIE(list_dl_s*, dns_udp_high_priority, sizeof(list_dl_s) * dns_udp_socket_count, GENERIC_TAG); // DON'T POOL, count ALWAYS > 0       
        for(int i = 0; i < dns_udp_socket_count; i++)
        {
            list_dl_init(&dns_udp_high_priority[i]);
        }
        
        // each couple of socket will be the responsibility of a writer
        
        if(ISOK(err = service_init_ex(&dns_udp_send_handler, dns_udp_send_service, "dns-udp-send", worker_count)))
        {
            async_queue_init(&dns_udp_send_handler_queue, dns_udp_settings->queue_size, 1, 100000, "dns-udp-send");
        
            if(ISOK(err = service_init_ex(&dns_udp_receive_handler, dns_udp_receive_service, "dns-udp-receive", worker_count)))
            {
                if(ISOK(err = service_init(&dns_udp_timeout_handler, dns_udp_timeout_service, "dns-udp-timeout")))
                {
#if HAS_TC_FALLBACK_TO_TCP_SUPPORT
                    if((tcp_query_thread_pool = thread_pool_init_ex(1, 0x4000, "dns-tcp-query")) != NULL)
                    {
#endif   
                        pool_init(&dns_simple_message_async_node_pool, dns_simple_message_async_node_pool_alloc, dns_simple_message_async_node_pool_free, NULL, "dns simple message answer");
                        pool_init(&dns_simple_message_pool, dns_simple_message_pool_alloc, dns_simple_message_pool_free, NULL, "dns simple message");
                        pool_init(&message_data_pool, message_data_pool_alloc, message_data_pool_free, NULL, "message data");
                    
#ifndef VALGRIND_FRIENDLY
                        pool_set_size(&dns_simple_message_async_node_pool, 0x10000);
                        pool_set_size(&dns_simple_message_pool, 0x10000);
                        pool_set_size(&message_data_pool, 0x2000);
                        
                        message_data_pool.hard_limit = TRUE;
#else
                        // for valgrind

                        pool_set_size(&dns_simple_message_async_node_pool, 0);
                        pool_set_size(&dns_simple_message_pool, 0);
                        pool_set_size(&message_data_pool, 0);
#endif
                        dns_udp_handler_initialized = TRUE;
                        
                        return SUCCESS;
#if HAS_TC_FALLBACK_TO_TCP_SUPPORT
                    }
                    else
                    {
                        service_finalize(&dns_udp_timeout_handler);
                        err = ERROR;
                    }
#endif
                }
                
                service_finalize(&dns_udp_receive_handler);
            }
            
            service_finalize(&dns_udp_send_handler);
        }
        
        for(int i = 0; i < dns_udp_socket_count; i++)
        {
            if(dns_udp_socket[i] != ~0)
            {
                log_debug1("dns_udp_handler_init: closing socket %i", dns_udp_socket[i]);
                close_ex(dns_udp_socket[i]);
                dns_udp_socket[i] = ~0;
            }
            //list_dl_s *list = &dns_udp_high_priority[i];
        }
        
        free(dns_udp_high_priority);
        dns_udp_high_priority = NULL;

        free(dns_udp_socket); // One array, don't pool

        dns_udp_socket = NULL;
        dns_udp_socket_count = 0;
    }

    return err;
}

int 
dns_udp_handler_start()
{
    int err = ERROR;

    if(dns_udp_handler_initialized)
    {
        if(ISOK(err = service_start(&dns_udp_send_handler)))
        {
            if(ISOK(err = service_start(&dns_udp_receive_handler)))
            {
                if(ISOK(err = service_start(&dns_udp_timeout_handler)))
                {
                    return err;
                }

                service_stop(&dns_udp_receive_handler);
                service_wait(&dns_udp_receive_handler);
            }
            
            service_stop(&dns_udp_send_handler);
            service_wait(&dns_udp_send_handler);
        }
    }
    
    return err;
}

int
dns_udp_handler_stop()
{
    int err = SUCCESS;
    int err0 = SUCCESS;
    int err1 = SUCCESS;
    int err2 = SUCCESS;
    int err3 = SUCCESS;
    int err4 = SUCCESS;
    
    if(!dns_udp_handler_initialized)
    {
        return SERVICE_NOT_INITIALISED;
    }
    
#if HAS_TC_FALLBACK_TO_TCP_SUPPORT
    if(tcp_query_thread_pool != NULL)
    {
        if(FAIL(err0 = thread_pool_destroy(tcp_query_thread_pool)))
        {
            log_err("failed to stop tcp_query_thread_pool: %r", err0);
            err = err0;
        }

        tcp_query_thread_pool = NULL;
    }
#endif
    
    if(!service_stopped(&dns_udp_send_handler))
    {
        if(FAIL(err1 = service_stop(&dns_udp_send_handler)))
        {
            log_err("failed to stop dns_udp_send_handler: %r", err1);
            err = err1;
        }
    }
    
    if(!service_stopped(&dns_udp_receive_handler))
    {
        if(FAIL(err2 = service_stop(&dns_udp_receive_handler)))
        {
            log_err("failed to stop dns_udp_receive_handler: %r", err2);
            err = err2;
        }
    }
    
    if(!service_stopped(&dns_udp_timeout_handler))
    {
        if(FAIL(err3 = service_stop(&dns_udp_timeout_handler)))
        {
            log_err("failed to stop dns_udp_timeout_handler: %r", err3);
            err = err3;
        }
    }
    
    log_debug("closing %i sockets", dns_udp_socket_count);
    
    for(int i = 0; i < dns_udp_socket_count; i++)
    {
        if(dns_udp_socket[i] != ~0)
        {
            log_debug1("dns_udp_handler_stop: closing socket %i", dns_udp_socket[i]);
            
            if(shutdown(dns_udp_socket[i], SHUT_RDWR) < 0)
            {
                err4 = ERRNO_ERROR;
                log_err("dns_udp_handler_stop: unable to shutdown socket %i: %r", dns_udp_socket[i], ERRNO_ERROR);
            }
            
            close_ex(dns_udp_socket[i]);
            dns_udp_socket[i] = ~0;
        }
    }
    
    log_debug("closed %i sockets", dns_udp_socket_count);
        
    // cleans-up whatever is waiting ...
    // but there is some issue here.  the program suck on the async_wait,
    // probably because the data was already freed (race?)
    
    if(dns_udp_high_priority != NULL)
    {
        for(int i = 0; i < dns_udp_socket_count; i++)
        {
            list_dl_s *list = &dns_udp_high_priority[i];
            async_wait_s *aw;
            while((aw = (async_wait_s*)list_dl_remove_first(list)) != NULL)
            {
                aw->error_code = ERROR;
                async_wait_progress(aw, 1);
            }
        }
    }
    
    if(ISOK(err1))
    {            
        service_wait(&dns_udp_send_handler);
    }
    
    if(ISOK(err2))
    {
        service_wait(&dns_udp_receive_handler);
    }
    
    if(ISOK(err3))
    {
        service_wait(&dns_udp_timeout_handler);
    }
    
    if(ISOK(err4))
    {
        dns_udp_socket_count = 0;
    }
        
    return err;
}

int
dns_udp_handler_finalize()
{    
    if(!dns_udp_handler_initialized)
    {
        return SUCCESS;
    }
    
    dns_udp_handler_stop();

    service_finalize(&dns_udp_send_handler);    
    service_finalize(&dns_udp_receive_handler);
    service_finalize(&dns_udp_timeout_handler);
    
    for(int i = 0; i < dns_udp_socket_count; i++)
    {
        if(dns_udp_socket[i] != ~0)
        {
            log_debug1("dns_udp_handler_finalize: closing socket %i", dns_udp_socket[i]);
            
            if(shutdown(dns_udp_socket[i], SHUT_RDWR) < 0)
            {
                log_debug1("dns_udp_handler_stop: unable to shutdown socket %i: %r", dns_udp_socket[i], ERRNO_ERROR);
            }
            
            close_ex(dns_udp_socket[i]);
            dns_udp_socket[i] = ~0;
        }
    }
    
    free(dns_udp_socket); // One array, don't pool
    
    dns_udp_socket = NULL;
    
    if(dns_udp_high_priority != NULL)
    {
        free(dns_udp_high_priority);
        dns_udp_high_priority = NULL;
    }
    
    dns_udp_socket_count = 0;
    
    async_queue_finalize(&dns_udp_send_handler_queue);
    
    treeset_avl_callback_and_destroy(&message_collection, dns_udp_handler_message_collection_free_node_callback);
    
    pool_finalize(&dns_simple_message_async_node_pool);
    pool_finalize(&dns_simple_message_pool);
    pool_finalize(&message_data_pool);
    
    rate_finalise(&dns_udp_send_rate);
    
    dns_udp_handler_initialized = FALSE;
    
    return SUCCESS;
}

static int
dns_udp_send_simple_message_node_compare(const void *key_a, const void *key_b)
{
    dns_simple_message_s *a = (dns_simple_message_s*)key_a;
    dns_simple_message_s *b = (dns_simple_message_s*)key_b;

    // test queried type
    
    int ka = a->qclass;
    ka <<= 16;
    ka |= a->qtype;
    
    
    int kb = b->qclass;
    kb <<= 16;
    kb |= b->qtype;
    
    if((ka -= kb) != 0)
    {
        return ka;
    }
    
    // test name server address
    
    if((ka = host_address_compare(a->name_server, b->name_server)) != 0)
    {
        return ka;
    }

    // test queried domain
    
    return dnsname_compare(a->fqdn, b->fqdn);
}


static message_data *
dns_udp_allocate_message_data(struct service_worker_s *worker)
{
    for(;;)
    {
        message_data *mesg = (message_data*)pool_alloc(&message_data_pool);

        if(mesg != NULL)
        {
            ZEROMEMORY(mesg, sizeof(message_data));
            
            return mesg;
        }

        if(!service_shouldrun(worker))
        {
            return NULL;
        }

        sleep(1);
    }
}

static void
dns_udp_simple_message_answer_call_handlers(dns_simple_message_s *simple_message)
{
    dns_simple_message_async_node_s *node = simple_message->async_node.next;
    while(node != NULL)
    {
        // the handler MUST release one reference so we increase it here
        dns_udp_simple_message_retain(simple_message);

        if((node->async != NULL) && (node->async->handler != NULL))
        {
            node->async->handler(node->async);
        }
        else
        {
            if(node->async != NULL)
            {
                log_err("receive: async=%p handler=%p", node->async, node->async->handler);
            }
            else
            {
                log_err("receive: async=%p handler=?", node->async);
            }
        }
        node = node->next;
    }

#ifdef DEBUG
    if(simple_message->rc.value > 1)
    {
        log_warn("receive: message RC is not 1 (%i)", simple_message->rc.value);
    }
#endif

    assert(simple_message->rc.value > 0);

    // there is no need to retain, the reference from the collection has not been decreased yet
    simple_message->async_node.async->handler(simple_message->async_node.async);
}

#if HAS_TC_FALLBACK_TO_TCP_SUPPORT

struct dns_udp_tcp_query_thread_params
{
    dns_simple_message_s *simple_message;
    struct service_worker_s *worker;
};

typedef struct dns_udp_tcp_query_thread_params dns_udp_tcp_query_thread_params;

int dns_udp_tcp_query_count = 0;
int dns_udp_tcp_query_failures = 0;

static void*
dns_udp_tcp_query_thread(void *args)
{
    dns_udp_tcp_query_thread_params *parms = (dns_udp_tcp_query_thread_params*)args;
    dns_simple_message_s *simple_message = (dns_simple_message_s *)parms->simple_message;
    struct service_worker_s *worker = (struct service_worker_s *)parms->worker;
    
    free(parms);
    
    ya_result ret;
        
    random_ctx rndctx = thread_pool_get_random_ctx();
    
    yassert(simple_message->answer == NULL);
    
    message_data *mesg = dns_udp_allocate_message_data(worker);
    
    dns_udp_tcp_query_count++;
        
    if(mesg != NULL)
    {
        simple_message->dns_id = (u16)random_next(rndctx);

        message_make_query_ex(mesg, simple_message->dns_id, simple_message->fqdn, simple_message->qtype, simple_message->qclass, simple_message->flags);

        if(simple_message->recurse)
        {
            MESSAGE_HIFLAGS(mesg->buffer) |= RD_BITS;
        }

        // send message

        socketaddress sa;
        //socklen_t sa_len = sizeof(sa.sa6);

        if(ISOK(ret = host_address2sockaddr(&sa, simple_message->name_server)))
        {
            s32 retries = (s32)dns_udp_settings->retry_count;

            do
            {
                // send the packet

                simple_message->sent_time_us = timeus();

                log_notice("send: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) using TCP", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status);

                ret = message_query_tcp_with_timeout(mesg, simple_message->name_server, dns_udp_settings->timeout / 1000000);

                if(ISOK(ret))
                {
                    log_notice("receive: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) using TCP", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status);

                    simple_message->status &= ~DNS_SIMPLE_MESSAGE_STATUS_COLLECTED;
                    simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_RECEIVED;
                    simple_message->received_time_us = timeus();
                    simple_message->answer = mesg;
                    mesg = NULL;

                    dns_udp_simple_message_answer_call_handlers(simple_message);
                    // dns_udp_simple_message_answer_call_handlers does a retain
                    //dns_udp_simple_message_release(simple_message);
                    simple_message = NULL;

                    break;
                }
                else
                {
                    if(--retries >= 0)
                    {
                        log_err("send: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) using TCP failed: %r, retrying", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status, ret);
                    }
                }
            }
            while(retries >= 0);
        }
    }
    else
    {
        log_err("send: tcp was unable to allocate a message");
        ret = ERROR;
    }
    
    if(FAIL(ret))
    {
        dns_udp_tcp_query_failures++;
        
        log_err("send: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) using TCP failed: %r", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status, ret);
        
        if(ret == MAKE_ERRNO_ERROR(EAGAIN))
        {
            ret = DNS_UDP_TIMEOUT;
        }
        
        simple_message->received_time_us = MAX_U64;

        dns_simple_message_async_node_s *node = simple_message->async_node.next;
        while(node != NULL)
        {
            // the handler MUST release one reference
            dns_udp_simple_message_retain(simple_message);
            node->async->error_code = ret;
            node->async->handler(node->async);
            node = node->next;
        }

        // there is no need to retain, the reference from the collection has not been decreased yet
        simple_message->async_node.async->error_code = ret;
        simple_message->async_node.async->handler(simple_message->async_node.async);
        
        simple_message = NULL;
    }
    
    if(mesg != NULL)
    {
        memset(mesg, 0xd6, sizeof(message_data));
        pool_release(&message_data_pool, mesg);
    }
   
    // simple_message->async_node.async->handler(simple_message->async_node.async);
    
    return NULL;
}

static void
dns_udp_tcp_query(dns_simple_message_s *simple_message, struct service_worker_s *worker)
{
    dns_udp_tcp_query_thread_params *parms;
    MALLOC_OR_DIE(dns_udp_tcp_query_thread_params*, parms, sizeof(dns_udp_tcp_query_thread_params), GENERIC_TAG);
    parms->simple_message = simple_message;
    parms->worker = worker;
    thread_pool_enqueue_call(tcp_query_thread_pool, dns_udp_tcp_query_thread, parms, NULL, "dns-udp-tcp");
}

#endif

int
dns_udp_send_simple_message(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass, u16 flags, async_done_callback *cb, void* cbargs)
{
    log_debug("query: %{hostaddr} %{dnsname} %{dnstype} %{dnsclass} %s", name_server, fqdn, &qtype, &qclass, (flags!=0)?"":"+dnssec");

    async_message_s *domain_message = async_message_alloc();
    
    dns_simple_message_s *simple_message = (dns_simple_message_s*)pool_alloc(&dns_simple_message_pool);
    
#ifdef DEBUG
    memset(simple_message, 0xac, sizeof(dns_simple_message_s));
#endif

    simple_message->name_server = host_address_copy(name_server); // MALLOCATED MEMORY RETURNED
    simple_message->answer = NULL;
    simple_message->async_node.async = domain_message;
    simple_message->async_node.next = NULL;
    simple_message->sent_time_us = MAX_S64;
    simple_message->received_time_us = 0;
    simple_message->qtype = qtype;
    simple_message->qclass = qclass;
    simple_message->retries_left = DNS_SIMPLE_MESSAGE_RETRIES_DEFAULT;
    simple_message->flags = flags;
    simple_message->dns_id = 0;
    simple_message->status = DNS_SIMPLE_MESSAGE_STATUS_QUEUED;
    simple_message->recurse = FALSE;
    
    mutex_init(&simple_message->mtx);
#if DNS_SIMPLE_MESSAGE_HAS_WAIT_COND
    pthread_cond_init(&simple_message->mtx_cond, NULL);
#endif
    simple_message->owner = 0;
    
    smp_int_init(&simple_message->rc);  // sets it to 0
    simple_message->rc.value = 1;       // no need to lock it yet to change it to 1
    
    dnsname_canonize(fqdn, simple_message->fqdn);
    
    log_debug5("new message@%p: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr}", simple_message, simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server);
    
    domain_message->id = DNS_UDP_SIMPLE_QUERY;
    domain_message->args = simple_message;
    domain_message->handler = cb;
    domain_message->handler_args = cbargs;
    
    async_message_call(&dns_udp_send_handler_queue, domain_message);
    
    return SUCCESS;
}

int
dns_udp_send_recursive_message(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass, u16 flags, async_done_callback *cb, void* cbargs)
{
    log_debug("query: %{hostaddr} %{dnsname} %{dnstype} %{dnsclass} %s (recursive)", name_server, fqdn, &qtype, &qclass, (flags!=0)?"":"+dnssec");

    async_message_s *domain_message = async_message_alloc();
    
    dns_simple_message_s *simple_message = (dns_simple_message_s*)pool_alloc(&dns_simple_message_pool);
    
#ifdef DEBUG
    memset(simple_message, 0xac, sizeof(dns_simple_message_s));
#endif
    
    simple_message->name_server = host_address_copy(name_server); // MALLOCATED MEMORY RETURNED
    simple_message->answer = NULL;
    simple_message->async_node.async = domain_message;
    simple_message->async_node.next = NULL;
    simple_message->sent_time_us = 0;
    simple_message->received_time_us = 0;
    simple_message->qtype = qtype;
    simple_message->qclass = qclass;
    simple_message->retries_left = DNS_SIMPLE_MESSAGE_RETRIES_DEFAULT;
    simple_message->flags = flags;
    simple_message->dns_id = 0;
    simple_message->status = DNS_SIMPLE_MESSAGE_STATUS_QUEUED;
    simple_message->recurse = TRUE;
    
    mutex_init(&simple_message->mtx);
#if DNS_SIMPLE_MESSAGE_HAS_WAIT_COND
    pthread_cond_init(&simple_message->mtx_cond, NULL);
#endif
    simple_message->owner = 0;
    smp_int_init(&simple_message->rc); // sets it to 0
    simple_message->rc.value = 1;       // no need to lock it yet to change it to 1
    
    dnsname_canonize(fqdn, simple_message->fqdn);
    
    log_debug5("new message@%p: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr}", simple_message, simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server);
    
    domain_message->id = DNS_UDP_SIMPLE_QUERY;
    domain_message->args = simple_message;
    domain_message->handler = cb;
    domain_message->handler_args = cbargs;
    
    async_message_call(&dns_udp_send_handler_queue, domain_message);
    
    return SUCCESS;
}

struct dns_udp_send_simple_message_sync_s
{
    struct async_wait_s wait;
    dns_simple_message_s *simple_message;
};

static void
dns_udp_send_simple_message_sync_handler(struct async_message_s *msg)
{
    dns_simple_message_s *simple_message = (dns_simple_message_s*)msg->args;
    struct dns_udp_send_simple_message_sync_s *args = (struct dns_udp_send_simple_message_sync_s*)msg->handler_args;
    args->simple_message = simple_message;
    args->wait.error_code = msg->error_code;
    async_wait_progress(&args->wait, 1);
}

int
dns_udp_send_recursive_message_sync(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass, u16 flags, dns_simple_message_s **to_release)
{
    struct dns_udp_send_simple_message_sync_s args;
    
    async_wait_init(&args.wait, 1);
    args.simple_message = NULL;
    
    int err = dns_udp_send_recursive_message(name_server, fqdn, qtype, qclass, flags, dns_udp_send_simple_message_sync_handler, &args);
    
    if(ISOK(err))
    {
        async_wait(&args.wait);
        
        err = args.wait.error_code;
        
        if(to_release != NULL)
        {
            *to_release = args.simple_message;
        }
    }
    
    async_wait_finalize(&args.wait);
    
    return err;
}

int
dns_udp_send_simple_message_sync(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass, u16 flags, dns_simple_message_s **to_release)
{
    struct dns_udp_send_simple_message_sync_s args;
    
    async_wait_init(&args.wait, 1);
    args.simple_message = NULL;
    
    int err = dns_udp_send_simple_message(name_server, fqdn, qtype, qclass, flags, dns_udp_send_simple_message_sync_handler, &args);
    
    if(ISOK(err))
    {
        async_wait(&args.wait);
        
        err = args.wait.error_code;
        
        if(to_release != NULL)
        {
            *to_release = args.simple_message;
        }
    }
    
    async_wait_finalize(&args.wait);
    
    return err;
}

#ifdef DNS_SIMPLE_MESSAGE_CAN_BE_LOCKED

bool
dns_udp_simple_message_trylock(dns_simple_message_s *message)
{
    log_debug7("dns_udp_simple_message_lock(%p) try locking (#%i)", message, message->rc.value);
    
    if(mutex_trylock(&message->mtx))
    {
        if(message->owner == 0)
        {
            message->owner = pthread_self();
        }
        
        log_debug7("dns_udp_simple_message_lock(%p) --- locked", message);
        
        //mutex_unlock(&message->mtx);
        
        return TRUE;
    }
    else
    {
        log_debug7("dns_udp_simple_message_lock(%p) NOT locked", message);
        
        return FALSE;
    }
}

void
dns_udp_simple_message_lock(dns_simple_message_s *message)
{
    log_debug7("dns_udp_simple_message_lock(%p) locking", message);
    
    mutex_lock(&message->mtx);
    
#if DNS_SIMPLE_MESSAGE_HAS_WAIT_COND
    while( message->owner != 0 )
    {
        pthread_cond_wait(&message->mtx_cond, &message->mtx);
    }
#endif
    message->owner = pthread_self();
    
    log_debug7("dns_udp_simple_message_lock(%p) locked", message);
}

void
dns_udp_simple_message_unlock(dns_simple_message_s *message)
{
    log_debug7("dns_udp_simple_message_lock(%p) unlocking", message);
    //mutex_lock(&message->mtx);
    
    message->owner = 0;
    
#if DNS_SIMPLE_MESSAGE_HAS_WAIT_COND
    pthread_cond_broadcast(&message->mtx_cond);
#endif
        
    mutex_unlock(&message->mtx);
        
    log_debug7("dns_udp_simple_message_lock(%p) unlocked", message);
}

#endif

void
dns_udp_simple_message_retain(dns_simple_message_s *simple_message)
{
    log_debug7("dns_udp_simple_message_retain(%p)", simple_message);
    
    int n = smp_int_inc_get(&simple_message->rc);
    
    if(n == 1)
    {
        log_warn("dns_udp_simple_message_retain(%p) : retained from 0", simple_message);
    }
}

void
dns_udp_simple_message_release(dns_simple_message_s *simple_message)
{
#ifdef DEBUG
    u16 qtype = simple_message->qtype;
    u16 qclass = simple_message->qclass;
    u32 fqdn_len;
    u8 fqdn[MAX_DOMAIN_LENGTH];
    if((fqdn_len = dnsname_len(simple_message->fqdn)) <= sizeof(fqdn))
    {
        memcpy(fqdn, simple_message->fqdn, fqdn_len);
    }
    else
    {
        log_err("dns_udp_simple_message_release(%p) looks broken", simple_message);
        memcpy(fqdn, "\006BROKEN", 8);
        logger_flush();
        abort();
    }
#endif
    
    int n = smp_int_dec_get(&simple_message->rc);

    if(n <= 0)
    {
        log_debug7("dns_udp_simple_message_release(%p) destroying", simple_message);
        
        if(n < 0)
        {
            log_err("dns_udp_simple_message_release(%p) : NEGATIVE RC: type=%{dnstype} class=%{dnsclass} status=%x", simple_message, &simple_message->qtype, &simple_message->qclass, simple_message->status);
            logger_flush();
            abort();                    
        }
        
        log_debug7("dns_udp_simple_message_release(%p) : %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x)", simple_message, simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status);
               
        // clear the answer

        if(simple_message->answer != NULL)
        {
            memset(simple_message->answer, 0xd4, sizeof(message_data));
            pool_release(&message_data_pool, simple_message->answer);
            simple_message->answer = NULL;
        }
        
        // clear the name server (hostaddr)

        host_address_delete(simple_message->name_server);
        simple_message->name_server = NULL;

        // release the sync
        
        if(simple_message->async_node.async != NULL)
        {
            async_message_release(simple_message->async_node.async);

            simple_message->async_node.async = NULL;
        }
        
        dns_simple_message_async_node_s *node = simple_message->async_node.next;
        
        while(node != NULL)
        {
            if(node->async != NULL)
            {
                async_message_release(node->async);
                node->async = NULL;
            }
            
            dns_simple_message_async_node_s *prev = node;
            
            node = node->next;

#ifdef DEBUG
            memset(prev, 0xd7, sizeof(dns_simple_message_async_node_s));
#endif
            
            pool_release(&dns_simple_message_async_node_pool, prev);
        }
        
        simple_message->async_node.next = NULL;
        
        // release the mutexes
#if DNS_SIMPLE_MESSAGE_HAS_WAIT_COND
        for(;;)
        {
            int err = pthread_cond_destroy(&simple_message->mtx_cond);
            if(err == 0)
            {
                break;
            }

            log_err("dns_udp_simple_message_release(%p) pthread_cond_destroy failed: %r", simple_message, MAKE_ERRNO_ERROR(err));
            
            usleep(10);
        }
#endif
        mutex_destroy(&simple_message->mtx);

        smp_int_destroy(&simple_message->rc);

        u8 status = simple_message->status | DNS_SIMPLE_MESSAGE_STATUS_INVALID;

        memset(simple_message, 0xd5, sizeof(dns_simple_message_s));
#if DEBUG
        simple_message->rc.value = -12345678;
#endif
        simple_message->status = status;
        
        log_debug7("dns_udp_simple_message_release(%p) destroyed (%x)", simple_message, simple_message->status);
        
        pool_release(&dns_simple_message_pool, simple_message);
    }
    else
    {
        // nothing to do yet.
        // note that since the message is not locked, the content CANNOT be printed
#ifndef DEBUG
        log_debug7("dns_udp_simple_message_release(%p) (%x)", simple_message, n);
#else
        log_debug7("dns_udp_simple_message_release(%p) (%x) : %{dnsname} %{dnstype} %{dnsclass}", simple_message, n, fqdn, &qtype, &qclass);
#endif
    }
}

static int
dns_udp_send_simple_message_process(async_message_s *domain_message, random_ctx rndctx, u16 source_port, int s, u32 worker_index)
{
    dns_simple_message_s *simple_message = (dns_simple_message_s*)domain_message->args;
    
    // check if in pending collection
    
#if DEBUG
    if((domain_message->start_time & 0x8000000000000000LL) != 0)
    {
        logger_flush();
        abort();
    }
#endif
    
    log_debug("sending: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x)", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status);
    
    // don't give a sent time until it's actually sent (high loads could trigger a timeout before the packet is sent)
    
    simple_message->sent_time_us = MAX_S64;
    simple_message->worker_index = worker_index;
    simple_message->source_port = source_port;

    // pre-increase the RC because of this new reference (into the DB)
    dns_udp_simple_message_retain(simple_message);
    /// @note: at this point the RC of simple_message is 2
    
    // lock the simple message
    dns_udp_simple_message_lock(simple_message);
    // lock the collection
    mutex_lock(&message_collection_mtx);
    
    treeset_node *node = treeset_avl_insert(&message_collection, simple_message);
    
    simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_COLLECTED;
    simple_message->status &= ~DNS_SIMPLE_MESSAGE_STATUS_QUEUED;
    
    int return_code;
    
    if(node->data == NULL)
    {
        // newly inserted
        // put in pending collection
        // RC already increased
                
        node->data = domain_message;
        
        mutex_unlock(&message_collection_mtx);
                
        log_debug5("set message@%p: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} %s (%x)",
                domain_message, simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, (simple_message->recurse)?"rd":"",
                simple_message->status);
    
        // generate message
        
        message_data mesg;
        
        if(simple_message->dns_id == 0)
        {
            simple_message->dns_id = (u16)random_next(rndctx);
        }
        
        message_make_query_ex(&mesg, simple_message->dns_id, simple_message->fqdn, simple_message->qtype, simple_message->qclass, simple_message->flags);

        if(simple_message->recurse)
        {
            MESSAGE_HIFLAGS(mesg.buffer) |= RD_BITS;
        }
        
        // send message
        
        socketaddress sa;
        socklen_t sa_len = sizeof(sa.sa6);
        
        if(ISOK(return_code = host_address2sockaddr(&sa, simple_message->name_server)))
        {
            for(;;)
            {
                // send the packet
                
                rate_wait(&dns_udp_send_rate, mesg.send_length);
                //rate_wait(&dns_udp_send_rate, 1);
                
                if((return_code = sendto(s, mesg.buffer, mesg.send_length, 0, &sa.sa, sa_len)) == mesg.send_length)
                {
                    simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_SENT;
                    
                    log_notice("sent: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x)", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status);
                    
                    simple_message->sent_time_us = timeus();
                    
#if DNS_SIMPLE_MESSAGE_CAN_BE_LOCKED
                    dns_udp_simple_message_unlock(simple_message);
#endif
                    // one RC can be released
                    dns_udp_simple_message_release(simple_message);
                    
                    /// @note at this point the RC is set to 1, but
                    /// it potentially could be 0 (and thus simple_message could already be destroyed)
                    
                    // message should NOT be used after this point
                    
                    // <statistics>
                    
                    u64 now = time(NULL);

                    mutex_lock(&sendto_statistics_mtx);
                    if(sendto_epoch == now)
                    {
                        sendto_total += return_code;
                        sendto_packets++;

                        mutex_unlock(&sendto_statistics_mtx);
                    }
                    else
                    {
                        u32 st = sendto_total;
                        u32 sq = sendto_packets;
                        u32 sqa = sendto_packets_aggregated;

                        sendto_epoch = now;
                        sendto_total = return_code;
                        sendto_packets = 0;
                        sendto_packets_aggregated = 0;

                        mutex_unlock(&sendto_statistics_mtx);

                        log_debug("sent: %d b/s (%d/%d q/s)", st, sq, sqa);
                    }
                    
                    // </statistics>

                    return return_code;
                }

                // an error occurred

                int err = errno;

                if((err != EINTR) && (err != EAGAIN))
                {
                    return_code = MAKE_ERRNO_ERROR(err);
                    
                    break;
                }

                // try again
            }
        }
        
        // error occurred while sending the message
    
        simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_FAILURE;

        log_err("error sending: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x): %r",
                simple_message->fqdn, &simple_message->qtype, &simple_message->qclass,
                simple_message->name_server, simple_message->status, return_code);

        mutex_lock(&message_collection_mtx);
        // ensure that the node still exists
        treeset_node *node = treeset_avl_insert(&message_collection, simple_message);
        if(node != NULL)
        {
            treeset_avl_delete(&message_collection, simple_message);
            // one RC can be released for the collection
            simple_message->status &= ~DNS_SIMPLE_MESSAGE_STATUS_COLLECTED;
            dns_udp_simple_message_release(simple_message);
        }
        else
        {
            // even if this is possible, this should NEVER happen
            log_debug6("the message @%p had been removed from the collection already", simple_message);
        }
        mutex_unlock(&message_collection_mtx);

#if DNS_SIMPLE_MESSAGE_CAN_BE_LOCKED
        dns_udp_simple_message_unlock(simple_message);
#endif
        /// @note RC = 1
        // the handler NEEDS to do the final release

        domain_message->error_code = return_code;        
        domain_message->handler(domain_message);

        return return_code;
    }
    else
    {
        // append the async callback to the dns_simple_message structure
        
        // a container for the new message node
        dns_simple_message_async_node_s *simple_message_node = (dns_simple_message_async_node_s*)pool_alloc(&dns_simple_message_async_node_pool);
        // the first message for this query, it will reference the new message
        dns_simple_message_s *first_message = (dns_simple_message_s *)node->key;
        
        // else it could be destroyed just after the unlock of the collection
        dns_udp_simple_message_retain(first_message);
        dns_udp_simple_message_lock(first_message);
        
        log_debug6("dns_udp_send_simple_message_process(%p) head %p->%p", simple_message, &first_message->async_node, first_message->async_node.next);
        
        // prepare the container to match the simple message's
        simple_message_node->next = simple_message->async_node.next;        //
        simple_message->async_node.next = NULL;
        simple_message_node->async = simple_message->async_node.async;
        simple_message->async_node.async = NULL;
        simple_message_node->async->args = first_message;                   // change the linked message to the first one
        
        log_debug6("dns_udp_send_simple_message_process(%p) edit %p->%p", simple_message, simple_message_node, simple_message_node->next);
        
        // append the whole list at once
        dns_simple_message_async_node_s *sm_last_node = simple_message_node;
        while(sm_last_node->next != NULL)
        {
            sm_last_node = sm_last_node->next;
            log_debug6("dns_udp_send_simple_message_process(%p) edit %p->%p", simple_message, sm_last_node, sm_last_node->next);
            sm_last_node->async->args = first_message;          // change the linked message to the first one
        }
        
        sm_last_node->next = first_message->async_node.next;
        first_message->async_node.next = simple_message_node;
        
        
#ifdef DEBUG
        while(simple_message_node != NULL)
        {
            log_debug6("dns_udp_send_simple_message_process(%p) node %p=>%p", simple_message, simple_message_node, simple_message_node->next);
            simple_message_node = simple_message_node->next;
        }
#endif
        
        first_message->status |= DNS_SIMPLE_MESSAGE_STATUS_AGGREGATED;
        dns_udp_simple_message_unlock(first_message); /// @todo 20140526 edf -- update the timeout
        
        mutex_unlock(&message_collection_mtx);
        
        dns_udp_simple_message_unlock(simple_message);
                
        // added
        
        sendto_packets_aggregated++;
        
        log_debug5("add message@%p to message@%p: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} %s (%x)",
                domain_message, first_message, first_message->fqdn, &first_message->qtype, &first_message->qclass, first_message->name_server, (first_message->recurse)?"rd":"",
                first_message->status);
        
        // the local reference can be released
        dns_udp_simple_message_release(first_message);
        // one RC can be released from the collection
        dns_udp_simple_message_release(simple_message);
        // one RC can be released from this reference
        dns_udp_simple_message_release(simple_message);
        // should be destroyed at this point
        
        return SUCCESS;
    }
}

static int
dns_udp_send_service(struct service_worker_s *worker)
{
    struct sockaddr_in6 sin6;
    random_ctx rndctx;
    const u32 worker_index = worker->worker_index;
    
    log_debug("send: service started (%u/%u)", worker_index + 1, worker->service->worker_count);
    
    const int my_socket = dns_udp_socket[worker_index];
    
    rndctx = thread_pool_get_random_ctx();
    
    ZEROMEMORY(&sin6, sizeof(sin6));
    socklen_t sin6len = sizeof(sin6);
    getsockname(my_socket, (struct sockaddr*)&sin6, &sin6len);
    
    const u16 source_port = sin6.sin6_port;

    while(service_shouldrun(worker) || !async_queue_emtpy(&dns_udp_send_handler_queue))
    {
        // timeout high priority list.
        
        async_message_s *async;
        
        // I'm using the worker lock to synchronise with its counterpart,
        // so I don't have to create yet another mutex
        
        mutex_lock(&worker->lock);
        u32 high_priority_size = list_dl_size(&dns_udp_high_priority[worker_index]);
        async = list_dl_dequeue(&dns_udp_high_priority[worker_index]);
        mutex_unlock(&worker->lock);
        
        if(async == NULL)
        {
            async = async_message_next(&dns_udp_send_handler_queue);

            if(async == NULL)
            {
                continue;
            }
        }
        else
        {
            log_debug("send: processing timeout retry (%u still in high priority queue)", high_priority_size);
        }
        
        log_debug6("send: processing message (%u still in queue)", async_queue_size(&dns_udp_send_handler_queue));

        switch(async->id)
        {
            case DNS_UDP_SIMPLE_QUERY:
            {
                log_debug6("DNS_UDP_SIMPLE_QUERY");
                dns_udp_send_simple_message_process(async, rndctx, source_port, my_socket, worker_index);
                break;
            }
            default:
            {
                log_err("DNS_UDP_? %u", async->id);
                async->error_code = SERVICE_ID_ERROR;
                async->handler(async);
                break;
            }
        }        
    }
    

    
    service_set_stopping(worker);

    log_debug("send: service stopped (%u/%u)", worker_index + 1, worker->service->worker_count);

    return 0;
}

static int
dns_udp_receive_service(struct service_worker_s *worker)
{
    log_debug("receive: service started (%u/%u)", worker->worker_index + 1, worker->service->worker_count);
    
    int my_socket = dns_udp_socket[worker->worker_index];
    

    
    // u16 port;
    
    struct sockaddr_in6 sin6;
    ZEROMEMORY(&sin6, sizeof(sin6));
    socklen_t sin6len = sizeof(sin6);
    getsockname(my_socket, (struct sockaddr*)&sin6, &sin6len);
    
    tcp_set_recvtimeout(my_socket, dns_udp_settings->timeout / 1000000LL, dns_udp_settings->timeout % 1000000LL);
    
    // port = sin6.sin6_port;
    
    message_data *mesg;
    
    for(;;)
    {
        mesg = (message_data*)pool_alloc(&message_data_pool);
        
        if(mesg != NULL)
        {
            ZEROMEMORY(mesg, sizeof(message_data));
            break;
        }
        
        if(!service_shouldrun(worker))
        {
            break;
        }
        
        sleep(1);
    }
    
    host_address sender_host_address;
    
    while(service_shouldrun(worker))
    {
        int n;
        
        yassert(mesg != NULL);
        
        mesg->addr_len = sizeof(mesg->other);
                
        if((n = recvfrom(my_socket, mesg->buffer, sizeof(mesg->buffer), 0, &mesg->other.sa, &mesg->addr_len)) >= 0)
        {
            if(n > 0)
            {
                log_debug6("receive: recvfrom(%i, ... , %{sockaddr}) = %i", my_socket, &mesg->other, n);
            }
            else
            {
                log_debug6("receive: empty packet");
            }
            
            mesg->received = n;
            
            u64 now = time(NULL);
            
            mutex_lock(&recvfrom_statistics_mtx);
            if(recvfrom_epoch == now)
            {
                recvfrom_total += n;
                recvfrom_packets++;
                mutex_unlock(&recvfrom_statistics_mtx);
            }
            else
            {
                recvfrom_epoch = now;
                u32 rt = recvfrom_total;
                recvfrom_total = n;
                u32 rq = recvfrom_packets;
                recvfrom_packets = 0;
                
                mutex_unlock(&recvfrom_statistics_mtx);
                
                log_debug("receive: recvfrom: %d b/s %d p/s", rt, rq);
            }
            
            ya_result return_code;
            
            if(ISOK(return_code = message_process_lenient(mesg)))
            {
                // look in the timeout collection
                
                host_address_set_with_sockaddr(&sender_host_address, &mesg->other);

                if(sender_host_address.version == 6)
                {
                    if(memcmp(sender_host_address.ip.v6.bytes, V4_WRAPPED_IN_V6, sizeof(V4_WRAPPED_IN_V6)) == 0)
                    {
                        // unwrap
                        
                        u32 ipv4 = sender_host_address.ip.v6.dwords[3];
                        sender_host_address.ip.v4.value = ipv4;
                        sender_host_address.version = 4;
                    }
                }
                
                dns_simple_message_s message;
                message.name_server = &sender_host_address;
                message.sent_time_us = MAX_S64;
                message.received_time_us = 0;
                message.retries_left = 0;

                
                int len = dnsname_copy(message.fqdn, mesg->qname);
                
                if(ISOK(len))
                {
                    message.qtype = GET_U16_AT(mesg->buffer[12 + len]);
                    message.qclass = GET_U16_AT(mesg->buffer[12 + len + 2]);
                    
                    // remove it from the collection
                
                    mutex_lock(&message_collection_mtx);
        
                    treeset_node *node = treeset_avl_find(&message_collection, &message);
                    
                    if(node != NULL)
                    {
                        // proceed
                        
                        bool truncated = MESSAGE_TC(mesg->buffer);
                        
                        dns_simple_message_s *simple_message = (dns_simple_message_s*)node->key;
                                        
                        dns_udp_simple_message_lock(simple_message);

                        treeset_avl_delete(&message_collection, simple_message);
                        
                        // the message is not in the timeout collection anymore
                        // it should contain an answer, or an error, ... or a message with the TC bit on
                        
                        if(!truncated)
                        {
                            simple_message->status &= ~DNS_SIMPLE_MESSAGE_STATUS_COLLECTED;
                            simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_RECEIVED;
                        }
                        
                        dns_udp_simple_message_unlock(simple_message);
                        
                        mutex_unlock(&message_collection_mtx);
                        
                        // RC is supposed to be 1
                        
#ifdef DEBUG
                        if(simple_message->rc.value != 1)
                        {
                            log_warn("receive: message RC is not 1 (%i)", simple_message->rc.value);
                        }
#endif
                        
#if HAS_TC_FALLBACK_TO_TCP_SUPPORT
                        if(!truncated)
                        {
#endif
                            simple_message->received_time_us = timeus();
                            simple_message->answer = mesg;

                            log_notice("receive: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x)", message.fqdn, &message.qtype, &message.qclass, message.name_server, simple_message->status);

                            dns_udp_simple_message_answer_call_handlers(simple_message);
                            
                            // allocate the next buffer, handle the hard_limit of the pool:
                            // when the pool has reached peak capacity, allocation returns NULL

                            mesg = dns_udp_allocate_message_data(worker);
#if HAS_TC_FALLBACK_TO_TCP_SUPPORT
                        
                        }
                        else
                        {
                            // the message has been truncated
                            // it should be queried again using TCP
                            
                            dns_udp_tcp_query(simple_message, worker);
                        }
#endif
                    }
                    else
                    {
                        mutex_unlock(&message_collection_mtx);
                        
                        // unknown
                        
                        log_warn("receive: unexpected message %{dnsname} %{dnstype} %{dnsclass}", message.fqdn, &message.qtype, &message.qclass);
                    }
                }
                else
                {
                    log_err("receive: an error occurred while copying the name '%{dnsname}': %r", mesg->qname, len);
                }
            }
            else
            {
                if(service_shouldrun(worker))
                {
                    log_err("receive: cannot handle answer: %r", return_code);
                }
            }
        }
        else
        {
            int err = errno;

            if(err == EINTR)
            {
#ifdef DEBUG
                log_debug7("receive: recvfrom EINTR");
#endif
                continue;
            }
            if(err == EAGAIN)
            {
#ifdef DEBUG
                log_debug7("receive: recvfrom EAGAIN");
#endif
                continue;
            }
                
            log_err("receive: recvfrom error: %r", MAKE_ERRNO_ERROR(err));
        }
    }
    
    if(mesg != NULL)
    {
        memset(mesg, 0xd6, sizeof(message_data));
        pool_release(&message_data_pool, mesg);
    }
    
    service_set_stopping(worker);

    log_debug("receive: service stopped (%u/%u)", worker->worker_index + 1, worker->service->worker_count);
    
    return 0;
}

static int
dns_udp_timeout_service(struct service_worker_s *worker)
{
    log_debug("dns_udp_timeout_service started");
    
    ptr_vector todelete = EMPTY_PTR_VECTOR;
    
    while(service_shouldrun(worker))
    {
        sleep(1);
        
        if(!service_shouldrun(worker))
        {
            break;
        }
        
        ptr_vector_empties(&todelete);
        
        u64 now = timeus();
        
        int messages_count = 0;
        int failed_tries = 0;
        
        mutex_lock(&message_collection_mtx);
        
        treeset_avl_iterator iter;
        treeset_avl_iterator_init(&message_collection, &iter);
        while(treeset_avl_iterator_hasnext(&iter))
        {
            treeset_node *node = treeset_avl_iterator_next_node(&iter);
            dns_simple_message_s *simple_message = (dns_simple_message_s *)node->key;
            
            messages_count++;
           
            if(dns_udp_simple_message_trylock(simple_message))
            {
                now = timeus();

                if(simple_message->sent_time_us != MAX_S64)
                {
#ifdef DEBUG
                    if(now <  simple_message->sent_time_us)
                    {
                        log_debug("message was sent %llu in the future! (sent at %llu, now is %llu, really %llu)", simple_message->sent_time_us - now, simple_message->sent_time_us, now, timeus());
                    }
#endif

                    if(now - simple_message->sent_time_us > dns_udp_settings->timeout) // older than 3s ? => remove
                    {
                        // timed out

                        // retain because the reference is now in two collection
                        dns_udp_simple_message_retain(simple_message);

                        simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_TIMEDOUT;
                        ptr_vector_append(&todelete, simple_message);
                    }
                }
#ifdef DEBUG
                else
                {
                    if(now - simple_message->sent_time_us > dns_udp_settings->timeout)
                    {
                        log_warn("timeout: message would have wrongly been timed-out");
                    }
                }
#endif
                
                dns_udp_simple_message_unlock(simple_message);
            }
            else
            {
                failed_tries++;
            }
        }
        
        if(failed_tries > 0)
        {
            log_warn("timeout: failed to lock %i messages (on a total of %i)", failed_tries, messages_count);
        }
        
        for(int i = 0; i <= todelete.offset; i++)
        {
            dns_simple_message_s *simple_message = (dns_simple_message_s *)todelete.data[i];
            
            treeset_avl_delete(&message_collection, simple_message);
            // release because it has been removed from one collection
            dns_udp_simple_message_release(simple_message);
            
            simple_message->status &= ~DNS_SIMPLE_MESSAGE_STATUS_COLLECTED;
        }
        
        mutex_unlock(&message_collection_mtx);
        
        now = timeus();

        for(int i = 0; i <= todelete.offset; i++)
        {
            dns_simple_message_s *simple_message = (dns_simple_message_s *)todelete.data[i];
            
            log_debug("timeout: [r=%i] %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) (sent at %llu, now is %llu)", simple_message->retries_left, simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status, simple_message->sent_time_us, now);

            if(simple_message->retries_left > 0)
            {
                simple_message->retries_left--;
             
                async_message_s* async = simple_message->async_node.async;
                
                log_debug5("timeout: re-queueing message with id=%i", async->id);
                
                /**
                 * @note Here was the issue.  The messages are queued so it can take a long time until they are retried.
                 */
                
                async->id = DNS_UDP_SIMPLE_QUERY;
                async->start_time = timeus();
                
                struct service_worker_s *owning_worker = service_get_worker(&dns_udp_send_handler, simple_message->worker_index);
                
                assert(owning_worker != NULL);
                
                mutex_lock(&owning_worker->lock);
                list_dl_enqueue(&dns_udp_high_priority[simple_message->worker_index], async);
                mutex_unlock(&owning_worker->lock);
            }
            else
            {
                simple_message->received_time_us = MAX_U64;

                yassert(now >= simple_message->sent_time_us);

                double tos = now - simple_message->sent_time_us;
                tos /= 1000000.0;
                log_notice("received: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) timed-out (%6.3fs)",
                        simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status,
                           tos);

                dns_simple_message_async_node_s *node = simple_message->async_node.next;
                while(node != NULL)
                {
                    // the handler MUST release one reference
                    dns_udp_simple_message_retain(simple_message);
                    node->async->error_code = DNS_UDP_TIMEOUT;
                    node->async->handler(node->async);
                    node = node->next;
                }

                // there is no need to retain, the reference from the collection has not been decreased yet
                simple_message->async_node.async->error_code = DNS_UDP_TIMEOUT;
                simple_message->async_node.async->handler(simple_message->async_node.async);
            }
        }
    }
    
    service_set_stopping(worker);
    
    ptr_vector_destroy(&todelete);

    log_debug("dns_udp_timeout_service stopped");
    
    return 0;
}
