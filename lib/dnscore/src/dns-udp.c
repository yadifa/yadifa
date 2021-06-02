/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2021, EURid vzw. All rights reserved.
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

#include "dnscore/dnscore-config.h"
#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>
#include <dnscore/threaded_queue.h>
#include "dnscore/fdtools.h"
#include "dnscore/dns_resource_record.h"
#include "dnscore/thread_pool.h"
#include "dnscore/random.h"
#include "dnscore/message.h"
#include "dnscore/tcp_io_stream.h"
#include "dnscore/u64_set.h"
#include "dnscore/ptr_set.h"
#include "dnscore/pool.h"
#include "dnscore/thread_pool.h"
#include "dnscore/service.h"
#include "dnscore/async.h"
#include "dnscore/dns-udp.h"
#include "dnscore/limiter.h"
#include "dnscore/list-dl.h"
#include "dnscore/list-sl.h"
#include "dnscore/mutex.h"
#include "dnscore/dnsname.h"

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#define SCKTARRY_TAG 0x59525241544b4353
#define DNSUDPHS_TAG 0x5348504455534e44


#define HAS_TC_FALLBACK_TO_TCP_SUPPORT 1

#define DNS_UDP_SIMPLE_QUERY 0

#define DNS_UDP_SIMPLE_MESSAGE_FLAG_NONE   0
#define DNS_UDP_SIMPLE_MESSAGE_FLAG_DNSSEC 1

#define DNS_SIMPLE_MESSAGE_RETRIES_DEFAULT 2 // 3 tries total

#define DNSURECV_TAG 0x5643455255534e44
#define DNSSMAND_TAG 0x444e414d53534e44
#define DNSSMESG_TAG 0x4753454d53534e44
#define DNSURMU_TAG  0x554d5255534e44
#define DNSURAU_TAG  0x55415255534e44
#define DNSURCTX_TAG 0x5854435255534e44

//#define DNS_UDP_HOST_RATE_WAIT        10000   // 10ms wait between two packets
#define DNS_UDP_HOST_RATE_WAIT          1000000 // 1s wait between two packets

#define DNS_UDP_HOST_BANDWIDTH_MAX      4096    // bytes per second
#define DNS_UDP_HOST_RATE_MAX           5       // packet per second

static const u8 V4_WRAPPED_IN_V6[12] = {0,0,0,0,0,0,0,0,0,0,255,255};

static struct service_s dns_udp_send_handler = UNINITIALIZED_SERVICE;

static struct service_s dns_udp_receive_read_handler = UNINITIALIZED_SERVICE;
static struct service_s dns_udp_receive_process_handler = UNINITIALIZED_SERVICE;

static struct service_s dns_udp_timeout_handler = UNINITIALIZED_SERVICE;

static async_queue_s dns_udp_send_handler_queue;

static bool dns_udp_handler_initialized = FALSE;

//static smp_int domain_test_count = SMP_INT_INITIALIZER;

static int dns_udp_send_service(struct service_worker_s *worker);

static int dns_udp_receive_read_service(struct service_worker_s *worker);
static int dns_udp_receive_process_service(struct service_worker_s *worker);
struct dns_udp_receive_ctx;
static size_t dns_udp_receive_ctx_available(struct dns_udp_receive_ctx *ctx);

static int dns_udp_timeout_service(struct service_worker_s *worker);

static int *dns_udp_socket = NULL;

struct dns_udp_receive_ctx;

static struct dns_udp_receive_ctx **dns_udp_receive_context = NULL;
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

static struct thread_pool_s *dns_udp_callback_tp = NULL;

static int dns_udp_send_simple_message_node_compare(const void *key_a, const void *key_b);

static ptr_set message_collection = { NULL, dns_udp_send_simple_message_node_compare };
static mutex_t message_collection_mtx = MUTEX_INITIALIZER;

static volatile s64 message_collection_keys = 0;
static volatile s64 message_collection_size = 0;

static const dns_udp_settings_s default_dns_udp_settings =
{
    DNS_UDP_TIMEOUT_US,
    DNS_UDP_SEND_RATE,
    DNS_UDP_SEND_BANDWIDTH,
    DNS_UDP_RECV_BANDWIDTH,
    DNS_UDP_SEND_QUEUE,
    DNS_UDP_PORT_COUNT,
    DNS_UDP_RETRY_COUNT,
    DNS_UDP_PER_DNS_RATE,
    DNS_UDP_PER_DNS_BANDWIDTH,
    DNS_UDP_PER_DNS_FREQ_MIN,
    DNS_UDP_READ_BUFFER_COUNT,
    DNS_UDP_CALLBACK_QUEUE_SIZE,
    DNS_UDP_CALLBACK_THREAD_COUNT,
    DNS_UDP_TCP_THREAD_POOL_SIZE,
    DNS_UDP_TCP_FALLBACK_ON_TIMEOUT
};

static const dns_udp_settings_s *dns_udp_settings = &default_dns_udp_settings;

/******************************************************************************
 * 
 * @note edf 20170905 -- this block handles the various new limits
 *
 *****************************************************************************/

// the bits that will be squashed so the delay collection does not explodes with keys

#define LIMIT_DELAYED_SET_GRANULARITY_WINDOW 16383    // 16ms

struct dns_udp_host_state_s
{
    host_address* host;         // a nameserver
    limiter_t send_rate;
    limiter_t send_bandwidth;
};

typedef struct dns_udp_host_state_s dns_udp_host_state_s;

static int dns_udp_host_state_node_compare(const void *key_a, const void *key_b)
{
    const host_address* a = (const host_address*)key_a;
    const host_address* b = (const host_address*)key_b;
  
    int d = host_address_compare(a, b);
    return d;
}

/**
 * @note edf 20170905 -- this is for limiting the global send bandwidth
 * 
 */

static limiter_t dns_udp_send_bandwidth;
static mutex_t limiter_send_wait_mtx = MUTEX_INITIALIZER;
static mutex_t limiter_recv_wait_mtx = MUTEX_INITIALIZER;

/**
 * @note edf 20170905 -- this is for limiting the global packets sent per second
 * 
 */

static limiter_t dns_udp_send_rate;

/**
 * @note edf 20170905 -- this is for limiting the global recv bandwidth
 *                       Of course there is no pps limiter for input as it is closely
 *                       correlated to the 'send' one.
 */

static limiter_t dns_udp_recv_bandwidth;

static struct ptr_set host_state_set = PTR_SET_EMPTY_WITH_COMPARATOR(dns_udp_host_state_node_compare);
static mutex_t host_state_set_mtx = MUTEX_INITIALIZER;

static dns_udp_host_state_s*
dns_udp_host_state_get_nolock(const host_address* host)
{
    ptr_node* node = ptr_set_insert(&host_state_set, (host_address*)host);
    dns_udp_host_state_s* state;
    
    if(node->value == NULL)
    {
        ZALLOC_OBJECT_OR_DIE(state, dns_udp_host_state_s, DNSUDPHS_TAG);
        state->host = host_address_copy(host);
        node->key = state->host;
        limiter_init(&state->send_bandwidth, dns_udp_settings->per_dns_bandwidth);
        limiter_init(&state->send_rate, dns_udp_settings->per_dns_rate);
        limiter_set_wait_time(&state->send_rate, dns_udp_settings->per_dns_freq_min);
        node->value = state;
    }
    
    state = (dns_udp_host_state_s*)node->value;
    
    return state;
}

u64
dns_udp_host_state_packet_try(host_address* host, u32 size)
{
    mutex_lock(&host_state_set_mtx);
    
    dns_udp_host_state_s* state = dns_udp_host_state_get_nolock(host);
    limiter_count_t available_now;
    u64 rate_wait_time;
    u64 bandwidth_wait_time = 0;
    u64 now;
    
    log_debug4("sender: %{hostaddr} waiting for the send rate to be low enough", host);
    
    now = limiter_quota(&state->send_rate, 1, &available_now, &rate_wait_time);
    if(available_now == 1)
    {
        log_debug4("sender: %{hostaddr} waiting for the send bandwidth to be low enough", host);
        
        limiter_quota(&state->send_bandwidth, size, &available_now, &bandwidth_wait_time);
        if(size == available_now)
        {
            limiter_add(&state->send_rate, 1, &available_now, &rate_wait_time);
            limiter_add(&state->send_bandwidth, size, &available_now, &bandwidth_wait_time);
            
            log_debug4("sender: %{hostaddr} allocating send rate and bandwidth", host);
                        
            // can be sent now
            
            mutex_unlock(&host_state_set_mtx);
            return 0;
        }
    }
    
    log_debug4("sender: %{hostaddr} query will be delayed", host);
    
    // has to be delayed
    
    u64 delay_epoch_us = (now + MAX(rate_wait_time, bandwidth_wait_time) + (LIMIT_DELAYED_SET_GRANULARITY_WINDOW - 1)) & ~LIMIT_DELAYED_SET_GRANULARITY_WINDOW;
    
    mutex_unlock(&host_state_set_mtx);
    return delay_epoch_us;
}

static u64_set delayed_message_set = U64_SET_EMPTY;
static mutex_t delayed_message_set_mtx = MUTEX_INITIALIZER;

static s64 delayed_message_count = 0;

static void
delayed_message_insert(u64 epoch_us, async_message_s* async)
{
    mutex_lock(&delayed_message_set_mtx);
    u64_node* node = u64_set_insert(&delayed_message_set, epoch_us);
    list_sl_s* list;
    
    if(node->value == NULL)
    {
        list = list_sl_new_instance();
        node->value = list;
    }
    
    list = (list_sl_s*)node->value;
    
    list_sl_add(list, async);
    
    ++delayed_message_count;
    
    mutex_unlock(&delayed_message_set_mtx);
}

static async_message_s*
delayed_message_next_at(u64 epoch_us)
{
    async_message_s* ret = NULL;
    
    mutex_lock(&delayed_message_set_mtx);
    
    for(;;)
    {
        u64_node* node = u64_set_get_first(&delayed_message_set);
        
        if(node == NULL)
        {
            break;
        }

        if(node->key > epoch_us)
        {
            break;
        }
        
        list_sl_s* list = (list_sl_s*)node->value;
        
        ret = (async_message_s*)list_sl_remove_first(list);

        if(ret != NULL)
        {
            --delayed_message_count;
            break;
        }

        // remove the whole node
        
        list_sl_delete_instance(list);
        
        u64_set_delete(&delayed_message_set, node->key);
    }
    
    mutex_unlock(&delayed_message_set_mtx);
    
    return ret;
}

static async_message_s*
delayed_message_next()
{
    async_message_s* async = delayed_message_next_at(timeus());
    return async;
}

/*****************************************************************************/

static void *
dns_simple_message_async_node_pool_alloc(void *_ignored_)
{
    dns_simple_message_async_node_s *sma;
    
    (void)_ignored_;
    
    ZALLOC_OBJECT_OR_DIE(sma, dns_simple_message_async_node_s, DNSSMAND_TAG);
    ZEROMEMORY(sma, sizeof(dns_simple_message_async_node_s));
    return sma;
}

static void
dns_simple_message_async_node_pool_free(void *sma_, void *_ignored_)
{
    (void)_ignored_;
    dns_simple_message_async_node_s* sma = (dns_simple_message_async_node_s*)sma_;
    memset(sma, 0xd0, sizeof(dns_simple_message_async_node_s));
    //free(sma); // POOL
    ZFREE_OBJECT(sma);
}

static void *
dns_simple_message_pool_alloc(void *_ignored_)
{
    dns_simple_message_s *msg;
    
    (void)_ignored_;
    
    ZALLOC_OBJECT_OR_DIE(msg, dns_simple_message_s, DNSSMESG_TAG);
    ZEROMEMORY(msg, sizeof(dns_simple_message_s));
    msg->sender_socket = -1;
    return msg;
}

static void
dns_simple_message_pool_free(void *msg_, void *_ignored_)
{
    (void)_ignored_;
    dns_simple_message_s* msg = (dns_simple_message_s*)msg_;
    memset(msg, 0xd1, sizeof(dns_simple_message_s));
#if DEBUG
    //msg->rc.value = 0;
#endif
    //free(p); // POOL
    ZFREE_OBJECT(msg);
}

static void *
message_data_pool_alloc(void *_ignored_)
{
    message_data *mesg;
    
    (void)_ignored_;
    
    mesg = message_new_instance();
    
    return mesg;
}

#if UNUSED
static void
message_data_pool_reset(void *p, void *_ignored_)
{
    (void)_ignored_;

    message_reset_buffer_size((message_data*)p);
    message_send_udp_reset((message_data*)p);
}
#endif

static void
message_data_pool_free(void *p, void *_ignored_)
{
    (void)_ignored_;

    message_free((message_data*)p);
}


static void
dns_udp_handler_message_collection_free_node_callback(ptr_node *node)
{
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

/**
 * Overwrites (creates) the limits for a given host.
 * Meant for the caching nameserver(s) for the DNSQ project.
 * 
 * @param name_server
 * @param rate
 * @param bandwidth
 * @param freq_min
 */

void dns_udp_handler_host_limit_set(const host_address* name_server,
        u32 rate,
        u32 bandwidth,
        u32 freq_min)
{
    mutex_lock(&host_state_set_mtx);
    
    dns_udp_host_state_s* state = dns_udp_host_state_get_nolock(name_server);
    
    limiter_init(&state->send_bandwidth, bandwidth);
    limiter_init(&state->send_rate, rate);
    limiter_set_wait_time(&state->send_rate, freq_min);
    
    mutex_unlock(&host_state_set_mtx);
}

int 
dns_udp_handler_start()
{
    int err = SERVICE_NOT_INITIALISED;

    if(dns_udp_handler_initialized)
    {
        if(ISOK(err = service_start(&dns_udp_send_handler)))
        {
            if(ISOK(err = service_start(&dns_udp_receive_read_handler)))
            {
                if(ISOK(err = service_start(&dns_udp_receive_process_handler)))
                {
                    if(ISOK(err = service_start(&dns_udp_timeout_handler)))
                    {
                        return err;
                    }

                    service_stop(&dns_udp_receive_process_handler);
                    service_wait(&dns_udp_receive_process_handler);
                }
            
                service_stop(&dns_udp_receive_read_handler);
                service_wait(&dns_udp_receive_read_handler);
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
    int err2b = SUCCESS;
    int err3 = SUCCESS;
    int err4 = SUCCESS;
    
    if(!dns_udp_handler_initialized)
    {
        return SERVICE_NOT_INITIALISED;
    }

    if(!service_stopped(&dns_udp_send_handler))
    {
        if(FAIL(err1 = service_stop(&dns_udp_send_handler)))
        {
            log_err("failed to stop dns_udp_send_handler: %r", err1);
            err = err1;
        }
    }
    
    if(!service_stopped(&dns_udp_receive_process_handler))
    {
        if(FAIL(err2 = service_stop(&dns_udp_receive_process_handler)))
        {
            log_err("failed to stop dns_udp_receive_process_handler: %r", err2);
            err = err2;
        }
    }
    
    if(!service_stopped(&dns_udp_receive_read_handler))
    {
        if(FAIL(err2b = service_stop(&dns_udp_receive_read_handler)))
        {
            log_err("failed to stop dns_udp_receive_read_handler: %r", err2);
            err = err2b;
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
    
    log_debug("closing %i sockets", dns_udp_socket_count);
    
    for(u32 i = 0; i < dns_udp_socket_count; i++)
    {
        if(dns_udp_socket[i] != ~0)
        {
            log_debug1("dns_udp_handler_stop: closing socket %i", dns_udp_socket[i]);

            close_ex(dns_udp_socket[i]);
            dns_udp_socket[i] = ~0;
        }
    }
    
    log_debug("closed %i sockets", dns_udp_socket_count);

    // cleans-up whatever is waiting ...

    
    if(dns_udp_high_priority != NULL)
    {
        for(u32 i = 0; i < dns_udp_socket_count; ++i)
        {
            list_dl_s *list = &dns_udp_high_priority[i];
            async_message_s *async;
            while((async = (async_message_s*)list_dl_remove_first(list)) != NULL)
            {
                dns_simple_message_s *simple_message = (dns_simple_message_s*)async->args;
                
                simple_message->sent_time_us = MAX_S64;
                simple_message->worker_index = i;
                simple_message->source_port = 0;

                // pre-increase the RC because of this new reference (into the DB)
                // dns_udp_simple_message_retain(simple_message);
                
                async->error_code = DNS_UDP_CANCEL;
                
                //dns_udp_simple_message_answer_call_handlers(simple_message);
                
                log_debug("send: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) is cancelled", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status);

                simple_message->received_time_us = MAX_U64;

                dns_simple_message_async_node_s *node = simple_message->async_node.next;
                while(node != NULL)
                {
                    // the handler MUST release one reference (so we acquire one right before)
                    dns_udp_simple_message_retain(simple_message);
                    node->async->error_code = DNS_UDP_CANCEL;
                    node->async->handler(node->async);              // stop time, no need to thread
                    node = node->next;
                }

                // there is no need to retain, the reference from the collection has not been decreased yet
                simple_message->async_node.async->error_code = DNS_UDP_CANCEL;
                simple_message->async_node.async->handler(simple_message->async_node.async);

                simple_message = NULL;

                //async->handler(async);
                //async_wait_progress(aw, 1);
            }
        }
    }
    
    if(ISOK(err1))
    {            
        service_wait(&dns_udp_send_handler);
    }
    
    if(ISOK(err2))
    {
        service_wait(&dns_udp_receive_process_handler);
    }
    if(ISOK(err2b))
    {
        service_wait(&dns_udp_receive_read_handler);
    }
    
    if(ISOK(err3))
    {
        service_wait(&dns_udp_timeout_handler);
    }
    
    if(ISOK(err4))
    {
        dns_udp_socket_count = 0;
    }
    
    dns_udp_cancel_all_queries();
        
    return err;
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
            return mesg;
        }

        if(!service_should_run(worker))
        {
            return NULL;
        }

        sleep(1);
    }
}

/**
 * Calls the handlers of the aggregated queries on a message.
 * 
 * First calls the handlers for the list of aggregated.
 * Then calls the handler for original one.
 * 
 * @param simple_message
 */
static void *dns_udp_simple_message_answer_call_handlers_thread(void* arg)
{
    dns_simple_message_s *simple_message = (dns_simple_message_s*)arg;

    s64 start = timeus();

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

#if DEBUG
    if(simple_message->rc.value > 1)
    {
        log_warn("receive: message RC is not 1 (%i)", simple_message->rc.value);
    }
#endif

    assert(simple_message->rc.value > 0);

    // there is no need to retain, the reference from the collection has not been decreased yet
    simple_message->async_node.async->handler(simple_message->async_node.async);

    s64 end = timeus();
    double dps = end - start;
    dps /= ONE_SECOND_US_F;
    log_debug("receive: handler processing took %6.3fs", dps);

    dns_udp_simple_message_release(simple_message);

    return NULL;
}

static void
dns_udp_simple_message_answer_call_handlers(dns_simple_message_s *simple_message)
{
    dns_udp_simple_message_retain(simple_message);
    thread_pool_enqueue_call(dns_udp_callback_tp, dns_udp_simple_message_answer_call_handlers_thread, simple_message, NULL, "dns-cb");
}

#if HAS_TC_FALLBACK_TO_TCP_SUPPORT

#define DNSUTQTP_TAG 0x5054515455534e44

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
    
    ZFREE(parms, dns_udp_tcp_query_thread_params);
    
    ya_result ret;
        
    random_ctx rndctx = thread_pool_get_random_ctx();
    
    yassert(simple_message->answer == NULL);
    
    message_data *mesg = dns_udp_allocate_message_data(worker);
    
    dns_udp_tcp_query_count++;
        
    if(mesg != NULL)
    {
        simple_message->dns_id = (u16)random_next(rndctx);
        simple_message->tcp_used = TRUE;

        message_make_query_ex(mesg, simple_message->dns_id, simple_message->fqdn, simple_message->qtype, simple_message->qclass, simple_message->flags);

        if(simple_message->recurse)
        {
            message_set_rd_flag(mesg);
        }

        // send message

        socketaddress sa;
        //socklen_t sa_len = sizeof(sa.sa6);

        if(ISOK(ret = host_address2sockaddr(simple_message->name_server, &sa)))
        {
            //s32 retries = (s32)dns_udp_settings->retry_count;
            s32 retries = simple_message->retries_left;

            do
            {
                // send the packet

                simple_message->sent_time_us = timeus();

                log_notice("send: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) using TCP", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status);

                ret = message_query_tcp_with_timeout(mesg, simple_message->name_server, dns_udp_settings->timeout / 1000000);
                
                simple_message->received_time_us = timeus();
                s64 dt = MAX(simple_message->received_time_us - simple_message->sent_time_us, 0);
                double dts = dt;
                dts/=ONE_SECOND_US_F;
                
                if(ISOK(ret) || ((ret & RCODE_ERROR_BASE) == RCODE_ERROR_BASE))
                {
                    log_notice("receive: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) [%6.3fs] using TCP", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status, dts);

                    simple_message->status &= ~DNS_SIMPLE_MESSAGE_STATUS_COLLECTED;
                    simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_RECEIVED;
                    simple_message->answer = mesg;
                    simple_message->tcp_replied = TRUE;
                    mesg = NULL;

                    dns_udp_simple_message_answer_call_handlers(simple_message);
                    // dns_udp_simple_message_answer_call_handlers does a retain
                    //dns_udp_simple_message_release(simple_message);
                    simple_message = NULL;

                    ret = SUCCESS;

                    break;
                }
                else
                {
                    if(--retries >= 0)
                    {
                        log_warn("send: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) [%6.3fs] using TCP failed: %r, retrying", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status, dts, ret);
                    }
                    else
                    {
                        log_err("send: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) [%6.3fs] using TCP failed: %r, no retries left", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status, dts, ret);
                    }
                }
            }
            while(retries >= 0);
        }
    }
    else
    {
        log_err("send: tcp was unable to allocate a message");
        ret = MAKE_ERRNO_ERROR(ENOMEM);
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
        
        // simple_message = NULL;
    }
    
    if(mesg != NULL)
    {
        message_debug_trash_buffer(mesg);
        pool_release(&message_data_pool, mesg);
    }
   
    // simple_message->async_node.async->handler(simple_message->async_node.async);
    
    return NULL;
}

static void
dns_udp_tcp_query(dns_simple_message_s *simple_message, struct service_worker_s *worker)
{
    dns_udp_tcp_query_thread_params *parms;
    ZALLOC_OBJECT_OR_DIE( parms, dns_udp_tcp_query_thread_params, DNSUTQTP_TAG);
    parms->simple_message = simple_message;
    parms->worker = worker;
    thread_pool_enqueue_call(tcp_query_thread_pool, dns_udp_tcp_query_thread, parms, NULL, "dns-udp-tcp");
}

#endif

void
dns_udp_send_simple_message(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass, u16 flags, async_done_callback *cb, void* cbargs)
{
    log_debug("query: %{hostaddr} %{dnsname} %{dnstype} %{dnsclass} %s", name_server, fqdn, &qtype, &qclass, (flags!=0)?"":"+dnssec");

    async_message_s *domain_message = async_message_alloc();
    
    dns_simple_message_s *simple_message = (dns_simple_message_s*)pool_alloc(&dns_simple_message_pool);
    
#if DEBUG
    memset(simple_message, 0xac, sizeof(dns_simple_message_s));
#endif

    simple_message->name_server = host_address_copy(name_server); // MALLOCATED MEMORY RETURNED
    simple_message->answer = NULL;
    simple_message->async_node.async = domain_message;
    simple_message->async_node.next = NULL;
    simple_message->queued_time_us = timeus();
    simple_message->sent_time_us = MAX_S64;
    simple_message->received_time_us = 0;
    simple_message->qtype = qtype;
    simple_message->qclass = qclass;
    simple_message->retries_left = dns_udp_settings->retry_count;
    simple_message->flags = flags;
    simple_message->dns_id = 0;
    simple_message->status = DNS_SIMPLE_MESSAGE_STATUS_QUEUED;
    simple_message->recurse = FALSE;
    simple_message->tcp = FALSE;
    simple_message->tcp_used = FALSE;
    simple_message->tcp_replied = FALSE;
    
    group_mutex_init(&simple_message->mtx);
#if DNS_SIMPLE_MESSAGE_HAS_WAIT_COND
    cond_init(&simple_message->mtx_cond);
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
}

void
dns_udp_send_recursive_message(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass, u16 flags, async_done_callback *cb, void* cbargs)
{
    log_debug("query: %{hostaddr} %{dnsname} %{dnstype} %{dnsclass} %s (recursive)", name_server, fqdn, &qtype, &qclass, (flags!=0)?"":"+dnssec");

    async_message_s *domain_message = async_message_alloc();
    
    dns_simple_message_s *simple_message = (dns_simple_message_s*)pool_alloc(&dns_simple_message_pool);
    
#if DEBUG
    memset(simple_message, 0xac, sizeof(dns_simple_message_s));
#endif
    
    simple_message->name_server = host_address_copy(name_server); // MALLOCATED MEMORY RETURNED
    simple_message->answer = NULL;
    simple_message->async_node.async = domain_message;
    simple_message->async_node.next = NULL;
    simple_message->queued_time_us = timeus();
    simple_message->sent_time_us = MAX_S64;
    simple_message->received_time_us = 0;
    simple_message->qtype = qtype;
    simple_message->qclass = qclass;
    simple_message->retries_left = dns_udp_settings->retry_count;
    simple_message->flags = flags;
    simple_message->dns_id = 0;
    simple_message->status = DNS_SIMPLE_MESSAGE_STATUS_QUEUED;
    simple_message->recurse = TRUE;
    simple_message->tcp = FALSE;
    simple_message->tcp_used = FALSE;
    simple_message->tcp_replied = FALSE;
    
    group_mutex_init(&simple_message->mtx);
#if DNS_SIMPLE_MESSAGE_HAS_WAIT_COND
    cond_init(&simple_message->mtx_cond);
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
}

struct dns_udp_send_simple_message_sync_s
{
#if __FreeBSD__
    struct async_wait_s* wait;
#else
    struct async_wait_s wait;
#endif
    dns_simple_message_s *simple_message;
};

static void
dns_udp_send_simple_message_sync_handler(struct async_message_s *msg)
{
    dns_simple_message_s *simple_message = (dns_simple_message_s*)msg->args;
    struct dns_udp_send_simple_message_sync_s *args = (struct dns_udp_send_simple_message_sync_s*)msg->handler_args;
    args->simple_message = simple_message;
#if __FreeBSD__
    args->wait->error_code = msg->error_code;
    async_wait_progress(args->wait, 1);
#else
    args->wait.error_code = msg->error_code;
    async_wait_progress(&args->wait, 1);
#endif
    }

ya_result
dns_udp_send_recursive_message_sync(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass, u16 flags, dns_simple_message_s **to_release)
{
    struct dns_udp_send_simple_message_sync_s args;

#if __FreeBSD__
    args.wait = async_wait_new_instance(1);
#else
    async_wait_init(&args.wait, 1);
#endif

    args.simple_message = NULL;
    dns_udp_send_recursive_message(name_server, fqdn, qtype, qclass, flags, dns_udp_send_simple_message_sync_handler, &args);

#if __FreeBSD__
    async_wait(args.wait);
    s32 ret = args.wait->error_code;
#else
    async_wait(&args.wait);
    s32 ret = args.wait.error_code;
#endif

    if(to_release != NULL)
    {
        *to_release = args.simple_message;
    }

#if __FreeBSD__
    async_wait_finalize(args.wait);
#else
    async_wait_finalize(&args.wait);
#endif
    
    return ret;
}

ya_result
dns_udp_send_simple_message_sync(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass, u16 flags, dns_simple_message_s **to_release)
{
    struct dns_udp_send_simple_message_sync_s args;

#if __FreeBSD__
    args.wait = async_wait_new_instance(1);
#else
    async_wait_init(&args.wait, 1);
#endif
    args.simple_message = NULL;
    
    dns_udp_send_simple_message(name_server, fqdn, qtype, qclass, flags, dns_udp_send_simple_message_sync_handler, &args);

#if __FreeBSD__
    async_wait(args.wait);
    s32 ret = args.wait->error_code;
#else
    async_wait(&args.wait);
    s32 ret = args.wait.error_code;
#endif

    if(to_release != NULL)
    {
        *to_release = args.simple_message;
    }

#if __FreeBSD__
    async_wait_finalize(args.wait);
#else
    async_wait_finalize(&args.wait);
#endif
    
    return ret;
}

bool
dns_udp_simple_message_trylock(dns_simple_message_s *message)
{
    log_debug7("dns_udp_simple_message_lock(%p) try locking (#%i)", message, message->rc.value);
    
    if(group_mutex_trylock(&message->mtx, GROUP_MUTEX_WRITE))
    {
        if(message->owner == 0)
        {
            message->owner = thread_self();
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
    
    group_mutex_lock(&message->mtx, GROUP_MUTEX_WRITE);
    
#if DNS_SIMPLE_MESSAGE_HAS_WAIT_COND
    while( message->owner != 0 )
    {
        cond_wait(&message->mtx_cond, &message->mtx);
    }
#endif
    message->owner = thread_self();
    
    log_debug7("dns_udp_simple_message_lock(%p) locked", message);
}

void
dns_udp_simple_message_unlock(dns_simple_message_s *message)
{
    log_debug7("dns_udp_simple_message_lock(%p) unlocking", message);
    //mutex_lock(&message->mtx);
    
    message->owner = 0;
    
#if DNS_SIMPLE_MESSAGE_HAS_WAIT_COND
    cond_notify(&message->mtx_cond);
#endif
        
    group_mutex_unlock(&message->mtx, GROUP_MUTEX_WRITE);
        
    log_debug7("dns_udp_simple_message_lock(%p) unlocked", message);
}

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
#if DEBUG
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
            message_debug_trash_buffer(simple_message->answer);
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
            //--message_collection_size; this one is with keys
            simple_message->async_node.async = NULL;
        }
        
        dns_simple_message_async_node_s *node = simple_message->async_node.next;
        
        while(node != NULL)
        {
            if(node->async != NULL)
            {
                async_message_release(node->async);
                --message_collection_size;
                node->async = NULL;
            }
            
            dns_simple_message_async_node_s *prev = node;
            
            node = node->next;
#if DEBUG
            memset(prev, 0xd7, sizeof(dns_simple_message_async_node_s));
#endif
            pool_release(&dns_simple_message_async_node_pool, prev);
        }
        
        simple_message->async_node.next = NULL;
        
        // release the mutexes
#if DNS_SIMPLE_MESSAGE_HAS_WAIT_COND
        cond_finalize(&simple_message->mtx_cond);
#endif
        group_mutex_destroy(&simple_message->mtx);

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
#if !DEBUG
        log_debug7("dns_udp_simple_message_release(%p) (%x)", simple_message, n);
#else
        log_debug7("dns_udp_simple_message_release(%p) (%x) : %{dnsname} %{dnstype} %{dnsclass}", simple_message, n, fqdn, &qtype, &qclass);
#endif
    }
}

static void
dns_udp_aggregate_simple_messages(dns_simple_message_s *head, dns_simple_message_s *tail)
{
    dns_simple_message_async_node_s *node = (dns_simple_message_async_node_s*)pool_alloc(&dns_simple_message_async_node_pool);
    
    dns_udp_simple_message_lock(head);
    dns_udp_simple_message_lock(tail);

    log_debug6("dns_udp_aggregate_simple_messages(%p, %p) head %p->%p", head, tail, &head->async_node, head->async_node.next);

    // prepare the container to match the simple message's
    // append the current list to the new node (should be only one item)
    node->next = tail->async_node.next;        //
    node->async = tail->async_node.async;
    tail->async_node.next = NULL;
    tail->async_node.async = NULL;
    node->async->args = head;                   // change the linked message to the first one

    log_debug6("dns_udp_aggregate_simple_messages(%p, %p) edit %p->%p", head, tail, node, node->next);

    // update the first_message for the whole list (every time ?)
    dns_simple_message_async_node_s *sm_last_node = node;
    while(sm_last_node->next != NULL)
    {
        sm_last_node = sm_last_node->next;
        log_debug6("dns_udp_aggregate_simple_messages(%p, %p) edit %p->%p. Updating message as %p (was %p)", head, tail, sm_last_node, sm_last_node->next, sm_last_node->async->args, head);
        sm_last_node->async->args = head;                      // change the linked message to the first one
    }

    // last node of the list, append the original list to the current list

    sm_last_node->next = head->async_node.next;
    head->async_node.next = node;

    // the list is ready

#if DEBUG
    while(node != NULL)
    {
        log_debug6("dns_udp_aggregate_simple_messages(%p, %p) node %p=>%p", head, tail, node, node->next);
        node = node->next;
    }
#endif

    head->status |= DNS_SIMPLE_MESSAGE_STATUS_AGGREGATED;
    
    // added

    sendto_packets_aggregated++;

    log_debug5("added message@%p to message@%p: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} %s (%x)",
            tail, head, head->fqdn, &head->qtype, &head->qclass, head->name_server, (head->recurse)?"rd":"",
            head->status);
    
    // adding a query grants a new retry
    
    head->retries_left = dns_udp_settings->retry_count + 1;

    dns_udp_simple_message_unlock(tail); // unlock B
    dns_udp_simple_message_unlock(head);
}



static int dns_udp_receive_service_hook(dns_simple_message_s *simple_message, message_data *mesg);

static bool
dns_udp_send_simple_message_process_hook_default(dns_simple_message_s *simple_message, message_data *mesg)
{
    (void)simple_message;
    (void)mesg;
    return FALSE;
}

static dns_udp_query_hook *dns_udp_send_simple_message_process_hook = dns_udp_send_simple_message_process_hook_default;

/**
 * Called by the send worker(s) to do a query
 * 
 * The return value is ignored by its only caller.
 */

static int
dns_udp_send_simple_message_process(async_message_s *domain_message, random_ctx rndctx, u16 source_port, int source_socket, u32 worker_index)
{
    dns_simple_message_s *simple_message = (dns_simple_message_s*)domain_message->args;
    
    // check if in pending collection
    
#if DEBUG
    if(domain_message->start_time < 0)
    {
        logger_flush();
        abort();
    }
#endif
    


    // pre-increase the RC because of this new reference (into the DB)
    dns_udp_simple_message_retain(simple_message);
    /// @note: at this point, in a normal usage, the RC of simple_message should be 2
    
    // lock the collection

    log_debug7("sending: locking message collection");

    mutex_lock(&message_collection_mtx); // lock A

    log_debug7("sending: message collection locked");

    // lock the simple message
    dns_udp_simple_message_lock(simple_message); // lock B

    ptr_node *node = ptr_set_find(&message_collection, simple_message);

    if((node == NULL) || (node->value == NULL))
    {
        u32 simple_message_size = DNS_HEADER_LENGTH + dnsname_len(simple_message->fqdn) + 4 + 11;

        u64 delay_epoch_us = dns_udp_host_state_packet_try(simple_message->name_server, simple_message_size);

        if(delay_epoch_us > 0)
        {
            dns_udp_simple_message_unlock(simple_message); // unlock B
            mutex_unlock(&message_collection_mtx); // unlock A

            dns_udp_simple_message_release(simple_message);

            // delay
            log_debug4("delaying: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) to %llT (from %llT)",
                       simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status,
                       delay_epoch_us, timeus());

            delayed_message_insert(delay_epoch_us, domain_message);
            return SUCCESS;
        }

        if(node == NULL)
        {
            node = ptr_set_insert(&message_collection, simple_message);
        }

        ++message_collection_keys;

        // newly inserted
        // put in pending collection
        // RC already increased

        node->value = domain_message;

        simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_COLLECTED;
        simple_message->status &= ~DNS_SIMPLE_MESSAGE_STATUS_QUEUED;
        dns_udp_simple_message_unlock(simple_message);

        mutex_unlock(&message_collection_mtx); // unlock A

        log_debug7("sending: message collection unlocked");

        int return_code;

        // we have allocated the right to send the query

        mutex_lock(&limiter_send_wait_mtx);
        // this one is a loose test
        // there cannot be a reasonable blocking lock with the sender
        // so for now I focus on having it's content added properly (senders are locking each-other for a few microseconds)
        // and I only ensure the memory wall is applied using the send mutex
        //
        // the next two waits are perfectly normal
        //
        // note: maybe I should use a group mutex as they are better equipped for potential long waits

        log_debug4("sender: waiting for the receiving bandwidth to be low enough");
        limiter_wait(&dns_udp_recv_bandwidth, 0);
        log_debug4("sender: waiting for the send rate to be low enough");
        limiter_wait(&dns_udp_send_rate, 1);
        log_debug4("sender: waiting for the send bandwidth to be low enough");
        limiter_wait(&dns_udp_send_bandwidth, simple_message_size);
        mutex_unlock(&limiter_send_wait_mtx);

        // don't give a sent time until it's actually sent (high loads could trigger a timeout before the packet is sent)

        simple_message->sent_time_us = MAX_S64;

        // if the message is retried, use the same address:port as before

        if(simple_message->sender_socket < 0)
        {
            log_debug("sending: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x)", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status);

            simple_message->sender_socket = source_socket;
            simple_message->worker_index = worker_index;
            simple_message->source_port = source_port;
        }
        else
        {
            log_debug("sending: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) again", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status);

            source_socket = simple_message->sender_socket;
            //worker_index = simple_message->worker_index;
            //source_port = simple_message->source_port;
        }

        dns_udp_simple_message_lock(simple_message);
        log_debug5("set message@%p: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} %s (%x)",
                   domain_message, simple_message->fqdn,
                   &simple_message->qtype, &simple_message->qclass,
                   simple_message->name_server, (simple_message->recurse)?"rd":"",
                   simple_message->status);

        // generate message

        message_data_with_buffer mesg_buff;
        message_data *mesg = message_data_with_buffer_init(&mesg_buff);

        // message_send_udp_reset(mesg);

        if(simple_message->dns_id == 0)
        {
            simple_message->dns_id = (u16)random_next(rndctx);
        }

        message_make_query_ex(mesg, simple_message->dns_id, simple_message->fqdn, simple_message->qtype, simple_message->qclass, simple_message->flags);

        if(simple_message->recurse)
        {
            message_set_rd_flag(mesg);
        }

        // send message

        //
        // answer = send back to sender
        //

        return_code = message_set_sender_from_host_address(mesg, simple_message->name_server);

        dns_udp_simple_message_unlock(simple_message);

        if(ISOK(return_code))
        {
            if(!dns_udp_send_simple_message_process_hook(simple_message, mesg))
            {
                for(;;)
                {
                    // send the packet

                    //if((return_code = sendto(s, mesg->buffer, mesg->send_length, 0, &sa.sa, sa_len)) == mesg->send_length)

                    if((return_code = message_send_udp(mesg, source_socket)) == (s32)message_get_size(mesg))
                    {
                        dns_udp_simple_message_lock(simple_message);
                        simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_SENT;

                        log_notice("sent: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) (@%p)", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status, simple_message);

                        simple_message->sent_time_us = timeus();
                        dns_udp_simple_message_unlock(simple_message); // unlock B

                        // one RC can be released from this reference
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

                            log_debug("sent: total=%db/s (packets=%d/aggregated=%d/s)", st, sq, sqa);
                        }

                        // </statistics>

                        return return_code;
                    }

                    // an error occurred

                    if((return_code != MAKE_ERRNO_ERROR(EAGAIN)) && (return_code != MAKE_ERRNO_ERROR(EWOULDBLOCK)))
                    {
                        // return_code = MAKE_ERRNO_ERROR(err);

                        break;
                    }

                    // try again
                }
            }
            else // the hook did something
            {
                if((simple_message->status & DNS_SIMPLE_MESSAGE_STATUS_TIMEDOUT) == 0)
                {
                    dns_udp_receive_service_hook(simple_message, mesg);
                }

                dns_udp_simple_message_release(simple_message);

                return SUCCESS;
            }
        }

        // error occurred while sending the message

        dns_udp_simple_message_lock(simple_message);

        simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_FAILURE;

        log_err("sending: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x): %r",
                simple_message->fqdn, &simple_message->qtype, &simple_message->qclass,
                simple_message->name_server, simple_message->status, return_code);

        dns_udp_simple_message_unlock(simple_message);

        mutex_lock(&message_collection_mtx);
        // ensure that the node still exists
        ptr_node *simple_message_node = ptr_set_find(&message_collection, simple_message);
        if(simple_message_node != NULL)
        {
            ptr_set_delete(&message_collection, simple_message);
            --message_collection_keys;
            // one RC can be released for the collection
            dns_udp_simple_message_lock(simple_message);
            simple_message->status &= ~DNS_SIMPLE_MESSAGE_STATUS_COLLECTED;
            dns_udp_simple_message_unlock(simple_message);
            dns_udp_simple_message_release(simple_message);
        }
        else
        {
            // even if this is possible, this should NEVER happen
            log_debug6("message @%p had been removed from the collection already", simple_message);
        }
        mutex_unlock(&message_collection_mtx);

        log_debug7("sending: message collection unlocked");

        /// @note RC = 1
        // the handler NEEDS to do the final release

        domain_message->error_code = return_code;
        domain_message->handler(domain_message);

        return return_code;
    }
    else // probable aggregation
    {
        simple_message->sent_time_us = timeus();
        simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_COLLECTED;
        simple_message->status &= ~DNS_SIMPLE_MESSAGE_STATUS_QUEUED;
        dns_udp_simple_message_unlock(simple_message);

        log_debug("sending: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) aggregated", simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status);

        // append the async callback to the dns_simple_message structure
        
        // the first message for this query, it will reference the new message
        dns_simple_message_s *old_message = (dns_simple_message_s *)node->key;
        
        // aggregate /append simple_message to first_message
        
        dns_udp_aggregate_simple_messages(old_message, simple_message);
        ++message_collection_size;
        
        mutex_unlock(&message_collection_mtx);
        
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
    
    struct dns_udp_receive_ctx *ctx = dns_udp_receive_context[worker->worker_index];
    
    rndctx = thread_pool_get_random_ctx();
    
    ZEROMEMORY(&sin6, sizeof(sin6));
    socklen_t sin6len = sizeof(sin6);
    getsockname(my_socket, (struct sockaddr*)&sin6, &sin6len);

    const u16 source_port = sin6.sin6_port;

    bool threadpool_pacing = FALSE;

    while(service_should_run(worker) /*|| !async_queue_empty(&dns_udp_send_handler_queue)*/)
    {
        // timeout high priority list.
        
        async_message_s *domain_message;

        // callback threadpool pacing

        if(dns_udp_settings->callback_queue_size > 0)
        {
            s64 r = thread_pool_queue_size(dns_udp_callback_tp);
            r *= 100;
            r /= dns_udp_settings->callback_queue_size;

            if(r > 95) // 95% full => pause
            {
                usleep(100000);

                if(!threadpool_pacing)
                {
                    log_debug("dns-udp: threadpool queue is almost full: pacing");
                    threadpool_pacing = TRUE;
                }

                continue;
            }
        }

        if(threadpool_pacing)
        {
            log_debug("dns-udp: threadpool queue has reached acceptable levels: resuming");
            threadpool_pacing = FALSE;
        }

        //

        size_t read_avail = dns_udp_receive_ctx_available(ctx);
        if(read_avail < 4)
        {
            log_debug("send: pausing as the buffer of receiver #%i is almost full: %lli slots available", worker_index, read_avail);
            usleep(20000);
            continue;
        }
        
        // I'm using the worker lock to synchronise with its counterpart,
        // so I don't have to create yet another mutex
        
        mutex_lock(&worker->lock);
        domain_message = list_dl_dequeue(&dns_udp_high_priority[worker_index]);
        mutex_unlock(&worker->lock);

        if(domain_message == NULL)
        {
            domain_message = delayed_message_next();
            
            if(domain_message == NULL)
            {
                domain_message = async_message_next(&dns_udp_send_handler_queue); // this call waits if nothing is available

                if(domain_message == NULL)
                {
                    continue;
                }
                else
                {
                    dns_simple_message_s *simple_message = (dns_simple_message_s*)domain_message->args;

                    log_debug3("send: next: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x)",
                            simple_message->fqdn, &simple_message->qtype, &simple_message->qclass,
                            simple_message->name_server, simple_message->status);
                }
            }
            else
            {
                dns_simple_message_s *simple_message = (dns_simple_message_s*)domain_message->args;

                log_debug3("send: delayed: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x)",
                        simple_message->fqdn, &simple_message->qtype, &simple_message->qclass,
                        simple_message->name_server, simple_message->status);
            }
        }
        else
        {
            dns_simple_message_s *simple_message = (dns_simple_message_s*)domain_message->args;

            log_debug3("send: timedout: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x)",
                    simple_message->fqdn, &simple_message->qtype, &simple_message->qclass,
                    simple_message->name_server, simple_message->status);
            
            if(dns_udp_settings->tcp_fallback_on_timeout)
            {
                simple_message->tcp |= simple_message->retries_left == 0;
            }
        }
        
        log_debug6("send: processing message (%u still in queue)", async_queue_size(&dns_udp_send_handler_queue));

        switch(domain_message->id)
        {
            case DNS_UDP_SIMPLE_QUERY:
            {
                log_debug6("DNS_UDP_SIMPLE_QUERY");

                dns_simple_message_s *simple_message = (dns_simple_message_s*)domain_message->args;

                if(!simple_message->tcp)
                {
                    log_debug3("send: next: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) (udp)",
                               simple_message->fqdn, &simple_message->qtype, &simple_message->qclass,
                               simple_message->name_server, simple_message->status);
                    dns_udp_send_simple_message_process(domain_message, rndctx, source_port, my_socket, worker_index);
                }
                else
                {
                    log_debug3("send: next: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) (tdp)",
                               simple_message->fqdn, &simple_message->qtype, &simple_message->qclass,
                               simple_message->name_server, simple_message->status);

                    dns_udp_tcp_query(simple_message, worker);
                }
                break;
            }
            default:
            {
                log_err("DNS_UDP_? %u", domain_message->id);
                domain_message->error_code = SERVICE_ID_ERROR;
                domain_message->handler(domain_message);
                break;
            }
        }        
    }
        
    service_set_stopping(worker);

    log_debug("send: service stopped (%u/%u)", worker_index + 1, worker->service->worker_count);

    return 0;
}

typedef u8 message_4k[4096];
struct aligned_socketaddress
{
    socketaddress sa;
    socklen_t sa_len;
    size_t msg_len;
    time_t epoch;
    
    
    // char padding[1024 - sizeof(socketaddress) - sizeof(size_t) * 2 - sizeof(time_t)];
};
typedef struct aligned_socketaddress aligned_socketaddress;

struct dns_udp_receive_ctx
{
    mutex_t mtx;
    cond_t cond;
    u8* messages_unaligned;
    u8* addreses_unaligned;
    message_4k *messages; // = malloc(message_buffer_count * sizeof(message_4k));
    aligned_socketaddress *addresses; // = malloc(message_buffer_count * sizeof(socketaddress));
    size_t count;                                   // total number of slots
#ifndef WIN32
    size_t read_index __attribute__((aligned(64))); // where incoming messages can be read
    size_t proc_index __attribute__((aligned(64))); // where processor can get its next one
    //size_t read_avail __attribute__((aligned(64))); // how many incoming slots are available
#else
    size_t read_index; // where incoming messages can be read
    size_t proc_index; // where processor can get its next one
    //size_t read_avail; // how many incoming slots are available
#endif
};

typedef struct dns_udp_receive_ctx dns_udp_receive_ctx;

static dns_udp_receive_ctx*
dns_udp_receive_ctx_init(size_t count)
{
    dns_udp_receive_ctx *ctx;
    ZALLOC_OBJECT_OR_DIE(ctx, dns_udp_receive_ctx, DNSURECV_TAG);
    //group_mutex_init(&ctx->mtx);
    mutex_init(&ctx->mtx);
    cond_init(&ctx->cond);
    MALLOC_OR_DIE(u8*, ctx->messages_unaligned, count * sizeof(message_4k) + 4095, DNSURMU_TAG);
    MALLOC_OR_DIE(u8*, ctx->addreses_unaligned, count * sizeof(aligned_socketaddress) + 63, DNSURAU_TAG);
    ctx->messages = (message_4k*)(((intptr)ctx->messages_unaligned + 4095) & ~4095);
    ctx->addresses = (aligned_socketaddress*)(((intptr)ctx->addreses_unaligned + 63) & ~63);
    ctx->count = count;
    ctx->read_index = 0; // avail = count - (r - p)
    ctx->proc_index = 0; // while p!=r: process, ++p
    for(size_t i = 0; i < count; ++i)
    {
        ctx->addresses->sa_len = sizeof(socketaddress);
        ctx->addresses->msg_len = 0;
    }
    //ctx->read_avail = count;
    
    return ctx;
}

static void
dns_udp_receive_ctx_destroy(dns_udp_receive_ctx *ctx)
{
    free(ctx->messages_unaligned);
    free(ctx->addreses_unaligned);
    //group_mutex_destroy(&ctx->mtx);
    cond_finalize(&ctx->cond);
    mutex_destroy(&ctx->mtx);    
    ZFREE_OBJECT(ctx);
}

static size_t
dns_udp_receive_ctx_available(dns_udp_receive_ctx *ctx)
{
    mutex_lock(&ctx->mtx);
    size_t avail = ctx->count - (ctx->read_index - ctx->proc_index);
    mutex_unlock(&ctx->mtx);
    return avail;
}

static ssize_t
dns_udp_receive_ctx_wait_to_read(dns_udp_receive_ctx *ctx)
{
    mutex_lock(&ctx->mtx);
    for(;;)
    {
        size_t avail = ctx->count - (ctx->read_index - ctx->proc_index);
        
        if(avail != 0)
        {
            break;
        }
        
        if(cond_timedwait(&ctx->cond, &ctx->mtx, 1000000ULL) != 0)
        {
            mutex_unlock(&ctx->mtx);
            return -1;
        }
    }
    mutex_unlock(&ctx->mtx);
    
    return ctx->read_index % ctx->count;
}

static void
dns_udp_receive_ctx_notify_read(dns_udp_receive_ctx *ctx)
{
    mutex_lock(&ctx->mtx);
    ++ctx->read_index;
    cond_notify(&ctx->cond);
    mutex_unlock(&ctx->mtx);
}

static ssize_t
dns_udp_receive_ctx_wait_to_process(dns_udp_receive_ctx *ctx)
{
    mutex_lock(&ctx->mtx);
    for(;;)
    {
        if(ctx->proc_index < ctx->read_index)
        {
            break;
        }
            
        if(cond_timedwait(&ctx->cond, &ctx->mtx, 1000000ULL) != 0)
        {
            mutex_unlock(&ctx->mtx);
            return -1;
        }
    }
    mutex_unlock(&ctx->mtx);
    
    return ctx->proc_index % ctx->count;
}

static void
dns_udp_receive_ctx_notify_process(dns_udp_receive_ctx *ctx)
{
    mutex_lock(&ctx->mtx);
    ++ctx->proc_index;
    cond_notify(&ctx->cond);
    mutex_unlock(&ctx->mtx);
}

static int
dns_udp_receive_read_service(struct service_worker_s *worker)
{
    log_debug("receive: service read started (%u/%u)", worker->worker_index + 1, worker->service->worker_count);
    
    int my_socket = dns_udp_socket[worker->worker_index];
    dns_udp_receive_ctx *ctx = dns_udp_receive_context[worker->worker_index];
    

    
    // u16 port;
    
    struct sockaddr_in6 sin6;
    ZEROMEMORY(&sin6, sizeof(sin6));
    socklen_t sin6len = sizeof(sin6);
    getsockname(my_socket, (struct sockaddr*)&sin6, &sin6len);
    
    log_debug("receive: listening on %{sockaddr}", &sin6);
    
    tcp_set_recvtimeout(my_socket, dns_udp_settings->timeout / ONE_SECOND_US, dns_udp_settings->timeout % ONE_SECOND_US);

    s64 last_loop = timeus();
    
    while(service_should_run(worker))
    {
        int n;
        
        ssize_t index = dns_udp_receive_ctx_wait_to_read(ctx);
        
        if(index < 0)
        {
#if DEBUG
            log_debug7("receive: wait to read");
#endif
            continue;
        }

        ctx->addresses[index].sa_len = sizeof(socketaddress);

        s64 now = timeus();
        s64 elapsed = now - last_loop;

        log_debug6("receive: recvfrom(%i, %p, %lli, %i, %p, %p=%i) in %lli (elapsed: %llu)", my_socket, &ctx->messages[index], sizeof(ctx->messages[index]), 0, &ctx->addresses[index].sa.sa, &ctx->addresses[index].sa_len, ctx->addresses[index].sa_len, index, elapsed);

        n = recvfrom(my_socket, &ctx->messages[index], sizeof(ctx->messages[index]), 0, &ctx->addresses[index].sa.sa, &ctx->addresses[index].sa_len);

        last_loop = timeus();

        if(n >= 0)
        {
            if(n > 0)
            {
                log_debug6("receive: recvfrom(%i, ... , %{sockaddr}) = %i", my_socket, &ctx->addresses[index].sa.sa, n);

                ctx->addresses[index].epoch = time(NULL);
                ctx->addresses[index].msg_len = n;
                dns_udp_receive_ctx_notify_read(ctx);
            }
            else
            {
                log_debug6("receive: recvfrom(%i, ... , %{sockaddr}) = 0 = empty packet (ignoring)", my_socket, &ctx->addresses[index].sa.sa);
            }
        }
        else
        {
            int err = errno;

            if(err == EINTR)
            {
#if DEBUG
                log_debug7("receive: recvfrom EINTR");
#endif
                continue;
            }
            if(err == EAGAIN)
            {
#if DEBUG
                log_debug7("receive: recvfrom EAGAIN");
#endif
                continue;
            }
                
            log_err("receive: recvfrom error: %r", MAKE_ERRNO_ERROR(err));
        }
    }
    
    service_set_stopping(worker);

    log_debug("receive: service read stopped (%u/%u)", worker->worker_index + 1, worker->service->worker_count);
    
    return SUCCESS;
}
           
static int
dns_udp_receive_process_service(struct service_worker_s *worker)
{
    log_debug("receive: service process started (%u/%u)", worker->worker_index + 1, worker->service->worker_count);
    
    int my_socket = dns_udp_socket[worker->worker_index];
    dns_udp_receive_ctx *ctx = dns_udp_receive_context[worker->worker_index];
    
    struct sockaddr_in6 sin6;
    ZEROMEMORY(&sin6, sizeof(sin6));
    socklen_t sin6len = sizeof(sin6);
    getsockname(my_socket, (struct sockaddr*)&sin6, &sin6len);
    
    message_data *mesg;
    
    for(;;)
    {
        mesg = (message_data*)pool_alloc(&message_data_pool);
        
        if(mesg != NULL)
        {
            break;
        }
        
        if(!service_should_run(worker))
        {
            service_set_stopping(worker);
            
            log_debug("receive: service process stopped (%u/%u) (early)", worker->worker_index + 1, worker->service->worker_count);
            
            return 0;
        }
        
        sleep(1);
    }
    
    host_address sender_host_address;
    
    while(service_should_run(worker))
    {
        log_debug("receive: waiting %i / next", my_socket);

        ssize_t index = dns_udp_receive_ctx_wait_to_process(ctx);
        
        if(index < 0)
        {
            log_debug("receive: timed-out %i / next", my_socket);
            continue;
        }
        
        log_debug("receive: processing %i / %lli", my_socket, index);

        size_t n = ctx->addresses[index].msg_len;
        time_t now = ctx->addresses[index].epoch;

        mutex_lock(&limiter_recv_wait_mtx);
        // force add the received bytes to the limit (this feels insufficient)
        limiter_add_anyway(&dns_udp_recv_bandwidth, n, NULL, NULL);
        mutex_unlock(&limiter_recv_wait_mtx);

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

        log_debug2("receive: statistics updated %i", my_socket);

        message_reset_buffer_size(mesg);
        message_copy_into_buffer(mesg, ctx->messages[index], n); // scan-build false-positive: mesg is not NULL, thus buffer cannot be NULL
        message_copy_sender_from_sa(mesg, &ctx->addresses[index].sa.sa, ctx->addresses[index].sa_len);
            
        ya_result return_code;

        if(ISOK(return_code = message_process_lenient(mesg)))
        {
            // look in the timeout collection

            host_address_set_with_sockaddr(&sender_host_address, message_get_sender(mesg));

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

            int len = dnsname_copy(message.fqdn, message_get_canonised_fqdn(mesg));

            if(ISOK(len))
            {
                message.qtype = message_get_u16_at(mesg, 12 + len);
                message.qclass = message_get_u16_at(mesg, 12 + len + 2);

                // remove it from the collection

                log_debug7("receive: locking message collection", my_socket);

                mutex_lock(&message_collection_mtx);

                log_debug7("receive: seeking matching message", my_socket);

                ptr_node *node = ptr_set_find(&message_collection, &message);

                if(node != NULL)
                {
                    // proceed

                    bool truncated = message_istruncated(mesg);

                    dns_simple_message_s *simple_message = (dns_simple_message_s*)node->key;

                    dns_udp_simple_message_lock(simple_message);

                    log_debug2("receive: deleting message", my_socket);

                    ptr_set_delete(&message_collection, simple_message);
                    --message_collection_keys;

                    // the message is not in the timeout collection anymore
                    // it should contain an answer, or an error, ... or a message with the TC bit on

                    if(!truncated)
                    {
                        simple_message->status &= ~DNS_SIMPLE_MESSAGE_STATUS_COLLECTED;
                        simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_RECEIVED;
                    }

                    dns_udp_simple_message_unlock(simple_message);

                    mutex_unlock(&message_collection_mtx);

                    log_debug7("receive: message collection unlocked", my_socket);

                    // RC is supposed to be 1
#if DEBUG
                    if(simple_message->rc.value != 1)
                    {
                        log_warn("receive: message RC is not 1 (%i)", simple_message->rc.value);
                    }
#endif
                    simple_message->received_time_us = timeus();
                    s64 dt = MAX(simple_message->received_time_us - simple_message->sent_time_us, 0);
                    double dts = dt;
                    dts /= ONE_SECOND_US_F;

#if HAS_TC_FALLBACK_TO_TCP_SUPPORT
                    if(!truncated)
                    {
#endif
                        simple_message->answer = mesg;

                        log_notice("receive: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) [%6.3fs]", message.fqdn, &message.qtype, &message.qclass, message.name_server, simple_message->status, dts);

                        dns_udp_simple_message_answer_call_handlers(simple_message);

                        // simple_message = NULL; // not necessarry, but informative

                        // allocate the next buffer, handle the hard_limit of the pool:
                        // when the pool has reached peak capacity, allocation returns NULL

                        mesg = dns_udp_allocate_message_data(worker);
#if HAS_TC_FALLBACK_TO_TCP_SUPPORT
                    }
                    else
                    {
                        // the message has been truncated
                        // it should be queried again using TCP

                        log_notice("receive: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) [%6.3fs]: truncated", message.fqdn, &message.qtype, &message.qclass, message.name_server, simple_message->status, dts);

                        dns_udp_tcp_query(simple_message, worker);
                    }
#endif
                }
                else
                {
                    mutex_unlock(&message_collection_mtx);

                    log_debug7("receive: message collection unlocked", my_socket);

                    // unknown

                    log_warn("receive: unexpected message %{dnsname} %{dnstype} %{dnsclass} from %{sockaddr}", message.fqdn, &message.qtype, &message.qclass, message_get_sender_sa(mesg));
                }
            }
            else
            {
                log_err("receive: an error occurred while copying the name '%{dnsname}': %r", message_get_canonised_fqdn(mesg), len);
            }
        }
        else
        {
            if(service_should_run(worker))
            {
#if DEBUG
                log_memdump(g_system_logger, MSG_DEBUG3, message_get_buffer_const(mesg), message_get_size(mesg), 32);
#endif
                log_err("receive: cannot handle answer: %r", return_code);
            }
        }
        
        dns_udp_receive_ctx_notify_process(ctx);
    }
    
    if(mesg != NULL)
    {
        message_debug_trash_buffer(mesg);
        pool_release(&message_data_pool, mesg);
    }
    
    service_set_stopping(worker);

    log_debug("receive: service process stopped (%u/%u)", worker->worker_index + 1, worker->service->worker_count);
    
    return 0;
}

static void
dns_udp_timeout_service_cull(ptr_vector *todeletep)
{
    int messages_count = 0;
    int failed_tries = 0;

    log_debug7("timeout: locking message collection");

    if(mutex_trylock(&message_collection_mtx))
    {
        log_debug7("timeout: message collection locked");

        ptr_set_iterator iter;
        ptr_set_iterator_init(&message_collection, &iter);
        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *node = ptr_set_iterator_next_node(&iter);
            dns_simple_message_s *simple_message = (dns_simple_message_s *)node->key;

            messages_count++;

            if(dns_udp_simple_message_trylock(simple_message))
            {
                s64 now = timeus();

                if(simple_message->sent_time_us != MAX_S64)
                {
    #if DEBUG
                    if(now <  simple_message->sent_time_us)
                    {
                        log_debug("message was sent %llT in the future! (sent at %llT, now is %llT, really %llT)", simple_message->sent_time_us - now, simple_message->sent_time_us, now, timeus());
                    }
    #endif

                    if((simple_message->status & DNS_SIMPLE_MESSAGE_STATUS_SENT) != 0)
                    {
                        if((simple_message->status & DNS_SIMPLE_MESSAGE_STATUS_RECEIVED) == 0)
                        {
                            if(now - simple_message->sent_time_us > dns_udp_settings->timeout) // older than 3s ? => remove
                            {
                                // timed out

                                // retain because the reference is now in two collection
                                dns_udp_simple_message_retain(simple_message);

                                simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_TIMEDOUT;
                                ptr_vector_append(todeletep, simple_message);
                            }
                        }
                    }
                }
                // else this message has not been sent yet

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

        for(int i = 0; i <= ptr_vector_last_index(todeletep); i++)
        {
            dns_simple_message_s *simple_message = (dns_simple_message_s *)ptr_vector_get(todeletep, i);

            ptr_set_delete(&message_collection, simple_message);
            // release because it has been removed from one collection
            --message_collection_keys;
            dns_udp_simple_message_release(simple_message);

            simple_message->status &= ~DNS_SIMPLE_MESSAGE_STATUS_COLLECTED;
        }

        mutex_unlock(&message_collection_mtx);

        log_debug7("timeout: message collection unlocked");
    }
    else
    {
        log_debug7("timeout: failed to lock message collection");
    }
}

static int
dns_udp_timeout_service(struct service_worker_s *worker)
{
    log_debug("dns_udp_timeout_service started");

    ptr_vector todelete = PTR_VECTOR_EMPTY;
    
    while(service_should_run(worker))
    {
        sleep(1);
        
        if(!service_should_run(worker))
        {
            break;
        }
        
        ptr_vector_clear(&todelete);
        
        dns_udp_timeout_service_cull(&todelete);
        
        s64 now = timeus();

        for(int i = 0; i <= ptr_vector_last_index(&todelete); i++)
        {
            dns_simple_message_s *simple_message = (dns_simple_message_s *)ptr_vector_get(&todelete, i);
            
            log_debug("timeout: [r=%i] %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) (sent at %llT, now is %llT)",
                simple_message->retries_left, simple_message->fqdn, &simple_message->qtype, &simple_message->qclass,
                simple_message->name_server, simple_message->status, simple_message->sent_time_us, now);

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

                double dts = now - simple_message->sent_time_us;
                dts /= ONE_SECOND_US_F;
                log_notice("receive: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) timed-out [%6.3fs]",
                        simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status,
                           dts);

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

void
dns_udp_cancel_all_queries()
{
    int messages_count = 0;
    int failed_tries = 0;
    
    ptr_vector todelete = PTR_VECTOR_EMPTY;

    s64 now = timeus();
    
    mutex_lock(&message_collection_mtx);

    ptr_set_iterator iter;
    ptr_set_iterator_init(&message_collection, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        dns_simple_message_s *simple_message = (dns_simple_message_s *)node->key;

        messages_count++;

        if(dns_udp_simple_message_trylock(simple_message))
        {
            now = timeus();

            if(simple_message->sent_time_us != MAX_S64)
            {
#if DEBUG
                if(now <  simple_message->sent_time_us)
                {
                    log_debug("message was sent %llT in the future! (sent at %llT, now is %llT, really %llT)", simple_message->sent_time_us - now, simple_message->sent_time_us, now, timeus());
                }
#endif

                if(now - simple_message->sent_time_us > dns_udp_settings->timeout) // older than 3s ? => remove
                {
                    // timed out

                    // retain because the reference is now in two collection
                    dns_udp_simple_message_retain(simple_message);

                    simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_TIMEDOUT|DNS_SIMPLE_MESSAGE_STATUS_INVALID;
                    ptr_vector_append(&todelete, simple_message);
                }
            }
#if DEBUG
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

    for(int i = 0; i <= ptr_vector_last_index(&todelete); i++)
    {
        dns_simple_message_s *simple_message = (dns_simple_message_s *)ptr_vector_get(&todelete, i);

        ptr_set_delete(&message_collection, simple_message);
        --message_collection_keys;
        // release because it has been removed from one collection
        dns_udp_simple_message_release(simple_message);

        simple_message->status &= ~DNS_SIMPLE_MESSAGE_STATUS_COLLECTED;
    }

    mutex_unlock(&message_collection_mtx);
    
    for(int i = 0; i <= ptr_vector_last_index(&todelete); i++)
    {
        dns_simple_message_s *simple_message = (dns_simple_message_s *)ptr_vector_get(&todelete, i);

        log_debug("cancel: [r=%i] %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) (sent at %llT, now is %llT)", simple_message->retries_left, simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status, simple_message->sent_time_us, now);
        
        simple_message->received_time_us = MAX_U64;

        yassert(now >= simple_message->sent_time_us);

        double dts = now - simple_message->sent_time_us;
        dts /= ONE_SECOND_US_F;
        log_notice("cancel: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) cancelled [%6.3fs]",
                simple_message->fqdn, &simple_message->qtype, &simple_message->qclass, simple_message->name_server, simple_message->status,
                dts);

        dns_simple_message_async_node_s *node = simple_message->async_node.next;
        while(node != NULL)
        {
            // the handler MUST release one reference
            dns_udp_simple_message_retain(simple_message);
            node->async->error_code = DNS_UDP_CANCEL;
            node->async->handler(node->async);
            node = node->next;
        }

        // there is no need to retain, the reference from the collection has not been decreased yet
        simple_message->async_node.async->error_code = DNS_UDP_CANCEL;
        simple_message->async_node.async->handler(simple_message->async_node.async);
    }
}

u32
dns_udp_send_queue_size()
{
    u32 ret = async_queue_size(&dns_udp_send_handler_queue);
    return ret;
}

u32
dns_udp_pending_queries_count()
{
    return message_collection_keys;
}

u32
dns_udp_pending_feedback_count()
{
    return message_collection_keys + message_collection_size;
}

/**
 * Sets a hook for queries.
 * 
 * The hook is called by the service on each messages and is expected to answer
 * TRUE if it wrote an answer on it
 * FALSE if it did not
 * 
 * Every use of the dns_udp service is affected by this.
 * Only one hook is possible at a given time.
 * 
 * @param hook a function or NULL to reset to no HOOK.
 */

void
dns_udp_set_query_hook(dns_udp_query_hook *hook)
{
    if(hook != NULL)
    {
        dns_udp_send_simple_message_process_hook = hook;
    }
    else
    {
        dns_udp_send_simple_message_process_hook = dns_udp_send_simple_message_process_hook_default;
    }
}

static int
dns_udp_receive_service_hook(dns_simple_message_s *simple_message, message_data *mesg)
{
    (void)simple_message;

    host_address sender_host_address;
    int n = message_get_size(mesg);
    
    if(n > 0)
    {
        log_debug6("receive: recvfrom(hook, ... , %{sockaddr}) = %i (hook)", message_get_sender(mesg), n);
    }
    else
    {
        log_debug6("receive: empty packet (hook)");
    }

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

        log_debug("receive: recvfrom: %d b/s %d p/s (hook)", rt, rq);
    }

    ya_result return_code;

    if(ISOK(return_code = message_process_lenient(mesg)))
    {
        // look in the timeout collection

        host_address_set_with_sockaddr(&sender_host_address, message_get_sender(mesg));

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


        int len = dnsname_copy(message.fqdn, message_get_canonised_fqdn(mesg));

        if(ISOK(len))
        {
            message.qtype = message_get_u16_at(mesg, 12 + len);
            message.qclass = message_get_u16_at(mesg, 12 + len + 2);

            // remove it from the collection

            mutex_lock(&message_collection_mtx);

            ptr_node *simple_message_node = ptr_set_find(&message_collection, &message);

            if(simple_message_node != NULL)
            {
                // proceed

                bool truncated = message_istruncated(mesg);

                dns_simple_message_s *simple_message_cached = (dns_simple_message_s*)simple_message_node->key;

                dns_udp_simple_message_lock(simple_message_cached);

                ptr_set_delete(&message_collection, simple_message_cached);
                --message_collection_keys;

                // the message is not in the timeout collection anymore
                // it should contain an answer, or an error, ... or a message with the TC bit on

                if(!truncated)
                {
                    simple_message_cached->status &= ~DNS_SIMPLE_MESSAGE_STATUS_COLLECTED;
                    simple_message_cached->status |= DNS_SIMPLE_MESSAGE_STATUS_RECEIVED;
                }

                dns_udp_simple_message_unlock(simple_message_cached);

                mutex_unlock(&message_collection_mtx);

                // RC is supposed to be 1

#if DEBUG
                if(simple_message_cached->rc.value != 1)
                {
                    log_warn("receive: message RC is not 1 (%i) (hook)", simple_message_cached->rc.value);
                }
#endif
                simple_message_cached->received_time_us = timeus();
                s64 dt = MAX(simple_message_cached->received_time_us - simple_message_cached->sent_time_us, 0);
                double dts = dt;
                dts /= ONE_SECOND_US_F;

#if HAS_TC_FALLBACK_TO_TCP_SUPPORT
                if(!truncated)
                {
#endif
                    simple_message_cached->answer = mesg;

                    log_notice("receive: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) [%6.3fs] (hook)", message.fqdn, &message.qtype, &message.qclass, message.name_server, simple_message_cached->status, dts);

                    dns_udp_simple_message_retain(simple_message_cached);
                    dns_udp_simple_message_answer_call_handlers(simple_message_cached);
                    simple_message_cached->answer = NULL;
                    //dns_udp_simple_message_release(simple_message_cached);

                    // allocate the next buffer, handle the hard_limit of the pool:
                    // when the pool has reached peak capacity, allocation returns NULL
#if HAS_TC_FALLBACK_TO_TCP_SUPPORT

                }
                else
                {
                    // the message has been truncated
                    // it should be queried again using TCP

                    log_notice("receive: %{dnsname} %{dnstype} %{dnsclass} to %{hostaddr} (%x) [%6.3fs]: truncated (hook)", message.fqdn, &message.qtype, &message.qclass, message.name_server, simple_message_cached->status, dts);

                    // TCP ???
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
            log_err("receive: an error occurred while copying the name '%{dnsname}': %r", message_get_canonised_fqdn(mesg), len);
        }
    }
    else
    {
        // nop
    }
    
    return return_code;
}

/**
 * 
 * Mark a simple message as being timed-out
 * Meant for use in hooks.
 * Use with care.
 * 
 * @param simple_message
 */

void
dns_udp_mark_as_timedout(dns_simple_message_s *simple_message)
{
    simple_message->sent_time_us = timeus() - 10000000; // 10 seconds ago
    simple_message->received_time_us = MAX_S64;
    simple_message->status |= DNS_SIMPLE_MESSAGE_STATUS_TIMEDOUT;
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

        limiter_init(&dns_udp_send_bandwidth, dns_udp_settings->send_bandwidth); // bytes-per-second
        limiter_init(&dns_udp_send_rate, dns_udp_settings->send_rate); // bytes-per-second
        limiter_init(&dns_udp_recv_bandwidth, dns_udp_settings->recv_bandwidth); // bytes-per-second
        //dns_udp_settings->port_count != 0
        u32 worker_count = dns_udp_settings->port_count;

        MALLOC_OR_DIE(dns_udp_receive_ctx**, dns_udp_receive_context, sizeof (dns_udp_receive_ctx*) * worker_count, DNSURCTX_TAG);
        for(u32 i = 0; i < worker_count; i++) // dns_udp_socket_count is guaranteed > 0
        {
            dns_udp_receive_context[i] = dns_udp_receive_ctx_init(dns_udp_settings->udp_read_buffer_count);
        }

        // open "worker_count" udp sockets (V6)

        dns_udp_socket_count = worker_count;
        MALLOC_OR_DIE(int*, dns_udp_socket, sizeof (int) * dns_udp_socket_count, SCKTARRY_TAG); // DON'T POOL

        for(u32 i = 0; i < dns_udp_socket_count; i++) // dns_udp_socket_count is guaranteed > 0
        {
            int s;

            if((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
            {
                for(u32 j = 0; j < i; j++)
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
            ZEROMEMORY(&sin6, sizeof (sin6));
            sin6.sin6_family = AF_INET6;
            socklen_t sin6len = sizeof (sin6);

            if(bind(s, (struct sockaddr*) &sin6, sin6len) < 0)
            {
                err = ERRNO_ERROR;

                log_err("bind: %r", err);

                for(u32 j = 0; j < i; j++)
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

            struct sockaddr_storage assigned_address;
            socklen_t assigned_address_len = sizeof (assigned_address);
            if(getsockname(s, (struct sockaddr*) &assigned_address, &assigned_address_len) == 0)
            {
                log_info("dns udp: socket[%i]=%i is bound to %{sockaddr}", i, s, &assigned_address);
            }
            else
            {
                log_warn("dns udp: socket[%i]=%i bound address cannot be found: %r", i, s, ERRNO_ERROR);
            }
        }
        // scan-build false positive: dns_udp_socket_count > 0
        assert(dns_udp_socket_count > 0);
        MALLOC_OR_DIE(list_dl_s*, dns_udp_high_priority, sizeof (list_dl_s) * dns_udp_socket_count, LISTDL_TAG); // DON'T POOL, count ALWAYS > 0       

        for(u32 i = 0; i < dns_udp_socket_count; i++)
        {
            list_dl_init(&dns_udp_high_priority[i]);
        }

        // each couple of socket will be the responsibility of a writer

        if(ISOK(err = service_init_ex(&dns_udp_send_handler, dns_udp_send_service, "qs", worker_count)))
        {
            async_queue_init(&dns_udp_send_handler_queue, dns_udp_settings->queue_size, 1, 100000, "dns-udp-send");

            if(ISOK(err = service_init_ex(&dns_udp_receive_read_handler, dns_udp_receive_read_service, "qrrs", worker_count)))
            {
                if(ISOK(err = service_init_ex(&dns_udp_receive_process_handler, dns_udp_receive_process_service, "qrps", worker_count)))
                {
                    if(ISOK(err = service_init(&dns_udp_timeout_handler, dns_udp_timeout_service, "qts")))
                    {
#if HAS_TC_FALLBACK_TO_TCP_SUPPORT
                        if((tcp_query_thread_pool = thread_pool_init_ex(dns_udp_settings->tcp_thread_pool_size, 0x4000, "dnstcpqr")) != NULL)
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
                            dns_udp_callback_tp = thread_pool_init_ex(dns_udp_settings->callback_thread_count, dns_udp_settings->callback_queue_size, "udp-cb");

                            if(dns_udp_callback_tp != NULL)
                            {
                                dns_udp_handler_initialized = TRUE;

                                return SUCCESS;
                            }

                            pool_finalize(&message_data_pool);
                            pool_finalize(&dns_simple_message_pool);
                            pool_finalize(&dns_simple_message_async_node_pool);

#if HAS_TC_FALLBACK_TO_TCP_SUPPORT
                            thread_pool_destroy(tcp_query_thread_pool);
                            tcp_query_thread_pool = NULL;
                        }

                        service_finalize(&dns_udp_timeout_handler);
                        err = THREAD_CREATION_ERROR;
#endif
                    }

                    service_finalize(&dns_udp_receive_process_handler);
                }
                
                service_finalize(&dns_udp_receive_read_handler);
            }

            service_finalize(&dns_udp_send_handler);
        }

        for(u32 i = 0; i < dns_udp_socket_count; i++)
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
dns_udp_handler_finalize()
{    
    if(!dns_udp_handler_initialized)
    {
        return SUCCESS;
    }
    
    dns_udp_handler_stop();

    if(dns_udp_callback_tp != NULL)
    {
        thread_pool_destroy(dns_udp_callback_tp);
        dns_udp_callback_tp = NULL;
    }

    service_finalize(&dns_udp_send_handler);

    service_finalize(&dns_udp_receive_read_handler);
    service_finalize(&dns_udp_receive_process_handler);

    service_finalize(&dns_udp_timeout_handler);
    
    if(dns_udp_socket != NULL)
    {
        for(u32 i = 0; i < dns_udp_socket_count; i++)
        {
            if(dns_udp_socket[i] != ~0)
            {
                log_debug1("dns_udp_handler_finalize: closing socket %i", dns_udp_socket[i]);

                if(shutdown(dns_udp_socket[i], SHUT_RDWR) < 0)
                {
                    log_debug1("dns_udp_handler_finalize: unable to shutdown socket %i: %r", dns_udp_socket[i], ERRNO_ERROR);
                }

                close_ex(dns_udp_socket[i]);
                dns_udp_socket[i] = ~0;
            }
        }

        free(dns_udp_socket); // One array, don't pool

        dns_udp_socket = NULL;
    }
    
    if(dns_udp_receive_context != NULL)
    {
        for(u32 i = 0; i < dns_udp_socket_count; i++) // dns_udp_socket_count is guaranteed > 0
        {
            dns_udp_receive_ctx_destroy(dns_udp_receive_context[i]);
        }

        free(dns_udp_receive_context);
        dns_udp_receive_context = NULL;
    }
    
    if(dns_udp_high_priority != NULL)
    {
        free(dns_udp_high_priority);
        dns_udp_high_priority = NULL;
    }
    
    dns_udp_socket_count = 0;
    
    async_queue_finalize(&dns_udp_send_handler_queue);
    
    ptr_set_callback_and_destroy(&message_collection, dns_udp_handler_message_collection_free_node_callback);

    message_collection_keys = 0;
    message_collection_size = 0;
    
    pool_finalize(&dns_simple_message_async_node_pool);
    pool_finalize(&dns_simple_message_pool);
    pool_finalize(&message_data_pool);
    
    limiter_finalize(&dns_udp_send_bandwidth);
    
    dns_udp_handler_initialized = FALSE;
    
    return SUCCESS;
}
