/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

#ifndef DNS_UDP_H
#define DNS_UDP_H

#include <dnscore/host_address.h>
#include <dnscore/dns_message.h>
#include <dnscore/mutex.h>
#include <dnscore/async.h>

// error codes

#define DNS_UDP_TIMEOUT                      ((int32_t)0x81000001)
#define DNS_UDP_INTERNAL                     ((int32_t)0x81000002)
#define DNS_UDP_CANCEL                       ((int32_t)0x81000003)

//

#define DNS_UDP_TIMEOUT_US                   3000000 // 3s

#define DNS_UDP_TIMEOUT_US_MIN               1000000    // 1s
#define DNS_UDP_TIMEOUT_US_MAX               3600000000 // 1h

#define DNS_UDP_SEND_RATE                    1000    // 1000 queries/s
#define DNS_UDP_SEND_BANDWIDTH               1000000 // 1MB/s
#define DNS_UDP_RECV_BANDWIDTH               1000000 // 1MB/s

#define DNS_UDP_SEND_RATE_MIN                1       // q/s
#define DNS_UDP_SEND_RATE_MAX                1000000 // q/s

#define DNS_UDP_SEND_BANDWIDTH_MIN           512       // 512B/s
#define DNS_UDP_SEND_BANDWIDTH_MAX           100000000 // 100MB/s

#define DNS_UDP_RECV_BANDWIDTH_MIN           512       // 512B/s
#define DNS_UDP_RECV_BANDWIDTH_MAX           100000000 // 100MB/s

#define DNS_UDP_SEND_QUEUE                   200000 // 200000 messages

#define DNS_UDP_SEND_QUEUE_MIN               1
#define DNS_UDP_SEND_QUEUE_MAX               0x1000000 // 16.7M messages

#define DNS_UDP_PORT_COUNT                   256 // A.K.A workers
#define DNS_UDP_PORT_COUNT_MIN               1
#define DNS_UDP_PORT_COUNT_MAX               4000

#define DNS_UDP_RETRY_COUNT                  2 // tries after the first failure
#define DNS_UDP_RETRY_COUNT_MIN              0
#define DNS_UDP_RETRY_COUNT_MAX              16

#define DNS_UDP_PER_DNS_RATE                 5 // packets per second
#define DNS_UDP_PER_DNS_RATE_MIN             1
#define DNS_UDP_PER_DNS_RATE_MAX             65536

#define DNS_UDP_PER_DNS_BANDWIDTH            4096 // bytes per second
#define DNS_UDP_PER_DNS_BANDWIDTH_MIN        512
#define DNS_UDP_PER_DNS_BANDWIDTH_MAX        65536

#define DNS_UDP_PER_DNS_FREQ_MIN             10000 // us between two queries
#define DNS_UDP_PER_DNS_FREQ_MIN_MIN         0
#define DNS_UDP_PER_DNS_FREQ_MIN_MAX         1000000

#define DNS_UDP_READ_BUFFER_COUNT            4096
#define DNS_UDP_READ_BUFFER_COUNT_MIN        1
#define DNS_UDP_READ_BUFFER_COUNT_MAX        8192

#define DNS_UDP_TCP_THREAD_POOL_SIZE         1
#define DNS_UDP_TCP_THREAD_POOL_MIN          1
#define DNS_UDP_TCP_THREAD_POOL_MAX          64

#define DNS_UDP_TCP_FALLBACK_ON_TIMEOUT      0

#define DNS_UDP_CALLBACK_THREAD_COUNT        4
#define DNS_UDP_CALLBACK_THREAD_COUNT_MIN    1
#define DNS_UDP_CALLBACK_THREAD_COUNT_MAX    8

#define DNS_UDP_CALLBACK_QUEUE_SIZE          0x100000
#define DNS_UDP_CALLBACK_QUEUE_SIZE_MIN      0x1000
#define DNS_UDP_CALLBACK_QUEUE_SIZE_MAX      0x1000000

#define DNS_SIMPLE_MESSAGE_HAS_WAIT_COND     0

#define DNS_SIMPLE_MESSAGE_FLAGS_DNSSEC      MESSAGE_EDNS0_DNSSEC

#define DNS_SIMPLE_MESSAGE_STATUS_QUEUED     0x01
#define DNS_SIMPLE_MESSAGE_STATUS_COLLECTED  0x02
#define DNS_SIMPLE_MESSAGE_STATUS_SENT       0x04
#define DNS_SIMPLE_MESSAGE_STATUS_AGGREGATED 0x08
#define DNS_SIMPLE_MESSAGE_STATUS_RECEIVED   0x10
#define DNS_SIMPLE_MESSAGE_STATUS_TIMEDOUT   0x20
#define DNS_SIMPLE_MESSAGE_STATUS_FAILURE    0x40
#define DNS_SIMPLE_MESSAGE_STATUS_INVALID    0x80

struct dns_udp_settings_s
{
    int64_t  timeout;
    uint32_t send_rate;
    uint32_t send_bandwidth;
    uint32_t recv_bandwidth;
    uint32_t queue_size;
    uint32_t port_count;
    uint32_t retry_count;

    uint32_t per_dns_rate;
    uint32_t per_dns_bandwidth;
    uint32_t per_dns_freq_min;

    uint32_t udp_read_buffer_count;

    uint32_t callback_queue_size;
    uint8_t  callback_thread_count;

    uint8_t  tcp_thread_pool_size;
    bool     tcp_fallback_on_timeout;
};

typedef struct dns_udp_settings_s dns_udp_settings_t;

// reference count common to all dns_simple_message (aggregation of answer for same query)

struct dns_simple_message_async_node_s
{
    struct dns_simple_message_async_node_s *next;
    async_message_t                        *async;
};

typedef struct dns_simple_message_async_node_s dns_simple_message_async_node_t;

/*
 * This is basically a DNS query descriptor (retries and all)
 */

struct dns_simple_message_s
{
    host_address_t                 *name_server;

    dns_message_t                  *answer; // answer, can be shared

    dns_simple_message_async_node_t async_node;
    volatile int64_t                queued_time_us;
    volatile int64_t                sent_time_us;
    volatile int64_t                received_time_us;

    smp_int                         rc; // number of references for this message
    group_mutex_t                   mtx;
    volatile thread_t               owner;

    int                             sender_socket; // used so a repeated message will be sent from the same address:port
    uint32_t                        worker_index;  // seems to be only useful to get the priority queue index
    uint16_t                        rtype;
    uint16_t                        rclass;
    uint16_t                        flags;
    uint16_t                        source_port; // seems useless
    uint16_t                        dns_id;
    int8_t                          retries_left;
    volatile uint8_t                status;
    uint8_t                         recurse : 1, tcp : 1, tcp_used : 1, tcp_replied : 1;
    // bool recurse;
    // bool tcp;                       // try TCP
    uint8_t fqdn[DOMAIN_LENGTH_MAX];
};

typedef struct dns_simple_message_s dns_simple_message_t;

/**
 * This needs to be called before dns_udp_handler_init() or some settings will not be taken
 * into account
 *
 * @param settings that will be used by the dns_udp handler
 */

void dns_udp_handler_configure(const dns_udp_settings_t *settings);
void dns_udp_handler_host_limit_set(const host_address_t *name_server, uint32_t rate, uint32_t bandwidth, uint32_t freq_min);
int  dns_udp_handler_init();
int  dns_udp_handler_start();
int  dns_udp_handler_stop();
int  dns_udp_handler_finalize();

/**
 * Returns true iff all the services related to dns_udp have been started.
 */

bool dns_udp_service_is_running();

/**
 * Cancels all pending queries.
 * Their handlers will be called with the error message DNS_UDP_CANCEL
 * The purpose is cleaning up before shutdown.
 */

void dns_udp_cancel_all_queries();

/**
 * Six functions giving access to the internal memory pools.
 * Required for the mockup mechanism of another project.
 */

dns_simple_message_t            *dns_udp_simple_message_alloc();

void                             dns_udp_simple_message_free(dns_simple_message_t *simple_message);

dns_message_t                   *dns_udp_message_alloc();

dns_message_t                   *dns_udp_message_alloc_wait();

dns_message_t                   *dns_udp_message_alloc_wait_timeout(int64_t timeoutus);

void                             dns_udp_message_free(dns_message_t *mesg);

dns_simple_message_async_node_t *dns_udp_simple_message_async_alloc();

void                             dns_udp_simple_message_async_free(dns_simple_message_async_node_t *node);

/**
 * Sends a simple message through the DNS-UDP service
 */

void                               dns_udp_send_simple_message(const host_address_t *name_server, const uint8_t *fqdn, uint16_t qtype, uint16_t qclass, uint32_t flags, async_done_callback *cb, void *cbargs);
void                               dns_udp_send_recursive_message(const host_address_t *name_server, const uint8_t *fqdn, uint16_t qtype, uint16_t qclass, uint32_t flags, async_done_callback *cb, void *cbargs);
ya_result                          dns_udp_send_simple_message_sync(const host_address_t *name_server, const uint8_t *fqdn, uint16_t qtype, uint16_t qclass, uint32_t flags, dns_simple_message_t **to_release);
ya_result                          dns_udp_send_recursive_message_sync(const host_address_t *name_server, const uint8_t *fqdn, uint16_t qtype, uint16_t qclass, uint32_t flags, dns_simple_message_t **to_release);

bool                               dns_udp_simple_message_trylock(dns_simple_message_t *simple_message);
void                               dns_udp_simple_message_lock(dns_simple_message_t *simple_message);
void                               dns_udp_simple_message_unlock(dns_simple_message_t *simple_message);

void                               dns_udp_simple_message_acquire(dns_simple_message_t *simple_message);
void                               dns_udp_simple_message_retain(dns_simple_message_t *simple_message); /// obsolete
void                               dns_udp_simple_message_release(dns_simple_message_t *simple_message);

static inline const dns_message_t *dns_udp_simple_message_get_answer(const dns_simple_message_t *simple_message) { return simple_message->answer; }

uint32_t                           dns_udp_send_queue_size();
uint32_t                           dns_udp_pending_queries_count();
uint32_t                           dns_udp_pending_feedback_count();

/**
 */

typedef bool dns_udp_query_hook(dns_simple_message_t *simple_message, dns_message_t *mesg);

/**
 * Sets a hook for queries.
 *
 * The hook is called by the service on each messages and is expected to answer
 * true if it wrote an answer on it
 * false if it did not
 *
 * Every use of the dns_udp service is affected by this.
 * Only one hook is possible at a given time.
 *
 * @param hook a function or NULL to reset to no HOOK.
 */

void dns_udp_set_query_hook(dns_udp_query_hook *hook);

/**
 *
 * Mark a simple message as being timed-out
 * Meant for use in hooks.
 * Use with care.
 *
 * @param simple_message
 */

void dns_udp_mark_as_timedout(dns_simple_message_t *simple_message);

/**
 * Gets the default size of a DNS message in the pool
 *
 * Default is 4KB
 */

int dns_udp_message_size_default_get();

/**
 * Sets the default size of a DNS message in the pool
 *
 * Default is 4KB
 */

int dns_udp_message_size_default_set(int size);

#endif // DNS_UDP_H
