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

#ifndef DNS_UDP_H
#define DNS_UDP_H

#include <dnscore/host_address.h>
#include <dnscore/message.h>
#include <dnscore/mutex.h>
#include <dnscore/async.h>

// error codes

#define DNS_UDP_TIMEOUT         ((s32)0x81000001)
#define DNS_UDP_INTERNAL        ((s32)0x81000002)
#define DNS_UDP_CANCEL          ((s32)0x81000003)

//

#define DNS_UDP_TIMEOUT_US     3000000   // 3s

#define DNS_UDP_TIMEOUT_US_MIN 1000000   // 1s
#define DNS_UDP_TIMEOUT_US_MAX 3600000000// 1h

#define DNS_UDP_SEND_RATE      1000      // 1000 queries/s
#define DNS_UDP_SEND_BANDWIDTH 1000000   // 1MB/s
#define DNS_UDP_RECV_BANDWIDTH 1000000   // 1MB/s

#define DNS_UDP_SEND_RATE_MIN  1         // q/s
#define DNS_UDP_SEND_RATE_MAX  1000000   // q/s

#define DNS_UDP_SEND_BANDWIDTH_MIN  512       // 512B/s
#define DNS_UDP_SEND_BANDWIDTH_MAX  100000000 // 100MB/s

#define DNS_UDP_RECV_BANDWIDTH_MIN  512       // 512B/s
#define DNS_UDP_RECV_BANDWIDTH_MAX  100000000 // 100MB/s

#define DNS_UDP_SEND_QUEUE     200000    // 200000 messages

#define DNS_UDP_SEND_QUEUE_MIN 1
#define DNS_UDP_SEND_QUEUE_MAX 0x1000000 // 16.7M messages

#define DNS_UDP_PORT_COUNT      256      // A.K.A workers
#define DNS_UDP_PORT_COUNT_MIN  1
#define DNS_UDP_PORT_COUNT_MAX  4000

#define DNS_UDP_RETRY_COUNT      2       // tries after the first failure
#define DNS_UDP_RETRY_COUNT_MIN  0
#define DNS_UDP_RETRY_COUNT_MAX  16

#define DNS_UDP_PER_DNS_RATE     5       // packets per second
#define DNS_UDP_PER_DNS_RATE_MIN 1
#define DNS_UDP_PER_DNS_RATE_MAX 65536

#define DNS_UDP_PER_DNS_BANDWIDTH     4096  // bytes per second
#define DNS_UDP_PER_DNS_BANDWIDTH_MIN 512
#define DNS_UDP_PER_DNS_BANDWIDTH_MAX 65536

#define DNS_UDP_PER_DNS_FREQ_MIN     10000  // us between two queries
#define DNS_UDP_PER_DNS_FREQ_MIN_MIN 0
#define DNS_UDP_PER_DNS_FREQ_MIN_MAX 1000000

#define DNS_UDP_READ_BUFFER_COUNT       4096
#define DNS_UDP_READ_BUFFER_COUNT_MIN      1
#define DNS_UDP_READ_BUFFER_COUNT_MAX   8192

#define DNS_UDP_TCP_THREAD_POOL_SIZE 1
#define DNS_UDP_TCP_THREAD_POOL_MIN 1
#define DNS_UDP_TCP_THREAD_POOL_MAX 64

#define DNS_UDP_TCP_FALLBACK_ON_TIMEOUT 0

#define DNS_UDP_CALLBACK_THREAD_COUNT 4
#define DNS_UDP_CALLBACK_THREAD_COUNT_MIN 1
#define DNS_UDP_CALLBACK_THREAD_COUNT_MAX 8

#define DNS_UDP_CALLBACK_QUEUE_SIZE 0x100000
#define DNS_UDP_CALLBACK_QUEUE_SIZE_MIN 0x1000
#define DNS_UDP_CALLBACK_QUEUE_SIZE_MAX 0x1000000

#define DNS_SIMPLE_MESSAGE_HAS_WAIT_COND 0

#define DNS_SIMPLE_MESSAGE_FLAGS_DNSSEC MESSAGE_EDNS0_DNSSEC

#define DNS_SIMPLE_MESSAGE_STATUS_QUEUED        0x01
#define DNS_SIMPLE_MESSAGE_STATUS_COLLECTED     0x02
#define DNS_SIMPLE_MESSAGE_STATUS_SENT          0x04
#define DNS_SIMPLE_MESSAGE_STATUS_AGGREGATED    0x08
#define DNS_SIMPLE_MESSAGE_STATUS_RECEIVED      0x10
#define DNS_SIMPLE_MESSAGE_STATUS_TIMEDOUT      0x20
#define DNS_SIMPLE_MESSAGE_STATUS_FAILURE       0x40
#define DNS_SIMPLE_MESSAGE_STATUS_INVALID       0x80

struct dns_udp_settings_s
{
    s64 timeout;
    u32 send_rate;
    u32 send_bandwidth;
    u32 recv_bandwidth;
    u32 queue_size;
    u32 port_count;
    u32 retry_count;
    
    u32 per_dns_rate;
    u32 per_dns_bandwidth;
    u32 per_dns_freq_min;

    u32 udp_read_buffer_count;

    u32 callback_queue_size;
    u8 callback_thread_count;

    u8 tcp_thread_pool_size;
    bool tcp_fallback_on_timeout;



};

typedef struct dns_udp_settings_s dns_udp_settings_s;

// reference count common to all dns_simple_message (aggregation of answer for same query)

struct dns_simple_message_async_node_s
{
    struct dns_simple_message_async_node_s *next;
    async_message_s *async;
};

typedef struct dns_simple_message_async_node_s dns_simple_message_async_node_s;

/*
 * This is basically a DNS query descriptor (retries and all)
 */

struct dns_simple_message_s
{   
    host_address *name_server;
    
    message_data *answer;   // answer, can be shared
    
    dns_simple_message_async_node_s async_node;
    volatile s64 queued_time_us;
    volatile s64 sent_time_us;
    volatile s64 received_time_us;
    
    smp_int rc; // number of references for this message
    group_mutex_t mtx;
    volatile thread_t owner;
    
    int sender_socket;              // used so a repeated message will be sent from the same address:port
    u32 worker_index;               // seems to be only useful to get the priority queue index
    u16 qtype;
    u16 qclass;
    u16 flags;
    u16 source_port;                // seems useless
    u16 dns_id;
    s8  retries_left;
    volatile u8  status;
    u8 recurse:1,tcp:1,tcp_used:1,tcp_replied:1;
    //bool recurse;
    //bool tcp;                       // try TCP
    u8 fqdn[MAX_DOMAIN_LENGTH];
};

typedef struct dns_simple_message_s dns_simple_message_s;

/**
 * This needs to be called before dns_udp_handler_init() or some settings will not be taken
 * into account
 * 
 * @param settings that will be used by the dns_udp handler
 */

void dns_udp_handler_configure(const dns_udp_settings_s *settings);
void dns_udp_handler_host_limit_set(const host_address* name_server,
        u32 rate,
        u32 bandwidth,
        u32 freq_min);
int dns_udp_handler_init();
int dns_udp_handler_start();
int dns_udp_handler_stop();
int dns_udp_handler_finalize();

/**
 * Cancels all pending queries.
 * Their handlers will be called with the error message DNS_UDP_CANCEL
 * The purpose is cleaning up before shutdown.
 */

void dns_udp_cancel_all_queries();

void dns_udp_send_simple_message(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass, u16 flags, async_done_callback *cb, void* cbargs);
void dns_udp_send_recursive_message(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass, u16 flags, async_done_callback *cb, void* cbargs);
ya_result dns_udp_send_simple_message_sync(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass,u16 flags, dns_simple_message_s **to_release);
ya_result dns_udp_send_recursive_message_sync(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass,u16 flags, dns_simple_message_s **to_release);

bool dns_udp_simple_message_trylock(dns_simple_message_s *simple_message);
void dns_udp_simple_message_lock(dns_simple_message_s *simple_message);
void dns_udp_simple_message_unlock(dns_simple_message_s *simple_message);

void dns_udp_simple_message_retain(dns_simple_message_s *simple_message);
void dns_udp_simple_message_release(dns_simple_message_s *simple_message);

static inline const message_data *dns_udp_simple_message_get_answer(const dns_simple_message_s *simple_message)
{
    return simple_message->answer;
}

u32 dns_udp_send_queue_size();
u32 dns_udp_pending_queries_count();
u32 dns_udp_pending_feedback_count();

/**
 */

typedef bool dns_udp_query_hook(dns_simple_message_s *simple_message, message_data *mesg);

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

void dns_udp_set_query_hook(dns_udp_query_hook *hook);

/**
 * 
 * Mark a simple message as being timed-out
 * Meant for use in hooks.
 * Use with care.
 * 
 * @param simple_message
 */

void dns_udp_mark_as_timedout(dns_simple_message_s *simple_message);

#endif // DNS_UDP_H

