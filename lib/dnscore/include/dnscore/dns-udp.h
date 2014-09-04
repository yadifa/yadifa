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

#ifndef DNS_UDP_H
#define DNS_UDP_H

#include <dnscore/host_address.h>
#include <dnscore/message.h>
#include <dnscore/mutex.h>
#include <dnscore/async.h>

// error codes

#define DNS_UDP_TIMEOUT 0x81000001
#define DNS_UDP_INTERNAL 0x81000002

//

#define DNS_UDP_TIMEOUT_US     3000000   // 3s

#define DNS_UDP_TIMEOUT_US_MIN 1000000   // 1s
#define DNS_UDP_TIMEOUT_US_MAX 3600000000// 1h

#define DNS_UDP_SEND_RATE      1000000   // 1MB/s

#define DNS_UDP_SEND_RATE_MIN  512       // 512B/s
#define DNS_UDP_SEND_RATE_MAX  100000000 // 100MB/s

#define DNS_UDP_SEND_QUEUE     200000    // 100000 messages

#define DNS_UDP_SEND_QUEUE_MIN 1
#define DNS_UDP_SEND_QUEUE_MAX 0x1000000 // 16.7M messages

#define DNS_UDP_PORT_COUNT      256      // A.K.A workers
#define DNS_UDP_PORT_COUNT_MIN  1
#define DNS_UDP_PORT_COUNT_MAX  4000

#define DNS_UDP_RETRY_COUNT      2       // tries after the first failure
#define DNS_UDP_RETRY_COUNT_MIN  0
#define DNS_UDP_RETRY_COUNT_MAX  16

#define DNS_SIMPLE_MESSAGE_CAN_BE_LOCKED 1
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
    u64 timeout;
    u32 send_rate;
    u32 queue_size;
    u32 port_count;
    u32 retry_count;
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
    volatile u64 sent_time_us;
    volatile u64 received_time_us;
    
    smp_int rc; // number of references for this message
    mutex_t mtx;
#if DNS_SIMPLE_MESSAGE_HAS_WAIT_COND
    pthread_cond_t mtx_cond;
#endif
    volatile pthread_t owner;
    
    u32 worker_index;
    u16 qtype;
    u16 qclass;
    u16 flags;
    u16 source_port;
    u16 dns_id;
    u8  retries_left;
    u8  status;
    bool recurse;
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
int dns_udp_handler_init();
int dns_udp_handler_start();
int dns_udp_handler_stop();
int dns_udp_handler_finalize();

int dns_udp_send_simple_message(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass, u16 flags, async_done_callback *cb, void* cbargs);
int dns_udp_send_recursive_message(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass, u16 flags, async_done_callback *cb, void* cbargs);
int dns_udp_send_simple_message_sync(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass,u16 flags, dns_simple_message_s **to_release);
int dns_udp_send_recursive_message_sync(const host_address* name_server, const u8 *fqdn, u16 qtype, u16 qclass,u16 flags, dns_simple_message_s **to_release);

bool dns_udp_simple_message_trylock(dns_simple_message_s *simple_message);
void dns_udp_simple_message_lock(dns_simple_message_s *simple_message);
void dns_udp_simple_message_unlock(dns_simple_message_s *simple_message);

void dns_udp_simple_message_retain(dns_simple_message_s *simple_message);
void dns_udp_simple_message_release(dns_simple_message_s *simple_message);

static inline const message_data *dns_udp_simple_message_get_answer(const dns_simple_message_s *simple_message)
{
    return simple_message->answer;
}

#endif // DNS_UDP_H