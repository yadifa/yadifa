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

/**-----------------------------------------------------------------------------
 * @defgroup server Server
 * @ingroup yadifad
 * @brief Server initialisation and launch
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include <dnscore/sys_types.h>
#include <dnscore/dns_message.h>
#include <dnscore/logger.h>
#include <dnscore/service.h>

#include "confs.h"

#include "server_context.h"
#include "server_error.h"
#include "log_statistics.h"

#ifndef SERVER_C_
extern logger_handle_t *g_server_logger;
extern volatile int     program_mode;
#endif

#include <dnscore/mutex.h>

#define SOA_REFRESH_MIN         60
#define SOA_RETRY_MIN           60
#define SOA_EXPIRE_MIN          60

#define TPROCPRM_TAG            0x4d5250434f525054
#define POLLFDBF_TAG            0x464244464c4c4f50
#define SOCKET_TAG              0x54454b434f53
#define SVRINSTS_TAG            0x5354534e49525653
#define SVRPLBIN_TAG            0x4e49424c50525653
#define SVRPLBOT_TAG            0x544f424c50525653

#define SERVER_POOL_BUFFER_SIZE 0x20000

#ifndef SERVER_L1_DATA_LINE_ALIGNED_SIZE

#define SERVER_L1_DATA_LINE_ALIGNED_SIZE  128
#define SERVER_L1_DATA_LINE_ALIGNED_SHIFT 7

#elif((1 << SERVER_L1_DATA_LINE_ALIGNED_SHIFT) != SERVER_L1_DATA_LINE_ALIGNED_SIZE)
#error "2^" TOSTRING(SERVER_L1_DATA_LINE_ALIGNED_SHIFT) " != " TOSTRING(SERVER_L1_DATA_LINE_ALIGNED_SIZE) " : please fix"
#endif

/*    ------------------------------------------------------------
 *
 *      PROTOTYPES
 */

/**
 * The servers are completely static entities with static accesses.
 * This is really just a set of methods to call to make a server type ready and run it.
 */

struct server_desc_s
{
    ya_result (*const context_init)(int workers_per_interface);
    ya_result (*const loop)(struct service_worker_s *worker);
    const char *name;
};

#define SUCCESS_DROPPED ((int)0x80ff0001)

/**
 * volatile is only needed for variables changed by another thread
 */

struct network_thread_context_base_s
{
    struct service_worker_s *worker;
    server_statistics_t     *statisticsp;
    thread_t                 idr;
    int                      sockfd;
    uint16_t                 idx;
    volatile bool            must_stop;
};

typedef struct network_thread_context_base_s network_thread_context_base_t;

struct network_thread_dns_tcp_context_s
{
    network_thread_context_base_t base;
    // tcp_manager_socket_context_t* sctx;
    // mutex_t mtx; // to lock writes
};

typedef struct network_thread_dns_tcp_context_s network_thread_dns_tcp_context_t;

void                                            server_process_message_udp_set_database(zdb_t *db);

int                                             server_process_message_udp(network_thread_context_base_t *ctx, dns_message_t *mesg);

/**
 * Initialises the DNS service.
 *
 * @return an error code
 */

ya_result server_service_init();

/**
 * Returns true iff the service has been started.
 *
 * @return true iff the service has been started.
 */

bool server_service_started();

/**
 * Starts the DNS service.
 *
 * @return an error code
 */

ya_result server_service_start();

/**
 * Starts the DNS service and waits for it to stop.
 * This is the most efficient startup when its use is possible.
 *
 * @return an error code
 */

ya_result server_service_start_and_wait();

/**
 * Waits for the DNS service to stop
 *
 * @return an error code
 */

ya_result server_service_wait();

/**
 * Tells the DNS service to reconfigure at the earliest convenience
 *
 * @return an error code
 */

ya_result server_service_reconfigure();

/**
 * Tell the DNS service to stop, do not wait for completion.
 *
 * @return an error code
 */

ya_result server_service_stop_nowait();

/**
 * Closes all server sockets (UDP/TCP)
 */

void server_context_close();
/**
 * Stops the DNS service.
 *
 * @return an error code
 */

ya_result server_service_stop();

/**
 * Finalise the DNS service.
 *
 * @return an error code
 */

ya_result server_service_finalize();

void      server_tcp_client_register(const struct sockaddr_storage *sa, int64_t connections_max);
int64_t   server_tcp_client_connections_max(const struct sockaddr_storage *sa, int64_t default_value);

/** @} */
