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
 * @defgroup logging Server logging
 * @ingroup yadifad
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _LOG_STATISTICS_H
#define _LOG_STATISTICS_H

/*******************************************************************************************************************
 *
 * Statistics logging
 *
 ******************************************************************************************************************/

#include <dnscore/mutex.h>
#include <dnscore/logger.h>

#ifndef SERVER_C_
extern logger_handle_t *g_server_logger;
#endif

#ifndef LOG_STATISTICS_C_
extern logger_handle_t *g_statistics_logger;
#endif

#define SVRSTATS_TAG                        0x5354415453525653

#define SERVER_STATISTICS_ERROR_CODES_COUNT 32 // RCODE 5 bits

#define USE_SERVER_STATISTICS_ATOMICS       0

#ifndef USE_SERVER_STATISTICS_ATOMICS
#if HAS_QUERY_LOG_AGGREGATION
#define USE_SERVER_STATISTICS_ATOMICS 0 // uses mutex and a sum
#else
#define USE_SERVER_STATISTICS_ATOMICS 1 // uses atomics
#endif
#endif

#if USE_SERVER_STATISTICS_ATOMICS

#ifndef STATS_NAME
#define STATS_NAME log_statistics_atomic
#endif

#define TCPSTATS(__field__) STATS_NAME.__field__

#define TCPSTATS_LOCK()
#define TCPSTATS_FIELD(__field__) STATS_NAME.__field__
#define TCPSTATS_UNLOCK()

struct server_statistics_s
{
    atomic_uint64_t input_loop_count;
    atomic_uint64_t input_timeout_count;

    atomic_uint64_t loop_rate_counter;
    atomic_uint64_t loop_rate_elapsed;

    /* udp */
#if __unix__
    atomic_uint64_t udp_input_count __attribute__((aligned(64)));
    atomic_uint64_t udp_queries_count __attribute__((aligned(64)));
#else
    atomic_uint64_t udp_input_count;
    atomic_uint64_t udp_queries_count;
#endif
    atomic_uint64_t udp_notify_input_count;
    atomic_uint64_t udp_updates_count;
    atomic_uint64_t udp_dropped_count;
    atomic_uint64_t udp_output_size_total;
    atomic_uint64_t udp_undefined_count;
    atomic_uint64_t udp_referrals_count;

    /* tcp */

    atomic_uint64_t tcp_input_count;
    atomic_uint64_t tcp_queries_count;
    atomic_uint64_t tcp_notify_input_count;
    atomic_uint64_t tcp_updates_count;
    atomic_uint64_t tcp_dropped_count;
    atomic_uint64_t tcp_output_size_total;
    atomic_uint64_t tcp_undefined_count;
    atomic_uint64_t tcp_referrals_count;
    atomic_uint64_t tcp_axfr_count;
    atomic_uint64_t tcp_ixfr_count;
    atomic_uint64_t tcp_overflow_count;

    /* rrl */

#if HAS_RRL_SUPPORT
    atomic_uint64_t rrl_slip;
    atomic_uint64_t rrl_drop;
#endif

    /* answers */

    atomic_uint64_t udp_fp[SERVER_STATISTICS_ERROR_CODES_COUNT];

    atomic_uint64_t tcp_fp[SERVER_STATISTICS_ERROR_CODES_COUNT];
};

typedef struct server_statistics_s server_statistics_t;

#ifndef LOG_STATISTICS_C_
extern server_statistics_t log_statistics_atomic;
#endif

#else

#ifndef STATS_NAME
#define STATS_NAME log_statistics_tcp
#endif

#define TCPSTATS(__field__)                                                                                                                                                                                                                    \
    mutex_lock(&STATS_NAME.mtx);                                                                                                                                                                                                               \
    STATS_NAME.__field__;                                                                                                                                                                                                                      \
    mutex_unlock(&STATS_NAME.mtx)

#define TCPSTATS_LOCK()           mutex_lock(&STATS_NAME.mtx)
#define TCPSTATS_FIELD(__field__) STATS_NAME.__field__
#define TCPSTATS_UNLOCK()         mutex_unlock(&STATS_NAME.mtx)

struct server_statistics_s
{
    mutex_t  mtx;

    uint64_t input_loop_count;
    uint64_t input_timeout_count;

    uint64_t loop_rate_counter;
    uint64_t loop_rate_elapsed;

    /* udp */
#if __unix__
    uint64_t udp_input_count __attribute__((aligned(64)));
    uint64_t udp_queries_count __attribute__((aligned(64)));
#else
    uint64_t udp_input_count;
    uint64_t udp_queries_count;
#endif
    uint64_t udp_notify_input_count;
    uint64_t udp_updates_count;
    uint64_t udp_dropped_count;
    uint64_t udp_output_size_total;
    uint64_t udp_undefined_count;
    uint64_t udp_referrals_count;

    /* tcp */

    uint64_t tcp_input_count;
    uint64_t tcp_queries_count;
    uint64_t tcp_notify_input_count;
    uint64_t tcp_updates_count;
    uint64_t tcp_dropped_count;
    uint64_t tcp_output_size_total;
    uint64_t tcp_undefined_count;
    uint64_t tcp_referrals_count;
    uint64_t tcp_axfr_count;
    uint64_t tcp_ixfr_count;
    uint64_t tcp_overflow_count;

    /* rrl */

#if HAS_RRL_SUPPORT
    uint64_t rrl_slip;
    uint64_t rrl_drop;
#endif

    /* answers */

    uint64_t udp_fp[SERVER_STATISTICS_ERROR_CODES_COUNT];

    uint64_t tcp_fp[SERVER_STATISTICS_ERROR_CODES_COUNT];
};

typedef struct server_statistics_s server_statistics_t;

void                               log_statistics_register(server_statistics_t *server_statistics);
void                               log_statistics_unregister(server_statistics_t *server_statistics);

server_statistics_t               *log_statistics_alloc_register();
void                               log_statistics_unregister_free(server_statistics_t *server_statistics);

#ifndef LOG_STATISTICS_C_
extern server_statistics_t log_statistics_tcp;
#endif

#endif

void                 log_statistics_init();
server_statistics_t *log_statistics_get();

void                 log_statistics_struct(server_statistics_t *server_statistics);

void                 log_statistics_legend();
void                 log_statistics();

#endif /* _LOG_STATISTICS_H */
