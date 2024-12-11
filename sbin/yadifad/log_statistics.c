/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

#include "server_config.h"

#define LOG_STATISTICS_C_

#include <dnscore/ptr_vector.h>
#include <dnscore/zalloc.h>

#include "log_statistics.h"
#include "confs.h"
#include "zone.h"

logger_handle_t *g_statistics_logger = LOGGER_HANDLE_SINK;

void             log_statistics_legend()
{
    logger_handle_msg(g_statistics_logger,
                      MSG_INFO,
                      "statistics legend: \n"
                      "\n"
                      "input: \n"
                      "\n"
                      "\tin : input count \n"
                      "\tqr : query count \n"
                      "\tni : notify count \n"
                      "\tup : update count \n"

                      "\tdr : dropped count \n"
                      "\tst : total bytes sent (simple queries only) \n"
                      "\tun : undefined opcode count \n"
                      "\trf : referral count\n"

                      "\tax : axfr query count \n"
                      "\tix : ixfr query count \n"
                      "\tov : (tcp) connection overflow \n"
                      "\n"
                      "output:\n"
                      "\n"
                      "\tOK : NOERROR answer count \n"
                      "\tFE : FORMERR answer count \n"
                      "\tSF : SERVFAIL answer count \n"
                      "\tNE : NXDOMAIN answer count \n"
                      "\tNI : NOTIMP answer count \n"
                      "\tRE : REFUSED answer count \n"
                      "\tXD : YXDOMAIN answer count \n"
                      "\tXR : YXRRSET answer count \n"
                      "\tNR : NXRRSET answer count \n"
                      "\tNA : NOTAUTH answer count \n"
                      "\tNZ : NOTZONE answer count \n"

                      "\tBV : BADVERS answer count \n"
                      "\tBS : BADSIG answer count \n"
                      "\tBK : BADKEY answer count \n"
                      "\tBT : BADTIME answer count \n"
                      "\tBM : BADMODE answer count \n"
                      "\tBN : BADNAME answer count \n"
                      "\tBA : BADALG answer count \n"
                      "\tTR : BADTRUNC answer count\n"

#if HAS_RRL_SUPPORT
                      "\n"
                      "rrl:\n"
                      "\n"
                      "\tsl : truncated answer count\n"
                      "\tdr : dropped answer count\n"
#endif
    );
}

#if USE_SERVER_STATISTICS_ATOMICS

server_statistics_t  log_statistics_atomic;

void                 log_statistics_init() { memset(&log_statistics_atomic, 0, sizeof(log_statistics_atomic)); }

server_statistics_t *log_statistics_get() { return &log_statistics_atomic; }

#else

server_statistics_t log_statistics_tcp;
static ptr_vector_t server_statistics_array = PTR_VECTOR_EMPTY;
static mutex_t      server_statistics_array_mtx = MUTEX_INITIALIZER;

void                log_statistics_init()
{
    memset(&log_statistics_tcp, 0, sizeof(log_statistics_tcp));
    mutex_init(&log_statistics_tcp.mtx);
}

server_statistics_t *log_statistics_get() { return &log_statistics_tcp; }

void                 log_statistics_register(server_statistics_t *server_statistics)
{
    mutex_lock(&server_statistics_array_mtx);
    ptr_vector_append(&server_statistics_array, server_statistics);
    mutex_unlock(&server_statistics_array_mtx);
}

void log_statistics_unregister(server_statistics_t *server_statistics)
{
    mutex_lock(&server_statistics_array_mtx);
    for(int_fast32_t i = 0; i <= ptr_vector_last_index(&server_statistics_array); ++i)
    {
        server_statistics_t *statistics = (server_statistics_t *)ptr_vector_get(&server_statistics_array, i);
        if(statistics == server_statistics)
        {
            ptr_vector_end_swap(&server_statistics_array, i);
            ptr_vector_remove_last(&server_statistics_array);
            break;
        }
    }
    mutex_unlock(&server_statistics_array_mtx);
}

server_statistics_t *log_statistics_alloc_register()
{
    server_statistics_t *ret;
    ZALLOC_OBJECT_OR_DIE(ret, server_statistics_t, SVRSTATS_TAG);
    memset(ret, 0, sizeof(server_statistics_t));
    mutex_init(&ret->mtx);
    log_statistics_register(ret);
    return ret;
}

void log_statistics_unregister_free(server_statistics_t *server_statistics)
{
    log_statistics_unregister(server_statistics);
    ZFREE_OBJECT(server_statistics);
}

#endif

void log_statistics_struct(server_statistics_t *server_statistics)
{
#if ZDB_ZONE_DESC_IS_TRACKED
    zone_dump_allocated();
#endif

    logger_handle_msg(g_statistics_logger,
                      MSG_INFO,

                      "udp (in=%llu qr=%llu ni=%llu up=%llu "
                      "dr=%llu st=%llu un=%llu "
                      "rf=%llu"
                      ") "

                      "tcp (in=%llu qr=%llu ni=%llu up=%llu "
                      "dr=%llu st=%llu un=%llu "
                      "rf=%llu "
                      "ax=%llu ix=%llu ov=%llu) "

                      "udpa (OK=%llu FE=%llu SF=%llu NE=%llu "
                      "NI=%llu RE=%llu XD=%llu XR=%llu "
                      "NR=%llu NA=%llu NZ=%llu BV=%llu "
                      "BS=%llu BK=%llu BT=%llu BM=%llu "
                      "BN=%llu BA=%llu TR=%llu) "

                      "tcpa (OK=%llu FE=%llu SF=%llu NE=%llu "
                      "NI=%llu RE=%llu XD=%llu XR=%llu "
                      "NR=%llu NA=%llu NZ=%llu BV=%llu "
                      "BS=%llu BK=%llu BT=%llu BM=%llu "
                      "BN=%llu BA=%llu TR=%llu) "
#if HAS_RRL_SUPPORT
                      "rrl (sl=%llu dr=%llu)"
#endif
                      ,
                      // udp

                      server_statistics->udp_input_count,
                      server_statistics->udp_queries_count,
                      server_statistics->udp_notify_input_count,
                      server_statistics->udp_updates_count,

                      server_statistics->udp_dropped_count,
                      server_statistics->udp_output_size_total,
                      server_statistics->udp_undefined_count,
                      server_statistics->udp_referrals_count,

                      // tcp

                      server_statistics->tcp_input_count,
                      server_statistics->tcp_queries_count,
                      server_statistics->tcp_notify_input_count,
                      server_statistics->tcp_updates_count,

                      server_statistics->tcp_dropped_count,
                      server_statistics->tcp_output_size_total,
                      server_statistics->tcp_undefined_count,
                      server_statistics->tcp_referrals_count,

                      server_statistics->tcp_axfr_count,
                      server_statistics->tcp_ixfr_count,
                      server_statistics->tcp_overflow_count,

                      // udp fp

                      server_statistics->udp_fp[RCODE_NOERROR],
                      server_statistics->udp_fp[RCODE_FORMERR],
                      server_statistics->udp_fp[RCODE_SERVFAIL],
                      server_statistics->udp_fp[RCODE_NXDOMAIN],
                      server_statistics->udp_fp[RCODE_NOTIMP],
                      server_statistics->udp_fp[RCODE_REFUSED],
                      server_statistics->udp_fp[RCODE_YXDOMAIN],
                      server_statistics->udp_fp[RCODE_YXRRSET],
                      server_statistics->udp_fp[RCODE_NXRRSET],
                      server_statistics->udp_fp[RCODE_NOTAUTH],
                      server_statistics->udp_fp[RCODE_NOTZONE],
                      server_statistics->udp_fp[RCODE_BADVERS],
                      server_statistics->udp_fp[RCODE_BADSIG],
                      server_statistics->udp_fp[RCODE_BADKEY],
                      server_statistics->udp_fp[RCODE_BADTIME],
                      server_statistics->udp_fp[RCODE_BADMODE],
                      server_statistics->udp_fp[RCODE_BADNAME],
                      server_statistics->udp_fp[RCODE_BADALG],
                      server_statistics->udp_fp[RCODE_BADTRUNC],

                      // tcp fp

                      server_statistics->tcp_fp[RCODE_NOERROR],
                      server_statistics->tcp_fp[RCODE_FORMERR],
                      server_statistics->tcp_fp[RCODE_SERVFAIL],
                      server_statistics->tcp_fp[RCODE_NXDOMAIN],
                      server_statistics->tcp_fp[RCODE_NOTIMP],
                      server_statistics->tcp_fp[RCODE_REFUSED],
                      server_statistics->tcp_fp[RCODE_YXDOMAIN],
                      server_statistics->tcp_fp[RCODE_YXRRSET],
                      server_statistics->tcp_fp[RCODE_NXRRSET],
                      server_statistics->tcp_fp[RCODE_NOTAUTH],
                      server_statistics->tcp_fp[RCODE_NOTZONE],
                      server_statistics->tcp_fp[RCODE_BADVERS],
                      server_statistics->tcp_fp[RCODE_BADSIG],
                      server_statistics->tcp_fp[RCODE_BADKEY],
                      server_statistics->tcp_fp[RCODE_BADTIME],
                      server_statistics->tcp_fp[RCODE_BADMODE],
                      server_statistics->tcp_fp[RCODE_BADNAME],
                      server_statistics->tcp_fp[RCODE_BADALG],
                      server_statistics->tcp_fp[RCODE_BADTRUNC]

#if HAS_RRL_SUPPORT
                      ,
                      server_statistics->rrl_slip,
                      server_statistics->rrl_drop
#endif
    );
}

void log_statistics()
{
    static uint64_t server_run_loop_rate_tick = 0;
    static uint32_t previous_tick = 0;

#if !USE_SERVER_STATISTICS_ATOMICS
    static server_statistics_t server_statistics_sum;
#endif

    uint32_t tick = dnscore_timer_get_tick();

    if((tick - previous_tick) >= g_config->statistics_max_period)
    {
        uint64_t now = timems();
        uint64_t delta = now - server_run_loop_rate_tick;

        if(delta > 0)
        {
            /* log_info specifically targeted to the g_statistics_logger handle */

#if USE_SERVER_STATISTICS_ATOMICS
            log_statistics_atomic.loop_rate_elapsed = delta;

            log_statistics_struct(&log_statistics_atomic);

#if HAS_EVENT_DYNAMIC_MODULE
            if(dynamic_module_statistics_interface_chain_available())
            {
                dynamic_module_on_statistics_update(&log_statistics_atomic, now);
            }
#endif

            log_statistics_atomic.loop_rate_counter = 0;

#else
            log_statistics_tcp.loop_rate_elapsed = delta;

            memcpy(&server_statistics_sum, &log_statistics_tcp, sizeof(server_statistics_t));

            mutex_lock(&server_statistics_array_mtx);
            for(int_fast32_t i = 0; i <= ptr_vector_last_index(&server_statistics_array); ++i)
            {
                server_statistics_t *stats = (server_statistics_t *)ptr_vector_get(&server_statistics_array, i);

                server_statistics_sum.input_loop_count += stats->input_loop_count;
                /* server_statistics_sum.input_timeout_count += stats->input_timeout_count; */

                server_statistics_sum.udp_output_size_total += stats->udp_output_size_total;
                server_statistics_sum.udp_referrals_count += stats->udp_referrals_count;
                server_statistics_sum.udp_input_count += stats->udp_input_count;
                server_statistics_sum.udp_dropped_count += stats->udp_dropped_count;
                server_statistics_sum.udp_queries_count += stats->udp_queries_count;
                server_statistics_sum.udp_notify_input_count += stats->udp_notify_input_count;
                server_statistics_sum.udp_updates_count += stats->udp_updates_count;

                server_statistics_sum.udp_undefined_count += stats->udp_undefined_count;
#if HAS_RRL_SUPPORT
                server_statistics_sum.rrl_slip += stats->rrl_slip;
                server_statistics_sum.rrl_drop += stats->rrl_drop;
#endif
                for(uint_fast32_t j = 0; j < SERVER_STATISTICS_ERROR_CODES_COUNT; j++)
                {
                    server_statistics_sum.udp_fp[j] += stats->udp_fp[j];
                }
            }

            mutex_unlock(&server_statistics_array_mtx);

#if HAS_EVENT_DYNAMIC_MODULE
            if(dynamic_module_statistics_interface_chain_available())
            {
                dynamic_module_on_statistics_update(&server_statistics_sum, now);
            }
#endif
            log_statistics_struct(&server_statistics_sum);

            log_statistics_tcp.loop_rate_counter = 0;
#endif // USE_SERVER_STATISTICS_ATOMICS

            server_run_loop_rate_tick = now;
#if DEBUG
#if HAS_ZALLOC_STATISTICS_SUPPORT
            zalloc_print_stats(termout);
#endif
#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT || DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT || DNSCORE_HAS_ZALLOC_STATISTICS_SUPPORT || DNSCORE_HAS_MMAP_DEBUG_SUPPORT
            debug_stat(DEBUG_STAT_TAGS | DEBUG_STAT_MMAP); // do NOT enable the dump
#endif
            // journal_log_status();

            debug_bench_logdump_all();
#endif // DEBUG
#if DNSCORE_HAS_LIBC_MALLOC_DEBUG_SUPPORT
            debug_malloc_hook_caller_dump();
#endif
        }

        previous_tick = tick;
    }
}

/** @} */
