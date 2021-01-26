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

/** @defgroup logging Server logging
 *  @ingroup yadifad
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "server-config.h"

#define LOG_STATISTICS_C_

#include "log_statistics.h"

logger_handle* g_statistics_logger = LOGGER_HANDLE_SINK;

void
log_statistics_legend()
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

void
log_statistics(server_statistics_t *server_statistics)
{
#if DEBUG
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

/*    ------------------------------------------------------------    */

/** @} */

