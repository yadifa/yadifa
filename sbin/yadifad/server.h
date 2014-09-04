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
/**
 *  @defgroup server Server
 *  @ingroup yadifad
 *  @brief Server initialisation and launch
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#ifndef SERVER_H_
#define SERVER_H_

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include <dnscore/message.h>
#include <dnscore/logger.h>

#include "confs.h"

#include "server_context.h"
#include "server_error.h"

#ifndef SERVER_C_
extern logger_handle *g_server_logger;
extern volatile int program_mode;
#endif

#include <dnscore/mutex.h>

#define SOA_MIN_REFRESH 60
#define SOA_MIN_RETRY   60
#define SOA_MIN_EXPIRE  60

#define ANCILIARY_BUFFER_SIZE 65536

#define TPROCPRM_TAG 0x4d5250434f525054
#define POLLFDBF_TAG 0x464244464c4c4f50

/*    ------------------------------------------------------------
 *
 *      PROTOTYPES
 */

typedef struct server_statistics_t server_statistics_t;

/**
 * volatile is only needed for variables changed by another thread
 */

#define SERVER_STATISTICS_ERROR_CODES_COUNT 32

struct server_statistics_t
{
    mutex_t mtx;
    
    volatile u64 input_loop_count;
    volatile u64 input_timeout_count;

    volatile u64 loop_rate_counter;
    volatile u64 loop_rate_elapsed;
    
    /* udp */

    volatile u64 udp_input_count;
    volatile u64 udp_queries_count;
    volatile u64 udp_notify_input_count;
    volatile u64 udp_updates_count;
    volatile u64 udp_dropped_count;
    volatile u64 udp_output_size_total;
    volatile u64 udp_undefined_count;
#if 1
    volatile u64 udp_referrals_count;
#endif
    
    /* REFERRALS : !AA + NOERROR */

    /* tcp */

    volatile u64 tcp_input_count;    
    volatile u64 tcp_queries_count;
    volatile u64 tcp_notify_input_count;
    volatile u64 tcp_updates_count;
    volatile u64 tcp_dropped_count;
    volatile u64 tcp_output_size_total;
    volatile u64 tcp_undefined_count;
#if 1
    volatile u64 tcp_referrals_count;
#endif
    volatile u64 tcp_axfr_count;
    volatile u64 tcp_ixfr_count;
    volatile u64 tcp_overflow_count;    
    
    /* rrl */
    
#if HAS_RRL_SUPPORT
    volatile u64 rrl_slip;
    volatile u64 rrl_drop;
#endif
    
    /* answers */
    
    volatile u64 udp_fp[SERVER_STATISTICS_ERROR_CODES_COUNT];
    
    volatile u64 tcp_fp[SERVER_STATISTICS_ERROR_CODES_COUNT];
};

#define TCPSTATS(__field__) mutex_lock(&server_statistics.mtx);server_statistics. __field__ ;mutex_unlock(&server_statistics.mtx)

#ifndef SERVER_C_
extern server_statistics_t server_statistics;

#endif



ya_result server_run();

void tcp_send_message_data(message_data* mesg);

void server_process_tcp(zdb *database, tcp *tcp_itf);

/*    ------------------------------------------------------------    */

#endif /* SERVER_H_ */

/*    ------------------------------------------------------------    */

/** @} */
