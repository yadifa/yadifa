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

/** @defgroup 
 *  @ingroup yadifad
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#ifndef _RRL_H
#define _RRL_H

#include <dnscore/message.h>
#include <dnscore/config_settings.h>
#include <dnsdb/zdb_types.h>

#ifndef RRL_PROCEED
#define RRL_PROCEED         0
#define RRL_SLIP            1
#define RRL_DROP            2
#endif

#define RRL_PROCEED_SLIP    (RRL_SLIP|4)    // ignored slip
#define RRL_PROCEED_DROP    (RRL_DROP|4)    // ignored drop

#define RRL_QUEUE_SIZE_MIN  0x00000400
#define RRL_QUEUE_SIZE_MAX  0x01000000

#define RRL_RESPONSES_PER_SECOND_DEFAULT        5 // MUST be stored in base 10
#define RRL_ERRORS_PER_SECOND_DEFAULT           5 // MUST be stored in base 10
#define RRL_WINDOW_DEFAULT                     15 // MUST be stored in base 10
#define RRL_SLIP_DEFAULT                        2 // MUST be stored in base 10
#define RRL_QUEUE_SIZE_MAX_DEFAULT          16384 // MUST be stored in base 10
#define RRL_QUEUE_SIZE_MIN_DEFAULT           1024 // MUST be stored in base 10
#define RRL_IPV4_PREFIX_LENGTH_DEFAULT         24 // MUST be stored in base 10
#define RRL_IPV6_PREFIX_LENGTH_DEFAULT         56 // MUST be stored in base 10
#define RRL_LOG_ONLY_DEFAULT                    0 // MUST be stored in base 10
#define RRL_ENABLED_DEFAULT                     0 // MUST be stored in base 10
#define RRL_EXEMPTED_DEFAULT               "none"

void rrl_init();
void rrl_finalize();

/**
 * Look at the message for RRL processing.
 * Returns an RRL code.
 * After this call, the message may be truncated.
 * 
 * @param mesg the query message
 * @param ans_auth_add the answer that would be given to the client
 * @return an RRL error code
 */

ya_result rrl_process(message_data *mesg, zdb_query_ex_answer *ans_auth_add);
void rrl_cull();
bool rrl_is_logonly();

const config_section_descriptor_s *confs_rrl_get_descriptor();

#endif /* _RRL_H */

/** @} */
