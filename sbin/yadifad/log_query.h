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

#ifndef _LOG_QUERY_H
#define _LOG_QUERY_H

#include <dnscore/logger.h>
#include <dnscore/message.h>
#include <dnscore/dnsname.h>

/*******************************************************************************************************************
 *
 * QUERY LOG SPECIALISED FUNCTIONS
 *
 ******************************************************************************************************************/

#ifndef LOG_QUERY_C_
extern logger_handle* g_queries_logger;
#endif

#define log_query_i(...) logger_handle_msg(g_queries_logger,MSG_INFO,__VA_ARGS__)
#define log_query_w(...) logger_handle_msg(g_queries_logger,MSG_WARNING,__VA_ARGS__)
#define log_query_e(...) logger_handle_msg(g_queries_logger,MSG_ERR,__VA_ARGS__)

#ifndef LOG_QUERY_C_
typedef void log_query_function(int, message_data*);
#endif

extern log_query_function* log_query;

void log_query_bind(int socket_fd, message_data *mesg);

void log_query_yadifa(int socket_fd, message_data *mesg);

static inline void
log_query_both(int socket_fd, message_data *mesg)
{
    log_query_yadifa(socket_fd, mesg);
    log_query_bind(socket_fd, mesg);
}

static inline void
log_query_none(int socket_fd, message_data *mesg)
{
    (void)socket_fd;
    (void)mesg;
}

void log_query_set_mode(u32 mode);

#endif

/** @} */

