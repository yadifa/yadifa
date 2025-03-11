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
 * @defgroup logger Logging functions
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _LOGGER_H
#define _LOGGER_H

#include <dnscore/logger_handle.h>

void ttylog_handle_dbg(logger_handle_t *handle, const char *format, ...);
void ttylog_handle_out(logger_handle_t *handle, const char *format, ...);
void ttylog_handle_notice(logger_handle_t *handle, const char *format, ...);
void ttylog_handle_warn(logger_handle_t *handle, const char *format, ...);
void ttylog_handle_err(logger_handle_t *handle, const char *format, ...);

#if defined(MODULE_MSG_HANDLE)
#define ttylog_dbg(...)    ttylog_handle_dbg(MODULE_MSG_HANDLE, __VA_ARGS__)
#define ttylog_out(...)    ttylog_handle_out(MODULE_MSG_HANDLE, __VA_ARGS__)
#define ttylog_info(...)   ttylog_handle_out(MODULE_MSG_HANDLE, __VA_ARGS__)
#define ttylog_notice(...) ttylog_handle_notice(MODULE_MSG_HANDLE, __VA_ARGS__)
#define ttylog_warn(...)   ttylog_handle_warn(MODULE_MSG_HANDLE, __VA_ARGS__)
#define ttylog_err(...)    ttylog_handle_err(MODULE_MSG_HANDLE, __VA_ARGS__)
#else
#define ttylog_dbg(...)    ttylog_handle_dbg(NULL, __VA_ARGS__)
#define ttylog_out(...)    ttylog_handle_out(NULL, __VA_ARGS__)
#define ttylog_info(...)   ttylog_handle_out(NULL, __VA_ARGS__)
#define ttylog_notice(...) ttylog_handle_notice(NULL, __VA_ARGS__)
#define ttylog_warn(...)   ttylog_handle_warn(NULL, __VA_ARGS__)
#define ttylog_err(...)    ttylog_handle_err(NULL, __VA_ARGS__)
#endif

#endif /* _LOGGER_H */

/** @} */
