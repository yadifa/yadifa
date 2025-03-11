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
 * @defgroup threading mutexes, ...
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnscore/debug.h>
#include <dnscore/logger.h>

void mutex_debug_stacktrace_log(void *handle, uint32_t level, stacktrace trace);
void mutex_debug_logger_handle_msg(const void *handle, uint32_t level, const char *fmt, ...);
void mutex_debug_log_stacktrace(void *handle, uint32_t level, const char *prefix);

#define logger_handle_msg    mutex_debug_logger_handle_msg
#define debug_stacktrace_log mutex_debug_stacktrace_log
#define debug_log_stacktrace mutex_debug_log_stacktrace
#define logger_flush         flushout

#define MODULE_MSG_HANDLE    NULL

#undef LOG_TEXT_PREFIX
#define LOG_TEXT_PREFIX ""

#undef MSG_DEBUG7
#undef MSG_DEBUG6
#undef MSG_DEBUG5
#undef MSG_DEBUG4
#undef MSG_DEBUG3
#undef MSG_DEBUG2
#undef MSG_DEBUG1
#undef MSG_DEBUG
#undef MSG_WARNING
#undef MSG_ERR

#define MSG_DEBUG7  0
#define MSG_DEBUG6  0
#define MSG_DEBUG5  0
#define MSG_DEBUG4  0
#define MSG_DEBUG3  0
#define MSG_DEBUG2  0
#define MSG_DEBUG1  0
#define MSG_DEBUG   0
#define MSG_WARNING 0
#define MSG_ERR     0

#undef log_debug7
#undef log_debug6
#undef log_debug5
#undef log_debug4
#undef log_debug3
#undef log_debug2
#undef log_debug1
#undef log_debug
#undef log_notice
#undef log_info
#undef log_warn
#undef log_err

#define log_debug7(...) logger_handle_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug6(...) logger_handle_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug5(...) logger_handle_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug4(...) logger_handle_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug3(...) logger_handle_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug2(...) logger_handle_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug1(...) logger_handle_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug(...)  logger_handle_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_notice(...) logger_handle_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_info(...)   logger_handle_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_warn(...)   logger_handle_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_err(...)    logger_handle_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)

#undef log_try_debug7
#undef log_try_debug6
#undef log_try_debug5
#undef log_try_debug4
#undef log_try_debug3
#undef log_try_debug2
#undef log_try_debug1
#undef log_try_debug
#undef log_try_notice
#undef log_try_info
#undef log_try_warn
#undef log_try_err

#define log_try_debug7(...) logger_handle_try_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_debug6(...) logger_handle_try_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_debug5(...) logger_handle_try_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_debug4(...) logger_handle_try_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_debug3(...) logger_handle_try_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_debug2(...) logger_handle_try_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_debug1(...) logger_handle_try_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_debug(...)  logger_handle_try_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_notice(...) logger_handle_try_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_info(...)   logger_handle_try_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_warn(...)   logger_handle_try_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_err(...)    logger_handle_try_msg(0, 0, LOG_TEXT_PREFIX __VA_ARGS__)

/** @} */
