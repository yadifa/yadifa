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
 * @defgroup threading mutexes, ...
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/mutex_mutex.h"
#include "dnscore/mutex_logger.h"
#include "dnscore/mutex_contention_monitor.h"
#include "dnscore/bytezarray_output_stream.h"

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
static const char *mutex_type_name = "mutex_lock";
#endif
#endif

void mutex_debug_stacktrace_log(void *handle, uint32_t level, stacktrace trace)
{
    (void)handle;
    (void)level;
    debug_stacktrace_print(termout, trace);
    output_stream_write_u8(termout, (uint8_t)'\n');
}

void mutex_debug_logger_handle_msg(const void *handle, uint32_t level, const char *fmt, ...)
{
    (void)handle;
    (void)level;

    format("%llT | %i | %p | ", timeus(), getpid(), thread_self());

    output_stream_t                  baos;
    bytezarray_output_stream_context baos_context;

    va_list                          args;
    va_start(args, fmt);
    uint8_t text_buffer[512];
    bytezarray_output_stream_init_ex_static(&baos, text_buffer, sizeof(text_buffer), 0, &baos_context);

    if(FAIL(vosformat(&baos, fmt, args)))
    {
        bytezarray_output_stream_reset(&baos);
        osprint(&baos, "*** ERROR : MESSAGE FORMATTING FAILED ***");
    }

    // output_stream_write_u8(&baos, 0);
    output_stream_write(termout, bytezarray_output_stream_buffer(&baos), bytezarray_output_stream_buffer_offset(&baos));
    output_stream_write_u8(termout, (uint8_t)'\n');
}

void mutex_debug_log_stacktrace(void *handle, uint32_t level, const char *prefix)
{
    println(prefix);
    stacktrace trace = debug_stacktrace_get();
    mutex_debug_stacktrace_log(handle, level, trace);
}

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT

extern const bool mutex_ultraverbose;

void              mutex_lock(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger, MSG_DEBUG7, "mutex_lock(%p)", mtx);
#endif
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), mutex_type_name);
#endif
#endif

    pthread_mutex_lock(mtx);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_end(mcm);
#endif
#endif

    if(mutex_ultraverbose)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger, MSG_DEBUG7, "mutex_lock(%p): locked", mtx);
#endif
    }
}

bool mutex_trylock(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger, MSG_DEBUG7, "mutex_trylock(%p)", mtx);
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), mutex_type_name);
#endif
#endif

    int err = pthread_mutex_trylock(mtx);

    if((err != 0) && (err != EBUSY))
    {
        logger_handle_msg(g_system_logger, MSG_ERR, "mutex_trylock(%p): %r", mtx, MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }

    if(err == 0)
    {
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_end(mcm);
#endif
#endif
    }
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    else
    {
        mutex_contention_lock_fail(mcm);
    }
#endif
#endif

    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger, MSG_DEBUG7, "mutex_trylock(%p): %s", mtx, (err == 0) ? "locked" : "failed");
    }

    return err == 0;
}

void mutex_unlock(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger, MSG_DEBUG7, "mutex_unlock(%p)", mtx);
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_unlock(thread_self(), mtx);
#endif
#endif

    int err = pthread_mutex_unlock(mtx);

    if(err != 0)
    {
        logger_handle_msg(g_system_logger, MSG_ERR, "mutex_unlock(%p) self=%p: %r", mtx, (intptr)thread_self(), MAKE_ERRNO_ERROR(err));
        debug_stacktrace_log(g_system_logger, MSG_ERR, debug_stacktrace_get());
        logger_flush();
        abort();
    }
}

int mutex_lock_unchecked(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger, MSG_DEBUG7, "mutex_lock(%p)", mtx);
#endif
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), mutex_type_name);
#endif
#endif

    int ret = pthread_mutex_lock(mtx);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_end(mcm);
#endif
#endif

    if(mutex_ultraverbose)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger, MSG_DEBUG7, "mutex_lock(%p): locked", mtx);
#endif
    }

    return ret;
}

int mutex_unlock_unchecked(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger, MSG_DEBUG7, "mutex_unlock(%p)", mtx);
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_unlock(thread_self(), mtx);
#endif
#endif

    int ret = pthread_mutex_unlock(mtx);

    if(ret != 0)
    {
        logger_handle_msg(g_system_logger, MSG_ERR, "mutex_unlock(%p) self=%p: %r", mtx, (intptr)thread_self(), MAKE_ERRNO_ERROR(ret));
        debug_stacktrace_log(g_system_logger, MSG_ERR, debug_stacktrace_get());
        logger_flush();
    }

    return ret;
}

#endif
