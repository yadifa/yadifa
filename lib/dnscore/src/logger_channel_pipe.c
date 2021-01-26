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

/** @defgroup logger Logging functions
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>

#include <dnscore/thread.h>

#include "dnscore/logger_channel_pipe.h"

#include "dnscore/buffer_output_stream.h"
#include "dnscore/file_output_stream.h"
#include "dnscore/format.h"
#include "dnscore/chroot.h"
#include "dnscore/fdtools.h"
#include "dnscore/thread_pool.h"
#include "dnscore/popen-output-stream.h"
#include "dnscore/process.h"

#define PIPE_CHANNEL_BUFFER_SIZE 65536



struct pipe_data
{
    output_stream os;
    char *command;
    bool force_flush;
};

typedef struct pipe_data pipe_data;

static ya_result
logger_channel_pipe_append(const char *command, pipe_data* sd);

static ya_result
logger_channel_pipe_constmsg(logger_channel* chan, int level, char* text, u32 text_len, u32 date_offset)
{
    (void)level;
    (void)date_offset;

    pipe_data* sd = (pipe_data*)chan->data;

    output_stream_write(&sd->os, (const u8*)text, text_len);

    ya_result ret = output_stream_write(&sd->os, (const u8*)"\n", 1);
    
    if(ret == MAKE_ERRNO_ERROR(EPIPE))
    {
        output_stream_flush(&sd->os);
        output_stream_close(&sd->os);
        output_stream_set_sink(&sd->os);

        if(ISOK(ret = logger_channel_pipe_append(sd->command, sd)))
        {
            output_stream_write(&sd->os, (const u8*)text, text_len);
            ret = output_stream_write(&sd->os, (const u8*)"\n", 1);

            if(ret == MAKE_ERRNO_ERROR(EPIPE))
            {
                output_stream_flush(&sd->os);
                output_stream_close(&sd->os);
                output_stream_set_sink(&sd->os);

                // no third chance
            }
        }
        else
        {
            output_stream_set_sink(&sd->os);
        }
    }

    if(sd->force_flush)
    {
        output_stream_flush(&sd->os);
    }

    return ret;
}

static ya_result
logger_channel_pipe_vmsg(logger_channel* chan, int level, char* text, va_list args)
{
    (void)level;

    pipe_data* sd = (pipe_data*)chan->data;

    vosformat(&sd->os, text, args);

    ya_result ret = output_stream_write(&sd->os, (const u8*)"\n", 1);
    
    if(ret == MAKE_ERRNO_ERROR(EPIPE))
    {
        // the child is probably dead as the connection has been closed

        // close our side

        output_stream_flush(&sd->os);
        output_stream_close(&sd->os);

        // sink it for now

        output_stream_set_sink(&sd->os);

        // try to pipe again

        if(ISOK(ret = logger_channel_pipe_append(sd->command, sd)))
        {
            vosformat(&sd->os, text, args);
            ret = output_stream_write(&sd->os, (const u8*)"\n", 1);

            if(ret == MAKE_ERRNO_ERROR(EPIPE))
            {
                output_stream_flush(&sd->os);
                output_stream_close(&sd->os);
                output_stream_set_sink(&sd->os);

                // no third chance
            }
        }
        else
        {
            // sink

            output_stream_set_sink(&sd->os);
        }
    }

    if(sd->force_flush)
    {
        output_stream_flush(&sd->os);
    }

    return ret;
}

static ya_result
logger_channel_pipe_msg(logger_channel* chan, int level, char* text, ...)
{
    va_list args;
    va_start(args, text);

    ya_result ret = logger_channel_pipe_vmsg(chan, level, text, args);

    va_end(args);

    return ret;
}

static void
logger_channel_pipe_flush(logger_channel* chan)
{
    pipe_data* sd = (pipe_data*)chan->data;

    output_stream_flush(&sd->os);
}

static void
logger_channel_pipe_close(logger_channel* chan)
{
    pipe_data* sd = (pipe_data*)chan->data;

    output_stream_flush(&sd->os);
    output_stream_close(&sd->os);
#ifndef WIN32
    chroot_unmanage_path(&sd->command);
#endif
    free(sd->command);
    
    chan->vtbl = NULL;
    sd->os.data = NULL;
    sd->os.vtbl = NULL;

    free(chan->data);
    chan->data = NULL;
}
static ya_result
logger_channel_pipe_append(const char *command, pipe_data* sd)
{
    // fork & exec
    
    popen_output_stream_parameters params;
    params.uid = logger_get_uid();
    params.gid = logger_get_gid();

    ya_result ret = popen_output_stream_ex(&sd->os, command, &params);
    if(ISOK(ret))
    {
        ret = buffer_output_stream_init(&sd->os, &sd->os, PIPE_CHANNEL_BUFFER_SIZE);
    }
    return ret;
}

static ya_result
logger_channel_pipe_reopen(logger_channel* chan)
{    
    ya_result ret;        
    pipe_data* sd = (pipe_data*)chan->data;
    struct timeval tv;
    struct tm t;
    
#if DNSCORE_HAS_LOG_THREAD_TAG
    char thread_tag_buffer[9];
#endif

    logger_channel_pipe_flush(chan);
    
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &t);
    
#if DNSCORE_HAS_LOG_THREAD_TAG
    thread_copy_tag_with_pid_and_tid(getpid_ex(), thread_self(), thread_tag_buffer);
#endif
    
    logger_channel_pipe_msg(chan, LOG_NOTICE,

#if (DEBUG || HAS_LOG_PID) && DNSCORE_HAS_LOG_THREAD_TAG
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %-5i | %s | %8s | I | reopening '%s'",
#elif DEBUG || (HAS_LOG_PID && HAS_LOG_THREAD_ID)
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %-5i | %08x | %8s | I | reopening '%s'",
#elif DNSCORE_HAS_LOG_THREAD_TAG
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %s | %8s | I | reopening '%s'",
#elif HAS_LOG_THREAD_ID
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %08x | %8s | I | reopening '%s'",
#elif HAS_LOG_PID
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %-5i | %8s | I | reopening '%s'",
#else
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %8s | I | reopening '%s'",
#endif
                            t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
                            t.tm_hour, t.tm_min, t.tm_sec, tv.tv_usec, // t is initialized at line 338 (localtime_r)
#if DEBUG || HAS_LOG_PID
                            getpid(),
#endif
#if DNSCORE_HAS_LOG_THREAD_TAG
                            thread_tag_buffer,
#else
    #if DEBUG || HAS_LOG_THREAD_ID
                            thread_self(),
    #endif
#endif
                            "system",
                            sd->command);
    
    logger_channel_pipe_flush(chan);
    
    output_stream_flush(&sd->os);
    output_stream_close(&sd->os);
    output_stream_set_sink(&sd->os);

    if(FAIL(ret = logger_channel_pipe_append(sd->command, sd)))
    {
        output_stream_set_sink(&sd->os);
    }
    
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &t);

    logger_channel_pipe_msg(chan, LOG_NOTICE,
    
#if (DEBUG || HAS_LOG_PID) && DNSCORE_HAS_LOG_THREAD_TAG
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %-5i | %s | %8s | I | reopened '%s'",
#elif DEBUG || (HAS_LOG_PID && HAS_LOG_THREAD_ID)
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %-5i | %08x | %8s | I | reopened '%s'",
#elif DNSCORE_HAS_LOG_THREAD_TAG
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %s | %8s | I | reopened '%s'",
#elif HAS_LOG_THREAD_ID
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %08x | %8s | I | reopened '%s'",
#elif HAS_LOG_PID
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %-5i | %8s | I | reopened '%s'",
#else
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %8s | I | reopened '%s'",
#endif
                            t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
                            t.tm_hour, t.tm_min, t.tm_sec, tv.tv_usec,
#if DEBUG || HAS_LOG_PID
                            getpid(),
#endif
#if DNSCORE_HAS_LOG_THREAD_TAG
                            thread_tag_buffer,
#else
    #if DEBUG || HAS_LOG_THREAD_ID
                            thread_self(),
    #endif
#endif
                            "system",
                            sd->command);
    logger_channel_pipe_flush(chan);
        
    return ret;
}

static void
logger_channel_pipe_sink(logger_channel* chan)
{
    pipe_data* sd = (pipe_data*)chan->data;
    //
    (void)sd;
}

static const logger_channel_vtbl stream_vtbl =
{
    logger_channel_pipe_constmsg,
    logger_channel_pipe_msg,
    logger_channel_pipe_vmsg,
    logger_channel_pipe_flush,
    logger_channel_pipe_close,
    logger_channel_pipe_reopen,
    logger_channel_pipe_sink,
    "pipe_channel"
};

ya_result
logger_channel_pipe_open(const char *fullpath, bool forceflush, logger_channel* chan)
{
    if(chan == NULL)
    {
        osformatln(termerr, "tried to open pipe '%s' on uninitialised channel", fullpath);
        return OBJECT_NOT_INITIALIZED;
    }
    
    ya_result ret;
    
    pipe_data* sd;
    MALLOC_OBJECT_OR_DIE(sd, pipe_data, 0x4d5254534e414843); /* CHANSTRM */

    if(ISOK(ret = logger_channel_pipe_append(fullpath, sd)))
    {
        sd->command = strdup(fullpath);
        //chroot_manage_path(&sd->command, fullpath, FALSE);
        sd->force_flush = forceflush;

        chan->data = sd;
        chan->vtbl = &stream_vtbl;
    }
    else
    {
        free(sd);
    }

    return ret;
}

/** @} */
