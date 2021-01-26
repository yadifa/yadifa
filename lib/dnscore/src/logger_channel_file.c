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

#include "dnscore/logger_channel_file.h"

#include "dnscore/buffer_output_stream.h"
#include "dnscore/file_output_stream.h"
#include "dnscore/format.h"
#include "dnscore/chroot.h"
#include "dnscore/fdtools.h"
#include "dnscore/thread_pool.h"
#include "dnscore/process.h"

/*
 * The new logger model does not requires MT protection on the channels
 */

#define FILE_CHANNEL_BUFFER_SIZE 65536

#define DEBUG_LOG_CHANNEL 0

typedef struct file_data file_data;

struct file_data
{
    output_stream os;
    char *file_name;
    int fd;
    uid_t uid;
    gid_t gid;
    u16 mode;
    bool force_flush;
};

static ya_result
logger_channel_file_constmsg(logger_channel* chan, int level, char* text, u32 text_len, u32 date_offset)
{
    (void)level;
    (void)date_offset;

    file_data* sd = (file_data*)chan->data;

    output_stream_write(&sd->os, (const u8*)text, text_len);

    ya_result ret = output_stream_write(&sd->os, (const u8*)"\n", 1);

    if(sd->force_flush)
    {
        output_stream_flush(&sd->os);
    }

    return ret;
}

static ya_result
logger_channel_file_vmsg(logger_channel* chan, int level, char* text, va_list args)
{
    (void)level;

    file_data* sd = (file_data*)chan->data;

    vosformat(&sd->os, text, args);

    ya_result ret = output_stream_write(&sd->os, (const u8*)"\n", 1);

    if(sd->force_flush)
    {
        output_stream_flush(&sd->os);
    }

    return ret;
}

static ya_result
logger_channel_file_msg(logger_channel* chan, int level, char* text, ...)
{
    va_list args;
    va_start(args, text);

    ya_result ret = logger_channel_file_vmsg(chan, level, text, args);

    va_end(args);

    return ret;
}

static void
logger_channel_file_flush(logger_channel* chan)
{
    file_data* sd = (file_data*)chan->data;

    output_stream_flush(&sd->os);
}

static void
logger_channel_file_close(logger_channel* chan)
{
    file_data* sd = (file_data*)chan->data;

    output_stream_flush(&sd->os);
    output_stream_close(&sd->os);
#ifndef WIN32
    chroot_unmanage_path(&sd->file_name);
#endif    
    free(sd->file_name);
    
    chan->vtbl = NULL;
    sd->os.data = NULL;
    sd->os.vtbl = NULL;

    free(chan->data);
    chan->data = NULL;
}

static ya_result
logger_channel_file_append(const char *fullpath, uid_t uid, gid_t gid, u16 mode, file_data* sd)
{
#if DEBUG_LOG_CHANNEL
    osformatln(termerr, "logger_channel_file_append(%s, %i, %i, %o, %p)", fullpath, uid, gid, mode, sd);
#endif
    
    output_stream errlog_os;
    output_stream buffered_errlog_os;
    ya_result return_code;

    if(FAIL(return_code = file_output_stream_open_ex_nolog(
                    &errlog_os,
                    fullpath,
                    O_CREAT|O_APPEND|O_RDWR|O_CLOEXEC,
                    mode)))
    {
#if DEBUG_LOG_CHANNEL
        osformatln(termerr, "logger_channel_file_append(%s, %i, %i, %o, %p) failed at open", fullpath, uid, gid, mode, sd);
#endif
        sd->fd = -1;
        return return_code;
    }

    /*
     * Change ownership of the file here.
     */

    int fd = fd_output_stream_get_filedescriptor(&errlog_os);
#ifndef WIN32
    if((getuid() != uid) || (getgid() != gid))
    {
        if(fchown(fd, uid, gid) < 0)
        {
#if DEBUG_LOG_CHANNEL
            osformatln(termerr, "logger_channel_file_append(%s, %i, %i, %o, %p) failed at fchown", fullpath, uid, gid, mode, sd);
#endif
            return_code = ERRNO_ERROR;
            output_stream_close(&errlog_os);
            sd->fd = -1;
            return return_code;
        }
    }
#endif
    sd->fd = fd;
    
    if(FAIL(return_code = buffer_output_stream_init(&buffered_errlog_os, &errlog_os, FILE_CHANNEL_BUFFER_SIZE)))
    {
#if DEBUG_LOG_CHANNEL
        osformatln(termerr, "logger_channel_file_append(%s, %i, %i, %o, %p) failed at buffering", fullpath, uid, gid, mode, sd);
#endif
        
        output_stream_close(&errlog_os);
        sd->fd = -1;
        return return_code;
    }

    sd->os.data = buffered_errlog_os.data;
    sd->os.vtbl = buffered_errlog_os.vtbl;

    return SUCCESS;
}

static ya_result
logger_channel_file_reopen(logger_channel* chan)
{    
    ya_result return_code;        
    file_data* sd = (file_data*)chan->data;
    struct timeval tv;
    struct tm t;
    
#if DEBUG_LOG_CHANNEL
    osformatln(termerr, "logger_channel_file_reopen(%s)", sd->file_name);
#endif
    
#if DNSCORE_HAS_LOG_THREAD_TAG
    char thread_tag_buffer[9];
#endif

    output_stream_flush(&sd->os);

    sd->uid = logger_get_uid();
    sd->gid = logger_get_gid();
    
    ///
    
    /* open a new file stream */
    
    output_stream errlog_os;

    if(FAIL(return_code = file_output_stream_open_ex_nolog(
                    &errlog_os,
                    sd->file_name,
                    O_CREAT|O_APPEND|O_RDWR|O_CLOEXEC,
                    sd->mode)))
    {
#if DEBUG_LOG_CHANNEL
        osformatln(termerr, "failed to file_output_stream_open_ex_nolog(os,%s,CREATE+APPEND+RDWR,%o)",
                sd->file_name,
                sd->mode
                );
#endif
        
        logger_channel_file_flush(chan);

        gettimeofday(&tv, NULL);
        localtime_r(&tv.tv_sec, &t);

        logger_channel_file_msg(chan, LOG_NOTICE, "%04d-%02d-%02d %02d:%02d:%02d.%06d | %-5i | %08x | %8s | N | unable to reopen '%s': %r, resuming on original",
                                t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
                                t.tm_hour, t.tm_min, t.tm_sec, tv.tv_usec,
                                getpid_ex(), thread_self(),  "system",
                                sd->file_name, return_code);
        logger_channel_file_flush(chan);
        
        return return_code;
    }

    /* change ownership of the file */

    int fd = fd_output_stream_get_filedescriptor(&errlog_os);
    
#if DEBUG_LOG_CHANNEL
    if(fd < 0)
    {
        osformatln(termerr, "failed to file_output_stream_open_ex_nolog(os,%s,CREATE+APPEND+RDWR,%o), got fd=-1 when everyting else looked fine",
                sd->file_name,
                sd->mode
                );
    }
#endif
#ifndef WIN32
    if((getuid() != sd->uid) || (getgid() != sd->gid))
#endif
    {
#ifndef WIN32
        if(fchown(fd, sd->uid, sd->gid) < 0)
#endif
        {
#if DEBUG_LOG_CHANNEL
            osformatln(termerr, "failed to chown(%i,%i,%i)",
                    fd, sd->uid, sd->gid
                    );
#endif
            
            return_code = ERRNO_ERROR;

            output_stream_close(&errlog_os);

            logger_channel_file_flush(chan);
            
            gettimeofday(&tv, NULL);
            localtime_r(&tv.tv_sec, &t);

            logger_channel_file_msg(chan, LOG_NOTICE, "%04d-%02d-%02d %02d:%02d:%02d.%06d | %-5i | %08x | %8s | N | unable to fchown '%s': %r, resuming on original",
                                    t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
                                    t.tm_hour, t.tm_min, t.tm_sec, tv.tv_usec,
                                    getpid_ex(), thread_self(),  "system",
                                    sd->file_name, return_code);

            logger_channel_file_flush(chan);

            return return_code;
        }
    }
    
    logger_channel_file_flush(chan);
    
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &t);
    
#if DNSCORE_HAS_LOG_THREAD_TAG
    thread_copy_tag_with_pid_and_tid(getpid_ex(), thread_self(), thread_tag_buffer);
#endif
    
    logger_channel_file_msg(chan, LOG_NOTICE,

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
                            t.tm_hour, t.tm_min, t.tm_sec, tv.tv_usec,
#if DEBUG || HAS_LOG_PID
                            getpid_ex(),
#endif
#if DNSCORE_HAS_LOG_THREAD_TAG
                            thread_tag_buffer,
#else
    #if DEBUG || HAS_LOG_THREAD_ID
                            thread_self(),
    #endif
#endif
                            "system",
                            sd->file_name);
    
    logger_channel_file_flush(chan);
    
#if DEBUG_LOG_CHANNEL
    osformatln(termerr, "so far so good: will exchange fds %i and %i in the channel", fd, sd->fd);
#endif
    
    output_stream* fos = buffer_output_stream_get_filtered(&sd->os);
    
    /* exchange the file descriptors */
    fd_output_stream_attach(fos, fd);
    fd_output_stream_attach(&errlog_os, sd->fd);
    sd->fd = fd;
    
#if DEBUG_LOG_CHANNEL
    osformatln(termerr, "closing the stream supposed to contain", sd->fd);
#endif
    
    file_output_stream_close_nolog(&errlog_os); // and NOT output_stream_close(&errlog_os);
    
    logger_channel_file_flush(chan);
    
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &t);

    logger_channel_file_msg(chan, LOG_NOTICE,
    
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
                            getpid_ex(),
#endif
#if DNSCORE_HAS_LOG_THREAD_TAG
                            thread_tag_buffer,
#else
    #if DEBUG || HAS_LOG_THREAD_ID
                            thread_self(),
    #endif
#endif
                            "system",
                            sd->file_name);
    logger_channel_file_flush(chan);
        
    return return_code;
}

static void
logger_channel_file_sink(logger_channel* chan)
{
    file_data* sd = (file_data*)chan->data;
    
//    fcntl(fd, F_GETFD);
    
    struct stat st;
    st.st_nlink = 0;
    fstat(sd->fd, &st);
    
#if DEBUG_LOG_CHANNEL
    osformatln(termerr, "logger_channel_file_sink(%s = %i) (going to /dev/null): %r", sd->file_name, sd->fd, ERRNO_ERROR);
#endif
        
    if(st.st_nlink == 0)
    {
        int ret = 0;
        // deleted
        // close and open /dev/null instead

        int dev_null = open_ex("/dev/null", O_WRONLY);
        
        if(dev_null >= 0)
        {
#if DEBUG_LOG_CHANNEL
            osformatln(termerr, "logger_channel_file_sink(%s) file is not referenced anymore: sinking it to /dev/null with fd=%i", sd->file_name, dev_null);
#endif
            if(ISOK(ret = dup2_ex(dev_null, sd->fd)))
            {        
                close_ex(dev_null);
/*
                if(ret < 0)
                {
                    close_ex(sd->fd);
                    sd->fd = -1;
                }
 */
            }
            else
            {
#if DEBUG_LOG_CHANNEL
                osformatln(termerr, "logger_channel_file_sink(%s) dup_ex(%i,%i) failed (%r)", sd->file_name, ret);
#endif
                // more involved work
                
#if DEBUG_LOG_CHANNEL
                osformatln(termerr, "instead will put fd %i in the channel, replacing %i", dev_null, sd->fd);
#endif
    
                output_stream* fos = buffer_output_stream_get_filtered(&sd->os);

                /* exchange the file descriptors */
                fd_output_stream_attach(fos, dev_null);
                if(sd->fd >= 0)
                {
#if DEBUG_LOG_CHANNEL
                    osformatln(termerr, "closing the contained file descriptor %i", sd->fd);
#endif
                    close_ex(sd->fd);
                }
                sd->fd = dev_null;                
            }
        }
        else
        {
#if DEBUG_LOG_CHANNEL
            osformatln(termerr, "logger_channel_file_sink(%s) failed to open /dev/null : cannot sink the output", sd->file_name, ret);
#endif            
        }
    }
    else
    {
#if DEBUG_LOG_CHANNEL
        osformatln(termerr, "logger_channel_file_sink(%s) file has still %i references", sd->file_name, st.st_nlink);
#endif
    }
}

static const logger_channel_vtbl stream_vtbl =
{
    logger_channel_file_constmsg,
    logger_channel_file_msg,
    logger_channel_file_vmsg,
    logger_channel_file_flush,
    logger_channel_file_close,
    logger_channel_file_reopen,
    logger_channel_file_sink,
    "file_channel"
};

ya_result
logger_channel_file_open(const char *fullpath, uid_t uid, gid_t gid, u16 mode, bool forceflush, logger_channel* chan)
{
    if(chan == NULL)
    {
        osformatln(termerr, "tried to open file '%s' on uninitialised channel", fullpath);
        return OBJECT_NOT_INITIALIZED;
    }
    
    ya_result return_code;
    
    file_data* sd;
    MALLOC_OBJECT_OR_DIE(sd, file_data, 0x4d5254534e414843); /* CHANSTRM */

    if(ISOK(return_code = logger_channel_file_append(fullpath, uid, gid, mode, sd)))
    {
        sd->file_name = strdup(fullpath);
#ifndef WIN32
        chroot_manage_path(&sd->file_name, fullpath, FALSE);
#endif
        sd->uid = uid;
        sd->gid = gid;
        sd->mode = mode;
        sd->force_flush = forceflush;

        chan->data = sd;
        chan->vtbl = &stream_vtbl;
    }
    else
    {
        free(sd);
    }

    return return_code;
}

ya_result
logger_channel_file_rename(logger_channel *chan, const char *newpath)
{
    file_data* sd = (file_data*)chan->data;

    if(sd != NULL)
    {
        if(strcmp(sd->file_name, newpath) != 0)
        {
            free(sd->file_name);
            sd->file_name = strdup(newpath);
            
            return SUCCESS;
        }
    }
    
    return INVALID_STATE_ERROR;
}

/** @} */
