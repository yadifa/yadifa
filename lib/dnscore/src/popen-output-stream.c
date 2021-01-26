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

/** @defgroup dnscore
 *  @ingroup dnscore
 *  @brief popen is not enough
 *  *
 * @{
 */

#include "dnscore/dnscore-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>

#define _ZALLOC_C

#include "dnscore/sys_types.h"
#include "dnscore/popen-output-stream.h"
#include "dnscore/fdtools.h"
#include "dnscore/zalloc.h"
#include "dnscore/identity.h"

#if DEBUG
#include "dnscore/format.h"
#endif

#define POPENOSD_TAG 0x44534f4e45504f50

struct popen_output_stream_data
{
    int fd;
    pid_t child;
};

typedef struct popen_output_stream_data popen_output_stream_data;

static ya_result
popen_output_stream_write(output_stream* stream, const u8* buffer, u32 len)
{
    int fd = ((popen_output_stream_data*)stream->data)->fd;

    const u8* start = buffer;

    while(len > 0)
    {
        ssize_t ret = write(fd, buffer, len);

        if(ret <= 0)
        {
            int err = errno;

            if(err == EINTR)
            {
                continue;
            }
            
            if(err == EAGAIN)
            {
#if __FreeBSD__ || __OpenBSD__ || __APPLE__
                int oldflags = fcntl (fd, F_GETFL, 0);
                if(oldflags < 0)
                {
                     return MAKE_ERRNO_ERROR(err);
                }
#endif
                continue;
            }
            
            /* error */
            return MAKE_ERRNO_ERROR(err);
        }

        buffer += ret;
        len -= ret;
    }

    return buffer - start;
}

static ya_result
popen_output_stream_flush(output_stream* stream)
{
    int fd = ((popen_output_stream_data*)stream->data)->fd;

    if(fsync_ex(fd) == 0) /* or fdatasync ... maybe it would be slightly better */
    {
        return SUCCESS;
    }

    return ERRNO_ERROR;
}

static void
popen_output_stream_close(output_stream* stream)
{
    struct popen_output_stream_data *data = (struct popen_output_stream_data*)stream->data;
#if DEBUG
    int fd = data->fd;
#endif
    close_ex(data->fd);
    data->fd = -1;
    int status;

#if DEBUG
    formatln("popen_output_stream_close(%i, %i) (wait)", data->child, fd);
#endif

    while(waitpid(data->child, &status, 0) < 0)
    {
        int err = errno;
        
        if(err != EINTR)
        {
            break;
        }
    }

#if DEBUG
    formatln("popen_output_stream_close(%i, %i) (done)", data->child, fd);
#endif

    data->child = -1;
    ZFREE_OBJECT(data);
}

static const output_stream_vtbl popen_output_stream_vtbl =
{
    popen_output_stream_write,
    popen_output_stream_flush,
    popen_output_stream_close,
    "popen_output_stream",
};

int
popen_output_stream_ex(output_stream* os, const char* command, popen_output_stream_parameters* parms)
{
#ifndef WIN32
    int write_pipe[2];
    ya_result ret;

    /// @note 20210104 edf -- The null file is opened at this moment so we can return with an error right now if it fails.
    ///                       It is way better than forking and failing.

#if DEBUG
    formatln("popen_output_stream_ex(%s) (open null)", command);
#endif

    int fdnull = open_ex("/dev/null", O_WRONLY);
    if(fdnull < 0)
    {
        return ERRNO_ERROR;
    }

#if DEBUG
    formatln("popen_output_stream_ex(%s) (pipe)", command);
#endif
    
    if(pipe(write_pipe) < 0)
    {
        ret = ERRNO_ERROR;
        close_ex(fdnull);
        return ret;
    }

#if DEBUG
    formatln("popen_output_stream_ex(%s) (fork)", command);
#endif
    
    pid_t child;
    if((child = fork()) > 0)
    {
        // child + write_pipe[1]
        
        close_ex(write_pipe[0]);
        fd_setcloseonexec(write_pipe[1]);

        close_ex(fdnull);
        
        popen_output_stream_data* data;
        ZALLOC_OBJECT_OR_DIE(data, popen_output_stream_data, POPENOSD_TAG);
        data->fd = write_pipe[1];
        data->child = child;
        os->data = data;
        os->vtbl = &popen_output_stream_vtbl;

#if DEBUG
        formatln("popen_output_stream_ex(%s) = (%i, %i)", command, data->child, data->fd);
#endif

        return SUCCESS;
    }
    else if(child == 0)
    {
        close_ex(write_pipe[1]);
#ifndef WIN32
        signal(SIGHUP, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGABRT, SIG_DFL);
        signal(SIGSEGV, SIG_DFL);
        signal(SIGPIPE, SIG_DFL);
        signal(SIGALRM, SIG_DFL);
        signal(SIGTERM, SIG_DFL);

        identity_change(parms->uid, parms->gid);   
#endif
        dup2_ex(write_pipe[0], 0);  // write to its standard input
        dup2_ex(fdnull, 1);                // ignore its standard output
        dup2_ex(fdnull, 2);                // ignore its standard error
        close_ex(write_pipe[0]);
        close_ex(fdnull);
        
        execl("/bin/sh", "sh", "-c", command, NULL); /// @note 20210104 edf -- this would obviously fail if /bin/sh isn't present.
        
        // never reached
        
        abort();
    }
    else // fork failed
    {
        ret = ERRNO_ERROR;

        close_ex(write_pipe[0]);
        close_ex(write_pipe[1]);
        close_ex(fdnull);

        return ret;
    }
#else
    return -1;
#endif
}

/** @} */
