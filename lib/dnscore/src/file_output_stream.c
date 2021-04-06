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

/** @defgroup streaming Streams
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "dnscore/file_output_stream.h"
#include "dnscore/fdtools.h"

/*
 * This structure is supposed to match the output_stream one
 * It helps using the void* data as an int without a INT_AT(x) kind of macro
 */

typedef struct file_output_stream file_output_stream;

struct file_output_stream
{

    union
    {
        void *voidp;
        int fd;
    } data;

    const output_stream_vtbl* vtbl;
};

static ya_result
file_output_stream_write(output_stream* stream_, const u8* buffer, u32 len)
{
    const file_output_stream* stream = (file_output_stream*)stream_;

    const u8* start = buffer;

    while(len > 0)
    {
        ssize_t ret = write(stream->data.fd, buffer, len);

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
                int oldflags = fcntl (stream->data.fd, F_GETFL, 0);
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
        len -= (u32)ret;
    }

    return (ya_result)(buffer - start);
}

static ya_result
file_output_stream_writefully(output_stream* stream_, const u8* buffer, u32 len)
{
    const file_output_stream* stream = (file_output_stream*)stream_;

    const u8* start = buffer;

    while(len > 0)
    {
        ssize_t ret = write(stream->data.fd, buffer, len);

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
                int oldflags = fcntl (stream->data.fd, F_GETFL, 0);
                if(oldflags < 0)
                {
                     return MAKE_ERRNO_ERROR(err);
                }
#endif
                continue;
            }
            
            if(err == ENOSPC)
            {
                // the disk is full : wait a bit, hope the admin catches it, try again later
                sleep((rand()&7) + 1);
                continue;
            }

            /* error */
            return MAKE_ERRNO_ERROR(err);
        }

        buffer += ret;
        len -= (u32)ret;
    }

    return (ya_result)(buffer - start);
}

static ya_result
file_output_stream_flush(output_stream* stream_)
{
    file_output_stream* stream = (file_output_stream*)stream_;

    if(fsync_ex(stream->data.fd) == 0) /* or fdatasync ... maybe it would be slightly better */
    {
        return SUCCESS;
    }

    return ERRNO_ERROR;
}

static void
file_output_stream_close(output_stream* stream_)
{
    file_output_stream* stream = (file_output_stream*)stream_;
    
    /* don't, it's only for a test that I did this assert((stream->data.fd < 0)||(stream->data.fd >2)); */
    
    if(stream->data.fd != -1)   /* harmless close but still ... */
    {
        close_ex(stream->data.fd);
    }

    output_stream_set_void(stream_);
}

static void
file_output_stream_noclose(output_stream* stream_)
{
    file_output_stream* stream = (file_output_stream*)stream_;
    stream->data.fd = -1;
    output_stream_set_void(stream_);
}

static const output_stream_vtbl file_output_stream_noclose_vtbl ={
    file_output_stream_write,
    file_output_stream_flush,
    file_output_stream_noclose,
    "file_output_stream-noclose",
};

static const output_stream_vtbl file_output_stream_vtbl ={
    file_output_stream_write,
    file_output_stream_flush,
    file_output_stream_close,
    "file_output_stream",
};

static const output_stream_vtbl file_full_output_stream_vtbl ={
    file_output_stream_writefully,
    file_output_stream_flush,
    file_output_stream_close,
    "file_output_stream",
};

ya_result
file_output_stream_open(output_stream* stream, const char* filename)
{
    ya_result ret;
    ret = file_output_stream_open_ex(stream, filename, O_RDWR|O_CLOEXEC, 0600);
    return ret;
}

ya_result
file_output_stream_create(output_stream* stream, const char* filename, mode_t mode)
{
    ya_result ret;
    ret = file_output_stream_open_ex(stream, filename, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    return ret;
}

ya_result
file_output_stream_create_excl(output_stream* stream, const char* filename, mode_t mode)
{
    ya_result ret;
    ret = file_output_stream_open_ex(stream, filename, O_RDWR | O_CREAT | O_TRUNC | O_EXCL | O_CLOEXEC, mode);
    return ret;
}

ya_result
file_output_stream_set_full_writes(output_stream* stream, bool full_writes)
{
    if(is_fd_output_stream(stream))
    {
        if(full_writes)
        {
            stream->vtbl = &file_full_output_stream_vtbl;
        }
        else
        {
            stream->vtbl = &file_output_stream_vtbl;
        }
        return SUCCESS;
    }
    else
    {
        return INVALID_STATE_ERROR;
    }
}

ya_result
file_output_stream_open_ex(output_stream* stream_, const char* filename, int flags, mode_t mode)
{
    yassert(sizeof(void*) >= sizeof(int));

    int fd = open_create_ex(filename, flags, mode);

    if(fd < 0)
    {
        return ERRNO_ERROR;
    }
    
#if (_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L) && !defined(__gnu__hurd__)
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

    file_output_stream* stream = (file_output_stream*)stream_;
    stream->data.fd = fd;

    stream->vtbl = &file_output_stream_vtbl;

    return SUCCESS;
}

ya_result
file_output_stream_open_ex_nolog(output_stream* stream_, const char* filename, int flags, mode_t mode)
{
    yassert(sizeof(void*) >= sizeof(int));

    int fd = open_create_ex_nolog(filename, flags, mode);

    if(fd < 0)
    {
        return ERRNO_ERROR;
    }
    
#if (_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L) && !defined(__gnu__hurd__)
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

    file_output_stream* stream = (file_output_stream*)stream_;
    stream->data.fd = fd;

    stream->vtbl = &file_output_stream_vtbl;

    return SUCCESS;
}

void
file_output_stream_close_nolog(output_stream* stream_)
{
    file_output_stream* stream = (file_output_stream*)stream_;
    
    /* don't, it's only for a test that I did this assert((stream->data.fd < 0)||(stream->data.fd >2)); */
    
    if(stream->data.fd != -1)   /* harmless close but still ... */
    {
        close_ex(stream->data.fd);
        stream->data.fd = -1;
    }

    output_stream_set_void(stream_);
}

ya_result
fd_output_stream_attach(output_stream* stream_, int fd)
{
    yassert(sizeof(void*) >= sizeof(int));

    file_output_stream* stream = (file_output_stream*)stream_;
    stream->data.fd = fd;

    stream->vtbl = &file_output_stream_vtbl;

    return SUCCESS;
}

ya_result
fd_output_stream_attach_noclose(output_stream* stream_, int fd)
{
    yassert(sizeof(void*) >= sizeof(int));

    file_output_stream* stream = (file_output_stream*)stream_;
    stream->data.fd = fd;

    stream->vtbl = &file_output_stream_noclose_vtbl;

    return SUCCESS;
}

void
fd_output_stream_detach(output_stream* stream_)
{
    yassert(sizeof(void*) >= sizeof(int));

    file_output_stream* stream = (file_output_stream*)stream_;
    stream->data.fd = -1;
}

ya_result
fd_output_stream_get_filedescriptor(output_stream* stream)
{
    file_output_stream *fos = (file_output_stream*)stream;
    return fos->data.fd;
}

bool
is_fd_output_stream(output_stream* stream_)
{
    file_output_stream* stream = (file_output_stream*)stream_;
    return (stream != NULL) && ((stream->vtbl == &file_output_stream_vtbl) || (stream->vtbl == &file_full_output_stream_vtbl));
}

s64 fd_output_stream_get_size(output_stream* stream_)
{
    file_output_stream* stream = (file_output_stream*)stream_;
    
    struct stat s;
    
    if(fstat(stream->data.fd, &s) >= 0)
    {
        if(S_ISREG(s.st_mode))
        {
            return s.st_size;
        }
    }
    
    return (s64)ERRNO_ERROR;
}

void file_output_steam_advise_sequential(output_stream* stream_)
{
    file_output_stream* stream = (file_output_stream*)stream_;
    
#if (_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L) && !defined(__gnu__hurd__)
    if(stream->data.fd >= 0)
    {
        posix_fadvise(stream->data.fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    }
#endif
}

/** @} */
