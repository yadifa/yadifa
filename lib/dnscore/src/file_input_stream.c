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
 * @defgroup streaming Streams
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#if _FILE_OFFSET_BITS != 64
#define _LARGEFILE64_SOURCE
#endif

#include "dnscore/dnscore_config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "dnscore/file_input_stream.h"
#include "dnscore/fdtools.h"
#include "dnscore/timems.h"

#define FILE_INPUT_STREAM_FD_GET(stream___)        ((int)(intptr_t)((stream___)->data))
#define FILE_INPUT_STREAM_FD_SET(stream___, fd___) (stream___)->data = (void *)(intptr_t)fd___;

#if DEBUG_BENCH_FD
static debug_bench_t debug_read;
static bool          file_input_stream_debug_bench_register_done = false;

static inline void   file_input_stream_debug_bench_register()
{
    if(!file_input_stream_debug_bench_register_done)
    {
        file_input_stream_debug_bench_register_done = true;
        debug_bench_register(&debug_read, "read");
    }
}
#endif

/*
 * Maybe I should not do a "read-fully" here ...
 */

static ya_result file_input_stream_read(input_stream_t *stream_, void *buffer_, uint32_t len)
{
#if DEBUG_BENCH_FD
    file_input_stream_debug_bench_register();
    uint64_t bench = debug_bench_start(&debug_read);
#endif

    uint8_t *buffer = (uint8_t *)buffer_;

    int      fd = FILE_INPUT_STREAM_FD_GET(stream_);

    uint8_t *start = buffer;

    while(len > 0)
    {
#if defined(SSIZE_MAX) && (SSIZE_MAX < 0xffffffffU)
        ssize_t ret = read(fd, buffer, MIN(len, SSIZE_MAX));
#else
        ssize_t ret = read(fd, buffer, len);
#endif
        if(ret < 0)
        {
            int err = errno;

            if(err == EINTR)
            {
                continue;
            }

#if DEBUG
            if(err == EBADF)
            {
                fprintf(stderr, "bad file descriptor %i", fd);
            }
#endif

            if(buffer - start > 0)
            {
                return buffer - start;
            }

            /* error */
            return MAKE_ERRNO_ERROR(err);
        }

        if(ret == 0) /* EOF */
        {
            break;
        }

        buffer += ret;
        len -= ret;
    }

#if DEBUG_BENCH_FD
    debug_bench_stop(&debug_read, bench);
#endif

    return buffer - start;
}

static void file_input_stream_close(input_stream_t *stream_)
{
    int fd = FILE_INPUT_STREAM_FD_GET(stream_);

    assert((fd < 0) || (fd > 2));

    if(fd != -1)
    {
        close_ex(fd);
    }

    input_stream_set_void(stream_);
}

static void      file_input_stream_noclose(input_stream_t *stream_) { input_stream_set_void(stream_); }

static ya_result file_input_stream_skip(input_stream_t *stream_, uint32_t len)
{
    int fd = FILE_INPUT_STREAM_FD_GET(stream_);
    if(lseek(fd, len, SEEK_CUR) >= 0)
    {
        return len;
    }

    return ERRNO_ERROR;
}

static const input_stream_vtbl file_input_stream_vtbl = {file_input_stream_read, file_input_stream_skip, file_input_stream_close, "file_input_stream"};

static const input_stream_vtbl file_input_stream_noclose_vtbl = {file_input_stream_read, file_input_stream_skip, file_input_stream_noclose, "file_input_stream-noclose"};

ya_result                      fd_input_stream_attach(input_stream_t *stream_, int fd)
{
    if(fd < 0)
    {
        return ERRNO_ERROR;
    }

    FILE_INPUT_STREAM_FD_SET(stream_, fd);
    stream_->vtbl = &file_input_stream_vtbl;

    return SUCCESS;
}

ya_result fd_input_stream_attach_noclose(input_stream_t *stream_, int fd)
{
    if(fd < 0)
    {
        return ERRNO_ERROR;
    }

    FILE_INPUT_STREAM_FD_SET(stream_, fd);
    stream_->vtbl = &file_input_stream_noclose_vtbl;

    return SUCCESS;
}

void      fd_input_stream_detach(input_stream_t *stream_) { FILE_INPUT_STREAM_FD_SET(stream_, -1); }

ya_result file_input_stream_open(input_stream_t *stream_, const char *filename)
{
    int fd = open_ex(filename, O_RDONLY | O_CLOEXEC);

#if (_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L) && !defined(__gnu__hurd__)
    if(fd >= 0)
    {
        posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    }
#endif

    return fd_input_stream_attach(stream_, fd);
}

ya_result file_input_stream_open_ex(input_stream_t *stream_, const char *filename, int flags)
{
    int fd = open_ex(filename, O_RDONLY | O_CLOEXEC | flags);

#if(_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L) && !defined(__gnu__hurd__)
    if(fd >= 0)
    {
        posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    }
#endif

    return fd_input_stream_attach(stream_, fd);
}

ya_result fd_input_stream_get_filedescriptor(input_stream_t *stream_) { return FILE_INPUT_STREAM_FD_GET(stream_); }

ya_result fd_input_stream_seek(input_stream_t *stream_, uint64_t offset)
{
    if(is_fd_input_stream(stream_))
    {
        int fd = FILE_INPUT_STREAM_FD_GET(stream_);

        int ret;
#if _FILE_OFFSET_BITS == 64
        ret = lseek(fd, offset, SEEK_SET);
#else
        ret = lseek64(fd, offset, SEEK_SET);
#endif

        if(ret >= 0)
        {
            return SUCCESS;
        }
        else
        {
            return ERRNO_ERROR;
        }
    }
    else
    {
        return INCORRECT_RDATA;
    }
}

bool is_fd_input_stream(input_stream_t *stream_) { return (stream_ != NULL) && (stream_->vtbl->read == file_input_stream_read); }

void file_input_steam_advise_sequential(input_stream_t *stream_)
{
#if(_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L) && !defined(__gnu_hurd__)
    int fd = FILE_INPUT_STREAM_FD_GET(stream_);
    if(fd >= 0)
    {
        posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    }
#else
    (void)stream_;
#endif
}

/** @} */
