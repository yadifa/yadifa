/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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

#if _FILE_OFFSET_BITS != 64
#define _LARGEFILE64_SOURCE
#endif


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "dnscore/file_input_stream.h"
#include "dnscore/fdtools.h"
#include "dnscore/timems.h"

typedef struct file_input_stream file_input_stream;

struct file_input_stream
{

    union
    {
        void* _voidp;
        int fd;
    } data;

    const input_stream_vtbl* vtbl;
};

#if DEBUG_BENCH_FD
static debug_bench_s debug_read;
static bool file_input_stream_debug_bench_register_done = FALSE;

static inline void file_input_stream_debug_bench_register()
{
    if(!file_input_stream_debug_bench_register_done)
    {
        file_input_stream_debug_bench_register_done = TRUE;
        debug_bench_register(&debug_read, "read");
    }
}
#endif

/*
 * Maybe I should not do a "read-fully" here ...
 */

static ya_result
file_read(input_stream* stream_, u8* buffer, u32 len)
{
#ifdef SSIZE_MAX
#if SSIZE_MAX < 0xffffffffU
#pragma message "POTENTIAL UNSPECIFIED RESULT IF len IS BIGGER THAN SSIZE_MAX"
#endif
#endif

#if DEBUG_BENCH_FD
    file_input_stream_debug_bench_register();
    u64 bench = debug_bench_start(&debug_read);
#endif
    
    file_input_stream* stream = (file_input_stream*)stream_;

    u8* start = buffer;

    while(len > 0)
    {
        ssize_t ret = read(stream->data.fd, buffer, len);

        if(ret < 0)
        {
            int err = errno;

            if(err == EINTR)
            {
                continue;
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

static void
file_close(input_stream* stream_)
{
    file_input_stream* stream = (file_input_stream*)stream_;
    
    assert((stream->data.fd < 0)||(stream->data.fd >2));
    
    if(stream->data.fd != ~0)
    {
        close_ex(stream->data.fd);
    }
    
    input_stream_set_void(stream_);
}

static ya_result
file_skip(input_stream* stream_, u32 len)
{
    file_input_stream* stream = (file_input_stream*)stream_;
    if(lseek(stream->data.fd, len, SEEK_CUR) >= 0)
    {
        return len;
    }

    return ERRNO_ERROR;
}

static const input_stream_vtbl file_input_stream_vtbl ={
    file_read,
    file_skip,
    file_close,
    "file_input_stream"
};

ya_result
fd_input_stream_attach(int fd, input_stream *stream_)
{
    file_input_stream* stream = (file_input_stream*)stream_;

    if(fd < 0)
    {
        return ERRNO_ERROR;
    }

    stream->data.fd = fd;
    stream->vtbl = &file_input_stream_vtbl;

    return SUCCESS;
}

void
fd_input_stream_detach(input_stream *stream_)
{
    file_input_stream* stream = (file_input_stream*)stream_;

    stream->data.fd = -1;
}

ya_result
file_input_stream_open(const char *filename, input_stream *stream_)
{
    int fd = open_ex(filename, O_RDONLY);

    return fd_input_stream_attach(fd, stream_);
}

ya_result
file_input_stream_open_ex(const char *filename, int flags, input_stream *stream_)
{
    int fd = open_ex(filename, O_RDONLY | flags);

    return fd_input_stream_attach(fd, stream_);
}

ya_result fd_input_stream_get_filedescriptor(input_stream* stream_)
{
    file_input_stream* stream = (file_input_stream*)stream_;

    return stream->data.fd ;
}

ya_result fd_input_stream_seek(input_stream* stream_, u64 offset)
{
    if(is_fd_input_stream(stream_))
    {
        file_input_stream* stream = (file_input_stream*)stream_;

        int ret;
#if _FILE_OFFSET_BITS == 64
        ret = lseek(stream->data.fd, offset, SEEK_SET);
#else
        ret = lseek64(stream->data.fd, offset, SEEK_SET);
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

bool
is_fd_input_stream(input_stream* stream_)
{
    file_input_stream* stream = (file_input_stream*)stream_;
    return (stream != NULL) && (stream->vtbl == &file_input_stream_vtbl);
}

/** @} */

/*----------------------------------------------------------------------------*/
