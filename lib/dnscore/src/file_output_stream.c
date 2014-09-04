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
file_write(output_stream* stream_, const u8* buffer, u32 len)
{
    file_output_stream* stream = (file_output_stream*)stream_;

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

            /* error */
            return MAKE_ERRNO_ERROR(err);
        }

        buffer += ret;
        len -= ret;
    }

    return buffer - start;
}

static ya_result
file_flush(output_stream* stream_)
{
    file_output_stream* stream = (file_output_stream*)stream_;

    if(fsync(stream->data.fd) == 0) /* or fdatasync ... maybe it would be slightly better */
    {
        return SUCCESS;
    }

    return ERRNO_ERROR;
}

static void
file_close(output_stream* stream_)
{
    file_output_stream* stream = (file_output_stream*)stream_;
    
    /* don't, it's only for a test that I did this assert((stream->data.fd < 0)||(stream->data.fd >2)); */
    
    if(stream->data.fd != -1)   /* harmless close but still ... */
    {
        close_ex(stream->data.fd);
    }

    output_stream_set_void(stream_);
}

static const output_stream_vtbl file_output_stream_vtbl ={
    file_write,
    file_flush,
    file_close,
    "file_output_stream",
};

ya_result
file_output_stream_open(const char* filename, output_stream* stream)
{
    return file_output_stream_open_ex(filename, O_RDWR, 0600, stream);
}

ya_result
file_output_stream_create(const char* filename, mode_t mode, output_stream* stream)
{
    return file_output_stream_open_ex(filename, O_RDWR | O_CREAT | O_TRUNC, mode, stream);
}

ya_result
file_output_stream_open_ex(const char* filename, int flags, mode_t mode, output_stream* stream_)
{
    yassert(sizeof (void*) >= sizeof (int));

    int fd = open_create_ex(filename, flags, mode);

    if(fd < 0)
    {
        return ERRNO_ERROR;
    }

    file_output_stream* stream = (file_output_stream*)stream_;
    stream->data.fd = fd;

    stream->vtbl = &file_output_stream_vtbl;

    return SUCCESS;
}

ya_result
fd_output_stream_attach(int fd, output_stream* stream_)
{
    yassert(sizeof(void*) >= sizeof(int));

    file_output_stream* stream = (file_output_stream*)stream_;
    stream->data.fd = fd;

    stream->vtbl = &file_output_stream_vtbl;

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
    return (stream != NULL) && (stream->vtbl == &file_output_stream_vtbl);
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

/** @} */

/*----------------------------------------------------------------------------*/

