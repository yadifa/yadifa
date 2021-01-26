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

#include "dnscore/filesystem-file.h"
#include "dnscore/fdtools.h"
#include "dnscore/zalloc.h"

//extern logger_handle *g_system_logger;
//#define MODULE_MSG_HANDLE g_system_logger

#define FILESYSTEM_FILE_TAG 0x454c49465346 // FSFILE_TAG

struct filesystem_file_t_ // matches the file_t_ signature, appends its own
{
    const struct file_vtbl *vtbl;
    int fd;
};

typedef struct filesystem_file_t_* filesystem_file_t;

static ssize_t
filesystem_file_read(file_t f, void *buffer, ssize_t size)
{
    filesystem_file_t fsf = (filesystem_file_t)f;
    int fd = fsf->fd;
    if(fd < 0)
    {
        return INVALID_STATE_ERROR;
    }
    
    ssize_t ret = readfully(fd, buffer, size);
    
    return ret;
}

static ssize_t
filesystem_file_write(file_t f, const void *buffer, ssize_t size)
{
    filesystem_file_t fsf = (filesystem_file_t)f;
    int fd = fsf->fd;
    if(fd < 0)
    {
        return INVALID_STATE_ERROR;
    }
    
    ssize_t ret = writefully(fd, buffer, size);
    
    return ret;
}

static ssize_t
filesystem_file_seek(file_t f, ssize_t position, int whence)
{
    filesystem_file_t fsf = (filesystem_file_t)f;
    int fd = fsf->fd;
    if(fd < 0)
    {
        return INVALID_STATE_ERROR;
    }
    
    off_t ret = lseek(fd, position, whence);
    
    if(ret < 0)
    {
        ret = ERRNO_ERROR;
    }
    
    return ret;
}

static ssize_t
filesystem_file_tell(file_t f)
{
    filesystem_file_t fsf = (filesystem_file_t)f;
    int fd = fsf->fd;
    if(fd < 0)
    {
        return INVALID_STATE_ERROR;
    }
    
    off_t ret = lseek(fd, 0, SEEK_CUR);
    
    if(ret < 0)
    {
        ret = ERRNO_ERROR;
    }
    
    return ret;
}

static ya_result
filesystem_file_flush(file_t f)
{
    filesystem_file_t fsf = (filesystem_file_t)f;
    int fd = fsf->fd;
    if(fd < 0)
    {
        return INVALID_STATE_ERROR;
    }
    
    int ret = fdatasync_ex(fd);
    
    if(FAIL(ret))
    {
        ret = ERRNO_ERROR;
    }
    
    return ret;
}

static int
filesystem_file_close(file_t f)
{
    filesystem_file_t fsf = (filesystem_file_t)f;
    int fd = fsf->fd;
    if(fd < 0)
    {
        return INVALID_STATE_ERROR;
    }
    close_ex(fd);
    fsf->fd = -2;
    fsf->vtbl = NULL;
    ZFREE_OBJECT(fsf);
    return SUCCESS;
}

static ssize_t
filesystem_file_size(file_t f)
{
    filesystem_file_t fsf = (filesystem_file_t)f;
    int fd = fsf->fd;
    if(fd < 0)
    {
        return INVALID_STATE_ERROR;
    }
    
    ssize_t ret;
    struct stat st;
    if(fstat(fd, &st) >= 0)
    {
        ret = st.st_size;
    }
    else
    {
        ret = ERRNO_ERROR;
    }
    return ret;
}

static int
filesystem_file_resize(file_t f, ssize_t size)
{
    filesystem_file_t fsf = (filesystem_file_t)f;
    int fd = fsf->fd;
    if(fd < 0)
    {
        return INVALID_STATE_ERROR;
    }
    
    ya_result ret = ftruncate(fd, size);
    
    if(FAIL(ret))
    {
        ret = ERRNO_ERROR;
    }
    
    return ret;
}

static const struct file_vtbl filesystem_file_vtbl =
{
    filesystem_file_read,
    filesystem_file_write,
    filesystem_file_seek,
    filesystem_file_tell,
    filesystem_file_flush,
    filesystem_file_close,
    filesystem_file_size,
    filesystem_file_resize
};

/*
file_t
filesystem_file_open_ex(const char *filename, int flags, mode_t mode, ya_result *ret)
*/

ya_result
filesystem_file_open_ex(file_t *fp, const char *filename, int flags)
{
    ya_result ret;
    
    if(fp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    ret = open_ex(filename, flags);
    if(FAIL(ret))
    {
        return ret;
    }
    
    filesystem_file_t fsf;
    ZALLOC_OBJECT_OR_DIE(fsf,struct filesystem_file_t_, FILESYSTEM_FILE_TAG);
    fsf->vtbl = &filesystem_file_vtbl;
    fsf->fd = ret;
    *fp = (file_t)fsf;
    return ret;
}

ya_result
filesystem_file_create_ex(file_t *fp, const char *filename, int flags, mode_t mode)
{
    ya_result ret;
    
    if(fp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    ret = open_create_ex(filename, flags, mode);
    if(ret < 0)
    {
        return ERRNO_ERROR;
    }
    
    filesystem_file_t fsf;
    ZALLOC_OBJECT_OR_DIE(fsf,struct filesystem_file_t_, FILESYSTEM_FILE_TAG);
    fsf->vtbl = &filesystem_file_vtbl;
    fsf->fd = ret;
    *fp = (file_t)fsf;
    return ret;
}

/** @} */
