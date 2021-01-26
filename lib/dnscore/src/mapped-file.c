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

#if HAS_MREMAP
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "dnscore/mapped-file.h"
#include "dnscore/fdtools.h"
#include "dnscore/zalloc.h"
#include "dnscore/mutex.h"

//extern logger_handle *g_system_logger;
//#define MODULE_MSG_HANDLE g_system_logger

#define MAPPED_FILE_TAG 0x454c494650414d4d // MMAPFILE_TAG

ssize_t g_page_size = 0;
ssize_t g_page_mask = 0;

static void
mapped_file_update_system_consts()
{
#ifndef WIN32
    if(g_page_size == 0)
    {
        g_page_size = sysconf(_SC_PAGE_SIZE);
        if(g_page_size < 0)
        {
            g_page_size = 4096;
        }
        g_page_mask = g_page_size - 1;
    }
#else
    g_page_size = 4096;
    g_page_mask = g_page_size - 1;
#endif
}

struct mapped_file_t_ // matches the file_t_ signature, appends its own
{
    const struct file_vtbl *vtbl;
    u8 *address;
    ssize_t size;
    ssize_t real_size;  // for non file-backed maps
    off_t position;
    group_mutex_t mtx;
    int fd;
    int prot;
    int flags;
};

typedef struct mapped_file_t_* mapped_file_t;

static int
mapped_file_resize_internal(mapped_file_t mf, size_t required_new_size)
{
    u8 *address;

    if((ssize_t)required_new_size <= mf->real_size)
    {
        mf->size = required_new_size;
        return SUCCESS;
    }
    
    size_t new_real_size = MAX(mf->real_size * 2, 0x1000000);
    
#if HAS_MREMAP
    if(mf->address != NULL)
    {
        address = mremap(mf->address, mf->real_size, new_real_size, MREMAP_MAYMOVE);

        if(address == (u8*)MAP_FAILED)
        {
            return ERRNO_ERROR;
        }
    }
    else
    {
        address = mmap(mf->address, new_real_size, mf->prot, mf->flags, mf->fd, 0);

        if(address == (u8*)MAP_FAILED)
        {
            return ERRNO_ERROR;
        }
    }
#else
    address = mmap(mf->address, new_real_size, mf->prot, mf->flags, mf->fd, 0);
    
    if(address == (u8*)MAP_FAILED)
    {
        return ERRNO_ERROR;
    }
    
    if(mf->address != NULL)
    {
        memcpy(address, mf->address, MIN(mf->size, (ssize_t)required_new_size));
        munmap(mf->address, mf->size);
    }    
#endif
    
    mf->address = address;
    mf->size = required_new_size;
    mf->real_size = new_real_size;
    
    return SUCCESS;
}

static ssize_t
mapped_file_read(file_t f, void *buffer, ssize_t size)
{
    mapped_file_t mf = (mapped_file_t)f;
    
    if((mf->prot & PROT_READ) == 0)
    {
        return INVALID_STATE_ERROR;
    }
    
    group_mutex_double_lock(&mf->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    ssize_t avail = mf->size - mf->position;
    
    if(avail < size)
    {
        size = avail;
    }
    memcpy(buffer, &mf->address[mf->position], size);
    
    group_mutex_exchange_locks(&mf->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    mf->position += size;
    group_mutex_exchange_locks(&mf->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
    
    group_mutex_double_unlock(&mf->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
        
    return size;
}

static ssize_t
mapped_file_write(file_t f, const void *buffer, ssize_t size)
{
    mapped_file_t mf = (mapped_file_t)f;
    
    if((mf->prot & PROT_WRITE) == 0)
    {
        return INVALID_STATE_ERROR;
    }
    
    group_mutex_lock(&mf->mtx, GROUP_MUTEX_WRITE);
    ssize_t avail = mf->size - mf->position;
    
    if(avail < size)
    {
        // grow the file
        if(mf->fd >= 0)
        {
            ftruncate(mf->fd, mf->position + size);
        }
        
        ssize_t ret = mapped_file_resize_internal(mf, mf->position + size);
        
        if(FAIL(ret))
        {
            group_mutex_unlock(&mf->mtx, GROUP_MUTEX_WRITE);
            
            return ret;
        }
    }
    
    memcpy(&mf->address[mf->position], buffer, size);
    
    mf->position += size;
    
    group_mutex_unlock(&mf->mtx, GROUP_MUTEX_WRITE);
        
    return size;
}

static ssize_t
mapped_file_seek(file_t f, ssize_t position, int whence)
{
    mapped_file_t mf = (mapped_file_t)f;
    
    if(mf->prot == PROT_NONE)
    {
        return INVALID_STATE_ERROR;
    }
    
    group_mutex_lock(&mf->mtx, GROUP_MUTEX_WRITE);
    
    switch(whence)
    {
        case SEEK_SET:
        {
            mf->position = position;
            
            group_mutex_unlock(&mf->mtx, GROUP_MUTEX_WRITE);
            
            return position;
        }
        case SEEK_CUR:
        {
            if(mf->position + position >= 0)
            {
                position = (mf->position += position);
                
                group_mutex_unlock(&mf->mtx, GROUP_MUTEX_WRITE);
                
                return position;
            }
            else
            {
                mf->position = 0;
                
                group_mutex_unlock(&mf->mtx, GROUP_MUTEX_WRITE);
                
                return 0;
            }
        }
        case SEEK_END:
        {
            if(mf->size + position >= 0)
            {
                position = mf->position = mf->size + position;
                group_mutex_unlock(&mf->mtx, GROUP_MUTEX_WRITE);
                return position;
            }
            else
            {
                mf->position = 0;
                group_mutex_unlock(&mf->mtx, GROUP_MUTEX_WRITE);
                return 0;
            }
        }
        default:
        {
            group_mutex_unlock(&mf->mtx, GROUP_MUTEX_WRITE);
            return ERROR;
        }
    }
}

static ssize_t
mapped_file_tell(file_t f)
{
    mapped_file_t mf = (mapped_file_t)f;
    
    if(mf->prot == PROT_NONE)
    {
        return INVALID_STATE_ERROR;
    }
    
    ssize_t ret;
    
    group_mutex_lock(&mf->mtx, GROUP_MUTEX_READ);
    ret = mf->position;
    group_mutex_unlock(&mf->mtx, GROUP_MUTEX_READ);
    
    return ret;
}

static ya_result
mapped_file_flush(file_t f)
{
    mapped_file_t mf = (mapped_file_t)f;
    
    if(mf->prot == PROT_NONE)
    {
        return INVALID_STATE_ERROR;
    }
    
    group_mutex_lock(&mf->mtx, GROUP_MUTEX_READ);
    
    int ret = msync(mf->address, mf->size, MS_SYNC);
    
    group_mutex_unlock(&mf->mtx, GROUP_MUTEX_READ);
    
    if(FAIL(ret))
    {
        ret = ERRNO_ERROR;
    }
    
    return ret;
}

static int
mapped_file_close(file_t f)
{
    mapped_file_t mf = (mapped_file_t)f;
    
    if(mf->prot == PROT_NONE)
    {
        return INVALID_STATE_ERROR;
    }
    
    group_mutex_lock(&mf->mtx, GROUP_MUTEX_WRITE);
    
    if(mf->address != NULL)
    {
        munmap(mf->address, mf->real_size);
        mf->address = NULL;
        mf->size = 0;
    }
    
    group_mutex_unlock(&mf->mtx, GROUP_MUTEX_WRITE);
    
    if(mf->fd >= 0)
    {
        close_ex(mf->fd);
        mf->fd = -2;
    }
    mf->vtbl = NULL;
    ZFREE_OBJECT(mf);
    
    return SUCCESS;
}

static ssize_t
mapped_file_size(file_t f)
{
    mapped_file_t mf = (mapped_file_t)f;
    
    if(mf->prot == PROT_NONE)
    {
        return INVALID_STATE_ERROR;
    }
    
    ssize_t ret;
    
    group_mutex_lock(&mf->mtx, GROUP_MUTEX_READ);
    ret = mf->size;
    group_mutex_unlock(&mf->mtx, GROUP_MUTEX_READ);
    
    return ret;
}

static int
mapped_file_resize(file_t f, ssize_t size)
{
    mapped_file_t mf = (mapped_file_t)f;
    
    if(mf->prot == PROT_NONE)
    {
        return INVALID_STATE_ERROR;
    }
    
    ya_result ret = SUCCESS;
    
    group_mutex_lock(&mf->mtx, GROUP_MUTEX_WRITE);
    
    if(mf->size != size)
    {    
        // grow the file
        if(mf->fd >= 0)
        {
            if(ISOK(ret = ftruncate(mf->fd, size)))
            {
                ret = mapped_file_resize_internal(mf, size);
            }
        }
        else
        {
            ret = mapped_file_resize_internal(mf, size);
        }
    }
        
    group_mutex_unlock(&mf->mtx, GROUP_MUTEX_WRITE);
            
    return ret;
}

static const struct file_vtbl mapped_file_vtbl =
{
    mapped_file_read,
    mapped_file_write,
    mapped_file_seek,
    mapped_file_tell,
    mapped_file_flush,
    mapped_file_close,
    mapped_file_size,
    mapped_file_resize
};

/*
file_t
mapped_file_open_ex(const char *filename, int flags, mode_t mode, ya_result *ret)
*/

ya_result
mapped_file_open_ex(file_t *fp, const char *filename, int flags)
{
    mapped_file_update_system_consts();
            
    if(fp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    int fd = open_ex(filename, flags);
    if(FAIL(fd))
    {
        return ERRNO_ERROR;
    }
    
    struct stat st;
    if(fstat(fd, &st) < 0)
    {
        close_ex(fd);
        return ERRNO_ERROR;
    }
    
    int prot;
    
    if((flags & O_RDWR) == O_RDWR)
    {
        prot = PROT_READ|PROT_WRITE;
    }
    else if((flags & O_RDONLY) == O_RDONLY)
    {
        prot = PROT_READ;
    }
    else if((flags & O_WRONLY) == O_WRONLY)
    {
        prot = PROT_WRITE;
    }
    else
    {
        prot = PROT_NONE;
    }
    
    int mmap_flags = MAP_SHARED;
    
    u8 *address = NULL;

    ssize_t real_size = 0;
    
    if(st.st_size > 0)
    {
        real_size = (st.st_size + 0xffffffLL) & ~0xffffffLL;
        address = mmap(NULL, real_size, prot, mmap_flags, fd, 0);

        if(address == (u8*)MAP_FAILED)
        {
            close_ex(fd);
            return ERRNO_ERROR;
        }
    }
    
    mapped_file_t mf;
    ZALLOC_OBJECT_OR_DIE(mf,struct mapped_file_t_, FILESYSTEM_FILE_TAG);
    mf->vtbl = &mapped_file_vtbl;
    mf->address = address;
    mf->size = st.st_size;
    mf->real_size = real_size;
    mf->position = 0;
    group_mutex_init(&mf->mtx);
    mf->fd = fd;
    mf->prot = prot;
    mf->flags = mmap_flags;
    
    *fp = (file_t)mf;
    
    return SUCCESS;
}

ya_result
mapped_file_create_ex(file_t *fp, const char *filename, int flags, mode_t mode)
{
    mapped_file_update_system_consts();
    
    if(fp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    int fd = open_create_ex(filename, flags, mode);
    
    if(FAIL(fd))
    {
        return ERRNO_ERROR;
    }
    
    struct stat st;
    if(fstat(fd, &st) < 0)
    {
        close_ex(fd);
        return ERRNO_ERROR;
    }
    
    int prot;
    
    if((flags & O_RDWR) == O_RDWR)
    {
        prot = PROT_READ|PROT_WRITE;
    }
    else if((flags & O_RDONLY) == O_RDONLY)
    {
        prot = PROT_READ;
    }
    else if((flags & O_WRONLY) == O_WRONLY)
    {
        prot = PROT_WRITE;
    }
    else
    {
        prot = PROT_NONE;
    }
    
    int mmap_flags = MAP_SHARED;
    
    u8 *address = NULL;
    size_t real_size = 0;
    
    if(st.st_size > 0)
    {
        real_size = (st.st_size + 0xffffffLL) & ~0xffffffLL;
        address = mmap(NULL, real_size, prot, mmap_flags, fd, 0);

        if(address == (u8*)MAP_FAILED)
        {
            close_ex(fd);
            return ERRNO_ERROR;
        }
    }
    
    mapped_file_t mf;
    ZALLOC_OBJECT_OR_DIE(mf,struct mapped_file_t_, FILESYSTEM_FILE_TAG);
    mf->vtbl = &mapped_file_vtbl;
    mf->address = address;
    mf->size = st.st_size;
    mf->real_size = real_size;
    mf->position = 0;
    group_mutex_init(&mf->mtx);
    mf->fd = fd;
    mf->prot = prot;
    mf->flags = mmap_flags;
    
    *fp = (file_t)mf;
    
    return SUCCESS;
}

ya_result
mapped_file_create_volatile(file_t *fp, const char *filename, size_t base_size)
{
    (void)filename;

    mapped_file_update_system_consts();

    if(fp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    int fd = -1;

    int prot = PROT_READ|PROT_WRITE;
    
    int mmap_flags = MAP_ANONYMOUS|MAP_PRIVATE;
    
    u8 *address = NULL;
    size_t real_size = 0;
    
    if(base_size > 0)
    {
        real_size = (base_size + 0xffffffLL) & ~0xffffffLL;
        
        address = mmap(NULL, real_size, prot, mmap_flags, fd, 0);

        if(address == (u8*)MAP_FAILED)
        {
            close_ex(fd);
            return ERRNO_ERROR;
        }
    }
    
    mapped_file_t mf;
    ZALLOC_OBJECT_OR_DIE(mf,struct mapped_file_t_, FILESYSTEM_FILE_TAG);
    mf->vtbl = &mapped_file_vtbl;
    mf->address = address;
    mf->size = 0;
    mf->real_size = real_size;
    mf->position = 0;
    group_mutex_init(&mf->mtx);
    mf->fd = fd;
    mf->prot = prot;
    mf->flags = mmap_flags;
    
    *fp = (file_t)mf;
    
    return SUCCESS;
}

ya_result
mapped_file_get_buffer(file_t f, void **address, ssize_t *size)
{
    mapped_file_t mf = (mapped_file_t)f;

    if(f->vtbl == &mapped_file_vtbl)
    {
        if(address != NULL)
        {
            *address = mf->address;
        }
        if(size != NULL)
        {
            *size = mf->size;
        }

        return SUCCESS;
    }
    else
    {
        return INVALID_ARGUMENT_ERROR;
    }
}

ya_result
mapped_file_get_buffer_const(file_t f, const void **address, ssize_t *size)
{
    mapped_file_t mf = (mapped_file_t)f;

    if(f->vtbl == &mapped_file_vtbl)
    {
        if(address != NULL)
        {
            *address = mf->address;
        }
        if(size != NULL)
        {
            *size = mf->size;
        }

        return SUCCESS;
    }
    else
    {
        return INVALID_ARGUMENT_ERROR;
    }
}

/** @} */
