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

#define __FILE_POOL_C__ 1

#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "dnscore/ptr_set.h"
#include "dnscore/mutex.h"
#include "dnscore/list-dl.h"
#include "dnscore/fdtools.h"
#include "dnscore/logger.h"

#define FP_USE_ABSTRACT_FILES   1
#if HAS_FILEPOOL_CACHE
#define FP_USE_CACHED_FILES     1           // minimal impact apparently
#else
#define FP_USE_CACHED_FILES     0           // minimal impact apparently
#endif

#if FP_USE_ABSTRACT_FILES
#include "dnscore/filesystem-file.h"
#include "dnscore/buffered-file.h"
#endif

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#define FILEPOOL_TAG    0x4c4f4f50454c4946 // FILEPOOL_TAG

struct file_pool_t_
{
    group_mutex_t mtx;
    ptr_set name_to_file;    
    list_dl_s mru;
    const char * name;
    int opened_file_count_max;
#if FP_USE_CACHED_FILES
    buffered_file_cache_t file_cache;
#endif
};

typedef struct file_pool_t_* file_pool_t;

struct file_common_t_
{
    list_dl_node_s mru_node;    // the struct MUST start with a node
    file_pool_t file_pool;      // the pool that manages this file
    char *name;                 // the name of this file
    size_t position;            // the current position in the current fd
#if FP_USE_ABSTRACT_FILES
    file_t file;
#else
    int fd;                     // the fd that accesses this file
#endif
    int rc;                     // the number of references to this file      (opened)
    int ioc;                    // the number of io operations going on       (immediately planned read/write/...) 
    bool old;                   // an old file has been renamed and cannot be closed anymore until its RC reaches 0
};

typedef struct file_common_t_* file_common_t;

struct file_pool_file_t_
{
#if DEBUG
    u64 magic;
#endif
    file_common_t common;       // the common part of the file
    size_t position;            // the position in the file
    int rdwr_flags;             // has this "handle" the right to access the file in read and/or write ?
};

typedef struct file_pool_file_t_* file_pool_file_t;

#include <dnscore/file-pool.h>

file_pool_t
file_pool_init_ex(const char * const pool_name, int opened_file_count_max, u32 cache_entries)  // name is for logging
{
#if FP_USE_CACHED_FILES
    buffered_file_cache_t file_cache = buffered_file_cache_new_instance(pool_name, cache_entries, 12, TRUE);

    if(file_cache == NULL)
    {
        log_err("file-pool: failed to instantiate new pool %s using %i file descriptors and a cache of %u pages", pool_name, opened_file_count_max, cache_entries);
        return NULL;
    }
#else
    (void)cache_entries;
#endif
    
    file_pool_t fp;
    ZALLOC_OBJECT_OR_DIE(fp, struct file_pool_t_, FILEPOOL_TAG);
    group_mutex_init(&fp->mtx);
    ptr_set_init(&fp->name_to_file);
    fp->name_to_file.compare = ptr_set_asciizp_node_compare;
    list_dl_init(&fp->mru);
    fp->name = pool_name;
    fp->opened_file_count_max = MAX(opened_file_count_max, 1);

#if FP_USE_CACHED_FILES
    fp->file_cache = file_cache;
#endif

    log_debug("file-pool: new pool %s using %i file descriptors at %p", pool_name, opened_file_count_max, fp);

    return fp;
}

file_pool_t
file_pool_init(const char * const pool_name, int opened_file_count_max)  // name is for logging
{
    file_pool_t fp = file_pool_init_ex(pool_name, opened_file_count_max, 4096);

    return fp;
}

static void file_pool_close_unused_in_excess(file_pool_t fp, int fd_max);
static void file_common_destroy(file_common_t fc);
static void file_common_mru_unlink(file_common_t fc);

static void file_pool_finalize_name_to_file(ptr_node *node)
{
    file_common_t fc = (file_common_t)node->value;
    file_common_mru_unlink(fc);
    file_common_destroy(fc);
}

void
file_pool_finalize(file_pool_t fp)
{
    if(fp == NULL)
    {
        return;
    }

    log_debug("file-pool: deleting pool %s using %i file descriptors at %p", fp->name, fp->opened_file_count_max, fp);
    
    ptr_set_iterator iter;

    group_mutex_double_lock(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    file_pool_close_unused_in_excess(fp, 0);
#if FP_USE_CACHED_FILES
    buffered_file_cache_delete(fp->file_cache);
#endif
    group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
    group_mutex_double_unlock(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);

    bool log_flush_required = FALSE;

    ptr_set_iterator_init(&fp->name_to_file, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        if(node->value != NULL)
        {
            file_common_t fc = (file_common_t)node->value;
            
            if(fc->rc > 0)
            {
                log_err("file-pool: '%s' is still referenced %i times", fc->name, fc->rc);
                log_flush_required = TRUE;
            }
        }
    }

    if(log_flush_required)
    {
        logger_flush();
    }

    ptr_set_callback_and_destroy(&fp->name_to_file, file_pool_finalize_name_to_file);
    group_mutex_destroy(&fp->mtx);
    ZFREE_OBJECT(fp);
}

#if FP_USE_ABSTRACT_FILES
static file_common_t
file_common_newinstance(file_pool_t fp, const char *name, file_t file)
#else
static file_common_t
file_common_newinstance(file_pool_t fp, const char *name, int fd)
#endif
{
    file_common_t fc;
    ZALLOC_OBJECT_OR_DIE(fc, struct file_common_t_, FILEPOOL_TAG);
    fc->mru_node.next = NULL;
    fc->mru_node.prev = NULL;
    fc->mru_node.data = fc;
    fc->file_pool = fp;
    fc->name = strdup(name);
    fc->position = 0;
#if FP_USE_ABSTRACT_FILES
    fc->file = file;
#else
    fc->fd = fd;
#endif
    fc->rc = 0;
    fc->ioc = 0;
    fc->old = FALSE;
    return fc;
}

static void
file_common_destroy(file_common_t fc)
{
    if(fc != NULL)
    {
#if FP_USE_ABSTRACT_FILES
        //yassert(fc->file == NULL);
        if(fc->file != NULL)
        {
            if(fc->rc == 0)
            {
                file_close(fc->file);
                fc->file = NULL;
            }
            else
            {
                log_err("error: file_common_destroy called on a file with rc=%i: '%s'", fc->rc, STRNULL(fc->name));
                logger_flush();
            }
        }
#else
        //yassert(fc->fd < 0);
        if(fc->fd >= 0)
        {
            if(fc->rc == 0)
            {
                close_ex(fc->fd);
                fc->fd = -1;
            }
            else
            {
                log_err("error: file_common_destroy called on a file with rc=%i: '%s'", fc->rc, STRNULL(fc->name));
                logger_flush();
            }
        }
#endif
        fc->file_pool = NULL;
        free(fc->name);
        ZFREE(fc, struct file_common_t_);
    }
}

static void
file_common_mru_to_link(file_common_t fc)
{
    file_common_t first_one = (file_common_t)list_dl_peek_first(&fc->file_pool->mru);
    if(first_one != fc)
    {
        list_dl_insert_node(&fc->file_pool->mru, &fc->mru_node);
    }
}

static void
file_common_mru_to_first(file_common_t fc)
{
    file_common_t first_one = (file_common_t)list_dl_peek_first(&fc->file_pool->mru);
    if(first_one != fc)
    {
        if(fc->mru_node.next != NULL)
        {
            list_dl_remove_node(&fc->file_pool->mru, &fc->mru_node);
        }
        list_dl_insert_node(&fc->file_pool->mru, &fc->mru_node);
    }
}

static void
file_common_mru_to_last(file_common_t fc)
{
    file_common_t last_one = (file_common_t)list_dl_peek_last(&fc->file_pool->mru);
    if(last_one != fc)
    {
        if(fc->mru_node.next != NULL)
        {
            list_dl_remove_node(&fc->file_pool->mru, &fc->mru_node);
        }
        list_dl_append_node(&fc->file_pool->mru, &fc->mru_node);
    }
}

static void
file_common_mru_unlink(file_common_t fc)
{
    //file_common_t first_one = (file_common_t)list_dl_peek_first(&fc->file_pool->mru);
    //if(first_one != fc)
    {
        list_dl_remove_node(&fc->file_pool->mru, &fc->mru_node);
    }
}

static bool
file_common_operating(file_common_t fc)
{
    return  (fc->ioc > 0) || (fc->old); // if there are operations running or the file is old (and thus is only waiting for RC reaching 0 to close)
}

/**
 * Close open FD above the given limit
 * 
 * Locks must be (W,R)
 * 
 * @param fp
 * @param fd_max
 */

static void
file_pool_close_unused_in_excess(file_pool_t fp, int fd_max)
{
    if(fd_max < 1)
    {
        fd_max = 1;
    }

    while(list_dl_size(&fp->mru) > (u32)fd_max)
    {
        file_common_t fc = (file_common_t)list_dl_peek_last(&fp->mru);
        
        if(!file_common_operating(fc))
        {
#if FP_USE_ABSTRACT_FILES
            if(fc->file != NULL)
            {
                group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
                file_close(fc->file);
                fc->file = NULL;
                group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
            }
#else
            if(fc->fd >= 0)
            {
                group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
                close_ex(fc->fd);
                group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
                
                fc->fd = -1;
            }
#endif
            file_common_mru_unlink(fc);
            
            if(fc->rc == 0)
            {
                // nobody is pointing to this anymore
                
                ptr_set_delete(&fp->name_to_file, fc->name);
                
                file_common_destroy(fc);
            }
        }
        else
        {
            group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
            group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
            break;
        }
    }
}

ya_result
file_pool_unlink_from_pool_and_filename(file_pool_t fp, const char *filename)
{
    ya_result ret;
    
    group_mutex_double_lock(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    
    if(unlink(filename) >= 0)
    {
        ret = SUCCESS;
        
        ptr_node *node;

        if((node = ptr_set_find(&fp->name_to_file, filename)) != NULL)
        {
            // the common node exists
            // get a new file referencing that node

            group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);

            file_common_t fc = (file_common_t)node->value;

            ptr_set_delete(&fp->name_to_file, fc->name);
            file_common_mru_unlink(fc);
            fc->old = TRUE;

            if(fc->rc == 0)
            {
                if(fc->file != NULL)
                {
                    file_close(fc->file);
                    fc->file = NULL;
                }

                file_common_destroy(fc);
            }

            group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
        }
    }
    else
    {
        ret = ERRNO_ERROR;
    }
    
    group_mutex_double_unlock(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    
    return ret;
}

static void
file_common_acquire(file_common_t fc)
{
    ++fc->rc;
}

static void
file_common_release(file_common_t fc)
{
    --fc->rc;
    
    if(fc->rc <= 0)
    {
        assert(fc->rc == 0);
        
        // an old file has been unlinked
        // it is not in the name_to_file set anymore
        // it is not in the mru anymore
        
        if(!fc->old)
        {
            file_common_mru_to_last(fc);
        }
        else
        {
#if FP_USE_ABSTRACT_FILES
            if(fc->file != NULL)
            {
                file_pool_t fp = fc->file_pool;
                
                group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
                file_close(fc->file);
                fc->file = NULL;
                group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
            }
#else
            if(fc->fd >= 0)
            {
                file_pool_t fp = fc->file_pool;
                
                group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
                close_ex(fc->fd);
                group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
                fc->fd = -1;
            }
#endif
            file_common_mru_unlink(fc);
            
            file_common_destroy(fc);
        }
    }
}

static file_pool_file_t
file_newinstance(file_common_t common, int rdwr_flags)
{
    file_pool_file_t f;
    ZALLOC_OBJECT_OR_DIE(f, struct file_pool_file_t_, FILEPOOL_TAG);
    file_common_acquire(common);
#if DEBUG
    f->magic = 0xf113B001;
#endif
    f->common = common;
    f->position = 0;
    f->rdwr_flags = rdwr_flags;
    return f;
}

static void
file_destroy(file_pool_file_t f)
{
    if(f != NULL)
    {
        file_common_t fc = f->common;
        ZEROMEMORY(f, sizeof(struct file_pool_file_t_));
        ZFREE(f, struct file_pool_file_t_);
        
        file_common_release(fc);
    }
}

/**
 * 
 * 
 * @param fp
 * @param filename
 * @param flags
 * @param mode
 * @return a handle or NULL (errno being set)
 */

file_pool_file_t
file_pool_open_ex(file_pool_t fp, const char *filename, int flags, mode_t mode)
{
    group_mutex_double_lock(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    
    file_common_t fc;
    file_pool_file_t f;
    
    char absolute_filename[1024];
    
    ya_result ret;
    if(ISOK(ret = file_get_absolute_path(filename, absolute_filename, sizeof(absolute_filename))))
    {
        filename = absolute_filename;
    }
    
    ptr_node *node;
    
    if((node = ptr_set_find(&fp->name_to_file, filename)) != NULL)
    {
        // the common node exists
        // get a new file referencing that node
        
        group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
        
        fc = (file_common_t)node->value;
        f = file_newinstance(fc, flags);
        
        file_common_mru_to_first(fc);
        
        group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
    }
    else
    {
        // the first opening is required to eventually return an error code
        
#if FP_USE_ABSTRACT_FILES
        file_t file;
        
        ret = filesystem_file_create_ex(&file, filename, O_RDWR|flags, mode);
        
        if(ISOK(ret))
        {
#if FP_USE_CACHED_FILES
            buffered_file_init(&file, file, fp->file_cache); // only fails if one of the parameters is NULL
#endif
            group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
            
            // close the exceeding fd(s)
            
            file_pool_close_unused_in_excess(fp, fp->opened_file_count_max - 1);
            
            // we know the node does not exist
            
            node = ptr_set_insert(&fp->name_to_file, (char*)filename); // cast as it will be fixed later
            fc = file_common_newinstance(fp, filename, file);
#else
        int fd = open_create_ex(filename, O_RDWR|flags, mode);
        
        if(fd > 0)
        {
            group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
            
            // close the exceeding fd(s)
            
            file_pool_close_unused_in_excess(fp, fp->opened_file_count_max - 1);
            
            // we know the node does not exist
            
            node = ptr_set_insert(&fp->name_to_file, (char*)filename); // cast as it will be fixed later
            fc = file_common_newinstance(fp, filename, fd);
#endif
            node->value = fc;
            node->key = fc->name;
            
            f = file_newinstance(fc, flags);
            
            file_common_mru_to_link(fc);
            
            group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
        }
        else
        {
            f = NULL;
        }
    }
        
    group_mutex_double_unlock(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    
    return f;
}

file_pool_file_t
file_dup(file_pool_file_t file)
{
    group_mutex_double_lock(&file->common->file_pool->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);

    group_mutex_exchange_locks(&file->common->file_pool->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);

    file_pool_file_t file_dup = file_newinstance(file->common, file->rdwr_flags);

    file_common_mru_to_first(file->common);

    group_mutex_exchange_locks(&file->common->file_pool->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);

    group_mutex_double_unlock(&file->common->file_pool->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    
    return file_dup;
}

file_pool_file_t
file_pool_open(file_pool_t fp, const char *filename)
{
    file_pool_file_t f = file_pool_open_ex(fp, filename, O_RDONLY|O_CLOEXEC, 0);
    return f;
}

file_pool_file_t
file_pool_create(file_pool_t fp, const char *filename, mode_t mode)
{
    file_pool_file_t f = file_pool_open_ex(fp, filename, O_RDWR|O_CREAT|O_CLOEXEC, mode);
    return f;
}

file_pool_file_t
file_pool_create_excl(file_pool_t fp, const char *filename, mode_t mode)
{
    file_pool_file_t f = file_pool_open_ex(fp, filename, O_RDWR|O_CREAT|O_CLOEXEC|O_EXCL, mode);
    return f;
}

static void
file_common_release_fd(file_pool_file_t f)
{
    file_common_t fc = f->common;
    file_pool_t fp = fc->file_pool;
    
    group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    
    fc->position = f->position;
    
    --fc->ioc;
    
    group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
    
    group_mutex_double_unlock(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
}

static void
file_common_advance_position_release_fd(file_pool_file_t f, size_t offset)
{
    file_common_t fc = f->common;
    file_pool_t fp = fc->file_pool;
    
    group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    
    f->position += offset;
    fc->position = f->position;
    
    --fc->ioc;
    
    group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
    
    group_mutex_double_unlock(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
}

#if FP_USE_ABSTRACT_FILES

static int
file_common_acquire_fd(file_pool_file_t f, file_t *filep)
{
#if DEBUG
    yassert(f->magic == 0xf113B001);
#endif
    
    // prevent changes, take dibs on making changes
    
    group_mutex_double_lock(&f->common->file_pool->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    
    file_common_t fc = f->common;
    file_pool_t fp = fc->file_pool;
    
    file_t file;
    ya_result ret = SUCCESS;
    
    if((file = fc->file) == NULL)
    {
        // need to get a file
        
        group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
        
        file_pool_close_unused_in_excess(fp, fp->opened_file_count_max - 1);
        
        group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
        
        ret = filesystem_file_open_ex(&file, fc->name, O_RDWR|O_CLOEXEC);
                
        if(FAIL(ret))
        {
            group_mutex_double_unlock(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
            
            return ret;
        }
        
#if FP_USE_CACHED_FILES
        buffered_file_init(&file, file, fp->file_cache); // only fails if one of the parameters is NULL
#endif
        fc->file = file;
        fc->position = 0;
    }
    
    if(fc->position != f->position)
    {    
        file_seek(file, f->position, SEEK_SET);
    }
    
    group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    file_common_mru_to_first(fc);
    ++fc->ioc;
    group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
    
    // successful acquisition will be unlocked at release
    
    *filep = file;
    
    return ret;
}

ya_result
file_pool_read(file_pool_file_t f, void *buffer, size_t bytes)
{
    file_t file;
    int ret = file_common_acquire_fd(f, &file);
    
    if(FAIL(ret))
    {
        return ret;
    }
    
    // read
    
    ssize_t n = file_read(file, buffer, bytes);
    
    if(n >= 0)
    {
        file_common_advance_position_release_fd(f, n);
    }
    else
    {
        file_common_release_fd(f);
    }
    
    return (ya_result)n;
}

ya_result
file_pool_readfully(file_pool_file_t f, void *buffer, size_t bytes)
{
    ya_result ret = file_pool_read(f, buffer, bytes);
    return ret;
}

ya_result
file_pool_write(file_pool_file_t f, const void *buffer, size_t bytes)
{
    file_t file;
    int ret = file_common_acquire_fd(f, &file);
    
    if(FAIL(ret))
    {
        return ret;
    }
    
    // read
    
    ssize_t n = file_write(file, buffer, bytes);
    
    if(n >= 0)
    {
        file_common_advance_position_release_fd(f, n);
    }
    else
    {
        file_common_release_fd(f);
    }
    
    return (ya_result)n;
}

ya_result
file_pool_writefully(file_pool_file_t f, const void *buffer, size_t bytes)
{
    ya_result ret = file_pool_write(f, buffer, bytes);
    return ret;
}

ya_result
file_pool_flush(file_pool_file_t f)
{
    file_t file;
    int ret = file_common_acquire_fd(f, &file);
    
    if(FAIL(ret))
    {
        return ret;
    }
    
    // flush
    
    ret = file_flush(file);

    file_common_release_fd(f);
    
    return ret;
}

ya_result
file_pool_get_size(file_pool_file_t f, size_t *sizep)
{
    if(sizep != NULL)
    {
        file_t file;
        int ret = file_common_acquire_fd(f, &file);

        if(FAIL(ret))
        {
            return ret;
        }

        *sizep = (size_t)file_size(file);

        file_common_release_fd(f);
        
        return ret;
    }
    else
    {
        return ERROR;
    }
}

ya_result
file_pool_resize(file_pool_file_t f, size_t size)
{
    file_t file;
    int ret = file_common_acquire_fd(f, &file);
    
    if(FAIL(ret))
    {
        return ret;
    }
    
    // truncate
    
    ret = file_resize(file, size);
        
    file_common_release_fd(f);
    
    return ret;
}

#else
static int
file_common_acquire_fd(file_pool_file_t f)
{
#if DEBUG
    yassert(f->magic == 0xf113B001);
#endif
    
    // prevent changes, take dibs on making changes
    
    group_mutex_double_lock(&f->common->file_pool->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    
    file_common_t fc = f->common;
    file_pool_t fp = fc->file_pool;
    
    int fd;
    
    if((fd = fc->fd) < 0)
    {
        // need to get an fd
        
        group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
        
        file_pool_close_unused_in_excess(fp, fp->opened_file_count_max - 1);
        
        group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
        
        if((fd = open_ex(fc->name, O_RDWR|O_CLOEXEC)) < 0)
        {
            fd = ERRNO_ERROR;
            
            group_mutex_double_unlock(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
            
            return fd;
        }
        
        fc->fd = fd;
        fc->position = 0;
    }
    
    if(fc->position != f->position)
    {    
        lseek(fd, f->position, SEEK_SET);
    }
    
    group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    file_common_mru_to_first(fc);
    ++fc->ioc;
    group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
    
    // successful acquisition will be unlocked at release
    
    return fd;
}

ya_result
file_pool_read(file_pool_file_t f, void *buffer, size_t bytes)
{
    int fd = file_common_acquire_fd(f);
    
    if(fd < 0)
    {
        return fd;
    }
    
    // read
    
    for(;;)
    {
        ssize_t n = read(fd, buffer, bytes);
        
        if(n >= 0)
        {
            file_common_advance_position_release_fd(f, n);
            return n;
        }
        else
        {
            int err = errno;
            
            if(err == EINTR)
            {
                continue;
            }
            
            file_common_release_fd(f);
            
            return err;
        }
    }
}

ya_result
file_pool_readfully(file_pool_file_t f, void *buffer, size_t bytes)
{
    int fd = file_common_acquire_fd(f);
    
    if(fd < 0)
    {
        return fd;
    }
    
    // read
    
    size_t total = 0;
    
    for(;;)
    {
        ssize_t n = read(fd, buffer, bytes);
        
        if(n >= 0)
        {
            bytes -= n;
            total += n;
            
            if((n == 0) || (bytes == 0))
            {
                file_common_advance_position_release_fd(f, total);
                return total;
            }
        }
        else
        {
            int err = errno;
            
            if(err == EINTR)
            {
                continue;
            }
            
            if(err == EAGAIN)
            {
                continue;
            }
            
            file_common_advance_position_release_fd(f, total);
            
            return err;
        }
    }
}

ya_result
file_pool_write(file_pool_file_t f, const void *buffer, size_t bytes)
{
    int fd = file_common_acquire_fd(f);
    
    if(fd < 0)
    {
        return fd;
    }
    
    // write
    
    for(;;)
    {
        ssize_t n = write(fd, buffer, bytes);
        
        if(n >= 0)
        {
            file_common_advance_position_release_fd(f, n);
            return n;
        }
        else
        {
            int err = errno;
            
            if(err == EAGAIN)
            {
                continue;
            }
            
            file_common_release_fd(f);
            
            return err;
        }
    }
}

ya_result
file_pool_writefully(file_pool_file_t f, const void *buffer, size_t bytes)
{
    int fd = file_common_acquire_fd(f);
    
    if(fd < 0)
    {
        return fd;
    }
    
    // write
    
    size_t total = 0;
    
    for(;;)
    {
        ssize_t n = write(fd, buffer, bytes);
        
        if(n >= 0)
        {
            bytes -= n;
            total += n;
            
            if((n == 0) || (bytes == 0))
            {
                file_common_advance_position_release_fd(f, total);
                return total;
            }
        }
        else
        {
            int err = errno;
            
            if(err == EINTR)
            {
                continue;
            }
            
            if(err == EAGAIN)
            {
                continue;
            }
            
            file_common_advance_position_release_fd(f, total);
            
            return err;
        }
    }
}

ya_result
file_pool_flush(file_pool_file_t f)
{
    int fd = file_common_acquire_fd(f);
    
    if(fd < 0)
    {
        return fd;
    }
    
    // flush
    
    ya_result ret = SUCCESS;
    
    if(fdatasync_ex(fd) < 0)
    {
        ret = ERRNO_ERROR;
    }
    
    file_common_release_fd(f);
    
    return ret;
}

ya_result
file_pool_get_size(file_pool_file_t f, size_t *sizep)
{
    if(sizep != NULL)
    {
        int fd = file_common_acquire_fd(f);

        if(fd < 0)
        {
            return fd;
        }

        // truncate

        ya_result ret = SUCCESS;

        struct stat st;

        if(fstat(fd, &st) >= 0)
        {
            *sizep = st.st_size;
        }
        else
        {
            ret = ERRNO_ERROR;
        }

        file_common_release_fd(f);
        
        return ret;
    }
    else
    {
        return ERROR;
    }
}

ya_result
file_pool_resize(file_pool_file_t f, size_t size)
{
    int fd = file_common_acquire_fd(f);
    
    if(fd < 0)
    {
        return fd;
    }
    
    // truncate
    
    ya_result ret = SUCCESS;
    if(ftruncate_ex(fd, size) < 0)
    {
        ret = ERRNO_ERROR;
    }
    
    file_common_release_fd(f);
    
    return ret;
}

#endif

ssize_t
file_pool_seek(file_pool_file_t f, ssize_t position, int from)
{
    ssize_t ret;
    group_mutex_lock(&f->common->file_pool->mtx, GROUP_MUTEX_WRITE);
    
    switch(from)
    {
        case SEEK_SET:
        {
            f->position = position;
            ret = (ssize_t)f->position;
            break;
        }
        case SEEK_CUR:
        {
            ssize_t p = f->position + position;
            if(p >= 0)
            {
                f->position = p;
            }
            else
            {
                f->position = 0;
            }
            ret = (ssize_t)f->position;
            break;
        }
        case SEEK_END:
        {   
            size_t size;
            file_pool_get_size(f, &size); // can only fail if a NULL is given
            
            ssize_t p =size + position;
            
            if(p >= 0)
            {
                f->position = p;
            }
            else
            {
                f->position = 0;
            }
            ret = (ssize_t)f->position;
            break;
        }
        default:
        {
            ret = INVALID_ARGUMENT_ERROR;
            break;
        }
    }
    
    group_mutex_unlock(&f->common->file_pool->mtx, GROUP_MUTEX_WRITE);

    return ret;
}

ya_result
file_pool_tell(file_pool_file_t f, size_t *positionp)
{
    if(positionp != NULL)
    {
        group_mutex_lock(&f->common->file_pool->mtx, GROUP_MUTEX_READ);
        *positionp = f->position;
        group_mutex_unlock(&f->common->file_pool->mtx, GROUP_MUTEX_READ);
        
        return SUCCESS;
    }
    else
    {
        return ERROR;
    }
}

// flushes, but only closes the file when fd are needed

ya_result
file_pool_close(file_pool_file_t f)
{
    group_mutex_double_lock(&f->common->file_pool->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    
    file_common_t fc = f->common;
    file_pool_t fp = fc->file_pool;
    
#if FP_USE_ABSTRACT_FILES
    if(fc->file != NULL)
    {
        file_flush(fc->file);
    }
#else
    if(fc->fd >= 0)
    {
        fdatasync_ex(fc->fd);
    }
#endif
    
    group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    file_destroy(f);
    group_mutex_exchange_locks(&fp->mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ);
    
    group_mutex_double_unlock(&fp->mtx, GROUP_MUTEX_READ, GROUP_MUTEX_WRITE);
    
    return SUCCESS;
}

ya_result
file_pool_unlink(file_pool_file_t f)
{
    ya_result ret;
    
    if(f != NULL)
    {
        ret = INVALID_ARGUMENT_ERROR;

        if(f->common != NULL)
        {
            if(f->common->file_pool != NULL)
            {
                ret = file_pool_unlink_from_pool_and_filename(f->common->file_pool, f->common->name);
            }
        }
    }
    else
    {
        ret = UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    return ret;
}

const char *
file_pool_filename(const file_pool_file_t f)
{
    if(f != NULL)
    {
        const file_common_t fc = f->common;
        return fc->name;
    }
    else
    {
        return "NULL";
    }
}

static ya_result
file_pool_file_output_stream_write(output_stream* os, const u8* buffer, u32 len)
{
    file_pool_file_t f = (file_pool_file_t)os->data;
    ya_result ret = file_pool_write(f, buffer, len);
    return ret;
}

static ya_result
file_pool_file_output_stream_writefully(output_stream* os, const u8* buffer, u32 len)
{
    file_pool_file_t f = (file_pool_file_t)os->data;
    ya_result ret = file_pool_writefully(f, buffer, len);
    return ret;
}

static ya_result
file_pool_file_output_stream_flush(output_stream* os)
{
    file_pool_file_t f = (file_pool_file_t)os->data;
    ya_result ret = INVALID_STATE_ERROR;
    if(f != NULL)
    {
        ret = file_pool_flush(f);
    }
    return ret;
}

static void
file_pool_file_output_stream_close(output_stream* os)
{
    file_pool_file_t f = (file_pool_file_t)os->data;
    if(f != NULL)
    {
        file_pool_close(f);
    }
}

static const output_stream_vtbl file_pool_file_output_stream_vtbl =
{
    file_pool_file_output_stream_write,
    file_pool_file_output_stream_flush,
    file_pool_file_output_stream_close,
    "file_pool_file_output_stream",
};

static const output_stream_vtbl file_pool_file_full_output_stream_vtbl =
{
    file_pool_file_output_stream_writefully,
    file_pool_file_output_stream_flush,
    file_pool_file_output_stream_close,
    "file_pool_file_output_stream",
};

void
file_pool_file_output_stream_init(output_stream *os, file_pool_file_t f)
{
    os->data = f;
    os->vtbl = &file_pool_file_output_stream_vtbl;
}

void
file_pool_file_output_stream_set_full_writes(output_stream *os, bool full_writes)
{
    if(full_writes)
    {
        os->vtbl = &file_pool_file_full_output_stream_vtbl;
    }
    else
    {
        os->vtbl = &file_pool_file_output_stream_vtbl;
    }
}

void
file_pool_file_output_stream_detach(output_stream *os)
{
    assert((os->vtbl == &file_pool_file_output_stream_vtbl) || (os->vtbl == &file_pool_file_full_output_stream_vtbl));
    os->data = NULL;
}

static ya_result
file_pool_file_input_stream_read(input_stream* os, void* buffer, u32 len)
{
    file_pool_file_t f = (file_pool_file_t)os->data;
    ya_result ret = file_pool_read(f, buffer, len);
    return ret;
}

static ya_result
file_pool_file_input_stream_readfully(input_stream* os, void* buffer, u32 len)
{
    file_pool_file_t f = (file_pool_file_t)os->data;
    ya_result ret = file_pool_readfully(f, buffer, len);
    return ret;
}

static ya_result
file_pool_file_input_stream_skip(input_stream* os, u32 len)
{
    file_pool_file_t f = (file_pool_file_t)os->data;
    ya_result ret = file_pool_seek(f, len, SEEK_CUR);
    return ret;
}

static void
file_pool_file_input_stream_close(input_stream* os)
{
    file_pool_file_t f = (file_pool_file_t)os->data;
    if(f != NULL)
    {
        file_pool_close(f);
    }
}

static const input_stream_vtbl file_pool_file_input_stream_vtbl =
{
    file_pool_file_input_stream_read,
    file_pool_file_input_stream_skip,
    file_pool_file_input_stream_close,
    "file_pool_file_input_stream"
};

static const input_stream_vtbl file_pool_file_full_input_stream_vtbl =
{
    file_pool_file_input_stream_readfully,
    file_pool_file_input_stream_skip,
    file_pool_file_input_stream_close,
    "file_pool_file_input_stream"
};

void
file_pool_file_input_stream_init(input_stream *is, file_pool_file_t f)
{
    is->data = f;
    is->vtbl = &file_pool_file_input_stream_vtbl;
}

void
file_pool_file_input_stream_detach(input_stream *os)
{
    assert((os->vtbl == &file_pool_file_input_stream_vtbl) || (os->vtbl == &file_pool_file_full_input_stream_vtbl));
    os->data = NULL;
}

void
file_pool_file_input_stream_set_full_reads(input_stream *is, bool full_writes)
{
    if(full_writes)
    {
        is->vtbl = &file_pool_file_full_input_stream_vtbl;
    }
    else
    {
        is->vtbl = &file_pool_file_input_stream_vtbl;
    }
}

/** @} */
