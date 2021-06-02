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

//#include "dnscore/circular-file.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define CIRCULAR_FILE_C 1

#include "dnscore/fdtools.h"
#include "dnscore/file-pool.h"
#include "dnscore/zalloc.h"

#if DEBUG
#include "dnscore/format.h"
#endif

#include "dnscore/logger.h"

#define MODULE_MSG_HANDLE g_system_logger

#define CIRCFILE_TAG 0x454c494643524943

#if DEBUG
#ifndef CIRCULAR_FILE_DEBUG
// should be 0
#define CIRCULAR_FILE_DEBUG 0
#endif
#else // not DEBUG
#if CIRCULAR_FILE_DEBUG
#pragma message("***********************************************************")
#pragma message("***********************************************************")
#pragma message("CIRCULAR_FILE_DEBUG 1")
#pragma message("***********************************************************")
#pragma message("***********************************************************")
#endif
#endif

/*
 * u32 magic
 * u32 reserved space size
 * u64 maximum size for the storage
 * u8 reserved[reserved space size]
 * u8 storage[]
 * 
 */

struct circular_file_s
{
    file_pool_file_t f;
    u64 maximum_size;       // the current maximum size of the file
    u64 pending_size;       // the pending maximum size of the file, to be put into maximum_size as soon as the file isn't wrapped (anymore)
    u64 begin;              // the beginning in the file, relative to the header
    u64 size;               // the size of the file, the number of bytes from begin (wrapped or not)
    u64 position;           // the relative position to read/write, relative to begin
    u64 modulo;             // the physical size of the file - headers
    u32 reserved_size;      // the size of a reserved header (for the calling code)
    bool header_changed;    // this flag tells the header has changed and should be written with the next flush or close
};

typedef struct circular_file_s circular_file_s;

struct circular_file_header_s
{
    u8 magic[4];        // magic number
    u32 reserved_size;  // fixed size reserved at the beginning of the file (just after this header)
    u64 maximum_size;   // maximum allowed size of the file
    u64 begin;          // beginning of the file
    u64 size;           // end of the file
};

#include "dnscore/circular-file.h"

/*
static inline u64 circular_file_end(circular_file_t cf)
{
    return (cf->begin + cf->size) % cf->modulo;
}

static inline u64 circular_file_end_checked(circular_file_t cf)
{
    if(cf->modulo > 0)
    {
        return circular_file_end(cf);
    }
    else
    {
        return 0;
    }
}
*/
static inline bool circular_file_wrapped(circular_file_t cf)
{
    return (cf->begin + cf->size) > cf->modulo;
}

ya_result
circular_file_create(circular_file_t *cfp, file_pool_t fp, const u8 magic[4], const char* path, s64 size_max, u32 reserved_header_size)
{
    // static_assert(sizeof(struct circular_file_header_s) == 32);

    if(size_max < 0)
    {
        size_max = MAX_S64;
    }
    
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_create(%p, %p, %08x, '%s', %lli, %u)", cfp, fp, *(u32*)magic, path, size_max, reserved_header_size);
#endif
    
    if(sizeof(struct circular_file_header_s) + reserved_header_size > (u64)size_max)
    {
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_create(%p, %p, %08x, '%s', %lli, %u) failed: %r", cfp, fp, *(u32*)magic, path, size_max, reserved_header_size, INVALID_ARGUMENT_ERROR);
#endif
        return INVALID_ARGUMENT_ERROR;
    }
    
    //O_LARGEFILE
    //O_NOATIME
            
    file_pool_file_t f = file_pool_open_ex(fp, path, O_CREAT|O_EXCL, 0644);
    
    if(f == NULL)
    {
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_create(%p, %p, %08x, '%s', %lli, %u) failed: %r", cfp, fp, *(u32*)magic, path, size_max, reserved_header_size, ERRNO_ERROR);
#endif
        return ERRNO_ERROR;
    }
    
    struct circular_file_header_s hdr;
    
    memcpy(hdr.magic, magic, 4);
    hdr.reserved_size = reserved_header_size;
    hdr.maximum_size = size_max - sizeof(hdr) - reserved_header_size;
    hdr.begin = 0;
    hdr.size = 0;
       
    ya_result ret = file_pool_writefully(f, &hdr, sizeof(hdr));
    
    if(FAIL(ret))
    {
        file_pool_close(f);
        
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_create(%p, %p, %08x, '%s', %lli, %u) failed: %r", cfp, fp, *(u32*)magic, path, ret);
#endif
        return ret;
    }
    
    circular_file_t cf;
    ZALLOC_OBJECT_OR_DIE(cf, circular_file_s, CIRCFILE_TAG);
    cf->f = f;
    cf->maximum_size = hdr.maximum_size;
    cf->pending_size = cf->maximum_size;
    cf->begin = hdr.begin;
    cf->size = hdr.size;
    cf->position = 0;
    cf->modulo = hdr.size;  // file size - (header + reserved)
    cf->reserved_size = hdr.reserved_size;
    cf->header_changed = FALSE;
    *cfp = cf;
    
    circular_file_seek(cf, 0);
    
    return SUCCESS;
}

ya_result
circular_file_open(circular_file_t *cfp, file_pool_t fp, const u8 magic[4], const char *path)
{
    // static_assert(sizeof(struct circular_file_header_s) == 32);
    
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_open(%p, %p, %08x, '%s')", cfp, fp, *(u32*)magic, path);
#endif
    
    file_pool_file_t f = file_pool_open(fp, path);
    
    if(f == NULL)
    {
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_open(%p, %p, %08x, '%s') failed: %r", cfp, fp, *(u32*)magic, path, ERRNO_ERROR);
#endif
        return ERRNO_ERROR;
    }
    
    struct circular_file_header_s hdr;
    
    ya_result ret = file_pool_readfully(f, &hdr, sizeof(hdr));
    
    if(FAIL(ret))
    {
        file_pool_close(f);
        
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_create(%p, %p, %08x, '%s') failed: %r", cfp, fp, *(u32*)magic, path, ret);
#endif
        return ret;
    }
    
    if(memcmp(magic, hdr.magic, 4) != 0)
    {
        file_pool_close(f);
        
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_create(%p, %p, %08x, '%s') failed: %r", cfp, fp, *(u32*)magic, path, DATA_FORMAT_ERROR);
#endif
        return DATA_FORMAT_ERROR; // wrong magic
    }
    
    if(sizeof(struct circular_file_header_s) + hdr.reserved_size > hdr.maximum_size)
    {
        file_pool_close(f);
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_create(%p, %p, %08x, '%s') failed: %r", cfp, fp, *(u32*)magic, path, DATA_FORMAT_ERROR);
#endif
        return DATA_FORMAT_ERROR; // the header makes no sense
    }
    
    size_t file_size = 0;
    if(FAIL(ret = file_pool_get_size(f, &file_size)))
    {
        file_pool_close(f);
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_create(%p, %p, %08x, '%s') failed: %r", cfp, fp, *(u32*)magic, path, ret);
#endif
        return ret;
    }
    
    ssize_t modulo = (ssize_t)(file_size - (sizeof(struct circular_file_header_s) + hdr.reserved_size));
    
    if((modulo < 0) || (modulo > (ssize_t )hdr.maximum_size))
    {
        file_pool_close(f);
        
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_create(%p, %p, %08x, '%s') failed: %r", cfp, fp, *(u32*)magic, path, DATA_FORMAT_ERROR);
#endif
        return DATA_FORMAT_ERROR;
    }
    
    circular_file_t cf;
    ZALLOC_OBJECT_OR_DIE(cf, circular_file_s, CIRCFILE_TAG);
    cf->f = f;
    cf->maximum_size = hdr.maximum_size;
    cf->pending_size = cf->maximum_size;
    cf->begin = hdr.begin;
    cf->size = hdr.size;
    cf->position = 0;
    
    cf->modulo = (u64)modulo;  // file size - (header + reserved)
    cf->reserved_size = hdr.reserved_size;
    cf->header_changed = FALSE;
    *cfp = cf;
    
    circular_file_seek(cf, 0);
        
    return SUCCESS;    
}

/**
 * Close the circular file reference.
 * The file will be effectively closed when
 */

ya_result
circular_file_close(circular_file_t cf)
{
    if(cf->f != NULL)
    {
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_close(%p)", cf);
#endif
        circular_file_flush(cf);
        
        file_pool_close(cf->f);
        memset(cf, 0x00, sizeof(*cf));
        ZFREE_OBJECT(cf);
        return SUCCESS;
    }
    else
    {
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_close(%p) failed: already closed", cf);
#endif
        return ERROR;
    }
}

const char*
circular_file_name(circular_file_t cf)
{
    if((cf != NULL) && (cf->f != NULL))
    {
        const char *name = file_pool_filename(cf->f);
        
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_name(%p) = '%s'", cf, name);
#endif
        return name;
    }
    else
    {
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_name(%p) failed: invalid state, returning 'NULL'", cf);
#endif
        return "NULL";
    }
}

ya_result
circular_file_unlink(circular_file_t cf)
{
    ya_result ret = file_pool_unlink(cf->f);
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_unlink(%p) (%r)", cf, ret);
#endif
    return ret;
}

u64
circular_file_tell(circular_file_t cf)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_tell(%p) = %llu", cf, cf->position);
#endif
    return cf->position;
}

/**
 * Moves to the specified position in the file
 * 
 * @param relative_offset
 * @return 
 */

ssize_t
circular_file_seek(circular_file_t cf, ssize_t relative_offset)
{
    ssize_t ret;
    
#if CIRCULAR_FILE_DEBUG
    ssize_t saved_position = relative_offset;
    log_debug5("circular_file_seek(%p, %lli)", cf, saved_position);
#endif

    relative_offset = MIN(relative_offset, (s64)cf->size);
    
    ssize_t wrapped_position = cf->begin + relative_offset;
    
    if(cf->modulo > 0)
    {
        if(circular_file_wrapped(cf))
        {
            wrapped_position %= cf->modulo;
        }
    }
    
    ret = file_pool_seek(cf->f, (size_t)wrapped_position + cf->reserved_size + sizeof(struct circular_file_header_s), SEEK_SET);
    
    if(ISOK(ret))
    {
        cf->position = (u64)relative_offset;
    }
    else
    {
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_seek(%p, %lli) failed: %r", cf, saved_position, ret);
#endif
        relative_offset = ret;
    }
    
    return relative_offset;
}

/**
 * Moves relatively from the current position in the file
 * 
 * @param relative_offset
 * @return 
 */

ssize_t
circular_file_seek_relative(circular_file_t cf, ssize_t relative_offset)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_seek_relative(%p, %lli)", cf, relative_offset);
#endif
    
    ssize_t position = circular_file_tell(cf) + relative_offset;
    position = circular_file_seek(cf, position);
    return position;
}

/**
 * Reads bytes in the file.
 */

ya_result
circular_file_read(circular_file_t cf, void* buffer_, u32 n)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_read(%p, %p, %i)", cf, buffer_, n);
#endif
    
    u8* buffer = (u8*)buffer_;
    
    ya_result ret;
    
    if(n == 0)
    {
        return 0;
    }

    u64 avail = cf->size - cf->position;    // both position and size are relative to begin
    
    if(avail < n)
    {
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_read(%p, %p, %i) failed: %r", cf, buffer_, n, CIRCULAR_FILE_SHORT);
#endif
        if(avail > 0)
        {
            return CIRCULAR_FILE_SHORT;
        }
        else
        {
            return CIRCULAR_FILE_END;
        }
    }

    if(!circular_file_wrapped(cf))
    {
        // the file does not wraps : everything will be read in one operation
        
        u64 abs_position = cf->begin + cf->position;
        
        assert(abs_position <= cf->maximum_size);
        
        if(ISOK(ret = file_pool_seek(cf->f, abs_position + cf->reserved_size + sizeof(struct circular_file_header_s), SEEK_SET)))
        {
            if(ISOK(ret = file_pool_readfully(cf->f, buffer, n)))
            {
                cf->position += n;
                
                assert(cf->position <= cf->maximum_size);
                
                ret = n;
            }
        }
    }
    else
    {
        // the file wraps: we may have to read in two operations
        
        u64 abs_position = (cf->begin + cf->position) % cf->modulo;
        
        assert(abs_position <= cf->maximum_size);

        //u64 abs_end = circular_file_end(cf);
        
        // abs_end is the position of the end of the data relatively to position 0
        
        if((cf->position > 0) && (abs_position <= cf->begin))
        {
            // if the absolute position is before the end, we will have to read from position to end
            // then if more has to be read, from 0 to whatever remains to be read
            
            u64 end_avail = MIN(cf->begin - abs_position, n);

            if(end_avail < n)
            {
                // it will be a short read

                return CIRCULAR_FILE_SHORT;
            }
            
            if(ISOK(ret = file_pool_seek(cf->f, abs_position + cf->reserved_size + sizeof(struct circular_file_header_s), SEEK_SET)))
            {
                if(ISOK(ret = file_pool_readfully(cf->f, buffer, end_avail)))
                {
                    cf->position += n;
                    assert(cf->position <= cf->maximum_size);
                    ret = n;
                }
            }
        }
        else
        {
            // if the absolute position is after or equal to the end, we will have to read from position to modulo
            // then from 0 to end
            
            u64 end_avail = MIN(cf->modulo - abs_position, n);
            
            if(ISOK(ret = file_pool_seek(cf->f, abs_position + cf->reserved_size + sizeof(struct circular_file_header_s), SEEK_SET)))
            {
                if(ISOK(ret = file_pool_readfully(cf->f, buffer, end_avail)))
                {
                    u64 m = n - end_avail;
                    
                    if(m > 0)
                    {   
                        if(ISOK(ret = file_pool_seek(cf->f, cf->reserved_size + sizeof(struct circular_file_header_s), SEEK_SET)))
                        {
                            if(ISOK(ret = file_pool_readfully(cf->f, &buffer[end_avail], m)))
                            {
                                cf->position += n;
                                assert(cf->position <= cf->maximum_size);
                                ret = n;
                            }
                        }
                    }
                    else
                    {
                        cf->position += n;
                        assert(cf->position <= cf->maximum_size);
                        ret = n;
                    }
                }
            }
        }
    }


    
#if CIRCULAR_FILE_DEBUG
    if(FAIL(ret))
    {
        log_debug5("circular_file_read(%p, %p, %i) failed: %r", cf, buffer_, n, ret);
    }
#endif
    
    return ret;
}

/**
 * Writes bytes in the file.
 * If there is no room anymore, a short count is returned.
 */

ya_result
circular_file_write(circular_file_t cf, const void* buffer_, u32 n)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_write(%p, %p, %i)", cf, buffer_, n);
#endif
    
    u8* buffer = (u8*)buffer_;
   
    ya_result ret;
    
    if(n == 0)
    {
        return 0;
    }

    if(!circular_file_wrapped(cf))
    {
        // the file does not wraps
        
        u64 abs_position = cf->begin + cf->position;
        
        assert(abs_position <= cf->maximum_size);
        
        u64 end_avail = cf->maximum_size - abs_position;
        
        u64 begin_avail = cf->begin;
        
        u64 avail = end_avail + begin_avail;
        
        if(avail < n)
        {
#if CIRCULAR_FILE_DEBUG
            log_debug5("circular_file_write(%p, %p, %i) failed: %r", cf, buffer_, n, CIRCULAR_FILE_FULL);
#endif
            return CIRCULAR_FILE_FULL;
        }
        
        end_avail = MIN(end_avail, n);
        
        if(ISOK(ret = file_pool_seek(cf->f, abs_position + cf->reserved_size + sizeof(struct circular_file_header_s), SEEK_SET)))
        {
            if(ISOK(ret = file_pool_writefully(cf->f, buffer, end_avail)))
            {
                if(abs_position + end_avail > cf->modulo)
                {
                    cf->modulo = abs_position + end_avail;
                }
                
                u64 m = n - end_avail;

                if(m > 0)
                {
                    if(ISOK(ret = file_pool_seek(cf->f, cf->reserved_size + sizeof(struct circular_file_header_s), SEEK_SET)))
                    {
                        if(ISOK(ret = file_pool_writefully(cf->f, &buffer[end_avail], m)))
                        {
                            cf->position += n;
                            
                            if(cf->position > cf->size)
                            {
                                cf->size = cf->position;
                                cf->header_changed = TRUE;
                            }
                            
                            ret = n;
                        }
                    }
                }
                else
                {
                    cf->position += n;
                    
                    assert(cf->position <= cf->maximum_size);
                            
                    if(cf->position > cf->size)
                    {
                        cf->size = cf->position;
                        cf->header_changed = TRUE;
                    }

                    ret = n;
                }
            }
        }
    }
    else
    {
        // the file wraps: we may have to write the buffer in two operations
        // the file cannot grow at this moment (as it is wrapped)
        // so what is available is
        
        // real position in file = (begin + position) % modulo
        // if real position < begin: available = begin - real position
        // else: available = modulo - real position + begin

        u64 abs_position = (cf->begin + cf->position) % cf->modulo;
        
        // abs_end is the position of the end of the data relatively to position 0
        
        if((cf->position > 0) && (abs_position <= cf->begin))
        {
            // if the absolute position is before the end, we will have to read from position to end
            // then if more has to be read, from 0 to whatever remains to be read
            
            u64 end_avail = cf->begin - abs_position;
            
            if(end_avail < n)
            {
#if CIRCULAR_FILE_DEBUG
                log_debug5("circular_file_write(%p, %p, %i) failed: %r", cf, buffer_, n, CIRCULAR_FILE_FULL);
#endif
                return CIRCULAR_FILE_FULL;
            }
            
            end_avail = MIN(end_avail, n);
            
            if(ISOK(ret = file_pool_seek(cf->f, abs_position + cf->reserved_size + sizeof(struct circular_file_header_s), SEEK_SET)))
            {
                if(ISOK(ret = file_pool_writefully(cf->f, buffer, end_avail)))
                {
                    if(abs_position + end_avail > cf->modulo)
                    {
                        cf->modulo = abs_position + end_avail;
                    }

                    cf->position += n;

                    if(cf->position > cf->size)
                    {
                        cf->size = cf->position;
                        cf->header_changed = TRUE;
                    }

                    ret = n;
                }
            }
        }
        else
        {
            // if the absolute position is after or equal to the end, we will have to write from position to begin
            // then from 0 to end
            
            u64 total_avail = cf->modulo - abs_position + cf->begin;
            
            if(total_avail < n)
            {
#if CIRCULAR_FILE_DEBUG
                log_debug5("circular_file_write(%p, %p, %i) failed: %r", cf, buffer_, n, CIRCULAR_FILE_FULL);
#endif
                return CIRCULAR_FILE_FULL;
            }
            
            u64 end_avail = MIN(cf->modulo - abs_position, n);
            
            if(ISOK(ret = file_pool_seek(cf->f, abs_position + cf->reserved_size + sizeof(struct circular_file_header_s), SEEK_SET)))
            {
                if(ISOK(ret = file_pool_writefully(cf->f, buffer, end_avail)))
                {
                    if(abs_position + end_avail > cf->modulo)
                    {
                        cf->modulo = abs_position + end_avail;
                    }
                    
                    u64 m = n - end_avail;
                    
                    if(m > 0)
                    {
                        if(ISOK(ret = file_pool_seek(cf->f, cf->reserved_size + sizeof(struct circular_file_header_s), SEEK_SET)))
                        {
                            if(ISOK(ret = file_pool_writefully(cf->f, &buffer[end_avail], m)))
                            {
                                cf->position += n;
                                
                                if(cf->position > cf->size)
                                {
                                    cf->size = cf->position;
                                    cf->header_changed = TRUE;
                                }
                                
                                ret = n;
                            }
                        }
                    }
                    else
                    {
                        cf->position += n;
                        
                        if(cf->position > cf->size)
                        {
                            cf->size = cf->position;
                            cf->header_changed = TRUE;
                        }
                        
                        ret = n;
                    }
                }
            }
        }
    }
    

    
#if CIRCULAR_FILE_DEBUG
    if(FAIL(ret))
    {
        log_debug5("circular_file_write(%p, %p, %i) failed: %r", cf, buffer_, n, ret);
    }
#endif
    
    return ret;
}

/**
 * To know how much space is available on the file before having to overwrite
 * 
 */

u64
circular_file_get_used_space(circular_file_t cf)
{    
    if(cf->begin <= cf->size)
    {
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_get_used_space(%p) = %llu", cf, (cf->maximum_size - cf->size) + cf->begin);
#endif
        return (cf->maximum_size - cf->size) + cf->begin;
    }
    else
    {
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_get_used_space(%p) = %llu", cf, cf->begin - cf->size);
#endif
        return cf->begin - cf->size;
    }
}

u64
circular_file_get_maximum_size(circular_file_t cf)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_get_maximum_size(%p) = %llu", cf, cf->maximum_size);
#endif
    return cf->maximum_size;
}

u64
circular_file_get_pending_size(circular_file_t cf)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_get_maximum_size(%p) = %llu", cf, cf->pending_size);
#endif
    return cf->pending_size;
}

u64
circular_file_get_size(circular_file_t cf)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_get_size(%p) = %llu", cf, cf->size);
#endif
    return cf->size;
}

void
circular_file_set_size(circular_file_t cf, u64 size)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_set_size(%p, %llu)", cf, size);
#endif
    cf->size = size;
    if(cf->position > size)
    {
        cf->position = size;
    }
}

s64
circular_file_get_read_available(circular_file_t cf)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_get_read_available(%p) = %llu", cf, cf->size - cf->position);
#endif
    return cf->size - cf->position;
}

s64
circular_file_get_write_available(circular_file_t cf)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_write(%p, %p, %i)", cf, buffer_, n);
#endif
    if(!circular_file_wrapped(cf))
    {
        // the file does not wraps

        s64 abs_position = cf->begin + cf->position;

        assert(abs_position <= cf->maximum_size);

        s64 end_avail = cf->maximum_size - abs_position;

        s64 begin_avail = cf->begin;

        s64 avail = end_avail + begin_avail;

        return avail;
    }
    else
    {
        s64 abs_position = (cf->begin + cf->position) % cf->modulo;

        // abs_end is the position of the end of the data relatively to position 0

        if((cf->position > 0) && (abs_position <= cf->begin))
        {
            // if the absolute position is before the end, we will have to read from position to end
            // then if more has to be read, from 0 to whatever remains to be read

            s64 end_avail = cf->begin - abs_position;

            return end_avail;
        }
        else
        {
            // if the absolute position is after or equal to the end, we will have to write from position to begin
            // then from 0 to end

            s64 total_avail = cf->modulo - abs_position + cf->begin;

            return total_avail;
        }
    }
}

/**
 * Changes the maximum size to an higher value.  The new space may not be made available
 * instantly if the write offset is physically before the logical start of the file.
 * The new size must bi bigger than sizeof(struct circular_file_header_s)
 */

ya_result
circular_file_grow(circular_file_t cf, s64 new_maximum_size)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_grow(%p, %lli)", cf, new_maximum_size);
#endif
    if(new_maximum_size <= (s64)sizeof(struct circular_file_header_s))
    {
        return INVALID_ARGUMENT_ERROR;
    }
    
    if(cf->maximum_size < (u64)new_maximum_size)
    {
        cf->pending_size = (u64)new_maximum_size;
        
        if(!circular_file_wrapped(cf))
        {
            cf->maximum_size = (u64)new_maximum_size;
            cf->header_changed = TRUE;
        }
        
        return SUCCESS;
    }
    else
    {
        return CIRCULAR_FILE_LIMIT_EXCEEDED;
    }
}

ya_result
circular_file_get_reserved_header_size(circular_file_t cf, s32 *reserved_size)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_get_reserved_header_size(%p, %p) = ", cf, reserved_size, cf->reserved_size);
#endif
    
    *reserved_size = cf->reserved_size;
    return SUCCESS;
}

ya_result
circular_file_read_reserved_header(circular_file_t cf, void *buffer, u32 buffer_size)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_read_reserved_header(%p, %p, %i) = ", cf, buffer, buffer_size);
#endif
    
    if(cf->reserved_size <= buffer_size)
    {
        ssize_t position;
        ya_result ret;
        
        if(ISOK(ret = file_pool_tell(cf->f, (size_t*)&position)))
        {
            if(ISOK(ret = file_pool_seek(cf->f, sizeof(struct circular_file_header_s), SEEK_SET)))
            {
                if(ISOK(ret = file_pool_read(cf->f, buffer, cf->reserved_size)))
                {
                    ret = file_pool_seek(cf->f, position, SEEK_SET);
                }
            }
        }
        
#if CIRCULAR_FILE_DEBUG
        if(FAIL(ret))
        {
            log_debug5("circular_file_read_reserved_header(%p, %p, %i) failed: %r", cf, buffer, buffer_size, ret);
        }
#endif
        
        return ret;
    }
    else
    {
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_read_reserved_header(%p, %p, %i) failed: %r", cf, buffer, buffer_size, BUFFER_WOULD_OVERFLOW);
#endif
        
        return BUFFER_WOULD_OVERFLOW;
    }
}

ya_result
circular_file_write_reserved_header(circular_file_t cf, void *buffer, u32 buffer_size)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_write_reserved_header(%p, %p, %i)", cf, buffer, buffer_size);
#endif
    
    if(cf->reserved_size <= buffer_size)
    {
        ssize_t position;
        ya_result ret;
        
        if(ISOK(ret = file_pool_tell(cf->f, (size_t*)&position)))
        {
            if(ISOK(ret = file_pool_seek(cf->f, sizeof(struct circular_file_header_s), SEEK_SET)))
            {
                if(ISOK(ret = file_pool_write(cf->f, buffer, cf->reserved_size)))
                {
                    ret = file_pool_seek(cf->f, position, SEEK_SET);
                }
            }
        }
        
#if CIRCULAR_FILE_DEBUG
        if(FAIL(ret))
        {
            log_debug5("circular_file_write_reserved_header(%p, %p, %i) failed: %r", cf, buffer, buffer_size, ret);
        }
#endif
        
        return ret;
    }
    else
    {
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_write_reserved_header(%p, %p, %i) failed: %r", cf, buffer, buffer_size, BUFFER_WOULD_OVERFLOW);
#endif
        return BUFFER_WOULD_OVERFLOW;
    }
}

ya_result
circular_file_flush(circular_file_t cf)
{
    ya_result ret = SUCCESS;
    
    log_debug5("circular_file_flush(%p)", cf);
    
    if(cf->header_changed)
    {
        ssize_t position;
        
        if(ISOK(ret = file_pool_tell(cf->f, (size_t*)&position)))
        {
            struct circular_file_header_s hdr =
            {
                {0,0,0,0},
                0,
                cf->maximum_size,
                cf->begin,
                cf->size,      
            };
                        
            if(ISOK(ret = file_pool_seek(cf->f, offsetof(struct circular_file_header_s, maximum_size), SEEK_SET)))
            {
                ret = file_pool_write(cf->f, &hdr.maximum_size, sizeof(struct circular_file_header_s) - offsetof(struct circular_file_header_s, maximum_size));
                
                file_pool_seek(cf->f, position, SEEK_SET); // can only fail if the 3rd parameter is wrong
            }
        }
        
        cf->header_changed = FALSE;
    }
    
    if(ISOK(ret))
    {
        ret = file_pool_flush(cf->f);
    }
    
#if CIRCULAR_FILE_DEBUG
    if(FAIL(ret))
    {
        log_debug5("circular_file_flush(%p) failed: %r", cf, ret);
    }
#endif
    
    return ret;
}

/**
 * Releases space at the logical beginning of the file
 * Should be called by the callback when space is needed
 */

ya_result
circular_file_shift(circular_file_t cf, s64 bytes)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_shift(%p, %lli)", cf, bytes);
#endif
    
    if(bytes > (s64)cf->size)
    {
#if CIRCULAR_FILE_DEBUG
        log_debug5("circular_file_shift(%p, %lli) failed: %r", cf, bytes, INVALID_ARGUMENT_ERROR);
#endif
        return INVALID_ARGUMENT_ERROR;
    }
    
    cf->begin += bytes;
    cf->size -= bytes;
    cf->position -= bytes; // could result in a negative position, but may be used by a relative seek forward

    assert(cf->size <= cf->maximum_size);
    
    if(cf->begin >= cf->modulo)
    {
        cf->begin %= cf->modulo;
    }
    
    if(cf->maximum_size < cf->pending_size)
    {
        if(!circular_file_wrapped(cf))
        {
            cf->maximum_size = cf->pending_size;
        }
    }
    
    cf->header_changed = TRUE;
    
    return SUCCESS;
}

static ya_result
circular_file_input_stream_read(input_stream* is, void *buffer, u32 len)
{
    ya_result ret;
    
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_input_stream_read(%p, %p, %u)", is, buffer, len);
#endif
    
    ret = circular_file_read((circular_file_t)is->data, buffer, len);
    
    return ret;
}

static ya_result
circular_file_input_stream_skip(input_stream* is, u32 len)
{
    ya_result ret;
    u32 remain = len;
    u8 tmp[512];
    
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_input_stream_skip(%p, %u)", is, len);
#endif
    
    while(remain > 0)
    {
        if(FAIL(ret = circular_file_read((circular_file_t)is->data, tmp, MIN(sizeof(tmp), remain))))
        {
            len -= remain;
            
            if(len > 0)
            {
                ret = len;
            }
            
            return ret;
        }
        
        remain -= ret;
    }
        
    return len;
}

static void
circular_file_input_stream_close(input_stream* is)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_input_stream_close(%p)", is);
#endif
    
    circular_file_close((circular_file_t)is->data);
}

static void
circular_file_input_stream_noclose(input_stream* is)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_input_stream_noclose(%p)", is);
#endif
    (void)is;
}

static const input_stream_vtbl circular_file_input_stream_vtbl = {
    circular_file_input_stream_read,
    circular_file_input_stream_skip,
    circular_file_input_stream_close,
    "circular_file_input_stream",
};

static const input_stream_vtbl circular_file_input_stream_noclose_vtbl = {
    circular_file_input_stream_read,
    circular_file_input_stream_skip,
    circular_file_input_stream_noclose,
    "circular_file_input_stream_noclose",
};

void
circular_file_input_stream_init(input_stream *is, circular_file_t cf)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_input_stream_init(%p, %p)", is, cf);
#endif
    
    is->data = cf;
    is->vtbl = &circular_file_input_stream_vtbl;
}

void
circular_file_input_stream_noclose_init(input_stream *is, circular_file_t cf)
{
#if CIRCULAR_FILE_DEBUG
    log_debug5("circular_file_input_stream_noclose_init(%p, %p)", is, cf);
#endif
    
    is->data = cf;
    is->vtbl = &circular_file_input_stream_noclose_vtbl;
}

void
circular_file_dump(circular_file_t cf)
{
#if DEBUG
    formatln("%p: [%6llu += %6llu] @ %6llu [%6llu of %6llu to %6llu] %i", cf->f, cf->begin, cf->size, cf->position, cf->modulo, cf->maximum_size, cf->pending_size, cf->header_changed);
    yassert(cf->size <= cf->maximum_size);
    yassert(cf->position <= cf->size);
#endif
    (void)cf;
}
