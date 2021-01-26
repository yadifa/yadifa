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
#pragma once

#include <dnscore/sys_types.h>

#ifdef	__cplusplus
extern "C" {
#endif
        
struct file_t_;
    
typedef struct file_t_* file_t;
    
struct file_vtbl
{
    ssize_t (*read)(file_t f, void *buffer, ssize_t size);
    ssize_t (*write)(file_t f, const void *buffer, ssize_t size);
    ssize_t (*seek)(file_t f, ssize_t position, int from);
    ssize_t (*tell)(file_t f);
    int (*flush)(file_t f);
    int (*close)(file_t f);
    ssize_t (*size)(file_t f);
    int (*resize)(file_t f, ssize_t size);
    // add unlink
    // add a copy of the path ?
    // add flags, starting with "is slow" meaning it would benefit from caching
};

struct file_t_
{
    const struct file_vtbl *vtbl;
};

static inline ssize_t file_read(file_t f, void *buffer, ssize_t size) { return f->vtbl->read(f, buffer, size); }
static inline ssize_t file_write(file_t f, const void *buffer, ssize_t size) { return f->vtbl->write( f, buffer, size); }
static inline ssize_t file_seek(file_t f, ssize_t position, int from) { return f->vtbl->seek(f, position, from); }
static inline ssize_t file_tell(file_t f) { return f->vtbl->tell(f); }
static inline int file_flush(file_t f) { return f->vtbl->flush(f); }
static inline int file_close(file_t f) { return f->vtbl->close(f); }
static inline ssize_t file_size(file_t f) { return f->vtbl->size(f); }
static inline int file_resize(file_t f, ssize_t size) { return f->vtbl->resize(f, size); }

#ifdef	__cplusplus
}
#endif

/** @} */
