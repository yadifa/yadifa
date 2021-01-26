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

/** @ingroup dnscore
 *
 * API for allocated memory. Meant to be used with mixed collections.
 * 
 * Allows allocation on ephemeral stacks, zalloc, malloc, ... of objects
 * put together, without having trouble sorting them out at destruction time.
 * 
 * Not used for now.
 * 
 * @{
 */
/*----------------------------------------------------------------------------*/
#ifndef __ALLOCATOR_H__
#define __ALLOCATOR_H__

#include <dnscore/sys_types.h>

struct allocator_s;

/**
 * allocator method signatures
 */

typedef void *allocate_method(struct allocator_s *allocator, u32 size);
typedef void free_method(struct allocator_s *allocator, void *ptr);            // for destruction

/**
 * allocator vtbl
 */

struct allocator_vtbl
{
    allocate_method *allocate_method;
    free_method *free_method;
    const char *__class__;
};

typedef struct allocator_vtbl allocator_vtbl;

/**
 * allocator common structure
 */

struct allocator_s
{
    const allocator_vtbl *vtbl;
};

typedef struct allocator_s allocator_s;

#define aalloc(ac__,size__) (ac__)->vtbl->allocate_method(ac__,size__)
#define afree(ac__,ptr__) (ac__)->vtbl->free_method((ac__),(ptr__))

#ifndef ALLOCATOR_C
extern allocator_s libc_allocator;
#endif

#endif // __ALLOCATOR_H__

/** @} */
