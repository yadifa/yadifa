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

/** @defgroup 
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#pragma once

/**
 * 
 * The RC struct helps having a structure referenced by multiple concurrent threads
 * released when nobody uses it anymore.
 * 
 */

#include <dnscore/mutex.h>

#ifdef	__cplusplus
extern "C"
{
#endif

typedef void rc_free_method(void*);
    
struct rc_vtbl
{
    rc_free_method *free_callback;
    mutex_t *mtx;
};

typedef struct rc_vtbl rc_vtbl;

/**
 * Initialises an RC vtbl.
 * The callback is called to free the struct when its last reference is released.
 * The mutex is meant to be shared trough a struct type.
 * 
 * @param spvtbl
 * @param free_callback
 * @param mtx
 */

void rc_init_vtbl(rc_vtbl *spvtbl, rc_free_method *free_callback, mutex_t *mtx);
void rc_finalize_vtbl(rc_vtbl *spvtbl);

struct rc_s
{
    rc_vtbl *vtbl;
    s32 count;
};

typedef struct rc_s rc_s;

/**
 * struct whatever
 * {
 *   RC_COUNTER;
 *   int brol;
 * };
 * 
 * alloc:
 * struct whatever *w = malloc & create & cie;
 * rc_acquire(w);
 * return w;
 * 
 * get:
 * rc_acquire(w);
 * return w;
 * 
 * 
 * rc_release(w);
 * w = NULL;
 * 
 */

#define RC_COUNTER struct rc_s __reference_counter

void rc_set_internal(rc_s *rc, rc_vtbl *vtbl);
void rc_aquire_internal(rc_s *rc);
void rc_release_internal(rc_s *rc, void *data);

#define rc_set(__structptr__, spvtbl) \
    rc_set_internal((__structptr__), &((__structptr__)->__reference_counter));

/**
 * The typical place of an rc_acquire is before returning the variable.
 */

#define rc_aquire(__structptr__, spvtbl) \
    rc_aquire_internal(&((__struct_ptr__)->__reference_counter))

/**
 * An rc_release SHOULD be followed by the variable being set to NULL.
 */

#define rc_release(__struct_ptr__) \
    rc_release_internal(&((__struct_ptr__)->__reference_counter), (__struct_ptr__))
    
#ifdef	__cplusplus
}
#endif

/** @} */

/*----------------------------------------------------------------------------*/

