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

/** @defgroup threading Threading, pools, queues, ...
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _THREADED_RINGLIST_H
#define	_THREADED_RINGLIST_H

#include <dnscore/thread.h>
#include <dnscore/sys_types.h>

#ifdef MUTEX_USE_SPINLOCK
#error "Cascaded MUTEX_USE_SPINLOCK definition.  Please remove the potential definition mistmatch (#undef ?)"
#endif

#define MUTEX_USE_SPINLOCK 0

#include <dnscore/sys_types.h>
#include <dnscore/mutex.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct threaded_ringlist threaded_ringlist;

struct threaded_ringlist_node;

struct threaded_ringlist
{
    /* DO NOT MOVE THESE POINTERS */
    struct threaded_ringlist_node *next;
    struct threaded_ringlist_node *prev;
    /* -------------------------- */

    struct threaded_ringlist_node *pool;

    mutex_t mutex;
    mutex_t mutex_enqueue;
    mutex_t mutex_dequeue;

    volatile u32             max_size;  /* DO NOT CACHE THIS INTO REGISTERS */
    volatile u32             size;      /* DO NOT CACHE THIS INTO REGISTERS */

};

#define THREADED_RINGLIST_EMPTY {0,0,0,MUTEX_INITIALIZER,MUTEX_INITIALIZER,MUTEX_INITIALIZER,0,0}

void  threaded_ringlist_init(threaded_ringlist* queue, int max_size);
void  threaded_ringlist_finalize(threaded_ringlist* queue);
void  threaded_ringlist_enqueue(threaded_ringlist* queue,void* constant_pointer);
bool  threaded_ringlist_try_enqueue(threaded_ringlist* queue,void* constant_pointer);
void* threaded_ringlist_peek(threaded_ringlist* queue);
void* threaded_ringlist_try_peek(threaded_ringlist* queue);
void* threaded_ringlist_dequeue(threaded_ringlist* queue);
void* threaded_ringlist_try_dequeue(threaded_ringlist *queue);
u32   threaded_ringlist_dequeue_set(threaded_ringlist* queue, void** array, u32 array_size);
void  threaded_ringlist_wait_empty(threaded_ringlist* queue);
int   threaded_ringlist_size(threaded_ringlist* queue);
/*
 * The queue will block (write) if bigger than this.
 * Note that if the key is already bigger it will blocked (write) until
 * the content is emptied by the readers.
 */
ya_result threaded_ringlist_set_maxsize(threaded_ringlist *queue, int max_size);

#undef MUTEX_USE_SPINLOCK

#ifdef	__cplusplus
}
#endif

#endif	/* _THREADED_QUEUE_H */
/** @} */
