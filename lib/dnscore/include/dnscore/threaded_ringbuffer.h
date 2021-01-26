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
#ifndef _THREADED_RINGBUFFER_H
#define	_THREADED_RINGBUFFER_H

#include <dnscore/sys_types.h>
#include <dnscore/mutex.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct threaded_ringbuffer threaded_ringbuffer;


struct threaded_ringbuffer_node;

/* NOTE: The algorithm does not need these to be volatile */

struct threaded_ringbuffer
{
    void** buffer;
    void** buffer_limit;
    void** write_slot;
    void** read_slot;

    mutex_t mutex;
    mutex_t mutex_enqueue;
    mutex_t mutex_dequeue;

    u32             max_size;
    u32             size;
};

#define THREADED_RINGBUFFER_NULL {0,0,0,0,MUTEX_INITIALIZER,MUTEX_INITIALIZER,MUTEX_INITIALIZER,0,0}

void  threaded_ringbuffer_init(threaded_ringbuffer* queue, int max_size);
void  threaded_ringbuffer_finalize(threaded_ringbuffer* queue);
void  threaded_ringbuffer_enqueue(threaded_ringbuffer* queue,void* constant_pointer);
bool  threaded_ringbuffer_try_enqueue(threaded_ringbuffer* queue,void* constant_pointer);
void* threaded_ringbuffer_peek(threaded_ringbuffer* queue);
void* threaded_ringbuffer_try_peek(threaded_ringbuffer* queue);
void* threaded_ringbuffer_dequeue(threaded_ringbuffer* queue);
void* threaded_ringbuffer_try_dequeue(threaded_ringbuffer *queue);
u32   threaded_ringbuffer_dequeue_set(threaded_ringbuffer* queue, void** array, u32 array_size);
void  threaded_ringbuffer_wait_empty(threaded_ringbuffer* queue);
int   threaded_ringbuffer_size(threaded_ringbuffer* queue);

/*
 * The queue will block (write) if bigger than this.
 * Note that if the key is already bigger it will blocked (write) until
 * the content is emptied by the readers.
 */

ya_result threaded_ringbuffer_set_maxsize(threaded_ringbuffer *queue, int max_size);

#ifdef	__cplusplus
}
#endif

#endif	/* _THREADED_QUEUE_H */
/** @} */
