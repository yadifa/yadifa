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
/** @defgroup threading Threading, pools, queues, ...
 *  @ingroup dnscore
 *  @brief 
 *
 *  This version of the ring buffer uses the condition-wait mechanism instead of the 3-mutex one.
 *  I'll have to bench both versions but the main incentive is to get rid of complains from helgrind
 * 
 * @{
 *
 *----------------------------------------------------------------------------*/
#pragma once

#include <pthread.h>

#include <dnscore/sys_types.h>
#include <dnscore/allocator.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct threaded_sll_cw threaded_sll_cw;

struct threaded_sll_cw_node
{
    struct threaded_sll_cw_node *next;
    void* data;
};

typedef struct threaded_sll_cw_node threaded_sll_cw_node;

/* NOTE: The algorithm does not need these to be volatile */

struct threaded_sll_cw
{
    struct threaded_sll_cw_node *first;
    struct threaded_sll_cw_node *last;
    
    allocator_s *allocator;
    
    pthread_mutex_t mutex;
    pthread_cond_t  cond_read;
    pthread_cond_t  cond_write;

    u32             max_size;
    u32             size;
};

#define THREADED_SLL_CW_NULL {NULL, NULL,&libc_allocator,PTHREAD_MUTEX_INITIALIZER,PTHREAD_COND_INITIALIZER,PTHREAD_COND_INITIALIZER,4096,0}

void  threaded_sll_cw_init(threaded_sll_cw *queue, int max_size);
void  threaded_sll_cw_finalize(threaded_sll_cw *queue);
void  threaded_sll_cw_enqueue(threaded_sll_cw *queue,void* constant_pointer);
bool  threaded_sll_cw_try_enqueue(threaded_sll_cw *queue,void* constant_pointer);
void* threaded_sll_cw_peek(threaded_sll_cw *queue);
void* threaded_sll_cw_try_peek(threaded_sll_cw *queue);
void* threaded_sll_cw_dequeue(threaded_sll_cw *queue);
void* threaded_sll_cw_try_dequeue(threaded_sll_cw *queue);
u32   threaded_sll_cw_dequeue_set(threaded_sll_cw *queue, void** array, u32 array_size);
void  threaded_sll_cw_wait_empty(threaded_sll_cw *queue);
int   threaded_sll_cw_size(threaded_sll_cw *queue);
int   threaded_sll_cw_room(threaded_sll_cw *queue);

/*
 * The queue will block (write) if bigger than this.
 * Note that if the key is already bigger it will blocked (write) until
 * the content is emptied by the readers.
 */

ya_result threaded_sll_cw_set_maxsize(threaded_sll_cw *queue, int max_size);

#ifdef	__cplusplus
}
#endif

/** @} */

/*----------------------------------------------------------------------------*/

