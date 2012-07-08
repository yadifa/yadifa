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
* DOCUMENTATION */
/** @defgroup threading Threading, pools, queues, ...
 *  @ingroup dnscore
 *  @brief 
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _THREADED_NB_RINGBUFFER_H
#define	_THREADED_NB_RINGBUFFER_H

#include <pthread.h>
#include "sys_types.h"

#if HAS_ATOMIC_FEATURES != 0

#ifdef	__cplusplus
extern "C" {
#endif

#define THREADED_NBRB_NULL {0,0,0,0}

typedef struct threaded_nbrb threaded_nbrb;

struct threaded_nbrb_node;

struct threaded_nbrb
{
    void** buffer;                  /* 64 bits chunks (need the aligment) */
#if __SIZEOF_POINTER__ == 8
    /* already aligned */
#elif __SIZEOF_POINTER__ == 4
    u32 padding_00;
#else
#error "Size of pointer is not supported"
#endif

    volatile s32 empty_slots;
    u32 padding_01;

    volatile s32 filled_slots;
    u32 padding_02;

    volatile s32 read_offset;
    u32 padding_03;

    volatile s32 write_offset;
    u32 padding_04;
    
    s32 size_mask;
    u32 padding_05;
};

void  threaded_nbrb_init(threaded_nbrb* queue, int log2_size);
void  threaded_nbrb_finalize(threaded_nbrb* queue);
void  threaded_nbrb_enqueue(threaded_nbrb* queue,void* constant_pointer);
bool  threaded_nbrb_try_enqueue(threaded_nbrb* queue,void* constant_pointer);
void* threaded_nbrb_peek(threaded_nbrb* queue);
void* threaded_nbrb_try_peek(threaded_nbrb* queue);
void* threaded_nbrb_dequeue(threaded_nbrb* queue);
void* threaded_nbrb_try_dequeue(threaded_nbrb *queue);
u32   threaded_nbrb_dequeue_set(threaded_nbrb* queue, void** array, u32 array_size);
void  threaded_nbrb_wait_empty(threaded_nbrb* queue);
int   threaded_nbrb_size(threaded_nbrb* queue);

/*
 * The queue will block (write) if bigger than this.
 * Note that if the key is already bigger it will blocked (write) until
 * the content is emptied by the readers.
 */

ya_result threaded_nbrb_set_maxsize(threaded_nbrb *queue, int max_size);

#ifdef	__cplusplus
}
#endif

#endif

#endif	/* _THREADED_QUEUE_H */
/** @} */

/*----------------------------------------------------------------------------*/

