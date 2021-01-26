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
 *  @brief "no-wait" stack allocator
 *          meant to be used with the "no-wait" queue
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore-config.h"
#include <stdlib.h>
#include <unistd.h>

#include "dnscore/threaded_nb_mm.h"

#define THRDNBMM_TAG 0x4d4d424e44524854

void
threaded_nb_mm_init(threaded_nb_mm *mm, u32 count, u32 size)
{
    assert(count > 1);
    
    size = (size + sizeof(void*) - 1) & ~(sizeof(void*)-1);
    
    u32 n = count * size;
    
    MALLOC_OR_DIE(u8*,mm->items, n, THRDNBMM_TAG);
    mm->item_count = count;
    mm->item_size = size;
    
    if(n == 0)
    {
        mm->item_head = NULL;
        return;
    }

    const u8 * const limit = &mm->items[n]; // n > 0, (n is unsigned) => limit > &mm->items[0]

    assert(&mm->items[0] < limit); // silents a false positive

    u8** pp;
    for(u8* p = &mm->items[0]; p < limit; p += size) // the loop runs at least once (see line 86)
    {
        pp = (u8**)p;
        *pp = &p[size];
    }
    *pp = NULL; // false "maybe-uninitialized" positive : the loop always runs AT LEAST once (n > 0 => and limit > p)

    mm->item_head = (volatile void**)&mm->items[0];
}

void*
threaded_nb_mm_alloc(threaded_nb_mm *mm)
{
    void *first;

    for(;;)
    {
        first = __sync_fetch_and_add(&mm->item_head, 0);

        if(first != NULL)
        {
            void **firstp = (void**)first;
            void *next = *firstp;

            if(__sync_bool_compare_and_swap(&mm->item_head, first, next))
            {
                break;
            }

            usleep(5);
        }
        else
        {
            return NULL;
        }
    }

    return first;
}

void threaded_nb_mm_free(threaded_nb_mm *mm, void *p)
{
    void **pp = (void**)p;

    for(;;)
    {
        void *first = __sync_fetch_and_add(&mm->item_head, 0);

        *pp = first;

        if(__sync_bool_compare_and_swap(&mm->item_head, first, p))
        {
            break;
        }

        usleep(5);
    }
}

void threaded_nb_mm_finalize(threaded_nb_mm *mm)
{
    free(mm->item_head);
    
    mm->item_head = NULL;
}
