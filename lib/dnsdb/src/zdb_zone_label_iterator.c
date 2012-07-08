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
/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Functions used to iterate through the labels of a zone
 *
 * @{
 */

#include <stdio.h>
#include <stdlib.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_zone_label_iterator.h"

/**
 * @brief Initializes a zone label iterator
 *
 * Initializes a zone label iterator (iterates zdb_rr_label)
 *
 * @param[in] zone The zone to explore
 * @param[in] iter a poitner to the iterator to initialize
 *
 */

void
zdb_zone_label_iterator_init(const zdb_zone* zone, zdb_zone_label_iterator* iter)
{
    s32 top = dnsname_to_dnslabel_stack(zone->origin, iter->dnslabels);

    if(top > 0)
    {
        dictionary empty;
        dictionary_init(&empty);

        s32 i;
        for(i = 0; i < top; i++)
        {
            dictionary_iterator_init(&empty, &iter->stack[i]);
        }
    }

    dictionary_iterator_init(&zone->apex->sub, &iter->stack[top]);

    iter->top = top;
    iter->current_label = zone->apex;
    iter->zone = zone;
    iter->prev_top = -1;
    iter->current_top = top;
}

/**
 * @brief Checks if there is still data available from an iterator
 *
 * Checks if there is still data available from an iterator
 *
 * @param[in] iter a poitner to the iterator
 *
 * @return TRUE if data is available, FALSE otherwise.
 *
 */

bool
zdb_zone_label_iterator_hasnext(zdb_zone_label_iterator* iter)
{
    return iter->current_label != NULL;
}

/**
 * @brief Copies the full name of the next label returned by the "next" call.
 *
 * Copies the full name of the next label returned by the "next" call.
 *
 * @param[in] iter a pointer to the iterator
 * @param[in] buffer256 a pointer to a buffer that will hold the full dns name
 *
 * @return the size of the dns name
 *
 */

u32
zdb_zone_label_iterator_nextname_to_cstr(zdb_zone_label_iterator* iter, char* buffer256)
{
    return dnslabel_stack_to_cstr(iter->dnslabels, iter->top, buffer256);
}

u32
zdb_zone_label_iterator_nextname(zdb_zone_label_iterator* iter, u8* buffer256)
{ /* TOP-DOWN stack */
    return dnslabel_stack_to_dnsname(iter->dnslabels, iter->top, buffer256);
}

/**
 * @brief Returns the next data available from an iterator
 *
 * Returns the next data available from an iterator
 *
 * @param[in] iter a pointer to the iterator
 *
 * @return a pointer the the next label
 *
 */

zdb_rr_label*
zdb_zone_label_iterator_next(zdb_zone_label_iterator* iter)
{
    zdb_rr_label* ret = iter->current_label;
    iter->prev_top = iter->current_top;

    iter->current_label = NULL;

    while(iter->top >= 0)
    {
        if(dictionary_iterator_hasnext(&iter->stack[iter->top]))
        {
            iter->current_label = *(zdb_rr_label**)dictionary_iterator_next(&iter->stack[iter->top]);
            iter->current_top = iter->top + 1;

            dictionary_iterator_init(&iter->current_label->sub, &iter->stack[++iter->top]);
            iter->dnslabels[iter->top] = iter->current_label->name;

            break;
        }

        iter->top--;
    }

    return ret;
}

/**
 * @brief Skips the children
 *
 * Skips the children
 *
 * @return
 *
 */

void
zdb_zone_label_skip_children(zdb_zone_label_iterator* iter)
{
    /*
     * If we are on a brother or on a parent there is nothing to do.
     */

    if(iter->prev_top >= iter->current_top)
    {
        return;
    }

    iter->current_label = NULL;

    iter->top = iter->current_top - 2;

    while(iter->top >= 0)
    {
        if(dictionary_iterator_hasnext(&iter->stack[iter->top]))
        {
            iter->current_label = *(zdb_rr_label**)dictionary_iterator_next(&iter->stack[iter->top]);
            iter->current_top = iter->top + 1;

            dictionary_iterator_init(&iter->current_label->sub, &iter->stack[++iter->top]);
            iter->dnslabels[iter->top] = iter->current_label->name;

            break;
        }

        iter->top--;
    }
}

/** @} */
