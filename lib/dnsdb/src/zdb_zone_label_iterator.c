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

/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Functions used to iterate through the labels of a zone
 *
 * @{
 */

#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>

#include "dnscore/logger.h"
#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_zone_label_iterator.h"
#include "dnsdb/zdb_rr_label.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

/**
 * @brief Initializes a zone label iterator
 *
 * Initializes a zone label iterator (iterates zdb_rr_label)
 *
 * @param[in] zone The zone to explore
 * @param[in] iter a pointer to the iterator to initialize
 *
 */


#define ZLI_DEBUG 0

void
zdb_zone_label_iterator_init(zdb_zone_label_iterator* iter, const zdb_zone* zone)
{
#if DEBUG
    memset(iter, 0xff, sizeof(zdb_zone_label_iterator));
#endif
    
    s32 top;
    
    if(*zone->origin != '\0')
    {    
        top = dnsname_to_dnslabel_stack(zone->origin, iter->dnslabels);

        // sets an empty iterator for the labels in the path of the zone

        for(s32 i = 0; i < top; i++)
        {
            dictionary_empty_iterator_init(&iter->stack[i]);
        }

        dictionary_iterator_init(&zone->apex->sub, &iter->stack[top]);

        iter->top = top;
        iter->current_label = zone->apex;
        iter->zone = zone;
#if ZDB_ZONE_LABEL_ITERATOR_CAN_SKIP_CHILDREN
        iter->prev_top = -1; // prev_top is used to skip children of the current label
#endif
        iter->current_top = top;
    }
    else
    {
        dictionary_iterator_init(&zone->apex->sub, &iter->stack[0]);
        iter->dnslabels[0] = zone->apex->name;
        iter->top = 0;
        iter->current_label = zone->apex;
        iter->zone = zone;
#if ZDB_ZONE_LABEL_ITERATOR_CAN_SKIP_CHILDREN
        iter->prev_top = -1; // prev_top is used to skip children of the current label
#endif
        iter->current_top = 0;
    }
}

void
zdb_zone_label_iterator_init_from(zdb_zone_label_iterator* iter, const zdb_zone* zone, const u8 *from_name)
{
#if DEBUG
    memset(iter, 0xff, sizeof(zdb_zone_label_iterator));
#endif
    
    dnslabel_stack from_name_stack;
            
    if(from_name == NULL) // from not set : initialise from the start
    {
        zdb_zone_label_iterator_init(iter, zone);
        return;
    }
    
    s32 top = dnsname_to_dnslabel_stack(zone->origin, iter->dnslabels);
    s32 real_top = dnsname_to_dnslabel_stack(from_name, from_name_stack);
    
    if(real_top <= top)
    {
        zdb_zone_label_iterator_init(iter, zone);
        return;
    }
    
    for(s32 i = 0; i < top; i++)
    {
        if(!dnslabel_equals(iter->dnslabels[i], from_name_stack[i]))
        {
            zdb_zone_label_iterator_init(iter, zone);
            return;
        }
    }
    
    // sets an empty iterator for the labels in the path of the zone

    for(s32 i = 0; i < top; i++)
    {
        dictionary_empty_iterator_init(&iter->stack[i]);
    }
    
    // while there are labels in from_name
    //   find if the next level exists
    //     if yes, initialise the iterator from it
    //  initialise an iterator for the next level
    
    // note: real_top > top
    
    zdb_rr_label *parent = zone->apex;
    
    do
    {
        zdb_rr_label *child = zdb_rr_label_find_child(parent, from_name_stack[top + 1]);
        
        if(child == NULL)
        {
            break;
        }
        
        iter->dnslabels[top + 1] = child->name;
        /*
        hashcode key = hash_dnslabel(child->name);
        dictionary_iterator_init_from(&parent->sub, &iter->stack[top], key);
        */
        dictionary_iterator_init_from(&parent->sub, &iter->stack[top], child->name);
        parent = child;
    }
    while( ++top < real_top);
    
    dictionary_iterator_init(&parent->sub, &iter->stack[top]);
    
    iter->top = top;
    iter->current_label = parent;
    iter->zone = zone;
#if ZDB_ZONE_LABEL_ITERATOR_CAN_SKIP_CHILDREN
    iter->prev_top = top - 1; // prev_top is used to skip children of the current label
#endif
    iter->current_top = top;
}

/**
 * @brief Checks if there is still data available from an iterator
 *
 * Checks if there is still data available from an iterator
 *
 * @param[in] iter a pointer to the iterator
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
    u32 ret = dnslabel_stack_to_cstr(iter->dnslabels, iter->top, buffer256);
    
#if ZLI_DEBUG
    zdb_rr_label *label = iter->current_label;
    if(label != NULL)
    {
        log_debug1("zli: %{dnsname}+%{dnslabel} nextname=%s (%u)", iter->zone->origin, label->name, buffer256, ret);
    }
    else
    {
        log_debug1("zli: %{dnsname}%NULL nextname=%s (%u)", iter->zone->origin, buffer256, ret);
    }
    u32 real_len = strlen(buffer256);
    if(real_len != ret)
    {
        log_err("zli: %d != %d", real_len, ret);
    }
#endif
    
    return ret;
}

u32
zdb_zone_label_iterator_nextname(zdb_zone_label_iterator* iter, u8* buffer256)
{ /* TOP-DOWN stack */
    u32 ret = dnslabel_stack_to_dnsname(iter->dnslabels, iter->top, buffer256);
    
    if(*iter->zone->origin == 0)
    {
        --ret;
    }
    
#if ZLI_DEBUG
    zdb_rr_label *label = iter->current_label;
    if(label != NULL)
    {
        log_debug1("zli: %{dnsname}+%{dnslabel} nextname=%{dnsname} (%u)", iter->zone->origin, label->name, buffer256, ret);
    }
    else
    {
        log_debug1("zli: %{dnsname}%NULL nextname=%{dnsname} (%u)", iter->zone->origin, buffer256, ret);
    }
    u32 real_len = dnsname_len(buffer256);
    if(real_len != ret)
    {
        log_err("zli: %d != %d", real_len, ret);
    }
#endif
    
    return ret;
}

/**
 * @brief Returns the next data available from an iterator
 *
 * Returns the next data available from an iterator
 *
 * @param[in] iter a pointer to the iterator
 *
 * @return a pointer to the next label
 *
 */

zdb_rr_label*
zdb_zone_label_iterator_next(zdb_zone_label_iterator* iter)
{
    zdb_rr_label* ret = iter->current_label;
#if ZDB_ZONE_LABEL_ITERATOR_CAN_SKIP_CHILDREN
    iter->prev_top = iter->current_top;
#endif

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
        
#if DEBUG
        iter->dnslabels[iter->top] = (u8*)(intptr)0xfefefefefefefefeLL;
        memset(&iter->stack[iter->top], 0xfe, sizeof(iter->stack[iter->top]));
#endif

        iter->top--;
    }
    
    return ret;
}

#if ZDB_ZONE_LABEL_ITERATOR_CAN_SKIP_CHILDREN

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

#endif

/** @} */
