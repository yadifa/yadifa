/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup collections Generic collections functions
 * @ingroup dnscore
 * @brief A node-based single linked list
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * A node-based single linked list

 ------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include "dnscore/list_dl_nodata.h"

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/**
 * Removes the node from the list, the node is not freed
 *
 * @param list
 * @param node
 */

void list_dl_nodata_remove_node(list_dl_nodata_t *list, list_dl_nodata_node_t *node)
{
#if DEBUG
    assert(list->sentinel.next != NULL);
    assert(list->sentinel.prev != NULL);
#endif
    if(node->prev != NULL)
    {
        node->prev->next = node->next;
    }
    if(node->next != NULL)
    {
        node->next->prev = node->prev;
    }
#if DEBUG
    assert(node->next->next != NULL);
    assert(node->next->prev != NULL);
    assert(node->prev->next != NULL);
    assert(node->prev->prev != NULL);
#endif
    node->next = NULL;
    node->prev = NULL;
#if DEBUG
    assert(list->sentinel.next != NULL);
    assert(list->sentinel.prev != NULL);
#endif

    list->size--;
}

void list_dl_nodata_move_node_to_first_position(list_dl_nodata_t *list, list_dl_nodata_node_t *node)
{
    // if it's not already at the first position

    if(list->size > 0)
    {
#if DEBUG
        assert(list->sentinel.next != NULL);
        assert(list->sentinel.prev != NULL);
        assert(node->next != NULL);
        assert(node->prev != NULL);
#endif

        if(list->sentinel.next != node)
        {
            list_dl_nodata_remove_node(list, node);
            list_dl_nodata_insert_node(list, node);
        }

#if DEBUG
        assert(list->sentinel.next != NULL);
        assert(list->sentinel.prev != NULL);
        assert(node->next != NULL);
        assert(node->prev != NULL);
#endif
    }
}
