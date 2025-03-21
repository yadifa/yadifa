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
 * @brief A node-based single linked list where insertions are always sorted
 *
 * A node-based single linked list where insertions are always sorted by priority.
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

/*    ------------------------------------------------------------
 *
 *      INCLUDES
 */

#include <dnscore/sys_types.h>

/*    ------------------------------------------------------------
 *
 *      STRUCTS
 */

#define BPQNODE_TAG 0x45444f4e515042

struct bpqueue_node_s
{
    struct bpqueue_node_s *next;
    void                  *data;
    uint32_t               priority;
};

typedef struct bpqueue_node_s bpqueue_node_t;

struct bpqueue_s
{
    bpqueue_node_t *first;
    bpqueue_node_t *last;
    uint32_t        size;
};

typedef struct bpqueue_s bpqueue_t;

#define EMPTY_BPQUEUE {NULL, NULL, 0}

/**
 * Initialises a list.
 *
 * @param list
 */

void bpqueue_init(bpqueue_t *list);
/**
 * Adds an item at the head of the list.
 *
 * @param list
 * @param data
 */

void bpqueue_enqueue(bpqueue_t *list, void *data, uint32_t priority);

/**
 * Remove the first item from the list.
 * Deletes the node but not the data.
 * The data is returned.
 *
 * @param list
 * @return the data or NULL if the list is empty
 */

void *bpqueue_dequeue(bpqueue_t *list);

/**
 * Remove all items from the list.
 * Deletes the nodes but not the data.
 *
 * @param list
 */

void bpqueue_clear(bpqueue_t *list);

/**
 *
 * Returns the size of the list
 *
 * @param list
 * @return the size of the list
 */

static inline uint32_t bpqueue_size(const bpqueue_t *list) { return list->size; }
