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

/** @defgroup dnsdbcollection Collections used by the database
 *  @ingroup dnsdb
 *  @brief Balanced Tree structures and functions for the database
 *
 *  Definitions of the Balanced Tree structures and functions for the database.
 *
 *  btree is the chosen balanced tree for the database.
 *  The current choice right now is AVL Tree.
 *  It could be set to something else. ie: Red-Black Tree.
 *
 * @{
 */

#ifndef _btree_H
#define	_btree_H

#include <dnsdb/avl.h>

#ifdef	__cplusplus
extern "C"
{
#endif

/*
 * The iterator returns the nodes sorted with their hash value.
 *
 * This macro is true for AVL
 */

#define BTREE_ITERATION_SORTED 1

typedef avl_node btree_node;
typedef avl_tree btree;
typedef avl_iterator btree_iterator;



#define btree_init avl_init
#define btree_find avl_find
#define btree_findp avl_findp
#define btree_insert avl_insert
#define btree_delete avl_delete
#define btree_destroy avl_destroy
#define btree_callback_and_destroy avl_callback_and_destroy

#define btree_iterator_init avl_iterator_init
#define btree_iterator_init_from avl_iterator_init_from_after
#define btree_iterator_hasnext avl_iterator_hasnext
#define btree_iterator_next avl_iterator_next
#define btree_iterator_next_node avl_iterator_next_node

#define btree_notempty(tree) ((tree)!=NULL)
#define btree_isempty(tree) ((tree)==NULL)

#ifdef	__cplusplus
}
#endif

#endif	/* _btree_H */

/** @} */
