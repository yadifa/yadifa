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
/** @defgroup collections Generic collections functions
 *  @ingroup dnscore
 *  @brief A dynamic-sized array of pointers
 *
 *  A dynamic-sized array of pointers
 *
 *  Used for resource record canonization and such.
 *
 * @{
 */

#ifndef _PTR_VECTOR_H
#define	_PTR_VECTOR_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <dnscore/sys_types.h>

#define PTR_VECTOR_TAG 0x524f544345565252 /** "RRVECTOR" */

#define PTR_VECTOR_DEFAULT_SIZE  32

#define EMPTY_PTR_VECTOR {NULL, -1, 0}
    
typedef struct ptr_vector ptr_vector;


struct ptr_vector
{
    void** data;
    s32 offset;
    s32 size;
};

/**
 * Initialises a vector structure with a size of PTR_VECTOR_DEFAULT_SIZE entries
 * 
 * @param v a pointer to the ptr_vector structure to initialise
 */

void  ptr_vector_init(ptr_vector* v);

/**
 * Frees the memory used by a vector structure (not the vector structure itself)
 * 
 * @param v a pointer to the ptr_vector structure
 */

void  ptr_vector_destroy(ptr_vector* v);

/**
 * Empties the vector (does not release memory)
 * 
 * @param v a pointer to the ptr_vector structure
 */

void  ptr_vector_empties(ptr_vector* v);

/**
 * Changes the capacity of a vector to the specified size
 * The new size MUST be enough to keep the current content
 * of the vector.  Failing to do so will most likely result
 * into a crash.
 * 
 * @param v a pointer to the ptr_vector structure
 * @param newsize the new size of the vector
 */

void  ptr_vector_resize(ptr_vector*v, s32 newsize);

/**
 * Ensures the vector has enough capacity to accommodate a
 * specified number of items
 * 
 * @param v a pointer to the ptr_vector structure
 * @param reqsize the minimum size of the vector
 */

void  ptr_vector_ensures(ptr_vector*v, s32 reqsize);

/**
 * Resizes the capacity so it can at most contain its
 * current size.
 * 
 * @param v a pointer to the ptr_vector structure
 */

void  ptr_vector_shrink(ptr_vector*v);

/**
 * Appends the item (pointer) to the vector
 * 
 * @param v     a pointer to the ptr_vector structure
 * @param data  a pointer to the item
 */

void  ptr_vector_append(ptr_vector* v, void* data);

/**
 * Removes an item from the back of the vector and returns its reference
 * 
 * @param v     a pointer to the ptr_vector structure
 * @return      a pointer to the removed item
 */

void* ptr_vector_pop(ptr_vector* v);

typedef int ptr_vector_qsort_callback(const void*, const void*);

/**
 * Sort the content of the vector using the compare callback
 * 
 * @param v       a pointer to the ptr_vector structure
 * @param compare comparison callback
 */

void ptr_vector_qsort(ptr_vector* v, ptr_vector_qsort_callback compare);

typedef void void_function_voidp(void*);

/**
 * Empties the vector releasing the item memory first
 * 
 * @param v       a pointer to the ptr_vector structure
 * @param free_memory item free callback
 */

void ptr_vector_free_empties(ptr_vector* v, void_function_voidp free_memory);

/*
 * First argument is the key, second one is the item to match with the key
 *
 */

typedef int ptr_vector_search_callback(const void*, const void*);

/**
 * Look sequentially in the vector for an item using a key and a comparison function
 * The callback only needs to tell equal (0) or not equal (anything else)
 * 
 * @param v         a pointer to the ptr_vector structure
 * @param what      the key
 * @param compare   the comparison function
 * 
 * @return the first matching item or NULL if none has been found
 */

void* ptr_vector_linear_search(ptr_vector* v, const void* what, ptr_vector_search_callback compare);

/**
 * Look in the vector for an item using a key and a comparison function
 * The callback needs to tell equal (0) smaller (<0) or bigger (>0)
 * 
 * @param v         a pointer to the ptr_vector structure
 * @param what      the key
 * @param compare   the comparison function
 * 
 * @return the first matching item or NULL if none has been found
 */

void* ptr_vector_search(ptr_vector* v, const void* what,ptr_vector_search_callback compare);

#define ptr_vector_get(_v_,_idx_) (_v_)->data[(_idx_)]

#define ptr_vector_set(_v_,_idx_,_val_) (_v_)->data[(_idx_)]=(_val_)

#ifdef	__cplusplus
}
#endif

#endif	/* _RR_VECTOR_H */

/** @} */
