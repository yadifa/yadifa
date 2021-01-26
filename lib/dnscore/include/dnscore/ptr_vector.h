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

#define PTR_VECTOR_EMPTY {NULL, -1, 0}
#define EMPTY_PTR_VECTOR {NULL, -1, 0} // obsolete

typedef struct ptr_vector ptr_vector;

struct ptr_vector
{
    void** data;
    s32 offset;
    s32 size;
};

static inline void
ptr_vector_init_empty(ptr_vector *v)
{
    v->data = NULL;
    v->offset = -1;
    v->size = 0;
}

/**
 * This tool function wraps an existing (const) array
 * This is meant as a helper to use ptr_vector functions like search & sort to on statically allocated data.
 * 
 * @param v
 * @param data
 * @param size
 */

static inline void
ptr_vector_wrap_const_array(ptr_vector *v, void *data, s32 size)
{
    v->data = data;
    v->offset = size - 1;
    v->size = size;
}

/**
 * Initialises a vector structure with a size of PTR_VECTOR_DEFAULT_SIZE entries
 * 
 * @param v a pointer to the ptr_vector structure to initialise
 */

void ptr_vector_init(ptr_vector *v);

/**
 * Initialises a vector structure with a size of PTR_VECTOR_DEFAULT_SIZE entries
 * 
 * @param v a pointer to the ptr_vector structure to initialise
 * @param initial_capacity the size to allocate to start with
 */

void ptr_vector_init_ex(ptr_vector *v, u32 initial_capacity);

/**
 * Initialises a vector as a copy as another vector.
 * The reserved size is the size of the original plus the extra size.
 * 
 * @param v a pointer to the ptr_vector structure to initialise
 * @param original the vector to copy
 * @param extra_size the amount of reserved slots to allocate
 */

void ptr_vector_init_copy(ptr_vector *v, const ptr_vector *original, u32 extra_size);

/**
 * Initialises a vector as a copy as another vector plus onz item added
 * The reserved size is the size of the original plus one
 * 
 * @param v a pointer to the ptr_vector structure to initialise
 * @param original the vector to copy
 * @param data an item to add
 */

void ptr_vector_init_copy_append(ptr_vector *v, const ptr_vector *original, void *data);

/**
 * Initialises a vector as a copy as another vector plus a few items added
 * The reserved size is the size of the original plus the data size.
 * 
 * @param v a pointer to the ptr_vector structure to initialise
 * @param original the vector to copy
 * @param data is an array of pointers
 * @param data_size the size of the data array
 */

void ptr_vector_init_copy_append_array(ptr_vector *v, const ptr_vector *original, void *data, u32 data_size);

/**
 * Calls the callback on every pointer stored in the vector.
 * Frees the memory used by a vector structure
 * 
 * @param v a pointer to the ptr_vector structure
 */

void ptr_vector_callback_and_destroy(ptr_vector *v, callback_function free_memory);

/**
 * Frees the memory used by a vector structure
 * 
 * @param v a pointer to the ptr_vector structure
 */

void ptr_vector_destroy(ptr_vector *v);

/**
 * Empties the vector (does not release memory)
 * 
 * @param v a pointer to the ptr_vector structure
 */

void ptr_vector_clear(ptr_vector *v);

/**
 * Cuts lose all indexes from the first bad one.
 * Allows to resize down without tripping an assert.
 */

void ptr_vector_remove_from(ptr_vector *v, s32 first_bad_index);

/**
 * Cuts lose all indexes after the last good one.
 * Allows to resize down without tripping an assert.
 */

void ptr_vector_remove_after(ptr_vector *v, s32 last_good_index);

/**
 * Changes the capacity of a vector to the specified size
 * The new size MUST be enough to keep the current content
 * of the vector.  Failing to do so will most likely result
 * into a crash.
 * 
 * @param v a pointer to the ptr_vector structure
 * @param newsize the new size of the vector
 */

void ptr_vector_resize(ptr_vector *v, s32 newsize);

/**
 * Ensures the vector has enough capacity to accommodate a
 * specified number of items
 * 
 * @param v a pointer to the ptr_vector structure
 * @param reqsize the minimum size of the vector
 */

void ptr_vector_ensures(ptr_vector *v, s32 reqsize);

/**
 * Resizes the capacity so it can at most contain its
 * current size.
 * 
 * @param v a pointer to the ptr_vector structure
 */

void ptr_vector_shrink(ptr_vector *v);

/**
 * Appends the item (pointer) to the vector
 * 
 * @param v     a pointer to the ptr_vector structure
 * @param data  a pointer to the item
 */

void ptr_vector_append(ptr_vector *v, void* data);

/**
 * Appends the item (pointer) to the vector
 * 
 * @param v     a pointer to the ptr_vector structure
 * @param datap  a pointer to the items
 * @param data_size the number of items to append
 */

void ptr_vector_append_array(ptr_vector *v, void** datap, u32 data_size);

/**
 * Appends the item (pointer) to the vector
 *
 * @param v     a pointer to the ptr_vector structure
 * @param datap  a pointer to the items
 * @param data_size the number of items to append
 */

void ptr_vector_append_vector(ptr_vector *v, ptr_vector *toappend);


/**
 * Appends the item (pointer) to the vector and try to keep the buffer size at at most
 * restrictedlimit.
 * The goal is to avoid a growth of *2 that would go far beyond the restrictedlimit.
 * The performance is extremely poor when the number of items in the buffer is restrictedlimit or more.
 * 
 * @param v     a pointer to the ptr_vector structure
 * @param data  a pointer to the item
 * @param restrictedlimit a guideline limit on the size of the vector
 */

void ptr_vector_append_restrict_size(ptr_vector *v, void* data, u32 restrictedlimit);

/**
 * Removes an item from the back of the vector and returns its reference
 * 
 * @param v     a pointer to the ptr_vector structure
 * @return      a pointer to the removed item
 */

void* ptr_vector_pop(ptr_vector *v);

/**
 * IMPORTANT NOTE: the callbacks are called with a pointer from the array
 */

typedef int ptr_vector_qsort_callback(const void*, const void*);

/**
 * IMPORTANT NOTE: the callbacks are called with a pointer from the array
 */

typedef int ptr_vector_qsort_r_callback(const void*, const void*, void*);

/**
 * Sort the content of the vector using the compare callback
 * 
 * @param v       a pointer to the ptr_vector structure
 * @param compare comparison callback
 */

void ptr_vector_qsort(ptr_vector *v, ptr_vector_qsort_callback compare);

void ptr_vector_qsort_r(ptr_vector *v, ptr_vector_qsort_r_callback compare, void *compare_context);

void ptr_vector_insertionsort_r(ptr_vector *v, ptr_vector_qsort_r_callback compare, void *compare_context);

/**
 * Empties the vector releasing the item memory first
 * 
 * @param v       a pointer to the ptr_vector structure
 * @param free_memory item free callback
 */

void ptr_vector_callback_and_clear(ptr_vector *v, callback_function free_memory);

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

void* ptr_vector_linear_search(const ptr_vector *v, const void* what, ptr_vector_search_callback compare);

s32 ptr_vector_search_ptr_index(const ptr_vector* v, const void* what);

/**
 * Look sequentially in the vector for an item using a key and a comparison function, returns the index of the first matching item
 * 
 * @param v         a pointer to the ptr_vector structure
 * @param what      the key
 * @param compare   the comparison function
 * 
 * @return the first matching item index or -1 if none has been found
 */

s32 ptr_vector_index_of(const ptr_vector *v, const void* what, ptr_vector_search_callback compare);

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

void* ptr_vector_search(const ptr_vector *v, const void* what,ptr_vector_search_callback compare);

s32 ptr_vector_search_index(const ptr_vector* v, const void* what, ptr_vector_search_callback compare);

/**
 * Returns a pointer to the item at index
 * Does NOT checks for the index range.
 * 
 * @param v
 * @param idx
 * @return a pointer to the item at index
 */

static inline void* ptr_vector_get(const ptr_vector *v, s32 idx)
{
    yassert(idx >= 0 && idx <= v->offset);
    return v->data[idx];
}

/**
 * Returns a pointer to the item at index, in a circular fashion
 * Does NOT checks for the index range.
 * The array must NOT be empty (div0).
 * 
 * @param v
 * @param idx
 * @return a pointer to the item at index
 */

static inline void* ptr_vector_get_mod(const ptr_vector *v, s32 idx)
{
    assert(v->offset >= 0);
    int m = idx % (v->offset + 1);
    if(m < 0) { m += v->offset + 1; } // modulo fix
    return v->data[m];
}

/**
 * Sets the item at index to value.
 * Does NOT checks for the index range.
 * Does NOT grows the vector.
 * 
 * @param v
 * @param idx
 * @param val
 */

static inline void ptr_vector_set(ptr_vector *v, s32 idx, void* val)
{
     v->data[idx] = val;
}

/**
 * Returns a pointer to the last item in the vector or NULL if the vector is empty.
 * 
 * @param v
 * @return a pointer to the last item or NULL if the vector is empty
 */

static inline void *ptr_vector_last(const ptr_vector *v)
{
    void *r = NULL;
    
    if(v->offset >= 0)
    {
        r = v->data[v->offset];
    }
    
    return r;
}

/**
 * Returns the size of the vector
 * 
 * @param pv
 * @param idx
 */

static inline s32 ptr_vector_size(const ptr_vector *v)
{
    return v->offset + 1;
}

/**
 * Returns the index of the last item in the vector
 * This is useful because of an implementaiton detail :
 * obtaining the last index is faster than the size.
 * 
 * @param pv
 * @param idx
 * @param val
 */

static inline s32 ptr_vector_last_index(const ptr_vector *v)
{
    return v->offset;
}

/**
 * Returns the capacity of the vector, that is : the number of items it can hold
 * without growing.
 * 
 * @param pv
 * @param idx
 * @param valp
 * @param n
 */

static inline s32 ptr_vector_capacity(const ptr_vector *v)
{
    return v->size;
}

static inline bool ptr_vector_isempty(const ptr_vector *v)
{
    return (v->offset < 0);
}

/**
 * Swap the last item of the vector with the one at index idx.
 * 
 * One typical use of this function is to remove an item and shrink:
 * If the vector does not need to keep the order of its content, the
 * item that is not wanted is exchanged with the end, then the size is
 * shrank of one slot.
 * 
 * This is certainly much faster than the insert and remove families
 * that can be found here below.
 * 
 * @param pv
 * @param idx
 */

static inline void ptr_vector_end_swap(ptr_vector *pv,s32 idx)
{
    void* tmp = pv->data[idx];
    pv->data[idx] = pv->data[pv->offset];
    pv->data[pv->offset] = tmp;
}


/**
 * Reverse the content 
 * 
 * e.g.
 * 'I' 'I' 'S' 'G'
 * becomes
 * 'G' 'S' 'I' 'I'
 * 
 * @param pv
 */

static inline void ptr_vector_reverse(ptr_vector *v)
{
    void *temp;

    void **start = v->data;
    void **end   = &v->data[v->offset];

    while (start < end)
    {
        temp   = *start;
        *start = *end;
        *end   = temp;

        start++;
        end--;
    }
}


/**
 * Inserts a value at position, pushing items from this position up
 * Potentially very slow.
 * 
 * @param pv
 * @param idx
 */

void ptr_vector_insert_at(ptr_vector *pv, s32 idx, void *val);

/**
 * Inserts multiple values at position, pushing items from this position up
 * Potentially very slow.
 * 
 * @param pv
 * @param idx
 * @param valp  an array of pointers that will be inserted
 * @param n the size of the array of pointers
 */

void ptr_vector_insert_array_at(ptr_vector *pv, s32 idx, void **valp, u32 n);

/**
 * 
 * Removes a value at position, pulling items above this position down
 * Potentially very slow
 * 
 * @param pv
 * @param idx
 * @return the removed value
 */

void* ptr_vector_remove_at(ptr_vector *pv, s32 idx);

typedef int ptr_vector_forall_callback(void*, void*);

static inline void ptr_vector_forall(ptr_vector *pv, ptr_vector_forall_callback callback, void *args)
{
    intptr *limit = (intptr*)&pv->data[pv->offset];
    for(intptr *p = (intptr*)pv->data; p <= limit; ++p)
    {
        if(callback((void*)*p, args) <= 0)
        {
            break;
        }
    }
}

int ptr_vector_compare_pointers_callback(const void *a, const void *b);

#ifdef	__cplusplus
}
#endif

#endif	/* _RR_VECTOR_H */

/** @} */
