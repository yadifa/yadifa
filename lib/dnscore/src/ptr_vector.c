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

#include "dnscore/ptr_vector.h"

/**
 * Initialises a vector structure with a size of PTR_VECTOR_DEFAULT_SIZE entries
 * 
 * @param v a pointer to the ptr_vector structure to initialise
 */

void
ptr_vector_init(ptr_vector* v)
{
    v->size = PTR_VECTOR_DEFAULT_SIZE;
    MALLOC_OR_DIE(void**, v->data, v->size * sizeof (void*), PTR_VECTOR_TAG);
    v->offset = -1;
}

/**
 * Initialises a vector structure with a size of PTR_VECTOR_DEFAULT_SIZE entries
 * 
 * @param v a pointer to the ptr_vector structure to initialise
 * @param initial_capacity the size to allocate to start with
 */

void
ptr_vector_init_ex(ptr_vector* v, s32 initial_capacity)
{
    v->size = initial_capacity;
    MALLOC_OR_DIE(void**, v->data, v->size * sizeof (void*), PTR_VECTOR_TAG);
    v->offset = -1;
}

/**
 * Frees the memory used by a vector structure (not the vector structure itself)
 * 
 * @param v a pointer to the ptr_vector structure
 */

void
ptr_vector_destroy(ptr_vector* v)
{
    v->size = -1;
    v->offset = -1;
    free(v->data);
    v->data = NULL;
}

/**
 * Empties the vector (does not release memory)
 * 
 * @param v a pointer to the ptr_vector structure
 */

void
ptr_vector_empties(ptr_vector* v)
{
    v->offset = -1;
}

/**
 * Changes the capacity of a vector to the specified size
 * The new size MUST be enough to keep the current content
 * of the vector.  Failing to do so will most likely result
 * into a crash.
 * 
 * @param v a pointer to the ptr_vector structure
 * @param newsize
 */

void
ptr_vector_resize(ptr_vector*v, s32 newsize)
{
    void** data;

    yassert(newsize >= v->offset + 1);

    if(v->offset >= 0)
    {
        /* Only the data up to v->offset (included) is relevant */
        MALLOC_OR_DIE(void**, data, newsize * sizeof (void*), PTR_VECTOR_TAG);
        MEMCOPY(data, v->data, (v->offset + 1) * sizeof (void*));

#ifdef DEBUG
        if(v->data != NULL)
        {
            memset(v->data, 0xff, v->size * sizeof (void*));
        }
#endif
        free(v->data);
    }
    else
    {
        free(v->data);
        MALLOC_OR_DIE(void**, data, newsize * sizeof (void*), PTR_VECTOR_TAG);
    }
    v->data = data;
    v->size = newsize;
}

/**
 * Ensures the vector has enough capacity to accommodate a
 * specified number of items
 * 
 * @param v a pointer to the ptr_vector structure
 * @param reqsize the minimum size of the vector
 */

void
ptr_vector_ensures(ptr_vector*v, s32 reqsize)
{
    if(v->size < reqsize)
    {
        ptr_vector_resize(v, reqsize);
    }
}

/**
 * Resizes the capacity so it can at most contain its
 * current size.
 * 
 * @param v a pointer to the ptr_vector structure
 */

void
ptr_vector_shrink(ptr_vector*v)
{
    if(v->size != (v->offset + 1))
    {
        ptr_vector_resize(v, v->offset + 1);
    }
}

/**
 * Appends the item (pointer) to the vector
 * 
 * @param v     a pointer to the ptr_vector structure
 * @param data  a pointer to the item
 */

void
ptr_vector_append(ptr_vector* v, void* data)
{
    if(v->offset + 1 >= v->size)
    {
        if(v->size == 0)
        {
            v->size = PTR_VECTOR_DEFAULT_SIZE;
        }
        ptr_vector_resize(v, v->size * 2);
    }

    v->data[++v->offset] = data;
}

void
ptr_vector_append_restrict_size(ptr_vector* v, void* data, u32 restrictedlimit)
{
    if(v->offset + 1 >= v->size)
    {
        u32 size = v->size;
        
        // if the size is not 0 prepare to double it, else set it to a reasonable minimum
        if(size != 0)
        {
            size <<= 1;
        }
        else
        {
            size = PTR_VECTOR_DEFAULT_SIZE;
        }
        
        // if the size is bigger than the restriction, set it to the maximum between the restriction and what we actually need
        
        if(size > restrictedlimit)
        {
            size = MAX(restrictedlimit, v->offset + 1);
        }
        
        ptr_vector_resize(v, size);
    }

    v->data[++v->offset] = data;
}

/**
 * Appends the item (pointer) to the vector
 * 
 * @param v     a pointer to the ptr_vector structure
 * @param data  a pointer to the item
 */

void*
ptr_vector_pop(ptr_vector* v)
{
    if(v->offset >= 0)
    {
        return v->data[v->offset--];
    }
    else
    {
        return NULL;
    }
}

/**
 * Sort the content of the vector using the compare callback
 * 
 * @param v       a pointer to the ptr_vector structure
 * @param compare comparison callback
 */

void
ptr_vector_qsort(ptr_vector* v, ptr_vector_qsort_callback compare)
{
    if(v->offset > 0) /* at least 2 items */
    {
        qsort(v->data, v->offset + 1, sizeof (void*), compare);
    }
}

/**
 * Empties the vector releasing the item memory first
 * 
 * @param v       a pointer to the ptr_vector structure
 * @param free_memory item free callback
 */

void
ptr_vector_free_empties(ptr_vector* v, void_function_voidp free_memory)
{
    int n = v->offset;
    int i;
    for(i = 0; i <= n; i++)
    {
        free_memory(v->data[i]);
#ifdef DEBUG
        v->data[i] = NULL;
#endif
    }
    v->offset = -1;
}

/**
 * Look sequentially in the vector for an item using a key and a comparison function
 * 
 * @param v         a pointer to the ptr_vector structure
 * @param what      the key
 * @param compare   the comparison function
 * 
 * @return the first matching item or NULL if none has been found
 */

void*
ptr_vector_linear_search(const ptr_vector* v, const void* what, ptr_vector_search_callback compare)
{
    int last = v->offset;
    int i;

    for(i = 0; i <= last; i++)
    {
        void* data = v->data[i];

        if(compare(what, data) == 0)
        {
            return data;
        }
    }

    return NULL;
}

/**
 * Look sequentially in the vector for an item using a key and a comparison function, returns the index of the first matching item
 * 
 * @param v         a pointer to the ptr_vector structure
 * @param what      the key
 * @param compare   the comparison function
 * 
 * @return the first matching item index or -1 if none has been found
 */

s32
ptr_vector_index_of(const ptr_vector* v, const void* what, ptr_vector_search_callback compare)
{
    s32 last = v->offset;
    s32 i;

    for(i = 0; i <= last; i++)
    {
        void* data = v->data[i];

        if(compare(what, data) == 0)
        {
            return i;
        }
    }

    return -1;
}

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

void*
ptr_vector_search(const ptr_vector* v, const void* what, ptr_vector_search_callback compare)
{
    int first = 0;
    int last = v->offset;

    /*
     * NOTE: for small intervals, a linear search may be faster
     *
     */

    while(first < last)
    {

        int pivot = (last + first) >> 1;

        void *item = v->data[pivot];

        int cmp = compare(what, item);

        if(cmp == 0)
        {
            return item;
        }

        if(cmp < 0)
        {
            last = pivot - 1;
        }
        else
        {
            first = pivot + 1;
        }
    }

    if(first == last)
    {
        void *item = v->data[first];

        if(compare(what, item) == 0)
        {
            return item;
        }
    }

    return NULL;
}

/** @} */
