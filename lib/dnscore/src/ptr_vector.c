/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2017, EURid. All rights reserved.
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

#include "dnscore/dnscore-config.h"
#include "dnscore/ptr_vector.h"

#define PTR_QSORT_SMALL 50
#define PTR_QSORT_DERECURSE_DEPTH 64

/**
 * Initialises a vector structure with a size of PTR_VECTOR_DEFAULT_SIZE entries
 * 
 * @param v a pointer to the ptr_vector structure to initialise
 */

void
ptr_vector_init(ptr_vector* v)
{
    v->size = PTR_VECTOR_DEFAULT_SIZE;
    MALLOC_OR_DIE(void**, v->data, v->size * sizeof(void*), PTR_VECTOR_TAG);
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
    if(initial_capacity > 0)
    {
        MALLOC_OR_DIE(void**, v->data, v->size * sizeof(void*), PTR_VECTOR_TAG);
    }
    else
    {
        v->data = NULL;
    }
    v->offset = -1;
}

/**
 * Initialises a vector as a copy as another vector.
 * The reserved size is the size of the original plus the extra size.
 * 
 * @param v a pointer to the ptr_vector structure to initialise
 * @param original the vector to copy
 * @param extra_size the amount of reserved slots to allocate
 */

void  ptr_vector_init_copy(ptr_vector* v, const ptr_vector* original, u32 extra_size)
{
    ptr_vector_init_ex(v, ptr_vector_size(original) + extra_size);
    if(ptr_vector_last_index(original) >= 0) // => size > 0 => v->data != NULL
    {
        assert(original->data != NULL && v->data != NULL);
        memcpy(v->data, original->data, ptr_vector_size(original) * sizeof(void*));
    }
    v->offset = original->offset;
}

/**
 * Initialises a vector as a copy as another vector plus onz item added
 * The reserved size is the size of the original plus one
 * 
 * @param v a pointer to the ptr_vector structure to initialise
 * @param original the vector to copy
 * @param data an item to add
 */

void  ptr_vector_init_copy_append(ptr_vector* v, const ptr_vector* original, void *data)
{
    ptr_vector_init_ex(v, ptr_vector_size(original) + 1);
    if(ptr_vector_last_index(original) >= 0)
    {
        assert(original->data != NULL && v->data != NULL);
        memcpy(v->data, original->data, ptr_vector_size(original) * sizeof(void*));
    }
    v->offset = original->offset;
    ptr_vector_append(v, data);
}

/**
 * Initialises a vector as a copy as another vector plus a few items added
 * The reserved size is the size of the original plus the data size.
 * 
 * @param v a pointer to the ptr_vector structure to initialise
 * @param original the vector to copy
 * @param data an array of pointers
 * @param data_size the size of the data array
 */

void  ptr_vector_init_copy_append_array(ptr_vector* v, const ptr_vector* original, void *data, u32 data_size)
{
    ptr_vector_init_ex(v, ptr_vector_size(original) + data_size);
    if(ptr_vector_last_index(original) >= 0)
    {
        assert(original->data != NULL && v->data != NULL);
        memcpy(v->data, original->data, ptr_vector_size(original) * sizeof(void*));
    }
    v->offset = original->offset;
    ptr_vector_append_array(v, data, data_size);
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
        MALLOC_OR_DIE(void**, data, newsize * sizeof(void*), PTR_VECTOR_TAG);
        MEMCOPY(data, v->data, (v->offset + 1) * sizeof(void*));
#ifdef DEBUG
        if(v->data != NULL)
        {
            memset(v->data, 0xff, v->size * sizeof(void*));
        }
#endif
        free(v->data);
    }
    else
    {
        free(v->data);
        MALLOC_OR_DIE(void**, data, newsize * sizeof(void*), PTR_VECTOR_TAG);
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

    assert(v->data != NULL);
    v->data[++v->offset] = data;
}

/**
 * Appends the item (pointer) to the vector
 * 
 * @param v     a pointer to the ptr_vector structure
 * @param datap  a pointer to the items
 * @param data_size the number of items to append
 */

void
ptr_vector_append_array(ptr_vector* v, void** datap, u32 data_size)
{
    while(v->offset + data_size >= v->size)
    {
        if(v->size == 0)
        {
            v->size = PTR_VECTOR_DEFAULT_SIZE;
        }
        ptr_vector_resize(v, v->size * 2);
    }
    assert(v->data != NULL);
    assert(datap != NULL);
    memcpy(&v->data[++v->offset], datap, data_size);
}

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
        qsort(v->data, v->offset + 1, sizeof(void*), compare);
    }
}

typedef int ptr_sort3_callback(const void *a, const void *b, void *data);

static int
ptr_sort_heap_parent(int index)
{
    assert(index > 0);
    return (index - 1) / 2;
}

static int
ptr_sort_heap_leftchild(int index)
{
    return (index * 2) + 1;
}

static void
ptr_sort_siftdown(void** base, int from, size_t n, ptr_sort3_callback *cmp, void *data)
{
    int root = from;
    int child;
    while((child = ptr_sort_heap_leftchild(root)) <= n)
    {
        int swp = root;
        if(cmp(base[swp], base[child], data) < 0)
        {
            swp = child;
        }
        if((child + 1 <= n) && (cmp(base[swp], base[child + 1], data) < 0))
        {
            swp = child + 1;
        }
        if(swp == root)
        {
            break;
        }
        
        void **tmp = base[swp];
        base[swp] = base[root];
        base[root] = tmp;
        
        root = swp;
    }
}

static void
ptr_sort_heapify(void **base, size_t n, ptr_sort3_callback *cmp, void *data)
{
    int start = ptr_sort_heap_parent(n - 1);
    
    while(start >= 0)
    {
        ptr_sort_siftdown(base, start, n - 1, cmp, data);
        --start;
    }
}

void
ptr_sort_heapsort(void **base, size_t n, ptr_sort3_callback *cmp, void *data)
{
    if(n > 2)
    {
        ptr_sort_heapify(base, n, cmp, data);

        size_t end = n - 1;
        while(end > 0)
        {
            void **tmp = base[0];
            base[0] = base[end];
            base[end] = tmp;

            --end;

            ptr_sort_siftdown(base, 0, end, cmp, data);
        }
    }
    else if(n == 2)
    {
        if(cmp(base[0], base[1], data) > 0)
        {
            void **tmp = base[0];
            base[0] = base[1];
            base[1] = tmp;
        }
    }
}

void
ptr_sort_insertion(void **base, size_t n, ptr_sort3_callback *cmp, void *data)
{
    for(ssize_t i = 1; i < (ssize_t)n; ++i)
    {
        void **tmp = base[i];
        ssize_t j = i - 1;
        for(; (j >= 0) && (cmp(base[j], tmp, data) > 0); --j)
        {
            base[j + 1] = base[j];
        }
        base[j + 1] = tmp;
    }
}

void
ptr_sort3_bubble(void **base, size_t n, ptr_sort3_callback *cmp, void *data)
{
    for(size_t i = 0; i < n; ++i)
    {
        for(size_t j = i + 1; j < n; ++j)
        {
            if(cmp(base[i], base[j], data) > 0)
            {
                void **tmp = base[j];
                base[j] = base[i];
                base[i] = tmp;
            }
        }
    }
}

struct ptr_sort3_quicksort2_stack_cell
{
    void **base;
    void **limit;
};

static void
ptr_sort3_quicksort2(void **base, size_t n_, ptr_sort3_callback *cmp, void *data)
{
    void **limit = &base[n_];
    ssize_t sp = -1;
    
    struct ptr_sort3_quicksort2_stack_cell stack[PTR_QSORT_DERECURSE_DEPTH];

    //ssize_t msp = -1;
    
    for(;;)
    {
        if(limit - base <= PTR_QSORT_SMALL)
        {
            //ptr_sort_insertion(base, limit - base, cmp, data);
            
            for(void **ip = base + 1; ip < limit; ++ip) //for(ssize_t i = 1; i < (ssize_t)n; ++i)
            {
                void *tmp = *ip;
                void **jp = ip - 1;
                for(; (jp >= base) && (cmp(*jp, tmp, data) > 0); --jp)
                {
                    jp[1] = *jp; // base[j + 1] = base[j];
                }
                jp[1] = tmp; //base[j + 1] = tmp;
            }
            
            if(sp >= 0)
            {
                //if(sp > msp) msp = sp;
                
                base = stack[sp].base;
                limit = stack[sp--].limit;
                continue;
            }
            
            return;
        }
        
        // choose a good enough pivot
        // doing this, start sorting

        void **hip = limit - 1;
        void **lop = base;
        void *pivot;
        
        {
            void **middlep = &base[(limit - base) >> 1];

            // A B C

            // A > B ?

            if(cmp(*lop, *middlep, data) > 0)
            {
                // A > C ?

                if(cmp(*lop, *hip, data) > 0)
                {
                    // A is the highest: ? ? A

                    if(cmp(*middlep, *hip, data) > 0)
                    {
                        // C is the smallest: C B A

                        register void *tmp = *lop;  // t = A
                        *lop = *hip;             // A = C
                        *hip = tmp;                 // C = t
                    }
                    else
                    {
                        // B is the smallest: B C A

                        register void *tmp = *lop;  // t = A
                        *lop = *middlep;         // A = B
                        *middlep = *hip;        // B = C
                        *hip = tmp;                 // C = t
                    }
                }
                else // A <= C
                {
                    // B A C

                    register void *tmp = *lop;      // t = A
                    *lop = *middlep;             // A = B
                    *middlep = tmp;                 // B = t
                }
            } // A <= B
            else
            {
                // B > C ?

                if(cmp(*middlep, *hip, data) > 0)
                {
                    // B is the highest: ? ? B

                    if(cmp(*lop, *hip, data) > 0)
                    {
                        // C is the smallest: C A B

                        register void *tmp = *lop;  // t = A
                        *lop = *hip;             // A = C
                        *hip = *middlep;        // C = B
                        *middlep = tmp;             // B = t
                    }
                    else
                    {
                        // A is the smallest: A C B

                        register void *tmp = *middlep; // t = B
                        *middlep = *hip;            // B = C
                        *hip = tmp;                     // C = t
                    }
                }
                else // B <= C
                {
                    // A B C
                }
            }
            
            pivot = *middlep;
        }

        // 0 is already < pivot
        // last is already > pivot
        // continue from there

        ++lop;
        --hip;
    
        for(;;)
        {
            while(cmp(*lop, pivot, data) < 0) // while smaller than pivot
            {
                ++lop;
            }

            while(cmp(*hip, pivot, data) > 0) // while bigger than pivot
            {
                --hip;
            }
            
            ssize_t d = hip - lop;

            if(d <= 1)
            {
                if(d > 0)
                {
                    register void *tmp = *lop;
                    *lop = *hip;
                    *hip = tmp;
                }
                else
                {
                    hip = lop;
                }
                break;
            }
            
            // exchange two values (<= pivot with >= pivot)

            register void *tmp = *lop;
            *lop = *hip;
            *hip = tmp;
            
            ++lop;
            --hip;
        }
 
        size_t first = hip - base;
        size_t second = limit - hip;
        
        assert(sp < PTR_QSORT_DERECURSE_DEPTH);
        
        if(first > second)
        {
            stack[++sp].base = base;
            stack[sp].limit = hip;
            
            base = hip;
        }
        else
        {
            stack[++sp].base = hip;
            stack[sp].limit = limit;

            limit = hip;
        }
    }
}

void
ptr_vector_qsort_r(ptr_vector *v, ptr_vector_qsort_r_callback compare, void *compare_context)
{
    if(v->offset > 0) /* at least 2 items */
    {
        ptr_sort3_quicksort2(v->data, v->offset + 1, compare, compare_context);
    }
}

void
ptr_vector_insertionsort_r(ptr_vector *v, ptr_vector_qsort_r_callback compare, void *compare_context)
{
    if(v->offset > 0) /* at least 2 items */
    {
        ptr_sort_insertion(v->data, v->offset + 1, compare, compare_context);
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
 * Look in the SORTED vector for an item using a key and a comparison function
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

/**
 * Inserts a value at position, pushing items from this position up
 * Potentially very slow.
 * 
 * @param pv
 * @param idx
 */

void
ptr_vector_insert_at(ptr_vector *pv, s32 idx, void *val)
{
    if(idx <= pv->offset)
    {
        ptr_vector_ensures(pv, pv->offset + 1);
        memmove(&pv->data[idx + 1], &pv->data[idx], (pv->offset - idx) * sizeof(void*));
        pv->data[idx] = val;
    }
    else
    {
        ptr_vector_ensures(pv, idx + 1);
        memset(&pv->data[pv->offset + 1], 0, &pv->data[idx] - &pv->data[pv->offset + 1]);
        pv->data[idx] = val;
        pv->offset = idx;
    }
}

/**
 * Inserts multiple values at position, pushing items from this position up
 * Potentially very slow.
 * 
 * @param pv
 * @param idx
 * @param valp  an array of pointers that will be inserted
 * @param n the size of the array of pointers
 */

void
ptr_vector_insert_array_at(ptr_vector *pv, s32 idx, void **valp, u32 n)
{
    if(idx <= pv->offset)
    {
        ptr_vector_ensures(pv, pv->offset + n);
        memmove(&pv->data[idx + n], &pv->data[idx], (pv->offset - idx + n) * sizeof(void*));
        memcpy(&pv->data[idx], valp, n);
    }
    else
    {
        ptr_vector_ensures(pv, idx + n);
        memset(&pv->data[pv->offset + n], 0, &pv->data[idx] - &pv->data[pv->offset + n]);
        memcpy(&pv->data[idx], valp, n);
        pv->offset = idx + n - 1;
    }
}

/**
 * 
 * Removes a value at position, pulling items above this position down
 * Potentially very slow
 * 
 * @param pv
 * @param idx
 * @return the removed value
 */

void*
ptr_vector_remove_at(ptr_vector *pv, s32 idx)
{
    void *data = pv->data[idx];
    
    if(idx <= pv->offset)
    {
        memmove(&pv->data[idx], &pv->data[idx + 1], (pv->offset - idx) * sizeof(void*));
        --pv->offset;
    }
    
    return data;
}

/** @} */
