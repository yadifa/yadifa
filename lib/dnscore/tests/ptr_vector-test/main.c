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

#include "yatest.h"
#include <dnscore/dnscore.h>
#include <dnscore/ptr_vector.h>

static ptr_vector_t v;
static uint64_t     rnd;

static void         init()
{
    dnscore_init();
    yatest_random_init(&rnd);
}

static void finalise() { dnscore_finalize(); }

// 3 sizes of arrays:

#define T_SIZE 6        // tiny
#define V_SIZE 256      // medium
#define S_SIZE 0x100000 // big

static void setup_ptr_vector(ptr_vector_t *v)
{
    ptr_vector_init(v);
    for(int i = 0; i < V_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(v, (void *)(intptr_t)r);
    }
}

static int ptr_vector_init_test()
{
    init();
    ptr_vector_init(&v);
    for(int i = 0; i < V_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }
    if(ptr_vector_size(&v) != V_SIZE)
    {
        yatest_err("ptr_vector_size didn't return %i", V_SIZE);
        return 1;
    }
    finalise();
    return 0;
}

static int ptr_vector_init_ex_test()
{
    init();
    ptr_vector_init_ex(&v, V_SIZE);
    for(int i = 0; i < V_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }
    if(ptr_vector_size(&v) != V_SIZE)
    {
        yatest_err("ptr_vector_size didn't return %i", V_SIZE);
        return 1;
    }
    finalise();
    return 0;
}

static int ptr_vector_init_ex_0_test()
{
    init();
    ptr_vector_init_ex(&v, 0);
    for(int i = 0; i < V_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }
    if(ptr_vector_size(&v) != V_SIZE)
    {
        yatest_err("ptr_vector_size didn't return %i", V_SIZE);
        return 1;
    }
    finalise();
    return 0;
}

static int ptr_vector_init_copy_test()
{
    init();
    ptr_vector_t v2;
    setup_ptr_vector(&v2);
    ptr_vector_init_copy(&v, &v2, V_SIZE);
    for(int i = 0; i < V_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }
    if(ptr_vector_size(&v) != V_SIZE * 2)
    {
        yatest_err("ptr_vector_size didn't return %i", V_SIZE);
        return 1;
    }
    finalise();
    return 0;
}

static int ptr_vector_init_copy_append_test()
{
    init();
    ptr_vector_t v2;
    uint64_t     to_append = yatest_random_next64(&rnd);
    setup_ptr_vector(&v2);
    ptr_vector_init_copy_append(&v, &v2, (void *)(intptr_t)to_append);
    for(int i = 0; i < V_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }
    if(ptr_vector_size(&v) != V_SIZE * 2 + 1)
    {
        yatest_err("ptr_vector_size didn't return %i", V_SIZE);
        return 1;
    }
    finalise();
    return 0;
}

static int ptr_vector_init_copy_append_array_test()
{
    init();
    ptr_vector_t v2;
    ptr_vector_t v3;
    setup_ptr_vector(&v2);
    setup_ptr_vector(&v3);
    ptr_vector_init_copy_append_array(&v, &v2, v3.data, v3.offset + 1);
    for(int i = 0; i < V_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }
    if(ptr_vector_size(&v) != V_SIZE * 3)
    {
        yatest_err("ptr_vector_size expected to return %i, got %i instead", V_SIZE * 3, ptr_vector_size(&v));
        return 1;
    }
    finalise();
    return 0;
}

static void ptr_vector_callback_and_destroy_test_callback_function(void *ptr) { (void)ptr; }

static int  ptr_vector_callback_and_destroy_test()
{
    init();
    ptr_vector_init_empty(&v);
    for(int i = 0; i < V_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }

    ptr_vector_callback_and_finalise(&v, ptr_vector_callback_and_destroy_test_callback_function);

    if(ptr_vector_size(&v) != 0)
    {
        yatest_err("ptr_vector_size expected to return %i, got %i instead", 0, ptr_vector_size(&v));
        return 1;
    }
    finalise();
    return 0;
}

static int ptr_vector_ensures_test()
{
    init();
    ptr_vector_t v2 = PTR_VECTOR_EMPTY;
    ptr_vector_ensures(&v2, V_SIZE / 2);
    if(ptr_vector_capacity(&v2) < V_SIZE / 2)
    {
        yatest_err("ptr_vector_ensures (initial) failed");
        return 1;
    }
    ptr_vector_ensures(&v2, V_SIZE);
    if(ptr_vector_capacity(&v2) < V_SIZE)
    {
        yatest_err("ptr_vector_ensures (secondary) failed");
        return 1;
    }
    finalise();
    return 0;
}

static int ptr_vector_remove_from_test()
{
    init();
    ptr_vector_init(&v);
    for(int i = 0; i < V_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }
    ptr_vector_remove_from(&v, 16);
    if(ptr_vector_size(&v) != 16)
    {
        yatest_err("ptr_vector_size didn't return %i", 16);
        return 1;
    }
    finalise();
    return 0;
}

static int ptr_vector_remove_after_test()
{
    init();
    ptr_vector_init(&v);
    for(int i = 0; i < V_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }
    ptr_vector_remove_after(&v, 15);
    if(ptr_vector_size(&v) != 16)
    {
        yatest_err("ptr_vector_size didn't return %i", 16);
        return 1;
    }
    finalise();
    return 0;
}

static int ptr_vector_append_array_test()
{
    init();
    ptr_vector_t v2;
    setup_ptr_vector(&v2);
    ptr_vector_init_empty(&v);
    ptr_vector_append_array(&v, v2.data, v2.offset + 1);
    if(ptr_vector_size(&v) != v2.offset + 1)
    {
        yatest_err("ptr_vector_size didn't return %i", v2.offset + 1);
        return 1;
    }
    finalise();
    return 0;
}

static int ptr_vector_append_vector_test()
{
    init();
    ptr_vector_t v2;
    setup_ptr_vector(&v2);
    ptr_vector_init_empty(&v);
    ptr_vector_append_vector(&v, &v2);
    if(ptr_vector_size(&v) != v2.offset + 1)
    {
        yatest_err("ptr_vector_size didn't return %i", v2.offset + 1);
        return 1;
    }
    finalise();
    return 0;
}

static int ptr_vector_append_restrict_size_test()
{
    init();
    uint64_t r = yatest_random_next64(&rnd);
    ptr_vector_init_empty(&v);
    ptr_vector_append_restrict_size(&v, (void *)(intptr_t)r, PTR_VECTOR_DEFAULT_SIZE / 2);
    if(ptr_vector_capacity(&v) > PTR_VECTOR_DEFAULT_SIZE / 2)
    {
        yatest_err("ptr_vector_capacity = %i > %i", ptr_vector_size(&v), PTR_VECTOR_DEFAULT_SIZE / 2);
        return 1;
    }
    for(int i = 0; i < PTR_VECTOR_DEFAULT_SIZE; ++i)
    {
        ptr_vector_append_restrict_size(&v, (void *)(intptr_t)r, PTR_VECTOR_DEFAULT_SIZE);
    }
    if(ptr_vector_capacity(&v) >= PTR_VECTOR_DEFAULT_SIZE * 2)
    {
        yatest_err("ptr_vector_capacity = %i >= %i", ptr_vector_size(&v), PTR_VECTOR_DEFAULT_SIZE * 2);
        return 1;
    }
    finalise();
    return 0;
}

static int ptr_vector_pop_test()
{
    init();
    ptr_vector_init_empty(&v);
    for(int i = 0; i < V_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }
    for(int i = 0; i < V_SIZE; ++i)
    {
        void *p = ptr_vector_pop(&v);
        if(p == NULL)
        {
            yatest_err("ptr_vector_pop unexpectedly returned 0");
            return 1;
        }
    }

    void *p = ptr_vector_pop(&v);
    if(p != NULL)
    {
        yatest_err("ptr_vector_pop expected to returned 0");
        return 1;
    }

    finalise();
    return 0;
}

static int ptr_vector_comparator_r_callback(const void *a, const void *b, void *data)
{
    (void)data;
    intptr_t ia = (intptr_t)a;
    intptr_t ib = (intptr_t)b;
    if(ia < ib)
    {
        return -1;
    }
    else if(ia > ib)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

static int ptr_vector_comparator_callback(const void *a, const void *b)
{
    intptr_t ia = (intptr_t)a;
    intptr_t ib = (intptr_t)b;
    if(ia < ib)
    {
        return -1;
    }
    else if(ia > ib)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

static int ptr_vector_heapsort_r_test()
{
    init();
    for(int s = 2; s <= S_SIZE; s *= 2)
    {
        ptr_vector_init_ex(&v, s);
        for(int i = 0; i < s; ++i)
        {
            uint64_t r = yatest_random_next64(&rnd);
            ptr_vector_append(&v, (void *)(intptr_t)r);
        }

        if((intptr_t)ptr_vector_get(&v, 0) < (intptr_t)ptr_vector_get(&v, 1))
        {
            void *tmp = ptr_vector_get(&v, 0);
            ptr_vector_set(&v, 0, ptr_vector_get(&v, 1));
            ptr_vector_set(&v, 1, tmp);
        }

        int64_t t;
        yatest_timer_start(&t);
        ptr_vector_heapsort_r(&v, ptr_vector_comparator_r_callback, NULL);
        yatest_timer_stop(&t);
        yatest_log("operation for %i items took %f seconds", s, yatest_timer_seconds(&t));
        for(int i = 1; i < s; ++i)
        {
            intptr_t ia = (intptr_t)ptr_vector_get(&v, i - 1);
            intptr_t ib = (intptr_t)ptr_vector_get(&v, i);
            if(ia > ib)
            {
                yatest_err("error at positions %i and %i", i - 1, i);
                return 1;
            }
        }
        ptr_vector_finalise(&v);

        if(yatest_timer_seconds(&t) > 1.0)
        {
            break;
        }
    }
    finalise();
    return 0;
}

static int ptr_vector_heapsort_r2_test()
{
    init();
    ptr_vector_init_ex(&v, 2);
    for(int i = 0; i < 2; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }

    if((intptr_t)ptr_vector_get(&v, 0) < (intptr_t)ptr_vector_get(&v, 1))
    {
        void *tmp = ptr_vector_get(&v, 0);
        ptr_vector_set(&v, 0, ptr_vector_get(&v, 1));
        ptr_vector_set(&v, 1, tmp);
    }

    int64_t t;
    yatest_timer_start(&t);
    ptr_vector_heapsort_r(&v, ptr_vector_comparator_r_callback, NULL);
    yatest_timer_stop(&t);
    yatest_log("operation took %f seconds", yatest_timer_seconds(&t));
    for(int i = 1; i < 2; ++i)
    {
        intptr_t ia = (intptr_t)ptr_vector_get(&v, i - 1);
        intptr_t ib = (intptr_t)ptr_vector_get(&v, i);
        if(ia > ib)
        {
            yatest_err("error at positions %i and %i", i - 1, i);
            return 1;
        }
    }
    finalise();
    return 0;
}

static int ptr_vector_insertionsort_r_test()
{
    init();
    for(int s = 2; s <= S_SIZE; s *= 2)
    {
        ptr_vector_init_ex(&v, s);
        for(int i = 0; i < s; ++i)
        {
            uint64_t r = yatest_random_next64(&rnd);
            ptr_vector_append(&v, (void *)(intptr_t)r);
        }

        if((intptr_t)ptr_vector_get(&v, 0) < (intptr_t)ptr_vector_get(&v, 1))
        {
            void *tmp = ptr_vector_get(&v, 0);
            ptr_vector_set(&v, 0, ptr_vector_get(&v, 1));
            ptr_vector_set(&v, 1, tmp);
        }

        int64_t t;
        yatest_timer_start(&t);
        ptr_vector_insertionsort_r(&v, ptr_vector_comparator_r_callback, NULL);
        yatest_timer_stop(&t);
        yatest_log("operation for %i items took %f seconds", s, yatest_timer_seconds(&t));
        for(int i = 1; i < s; ++i)
        {
            intptr_t ia = (intptr_t)ptr_vector_get(&v, i - 1);
            intptr_t ib = (intptr_t)ptr_vector_get(&v, i);
            if(ia > ib)
            {
                yatest_err("error at positions %i and %i", i - 1, i);
                return 1;
            }
        }
        ptr_vector_finalise(&v);

        if(yatest_timer_seconds(&t) > 1.0)
        {
            break;
        }
    }
    finalise();
    return 0;
}

static int ptr_vector_bubblesort_r_test()
{
    init();
    for(int s = 2; s <= S_SIZE; s *= 2)
    {
        ptr_vector_init_ex(&v, s);
        for(int i = 0; i < s; ++i)
        {
            uint64_t r = yatest_random_next64(&rnd);
            ptr_vector_append(&v, (void *)(intptr_t)r);
        }

        if((intptr_t)ptr_vector_get(&v, 0) < (intptr_t)ptr_vector_get(&v, 1))
        {
            void *tmp = ptr_vector_get(&v, 0);
            ptr_vector_set(&v, 0, ptr_vector_get(&v, 1));
            ptr_vector_set(&v, 1, tmp);
        }

        int64_t t;
        yatest_timer_start(&t);
        ptr_vector_bubblesort_r(&v, ptr_vector_comparator_r_callback, NULL);
        yatest_timer_stop(&t);
        yatest_log("operation for %i items took %f seconds", s, yatest_timer_seconds(&t));
        for(int i = 1; i < s; ++i)
        {
            intptr_t ia = (intptr_t)ptr_vector_get(&v, i - 1);
            intptr_t ib = (intptr_t)ptr_vector_get(&v, i);
            if(ia > ib)
            {
                yatest_err("error at positions %i and %i", i - 1, i);
                return 1;
            }
        }
        ptr_vector_finalise(&v);

        if(yatest_timer_seconds(&t) > 1.0)
        {
            break;
        }
    }
    finalise();
    return 0;
}

static int ptr_vector_qsort_r_test()
{
    init();
    for(int s = 2; s <= S_SIZE; s *= 2)
    {
        ptr_vector_init_ex(&v, s);
        for(int i = 0; i < s; ++i)
        {
            uint64_t r = yatest_random_next64(&rnd);
            ptr_vector_append(&v, (void *)(intptr_t)r);
        }

        if((intptr_t)ptr_vector_get(&v, 0) < (intptr_t)ptr_vector_get(&v, 1))
        {
            void *tmp = ptr_vector_get(&v, 0);
            ptr_vector_set(&v, 0, ptr_vector_get(&v, 1));
            ptr_vector_set(&v, 1, tmp);
        }

        int64_t t;
        yatest_timer_start(&t);
        ptr_vector_qsort_r(&v, ptr_vector_comparator_r_callback, NULL);
        yatest_timer_stop(&t);
        yatest_log("operation for %i items took %f seconds", s, yatest_timer_seconds(&t));
        for(int i = 1; i < s; ++i)
        {
            intptr_t ia = (intptr_t)ptr_vector_get(&v, i - 1);
            intptr_t ib = (intptr_t)ptr_vector_get(&v, i);
            if(ia > ib)
            {
                yatest_err("error at positions %i and %i", i - 1, i);
                return 1;
            }
        }
        ptr_vector_finalise(&v);

        if(yatest_timer_seconds(&t) > 1.0)
        {
            break;
        }
    }
    finalise();
    return 0;
}

static int ptr_vector_qsort_test()
{
    init();
    for(int s = 2; s <= S_SIZE; s *= 2)
    {
        ptr_vector_init_ex(&v, s);
        for(int i = 0; i < s; ++i)
        {
            uint64_t r = yatest_random_next64(&rnd);
            ptr_vector_append(&v, (void *)(intptr_t)r);
        }
        int64_t t;
        yatest_timer_start(&t);
        ptr_vector_qsort(&v, ptr_vector_comparator_callback);
        yatest_timer_stop(&t);
        yatest_log("operation for %i items took %f seconds", s, yatest_timer_seconds(&t));
        for(int i = 1; i < s; ++i)
        {
            intptr_t ia = (intptr_t)ptr_vector_get(&v, i - 1);
            intptr_t ib = (intptr_t)ptr_vector_get(&v, i);
            if(ia > ib)
            {
                yatest_err("error at positions %i and %i", i - 1, i);
                return 1;
            }
        }
        ptr_vector_finalise(&v);

        if(yatest_timer_seconds(&t) > 1.0)
        {
            break;
        }
    }
    finalise();
    return 0;
}

static int ptr_vector_linear_search_test()
{
    init();
    ptr_vector_init_ex(&v, S_SIZE);
    for(int i = 0; i < S_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }
    ptr_vector_qsort(&v, ptr_vector_comparator_callback);
    int   index = S_SIZE / 2;
    void *target;

    target = ptr_vector_get(&v, index);
    if((ptr_vector_get(&v, index - 1) == target) || (ptr_vector_get(&v, index + 1) == target))
    {
        yatest_err("test setup failed");
    }

    int64_t t;
    yatest_timer_start(&t);
    void *found = ptr_vector_linear_search(&v, target, ptr_vector_comparator_callback);
    yatest_timer_stop(&t);
    yatest_log("operation for %i items took %f seconds", S_SIZE, yatest_timer_seconds(&t));

    if(found != target)
    {
        yatest_err("ptr_vector_linear_search failed: expected %p, got %p", target, found);
        return 1;
    }

    finalise();
    return 0;
}

static int ptr_vector_search_ptr_index_test()
{
    init();
    ptr_vector_init_ex(&v, S_SIZE);
    for(int i = 0; i < S_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }
    ptr_vector_qsort(&v, ptr_vector_comparator_callback);
    int32_t index = S_SIZE / 2;
    void   *target;

    target = ptr_vector_get(&v, index);
    if((ptr_vector_get(&v, index - 1) == target) || (ptr_vector_get(&v, index + 1) == target))
    {
        yatest_err("test setup failed");
    }

    int64_t t;
    yatest_timer_start(&t);
    int32_t found_index = ptr_vector_search_ptr_index(&v, target);
    yatest_timer_stop(&t);
    yatest_log("operation for %i items took %f seconds", S_SIZE, yatest_timer_seconds(&t));

    if(found_index != index)
    {
        yatest_err("ptr_vector_linear_search failed: expected %i, got %i", index, found_index);
        return 1;
    }

    finalise();
    return 0;
}

static int ptr_vector_index_of_test()
{
    init();
    ptr_vector_init_ex(&v, S_SIZE);
    for(int i = 0; i < S_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }
    ptr_vector_qsort(&v, ptr_vector_comparator_callback);
    int32_t index = S_SIZE / 2;
    void   *target;

    target = ptr_vector_get(&v, index);
    if((ptr_vector_get(&v, index - 1) == target) || (ptr_vector_get(&v, index + 1) == target))
    {
        yatest_err("test setup failed");
    }

    int64_t t;
    yatest_timer_start(&t);
    int32_t found_index = ptr_vector_index_of(&v, target, ptr_vector_comparator_callback);
    yatest_timer_stop(&t);
    yatest_log("operation for %i items took %f seconds", S_SIZE, yatest_timer_seconds(&t));

    if(found_index != index)
    {
        yatest_err("ptr_vector_linear_search failed: expected %i, got %i", index, found_index);
        return 1;
    }

    finalise();
    return 0;
}

static int ptr_vector_search_test()
{
    init();
    ptr_vector_init_ex(&v, S_SIZE);
    for(int i = 0; i < S_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }
    ptr_vector_qsort(&v, ptr_vector_comparator_callback);
    int32_t index = S_SIZE / 2;
    void   *target;

    target = ptr_vector_get(&v, index);
    if((ptr_vector_get(&v, index - 1) == target) || (ptr_vector_get(&v, index + 1) == target))
    {
        yatest_err("test setup failed");
    }

    int64_t t;
    yatest_timer_start(&t);
    void *found = ptr_vector_search(&v, target, ptr_vector_comparator_callback);
    yatest_timer_stop(&t);
    yatest_log("operation for %i items took %f seconds", S_SIZE, yatest_timer_seconds(&t));

    if(found != target)
    {
        yatest_err("ptr_vector_linear_search failed: expected %p, got %p", target, found);
        return 1;
    }

    finalise();
    return 0;
}

static int ptr_vector_search_index_test()
{
    init();
    ptr_vector_init_ex(&v, S_SIZE);
    for(int i = 0; i < S_SIZE; ++i)
    {
        uint64_t r = yatest_random_next64(&rnd);
        ptr_vector_append(&v, (void *)(intptr_t)r);
    }
    ptr_vector_qsort(&v, ptr_vector_comparator_callback);
    int32_t index = S_SIZE / 2;
    void   *target;

    target = ptr_vector_get(&v, index);
    if((ptr_vector_get(&v, index - 1) == target) || (ptr_vector_get(&v, index + 1) == target))
    {
        yatest_err("test setup failed");
    }

    int64_t t;
    yatest_timer_start(&t);
    int32_t found_index = ptr_vector_search_index(&v, target, ptr_vector_comparator_callback);
    yatest_timer_stop(&t);
    yatest_log("operation for %i items took %f seconds", S_SIZE, yatest_timer_seconds(&t));

    if(found_index != index)
    {
        yatest_err("ptr_vector_linear_search failed: expected %p, got %p", index, found_index);
        return 1;
    }

    finalise();
    return 0;
}

static int ptr_vector_insert_at_test()
{
    init();
    ptr_vector_init_ex(&v, T_SIZE);
    for(int i = 0; i < T_SIZE / 2; ++i)
    {
        ptr_vector_append(&v, (void *)(intptr_t)i);
    }
    for(int i = T_SIZE / 2; i < T_SIZE; ++i)
    {
        ptr_vector_append(&v, (void *)(intptr_t)(i + 1));
    }

    if(ptr_vector_size(&v) != T_SIZE)
    {
        yatest_err("size is wrong: expected %i, got %i (init)", T_SIZE, ptr_vector_size(&v));
        return 1;
    }

    int64_t t;
    yatest_timer_start(&t);
    ptr_vector_insert_at(&v, T_SIZE / 2, (void *)(intptr_t)(T_SIZE / 2));
    yatest_timer_stop(&t);
    yatest_log("operation for %i items took %f seconds", T_SIZE, yatest_timer_seconds(&t));

    if(ptr_vector_size(&v) != T_SIZE + 1)
    {
        yatest_err("size is wrong: expected %i, got %i", T_SIZE + 1, ptr_vector_size(&v));
        return 1;
    }

    for(int i = 0; i < T_SIZE + 1; ++i)
    {
        intptr_t j = (intptr_t)ptr_vector_get(&v, i);
        if(j != i)
        {
            yatest_err("error at position %i: expected %i, got %i", i, i, j);
            return 1;
        }
    }

    yatest_timer_start(&t);
    ptr_vector_insert_at(&v, T_SIZE + 2, (void *)(intptr_t)(T_SIZE + 2));
    yatest_timer_stop(&t);
    yatest_log("operation for %i items took %f seconds", T_SIZE, yatest_timer_seconds(&t));

    {
        intptr_t j = (intptr_t)ptr_vector_get(&v, T_SIZE + 1);
        if(j != 0)
        {
            yatest_err("error at position %i: expected %i, got %i", T_SIZE + 1, 0, j);
            return 1;
        }
    }

    {
        intptr_t j = (intptr_t)ptr_vector_get(&v, T_SIZE + 2);
        if(j != T_SIZE + 2)
        {
            yatest_err("error at position %i: expected %i, got %i", T_SIZE + 2, T_SIZE + 2, j);
            return 1;
        }
    }

    finalise();
    return 0;
}

static int ptr_vector_insert_array_at_test()
{
    init();
    ptr_vector_init_ex(&v, T_SIZE);
    ptr_vector_t v2;
    ptr_vector_init_empty(&v2);
    for(int i = 0; i < T_SIZE / 2; ++i)
    {
        ptr_vector_append(&v2, (void *)(intptr_t)(i + T_SIZE / 2));
    }
    ptr_vector_t v3;
    ptr_vector_init_empty(&v3);
    for(int i = 0; i < T_SIZE / 2; ++i)
    {
        ptr_vector_append(&v3, (void *)(intptr_t)(i + 4 * (T_SIZE / 2)));
    }

    for(int i = 0; i < T_SIZE / 2; ++i)
    {
        ptr_vector_append(&v, (void *)(intptr_t)i);
    }
    for(int i = T_SIZE / 2; i < T_SIZE; ++i)
    {
        ptr_vector_append(&v, (void *)(intptr_t)(i + T_SIZE / 2));
    }

    if(ptr_vector_size(&v) != T_SIZE)
    {
        yatest_err("size is wrong: expected %i, got %i (init)", T_SIZE, ptr_vector_size(&v));
        return 1;
    }

    int64_t t;
    yatest_timer_start(&t);
    ptr_vector_insert_array_at(&v, T_SIZE / 2, v2.data, v2.offset + 1);
    yatest_timer_stop(&t);
    yatest_log("operation for %i items took %f seconds", T_SIZE, yatest_timer_seconds(&t));

    if(ptr_vector_size(&v) != T_SIZE + T_SIZE / 2)
    {
        yatest_err("size is wrong: expected %i, got %i (mid)", T_SIZE + T_SIZE / 2, ptr_vector_size(&v));
        return 1;
    }

    for(int i = 0; i < T_SIZE + T_SIZE / 2; ++i)
    {
        intptr_t j = (intptr_t)ptr_vector_get(&v, i);
        if(j != i)
        {
            yatest_err("error at position %i: expected %i, got %i", i, i, j);
            return 1;
        }
    }

    yatest_timer_start(&t);
    ptr_vector_insert_array_at(&v, 4 * T_SIZE / 2, v3.data, v3.offset + 1);
    yatest_timer_stop(&t);
    yatest_log("operation for %i items took %f seconds", T_SIZE, yatest_timer_seconds(&t));

    if(ptr_vector_size(&v) != 5 * T_SIZE / 2)
    {
        yatest_err("size is wrong: expected %i, got %i (mid)", T_SIZE + T_SIZE / 2, ptr_vector_size(&v));
        return 1;
    }

    {
        for(int i = 3 * T_SIZE / 2; i < 4 * T_SIZE / 2; ++i)
        {
            intptr_t j = (intptr_t)ptr_vector_get(&v, i);
            if(j != 0)
            {
                yatest_err("error at position %i: expected %i, got %i", i, 0, j);
                return 1;
            }
        }
    }

    {
        for(int i = 4 * T_SIZE / 2; i < 5 * T_SIZE / 2; ++i)
        {
            intptr_t j = (intptr_t)ptr_vector_get(&v, i);
            if(j != i)
            {
                yatest_err("error at position %i: expected %i, got %i", i, i, j);
                return 1;
            }
        }
    }

    finalise();
    return 0;
}

static int ptr_vector_remove_at_test()
{
    init();
    ptr_vector_init_ex(&v, T_SIZE);
    for(int i = 0; i < T_SIZE / 2; ++i)
    {
        ptr_vector_append(&v, (void *)(intptr_t)i);
    }
    for(int i = T_SIZE / 2; i < T_SIZE; ++i)
    {
        ptr_vector_append(&v, (void *)(intptr_t)(i - 1));
    }

    if(ptr_vector_size(&v) != T_SIZE)
    {
        yatest_err("size is wrong: expected %i, got %i (init)", T_SIZE, ptr_vector_size(&v));
        return 1;
    }

    int64_t t;
    yatest_timer_start(&t);
    ptr_vector_remove_at(&v, T_SIZE / 2);
    yatest_timer_stop(&t);
    yatest_log("operation for %i items took %f seconds", T_SIZE, yatest_timer_seconds(&t));

    if(ptr_vector_size(&v) != T_SIZE - 1)
    {
        yatest_err("size is wrong: expected %i, got %i", T_SIZE + 1, ptr_vector_size(&v));
        return 1;
    }

    for(int i = 0; i < T_SIZE - 1; ++i)
    {
        intptr_t j = (intptr_t)ptr_vector_get(&v, i);
        if(j != i)
        {
            yatest_err("error at position %i: expected %i, got %i", i, i, j);
            return 1;
        }
    }

    if(ptr_vector_remove_at(&v, T_SIZE) != NULL)
    {
        yatest_err("error at position %i: expected NULL", T_SIZE);
        return 1;
    }

    finalise();
    return 0;
}

static int ptr_vector_compare_pointers_callback_test()
{
    for(intptr_t i = 0; i < 10; ++i)
    {
        for(intptr_t j = 0; j < 10; ++j)
        {
            int d = ptr_vector_compare_pointers_callback((void *)i, (void *)j);
            if(d != (i - j))
            {
                yatest_err("ptr_vector_compare_pointers_callback didn't return i - j");
                return 1;
            }
        }
    }
    return 0;
}

static void ptr_vector_new_instance_test_free(void *ptr) { free(ptr); }

static int  ptr_vector_new_instance_test()
{
    init();
    ptr_vector_t *v_empty = ptr_vector_new_instance_empty();
    ptr_vector_t *v_default = ptr_vector_new_instance();
    ptr_vector_t *v_ex = ptr_vector_new_instance_ex(12345);
    if(ptr_vector_capacity(v_empty) != 0)
    {
        yatest_err("v_empty is wrong");
        return 1;
    }
    if(ptr_vector_capacity(v_default) != PTR_VECTOR_DEFAULT_SIZE)
    {
        yatest_err("v_default is wrong");
        return 1;
    }
    if(ptr_vector_capacity(v_ex) != 12345)
    {
        yatest_err("v_ex is wrong");
        return 1;
    }
    ptr_vector_delete(v_ex);
    ptr_vector_delete(v_default);
    ptr_vector_callback_and_delete(v_empty, ptr_vector_new_instance_test_free);
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(ptr_vector_init_test)
YATEST(ptr_vector_init_ex_test)
YATEST(ptr_vector_init_ex_0_test)
YATEST(ptr_vector_init_copy_test)
YATEST(ptr_vector_init_copy_append_test)
YATEST(ptr_vector_init_copy_append_array_test)
YATEST(ptr_vector_callback_and_destroy_test)
YATEST(ptr_vector_ensures_test)
YATEST(ptr_vector_remove_from_test)
YATEST(ptr_vector_remove_after_test)
YATEST(ptr_vector_append_array_test)
YATEST(ptr_vector_append_vector_test)
YATEST(ptr_vector_append_restrict_size_test)
YATEST(ptr_vector_pop_test)
YATEST(ptr_vector_heapsort_r_test)
YATEST(ptr_vector_heapsort_r2_test)
YATEST(ptr_vector_insertionsort_r_test)
YATEST(ptr_vector_bubblesort_r_test)
YATEST(ptr_vector_qsort_r_test)
YATEST(ptr_vector_qsort_test)
YATEST(ptr_vector_linear_search_test)
YATEST(ptr_vector_search_ptr_index_test)
YATEST(ptr_vector_index_of_test)
YATEST(ptr_vector_search_test)
YATEST(ptr_vector_search_index_test)
YATEST(ptr_vector_insert_at_test)
YATEST(ptr_vector_insert_array_at_test)
YATEST(ptr_vector_remove_at_test)
YATEST(ptr_vector_compare_pointers_callback_test)
YATEST(ptr_vector_new_instance_test)
YATEST_TABLE_END
