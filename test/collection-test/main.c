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

/** @defgroup test
 *  @ingroup test
 *  @brief skeleton file
 * 
 * skeleton test program, will not be installed with a "make install"
 * 
 * To create a new test based on the skeleton:
 * 
 * _ copy the folder
 * _ replace "skeleton" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 *
 */

#include <dnscore/dnscore.h>

#include <dnscore/ptr_vector.h>
#include <dnscore/ptr_set.h>
#include <dnscore/u32_set.h>
#include <dnscore/u64_set.h>
#include <dnscore/format.h>

#define PRIME_ABOVE_2M 2000003

typedef void ptr_vector_fill_cb(ptr_vector *, int);

static int intptr_compare(const void *a, const void *b)
{
    intptr va = (intptr)a;
    intptr vb = (intptr)b;
    return va - vb;
}

static int intptr_compare3(const void *a, const void *b, void *ctx)
{
    (void)ctx;
    intptr va = (intptr)a;
    intptr vb = (intptr)b;
    return va - vb;
}

static void ptr_vector_print(ptr_vector *tv)
{
    int s = MIN(ptr_vector_size(tv), 32);
    for(int i = 0; i < s; ++i)
    {
        intptr v = (intptr)ptr_vector_get(tv, i);
        format("%6lli ", v);
    }
}

static void ptr_vector_fill_linear(ptr_vector *tv, int count)
{
    assert(ptr_vector_size(tv) <= count);
    ptr_vector_clear(tv);
    for(int i = 0; i < count; ++i)
    {
        ptr_vector_append(tv, (void*)(intptr)i);
    }
}

static void ptr_vector_fill_linear_reverse(ptr_vector *tv, int count)
{
    ptr_vector_fill_linear(tv, count);
    ptr_vector_reverse(tv);
}

static void ptr_vector_fill_alternated(ptr_vector *tv, int count)
{
    assert(ptr_vector_size(tv) <= count);
    ptr_vector_clear(tv);
    for(int i = 0; i < count; ++i)
    {
        intptr v = PRIME_ABOVE_2M;
        v *= i;
        v %= 1000000;
        ptr_vector_append(tv, (void*)v);
    }
}

static void ptr_vector_fill_alternated_reverse(ptr_vector *tv, int count)
{
    ptr_vector_fill_alternated(tv, count);
    ptr_vector_reverse(tv);
}

static void ptr_vector_sorted_test(ptr_vector *tv)
{
    bool fail = FALSE;
    
    for(int i = 1; i <= ptr_vector_last_index(tv); ++i)
    {
        intptr u = (intptr)ptr_vector_get(tv, i - 1);
        intptr v = (intptr)ptr_vector_get(tv, i);
        
        if(u > v)
        {
            formatln("error at positions %i and %i: %lli > %lli", i - 1, i, u, v);
            fail = TRUE;
        }
    }
    
    if(fail)
    {
        ptr_vector_print(tv);
        flushout();
        abort();
    }
}

static ptr_vector_fill_cb *ptr_vector_filler_table[4] =
{
    ptr_vector_fill_linear,
    ptr_vector_fill_linear_reverse,
    ptr_vector_fill_alternated,
    ptr_vector_fill_alternated_reverse,
};

static char *ptr_vector_filler_table_name[4] =
{
    "ptr_vector_fill_linear",
    "ptr_vector_fill_linear_reverse",
    "ptr_vector_fill_alternated",
    "ptr_vector_fill_alternated_reverse",
};

typedef int ptr_sort3_callback(const void *a, const void *b, void *data);
void ptr_sort_heapsort(void **base, size_t n, ptr_sort3_callback *cmp, void *data);
void ptr_sort3_bubble(void **base, size_t n, ptr_sort3_callback *cmp, void *data);
void ptr_sort_insertion(void **base, size_t n, ptr_sort3_callback *cmp, void *data);

static void ptr_vector_sort_performance()
{
    ptr_vector tv;
    ptr_vector_init_ex(&tv, 500000);
    s64 d;
    
    static int ranges[4][3] =
    {
        {0,128,1},
        {1024,128*1024,1009},
        {128*1024, 500000,10009 * 5}
    };
    
    for(int r = 0; r < 3; ++r)
    {
        for(int size = ranges[r][0]; size < ranges[r][1]; size += ranges[r][2])
        {
            for(size_t filler = 0; filler < sizeof(ptr_vector_filler_table) / sizeof(void*); ++filler)
            {
                format("perf: size: %i, filler: %s", size, ptr_vector_filler_table_name[filler]);    
                // fill the vector with values
                
                ptr_vector_filler_table[filler](&tv, size);
                ptr_vector_qsort(&tv, intptr_compare);
                
                ptr_vector_filler_table[filler](&tv, size);
                d = timeus();
                ptr_vector_qsort(&tv, intptr_compare);
                d = timeus() - d;
                format(", qsort: %llius", d);
                
                s64 q0 = d;
                
                ptr_vector_filler_table[filler](&tv, size);
                d = timeus();
                ptr_vector_qsort_r(&tv, intptr_compare3, NULL);
                d = timeus() - d;
                format(", qsort_r: %llius", d);
                
                s64 q1 = d;
                
#if DONT_DO_THIS_ITS_TOO_SLOW
                ptr_vector_filler_table[filler](&tv, size);
                d = timeus();
                ptr_sort_heapsort(tv.data, size, intptr_compare3, NULL);
                d = timeus() - d;
                ptr_vector_sorted_test(&tv);
                format(", RAW-heapsort: %llius", d);
                
                ptr_vector_filler_table[filler](&tv, size);
                d = timeus();
                ptr_vector_insertionsort_r(&tv, intptr_compare3, NULL);
                d = timeus() - d;
                ptr_vector_sorted_test(&tv);
                format(", insertion: %llius", d);
                
                d = timeus();
                ptr_sort3_bubble(tv.data, size, intptr_compare3, NULL);
                d = timeus() - d;
                format(", RAW-bubblesort: %llius", d);
#endif
                if(q0 == 0) { q0 = 1; }
                if(q1 == 0) { q1 = 1; }
                
                double pc = q0;
                pc *= 100.0;
                pc /= q1;
                pc -= 100.0;
                formatln("%s (%8.3f)", (q1 <= q0) ? " WIN":" LOSE", pc);
            }
        }
    }
    
    ptr_vector_destroy(&tv);
}

static void ptr_vector_qsort_test()
{
    ptr_vector tv;
    ptr_vector_init_ex(&tv, 500000);
    s64 d;
    
    static int ranges[3][3] =
    {
        {0,128,1},
        {1024,128*1024,1009},
        {128*1024, 500000,10009}
    };
    
    for(int r = 0; r < 3; ++r)
    {
        for(int size = ranges[r][0]; size < ranges[r][1]; size += ranges[r][2])
        {
            for(size_t filler = 0; filler < sizeof(ptr_vector_filler_table) / sizeof(void*); ++filler)
            {
                format("q: size: %i, filler: %s", size, ptr_vector_filler_table_name[filler]);

                // fill the vector with values

                ptr_vector_filler_table[filler](&tv, size);

                // sort the values

                d = timeus();
                ptr_vector_qsort(&tv, intptr_compare);
                d = timeus() - d;

                formatln(", time: %llius", d);

                // test the values are properly sorted

                ptr_vector_sorted_test(&tv);

                flushout();
            }
        }
    }
    
    ptr_vector_destroy(&tv);
}

static void ptr_vector_qsort_r_test()
{
    ptr_vector tv;
    ptr_vector_init_ex(&tv, 500000);
    s64 d;
    
    static int ranges[3][3] =
    {
        //{341261, 341261+1, 1},
        {0,128,1},
        {1024,128*1024,1009},
        {128*1024, 500000,10009*7}
    };
    
    for(int r = 0; r < 3; ++r)
    {
        for(int size = ranges[r][0]; size < ranges[r][1]; size += ranges[r][2])
        {
            for(size_t filler = 0; filler < sizeof(ptr_vector_filler_table) / sizeof(void*); ++filler)
            {
                format("q_r: size: %i, filler: %s", size, ptr_vector_filler_table_name[filler]);

                // fill the vector with values

                ptr_vector_filler_table[filler](&tv, size);

                // sort the values

                d = timeus();
                ptr_vector_qsort_r(&tv, intptr_compare3, NULL);
                d = timeus() - d;

                formatln(", time: %llius", d);

                // test the values are properly sorted

                ptr_vector_sorted_test(&tv);

                flushout();
            }
        }
    }
    
    ptr_vector_destroy(&tv);
}

static void ptr_vector_insertionsort_r_test()
{
    ptr_vector tv;
    ptr_vector_init_ex(&tv, 128);
    s64 d;
    
    static int ranges[1][3] =
    {
        {0,128,1},
        /*{1024,128*1024,1009},
        {128*1024, 500000,10009}*/
    };
    
    for(int r = 0; r < 1; ++r)
    {
        for(int size = ranges[r][0]; size < ranges[r][1]; size += ranges[r][2])
        {
            for(size_t filler = 0; filler < sizeof(ptr_vector_filler_table) / sizeof(void*); ++filler)
            {
                format("i_r: size: %i, filler: %s", size, ptr_vector_filler_table_name[filler]);

                // fill the vector with values

                ptr_vector_filler_table[filler](&tv, size);

                // sort the values

                d = timeus();
                ptr_vector_insertionsort_r(&tv, intptr_compare3, NULL);
                d = timeus() - d;

                formatln(", time: %llius", d);

                // test the values are properly sorted

                ptr_vector_sorted_test(&tv);

                flushout();
            }
        }
    }
    
    ptr_vector_destroy(&tv);
}

static void u32_set_test()
{
    u32_set set = U32_SET_EMPTY;
    u32_set_destroy(&set);
}

static void u64_set_test()
{
    u64_set set = U64_SET_EMPTY;
    u64_set_destroy(&set);
}

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    /* initializes the core library */
    dnscore_init();

    // sort with context given to the comparator
    
    ptr_vector_qsort_r_test();

    // standard sort
    
    ptr_vector_qsort_test();
    
    // insertion sort
    
    ptr_vector_insertionsort_r_test();

    // performance test
    
    ptr_vector_sort_performance();
    
    u32_set_test();
    
    u64_set_test();
    
    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
