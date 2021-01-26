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
#include <dnscore/format.h>
#include <dnscore/shared-heap.h>
#include <dnscore/shared-heap-bytearray-output-stream.h>
#include <dnscore/random.h>
#include <dnscore/process.h>

#define MEMORY_HEAP_SIZE 0x40000000
#define LOOP_COUNT 4096

#define CHILDREN 4

#define FORK_LOOPS 64

#define L1_SIZE 64
#define L1_MASK (L1_SIZE - 1)

#define MEMORY_HEAP_L1_SLOTS (MEMORY_HEAP_SIZE / L1_SIZE)
#define FORK_LOOP_POINTER_ARRAY_SIZE (MEMORY_HEAP_L1_SLOTS * sizeof(void*))
#define FORK_LOOP_COUNT ((((MEMORY_HEAP_SIZE - FORK_LOOP_POINTER_ARRAY_SIZE)) / L1_SIZE) / 2)

static u8 *pointers[LOOP_COUNT];

static void** shared_blocs;

static char one_kb_string[1048] =
    "BEGIN0123456789ABCDEFGHIJKLMNOPQ"
    "RSTUVWXYZabcdefghijklmnopqrstuvw"
    "xyz-j7YZ5sjpN2GPC6B870yZ3HJBIbpk"
    "7v6hmzxHu6eAomRhAb9ikkfxSP1qy7S6"
    "Q6cnNREREssBkSv8hlsEoD0GR0Ip1Tu1"
    "yDQj2LhCpzTJacaJ1qxJ2TjoQxoVi6xe"
    "m7DHzeUvyJca06wmuZOs0oKGQmJFRu9a"
    "uz9f8fT8onBFjgBpBcPmzor7rEpqWrcK"
    "NEtpoueRln6q1qSK6RUkULbYwLShTWgD"
    "bMstlAEVp5EqUIPhlQXSf4eOpImJM4Yt"
    "Lu4LFThG5GU8n9zNTk4WlxcGQCj8Emx1"
    "pqtjHWx55lLiqoJCLgDYPDN99vjB8ukz"
    "XfaXHQIjq44rnxvwpf7cEpMMxHCp7IOO"
    "18nJ42O4CmxTfoKtIkJkuA0NczkitEeF"
    "64Gtj3TubiBLtfRra8zBN8ByqfeeQZG1"
    "XgHaO6s6covHabtb0gzLVV1GenCPvYfp"
    "pivvH8lSWvkeH0xJ5zTjG19Voql883Ii"
    "y28NCXTosBFe81DhvqHQgQ7FU7Njv96o"
    "kiC9Cr8f6CEXp23qe8fL3A4iaEcMPg4f"
    "iRZzUAQtblzzf3nryBpe7gHZiIjE1kUG"
    "eMXJehH0LDFrWR4AmUhZNxR8aK1RSFKZ"
    "Uy32zPIx6TMrTFncSTBgqluwObbFAk6R"
    "1G6ToGPL1X75JNpwXhURN752RNQQUCGo"
    "Vv1SMKBTzpMXH9hfy33wllyiru6ZAciJ"
    "iAa0KmlE9vfqYIv6hA0PyMqIwP7twDRs"
    "kuVI4tbBBY5ScHsa42SnsFpYEXBJuKk1"
    "LFQ4sQED1Stvt5rtf7FDUx316eZ64qVB"
    "1k1sO9YgNzrrv3gpip3vcHr6SWLybVMa"
    "yw047f0YZhjfNXg2YOXPJaNmXvKaUiOe"
    "SyeINNqCIQuDzCUYeLscEEWaoyx5NAyt"
    "mj9hcK4v3S4zLpB3fs1xa5icmV9uz2SW"
    "Uk75WhbSnQ3iW8kMcP1TYz9yDIufAz6m"
    "THE-END";

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    /* initializes the core library */
    
    ya_result ret;
    
    dnscore_init();
    
    if(FAIL(ret = shared_heap_init()))
    {
        formatln("shared_heap_init() failed: %r", ret);
        return 1;
    }
    
    if(FAIL(ret = shared_heap_create(MEMORY_HEAP_SIZE))) // 64MB
    {
        formatln("shared_heap_create() failed: %r", ret);
        return 2;
    }
    
    u8 id = (u8)ret;
    
    int count = LOOP_COUNT;
    
    shared_heap_check(id);
    
    for(int j = 11; j < 1023; ++j)
    {
        output_stream baos;
        //output_stream baos2;
        shared_heap_output_stream_context shos_context;
        shared_heap_output_stream_init_ex_static(&baos, id, NULL, 48, SHARED_HEAP_DYNAMIC, &shos_context);
        //shared_heap_output_stream_context shos_context2;
        //shared_heap_output_stream_init_ex_static(&baos2, id, NULL, 48, SHARED_HEAP_DYNAMIC, &shos_context2);
        
        for(int i = 0; i < j; ++i)
        {
            output_stream_write(&baos, one_kb_string, i & 1023);
            //output_stream_write(&baos2, one_kb_string, 1023 - (i & 1023));
            
            shared_heap_check(id);
        }
        
        output_stream_close(&baos);
        //output_stream_close(&baos2);
        
        shared_heap_check(id);
        
        size_t total;
        size_t count;
        
        shared_heap_count_allocated(id, &total, &count);
        
        assert((total == 0) && (count == 0));
    }
    
    for(int i = 0; i < count; ++i)
    {
        pointers[i] = (u8*)shared_heap_alloc(id, i);
        if(pointers[i] == NULL)
        {
            formatln("failed to allocate %i bytes", i);
            return 3;
        }
        shared_heap_check_ptr(id, pointers[i]);
        shared_heap_check(id);
        memset(pointers[i], i, i);
        formatln("alloc: @%p: %i bytes", pointers[i], i);
    }
    
    shared_heap_check(id);
    
    for(int i = 0; i < count; ++i)
    {
        formatln("---->: @%p: %i bytes", pointers[i], i);
        shared_heap_check_ptr(id, pointers[i]);
        shared_heap_free(/*id, */pointers[i]);
        formatln("freed: @%p: %i bytes", pointers[i], i);
    }
    
    shared_heap_check(id);
    
    pointers[0] = (u8*)shared_heap_alloc(id, 0);
    shared_heap_free(/*id, */pointers[0]);
    
    for(int i = 0; i < count; ++i)
    {
        pointers[i] = (u8*)shared_heap_alloc(id, i);
        if(pointers[i] == NULL)
        {
            formatln("failed to allocate %i bytes", i);
            return 3;
        }
        shared_heap_check_ptr(id, pointers[i]);
        memset(pointers[i], i, i);
        formatln("alloc: @%p: %i bytes", pointers[i], i);
    }
    
    shared_heap_check(id);
    
    for(int i = count - 1; i >= 0; --i)
    {
        formatln("---->: @%p: %i bytes", pointers[i], i);
        shared_heap_check_ptr(id, pointers[i]);
        shared_heap_free(/*id, */pointers[i]);
        formatln("freed: @%p: %i bytes", pointers[i], i);
    }
    
    shared_heap_check(id);
    
    random_ctx rndctx = random_init(0);
    
    int next_ptr = 0;
    for(int i = 0; i < 1000000; ++i)
    {
        if(next_ptr < LOOP_COUNT)
        {
            shared_heap_check(id);
            pointers[next_ptr] = (u8*)shared_heap_alloc(id, i & 1023);
            shared_heap_check(id);

            if(pointers[next_ptr] == NULL)
            {
                --next_ptr;
                assert(next_ptr >= 0);
                shared_heap_check(id);
                shared_heap_free(pointers[next_ptr]);
                shared_heap_check(id);
                continue;
            }

            memset(pointers[next_ptr], i, i & 1023);
            shared_heap_check(id);

            ++next_ptr;
        }
        
        if(i & 1)
        {
            u32 r = random_next(rndctx);
            if(r & 1)
            {
                r = random_next(rndctx);
                r %= next_ptr;
                shared_heap_check(id);
                shared_heap_free(pointers[r]);
                shared_heap_check(id);
                pointers[r] = pointers[--next_ptr];
            }
        }
    }
    
    for(int i = 0; i < next_ptr; ++i)
    {
        shared_heap_free(pointers[i]);
        shared_heap_check(id);
    }
    
    next_ptr = 0;
    
    for(int i = 0; i < 1000000; ++i)
    {
        if(next_ptr < LOOP_COUNT)
        {
            shared_heap_check(id);
            pointers[next_ptr] = (u8*)shared_heap_alloc(id, 48);
            shared_heap_check(id);

            if(pointers[next_ptr] == NULL)
            {
                --next_ptr;
                assert(next_ptr >= 0);
                shared_heap_check(id);
                shared_heap_free(pointers[next_ptr]);
                shared_heap_check(id);
                continue;
            }

            memset(pointers[next_ptr], i, 48);
            shared_heap_check(id);

            ++next_ptr;
        }
        
        if(i & 1)
        {
            u32 r = random_next(rndctx);
            if(r & 1)
            {
                r = random_next(rndctx);
                r %= next_ptr;
                shared_heap_check(id);
                shared_heap_free(pointers[r]);
                shared_heap_check(id);
                pointers[r] = pointers[--next_ptr];
            }
        }
    }
    
    for(int i = 0; i < next_ptr; ++i)
    {
        shared_heap_free(pointers[i]);
        shared_heap_check(id);
    }
    
    random_finalize(rndctx);
    
    pointers[0] = (u8*)shared_heap_alloc(id, 0);
    shared_heap_free(/*id, */pointers[0]);
    
    shared_heap_check(id);
    
    shared_blocs = (void**)shared_heap_alloc(id, LOOP_COUNT * sizeof(void*));
    assert(shared_blocs != NULL);
    
    for(int f = 0; f < FORK_LOOPS; ++f)
    {
        formatln("fork test %i/%i begin", f, FORK_LOOPS);
        pid_t child[CHILDREN];
        for(int i = 0; i < CHILDREN; ++i)
        {
            if((child[i] = fork_ex()) == 0)
            {
                formatln("[%5i] working", getpid_ex());
                
                for(int j = 0; j < LOOP_COUNT; j += CHILDREN)
                {
                    shared_blocs[i + j] = shared_heap_alloc(id, j);
                    //shared_heap_check_ptr(id, shared_blocs[i + j]);
                    memset(shared_blocs[i + j], 0xff, j);
                    formatln("[%5i] alloc: @%p: %i bytes", getpid_ex(), shared_blocs[i + j], j);
                }

                formatln("[%5i] done", getpid_ex());

                flushout();

                exit(0);
            }
            else if(child[i] < 0)
            {
                abort();
            }
        }
        
        formatln("fork test %i/%i: waiting for children", f, FORK_LOOPS);

        for(int i = 0; i < CHILDREN; ++i)
        {
            waitpid_ex(child[i], NULL, 0);
        }
        
        formatln("fork test %i/%i: integrity check before free", f, FORK_LOOPS);
        
        shared_heap_check(id);

        for(int i = 0; i < LOOP_COUNT; ++i)
        {
            formatln("---->: @%p: %i bytes", shared_blocs[i], i / CHILDREN);
            shared_heap_check_ptr(id, shared_blocs[i]);
            shared_heap_free(/*id, */shared_blocs[i]);
            formatln("freed: @%p: %i bytes", shared_blocs[i], i);
        }
        
        formatln("fork test %i/%i: integrity check after free", f, FORK_LOOPS);
        
        flushout();
    }
    
    shared_heap_free(/*id, */shared_blocs);
    
    shared_heap_check(id);
    
    println("and now for a bigger one");
    
    pointers[0] = (u8*)shared_heap_alloc(id, 0);
    shared_heap_free(/*id, */pointers[0]);
    
    shared_heap_check(id);
    
    shared_blocs = (void**)shared_heap_alloc(id, FORK_LOOP_POINTER_ARRAY_SIZE);
    assert(shared_blocs != NULL);
    
    for(int f = 0; f < FORK_LOOPS; ++f)
    {
        formatln("fork test %i/%i begin", f, FORK_LOOPS);
        pid_t child[CHILDREN];
        for(int i = 0; i < CHILDREN; ++i)
        {
            if((child[i] = fork_ex()) == 0)
            {
                formatln("[%5i] working", getpid_ex());
                
                for(size_t j = 0; j < FORK_LOOP_COUNT; j += CHILDREN)
                {
                    shared_blocs[i + j] = shared_heap_alloc(id, j & L1_MASK);
                    assert(shared_blocs[i + j] != NULL);
                    //shared_heap_check_ptr(id, shared_blocs[i + j]);
                    //formatln("[%5i] alloc: @%p: %i bytes", getpid_ex(), shared_blocs[i + j], j & L1_MASK);
                }

                formatln("[%5i] done", getpid_ex());

                flushout();

                exit(0);
            }
            else if(child[i] < 0)
            {
                abort();
            }
        }
        
        formatln("fork test %i/%i: waiting for children", f, FORK_LOOPS);

        for(int i = 0; i < CHILDREN; ++i)
        {
            waitpid_ex(child[i], NULL, 0);
        }
        
        formatln("fork test %i/%i: integrity check before free", f, FORK_LOOPS);
        
        shared_heap_check(id);

        for(size_t i = 0; i < FORK_LOOP_COUNT; ++i)
        {
            //formatln("---->: @%p: %i bytes", shared_blocs[i], i);
            //shared_heap_check_ptr(id, shared_blocs[i]);
            assert(shared_blocs[i] != NULL);
            shared_heap_free(/*id, */shared_blocs[i]);
            //formatln("freed: @%p: %i bytes", shared_blocs[i], i);
        }
        
        formatln("fork test %i/%i: integrity check after free", f, FORK_LOOPS);
        
        flushout();
    }
    
    shared_heap_free(/*id, */shared_blocs);
    
    shared_heap_check(id);
    
    pointers[0] = (u8*)shared_heap_alloc(id, 0);
    shared_heap_free(/*id, */pointers[0]);
        
    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
