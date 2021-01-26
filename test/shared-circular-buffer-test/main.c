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
#include <dnscore/shared-circular-buffer.h>
#include <dnscore/shared-heap.h>
#include <dnscore/thread_pool.h>
#include <dnscore/process.h>

#define CHILDREN 4
#define LOOPS 1000000
#define FORK_LOOPS_A 2
#define FORK_LOOPS_B 16
#define TEXT_BUFFER_SIZE 32*1024*1024
#define LINE_SIZE 48

#define HEAVY_HEAP_TEST 0

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    
    /* initializes the core library */
    dnscore_init();
    
    shared_circular_buffer* scb = shared_circular_buffer_create(20); // 64MB a.k.a 2^20 * 64

    if(scb == NULL)
    {
        println("shared_circular_buffer_create failed");
        exit(1);
    }
/*
    shared_circular_buffer_slot *slot = shared_circular_buffer_prepare_enqueue(scb);
    snformat((char*)slot->data, sizeof(slot->data), "This is a test");    
    shared_circular_buffer_ready(scb, slot);
    shared_circular_buffer_slot *recv = shared_circular_buffer_dequeue(scb);
    (void)recv;
*/
    pid_t child[CHILDREN];
        
    for(size_t l = 0; l < FORK_LOOPS_A; ++l)
    {
        formatln("test loop #%llu", l);
        
        for(size_t f = 0; f < CHILDREN; ++f)
        {
            formatln("spawning child #%llu : %llu", l, f);
            
            flushout();
            
            child[f] = fork_ex();
            
            if(child[f] == 0)
            {
                formatln("[%5i] working", getpid_ex());
                
                s64 start = timeus();
                
                for(size_t i = 0; i < LOOPS; ++i)
                {
                    shared_circular_buffer_slot *slot = shared_circular_buffer_prepare_enqueue(scb);
                    snformat((char*)slot->data, sizeof(slot->data), "[%5i] %lT: %llu", getpid_ex(), timeus(), i);
                    shared_circular_buffer_commit_enqueue(scb, slot);
                }
                
                s64 stop = timeus();
                
                formatln("[%5i] done (%lluus)", getpid_ex(), stop - start);
                
                flushout();
                
                exit(0);
            }
            else if(child[f] < 0)
            {
                abort();
            }
        }
        
        size_t n = LOOPS * CHILDREN;
        
        formatln("starting to read the queue (%llu elements)", n);
        
        for(size_t i = 0; i < n; ++i)
        {
            shared_circular_buffer_slot *recv = shared_circular_buffer_prepare_dequeue_with_timeout(scb, 5000000);
            (void)recv;
            if(recv == NULL)
            {
                formatln("timed-out at entry %llu/%llu", i + 1, n);
                flushout();
                abort();
            }
            shared_circular_buffer_commit_dequeue(scb);
        }
        
        formatln("queue read, waiting for children");
        
        for(int i = 0; i < CHILDREN; ++i)
        {
            waitpid_ex(child[i], NULL, 0);
        }
        
        formatln("done");
        
        sleep(1);
    }
    
    struct log_like
    {
        u8 reserved;
        u8 flags[7];
        u64 enqueue_index;
        u64 dequeue_index;
        char* text;
        size_t text_size;
    };
    
    if(FAIL(shared_heap_init()))
    {
        abort();
    }
    
    for(int i = 0; i < CHILDREN; ++i)
    {
        if(FAIL(shared_heap_create(TEXT_BUFFER_SIZE)))
        {
            abort();
        }
    }
    
    for(size_t l = 0; l < FORK_LOOPS_B; ++l)
    {
        formatln("test loop #%llu", l);
        
        for(size_t f = 0; f < CHILDREN; ++f)
        {
            formatln("spawning child #%llu : %llu", l, f);
            
            flushout();
            
            child[f] = fork_ex();
            
            if(child[f] == 0)
            {
                formatln("[%5i] working", getpid_ex());
                
                s64 start = timeus();

#if HEAVY_HEAP_TEST > 0
                shared_heap_check(f);
#endif
                s64 last = timeus();
                
                for(size_t i = 0; i < LOOPS; ++i)
                {
                    shared_circular_buffer_slot *slot = shared_circular_buffer_prepare_enqueue(scb);
                    struct log_like *ll = (struct log_like *)slot;

#if 1
                    ll->text = shared_heap_wait_alloc(f, LINE_SIZE);
#else
                    ll->text = shared_heap_alloc(f, LINE_SIZE);
#endif
                    
#if HEAVY_HEAP_TEST > 0
                    shared_heap_check(f);
#endif                    
                    if(ll->text == NULL)
                    {
                        formatln("[%5i] out of memory", getpid_ex());
                        flushout();
                        abort();
                    }
                    
                    memcpy(ll->flags, "ENQUEUE", 7);
                    ll->enqueue_index = shared_circular_buffer_get_index(scb, slot);
                    ll->text_size = snformat(ll->text, LINE_SIZE, "[%5i] %llT: %llu", getpid_ex(), timeus(), i);
                    shared_circular_buffer_commit_enqueue(scb, slot);
                    
                    s64 now = timeus();
                    if(now - last >= 1000000)
                    {
                        formatln("[%5i] %llu elements written", getpid_ex(), i);
                        last = now;
                        flushout();
                    }
                }
                
#if HEAVY_HEAP_TEST > 0
                shared_heap_check(f);
#endif
                    
                s64 stop = timeus();
                
                formatln("[%5i] done (%lluus)", getpid_ex(), stop - start);
                
                flushout();
                
                exit(0);
            }
            else if(child[f] < 0)
            {
                abort();
            }
        }
        
        size_t n = LOOPS * CHILDREN;
        
        formatln("starting to read the queue (%llu elements)", n);
        
        s64 last = timeus();
        for(size_t i = 0; i < n; ++i)
        {
            //shared_circular_buffer_slot *recv = shared_circular_buffer_prepare_dequeue(scb);
            shared_circular_buffer_slot *recv = shared_circular_buffer_prepare_dequeue_with_timeout(scb, 1000000);
            if(recv == NULL)
            {
                formatln("shared_circular_buffer_prepare_dequeue_with_timeout timed out");
                --i;
                continue;
            }
            
            struct log_like *ll = (struct log_like *)recv;
            //formatln("%p: '%s' (%llu)", recv, ll->text, ll->text_size);
            //memset(&ll->text[0], 0xfe, 16);
            //memset(&ll->text[40], 0xee, 8);
            memcpy(ll->flags, "DEQUEUE", 7);
            ll->dequeue_index = i;
            void *ptr = ll->text;
            ll->text = NULL;
            shared_circular_buffer_commit_dequeue(scb);
            shared_heap_free(ptr);
            s64 now = timeus();
            if(now - last >= 1000000)
            {
                formatln("%llu elements read", i);
                
                for(int f = 0; f < CHILDREN; ++f)
                {
                    size_t total;
                    size_t count;

                    shared_heap_count_allocated(f, &total, &count);
                    formatln("  (%5i) %llu blocs for a total of %llu bytes", child[f], count, total);
                }
                
                last = now;
                flushout();
            }
        }
        
        formatln("queue read, waiting for children");
        
        for(int i = 0; i < CHILDREN; ++i)
        {
            waitpid_ex(child[i], NULL, 0);
        }
        
        formatln("post process state:");
        
        for(int f = 0; f < CHILDREN; ++f)
        {
            size_t total;
            size_t count;

            shared_heap_count_allocated(f, &total, &count);
            formatln("  (%5i) %llu blocs for a total of %llu bytes", child[f], count, total);
            
            shared_heap_check(f);
        }
        
        formatln("done");
        
        sleep(1);
    }

    shared_circular_buffer_destroy(scb);

    sleep(10);
    
    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
