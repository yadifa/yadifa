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
 *  @brief logger_test file
 * 
 * logger_test test program, will not be installed with a "make install"
 * 
 * To create a new test based on the logger_test:
 * 
 * _ copy the folder
 * _ replace "logger_test" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 *
 */
#include <sys/mman.h>

#include <dnscore/dnscore.h>
#include <dnscore/logger.h>
#include <dnscore/fdtools.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/logger_channel_stream.h>
#include <dnscore/thread_pool.h>
#include <dnscore/zalloc.h>
#include <dnscore/shared-heap.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/process.h>
#include <dnscore/async.h>

pid_t fork_ex();

logger_handle *parent = LOGGER_HANDLE_SINK;
logger_handle *child = LOGGER_HANDLE_SINK;

#define HEAP_SIZE 0x40000000

#define CHILDREN 4

#define LOOP_COUNT_DEFAULT 1000000

#define MMAP_TEST 0
#if 0
#define MICROPAUSE 10000
#endif

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

struct thread_ctx
{
    async_wait_s *aw;
    logger_handle *logger;
    int f;
    int count;
};

static void*
logging_stuff_thread(void *args)
{
    struct thread_ctx *ctx = (struct thread_ctx*)args;
    async_wait_s *aw = ctx->aw;
    int f = ctx->f;
    int count = ctx->count;
    
#define MODULE_MSG_HANDLE ctx->logger
    
    logger_handle_set_thread_tag("stuff");
    
    async_wait(aw);
        
    for(int j = 0; j < count; j += 100)
    {
        for(int i = 0; i < 50; ++i)
        {
            log_info("child #%i log line %i that will require a growth of the originally allocated 48 bytes buffer (thread)", f, j + i);
#if MICROPAUSE > 0
            usleep(MICROPAUSE);
#endif
        }

        for(int i = 50; i < 100; ++i)
        {
            log_info("child #%i log line %i '%s' (thread)", f, j + i, &one_kb_string[(j + i) & 1023]);
#if MICROPAUSE > 0
            usleep(MICROPAUSE);
#endif
        }

#if 0
        if(j < 250)
        {
            logger_flush();
        }

        if(j < 500)
        {
            usleep(10000);
        }
#endif
    }
    
#undef MODULE_MSG_HANDLE
    
    logger_handle_clear_thread_tag();
    
    return NULL;
}

int
main(int argc, char *argv[])
{
    /* initializes the core library */
    
    int count = 0;
    if(argc >= 2)
    {
        count = atoi(argv[1]);
    }
    
    if(count <= 1)
    {
        count = LOOP_COUNT_DEFAULT;
    }
    
    u32 features = DNSCORE_MOST& ~DNSCORE_LOGGER;
    
    dnscore_init_ex(features, argc, argv);

    {
        int sentinel = 0;
        s64 now = timeus();
        s64 max = MAX_S64;
        formatln("%i %lT %i %llT %i %lT %i %llT %i", sentinel, now, sentinel, now, sentinel, max, sentinel, max, sentinel);
    }
    
#if MMAP_TEST
    int *please_dont_be_shared_ptr;
    please_dont_be_shared_ptr = (int*)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    *please_dont_be_shared_ptr = 0;
#endif
        
    logger_init_ex(0x100000, HEAP_SIZE);
    logger_start();
    
    {
        output_stream stdout_os;
        logger_channel *stdout_channel;
        static const char * const log_file_name = "/tmp/logger-test.log";
        ya_result ret;
        //fd_output_stream_attach(&stdout_os, dup_ex(1));
        if(FAIL(ret = file_output_stream_create(&stdout_os, log_file_name, 0644)))
        {
            formatln("failed to create %s: %r", log_file_name, ret);
            exit(1);
        }
        buffer_output_stream_init(&stdout_os, &stdout_os, 65536);
        stdout_channel = logger_channel_alloc();
        logger_channel_stream_open(&stdout_os, FALSE, stdout_channel);
        logger_channel_register("stdout", stdout_channel);
        logger_handle_create("parent", &parent);
        logger_handle_create("child", &child);
        
        logger_handle_add_channel("parent", MSG_ALL_MASK, "stdout");
        logger_handle_add_channel("child", MSG_ALL_MASK, "stdout");
        
        logger_flush();
        
        sleep(1);
    }
    
    async_wait_s *aw = async_wait_create_shared(0, 1);
    
#if CHILDREN
    u8 child_heap_id[CHILDREN];
    pid_t pid[CHILDREN];
    
    for(int f = 0; f < CHILDREN; ++f)
    {
        int id = shared_heap_create(HEAP_SIZE);
        if(id < 0)
        {
            formatln("failed to allocate heap #%i", f);
            exit(1);
        }
        child_heap_id[f] = (u8)id;
    }
    
    for(int f = 0; f < CHILDREN; ++f)
    {
        pid[f] = fork_ex();
        
        if(pid[f] < 0)
        {
            formatln("failed to spawn child #%i", f);
            exit(2);
        }

        if(pid[f] == 0)
        {
            logger_handle_set_thread_tag("childid");
            
            logger_set_shared_heap(child_heap_id[f]);

#if MMAP_TEST
            for(int j = 0; j < 1000; j += 100)
            {
                for(int i = 0; i < 100; ++i)
                {
                    please_dont_be_shared_ptr[1] = j + i;
                    formatln("[CHILD] *please_dont_be_shared_ptr = %i,%i", please_dont_be_shared_ptr[0], please_dont_be_shared_ptr[1]);
                }
                flushout();
            }
#endif

            struct thread_ctx ctx;
            ctx.aw = aw;
            ctx.logger = child;
            ctx.f =f;
            ctx.count = count;
            
            thread_t tid  = 0;
            if(thread_create(&tid, logging_stuff_thread, &ctx) != 0)
            {
            }

            async_wait(aw);

#if !HAS_SHARED_QUEUE_SUPPORT
            logger_init_ex(16384);
            logger_start_client();
#endif

#define MODULE_MSG_HANDLE child
            //formatln("client logger @ %p = %p", child, MODULE_MSG_HANDLE);
            //flushout();

            for(int j = 0; j < count; j += 100)
            {
                for(int i = 0; i < 50; ++i)
                {
                    log_info("child #%i log line %i that will require a growth of the originally allocated 48 bytes buffer", f, j + i);
#if MICROPAUSE > 0
                    usleep(MICROPAUSE);
#endif
                }

                for(int i = 50; i < 100; ++i)
                {
                    log_info("child #%i log line %i", f, j + i);
#if MICROPAUSE > 0
                    usleep(MICROPAUSE);
#endif
                }

#if 0
                if(j < 250)
                {
                    logger_flush();
                }

                if(j < 500)
                {
                    usleep(10000);
                }
#endif
            }

            log_info("child #%i done", f);

#undef MODULE_MSG_HANDLE

            if(tid != 0)
            {
                thread_join(tid, NULL);
            }
            
            //logger_stop_client();
            exit(0);
        }
    }
    
#endif
    
    {
#if MMAP_TEST
        for(int j = 0; j < 1000; j += 100)
        {
            for(int i = 0; i < 100; ++i)
            {
                please_dont_be_shared_ptr[0] = j + i;
                formatln("[PARNT] *please_dont_be_shared_ptr = %i,%i", please_dont_be_shared_ptr[0], please_dont_be_shared_ptr[1]);
            }
            flushout();
        }
#endif
#if !HAS_SHARED_QUEUE_SUPPORT
        logger_start_server();
#endif

#define MODULE_MSG_HANDLE parent
        
        //formatln("parent logger @ %p = %p", parent, MODULE_MSG_HANDLE);
        //flushout();
        
        struct thread_ctx ctx;
        ctx.aw = aw;
        ctx.logger = parent;
        ctx.f = -1;
        ctx.count = count;

        thread_t tid  = 0;
        if(thread_create(&tid, logging_stuff_thread, &ctx) != 0)
        {
        }
        
        sleep(1);
        
        async_wait_progress(aw, 1);
        
        for(int j = 0; j < count; j += 100)
        {
            for(int i = 0; i < 50; ++i)
            {
                log_info("parent log line %i", j + i);
#if MICROPAUSE > 0
                usleep(MICROPAUSE);
#endif
            }
            
            for(int i = 50; i < 100; ++i)
            {
                log_info("parent log line %i that will require a growth of the originally allocated 48 bytes buffer", j + i);
#if MICROPAUSE > 0
                usleep(MICROPAUSE);
#endif
            }
            
#if 0
            if(j < 250)
            {
                logger_flush();
            }
            
            if(j < 500)
            {
                usleep(10000);
            }
#endif
        }
        
#if CHILDREN
        log_info("waiting for child");
    
        for(int f = 0; f < CHILDREN; ++f)
        {
            waitpid_ex(pid[f], NULL, 0);
        }
#endif
        
        if(tid != 0)
        {
            thread_join(tid, NULL);
        }
        
        log_info("done");
        
#undef MODULE_MSG_HANDLE
        
#if !HAS_SHARED_QUEUE_SUPPORT
        logger_stop_server();
#endif
        logger_stop();
    }
    
    async_wait_destroy_shared(aw);
    
    {
        size_t total, count;
        formatln("[0] testing block");
        flushout();
        shared_heap_count_allocated(0, &total, &count);
        formatln("[0] after use: %llu allocated blocs using %llu bytes", count, total);
        flushout();
        
        
#if CHILDREN
        for(int f = 0; f < CHILDREN; ++f)
        {
            formatln("[%i] testing block", child_heap_id[f]);
            flushout();
            shared_heap_count_allocated(child_heap_id[f], &total, &count);
            formatln("[%i] after use: %llu allocated blocs using %llu bytes", child_heap_id[f], count, total);
            flushout();
        }
#endif
    }

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
