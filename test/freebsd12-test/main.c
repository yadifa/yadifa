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
 *  @brief freebsd12 test
 * 
 * So called because it tries to trigger an issue only seen on FreeBSD 12.0 (but likely happens on earlier versions)
 *
 */

#include <dnscore/dnscore.h>
#include <dnscore/logger.h>
#include <dnscore/thread_pool.h>
#include <dnscore/service.h>
#include <dnscore/format.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/fdtools.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/logger_channel_stream.h>


logger_handle *g_program_logger = LOGGER_HANDLE_SINK;
#define MODULE_MSG_HANDLE g_program_logger

static void
main_logger_setup()
{
    output_stream stdout_os;
    fd_output_stream_attach(&stdout_os, dup_ex(1));
    buffer_output_stream_init(&stdout_os, &stdout_os, 65536);

    logger_channel *stdout_channel = logger_channel_alloc();
    logger_channel_stream_open(&stdout_os, FALSE, stdout_channel);
    logger_channel_register("stdout", stdout_channel);

    logger_handle_create("system", &g_system_logger);
    logger_handle_add_channel("system", MSG_ALL_MASK, "stdout");

    logger_handle_create("program", &g_program_logger);
    logger_handle_add_channel("program", MSG_ALL_MASK, "stdout");
}

static void *thread_pool_0_function(void* name_)
{
    char* name = (char*)name_;
    logger_handle_set_thread_tag_with_pid_and_tid(getpid(), thread_self(), name);
    for(int i = 0; i < 5; ++i)
    {
        usleep(100000);     // 0.1s
        log_info("tp0: %s: %i", name, i);
    }
    free(name);
    return NULL;
}

static void *thread_pool_1_function(void* name_)
{
    char* name = (char*)name_;
    logger_handle_set_thread_tag_with_pid_and_tid(getpid(), thread_self(), name);
    for(int i = 0; i < 5; ++i)
    {
        usleep(10000);     // 0.01s
        log_info("tp1: %s: %i", name, i);
    }
    free(name);
    return NULL;
}

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    /* initializes the core library */
    dnscore_init();

    logger_start();

    main_logger_setup();

    log_info("init");
    logger_flush();
    sleep(1);

    struct thread_pool_s* tp0 = thread_pool_init_ex(255, 65536, "tp0-pool");

    if(tp0 == NULL)
    {
        log_err("tp0");
        return EXIT_FAILURE;
    }

    struct thread_pool_s* tp1 = thread_pool_init_ex(255, 65536, "tp1-pool");

    if(tp1 == NULL)
    {
        log_err("tp1");
        return EXIT_FAILURE;
    }

    log_info("begin");

    for(int i = 0; i < 65536; ++i)
    {
        char* name0;
        char* name1;
        log_info("queue: %i", i);
        asnformat(&name0, 256, "tp0-%i", i);
        asnformat(&name1, 256, "tp1-%i", i);
        //char namstrdup();
        thread_pool_enqueue_call(tp0, thread_pool_0_function, name0, NULL, "tp0");
        thread_pool_enqueue_call(tp1, thread_pool_1_function, name1, NULL, "tp1");
    }

    log_info("end");

    thread_pool_destroy(tp1);
    tp1 = NULL;
    thread_pool_destroy(tp0);
    tp0 = NULL;

    log_info("flush");

    flushout();
    flusherr();
    fflush(NULL);

    log_info("done");

    logger_stop();

    dnscore_finalize();

    return EXIT_SUCCESS;
}
