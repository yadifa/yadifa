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
#include <dnscore/random.h>
#include <dnscore/message.h>
#include <dnscore/config_settings.h>
#include <dnscore/host_address.h>
#include <dnscore/format.h>
#include <dnscore/thread_pool.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/logger_channel_stream.h>
#include <dnscore/file_output_stream.h>

#define HEAP_SIZE 0x40000000

static logger_handle *notify_log = LOGGER_HANDLE_SINK;

#define MODULE_MSG_HANDLE notify_log

static void help()
{
    println("parameters: server-ip zone [count [loops]]");
    flushout();
}

struct notify_send_args_s
{
    host_address *ip;
    int count;
    int loops;
    u8 zone[256];
};

static void *notify_send(void* args_)
{
    struct notify_send_args_s *args = (struct notify_send_args_s*)args_;

    ya_result ret;
    random_ctx rndctx = random_init_auto();
    message_data* mesg = message_new_instance();

    s64 last = timeus();

    s64 total_time = 0;
    s64 max_time = 0;
    s64 min_time = MAX_S64;
    s64 faults = 0;
    s64 delta;

    for(int i = 0; i < args->loops; ++i)
    {
        u16 id = (u16)random_next(rndctx);
        message_make_notify(mesg, id, args->zone, TYPE_SOA, CLASS_IN);

        s64 now = timeus();

        if(now - last > ONE_SECOND_US)
        {
            s64 next = last + ONE_SECOND_US;
            last = next;
            while(next < now)
            {
                last = next;
                next += ONE_SECOND_US;
            }

            double mean_reply_time = total_time;
            mean_reply_time /= (i + 1);
            mean_reply_time /= ONE_SECOND_US_F;

            double max_reply_time = max_time;
            max_reply_time /= ONE_SECOND_US_F;
            double min_reply_time = min_time;
            min_reply_time /= ONE_SECOND_US_F;

            log_info("notify %{dnsname} to %{hostaddr} %i/%i, %lli faults, mean reply time = %3.6fs [%3.6fs; %3.6fs]", args->zone, args->ip, i, args->loops, faults, mean_reply_time, min_reply_time, max_reply_time);
        }

        if(ISOK(ret = message_query_udp_with_timeout(mesg, args->ip, 600, 0)))
        {
            s64 reply = timeus();
            delta = reply - now;

            // message_print_format_dig(termout, message_get_buffer_const(mesg), message_get_size(mesg), 15, 0);
        }
        else
        {
            s64 reply = timeus();
            delta = reply - now;
            ++faults;

            log_err("%{dnsname}  network failed with: %r", args->zone, ret);
            --i;
        }

        total_time += delta;
        max_time = MAX(delta, max_time);
        min_time = MIN(delta, min_time);

        // message_reset_control(mesg);
    }

    message_free(mesg);

    return NULL;
}

int
main(int argc, char *argv[])
{
    ya_result ret;

    struct notify_send_args_s args;

    args.ip = NULL;
    args.zone[0] = '\0';
    args.count = 1;
    
    /* initializes the core library */
    dnscore_init();
    
    if(argc < 3)
    {
        help();
        return EXIT_FAILURE;
    }
    
    static const anytype defaults = {._8u8={CONFIG_HOST_LIST_FLAGS_DEFAULT,128,0,0,0,0,0,0}};
    
    if(FAIL(ret = config_set_host_list(argv[1], &args.ip, defaults)))
    {
        formatln("%s is an invalid ip: %r", argv[1], ret);
        help();
        return EXIT_FAILURE;
    }

    if(args.ip->port == 0)
    {
        args.ip->port = NU16(53);
    }

    if(FAIL(ret = cstr_to_dnsname_with_check(args.zone, argv[2])))
    {
        formatln("%s is an invalid zone: %r", argv[2], ret);
        help();
        return EXIT_FAILURE;
    }

    if(argc >= 4)
    {
        args.count = atoi(argv[3]);
        if(args.count < 0)
        {
            args.count = 1;
        }
        if(args.count > 255)
        {
            args.count = 255;
        }
    }

    if(argc >= 5)
    {
        args.loops = atoi(argv[4]);
        if(args.loops < 0)
        {
            args.loops = 1;
        }
    }

    logger_init_ex(0x100000, HEAP_SIZE);
    logger_start();

    {
        output_stream stdout_os;
        logger_channel *stdout_channel;
        static const char * const log_file_name = "/tmp/notify-test.log";

        unlink(log_file_name);

        fd_output_stream_attach(&stdout_os, dup_ex(1));
        /*
        ya_result ret;
        if(FAIL(ret = file_output_stream_create(&stdout_os, log_file_name, 0644)))
        {
            formatln("failed to create %s: %r", log_file_name, ret);
            exit(1);
        }
        */
        buffer_output_stream_init(&stdout_os, &stdout_os, 65536);
        stdout_channel = logger_channel_alloc();
        logger_channel_stream_open(&stdout_os, FALSE, stdout_channel);
        logger_channel_register("stdout", stdout_channel);
        logger_handle_create("notify", &notify_log);

        logger_handle_add_channel("notify", MSG_ALL_MASK, "stdout");

        logger_flush();

        sleep(1);
    }


    message_edns0_setmaxsize(4096);

    struct thread_pool_s *tp = thread_pool_init_ex(args.count, args.count * 2, "notify");

    // thread_pool_wait_all_running(tp);

    if(tp != NULL)
    {
        for(int i = 0; i < args.count; ++i)
        {
            log_info("starting notify_send %i", i);
            thread_pool_enqueue_call(tp, notify_send, &args, NULL, "notify");
        }
    }

    thread_pool_destroy(tp);
    tp = NULL;
    
    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
