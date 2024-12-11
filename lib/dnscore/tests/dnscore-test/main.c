/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
#include "dnscore/fdtools.h"
#include <dnscore/dnscore.h>
#include <dnscore/mutex.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/mt_output_stream.h>

static const char *ipc_suffix = "ipc_suffix";

static const int   fake_argc = 3;
static char       *fake_argv[4] = {"/usr/local/bin/myprogram", "-v", "--help", NULL};

static int         dnscore_init_start_test()
{
    dnscore_init();
    dnscore_hookme();
    log_assert__(true, "true", __FILE__, __LINE__);
    dnscore_finalize();
    return 0; // didn't crash
}

static int dnscore_ipc_test()
{
    int  ret;
    char buffer[512];

    dnscore_init();
    ret = dnscore_ipc_make_name(ipc_suffix, buffer, sizeof(buffer));
    if(ret == 0)
    {
        yatest_err("dnscore_ipc_make_name returned 0");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int dnscore_fingerprint_test()
{
    int ret;
    dnscore_init();
    ret = dnscore_getfingerprint();
    yatest_log("dnscore_getfingerprint: %x", ret);
    ret = dnscore_fingerprint_mask();
    yatest_log("dnscore_fingerprint_mask: %x", ret);
    DNSCORE_API_CHECK();
    ret = dnscore_get_active_features();
    yatest_log("dnscore_get_active_features: %x", ret);
    dnscore_finalize();
    return 0;
}

static int dnscore_monitored_test()
{
    dnscore_init();
    if(dnscore_monitored_isok(-1))
    {
        yatest_err("dnscore_monitored_isok expected to return false");
        return 1;
    }
    if(!dnscore_monitored_isok(1))
    {
        yatest_err("dnscore_monitored_isok expected to return true");
        return 1;
    }
    if(!dnscore_monitored_fail(-1))
    {
        yatest_err("dnscore_monitored_fail expected to return true");
        return 1;
    }
    if(dnscore_monitored_fail(1))
    {
        yatest_err("dnscore_monitored_fail expected to return false");
        return 1;
    }
    dnscore_finalize();
    return 0; // didn't crash
}

static int dnscore_detach_make_stream(output_stream_t *os, int code)
{
    int                ret;
    static const char *file_name = "/tmp/dnscore_detach_make_stream";
    unlink(file_name);
    ret = file_output_stream_create(os, file_name, 0640);
    int fd = fd_output_stream_get_filedescriptor(os);
    if(FAIL(ret))
    {
        yatest_err("internal setup failed: %s", error_gettext(ret));
        exit(255);
    }
    if(code & 1)
    {
        buffer_output_stream_init(os, os, 4096);
    }
    if(code & 2)
    {
        mt_output_stream_init(os, os);
    }
    return fd;
}

static int dnscore_detach_test()
{
    dnscore_init();

    for(int f = 0; f <= 1; ++f)
    {
        output_stream_t os;
        int             fd;
        for(int code = 0; code < 4; ++code)
        {
            fd = dnscore_detach_make_stream(&os, code);

            if(!stdstream_is_tty(&os))
            {
                yatest_err("stdstream_is_tty returned false");
                return 1;
            }
            switch(f)
            {
                case 0:
                {
                    stdstream_detach_fd(&os);
                    close_ex(fd);
                    break;
                }
                case 1:
                {
                    stdstream_detach_fd_and_close_filtered(&os);
                    break;
                }
            }
        }
    }

    stdstream_detach_fds_and_close();
    stdstream_detach_fds();

    dnscore_finalize();
    return 0; // didn't crash
}

static int dnscore_args_test()
{
    dnscore_init_ex(DNSCORE_TINYRUN, fake_argc, fake_argv);

    if(dnscore_args_count() != fake_argc)
    {
        yatest_err("dnscore_args_count() returned %i != %i", dnscore_args_count(), fake_argc);
        return 1;
    }

    for(int i = 0; i < fake_argc; ++i)
    {
        if(strcmp(dnscore_args_get(i), fake_argv[i]) != 0)
        {
            yatest_err("strcmp(dnscore_args_get(%i) returned '%s' instead of '%s'", i, dnscore_args_get(i), fake_argv[i]);
            return 1;
        }
    }

    if(dnscore_args_get(-1) != NULL)
    {
        yatest_err("dnscore_args_get(-1) exptected to return NULL");
        return 1;
    }

    if(dnscore_args_get(fake_argc) != NULL)
    {
        yatest_err("dnscore_args_get(%i) exptected to return NULL", fake_argc);
        return 1;
    }

    dnscore_finalize();
    return 0; // didn't crash
}

static int dnscore_timer_test()
{
    dnscore_init();

    int64_t ts = dnscore_init_timestamp();
    yatest_log("dnscore_init_timestamp: %lli", ts);

    uint32_t start = dnscore_timer_get_tick();
    uint32_t now = 0; // avoids a silly "maybe-uninitialized"
    time_t   t_end = time(NULL) + 30;
    while(time(NULL) < t_end)
    {
        now = dnscore_timer_get_tick();
        if(now > start)
        {
            break;
        }
        sleep(1);
    }
    if(now == start)
    {
        yatest_err("dnscore_timer_get_tick always returns value %u", start);
        return 1;
    }
    dnscore_finalize();
    return 0; // didn't crash
}

YATEST_TABLE_BEGIN
YATEST(dnscore_init_start_test)
YATEST(dnscore_ipc_test)
YATEST(dnscore_fingerprint_test)
YATEST(dnscore_monitored_test)
YATEST(dnscore_detach_test)
YATEST(dnscore_args_test)
YATEST(dnscore_timer_test)
YATEST_TABLE_END
