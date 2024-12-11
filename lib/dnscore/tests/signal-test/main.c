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
#include <dnscore/dnscore.h>
#include <dnscore/signals.h>

static int32_t signal_called = -1;
static int64_t signal_delay;

static void    init()
{
    dnscore_init();
    signal_handler_init();
}

static void finalise()
{
    signal_handler_stop();
    signal_handler_finalize();
    dnscore_finalize();
}

static void signal_handler_function_test(uint8_t signum)
{
    yatest_timer_stop(&signal_delay);
    yatest_log("signal_handler_function_test(%i)", signum);
    signal_called = signum;
}

static int signal_handler_test() // note: the test fails in CLion because it interferes with signals
{
    init();
    signal_handler_set(SIGINT, signal_handler_function_test);
    yatest_timer_start(&signal_delay);
    kill(getpid(), SIGINT);
    yatest_sleep(1); // because dnscore signals are asynchronous
    if(signal_called != SIGINT)
    {
        yatest_err("signal handler not called properly");
        return 1;
    }
    yatest_log("signal delay: %f seconds", yatest_timer_seconds(&signal_delay));
    if(signal_handler_get(SIGINT) != signal_handler_function_test)
    {
        yatest_err("signal_handler_get didn't return the expected value");
        return 1;
    }
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(signal_handler_test)
YATEST_TABLE_END
