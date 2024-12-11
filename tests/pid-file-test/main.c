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

#include <dnscore/dnscore.h>
#include <dnscore/pid.h>
#include "dnscore/format.h"

#define PID_FILE_PATH "/tmp/pid-file-test.run"

static void pid_file_create_and_destroy()
{
    ya_result ret;
    pid_t     pid;
    ret = pid_file_create(PID_FILE_PATH, &pid, 0, 0);
    formatln("pid_file_create(%s, %p, 0, 0) returned %r", PID_FILE_PATH, &pid, 0, 0, ret);
    if(FAIL(ret))
    {
        println("ERROR");
        return;
    }
    pid = 0;
    ret = pid_file_read(PID_FILE_PATH, &pid);
    formatln("pid_file_read(%s, %p) returned %r", PID_FILE_PATH, &pid, ret);
    if(FAIL(ret))
    {
        println("ERROR");
        return;
    }
    pid = 0;
    ret = pid_check_running_program(PID_FILE_PATH, &pid);
    formatln("pid_check_running_program(%s, %p) return %r", PID_FILE_PATH, &pid, ret);
    if(FAIL(ret))
    {
        println("ERROR");
        return;
    }
    formatln("pid_file_destroy(%s)", PID_FILE_PATH);
    pid_file_destroy(PID_FILE_PATH);
    pid = 0;
    ret = pid_file_read(PID_FILE_PATH, &pid);
    formatln("pid_file_read(%s, %p) returned %r", PID_FILE_PATH, &pid, ret);
    if(ISOK(ret))
    {
        println("ERROR");
        return;
    }
    pid = 0;
    ret = pid_check_running_program(PID_FILE_PATH, &pid);
    formatln("pid_check_running_program(%s, %p) return %r", PID_FILE_PATH, &pid, ret);
    if(FAIL(ret))
    {
        println("ERROR");
        return;
    }
    println("SUCCESS");
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    /* initializes the core library */
    dnscore_init();

    pid_file_create_and_destroy();

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
