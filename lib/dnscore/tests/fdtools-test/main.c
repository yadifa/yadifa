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
#include "glibchooks/glibchooks_controller.h"
#include "glibchooks/filedescriptor.h"
#include "dnscore/fdtools.h"
#include <dnscore/dnscore.h>
#include <sys/socket.h>

#define DUMMY_FD        65535
#define BUFFER_SIZE     65535
#define MINIMUM_RATE_US 512000000.0
#define IO_TIMEOUT_US   5000000

static bool hooks_init()
{
    ssize_t ret = glibchooks_controller_init();
    return ret >= 0;
}

static void init(bool with_hooks)
{
    if(with_hooks)
    {
        if(!hooks_init())
        {
            yatest_log("Unable to setup glibc hook: skipped");
            exit(0);
        }
    }
    dnscore_init();
}

static void finalise() { dnscore_finalize(); }

static int  recvfully_test_hook_offset = 0;
static bool recvfully_test_hook_arm = false;
static bool recvfully_test_hook_slow = false;

static void recvfully_test_hook(recv_function_args_t *args)
{
    if(args->sockfd != DUMMY_FD)
    {
        return;
    }

    uint8_t *buffer = args->buf;
    int      remaining = BUFFER_SIZE - recvfully_test_hook_offset;

    if(remaining == 0) // EOF
    {
        args->mask = 0x3f;
        args->n = 0;
        args->errno_value = 0;
        return;
    }

    if(remaining == 4096) // trigger EINTR
    {
        if(!recvfully_test_hook_arm)
        {
            recvfully_test_hook_arm = true;
            args->mask = 0x3f;
            args->n = -1;
            args->errno_value = EINTR;
            return;
        }
        else
        {
            recvfully_test_hook_arm = false;
        }
    }

    if(remaining == 2048) // trigger EAGAIN
    {
        if(!recvfully_test_hook_arm)
        {
            recvfully_test_hook_arm = true;
            args->mask = 0x3f;
            args->n = -1;
            args->errno_value = EAGAIN;
            return;
        }
        else
        {
            recvfully_test_hook_arm = false;
        }
    }

    if(remaining == 512)
    {
        if(recvfully_test_hook_slow)
        {
            if(!recvfully_test_hook_arm)
            {
                yatest_sleep(5);
                recvfully_test_hook_arm = true;
                args->mask = 0x3f;
                args->n = -1;
                args->errno_value = EAGAIN;
                return;
            }
            else
            {
                recvfully_test_hook_arm = false;
            }
        }
    }

    int n = (remaining > 1) ? (remaining / 2) : 1;
    yatest_log("remaining=%i n=%i", remaining, n);

    for(int i = 0; i < n; ++i)
    {
        buffer[i] = i + recvfully_test_hook_offset;
    }

    recvfully_test_hook_offset += n;
    remaining -= n;

    args->mask = 0x3f;
    args->n = n;
    args->errno_value = EINTR;
}

static int  sendfully_test_hook_offset = 0;
static bool sendfully_test_hook_arm = false;
static bool sendfully_test_hook_slow = false;

static void sendfully_limited_test_hook(send_function_args_t *args)
{
    if(args->sockfd != DUMMY_FD)
    {
        return;
    }

    int remaining = BUFFER_SIZE - sendfully_test_hook_offset;

    if(remaining == 0) // EOF
    {
        args->mask = 0x1f;
        args->n = 0;
        args->errno_value = 0;
        return;
    }

    if(remaining == 4096) // trigger EINTR
    {
        if(!sendfully_test_hook_arm)
        {
            sendfully_test_hook_arm = true;
            args->mask = 0x1f;
            args->n = -1;
            args->errno_value = EINTR;
            return;
        }
        else
        {
            sendfully_test_hook_arm = false;
        }
    }

    if(remaining == 2048) // trigger EAGAIN
    {
        if(!sendfully_test_hook_arm)
        {
            sendfully_test_hook_arm = true;
            args->mask = 0x1f;
            args->n = -1;
            args->errno_value = EAGAIN;
            return;
        }
        else
        {
            sendfully_test_hook_arm = false;
        }
    }

    if(remaining == 512)
    {
        if(sendfully_test_hook_slow)
        {
            if(!sendfully_test_hook_arm)
            {
                sendfully_test_hook_arm = true;
                yatest_sleep(5);
                args->mask = 0x1f;
                args->n = -1;
                args->errno_value = EAGAIN;
                return;
            }
            else
            {
                sendfully_test_hook_arm = false;
            }
        }
    }

    int n = (remaining > 1) ? (remaining / 2) : 1;
    yatest_log("remaining=%i n=%i", remaining, n);

    sendfully_test_hook_offset += n;
    remaining -= n;

    args->mask = 0x1f;
    args->n = n;
    args->errno_value = EINTR;
}

static int  writefully_test_hook_offset = 0;
static bool writefully_test_hook_arm = false;
static bool writefully_test_hook_slow = false;

static void writefully_test_hook(write_function_args_t *args)
{
    if(args->fd != DUMMY_FD)
    {
        return;
    }

    int remaining = BUFFER_SIZE - writefully_test_hook_offset;

    if(remaining == 0) // EOF
    {
        args->mask = 0x1f;
        args->n = 0;
        args->errno_value = 0;
        return;
    }

    if(remaining == 4096) // trigger EINTR
    {
        if(!writefully_test_hook_arm)
        {
            writefully_test_hook_arm = true;
            args->mask = 0x1f;
            args->n = -1;
            args->errno_value = EINTR;
            return;
        }
        else
        {
            writefully_test_hook_arm = false;
        }
    }

    if(remaining == 2048) // trigger EAGAIN
    {
        if(!writefully_test_hook_arm)
        {
            writefully_test_hook_arm = true;
            args->mask = 0x1f;
            args->n = -1;
            args->errno_value = EAGAIN;
            return;
        }
        else
        {
            writefully_test_hook_arm = false;
        }
    }

    if(remaining == 1024) // trigger EAGAIN
    {
        if(!writefully_test_hook_arm)
        {
            writefully_test_hook_arm = true;
            args->mask = 0x1f;
            args->n = -1;
            args->errno_value = ENOSPC;
            return;
        }
        else
        {
            writefully_test_hook_arm = false;
        }
    }

    if(remaining == 512)
    {
        if(writefully_test_hook_slow)
        {
            if(!writefully_test_hook_arm)
            {
                writefully_test_hook_arm = true;
                yatest_sleep(5);
                args->mask = 0x1f;
                args->n = -1;
                args->errno_value = EAGAIN;
                return;
            }
            else
            {
                writefully_test_hook_arm = false;
            }
        }
    }

    int n = (remaining > 1) ? (remaining / 2) : 1;
    yatest_log("remaining=%i n=%i", remaining, n);

    writefully_test_hook_offset += n;
    remaining -= n;

    args->mask = 0x1f;
    args->n = n;
    args->errno_value = EINTR;
}

static int  readfully_test_hook_offset = 0;
static bool readfully_test_hook_arm = false;
static bool readfully_test_hook_slow = false;

static void readfully_test_hook(read_function_args_t *args)
{
    if(args->fd != DUMMY_FD)
    {
        return;
    }

    uint8_t *buffer = args->buf;
    int      remaining = BUFFER_SIZE - readfully_test_hook_offset;

    if(remaining == 0) // EOF
    {
        args->mask = 0x1f;
        args->n = 0;
        args->errno_value = 0;
        return;
    }

    if(remaining == 4096) // trigger EINTR
    {
        if(!readfully_test_hook_arm)
        {
            readfully_test_hook_arm = true;
            args->mask = 0x1f;
            args->n = -1;
            args->errno_value = EINTR;
            return;
        }
        else
        {
            readfully_test_hook_arm = false;
        }
    }

    if(remaining == 2048) // trigger EAGAIN
    {
        if(!readfully_test_hook_arm)
        {
            readfully_test_hook_arm = true;
            args->mask = 0x1f;
            args->n = -1;
            args->errno_value = EAGAIN;
            return;
        }
        else
        {
            readfully_test_hook_arm = false;
        }
    }

    if(remaining == 512)
    {
        if(readfully_test_hook_slow)
        {
            if(!readfully_test_hook_arm)
            {
                yatest_sleep(5);
                readfully_test_hook_arm = true;
                args->mask = 0x1f;
                args->n = -1;
                args->errno_value = EAGAIN;
                return;
            }
            else
            {
                readfully_test_hook_arm = false;
            }
        }
    }

    int n = (remaining > 1) ? (remaining / 2) : 1;
    yatest_log("remaining=%i n=%i", remaining, n);

    for(int i = 0; i < n; ++i)
    {
        buffer[i] = i + readfully_test_hook_offset;
    }

    readfully_test_hook_offset += n;
    remaining -= n;

    args->mask = 0x1f;
    args->n = n;
    args->errno_value = EINTR;
}

static int readfully_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("read", readfully_test_hook);
    memset(buffer, 0, buffer_size);
    ret = readfully(DUMMY_FD, buffer, buffer_size + 1);
    if(ret != buffer_size)
    {
        yatest_err("readfully expected to return %i, got %i instead", buffer_size, ret);
        return 1;
    }
    for(int i = 0; i < buffer_size; ++i)
    {
        if(buffer[i] != (uint8_t)i)
        {
            yatest_err("buffer[%i] = %02x instead of %02x", i, buffer[i], (uint8_t)i);
            return 1;
        }
    }
    free(buffer);
    finalise();
    return 0;
}

static bool readfully_error_short_read_hook_arm = false;

static void readfully_error_short_read_hook(read_function_args_t *args)
{
    if(args->fd != DUMMY_FD)
    {
        return;
    }

    if(!readfully_error_short_read_hook_arm)
    {
        uint8_t *buffer = args->buf;

        for(int i = 0; i < BUFFER_SIZE / 2; ++i)
        {
            buffer[i] = i;
        }

        args->mask = 0x1f;
        args->n = BUFFER_SIZE / 2;
        args->errno_value = 0;
        readfully_error_short_read_hook_arm = true;
    }
    else
    {
        args->mask = 0x1f;
        args->n = -1;
        args->errno_value = EIO;
        readfully_error_short_read_hook_arm = false;
    }
}

static int readfully_error_short_read_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("read", readfully_error_short_read_hook);
    memset(buffer, 0, buffer_size);
    ret = readfully(DUMMY_FD, buffer, buffer_size);
    if(ret != BUFFER_SIZE / 2)
    {
        yatest_err("readfully expected to return %i, got %i instead", BUFFER_SIZE / 2, ret);
        return 1;
    }
    for(int i = 0; i < ret; ++i)
    {
        if(buffer[i] != (uint8_t)i)
        {
            yatest_err("buffer[%i] = %02x instead of %02x", i, buffer[i], (uint8_t)i);
            return 1;
        }
    }
    free(buffer);
    finalise();
    return 0;
}

static void readfully_error_zero_read_hook(read_function_args_t *args)
{
    if(args->fd != DUMMY_FD)
    {
        return;
    }

    args->mask = 0x1f;
    args->n = -1;
    args->errno_value = EIO;
}

static int readfully_error_zero_read_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("read", readfully_error_zero_read_hook);
    memset(buffer, 0, buffer_size);
    ret = readfully(DUMMY_FD, buffer, buffer_size);
    if(ret != -1)
    {
        yatest_err("readfully expected to return %i, got %i instead", -1, ret);
        return 1;
    }

    free(buffer);
    finalise();
    return 0;
}

static int readfully_limited_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("read", readfully_test_hook);
    memset(buffer, 0, buffer_size);
    ret = readfully_limited(DUMMY_FD, buffer, buffer_size + 1, MINIMUM_RATE_US);
    if(ret != buffer_size)
    {
        yatest_err("readfully_limited expected to return %i, got %i instead", buffer_size, ret);
        return 1;
    }
    for(int i = 0; i < buffer_size; ++i)
    {
        if(buffer[i] != (uint8_t)i)
        {
            yatest_err("buffer[%i] = %02x instead of %02x", i, buffer[i], (uint8_t)i);
            return 1;
        }
    }
    free(buffer);
    finalise();
    return 0;
}

static int readfully_limited_slow_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    readfully_test_hook_slow = true;
    glibchooks_set_or_die("read", readfully_test_hook);
    memset(buffer, 0, buffer_size);
    ret = readfully_limited(DUMMY_FD, buffer, buffer_size + 1, MINIMUM_RATE_US);
    if(ret != TCP_RATE_TOO_SLOW)
    {
        yatest_err("readfully_limited expected to return %i=%08x, got %i=%08x instead", TCP_RATE_TOO_SLOW, TCP_RATE_TOO_SLOW, ret, ret);
        return 1;
    }
    free(buffer);
    finalise();
    return 0;
}

static int readfully_limited_error_short_read_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("read", readfully_error_short_read_hook);
    memset(buffer, 0, buffer_size);
    ret = readfully_limited(DUMMY_FD, buffer, buffer_size, MINIMUM_RATE_US);
    if(ret != BUFFER_SIZE / 2)
    {
        yatest_err("readfully_limited expected to return %i, got %i instead", BUFFER_SIZE / 2, ret);
        return 1;
    }
    for(int i = 0; i < ret; ++i)
    {
        if(buffer[i] != (uint8_t)i)
        {
            yatest_err("buffer[%i] = %02x instead of %02x", i, buffer[i], (uint8_t)i);
            return 1;
        }
    }
    free(buffer);
    finalise();
    return 0;
}

static int readfully_limited_error_zero_read_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("read", readfully_error_zero_read_hook);
    memset(buffer, 0, buffer_size);
    ret = readfully_limited(DUMMY_FD, buffer, buffer_size, MINIMUM_RATE_US);
    if(ret != -1)
    {
        yatest_err("readfully_limited expected to return %i, got %i instead", -1, ret);
        return 1;
    }

    free(buffer);
    finalise();
    return 0;
}

static int readfully_limited_ex_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("read", readfully_test_hook);
    memset(buffer, 0, buffer_size);
    ret = readfully_limited_ex(DUMMY_FD, buffer, buffer_size + 1, IO_TIMEOUT_US, MINIMUM_RATE_US);
    if(ret != buffer_size)
    {
        yatest_err("readfully_limited_ex expected to return %i, got %i instead", buffer_size, ret);
        return 1;
    }
    for(int i = 0; i < buffer_size; ++i)
    {
        if(buffer[i] != (uint8_t)i)
        {
            yatest_err("buffer[%i] = %02x instead of %02x", i, buffer[i], (uint8_t)i);
            return 1;
        }
    }
    free(buffer);
    finalise();
    return 0;
}

static int readfully_limited_ex_slow_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    readfully_test_hook_slow = true;
    glibchooks_set_or_die("read", readfully_test_hook);
    memset(buffer, 0, buffer_size);
    ret = readfully_limited_ex(DUMMY_FD, buffer, buffer_size + 1, IO_TIMEOUT_US, MINIMUM_RATE_US);
    if(ret != TCP_RATE_TOO_SLOW)
    {
        yatest_err("readfully_limited_ex expected to return %i=%08x, got %i=%08x instead", TCP_RATE_TOO_SLOW, TCP_RATE_TOO_SLOW, ret, ret);
        return 1;
    }
    free(buffer);
    finalise();
    return 0;
}

static int readfully_limited_ex_error_short_read_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("read", readfully_error_short_read_hook);
    memset(buffer, 0, buffer_size);
    ret = readfully_limited_ex(DUMMY_FD, buffer, buffer_size, IO_TIMEOUT_US, MINIMUM_RATE_US);
    if(ret != BUFFER_SIZE / 2)
    {
        yatest_err("readfully_limited_ex expected to return %i, got %i instead", BUFFER_SIZE / 2, ret);
        return 1;
    }
    for(int i = 0; i < ret; ++i)
    {
        if(buffer[i] != (uint8_t)i)
        {
            yatest_err("buffer[%i] = %02x instead of %02x", i, buffer[i], (uint8_t)i);
            return 1;
        }
    }
    free(buffer);
    finalise();
    return 0;
}

static int readfully_limited_ex_error_zero_read_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("read", readfully_error_zero_read_hook);
    memset(buffer, 0, buffer_size);
    ret = readfully_limited_ex(DUMMY_FD, buffer, buffer_size, IO_TIMEOUT_US, MINIMUM_RATE_US);
    if(ret != -1)
    {
        yatest_err("readfully_limited_ex expected to return %i, got %i instead", -1, ret);
        return 1;
    }

    free(buffer);
    finalise();
    return 0;
}

static int writefully_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("write", writefully_test_hook);
    memset(buffer, 0, buffer_size);
    ret = writefully(DUMMY_FD, buffer, buffer_size + 1);
    if(ret != buffer_size)
    {
        yatest_err("writefully expected to return %i, got %i instead (%i difference)", buffer_size, ret, buffer_size - ret);
        return 1;
    }

    free(buffer);
    finalise();
    return 0;
}

static int writefully_limited_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("write", writefully_test_hook);
    memset(buffer, 0, buffer_size);
    ret = writefully_limited(DUMMY_FD, buffer, buffer_size + 1, MINIMUM_RATE_US);
    if(ret != buffer_size)
    {
        yatest_err("writefully_limited expected to return %i, got %i instead", buffer_size, ret);
        return 1;
    }
    free(buffer);
    finalise();
    return 0;
}

static int writefully_limited_slow_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    writefully_test_hook_slow = true;
    glibchooks_set_or_die("write", writefully_test_hook);
    memset(buffer, 0, buffer_size);
    ret = writefully_limited(DUMMY_FD, buffer, buffer_size + 1, MINIMUM_RATE_US);
    if(ret != TCP_RATE_TOO_SLOW)
    {
        yatest_err("writefully_limited expected to return %i=%08x, got %i=%08x instead", TCP_RATE_TOO_SLOW, TCP_RATE_TOO_SLOW, ret, ret);
        return 1;
    }
    free(buffer);
    finalise();
    return 0;
}

static int sendfully_limited_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("send", sendfully_limited_test_hook);
    memset(buffer, 0, buffer_size);
    ret = sendfully_limited(DUMMY_FD, buffer, buffer_size, 0, MINIMUM_RATE_US);
    if(ret != buffer_size)
    {
        yatest_err("sendfully_limited expected to return %i, got %i instead (difference is %i)", buffer_size, ret, buffer_size - ret);
        return 1;
    }
    free(buffer);
    finalise();
    return 0;
}

static int sendfully_limited_slow_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    sendfully_test_hook_slow = true;
    glibchooks_set_or_die("send", sendfully_limited_test_hook);
    memset(buffer, 0, buffer_size);
    ret = sendfully_limited(DUMMY_FD, buffer, buffer_size, 0, MINIMUM_RATE_US);
    if(ret != TCP_RATE_TOO_SLOW)
    {
        yatest_err("sendfully_limited expected to return %i=%08x, got %i=%08x", TCP_RATE_TOO_SLOW, TCP_RATE_TOO_SLOW, ret, ret);
        return 1;
    }
    free(buffer);
    finalise();
    return 0;
}

static int recvfully_limited_ex_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("recv", recvfully_test_hook);
    memset(buffer, 0, buffer_size);
    ret = recvfully_limited_ex(DUMMY_FD, buffer, buffer_size + 1, 0, IO_TIMEOUT_US, MINIMUM_RATE_US);
    if(ret != buffer_size)
    {
        yatest_err("recvfully_limited_ex expected to return %i, got %i instead", buffer_size, ret);
        return 1;
    }
    for(int i = 0; i < buffer_size; ++i)
    {
        if(buffer[i] != (uint8_t)i)
        {
            yatest_err("buffer[%i] = %02x instead of %02x", i, buffer[i], (uint8_t)i);
            return 1;
        }
    }
    free(buffer);
    finalise();
    return 0;
}

static int recvfully_limited_ex_slow_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    uint8_t         *buffer = malloc(buffer_size);
    init(true);
    recvfully_test_hook_slow = true;
    glibchooks_set_or_die("recv", recvfully_test_hook);
    memset(buffer, 0, buffer_size);
    ret = recvfully_limited_ex(DUMMY_FD, buffer, buffer_size + 1, 0, IO_TIMEOUT_US, MINIMUM_RATE_US);
    if(ret != TCP_RATE_TOO_SLOW)
    {
        yatest_err("recvfully_limited_ex expected to return %i=%08x, got %i=%08x instead", TCP_RATE_TOO_SLOW, TCP_RATE_TOO_SLOW, ret, ret);
        return 1;
    }
    free(buffer);
    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define READTEXTLINE_TEST_LINE_COUNT 16

static int  readtextline_test_hook_line_num = 0;
static int  readtextline_test_hook_line_position = 0;
static bool readtextline_test_hook_line_arm = false;

static void readtextline_test_hook(read_function_args_t *args)
{
    if(args->fd != DUMMY_FD)
    {
        return;
    }

    if(args->count != 1)
    {
        yatest_err("readtextline hook expects count parameter to be 1");
        exit(1);
    }

    if(readtextline_test_hook_line_num >= READTEXTLINE_TEST_LINE_COUNT) // EOF
    {
        args->mask = 0x3f;
        args->n = 0;
        args->errno_value = 0;
        return;
    }

    ssize_t  n = 1 << (readtextline_test_hook_line_num + 1);
    uint8_t *buffer = args->buf;

    if(readtextline_test_hook_line_position < n - 1)
    {
        if((readtextline_test_hook_line_position & 7) == 0)
        {
            if(!readtextline_test_hook_line_arm)
            {
                readtextline_test_hook_line_arm = true;
                args->mask = 0x3f;
                args->n = -1;
                args->errno_value = EINTR;
                return;
            }
            else
            {
                readtextline_test_hook_line_arm = false;
            }
        }
        else if((readtextline_test_hook_line_position & 7) == 1)
        {
            if(!readtextline_test_hook_line_arm)
            {
                readtextline_test_hook_line_arm = true;
                args->mask = 0x3f;
                args->n = -1;
                args->errno_value = EAGAIN;
                return;
            }
            else
            {
                readtextline_test_hook_line_arm = false;
            }
        }

        buffer[0] = 'X';
        ++readtextline_test_hook_line_position;
    }
    else if(readtextline_test_hook_line_position == n - 1)
    {
        buffer[0] = '\n';
        readtextline_test_hook_line_position = 0;
        ++readtextline_test_hook_line_num;
    }

    args->mask = 0x3f;
    args->n = 1;
    args->errno_value = 0;
}

static int readtextline_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    char            *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("read", readtextline_test_hook);

    for(int line = 0;; ++line)
    {
        memset(buffer, 0, buffer_size);
        ret = readtextline(DUMMY_FD, buffer, buffer_size);
        if(ret <= 0)
        {
            if(ret == 0)
            {
                break;
            }
            else
            {
                yatest_err("readtextline returned an error %08x", ret);
                return 1;
            }
        }
        buffer[ret] = '\0';
        int o = ret - 8;
        if(o < 0)
        {
            o = 0;
        }
        yatest_log("line %i, len=%i, value=...'%s'", line, ret, &buffer[o]);
    }
    free(buffer);
    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static const char *unlink_ex_test_hook_expected = "?";

static void        unlink_ex_test_hook(unlink_function_args_t *args)
{
    args->mask = 0x1f;
    if(strcmp(args->pathname, unlink_ex_test_hook_expected) == 0)
    {
        args->n = 0;
        args->errno_value = 0;
    }
    else
    {
        args->n = -1;
        args->errno_value = ENOENT;
    }
}

static int unlink_ex_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    char            *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("unlink", unlink_ex_test_hook);

    unlink_ex_test_hook_expected = "/tmp/myfile";
    ret = unlink_ex("/tmp", "myfile");
    if(ret < 0)
    {
        yatest_err("unlink /tmp myfile failed");
        return 1;
    }

    memset(buffer, 'X', buffer_size);
    buffer[0] = '/';
    buffer[buffer_size - 1] = '\0';
    unlink_ex_test_hook_expected = "-";
    ret = unlink_ex(buffer, "myfile");
    if(ret >= 0)
    {
        yatest_err("unlink exceeding PATH_MAX succeeded");
        return 1;
    }

    free(buffer);
    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static const char *file_get_absolute_path_value = "?";
static int         file_get_absolute_path_errno = 0;

static void        file_get_absolute_path_hook(getcwd_function_args_t *args)
{
    args->mask = 0x1f;
    if(file_get_absolute_path_errno == 0)
    {
        strcpy_ex(args->buf, file_get_absolute_path_value, args->size);
        args->text = args->buf;
        args->errno_value = 0;
    }
    else
    {
        args->text = NULL;
        args->errno_value = file_get_absolute_path_errno;
    }
}

static int file_get_absolute_path_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    char            *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("getcwd", file_get_absolute_path_hook);

    const char *path0 = "/tmp/file.txt";
    ret = file_get_absolute_path(path0, buffer, buffer_size);
    if(ret < 0)
    {
        yatest_err("file_get_absolute_path '%s' returned %08x", path0, ret);
        return 1;
    }
    if(strcmp(buffer, path0) != 0)
    {
        yatest_err("file_get_absolute_path '%s' returned '%s' instead of '%s'", path0, buffer, path0);
        return 1;
    }

    file_get_absolute_path_value = "/home/yadifa";
    const char *path1 = "subdir/file.txt";
    const char *path1_expected = "/home/yadifa/subdir/file.txt";
    ret = file_get_absolute_path(path1, buffer, buffer_size);
    if(ret < 0)
    {
        yatest_err("file_get_absolute_path '%s' returned %08x", path1, ret);
        return 1;
    }
    if(strcmp(buffer, path1_expected) != 0)
    {
        yatest_err("file_get_absolute_path '%s' returned '%s' instead of '%s'", path1, buffer, path1_expected);
        return 1;
    }

    file_get_absolute_path_errno = EACCES;
    ret = file_get_absolute_path(path1, buffer, buffer_size);
    if(ret != MAKE_ERRNO_ERROR(EACCES))
    {
        yatest_err("file_get_absolute_path '%s' returned %08x instead of %08x", path1, ret, MAKE_ERRNO_ERROR(EACCES));
        return 1;
    }

    free(buffer);
    finalise();
    return 0;
}

static int file_get_absolute_parent_directory_test()
{
    int              ret;
    static const int buffer_size = BUFFER_SIZE;
    char            *buffer = malloc(buffer_size);
    init(true);
    glibchooks_set_or_die("getcwd", file_get_absolute_path_hook);

    const char *path0 = "/tmp/file.txt";
    const char *path0_expected = "/tmp";
    ret = file_get_absolute_parent_directory(path0, buffer, buffer_size);
    if(ret < 0)
    {
        yatest_err("file_get_absolute_parent_directory '%s' returned %08x", path0, ret);
        return 1;
    }
    if(strcmp(buffer, path0_expected) != 0)
    {
        yatest_err("file_get_absolute_parent_directory '%s' returned '%s' instead of '%s'", path0, buffer, path0_expected);
        return 1;
    }

    file_get_absolute_path_value = "/home/yadifa";
    const char *path1 = "subdir/file.txt";
    const char *path1_expected = "/home/yadifa/subdir";
    ret = file_get_absolute_parent_directory(path1, buffer, buffer_size);
    if(ret < 0)
    {
        yatest_err("file_get_absolute_parent_directory '%s' returned %08x", path1, ret);
        return 1;
    }
    if(strcmp(buffer, path1_expected) != 0)
    {
        yatest_err("file_get_absolute_parent_directory '%s' returned '%s' instead of '%s'", path1, buffer, path1_expected);
        return 1;
    }

    file_get_absolute_path_value = "/home/yadifa";
    const char *path2 = "file.txt";
    const char *path2_expected = "/home/yadifa";
    ret = file_get_absolute_parent_directory(path2, buffer, buffer_size);
    if(ret < 0)
    {
        yatest_err("file_get_absolute_parent_directory '%s' returned %08x", path2, ret);
        return 1;
    }
    if(strcmp(buffer, path2_expected) != 0)
    {
        yatest_err("file_get_absolute_parent_directory '%s' returned '%s' instead of '%s'", path2, buffer, path2_expected);
        return 1;
    }

    file_get_absolute_path_errno = EACCES;
    ret = file_get_absolute_parent_directory(path1, buffer, buffer_size);
    if(ret != MAKE_ERRNO_ERROR(EACCES))
    {
        yatest_err("file_get_absolute_parent_directory '%s' returned %08x instead of %08x", path1, ret, MAKE_ERRNO_ERROR(EACCES));
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int  open_hook_ret = 0;
static int  open_hook_errno = 0;

static void open_hook(open_function_args_t *args)
{
    args->mask = 0x1f;
    args->fd = open_hook_ret;
    args->errno_value = open_hook_errno;
    if(open_hook_errno == EINTR)
    {
        args->fd = -1;
        open_hook_errno = 0;
    }
}

static int open_ex_test()
{
    init(true);
    glibchooks_set_or_die("open", open_hook);

    open_hook_ret = DUMMY_FD;
    open_hook_errno = 0;
    int fd = open_ex("/dummy/path", O_RDWR);
    if(fd != open_hook_ret)
    {
        yatest_err("open_ex didn't return the expected file descriptor");
        return 1;
    }

    open_hook_ret = DUMMY_FD;
    open_hook_errno = EINTR;
    fd = open_ex("/dummy/path", O_RDWR);
    if(fd != open_hook_ret)
    {
        yatest_err("open_ex didn't return the expected file descriptor");
        return 1;
    }

    open_hook_ret = -1;
    open_hook_errno = EPERM;
    fd = open_ex("/dummy/path", O_RDWR);
    if(fd != -1)
    {
        yatest_err("open_ex didn't return the expected error code");
        return 1;
    }

    finalise();
    return 0;
}

static int open_create_ex_test()
{
    init(true);
    glibchooks_set_or_die("open", open_hook);

    open_hook_ret = DUMMY_FD;
    open_hook_errno = 0;
    int fd = open_create_ex("/dummy/path", O_RDWR, 0640);
    if(fd != open_hook_ret)
    {
        yatest_err("open_create_ex didn't return the expected file descriptor");
        return 1;
    }

    open_hook_ret = DUMMY_FD;
    open_hook_errno = EINTR;
    fd = open_create_ex("/dummy/path", O_RDWR, 0640);
    if(fd != open_hook_ret)
    {
        yatest_err("open_hook_ret didn't return the expected file descriptor");
        return 1;
    }

    open_hook_ret = -1;
    open_hook_errno = EPERM;
    fd = open_create_ex("/dummy/path", O_RDWR, 0640);
    if(fd != -1)
    {
        yatest_err("open_create_ex didn't return the expected error code");
        return 1;
    }

    finalise();
    return 0;
}

static int open_create_ex_nolog_test()
{
    init(true);
    glibchooks_set_or_die("open", open_hook);

    open_hook_ret = DUMMY_FD;
    open_hook_errno = 0;
    int fd = open_create_ex_nolog("/dummy/path", O_RDWR, 0640);
    if(fd != open_hook_ret)
    {
        yatest_err("open_create_ex_nolog didn't return the expected file descriptor");
        return 1;
    }

    open_hook_ret = DUMMY_FD;
    open_hook_errno = EINTR;
    fd = open_create_ex_nolog("/dummy/path", O_RDWR, 0640);
    if(fd != open_hook_ret)
    {
        yatest_err("open_hook_ret didn't return the expected file descriptor");
        return 1;
    }

    open_hook_ret = -1;
    open_hook_errno = EPERM;
    fd = open_create_ex_nolog("/dummy/path", O_RDWR, 0640);
    if(fd != -1)
    {
        yatest_err("open_create_ex_nolog didn't return the expected error code");
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int  close_hook_ret = 0;
static int  close_hook_errno = 0;

static void close_hook(close_function_args_t *args)
{
    if(args->fd != DUMMY_FD)
    {
        return;
    }
    args->mask = 0x07;
    args->ret = close_hook_ret;
    args->errno_value = close_hook_errno;
    if(close_hook_errno == EINTR)
    {
        args->ret = -1;
        close_hook_errno = 0;
    }
}

static int close_ex_test()
{
    init(true);
    glibchooks_set_or_die("close", close_hook);

    close_hook_ret = 0;
    close_hook_errno = 0;
    int fd = close_ex(DUMMY_FD);
    if(fd != close_hook_ret)
    {
        yatest_err("close_ex didn't return the expected file descriptor");
        return 1;
    }

    close_hook_ret = 0;
    close_hook_errno = EINTR;
    fd = close_ex(DUMMY_FD);
    if(fd != close_hook_ret)
    {
        yatest_err("close_ex didn't return the expected file descriptor");
        return 1;
    }

    close_hook_ret = -1;
    close_hook_errno = EBADF;
    fd = close_ex(DUMMY_FD);
    if(fd != MAKE_ERRNO_ERROR(EBADF))
    {
        yatest_err("close_ex didn't return the expected error code");
        return 1;
    }

    finalise();
    return 0;
}

static int socketclose_ex_test()
{
    init(true);
    glibchooks_set_or_die("close", close_hook);

    close_hook_ret = 0;
    close_hook_errno = 0;
    int fd = socketclose_ex(DUMMY_FD);
    if(fd != close_hook_ret)
    {
        yatest_err("socketclose_ex didn't return the expected file descriptor");
        return 1;
    }

    close_hook_ret = 0;
    close_hook_errno = EINTR;
    fd = socketclose_ex(DUMMY_FD);
    if(fd != close_hook_ret)
    {
        yatest_err("socketclose_ex didn't return the expected file descriptor");
        return 1;
    }

    close_hook_ret = -1;
    close_hook_errno = EBADF;
    fd = socketclose_ex(DUMMY_FD);
    if(fd != MAKE_ERRNO_ERROR(EBADF))
    {
        yatest_err("socketclose_ex didn't return the expected error code");
        return 1;
    }

    finalise();
    return 0;
}

static int close_ex_nolog_test()
{
    init(true);
    glibchooks_set_or_die("close", close_hook);

    close_hook_ret = 0;
    close_hook_errno = 0;
    int fd = close_ex_nolog(DUMMY_FD);
    if(fd != close_hook_ret)
    {
        yatest_err("close_ex_nolog didn't return the expected file descriptor");
        return 1;
    }

    close_hook_ret = 0;
    close_hook_errno = EINTR;
    fd = close_ex_nolog(DUMMY_FD);
    if(fd != close_hook_ret)
    {
        yatest_err("close_ex_nolog didn't return the expected file descriptor");
        return 1;
    }

    close_hook_ret = -1;
    close_hook_errno = EBADF;
    fd = close_ex_nolog(DUMMY_FD);
    if(fd != MAKE_ERRNO_ERROR(EBADF))
    {
        yatest_err("close_ex_nolog didn't return the expected error code");
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int  fsync_hook_ret = 0;
static int  fsync_hook_errno = 0;

static void fsync_hook(fsync_function_args_t *args)
{
    if(args->fd != DUMMY_FD)
    {
        return;
    }
    args->mask = 0x07;
    args->ret = fsync_hook_ret;
    args->errno_value = fsync_hook_errno;
    if(fsync_hook_errno == EINTR)
    {
        args->ret = -1;
        fsync_hook_errno = 0;
    }
}

static int fsync_ex_test()
{
    init(true);
    glibchooks_set_or_die("fsync", fsync_hook);

    fsync_hook_ret = 0;
    fsync_hook_errno = 0;
    int fd = fsync_ex(DUMMY_FD);
    if(fd != 0)
    {
        yatest_err("fsync_ex returned an error");
        return 1;
    }

    fsync_hook_ret = 0;
    fsync_hook_errno = EINTR;
    fd = fsync_ex(DUMMY_FD);
    if(fd != 0)
    {
        yatest_err("fsync_ex returned an error");
        return 1;
    }

    fsync_hook_ret = -1;
    fsync_hook_errno = EBADF;
    fd = fsync_ex(DUMMY_FD);
    if(fd != MAKE_ERRNO_ERROR(EBADF))
    {
        yatest_err("fsync_ex didn't return the expected error code");
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int  fdatasync_hook_ret = 0;
static int  fdatasync_hook_errno = 0;

static void fdatasync_hook(fdatasync_function_args_t *args)
{
    if(args->fd != DUMMY_FD)
    {
        return;
    }
    args->mask = 0x07;
    args->ret = fdatasync_hook_ret;
    args->errno_value = fdatasync_hook_errno;
    if(fdatasync_hook_errno == EINTR)
    {
        args->ret = -1;
        fdatasync_hook_errno = 0;
    }
}

static int fdatasync_ex_test()
{
    init(true);
    glibchooks_set_or_die("fdatasync", fdatasync_hook);

    fdatasync_hook_ret = 0;
    fdatasync_hook_errno = 0;
    int fd = fdatasync_ex(DUMMY_FD);
    if(fd != 0)
    {
        yatest_err("fdatasync_ex returned an error");
        return 1;
    }

    fdatasync_hook_ret = 0;
    fdatasync_hook_errno = EINTR;
    fd = fdatasync_ex(DUMMY_FD);
    if(fd != 0)
    {
        yatest_err("fdatasync_ex returned an error");
        return 1;
    }

    fdatasync_hook_ret = -1;
    fdatasync_hook_errno = EBADF;
    fd = fdatasync_ex(DUMMY_FD);
    if(fd != MAKE_ERRNO_ERROR(EBADF))
    {
        yatest_err("fdatasync_ex didn't return the expected error code");
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int  dup_hook_ret = 0;
static int  dup_hook_errno = 0;

static void dup_hook(dup_function_args_t *args)
{
    if(args->oldfd != DUMMY_FD)
    {
        return;
    }
    args->mask = 0x07;
    args->fd = dup_hook_ret;
    args->errno_value = dup_hook_errno;
    if(dup_hook_errno == EINTR)
    {
        args->fd = -1;
        dup_hook_errno = 0;
    }
}

static int dup_ex_test()
{
    init(true);
    glibchooks_set_or_die("dup", dup_hook);

    dup_hook_ret = DUMMY_FD - 1;
    dup_hook_errno = 0;
    int fd = dup_ex(DUMMY_FD);
    if(fd != DUMMY_FD - 1)
    {
        yatest_err("dup_ex returned an error");
        return 1;
    }

    dup_hook_ret = DUMMY_FD - 1;
    dup_hook_errno = EINTR;
    fd = dup_ex(DUMMY_FD);
    if(fd != DUMMY_FD - 1)
    {
        yatest_err("dup_ex returned an error");
        return 1;
    }

    dup_hook_ret = -1;
    dup_hook_errno = EBADF;
    fd = dup_ex(DUMMY_FD);
    if(fd != MAKE_ERRNO_ERROR(EBADF))
    {
        yatest_err("dup_ex didn't return the expected error code");
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int  dup2_hook_ret = 0;
static int  dup2_hook_errno = 0;

static void dup2_hook(dup2_function_args_t *args)
{
    if(args->oldfd != DUMMY_FD)
    {
        return;
    }
    args->mask = 0x0f;
    args->fd = dup2_hook_ret;
    args->errno_value = dup2_hook_errno;
    if(dup2_hook_errno == EINTR)
    {
        args->fd = -1;
        dup2_hook_errno = 0;
    }
}

static int dup2_ex_test()
{
    init(true);
    glibchooks_set_or_die("dup2", dup2_hook);

    dup2_hook_ret = DUMMY_FD - 1;
    dup2_hook_errno = 0;
    int fd = dup2_ex(DUMMY_FD, DUMMY_FD - 1);
    if(fd != DUMMY_FD - 1)
    {
        yatest_err("dup2_ex returned an error");
        return 1;
    }

    dup2_hook_ret = DUMMY_FD - 1;
    dup2_hook_errno = EINTR;
    fd = dup2_ex(DUMMY_FD, DUMMY_FD - 1);
    if(fd != DUMMY_FD - 1)
    {
        yatest_err("dup2_ex returned an error");
        return 1;
    }

    dup2_hook_ret = -1;
    dup2_hook_errno = EBADF;
    fd = dup2_ex(DUMMY_FD, DUMMY_FD - 1);
    if(fd != MAKE_ERRNO_ERROR(EBADF))
    {
        yatest_err("dup2_ex didn't return the expected error code");
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int  truncate_hook_ret = 0;
static int  truncate_hook_errno = 0;

static void truncate_hook(truncate_function_args_t *args)
{
    args->mask = 0x07;
    args->ret = truncate_hook_ret;
    args->errno_value = truncate_hook_errno;
    if(truncate_hook_errno == EINTR)
    {
        args->ret = -1;
        truncate_hook_errno = 0;
    }
}

static int truncate_ex_test()
{
    init(true);
    glibchooks_set_or_die("truncate", truncate_hook);

    truncate_hook_ret = 0;
    truncate_hook_errno = 0;
    int fd = truncate_ex("/dummy/path", 1234);
    if(fd != 0)
    {
        yatest_err("truncate_ex returned an error");
        return 1;
    }

    truncate_hook_ret = 0;
    truncate_hook_errno = EINTR;
    fd = truncate_ex("/dummy/path", 1234);
    if(fd != 0)
    {
        yatest_err("truncate_ex returned an error");
        return 1;
    }

    truncate_hook_ret = -1;
    truncate_hook_errno = EBADF;
    fd = truncate_ex("/dummy/path", 1234);
    if(fd != MAKE_ERRNO_ERROR(EBADF))
    {
        yatest_err("truncate_ex didn't return the expected error code");
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int  ftruncate_hook_ret = 0;
static int  ftruncate_hook_errno = 0;

static void ftruncate_hook(ftruncate_function_args_t *args)
{
    args->mask = 0x07;
    args->ret = ftruncate_hook_ret;
    args->errno_value = ftruncate_hook_errno;
    if(ftruncate_hook_errno == EINTR)
    {
        args->ret = -1;
        ftruncate_hook_errno = 0;
    }
}

static int ftruncate_ex_test()
{
    init(true);
    glibchooks_set_or_die("ftruncate", ftruncate_hook);

    ftruncate_hook_ret = 0;
    ftruncate_hook_errno = 0;
    int fd = ftruncate_ex(DUMMY_FD, 1234);
    if(fd != 0)
    {
        yatest_err("ftruncate_ex returned an error");
        return 1;
    }

    ftruncate_hook_ret = 0;
    ftruncate_hook_errno = EINTR;
    fd = ftruncate_ex(DUMMY_FD, 1234);
    if(fd != 0)
    {
        yatest_err("ftruncate_ex returned an error");
        return 1;
    }

    ftruncate_hook_ret = -1;
    ftruncate_hook_errno = EBADF;
    fd = ftruncate_ex(DUMMY_FD, 1234);
    if(fd != MAKE_ERRNO_ERROR(EBADF))
    {
        yatest_err("ftruncate_ex didn't return the expected error code");
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static void     *getsockopt_option_value = NULL;
static socklen_t getsockopt_option_len = 0;
static int       getsockopt_hook_ret = 0;
static int       getsockopt_hook_errno = 0;

static void      getsockopt_hook(getsockopt_function_args_t *args)
{
    args->mask = 0x7f;
    if((args->option_value != NULL) && (getsockopt_option_value != NULL) && (args->option_len != NULL) && (*args->option_len <= getsockopt_option_len))
    {
        memcpy(args->option_value, getsockopt_option_value, getsockopt_option_len);
        *args->option_len = getsockopt_option_len;
    }
    args->ret = getsockopt_hook_ret;
    args->errno_value = getsockopt_hook_errno;
}

static int fd_getsockettype_test()
{
    init(true);
    glibchooks_set_or_die("getsockopt", getsockopt_hook);

    int sock_type = SOCK_STREAM;
    getsockopt_option_value = &sock_type;
    getsockopt_option_len = sizeof(sock_type);
    getsockopt_hook_ret = 0;
    getsockopt_hook_errno = 0;
    int st = fd_getsockettype(DUMMY_FD);
    if(st != SOCK_STREAM)
    {
        yatest_err("fd_getsockettype returned %08x instead of %08x", st, SOCK_STREAM);
        return 1;
    }

    getsockopt_hook_ret = -1;
    getsockopt_hook_errno = EBADF;
    st = fd_getsockettype(DUMMY_FD);
    if(st != MAKE_ERRNO_ERROR(EBADF))
    {
        yatest_err("fd_getsockettype didn't return the expected error");
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static struct stat stat_option_value = {0};
static int         stat_hook_ret = 0;
static int         stat_hook_errno = 0;

static void        stat_hook(stat_function_args_t *args)
{
    args->mask = 0x0f;
    if(args->statbuf != NULL)
    {
        *args->statbuf = stat_option_value;
    }
    args->ret = stat_hook_ret;
    args->errno_value = stat_hook_errno;
}

static int filesize_test()
{
    init(true);
    glibchooks_set_or_die("stat", stat_hook);

    stat_option_value.st_mode = S_IFREG;
    stat_option_value.st_size = 12345678;
    stat_hook_ret = 0;
    stat_hook_errno = 0;
    int64_t ret = filesize("/dummy/file");
    if(ret != stat_option_value.st_size)
    {
        yatest_err("filesize returned %08lx instead of %08lx", ret, stat_option_value.st_size);
        return 1;
    }

    stat_option_value.st_mode = S_IFDIR;
    stat_option_value.st_size = 4096;
    stat_hook_ret = 0;
    stat_hook_errno = 0;
    ret = filesize("/dummy/dir");
    if(ret != INVALID_ARGUMENT_ERROR)
    {
        yatest_err("filesize returned %08lx instead of %08lx", ret, INVALID_ARGUMENT_ERROR);
        return 1;
    }

    stat_hook_ret = -1;
    stat_hook_errno = ENOENT;
    ret = filesize("/dummy/nosuchfile");
    if(ret != MAKE_ERRNO_ERROR(ENOENT))
    {
        yatest_err("filesize returned %08lx instead of %08lx", ret, MAKE_ERRNO_ERROR(ENOENT));
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static struct stat lstat_option_value = {0};
static int         lstat_hook_ret = 0;
static int         lstat_hook_errno = 0;

static void        lstat_hook(lstat_function_args_t *args)
{
    args->mask = 0x0f;
    if(args->statbuf != NULL)
    {
        *args->statbuf = lstat_option_value;
    }
    args->ret = lstat_hook_ret;
    args->errno_value = lstat_hook_errno;
}

static int file_exists_test()
{
    init(true);
    glibchooks_set_or_die("lstat", lstat_hook);

    lstat_option_value.st_mode = S_IFREG;
    lstat_option_value.st_size = 12345678;
    lstat_hook_ret = 0;
    lstat_hook_errno = 0;
    ya_result ret = file_exists("/dummy/file");
    if(ret != 1)
    {
        yatest_err("file_exists returned %08x instead of %08x", ret, 1);
        return 1;
    }

    lstat_hook_ret = -1;
    lstat_hook_errno = ENOENT;
    ret = file_exists("/dummy/nosuchfile");
    if(ret != 0)
    {
        yatest_err("file_exists returned %08x instead of %08x", ret, 0);
        return 1;
    }

    lstat_hook_ret = -1;
    lstat_hook_errno = EPERM;
    ret = file_exists("/dummy/badpath");
    if(ret != MAKE_ERRNO_ERROR(EPERM))
    {
        yatest_err("file_exists returned %08x instead of %08x", ret, MAKE_ERRNO_ERROR(EPERM));
        return 1;
    }

    finalise();
    return 0;
}

static int file_is_link_test()
{
    init(true);
    glibchooks_set_or_die("lstat", lstat_hook);

    lstat_option_value.st_mode = S_IFLNK;
    lstat_option_value.st_size = 64;
    lstat_hook_ret = 0;
    lstat_hook_errno = 0;
    ya_result ret = file_is_link("/dummy/link");
    if(ret != 1)
    {
        yatest_err("file_is_link returned %08x instead of %08x", ret, 1);
        return 1;
    }

    lstat_option_value.st_mode = S_IFREG;
    lstat_option_value.st_size = 12345678;
    lstat_hook_ret = 0;
    lstat_hook_errno = 0;
    ret = file_is_link("/dummy/file");
    if(ret != 0)
    {
        yatest_err("file_is_link returned %08x instead of %08x", ret, 0);
        return 1;
    }

    lstat_hook_ret = -1;
    lstat_hook_errno = EPERM;
    ret = file_is_link("/dummy/badpath");
    if(ret != MAKE_ERRNO_ERROR(EPERM))
    {
        yatest_err("file_is_link returned %08x instead of %08x", ret, MAKE_ERRNO_ERROR(EPERM));
        return 1;
    }

    finalise();
    return 0;
}

static int file_is_directory_test()
{
    init(true);
    glibchooks_set_or_die("lstat", lstat_hook);

    lstat_option_value.st_mode = S_IFDIR;
    lstat_option_value.st_size = 0;
    lstat_hook_ret = 0;
    lstat_hook_errno = 0;
    ya_result ret = file_is_directory("/dummy/directory");
    if(ret != 1)
    {
        yatest_err("file_is_directory returned %08x instead of %08x", ret, 1);
        return 1;
    }

    lstat_option_value.st_mode = S_IFREG;
    lstat_option_value.st_size = 12345678;
    lstat_hook_ret = 0;
    lstat_hook_errno = 0;
    ret = file_is_directory("/dummy/file");
    if(ret != 0)
    {
        yatest_err("file_is_directory returned %08x instead of %08x", ret, 0);
        return 1;
    }

    lstat_hook_ret = -1;
    lstat_hook_errno = EPERM;
    ret = file_is_directory("/dummy/badpath");
    if(ret != MAKE_ERRNO_ERROR(EPERM))
    {
        yatest_err("file_is_directory returned %08x instead of %08x", ret, MAKE_ERRNO_ERROR(EPERM));
        return 1;
    }

    finalise();
    return 0;
}

static int file_mtime_test()
{
    init(true);
    glibchooks_set_or_die("stat", stat_hook);

    stat_option_value.st_mode = S_IFREG;
    stat_option_value.st_size = 12345678;
    stat_option_value.st_mtim.tv_sec = 123456789;
    stat_option_value.st_mtim.tv_nsec = 987654321;
    stat_hook_ret = 0;
    stat_hook_errno = 0;
    int64_t   ts = -1;
    ya_result ret = file_mtime("/dummy/file", &ts);
    if(ret != 0)
    {
        yatest_err("file_mtime returned %08x instead of %08x", ret, 0);
        return 1;
    }
    if(ts != 123456789987654LL)
    {
        yatest_err("file_mtime ts = %016lx instead of %016lx", ts, 123456789987654LL);
        return 1;
    }

    stat_hook_ret = -1;
    stat_hook_errno = EPERM;
    ret = file_mtime("/dummy/file", &ts);
    if(ret != MAKE_ERRNO_ERROR(EPERM))
    {
        yatest_err("file_mtime returned %08x instead of %08x", ret, MAKE_ERRNO_ERROR(EPERM));
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static struct stat fstat_option_value = {0};
static int         fstat_hook_ret = 0;
static int         fstat_hook_errno = 0;

static void        fstat_hook(fstat_function_args_t *args)
{
    args->mask = 0x0f;
    if(args->statbuf != NULL)
    {
        *args->statbuf = fstat_option_value;
    }
    args->ret = fstat_hook_ret;
    args->errno_value = fstat_hook_errno;
}

static int fd_mtime_test()
{
    init(true);
    glibchooks_set_or_die("fstat", fstat_hook);

    fstat_option_value.st_mode = S_IFREG;
    fstat_option_value.st_size = 12345678;
    fstat_option_value.st_mtim.tv_sec = 123456789;
    fstat_option_value.st_mtim.tv_nsec = 987654321;
    fstat_hook_ret = 0;
    fstat_hook_errno = 0;
    int64_t   ts = -1;
    ya_result ret = fd_mtime(DUMMY_FD, &ts);
    if(ret != 0)
    {
        yatest_err("fd_mtime returned %08x instead of %08x", ret, 0);
        return 1;
    }
    if(ts != 123456789987654LL)
    {
        yatest_err("fd_mtime ts = %016lx instead of %016lx", ts, 123456789987654LL);
        return 1;
    }

    fstat_hook_ret = -1;
    fstat_hook_errno = EPERM;
    ret = fd_mtime(DUMMY_FD, &ts);
    if(ret != MAKE_ERRNO_ERROR(EPERM))
    {
        yatest_err("fd_mtime returned %08x instead of %08x", ret, MAKE_ERRNO_ERROR(EPERM));
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static const char **mkdir_hook_expected_path = NULL;
static int          mkdir_hook_expected_path_index = -1;
static int          mkdir_hook_ret = 0;
static int          mkdir_hook_errno = 0;

static void         mkdir_hook(mkdir_function_args_t *args)
{
    args->mask = 0x0f;
    yatest_log("mkdir(%s,%o)", args->pathname, args->mode);
    if((mkdir_hook_expected_path != NULL) && (mkdir_hook_expected_path_index >= 0))
    {
        if(strcmp(args->pathname, mkdir_hook_expected_path[mkdir_hook_expected_path_index]) != 0)
        {
            yatest_err("mkdir path '%s' but expected '%s'", args->pathname, mkdir_hook_expected_path[mkdir_hook_expected_path_index]);
            exit(1);
        }
        ++mkdir_hook_expected_path_index;
    }
    args->ret = mkdir_hook_ret;
    args->errno_value = mkdir_hook_errno;
}

static int mkdir_ex_test()
{
    init(true);
    glibchooks_set_or_die("stat", stat_hook);
    glibchooks_set_or_die("mkdir", mkdir_hook);

    static const char *mkdir_one_two_three_four[] = {"/one", "/one/two", "/one/two/three", "/one/two/three/four", "<nothing>"};
    mkdir_hook_expected_path = mkdir_one_two_three_four;
    mkdir_hook_expected_path_index = 0;
    stat_hook_ret = -1;
    stat_hook_errno = ENOENT;
    ya_result ret = mkdir_ex("/one/two/three/four/FILE", 0750, MKDIR_EX_PATH_TO_FILE);
    if(ret < 0)
    {
        yatest_err("mkdir_ex returned %08lx instead of %08lx", ret, 0);
        return 1;
    }

    mkdir_hook_expected_path_index = 0;
    ret = mkdir_ex("/one/two/three/four", 0750, 0);
    if(ret < 0)
    {
        yatest_err("mkdir_ex returned %08x instead of %08x", ret, 0);
        return 1;
    }

    mkdir_hook_expected_path_index = 0;
    ret = mkdir_ex("//one/two/three//four///", 0750, 0);
    if(ret < 0)
    {
        yatest_err("mkdir_ex returned %08x instead of %08x", ret, 0);
        return 1;
    }

    mkdir_hook_expected_path_index = 0;
    mkdir_hook_ret = -1;
    mkdir_hook_errno = EPERM;
    ret = mkdir_ex("//one/two/three//four///", 0750, 0);
    if(ret != MAKE_ERRNO_ERROR(EPERM))
    {
        yatest_err("mkdir_ex returned %08x instead of %08x", ret, MAKE_ERRNO_ERROR(EPERM));
        return 1;
    }

    mkdir_hook_expected_path_index = 0;
    stat_hook_ret = -1;
    stat_hook_errno = EPERM;
    ret = mkdir_ex("//one/two/three//four///", 0750, 0);
    if(ret != MAKE_ERRNO_ERROR(EPERM))
    {
        yatest_err("mkdir_ex returned %08x instead of %08x", ret, MAKE_ERRNO_ERROR(EPERM));
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int  fcntl_hook_ret = 0;
static int  fcntl_hook_errno = 0;

static void fcntl_hook(fcntl_function_args_t *args)
{
    if(args->fd != DUMMY_FD)
    {
        return;
    }
    args->mask = 0x1f;
    args->ret = fcntl_hook_ret;
    args->errno_value = fcntl_hook_errno;
}

static int fd_setcloseonexec_test()
{
    init(true);
    glibchooks_set_or_die("fcntl", fcntl_hook);

    int ret = fd_setcloseonexec(DUMMY_FD);
    if(ret != 0)
    {
        yatest_err("fd_setcloseonexec returned %08x instead of %08x", ret, 0);
        return 1;
    }

    fcntl_hook_ret = -1;
    fcntl_hook_errno = EBADF;
    ret = fd_setcloseonexec(DUMMY_FD);
    if(ret != MAKE_ERRNO_ERROR(EBADF))
    {
        yatest_err("fd_setcloseonexec returned %08x instead of %08x", ret, MAKE_ERRNO_ERROR(EBADF));
        return 1;
    }

    finalise();
    return 0;
}

static int fd_setnonblocking_test()
{
    init(true);
    glibchooks_set_or_die("fcntl", fcntl_hook);

    fcntl_hook_ret = O_RDWR;
    int ret = fd_setnonblocking(DUMMY_FD);
    if(ret != O_RDWR)
    {
        yatest_err("fd_setnonblocking returned %08x instead of %08x", ret, O_RDWR);
        return 1;
    }

    fcntl_hook_ret = -1;
    fcntl_hook_errno = EBADF;
    ret = fd_setnonblocking(DUMMY_FD);
    if(ret != MAKE_ERRNO_ERROR(EBADF))
    {
        yatest_err("fd_setnonblocking returned %08x instead of %08x", ret, MAKE_ERRNO_ERROR(EBADF));
        return 1;
    }

    finalise();
    return 0;
}

static int fd_setblocking_test()
{
    init(true);
    glibchooks_set_or_die("fcntl", fcntl_hook);

    fcntl_hook_ret = O_RDWR | O_NONBLOCK;
    int ret = fd_setblocking(DUMMY_FD);
    if(ret != (O_RDWR | O_NONBLOCK))
    {
        yatest_err("fd_setblocking returned %08x instead of %08x", ret, O_RDWR | O_NONBLOCK);
        return 1;
    }

    fcntl_hook_ret = -1;
    fcntl_hook_errno = EBADF;
    ret = fd_setblocking(DUMMY_FD);
    if(ret != MAKE_ERRNO_ERROR(EBADF))
    {
        yatest_err("fd_setblocking returned %08x instead of %08x", ret, MAKE_ERRNO_ERROR(EBADF));
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int dirent_get_file_type_test()
{
    init(true);
    glibchooks_set_or_die("stat", stat_hook);

    stat_option_value.st_mode = S_IFREG;
    stat_option_value.st_size = 12345678;
    stat_option_value.st_mtim.tv_sec = 123456789;
    stat_option_value.st_mtim.tv_nsec = 987654321;
    stat_hook_ret = 0;
    stat_hook_errno = 0;

    ya_result ret = dirent_get_file_type("/dummy", "file");
    if(ret != DT_REG)
    {
        yatest_err("fd_mtime returned %08x instead of %08x", ret, DT_REG);
        return 1;
    }

    stat_option_value.st_mode = S_IFDIR;
    stat_option_value.st_size = 0;
    stat_hook_ret = 0;
    stat_hook_errno = 0;

    ret = dirent_get_file_type("/dummy", "dir");
    if(ret != DT_DIR)
    {
        yatest_err("fd_mtime returned %08x instead of %08x", ret, DT_DIR);
        return 1;
    }

    stat_hook_ret = -1;
    stat_hook_errno = EPERM;

    ret = dirent_get_file_type("/dummy/error", "dir");
    if(ret != 0)
    {
        yatest_err("fd_mtime returned %08x instead of %08x", ret, 0);
        return 1;
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct my_DIR_s
{
    struct dirent entry;
    const char  **names;
    int           index;
};

static const char *dir0_names[] = {".", "..", "dir1", "two", "three", NULL};

static const char *dir1_names[] = {".", "..", "four", "five", "six", NULL};

static const char *dir3_names[] = {".", "..", "seven", NULL};

static void        opendir_hook(opendir_function_args_t *args)
{
    if(open_hook_errno == 0)
    {
        const char **names = NULL;

        if(strcmp(args->name, "dir0") == 0)
        {
            names = dir0_names;
        }
        else if(strcmp(args->name, "dir0/dir1") == 0)
        {
            names = dir1_names;
        }
        else if(strcmp(args->name, "dir3") == 0)
        {
            names = dir3_names;
        }

        if(names != NULL)
        {
            struct my_DIR_s *dir = malloc(sizeof(struct my_DIR_s));
            memset(dir, 0, sizeof(*dir));
            dir->names = names;
            args->mask = 0x07;
            args->ret = (DIR *)dir;
            args->errno_value = 0;
        }
        else
        {
            args->mask = 0x07;
            args->ret = NULL;
            args->errno_value = ENOENT;
        }
    }
    else
    {
        args->mask = 0x07;
        args->ret = NULL;
        args->errno_value = open_hook_errno;
    }
}

static void readdir_stat_hook(stat_function_args_t *args)
{
    args->mask = 0x0f;
    if(args->statbuf != NULL)
    {
        int i;
        int last = 0;
        for(i = 0; args->pathname[i] != '\0'; ++i)
        {
            if(args->pathname[i] == '/')
            {
                last = i + 1;
            }
        }
        if((args->pathname[last] == '.') || (args->pathname[last] == 'd'))
        {
            yatest_log("stat('%s') = dir", args->pathname);
            args->statbuf->st_mode = S_IFDIR;
        }
        else
        {
            yatest_log("stat('%s') = file", args->pathname);
            args->statbuf->st_mode = S_IFREG;
        }
    }
    args->ret = 0;
    args->errno_value = 0;
}

static void readdir_hook(readdir_function_args_t *args)
{
    struct my_DIR_s *dir = (struct my_DIR_s *)args->dirp;
    if(dir->names[dir->index] != NULL)
    {
        strcpy(dir->entry.d_name, dir->names[dir->index]);
        dir->entry.d_ino = dir->index * 7777;
        dir->entry.d_off = dir->index;
        dir->entry.d_reclen = 0;
        dir->entry.d_type = ((dir->entry.d_name[0] != 'd') && (dir->entry.d_name[0] != '.')) ? DT_REG : DT_DIR;
        args->mask = 0x07;
        args->ret = &dir->entry;
        args->errno_value = 0;
        ++dir->index;

        yatest_log("readdir: '%s' = %s", dir->entry.d_name, (dir->entry.d_type == DT_REG) ? "file" : "dir");
    }
    else
    {
        args->mask = 0x07;
        args->ret = NULL;
        args->errno_value = 0;
        yatest_log("readdir: done");
    }
}

static void closedir_hook(closedir_function_args_t *args)
{
    free(args->dirp);
    args->mask = 0x07;
    args->ret = 0;
    args->errno_value = 0;
}

static ya_result readdir_forall_test_callback(const char *basedir, const char *file, uint8_t filetype, void *args)
{
    yatest_log("readdir_forall_callback('%s', '%s', %i, %p)", basedir, file, filetype, args);

    if(strcmp(file, "dir1") == 0)
    {
        return READDIR_CALLBACK_ENTER;
    }
    else if(strcmp(file, "five") == 0)
    {
        return READDIR_CALLBACK_EXIT;
    }
    else
    {
        return READDIR_CALLBACK_CONTINUE;
    }
}

static int readdir_forall_test()
{
    init(true);
    glibchooks_set_or_die("stat", readdir_stat_hook);
    glibchooks_set_or_die("opendir", opendir_hook);
    glibchooks_set_or_die("readdir", readdir_hook);
    glibchooks_set_or_die("closedir", closedir_hook);

    ya_result ret = readdir_forall("dir0", readdir_forall_test_callback, NULL);
    if(ret < 0)
    {
        yatest_err("readfdir_forall returned an error code: %08x", ret);
        return ret;
    }

    ret = readdir_forall("dir3", readdir_forall_test_callback, NULL);
    if(ret < 0)
    {
        yatest_err("readfdir_forall returned an error code: %08x", ret);
        return ret;
    }

    ret = readdir_forall("dir2", readdir_forall_test_callback, NULL);
    if(ret != MAKE_ERRNO_ERROR(ENOENT))
    {
        yatest_err("readfdir_forall returned %08x instead of %08x", MAKE_ERRNO_ERROR(ENOENT));
        return ret;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int  access_hook_ret = 0;
static int  access_hook_errno = 0;

static void access_hook(access_function_args_t *args)
{
    args->mask = 0x0f;
    args->ret = access_hook_ret;
    args->errno_value = access_hook_errno;
}

static int access_check_test()
{
    init(true);
    glibchooks_set_or_die("access", access_hook);

    access_hook_ret = 0;
    access_hook_errno = 0;
    ya_result ret = access_check("dummy/file", R_OK | W_OK);
    if(ret != 0)
    {
        yatest_err("access_check returned %08 instead of %08x", ret, 0);
        return 1;
    }

    access_hook_ret = -1;
    access_hook_errno = EPERM;
    ret = access_check("dummy/file", R_OK | W_OK);
    if(ret != MAKE_ERRNO_ERROR(EPERM))
    {
        yatest_err("access_check returned %08 instead of %08x", ret, MAKE_ERRNO_ERROR(EPERM));
        return 1;
    }

    finalise();
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int mkstemp_test()
{
    init(false);
    char buffer[PATH_MAX] = "/tmp/dnscore-tests-mkstemp.XXXXXX";
    int  fd = mkstemp_ex(buffer);
    if(fd < 0)
    {
        int err = errno;
        yatest_err("mkstemp_ex(%s) failed with %i: %s", buffer, err, strerror(err));
        exit(1);
    }
    finalise();
    return 0;
}

static int  success_test() { return 0; }

static void rmdir_ex_test_mkdir(const char *path)
{
    if(mkdir(path, 0750) < 0)
    {
        perror(path);
        exit(1);
    }
}

static void rmdir_ex_test_touch(const char *path)
{
    int fd;
    if((fd = open("/tmp/fdtools-test/rmdir_ex-test/f0", O_RDWR | O_CREAT, 0640)) < 0)
    {
        perror(path);
        exit(1);
    }
    close_ex(fd);
}

static int rmdir_ex_test()
{
    ya_result ret;

    rmdir_ex("/tmp/fdtools-test", true);

    rmdir_ex_test_mkdir("/tmp/fdtools-test");
    rmdir_ex_test_mkdir("/tmp/fdtools-test/rmdir_ex-test");
    rmdir_ex_test_mkdir("/tmp/fdtools-test/rmdir_ex-test/a");
    rmdir_ex_test_mkdir("/tmp/fdtools-test/rmdir_ex-test/b");
    rmdir_ex_test_mkdir("/tmp/fdtools-test/rmdir_ex-test/c");
    rmdir_ex_test_touch("/tmp/fdtools-test/rmdir_ex-test/f0");
    rmdir_ex_test_touch("/tmp/fdtools-test/rmdir_ex-test/a/f1");
    rmdir_ex_test_touch("/tmp/fdtools-test/rmdir_ex-test/b/f2");
    rmdir_ex_test_touch("/tmp/fdtools-test/rmdir_ex-test/b/f3");

    if((ret = rmdir_ex("/tmp/fdtools-test", true)) < 0)
    {
        yatest_err("rmdir_ex failed with %08x", ret);
    }

    if((ret = rmdir_ex("/tmp/fdtools-test", true)) >= 0)
    {
        yatest_err("rmdir_ex expected to fail");
    }

    return 0;
}

YATEST_TABLE_BEGIN
YATEST(success_test)
YATEST(readfully_test)
YATEST(readfully_error_short_read_test)
YATEST(readfully_error_zero_read_test)
YATEST(readfully_limited_test)
YATEST(readfully_limited_slow_test)
YATEST(readfully_limited_error_short_read_test)
YATEST(readfully_limited_error_zero_read_test)
YATEST(readfully_limited_ex_test)
YATEST(readfully_limited_ex_slow_test)
YATEST(readfully_limited_ex_error_short_read_test)
YATEST(readfully_limited_ex_error_zero_read_test)
YATEST(writefully_test)
YATEST(writefully_limited_test)
YATEST(writefully_limited_slow_test)
YATEST(sendfully_limited_test)
YATEST(sendfully_limited_slow_test)
YATEST(recvfully_limited_ex_test)
YATEST(recvfully_limited_ex_slow_test)
YATEST(readtextline_test)
YATEST(unlink_ex_test)
YATEST(file_get_absolute_path_test)
YATEST(file_get_absolute_parent_directory_test)
YATEST(open_ex_test)
YATEST(open_create_ex_test)
YATEST(open_create_ex_nolog_test)
YATEST(close_ex_test)
YATEST(socketclose_ex_test)
YATEST(close_ex_nolog_test)
YATEST(fsync_ex_test)
YATEST(fdatasync_ex_test)
YATEST(dup_ex_test)
YATEST(dup2_ex_test)
YATEST(truncate_ex_test)
YATEST(ftruncate_ex_test)
YATEST(fd_getsockettype_test)
YATEST(filesize_test)
YATEST(file_exists_test)
YATEST(file_is_link_test)
YATEST(file_is_directory_test)
YATEST(mkdir_ex_test)
YATEST(file_mtime_test)
YATEST(fd_mtime_test)
YATEST(fd_setcloseonexec_test)
YATEST(fd_setnonblocking_test)
YATEST(fd_setblocking_test)
YATEST(dirent_get_file_type_test)
YATEST(readdir_forall_test)
YATEST(access_check_test)
YATEST(mkstemp_test)
YATEST(rmdir_ex_test)
YATEST_TABLE_END
