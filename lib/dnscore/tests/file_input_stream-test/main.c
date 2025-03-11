/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
#include "yatest_stream.h"

#include <stdio.h>

#include <dnscore/dnscore.h>
#include <dnscore/file_input_stream.h>
#include <fcntl.h>

static int file_input_stream_factory(input_stream_t *is, uint32_t *in_out_size)
{
    char filename[64];
    yatest_file_getname(*in_out_size, filename, sizeof(filename));
    yatest_file_create(*in_out_size);
    int ret = file_input_stream_open(is, filename);
    return ret;
}

static int file_input_stream_factory_ex(input_stream_t *is, uint32_t *in_out_size)
{
    char filename[64];
    yatest_file_getname(*in_out_size, filename, sizeof(filename));
    yatest_file_create(*in_out_size);
    int ret = file_input_stream_open_ex(is, filename, 0);
    return ret;
}

static int file_input_stream_factory_fd(input_stream_t *is, uint32_t *in_out_size)
{
    char filename[64];
    yatest_file_getname(*in_out_size, filename, sizeof(filename));
    yatest_file_create(*in_out_size);
    int fd = open(filename, O_RDONLY);
    if(fd < 0)
    {
        yatest_err("file_input_stream_factory_fd: failed to open file", strerror(errno));
        return 1;
    }
    int ret = fd_input_stream_attach(is, fd);
    return ret;
}

static int file_input_stream_factory_fd_noclose(input_stream_t *is, uint32_t *in_out_size)
{
    char filename[64];
    yatest_file_getname(*in_out_size, filename, sizeof(filename));
    yatest_file_create(*in_out_size);
    int fd = open(filename, O_RDONLY);
    if(fd < 0)
    {
        yatest_err("file_input_stream_factory_fd: failed to open file", strerror(errno));
        return 1;
    }
    int ret = fd_input_stream_attach_noclose(is, fd);
    return ret;
}

static int file_input_stream_factoryempty(input_stream_t *is, uint32_t *in_out_size)
{
    *in_out_size = 0;
    char filename[64];
    yatest_file_getname(*in_out_size, filename, sizeof(filename));
    yatest_file_create(*in_out_size);
    int ret = file_input_stream_open(is, filename);
    return ret;
}

static int read_consistencyempty_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(file_input_stream_factoryempty, 4096, 1, 4097 + 1, 1, "file_input_stream");
    if(ret != 0)
    {
        yatest_err("read_consistencyempty_test failed");
        return ret;
    }
    return 0;
}

static int read_consistency4096_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(file_input_stream_factory, 4096, 1, 4097 * 3 + 1, 1, "file_input_stream");
    if(ret != 0)
    {
        yatest_err("read_consistency4096_test failed");
        return ret;
    }

    yatest_file_delete(4096);

    return 0;
}

static int read_consistency4096ex_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(file_input_stream_factory_ex, 4096, 1, 4097 * 3 + 1, 1, "file_input_stream");
    if(ret != 0)
    {
        yatest_err("read_consistency4096ex_test failed");
        return ret;
    }

    yatest_file_delete(4096);

    return 0;
}

static int read_consistency4096fd_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(file_input_stream_factory_fd, 4096, 1, 4097 * 3 + 1, 1, "file_input_stream");
    if(ret != 0)
    {
        yatest_err("read_consistency4096fd_test failed");
        return ret;
    }

    yatest_file_delete(4096);

    return 0;
}

static int read_consistency4096fdnc_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(file_input_stream_factory_fd_noclose, 4096, 1, 4097 * 3 + 1, 111, "file_input_stream");
    if(ret != 0)
    {
        yatest_err("read_consistency4096fdnc_test failed");
        return ret;
    }

    yatest_file_delete(4096);

    return 0;
}

static int read_consistency1_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(file_input_stream_factory, 1, 1, 7, 1, "file_input_stream");
    if(ret != 0)
    {
        yatest_err("read_consistency1_test failed");
        return ret;
    }

    yatest_file_delete(1);

    return 0;
}

static int skip_consistency4096_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_skip_consistency_test(file_input_stream_factory, 4096, 1, 4097 * 3 + 1, 1, "file_input_stream");
    if(ret != 0)
    {
        yatest_err("skip_consistency4096_test failed");
        return ret;
    }

    yatest_file_delete(4096);

    return 0;
}

static int skip_consistency1_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_skip_consistency_test(file_input_stream_factory, 1, 1, 7, 1, "file_input_stream");
    if(ret != 0)
    {
        yatest_err("skip_consistency1_test failed");
        return ret;
    }

    yatest_file_delete(1);

    return 0;
}

static int features_test()
{
    int ret;
    dnscore_init();
    int            size = 4096;

    input_stream_t is;
    char           filename[64];
    yatest_file_getname(4096, filename, sizeof(filename));
    yatest_file_create(4096);
    ret = file_input_stream_open_ex(&is, filename, 0);
    if(ret != 0)
    {
        yatest_err("features_test: open '%s' failed", filename);
        return 1;
    }

    int fd = fd_input_stream_get_filedescriptor(&is);
    yatest_log("features_test: fd=%i", fd);
    if((fd < 0) || (fd > 8))
    {
        yatest_err("features_test: fd_input_stream_get_filedescriptor '%s' returned a value out of the expected range", filename, fd);
        return 1;
    }

    if(!is_fd_input_stream(&is))
    {
        yatest_err("features_test: is_fd_input_stream '%s' returned false when it should have returned true", filename);
        return 1;
    }

    input_stream_t ris;
    yatest_random_input_stream_init(&ris, 0);

    if(is_fd_input_stream(&ris))
    {
        yatest_err("features_test: is_fd_input_stream '%s' returned true when it should have returned false", filename);
        return 1;
    }

    file_input_steam_advise_sequential(&is);

    char *buffer0 = (char *)malloc(4096);
    char *buffer1 = (char *)malloc(4096);
    input_stream_read_fully(&is, buffer0, size);
    ret = fd_input_stream_seek(&is, 0);
    if(ret != 0)
    {
        yatest_err("features_test: fd_input_stream_seek '%s' ret=%i/%08x", filename, ret, ret);
        return 1;
    }
    input_stream_read_fully(&is, buffer1, size);

    fd_input_stream_detach(&is);

    ret = fd_input_stream_get_filedescriptor(&is);
    if(ret >= 0)
    {
        yatest_err("features_test: fd_input_stream_get_filedescriptor '%s' expected to return an error, got %i instead", filename, ret);
        return 1;
    }

    input_stream_close(&is);

    ret = fd_input_stream_attach(&is, -1);
    if(ret >= 0)
    {
        yatest_err("features_test: fd_input_stream_attach of an invalid fd expected to return an error, got %i instead", ret);
        return 1;
    }

    return 0;
}

static int error_test()
{
    input_stream_t is;
    uint32_t       size = 4096;
    char           dummy[1];
    file_input_stream_factory_fd(&is, &size);
    int fd = fd_input_stream_get_filedescriptor(&is);
    fd_input_stream_detach(&is);
    int ret = input_stream_read(&is, dummy, sizeof(dummy));
    if(ret >= 0)
    {
        yatest_err("error_test: input_stream_read expected to return an error but got %i instead", ret);
        return 1;
    }
    input_stream_close(&is);
    yatest_close_nointr(fd);
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(read_consistencyempty_test)
YATEST(read_consistency4096_test)
YATEST(read_consistency4096ex_test)
YATEST(read_consistency4096fd_test)
YATEST(read_consistency4096fdnc_test)
YATEST(read_consistency1_test)
YATEST(skip_consistency4096_test)
YATEST(skip_consistency1_test)
YATEST(features_test)
YATEST(error_test)
YATEST_TABLE_END
