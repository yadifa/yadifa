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

#include <dnscore/dnscore.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/fdtools.h>
#include <fcntl.h>

#define TEST_FILE_SIZE 64

static int file_output_stream_factory(output_stream_t *os, uint32_t *in_out_size)
{
    char filename[64];
    yatest_file_getname(*in_out_size, filename, sizeof(filename));
    unlink(filename);
    int ret = file_output_stream_create(os, filename, 0644);
    if(FAIL(ret))
    {
        yatest_err("file_output_stream_create_excl('%s') failed with %s", filename, error_gettext(ret));
        exit(1);
    }
    file_output_stream_set_full_writes(os, false);
    return 0;
}

static int file_output_stream_excl_factory(output_stream_t *os, uint32_t *in_out_size)
{
    char filename[64];
    yatest_file_getname(*in_out_size, filename, sizeof(filename));
    unlink(filename);
    int ret = file_output_stream_create_excl(os, filename, 0644);
    if(FAIL(ret))
    {
        yatest_err("file_output_stream_create_excl('%s') failed with %s", filename, error_gettext(ret));
        exit(1);
    }
    return 0;
}

static int file_output_stream_fully_factory(output_stream_t *os, uint32_t *in_out_size)
{
    file_output_stream_factory(os, in_out_size);
    file_output_stream_set_full_writes(os, true);
    return 0;
}

static int file_output_stream_noclose_factory(output_stream_t *os, uint32_t *in_out_size)
{
    file_output_stream_factory(os, in_out_size);
    int fd = fd_output_stream_get_filedescriptor(os);
    fd_output_stream_detach(os);
    fd_output_stream_attach_noclose(os, fd);
    return 0;
}

static int file_output_stream_open_factory(output_stream_t *os, uint32_t *in_out_size)
{
    char filename[64];
    yatest_file_getname(*in_out_size, filename, sizeof(filename));
    unlink(filename);
    yatest_file_create_empty(*in_out_size);
    int ret = file_output_stream_open(os, filename);
    if(FAIL(ret))
    {
        yatest_err("file_output_stream_create_excl('%s') failed with %s", filename, error_gettext(ret));
        exit(1);
    }
    file_output_steam_advise_sequential(os);
    return 0;
}

static int file_output_stream_nolog_factory(output_stream_t *os, uint32_t *in_out_size)
{
    char filename[64];
    yatest_file_getname(*in_out_size, filename, sizeof(filename));
    unlink(filename);
    yatest_file_create_empty(*in_out_size);
    int ret = file_output_stream_open_ex_nolog(os, filename, O_RDWR, 0644);
    if(FAIL(ret))
    {
        yatest_err("file_output_stream_open_ex_nolog('%s') failed with %s", filename, error_gettext(ret));
        exit(1);
    }
    return 0;
}

static int file_output_stream_close_readback(output_stream_t *os, void **bufferp, size_t *buffer_sizep)
{
    if(!is_fd_output_stream(os))
    {
        yatest_err("file_output_stream_close_readback: stream is not a file_output_stream");
        exit(1);
    }

    int     fd = fd_output_stream_get_filedescriptor(os);

    int64_t file_size = fd_output_stream_get_size(os);

    off_t   pos = lseek(fd, 0, SEEK_CUR);

    if(file_size != pos)
    {
        yatest_err("position (%i) and size (%lli) do not match)", pos, file_size);
        exit(1);
    }

    *buffer_sizep = pos;
    void *buffer = (void *)malloc(*buffer_sizep);
    *bufferp = buffer;
    lseek(fd, 0, SEEK_SET);
    ssize_t n = readfully(fd, buffer, pos);
    if(n != pos)
    {
        yatest_err("readfully failed to read %i bytes (%i instead)", pos, n);
        exit(1);
    }

    bool noclose = fd_output_stream_is_noclose_instance(os);

    output_stream_close(os);

    if(noclose)
    {
        close_ex(fd);
    }

    return 0;
}

static int file_output_stream_nolog_close_readback(output_stream_t *os, void **bufferp, size_t *buffer_sizep)
{
    if(!is_fd_output_stream(os))
    {
        yatest_err("file_output_stream_close_readback: stream is not a file_output_stream");
        exit(1);
    }

    int   fd = fd_output_stream_get_filedescriptor(os);
    off_t pos = lseek(fd, 0, SEEK_CUR);
    *buffer_sizep = pos;
    void *buffer = (void *)malloc(*buffer_sizep);
    *bufferp = buffer;
    lseek(fd, 0, SEEK_SET);
    ssize_t n = readfully(fd, buffer, pos);
    if(n != pos)
    {
        yatest_err("readfully failed to read %i bytes (%i instead)", pos, n);
        exit(1);
    }

    bool noclose = fd_output_stream_is_noclose_instance(os);

    file_output_stream_close_nolog(os);

    if(noclose)
    {
        close_ex(fd);
    }

    return 0;
}

static int write_consistency_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(file_output_stream_factory, file_output_stream_close_readback, TEST_FILE_SIZE, 1, TEST_FILE_SIZE + 1 + 1, 1, "file_output_stream");
    return ret;
}

static int write_open_consistency_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(file_output_stream_open_factory, file_output_stream_close_readback, TEST_FILE_SIZE, 1, TEST_FILE_SIZE + 1 + 1, 1, "file_output_stream");
    return ret;
}

static int write_excl_consistency_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(file_output_stream_excl_factory, file_output_stream_close_readback, TEST_FILE_SIZE, 1, TEST_FILE_SIZE + 1 + 1, 1, "file_output_stream");
    return ret;
}

static int write_fully_consistency_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(file_output_stream_fully_factory, file_output_stream_close_readback, TEST_FILE_SIZE, 1, TEST_FILE_SIZE + 1 + 1, 1, "file_output_stream");
    return ret;
}

static int write_nolog_consistency_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(file_output_stream_nolog_factory, file_output_stream_nolog_close_readback, TEST_FILE_SIZE, 1, TEST_FILE_SIZE + 1 + 1, 1, "file_output_stream");
    return ret;
}

static int write_noclose_consistency_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(file_output_stream_noclose_factory, file_output_stream_close_readback, TEST_FILE_SIZE, 1, TEST_FILE_SIZE + 1 + 1, 1, "file_output_stream");
    return ret;
}

YATEST_TABLE_BEGIN
YATEST(write_consistency_test)
YATEST(write_excl_consistency_test)
YATEST(write_open_consistency_test)
YATEST(write_fully_consistency_test)
YATEST(write_nolog_consistency_test)
YATEST(write_noclose_consistency_test)
YATEST_TABLE_END
