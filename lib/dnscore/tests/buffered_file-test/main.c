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
#include <dnscore/buffered_file.h>
#include <dnscore/filesystem_file.h>

#define FILE_SIZE 4096

static file_t                fsf;
static file_t                bf;
static buffered_file_cache_t cache;
static uint8_t               bytes[FILE_SIZE];

static void                  init(uint32_t count, uint8_t log2g, bool map)
{
    int  ret;
    char filename[PATH_MAX];
    dnscore_init();

    // creates a file with random content (yatest_random_input_stream)

    yatest_file_create(FILE_SIZE);
    yatest_file_getname(FILE_SIZE, filename, sizeof(filename));

    // creates a copy of the expected content of the test file

    input_stream_t ris;
    yatest_random_input_stream_init(&ris, FILE_SIZE);
    input_stream_read(&ris, bytes, sizeof(bytes));
    input_stream_close(&ris);

    ret = filesystem_file_open_ex(&fsf, filename, O_RDWR);
    if(FAIL(ret))
    {
        yatest_err("filesystem_file_open_ex('%s') failed with %s", filename, error_gettext(ret));
        exit(1);
    }

    if(file_size(fsf) != FILE_SIZE)
    {
        yatest_err("file_size(filesystem) returned %i instead of %i", file_size(bf), FILE_SIZE);
        exit(1);
    }

    cache = buffered_file_cache_new_instance("test", count, log2g, map);
    if(cache == NULL)
    {
        yatest_err("buffered_file_cache_new_instance(%u,%u,%i) failed", count, log2g, map);
        exit(1);
    }

    ret = buffered_file_init(&bf, fsf, cache);
    buffered_file_cache_delete(cache);
    if(FAIL(ret))
    {
        yatest_err("buffered_file_init() failed with %s", error_gettext(ret));
        exit(1);
    }

    if(file_size(bf) != FILE_SIZE)
    {
        yatest_err("file_size(buffered) returned %i instead of %i", file_size(bf), FILE_SIZE);
        exit(1);
    }
}

static int loop_read_n_test(uint32_t dummy_size, uint32_t count, uint8_t log2g, bool map)
{
    int      ret;
    uint8_t *dummy = (uint8_t *)malloc(dummy_size);

    init(count, log2g, map);

    // read

    for(int j = 0; j < 2; ++j)
    {
        for(int i = 0; i < file_size(bf); i += dummy_size)
        {
            if(file_tell(bf) != i)
            {
                yatest_err("loop%u(%u,%u,%i) loop %i, position %i file_tell returned %i instead of %i", dummy_size, count, log2g, map, j, i, file_tell(bf), i);
                free(dummy);
                return 1;
            }

            ret = file_read(bf, dummy, dummy_size);
            if(FAIL(ret))
            {
                yatest_err("loop%u(%u,%u,%i) loop %i, position %i file_read failed with %s", dummy_size, count, log2g, map, j, i, error_gettext(ret));
                free(dummy);
                return 1;
            }
            if(ret != (int)dummy_size)
            {
                yatest_err("loop%u(%u,%u,%i) loop %i, position %i file_read didn't read %i bytes", dummy_size, count, log2g, map, j, i, dummy_size);
                free(dummy);
                return 1;
            }
            if(memcmp(&bytes[i], dummy, dummy_size) != 0)
            {
                yatest_err("loop%u(%u,%u,%i) loop %i, position %i expectations differ", dummy_size, count, log2g, map, j, i);
                yatest_log("got");
                yatest_hexdump(dummy, dummy + dummy_size);
                yatest_log("expected");
                yatest_hexdump(&bytes[i], &bytes[i] + dummy_size);
                free(dummy);
                return 1;
            }
        }

        file_seek(bf, 0, SEEK_SET);
    }

    file_close(bf);

    free(dummy);

    return 0;
}

static int loop_write_n_test_inner(uint32_t dummy_size, uint32_t count, uint8_t log2g, bool map)
{
    int      ret;
    uint8_t *dummy = (uint8_t *)malloc(dummy_size);

    // read

    for(int j = 0; j < 2; ++j)
    {
        for(int i = 0; i < file_size(bf); i += dummy_size)
        {
            for(int k = 0; k < (int)dummy_size; ++k)
            {
                dummy[k] = (j + 1) * 7 + (i + 1) * 5 + k;
            }

            ret = file_write(bf, dummy, dummy_size);

            if(FAIL(ret))
            {
                yatest_err("loop%u(%u,%u,%i) %i, %i file_read failed with %s", dummy_size, count, log2g, map, j, i, error_gettext(ret));
                free(dummy);
                return 1;
            }
        }

        file_seek(bf, 0, SEEK_SET);

        for(int i = 0; i < file_size(bf); i += dummy_size)
        {
            ret = file_read(bf, dummy, dummy_size);
            if(FAIL(ret))
            {
                yatest_err("loop%u(%u,%u,%i) %i, %i file_read failed with %s", dummy_size, count, log2g, map, j, i, error_gettext(ret));
                free(dummy);
                return 1;
            }

            for(int k = 0; k < (int)dummy_size; ++k)
            {
                uint8_t expected = (j + 1) * 7 + (i + 1) * 5 + k;
                if(dummy[k] != expected)
                {
                    yatest_err("loop%u(%u,%u,%i) %i, %i differs from expectations: got %i, expected %i", dummy_size, count, log2g, map, j, i + k, dummy[k], expected);
                    free(dummy);
                    return 1;
                }
            }
        }

        file_seek(bf, 0, SEEK_SET);
    }

    file_close(bf);

    free(dummy);
    return 0;
}

static int loop_write_n_test(uint32_t dummy_size, uint32_t count, uint8_t log2g, bool map)
{
    init(count, log2g, map);

    return loop_write_n_test_inner(dummy_size, count, log2g, map);
}

static int loop_read_1_4_256_test() { return loop_read_n_test(1, 4, 8, false); }

static int loop_read_1_1_256_test() { return loop_read_n_test(1, 1, 8, false); }

static int loop_read_1_4_256_map_test() { return loop_read_n_test(1, 4, 8, true); }

static int loop_read_1_1_256_map_test() { return loop_read_n_test(1, 1, 8, true); }

static int loop_read_512_4_256_test() { return loop_read_n_test(512, 4, 8, false); }

static int loop_read_512_1_256_test() { return loop_read_n_test(512, 1, 8, false); }

static int loop_read_512_4_256_map_test() { return loop_read_n_test(512, 4, 8, true); }

static int loop_read_512_1_256_map_test() { return loop_read_n_test(512, 1, 8, true); }

static int loop_write_1_4_256_test() { return loop_write_n_test(1, 4, 8, false); }

static int loop_write_1_1_256_test() { return loop_write_n_test(1, 1, 8, false); }

static int loop_write_1_4_256_map_test() { return loop_write_n_test(1, 4, 8, true); }

static int loop_write_1_1_256_map_test() { return loop_write_n_test(1, 1, 8, true); }

static int loop_write_512_4_256_test() { return loop_write_n_test(512, 4, 8, false); }

static int loop_write_512_1_256_test() { return loop_write_n_test(512, 1, 8, false); }

static int loop_write_512_4_256_map_test() { return loop_write_n_test(512, 4, 8, true); }

static int loop_write_512_1_256_map_test() { return loop_write_n_test(512, 1, 8, true); }

static int resize_grow_test()
{
    int      ret;
    uint32_t count = 4;
    uint8_t  log2g = 8;
    bool     map = false;
    init(count, log2g, map);
    ret = file_resize(bf, FILE_SIZE * 8);
    if(FAIL(ret))
    {
        yatest_err("file_resize failed with %s", error_gettext(ret));
        return 1;
    }

    return loop_write_n_test_inner(FILE_SIZE * 8, count, log2g, map);
}

static int resize_shrink_test()
{
    int      ret;
    uint32_t count = 4;
    uint8_t  log2g = 8;
    bool     map = false;
    init(count, log2g, map);
    ret = file_resize(bf, FILE_SIZE / 2);
    if(FAIL(ret))
    {
        yatest_err("file_resize failed with %s", error_gettext(ret));
        return 1;
    }

    return loop_write_n_test_inner(FILE_SIZE / 2, count, log2g, map);
}

static int seek_test()
{
    int      ret;
    uint32_t count = 4;
    uint8_t  log2g = 8;
    bool     map = false;
    uint8_t  dummy[1];

    init(count, log2g, map);

    ret = file_seek(bf, 0, SEEK_END);

    if(FAIL(ret))
    {
        yatest_err("file_seek(SEEK_END) failed with %s", error_gettext(ret));
        return 1;
    }

    if(file_tell(bf) != file_size(bf))
    {
        yatest_err("file_seek(SEEK_END) failed: file_tell returned %i instead of %i", file_tell(bf), file_size(bf));
        return 1;
    }

    for(int i = file_size(bf) - 1; i >= 0; --i)
    {
        ret = file_seek(bf, -1, SEEK_CUR);

        if(FAIL(ret))
        {
            yatest_err("file_seek(SEEK_CUR) failed with %s", error_gettext(ret));
            return 1;
        }

        if(file_tell(bf) != i)
        {
            yatest_err("file_seek(SEEK_CUR) failed: file_tell returned %i instead of %i", file_tell(bf), i);
            return 1;
        }

        ret = file_read(bf, dummy, 1);

        if(FAIL(ret))
        {
            yatest_err("file_read failed with %s", error_gettext(ret));
            return 1;
        }

        if(ret != 1)
        {
            yatest_err("file_read didn't return 1 (got %i)", ret);
            return 1;
        }

        if(dummy[0] != bytes[i])
        {
            yatest_err("byte read at position %i differs from expectations: got %i, expected %i", i, dummy[0], bytes[i]);
            return 1;
        }

        ret = file_seek(bf, -1, SEEK_CUR);

        if(FAIL(ret))
        {
            yatest_err("file_seek(SEEK_CUR) failed with %s", error_gettext(ret));
            return 1;
        }

        if(file_tell(bf) != i)
        {
            yatest_err("file_seek(SEEK_CUR) failed: file_tell returned %i instead of %i", file_tell(bf), i);
            return 1;
        }
    }

    // relative with end

    ret = file_seek(bf, -file_size(bf), SEEK_END);
    if(FAIL(ret))
    {
        yatest_err("file_seek(-size, SEEK_END) failed with %s", error_gettext(ret));
        return 1;
    }
    ret = file_tell(bf);
    if(ret != 0)
    {
        yatest_err("expected SEEK_END of -size to set position to 0 instead of %i", ret);
        return 1;
    }

    ret = file_seek(bf, 0, SEEK_END);
    if(FAIL(ret))
    {
        yatest_err("file_seek(0, SEEK_END) failed with %s", error_gettext(ret));
        return 1;
    }

    // relative with cur

    ret = file_seek(bf, -file_size(bf), SEEK_CUR);
    if(FAIL(ret))
    {
        yatest_err("file_seek(-size, SEEK_CUR) failed with %s", error_gettext(ret));
        return 1;
    }
    ret = file_tell(bf);
    if(ret != 0)
    {
        yatest_err("expected SEEK_CUR of -size to set position to 0 instead of %i", ret);
        return 1;
    }
    ret = file_seek(bf, 0, SEEK_END);
    if(FAIL(ret))
    {
        yatest_err("file_seek(0, SEEK_END) failed with %s", error_gettext(ret));
        return 1;
    }

    // relative overflow with end

    ret = file_seek(bf, -file_size(bf) - 1, SEEK_END);
    if(FAIL(ret))
    {
        yatest_err("file_seek(-size-1, SEEK_END) failed with %s", error_gettext(ret));
        return 1;
    }
    ret = file_tell(bf);
    if(ret != 0)
    {
        yatest_err("expected SEEK_END of -size to set position to 0 instead of %i", ret);
        return 1;
    }

    ret = file_seek(bf, 0, SEEK_END);
    if(FAIL(ret))
    {
        yatest_err("file_seek(0, SEEK_END) failed with %s", error_gettext(ret));
        return 1;
    }

    // relative with cur

    ret = file_seek(bf, -file_size(bf) - 1, SEEK_CUR);
    if(FAIL(ret))
    {
        yatest_err("file_seek(-size-1, SEEK_CUR) failed with %s", error_gettext(ret));
        return 1;
    }
    ret = file_tell(bf);
    if(ret != 0)
    {
        yatest_err("expected SEEK_CUR of -size to set position to 0 instead of %i", ret);
        return 1;
    }
    ret = file_seek(bf, 0, SEEK_END);
    if(FAIL(ret))
    {
        yatest_err("file_seek(0, SEEK_END) failed with %s", error_gettext(ret));
        return 1;
    }

    file_close(bf);
    return 0;
}

static int error_test()
{
    int      ret;
    uint32_t count = 4;
    uint8_t  log2g = 8;
    bool     map = false;
    char     filename[PATH_MAX];
    dnscore_init();

    // creates a file with random content (yatest_random_input_stream)

    yatest_file_create(FILE_SIZE);
    yatest_file_getname(FILE_SIZE, filename, sizeof(filename));

    // creates a copy of the expected content of the test file

    input_stream_t ris;
    yatest_random_input_stream_init(&ris, FILE_SIZE);
    input_stream_read(&ris, bytes, sizeof(bytes));
    input_stream_close(&ris);

    ret = filesystem_file_open_ex(&fsf, filename, O_RDWR);
    if(FAIL(ret))
    {
        yatest_err("filesystem_file_open_ex('%s') failed with %s", filename, error_gettext(ret));
        return 1;
    }

    if(file_size(fsf) != FILE_SIZE)
    {
        yatest_err("file_size(filesystem) returned %i instead of %i", file_size(bf), FILE_SIZE);
        return 1;
    }

    cache = buffered_file_cache_new_instance("test", count, 255, map);
    if(cache != NULL)
    {
        yatest_err("buffered_file_cache_new_instance(%u,%u,%i) should have failed", count, 255, map);
        return 1;
    }

    cache = buffered_file_cache_new_instance("test", count, log2g, map);
    if(cache == NULL)
    {
        yatest_err("buffered_file_cache_new_instance(%u,%u,%i) failed", count, log2g, map);
        return 1;
    }

    ret = buffered_file_init(&bf, NULL, NULL);
    if(ISOK(ret))
    {
        yatest_err("buffered_file_init should have failed");
        return 1;
    }

    ret = buffered_file_init(&bf, fsf, cache);
    buffered_file_cache_delete(cache);
    if(FAIL(ret))
    {
        yatest_err("buffered_file_init failed with %s", error_gettext(ret));
        return 1;
    }

    ret = file_resize(bf, -1);
    if(ISOK(ret))
    {
        yatest_err("file_resize should have failed");
        return 1;
    }

    ret = file_seek(bf, 0, -1);
    if(ISOK(ret))
    {
        yatest_err("file_seek should have failed");
        return 1;
    }
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(loop_read_1_4_256_test)
YATEST(loop_read_1_1_256_test)
YATEST(loop_read_1_4_256_map_test)
YATEST(loop_read_1_1_256_map_test)
YATEST(loop_read_512_4_256_test)
YATEST(loop_read_512_1_256_test)
YATEST(loop_read_512_4_256_map_test)
YATEST(loop_read_512_1_256_map_test)
YATEST(loop_write_1_4_256_test)
YATEST(loop_write_1_1_256_test)
YATEST(loop_write_1_4_256_map_test)
YATEST(loop_write_1_1_256_map_test)
YATEST(loop_write_512_4_256_test)
YATEST(loop_write_512_1_256_test)
YATEST(loop_write_512_4_256_map_test)
YATEST(loop_write_512_1_256_map_test)
YATEST(resize_grow_test)
YATEST(resize_shrink_test)
YATEST(seek_test)
YATEST(error_test)
YATEST_TABLE_END
