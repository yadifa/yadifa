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
#include "yatest_stream.h"

#include <dnscore/dnscore.h>
#include <dnscore/mapped_file.h>

#define FILE_SIZE 4096

static file_t  fsf;
static uint8_t bytes[FILE_SIZE];

static void    init(uint8_t open_mode)
{
    int  ret;
    char filename[PATH_MAX];
    dnscore_init();

    // creates a copy of the expected content of the test file

    input_stream_t ris;
    yatest_random_input_stream_init(&ris, FILE_SIZE);
    input_stream_read(&ris, bytes, sizeof(bytes));
    input_stream_close(&ris);

    // creates a file with random content (yatest_random_input_stream)

    yatest_file_getname(FILE_SIZE, filename, sizeof(filename));

    switch(open_mode)
    {
        case 0:
        {
            yatest_file_create(FILE_SIZE);

            ret = mapped_file_open_ex(&fsf, filename, O_RDWR);
            if(FAIL(ret))
            {
                yatest_err("mapped_file_open_ex('%s') failed with %s", filename, error_gettext(ret));
                exit(1);
            }
            break;
        }
        case 1:
        {
            unlink(filename);
            ret = mapped_file_create_ex(&fsf, filename, O_RDWR, 0644);
            if(FAIL(ret))
            {
                yatest_err("mapped_file_create_ex('%s') failed with %s", filename, error_gettext(ret));
                exit(1);
            }

            file_write(fsf, bytes, sizeof(bytes));
            file_seek(fsf, 0, SEEK_SET);
            break;
        }
        case 2:
        {
            unlink(filename);
            ret = mapped_file_create_volatile(&fsf, filename, FILE_SIZE);
            if(FAIL(ret))
            {
                yatest_err("mapped_file_create_volatile('%s') failed with %s", filename, error_gettext(ret));
                exit(1);
            }

            file_write(fsf, bytes, sizeof(bytes));
            file_seek(fsf, 0, SEEK_SET);
            break;
        }
        default:
        {
            yatest_err("open_mode is invalid: %i", open_mode);
            exit(1);
        }
    }

    if(file_size(fsf) != FILE_SIZE)
    {
        yatest_err("file_size(filesystem) returned %i instead of %i", file_size(fsf), FILE_SIZE);
        exit(1);
    }

    if(file_size(fsf) != FILE_SIZE)
    {
        yatest_err("file_size(buffered) returned %i instead of %i", file_size(fsf), FILE_SIZE);
        exit(1);
    }

    void       *buffer;
    const void *buffer_const;
    ssize_t     buffer_size;

    ret = mapped_file_get_buffer(fsf, &buffer, &buffer_size);
    if(FAIL(ret))
    {
        yatest_err("mapped_file_get_buffer failed with %s", error_gettext(ret));
        exit(1);
    }

    ret = mapped_file_get_buffer_const(fsf, &buffer_const, &buffer_size);
    ret = mapped_file_get_buffer(fsf, &buffer, &buffer_size);
    if(FAIL(ret))
    {
        yatest_err("mapped_file_get_buffer_const failed with %s", error_gettext(ret));
        exit(1);
    }
}

static int loop_read_n_test(uint32_t dummy_size, uint32_t mode)
{
    int      ret;
    uint8_t *dummy = (uint8_t *)malloc(dummy_size);

    init(mode);

    // read

    for(int j = 0; j < 2; ++j)
    {
        for(int i = 0; i < file_size(fsf); i += dummy_size)
        {
            if(file_tell(fsf) != i)
            {
                yatest_err("loop%u(%u) loop %i, position %i file_tell returned %i instead of %i", dummy_size, mode, j, i, file_tell(fsf), i);
                free(dummy);
                return 1;
            }

            ret = file_read(fsf, dummy, dummy_size);
            if(FAIL(ret))
            {
                yatest_err("loop%u(%u) loop %i, position %i file_read failed with %s", dummy_size, mode, j, i, error_gettext(ret));
                free(dummy);
                return 1;
            }
            if(ret != (int)dummy_size)
            {
                yatest_err("loop%u(%u) loop %i, position %i file_read didn't read %i bytes", dummy_size, mode, j, i, dummy_size);
                free(dummy);
                return 1;
            }
            if(memcmp(&bytes[i], dummy, dummy_size) != 0)
            {
                yatest_err("loop%u(%u) loop %i, position %i expectations differ", dummy_size, mode, j, i);
                yatest_log("got");
                yatest_hexdump(dummy, dummy + dummy_size);
                yatest_log("expected");
                yatest_hexdump(&bytes[i], &bytes[i] + dummy_size);
                free(dummy);
                return 1;
            }
        }

        file_seek(fsf, 0, SEEK_SET);
    }

    file_flush(fsf);
    file_close(fsf);

    free(dummy);

    return 0;
}

static int loop_write_n_test_inner(uint32_t dummy_size, uint32_t mode)
{
    int      ret;
    uint8_t *dummy = (uint8_t *)malloc(dummy_size);

    // read

    for(int j = 0; j < 2; ++j)
    {
        for(int i = 0; i < file_size(fsf); i += dummy_size)
        {
            for(int k = 0; k < (int)dummy_size; ++k)
            {
                dummy[k] = (j + 1) * 7 + (i + 1) * 5 + k;
            }

            ret = file_write(fsf, dummy, dummy_size);

            if(FAIL(ret))
            {
                yatest_err("loop%u(%u) %i, %i file_read failed with %s", dummy_size, mode, j, i, error_gettext(ret));
                free(dummy);
                return 1;
            }
        }

        file_seek(fsf, 0, SEEK_SET);

        for(int i = 0; i < file_size(fsf); i += dummy_size)
        {
            ret = file_read(fsf, dummy, dummy_size);
            if(FAIL(ret))
            {
                yatest_err("loop%u(%u) %i, %i file_read failed with %s", dummy_size, mode, j, i, error_gettext(ret));
                free(dummy);
                return 1;
            }

            for(int k = 0; k < (int)dummy_size; ++k)
            {
                uint8_t expected = (j + 1) * 7 + (i + 1) * 5 + k;
                if(dummy[k] != expected)
                {
                    yatest_err("loop%u(%u) %i, %i differs from expectations: got %i, expected %i", dummy_size, mode, j, i + k, dummy[k], expected);
                    free(dummy);
                    return 1;
                }
            }
        }

        file_seek(fsf, 0, SEEK_SET);
    }

    file_flush(fsf);
    file_close(fsf);

    free(dummy);
    return 0;
}
/*
static int loop_write_n_test(uint32_t dummy_size, uint32_t mode)
{
    init(mode);
    return loop_write_n_test_inner(dummy_size, mode);
}
*/
static int loop_read_1_0_test() { return loop_read_n_test(1, 0); }

static int loop_read_1_1_test() { return loop_read_n_test(1, 1); }

static int loop_read_1_2_test() { return loop_read_n_test(1, 2); }

static int loop_read_512_0_test() { return loop_read_n_test(1, 0); }

static int loop_read_512_1_test() { return loop_read_n_test(1, 1); }

static int loop_read_512_2_test() { return loop_read_n_test(1, 2); }

static int resize_grow_test()
{
    int ret;
    init(0);
    ret = file_resize(fsf, FILE_SIZE * 8);
    if(FAIL(ret))
    {
        yatest_err("file_resize failed with %s", error_gettext(ret));
        return 1;
    }

    return loop_write_n_test_inner(FILE_SIZE * 8, 0);
}

static int resize_shrink_test()
{
    int ret;
    init(1);
    ret = file_resize(fsf, FILE_SIZE / 2);
    if(FAIL(ret))
    {
        yatest_err("file_resize failed with %s", error_gettext(ret));
        return 1;
    }

    return loop_write_n_test_inner(FILE_SIZE / 2, 1);
}

static int seek_test()
{
    int     ret;
    uint8_t dummy[1];

    init(2);

    ret = file_seek(fsf, 0, SEEK_END);

    if(FAIL(ret))
    {
        yatest_err("file_seek(SEEK_END) failed with %s", error_gettext(ret));
        return 1;
    }

    if(file_tell(fsf) != file_size(fsf))
    {
        yatest_err("file_seek(SEEK_END) failed: file_tell returned %i instead of %i", file_tell(fsf), file_size(fsf));
        return 1;
    }

    for(int i = file_size(fsf) - 1; i >= 0; --i)
    {
        ret = file_seek(fsf, -1, SEEK_CUR);

        if(FAIL(ret))
        {
            yatest_err("file_seek(SEEK_CUR) failed with %s", error_gettext(ret));
            return 1;
        }

        if(file_tell(fsf) != i)
        {
            yatest_err("file_seek(SEEK_CUR) failed: file_tell returned %i instead of %i", file_tell(fsf), i);
            return 1;
        }

        ret = file_read(fsf, dummy, 1);

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

        ret = file_seek(fsf, -1, SEEK_CUR);

        if(FAIL(ret))
        {
            yatest_err("file_seek(SEEK_CUR) failed with %s", error_gettext(ret));
            return 1;
        }

        if(file_tell(fsf) != i)
        {
            yatest_err("file_seek(SEEK_CUR) failed: file_tell returned %i instead of %i", file_tell(fsf), i);
            return 1;
        }
    }

    // relative with end

    ret = file_seek(fsf, -file_size(fsf), SEEK_END);
    if(FAIL(ret))
    {
        yatest_err("file_seek(-size, SEEK_END) failed with %s", error_gettext(ret));
        return 1;
    }
    ret = file_tell(fsf);
    if(ret != 0)
    {
        yatest_err("expected SEEK_END of -size to set position to 0 instead of %i", ret);
        return 1;
    }

    ret = file_seek(fsf, 0, SEEK_END);
    if(FAIL(ret))
    {
        yatest_err("file_seek(0, SEEK_END) failed with %s", error_gettext(ret));
        return 1;
    }

    // relative with cur

    ret = file_seek(fsf, -file_size(fsf), SEEK_CUR);
    if(FAIL(ret))
    {
        yatest_err("file_seek(-size, SEEK_CUR) failed with %s", error_gettext(ret));
        return 1;
    }
    ret = file_tell(fsf);
    if(ret != 0)
    {
        yatest_err("expected SEEK_CUR of -size to set position to 0 instead of %i", ret);
        return 1;
    }
    ret = file_seek(fsf, 0, SEEK_END);
    if(FAIL(ret))
    {
        yatest_err("file_seek(0, SEEK_END) failed with %s", error_gettext(ret));
        return 1;
    }

    file_flush(fsf);
    file_close(fsf);
    return 0;
}

static int error_test()
{
    int  ret;
    char filename[PATH_MAX];
    dnscore_init();

    ret = mapped_file_open_ex(NULL, filename, O_RDWR);
    if(ISOK(ret))
    {
        yatest_err("filesystem_file_open_ex should have failed");
        return 1;
    }

    ret = mapped_file_create_ex(NULL, filename, O_RDWR, 0640);
    if(ISOK(ret))
    {
        yatest_err("filesystem_file_create_ex should have failed");
        return 1;
    }

    ret = mapped_file_open_ex(&fsf, "/proc/filesystem_file-test", O_RDWR);
    if(ISOK(ret))
    {
        yatest_err("filesystem_file_open_ex should have failed");
        return 1;
    }

    ret = mapped_file_create_ex(&fsf, "/proc/filesystem_file-test", O_RDWR, 0640);
    if(ISOK(ret))
    {
        yatest_err("filesystem_file_create_ex should have failed");
        return 1;
    }

    void *broken = NULL;

    fsf = (file_t)&broken;

    void       *buffer;
    const void *buffer_const;
    ssize_t     buffer_size;

    ret = mapped_file_get_buffer(fsf, &buffer, &buffer_size);
    if(ISOK(ret))
    {
        yatest_err("mapped_file_get_buffer should have failed");
        return 1;
    }

    ret = mapped_file_get_buffer_const(fsf, &buffer_const, &buffer_size);
    if(ISOK(ret))
    {
        yatest_err("mapped_file_get_buffer_const should have failed");
        return 1;
    }

    // creates a file with random content (yatest_random_input_stream)

    yatest_file_create(FILE_SIZE);
    yatest_file_getname(FILE_SIZE, filename, sizeof(filename));

    // creates a copy of the expected content of the test file

    input_stream_t ris;
    yatest_random_input_stream_init(&ris, FILE_SIZE);
    input_stream_read(&ris, bytes, sizeof(bytes));
    input_stream_close(&ris);

    ret = mapped_file_open_ex(&fsf, filename, O_RDWR);
    if(FAIL(ret))
    {
        yatest_err("filesystem_file_open_ex('%s') failed with %s", filename, error_gettext(ret));
        return 1;
    }

    if(file_size(fsf) != FILE_SIZE)
    {
        yatest_err("file_size(filesystem) returned %i instead of %i", file_size(fsf), FILE_SIZE);
        return 1;
    }

    ret = file_resize(fsf, -1);
    if(ISOK(ret))
    {
        yatest_err("file_resize should have failed");
        return 1;
    }

    ret = file_seek(fsf, 0, -1);
    if(ISOK(ret))
    {
        yatest_err("file_seek should have failed");
        return 1;
    }

    return 0;
}

YATEST_TABLE_BEGIN
YATEST(loop_read_1_0_test)
YATEST(loop_read_1_1_test)
YATEST(loop_read_1_2_test)
YATEST(loop_read_512_0_test)
YATEST(loop_read_512_1_test)
YATEST(loop_read_512_2_test)
YATEST(resize_grow_test)
YATEST(resize_shrink_test)
YATEST(seek_test)
YATEST(error_test)
YATEST_TABLE_END
