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
#include "dnscore/timems.h"
#include "dnscore/fdtools.h"
#include "yatest_stream.h"
#include <dnscore/dnscore.h>
#include <dnscore/file_pool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static file_pool_t file_pool1;
static file_pool_t file_pool2;

static void        init()
{
    dnscore_init();
    file_pool1 = file_pool_init("file_pool-test1", 1);
    file_pool2 = file_pool_init("file_pool-test2", 2);
}

static void finalise()
{
    file_pool_finalize(file_pool2);
    file_pool_finalize(file_pool1);
    dnscore_finalize();
}

static int init_test()
{
    init();
    finalise();
    return 0;
}

#define DIR_PREFIX "/tmp/yadifa-file-pool-test/"

#define N          10000
#define L          64
#define P          16

static int file_pool_test_read_line(file_pool_file_t f, char *buffer, size_t buffer_size)
{
    for(size_t i = 0; i < buffer_size - 1; ++i)
    {
        ya_result ret = file_pool_readfully(f, &buffer[i], 1);

        if(ret == 1)
        {
            if(buffer[i] == '\n')
            {
                ++i;
                buffer[i] = '\0';
                return (int)i;
            }
        }
        else
        {
            return ERROR;
        }
    }

    return BUFFER_WOULD_OVERFLOW;
}

static int file_pool_operations_test()
{
    int n = N;

    assert(sizeof(size_t) == sizeof(int64_t));

#if C11_VLA_AVAILABLE
    file_pool_file_t file_array[n];
#else
    file_pool_file_t *file_array = (file_pool_file_t *)stack_alloc(sizeof(file_pool_file_t) * n);
#endif

    init();

    size_t *lines_positions = (size_t *)malloc(sizeof(size_t) * n * (L * 2));
    if(lines_positions == NULL)
    {
        return MAKE_ERRNO_ERROR(ENOMEM);
    }

    char tmp[1024];
    char tmp2[1024];

    yatest_log("mkdir " DIR_PREFIX);
    mkdir_ex(DIR_PREFIX, 0777, 0);
    yatest_log("deleting files from a previous test");
    for(int i = 0; i < N; ++i)
    {
        int l = snprintf(tmp, sizeof(tmp), DIR_PREFIX "myfile-%06i.txt", i);
        if(l > 0)
        {
            unlink(tmp);
        }
    }
    yatest_log("starting test");

    file_pool_t fp = file_pool_init("mypool", P);

    int64_t     create_ts = timeus();

    // creates n files containing their path

    for(int i = 0; i < n; ++i)
    {
        int l = snprintf(tmp, sizeof(tmp), DIR_PREFIX "myfile-%06i.txt", i);
        file_array[i] = file_pool_open_ex(fp, tmp, O_CREAT | O_TRUNC | O_CLOEXEC, 0660);

        if(file_array[i] == 0)
        {
            perror("error: ");
            exit(EXIT_FAILURE);
        }

        tmp[l++] = '\n';
        tmp[l] = '\0';
        file_pool_write(file_array[i], tmp, l);
    }

    int64_t write_ts = timeus();

    // j=L=64 times, i=n times, add a line in file i, i=n (reversed) add a line in file i

    for(int32_t j = 0; j < L; ++j)
    {
        for(int32_t i = 0; i < n; ++i)
        {
            int l = snprintf(tmp, sizeof(tmp), "File %i Line %i\n", i, j * 2);
            file_pool_tell(file_array[i], &lines_positions[i * (L * 2) + j * 2]);
            file_pool_write(file_array[i], tmp, l);
        }

        for(int32_t i = n - 1; i >= 0; --i)
        {
            int l = snprintf(tmp, sizeof(tmp), "File %i Line %i\n", i, j * 2 + 1);
            file_pool_tell(file_array[i], &lines_positions[i * (L * 2) + j * 2 + 1]);
            file_pool_write(file_array[i], tmp, l);
        }
    }

    int64_t seekread_ts = timeus();

    for(int32_t i = 0; i < n; ++i)
    {
        ssize_t p = file_pool_seek(file_array[i], 0, SEEK_SET);
        if(p != 0)
        {
            yatest_err("file_pool_seek(#%i, 0, SEEK_SET) failed with %08x = %s", i, (ya_result)p, error_gettext((ya_result)p));
            return 1;
        }

        snprintf(tmp, sizeof(tmp), DIR_PREFIX "myfile-%06i.txt\n", i);
        file_pool_test_read_line(file_array[i], tmp2, sizeof(tmp2));
        if(strcmp(tmp, tmp2) != 0)
        {
            yatest_err("failed to read-back the lines:\n%s!=%s", tmp, tmp2);
            return 1;
        }
    }

    int64_t read_ts = timeus();

    for(int32_t j = 0; j < L; ++j)
    {
        for(int32_t i = 0; i < n; ++i)
        {
            snprintf(tmp, sizeof(tmp), "File %i Line %i\n", i, j * 2);
            file_pool_test_read_line(file_array[i], tmp2, sizeof(tmp2));
            if(strcmp(tmp, tmp2) != 0)
            {
                yatest_err("failed to read-back the lines:\n%s!=%s", tmp, tmp2);
                return 1;
            }
        }

        for(int32_t i = n - 1; i >= 0; --i)
        {
            snprintf(tmp, sizeof(tmp), "File %i Line %i\n", i, j * 2 + 1);
            file_pool_test_read_line(file_array[i], tmp2, sizeof(tmp2));
            if(strcmp(tmp, tmp2) != 0)
            {
                yatest_err("failed to read-back the lines:\n%s!=%s", tmp, tmp2);
                return 1;
            }
        }
    }

    int64_t readbackwards_ts = timeus();

    for(int i = 0; i < n; ++i)
    {
        for(int j = L * 2 - 1; j >= 0; --j)
        {
            snprintf(tmp, sizeof(tmp), "File %i Line %i\n", i, j);
            file_pool_seek(file_array[i], lines_positions[i * (L * 2) + j], SEEK_SET);
            file_pool_test_read_line(file_array[i], tmp2, sizeof(tmp2));
            if(strcmp(tmp, tmp2) != 0)
            {
                yatest_err("failed to read-backwards-back the lines:\n%s!=%s", tmp, tmp2);
                return 1;
            }
        }
    }

    int64_t close_ts = timeus();

    for(int32_t i = 0; i < n; ++i)
    {
        file_pool_close(file_array[i]);
        file_array[i] = 0;
    }

    int64_t closedwrite_ts = timeus();

    for(int32_t i = 0; i < P; ++i)
    {
        int l = snprintf(tmp, sizeof(tmp), DIR_PREFIX "myfile-%06i.txt", i);
        file_array[i] = file_pool_open(fp, tmp);
        l = snprintf(tmp, sizeof(tmp), "File %i close test start write\n", i);
        file_pool_write(file_array[i], tmp, l);
        file_pool_close(file_array[i]);
    }

    for(int32_t i = 0; i < P; ++i)
    {
        int l = snprintf(tmp, sizeof(tmp), DIR_PREFIX "myfile-%06i.txt", i);
        file_array[i] = file_pool_open(fp, tmp);
        l = snprintf(tmp, sizeof(tmp), "File %i close test middle .\n", i);
        file_pool_write(file_array[i], tmp, l);
        file_pool_close(file_array[i]);
    }

    double create_time = (double)(write_ts - create_ts);
    double write_time = (double)(seekread_ts - write_ts);
    double seekread_time = (double)(read_ts - seekread_ts);
    double read_time = (double)(readbackwards_ts - read_ts);
    double readbackwards_time = (double)(close_ts - readbackwards_ts);
    double close_time = (double)(closedwrite_ts - close_ts);
    create_time /= ONE_SECOND_US_F;
    write_time /= ONE_SECOND_US_F;
    seekread_time /= ONE_SECOND_US_F;
    read_time /= ONE_SECOND_US_F;
    readbackwards_time /= ONE_SECOND_US_F;
    close_time /= ONE_SECOND_US_F;

    yatest_log(
        "create=%6.4fs\n"
        "write=%6.4fs\n"
        "seek-read=%6.4fs\n"
        "read=%6.4fs\n"
        "read-backwards=%6.4fs\n"
        "close=%6.4fs\n",
        create_time,
        write_time,
        seekread_time,
        read_time,
        readbackwards_time,
        close_time);

    yatest_log("mkdir " DIR_PREFIX);
    mkdir_ex(DIR_PREFIX, 0777, 0);
    yatest_log("deleting files from current test");
    for(int i = 0; i < N; ++i)
    {
        int l = snprintf(tmp, sizeof(tmp), DIR_PREFIX "myfile-%06i.txt", i);
        if(l > 0)
        {
            unlink(tmp);
        }
    }

    finalise();

    return SUCCESS;
}

static int file_pool_unlink_from_pool_and_filename_test()
{
    ya_result ret;
    char      filename[64];
    yatest_file_getname(0, filename, sizeof(filename));
    init();
    unlink(filename);
    ret = file_pool_unlink_from_pool_and_filename(file_pool1, filename);
    if(ret != MAKE_ERRNO_ERROR(ENOENT))
    {
        yatest_err("file_pool_unlink_from_pool_and_filename %s (nofile) returned %08x = %s instead of %08x", filename, ret, error_gettext(ret), MAKE_ERRNO_ERROR(ENOENT));
        return 1;
    }
    yatest_file_create_empty(0);
    ret = file_pool_unlink_from_pool_and_filename(file_pool1, filename);
    if(ret != 0)
    {
        yatest_err("file_pool_unlink_from_pool_and_filename %s (empty) returned %08x = %s", filename, ret, error_gettext(ret));
        return 1;
    }
    //
    yatest_file_create_empty(0);
    file_pool_file_t fpf = file_pool_open(file_pool1, filename);
    if(fpf == NULL)
    {
        yatest_err("file_pool_open %s returned NULL", filename);
        return 1;
    }
    ret = file_pool_unlink_from_pool_and_filename(file_pool1, filename);
    if(ret != 0)
    {
        yatest_err("file_pool_unlink_from_pool_and_filename %s (opened) returned %08x = %s", filename, ret, error_gettext(ret));
        return 1;
    }
    file_pool_close(fpf);
    //
    yatest_file_create_empty(0);
    fpf = file_pool_open(file_pool1, filename);
    if(fpf == NULL)
    {
        yatest_err("file_pool_open %s returned NULL", filename);
        return 1;
    }
    file_pool_close(fpf);
    ret = file_pool_unlink_from_pool_and_filename(file_pool1, filename);
    if(ret != 0)
    {
        yatest_err("file_pool_unlink_from_pool_and_filename %s (closed) returned %08x = %s", filename, ret, error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int file_pool_dup_test()
{
    char filename[64];
    yatest_file_getname(0, filename, sizeof(filename));
    init();
    yatest_file_create_empty(0);
    file_pool_file_t fpf = file_pool_open(file_pool1, filename);
    if(fpf == NULL)
    {
        yatest_err("file_pool_open %s returned NULL", filename);
        return 1;
    }
    file_pool_file_t fpf2 = file_dup(fpf);
    if(fpf2 == NULL)
    {
        yatest_err("file_dup %s returned NULL", filename);
        return 1;
    }
    file_pool_close(fpf);
    finalise();
    return 0;
}

static int file_pool_create_test()
{
    char filename[64];
    yatest_file_getname(0, filename, sizeof(filename));
    unlink(filename);
    init();
    int              mode = 0640;
    file_pool_file_t fpf = file_pool_create(file_pool1, filename, mode);
    if(fpf == NULL)
    {
        yatest_err("file_pool_create %s returned NULL", filename);
        return 1;
    }

    struct stat st;
    if(stat(filename, &st) < 0)
    {
        yatest_err("stat %s failed with %s", filename, strerror(errno));
        return 1;
    }
    /*
        st.st_mode &= 0777;

        if(st.st_mode != 0640)
        {
            yatest_err("mode is %04o, expected to be %04o", st.st_mode, mode);
            return 1;
        }
    */
    file_pool_close(fpf);
    finalise();
    return 0;
}

static int file_pool_create_excl_test()
{
    char filename[64];
    yatest_file_getname(0, filename, sizeof(filename));
    unlink(filename);
    init();
    int              mode = 0640;
    file_pool_file_t fpf = file_pool_create_excl(file_pool1, filename, mode);
    if(fpf == NULL)
    {
        yatest_err("file_pool_create_excl %s returned NULL", filename);
        return 1;
    }

    struct stat st;
    if(stat(filename, &st) < 0)
    {
        yatest_err("stat %s failed with %s", filename, strerror(errno));
        return 1;
    }

    st.st_mode &= 0777;

    if(st.st_mode != 0640)
    {
        yatest_err("mode is %04o, expected to be %04o", st.st_mode, mode);
        return 1;
    }

    file_pool_close(fpf);
    finalise();
    return 0;
}

static int file_common_release_fd_test()
{
    init();
    // file_common_release_fd is called if a read on a file returns an error
    // can't do at the moment
    finalise();
    return 0;
}

static int file_pool_flush_test()
{
    ya_result ret;
    char      filename[64];
    yatest_file_getname(0, filename, sizeof(filename));
    unlink(filename);
    init();
    int              mode = 0640;
    file_pool_file_t fpf = file_pool_create_excl(file_pool1, filename, mode);
    if(fpf == NULL)
    {
        yatest_err("file_pool_create_excl %s returned NULL", filename);
        return 1;
    }

    ret = file_pool_writefully(fpf, yatest_lorem_ipsum, sizeof(yatest_lorem_ipsum));
    if(ret < 0)
    {
        yatest_err("file_pool_writefully failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    ret = file_pool_flush(fpf);
    if(ret < 0)
    {
        yatest_err("file_pool_flush failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    file_pool_close(fpf);
    finalise();
    return 0;
}

static int file_pool_get_size_test()
{
    ya_result ret;
    char      filename[64];
    yatest_file_getname(0, filename, sizeof(filename));
    unlink(filename);
    init();

    int              mode = 0640;
    file_pool_file_t fpf = file_pool_create_excl(file_pool1, filename, mode);
    if(fpf == NULL)
    {
        yatest_err("file_pool_create_excl %s returned NULL", filename);
        return 1;
    }

    ret = file_pool_writefully(fpf, yatest_lorem_ipsum, sizeof(yatest_lorem_ipsum));
    if(ret < 0)
    {
        yatest_err("file_pool_writefully failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    size_t size;
    ret = file_pool_get_size(fpf, &size);
    if(ret < 0)
    {
        yatest_err("file_pool_get_size failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    if(size != sizeof(yatest_lorem_ipsum))
    {
        yatest_err("file_pool_get_size returned %llu, expected %llu", size, sizeof(yatest_lorem_ipsum));
        return 1;
    }

    file_pool_close(fpf);
    finalise();
    return 0;
}

static int file_pool_resize_test()
{
    ya_result ret;
    char      filename[64];
    yatest_file_getname(0, filename, sizeof(filename));
    unlink(filename);
    init();

    int              mode = 0640;
    file_pool_file_t fpf = file_pool_create_excl(file_pool1, filename, mode);
    if(fpf == NULL)
    {
        yatest_err("file_pool_create_excl %s returned NULL", filename);
        return 1;
    }

    ret = file_pool_writefully(fpf, yatest_lorem_ipsum, sizeof(yatest_lorem_ipsum));
    if(ret < 0)
    {
        yatest_err("file_pool_writefully failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    size_t size;
    ret = file_pool_get_size(fpf, &size);
    if(ret < 0)
    {
        yatest_err("file_pool_get_size failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    if(size != sizeof(yatest_lorem_ipsum))
    {
        yatest_err("file_pool_get_size returned %llu, expected %llu", size, sizeof(yatest_lorem_ipsum));
        return 1;
    }

    const size_t smaller_size = 16;

    assert(smaller_size < sizeof(yatest_lorem_ipsum));

    ret = file_pool_resize(fpf, smaller_size);
    if(ret < 0)
    {
        yatest_err("file_pool_resize failed with %08x = %s (shrink)", ret, error_gettext(ret));
        return 1;
    }

    ret = file_pool_get_size(fpf, &size);
    if(ret < 0)
    {
        yatest_err("file_pool_get_size failed with %08x = %s (after shrink)", ret, error_gettext(ret));
        return 1;
    }

    if(size != smaller_size)
    {
        yatest_err("file_pool_get_size returned %llu, expected %llu (after shrink)", size, smaller_size);
        return 1;
    }

    char   *buffer = (char *)malloc(sizeof(yatest_lorem_ipsum) * 2 + 1);

    ssize_t pos = file_pool_seek(fpf, 0, SEEK_SET);

    if(pos != 0)
    {
        yatest_err("file_pool_seek didn't return 0 (after shrink)");
        return 1;
    }

    ret = file_pool_read(fpf, buffer, smaller_size * 2);
    if(ret != (ssize_t)smaller_size)
    {
        yatest_err("file_pool_read returned %08x, expected %08x (after shrink)", ret, smaller_size);
        return 1;
    }

    const size_t bigger_size = sizeof(yatest_lorem_ipsum) * 2;

    ret = file_pool_resize(fpf, bigger_size);
    if(ret < 0)
    {
        yatest_err("file_pool_resize failed with %08x = %s (grow)", ret, error_gettext(ret));
        return 1;
    }

    ret = file_pool_get_size(fpf, &size);
    if(ret < 0)
    {
        yatest_err("file_pool_get_size failed with %08x = %s (after grow)", ret, error_gettext(ret));
        return 1;
    }

    if(size != bigger_size)
    {
        yatest_err("file_pool_get_size returned %llu, expected %llu (after grow)", size, bigger_size);
        return 1;
    }

    pos = file_pool_seek(fpf, 0, SEEK_SET);

    if(pos != 0)
    {
        yatest_err("file_pool_seek didn't return 0 (after grow)");
        return 1;
    }

    ret = file_pool_writefully(fpf, yatest_lorem_ipsum, sizeof(yatest_lorem_ipsum));
    if(ret < 0)
    {
        yatest_err("file_pool_writefully failed with %08x = %s (after grow, 0)", ret, error_gettext(ret));
        return 1;
    }

    ret = file_pool_writefully(fpf, yatest_lorem_ipsum, sizeof(yatest_lorem_ipsum));
    if(ret < 0)
    {
        yatest_err("file_pool_writefully failed with %08x = %s (after grow, 1)", ret, error_gettext(ret));
        return 1;
    }

    ret = file_pool_tell(fpf, (size_t *)&pos);
    if(ret < 0)
    {
        yatest_err("file_pool_tell returned %i (after grow)", ret);
        return 1;
    }

    if(pos != sizeof(yatest_lorem_ipsum) * 2)
    {
        yatest_err("file_pool_get_size returned %llu, expected %llu (after grow)", size, bigger_size);
        return 1;
    }

    file_pool_close(fpf);
    free(buffer);
    finalise();
    return 0;
}

static int file_pool_seek_test()
{
    char filename[64];
    int  file_size = 4096;
    yatest_file_getname(file_size, filename, sizeof(filename));
    yatest_file_create(file_size);
    init();
    file_pool_file_t fpf = file_pool_open(file_pool1, filename);
    if(fpf == NULL)
    {
        yatest_err("file_pool_open %s returned NULL", filename);
        return 1;
    }
    ssize_t current;
    current = file_pool_seek(fpf, file_size / 2, SEEK_SET);
    if(current != file_size / 2)
    {
        yatest_err("file_pool_seek returned %lli instead of %i", current, file_size / 2);
        return 1;
    }
    current = file_pool_seek(fpf, 16, SEEK_CUR);
    if(current != file_size / 2 + 16)
    {
        yatest_err("file_pool_seek returned %lli instead of %i", current, file_size / 2 + 16);
        return 1;
    }
    current = file_pool_seek(fpf, -32, SEEK_CUR);
    if(current != file_size / 2 - 16)
    {
        yatest_err("file_pool_seek returned %lli instead of %i", current, file_size / 2 - 16);
        return 1;
    }
    current = file_pool_seek(fpf, -16, SEEK_END);
    if(current != file_size - 16)
    {
        yatest_err("file_pool_seek returned %lli instead of %i", current, file_size - 16);
        return 1;
    }
    current = file_pool_seek(fpf, -16, 0x1234567);
    if(current != INVALID_ARGUMENT_ERROR)
    {
        yatest_err("file_pool_seek returned %08x instead of %08x", current, INVALID_ARGUMENT_ERROR);
        return 1;
    }
    finalise();
    return 0;
}

static int file_pool_unlink_test()
{
    ya_result ret;
    char      filename[64];
    yatest_file_getname(0, filename, sizeof(filename));
    init();
    unlink(filename);
    yatest_file_create_empty(0);
    file_pool_file_t fpf = file_pool_open(file_pool1, filename);
    if(fpf == NULL)
    {
        yatest_err("file_pool_open %s returned NULL", filename);
        return 1;
    }
    ret = file_pool_unlink(fpf);
    if(ret != 0)
    {
        yatest_err("file_pool_unlink %s returned %08x = %s", filename, ret, error_gettext(ret));
        return 1;
    }
    file_pool_close(fpf);

    finalise();
    return 0;
}

static int file_pool_filename_test()
{
    char filename[64];
    yatest_file_getname(0, filename, sizeof(filename));
    init();
    unlink(filename);
    yatest_file_create_empty(0);
    file_pool_file_t fpf = file_pool_open(file_pool1, filename);
    if(fpf == NULL)
    {
        yatest_err("file_pool_open %s returned NULL", filename);
        return 1;
    }
    const char *fpf_filename = file_pool_filename(fpf);
    if(strcmp(fpf_filename, filename) != 0)
    {
        yatest_err("file_pool_filename '%s' returned '%s'", filename, fpf_filename);
        return 1;
    }

    file_pool_close(fpf);

    finalise();
    return 0;
}

static int file_pool_file_output_stream_test()
{
    char filename[64];
    int  file_size = 4096;
    yatest_file_getname(file_size, filename, sizeof(filename));
    init();

    for(int fw = 0; fw < 4; ++fw)
    {
        bool full_writes = ((fw & 1) != 0);

        yatest_file_create(file_size);

        file_pool_file_t fpf = file_pool_open(file_pool1, filename);
        if(fpf == NULL)
        {
            yatest_err("file_pool_open %s returned NULL", filename);
            return 1;
        }
        output_stream_t os;
        file_pool_file_output_stream_init(&os, fpf);
        file_pool_file_output_stream_set_full_writes(&os, true);
        file_pool_file_output_stream_set_full_writes(&os, false);
        file_pool_file_output_stream_set_full_writes(&os, full_writes);
        output_stream_write(&os, yatest_lorem_ipsum, sizeof(yatest_lorem_ipsum));
        output_stream_flush(&os);
        if(fw < 2)
        {
            file_pool_file_output_stream_detach(&os);
        }
        output_stream_close(&os);
        if(fw < 2)
        {
            file_pool_close(fpf);
        }
    }
    finalise();
    return 0;
}

static int file_pool_file_input_stream_test()
{
    char filename[64];
    int  file_size = 4096;
    yatest_file_getname(file_size, filename, sizeof(filename));
    init();

    char *buffer = (char *)malloc(file_size);
    if(buffer == NULL)
    {
        yatest_err("malloc failed: internal error");
        return 1;
    }

    for(int fr = 0; fr < 4; ++fr)
    {
        bool full_reads = ((fr & 1) != 0);

        yatest_file_create(file_size);

        file_pool_file_t fpf = file_pool_open(file_pool1, filename);
        if(fpf == NULL)
        {
            yatest_err("file_pool_open %s returned NULL", filename);
            return 1;
        }
        input_stream_t is;
        file_pool_file_input_stream_init(&is, fpf);
        file_pool_file_input_stream_set_full_reads(&is, true);
        file_pool_file_input_stream_set_full_reads(&is, false);
        file_pool_file_input_stream_set_full_reads(&is, full_reads);
        input_stream_read(&is, buffer, file_size);
        input_stream_skip(&is, 0);

        if(fr < 2)
        {
            file_pool_file_input_stream_detach(&is);
        }
        output_stream_close(&is);
        if(fr < 2)
        {
            file_pool_close(fpf);
        }
    }
    free(buffer);
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(init_test)
YATEST(file_pool_operations_test)
YATEST(file_pool_unlink_from_pool_and_filename_test)
YATEST(file_pool_dup_test)
YATEST(file_pool_create_test)
YATEST(file_pool_create_excl_test)
YATEST(file_common_release_fd_test)
YATEST(file_pool_flush_test)
YATEST(file_pool_get_size_test)
YATEST(file_pool_resize_test)
YATEST(file_pool_seek_test)
YATEST(file_pool_unlink_test)
YATEST(file_pool_filename_test)
YATEST(file_pool_file_output_stream_test)
YATEST(file_pool_file_input_stream_test)
YATEST_TABLE_END
