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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if WIN32
#include <direct.h>
#endif

#include <dnscore/dnscore.h>
#include <dnscore/format.h>
#include <dnscore/fdtools.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/file-pool.h>
#include <dnscore/timems.h>

#define DIR_PREFIX "/tmp/yadifa-file-pool-test/"


#define N 10000
#define L 64
#define P 16

/*
 * 
 */

static int read_line(file_pool_file_t f, char *buffer, size_t buffer_size)
{
    for(size_t i = 0; i < buffer_size - 1; ++i)
    {
        ya_result ret = file_pool_read(f, &buffer[i], 1);

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

static ya_result filepool_test()
{
    int n = N;

    assert(sizeof(size_t) == sizeof(s64));

#if C11_VLA_AVAILABLE
    file_pool_file_t file_array[n];
#else
    file_pool_file_t* file_array = (file_pool_file_t*)stack_alloc(sizeof(file_pool_file_t) * n);
#endif

    size_t *lines_positions = (size_t*)malloc(sizeof(size_t) * n * (L * 2));
    if(lines_positions == NULL)
    {
        return MAKE_ERRNO_ERROR(ENOMEM);
    }

    char tmp[1024];
    char tmp2[1024];

    println("mkdir " DIR_PREFIX);
    mkdir(DIR_PREFIX, 0777);
    formatln("deleteing files from a previous test");
    for(int i = 0; i < N; ++i)
    {
        unlink(DIR_PREFIX "myfile-%06i.txt");
    }
    formatln("starting test");

    file_pool_t fp = file_pool_init("mypool", P);

    s64 create_ts = timeus();

    // creates n files containing their path

    for(int i = 0; i < n; ++i)
    {
        int l = snformat(tmp, sizeof(tmp), DIR_PREFIX "myfile-%06i.txt", i);
        file_array[i] = file_pool_open_ex(fp, tmp, O_CREAT|O_TRUNC|O_CLOEXEC, 0660);

        if(file_array[i] == 0)
        {
            perror("error: ");
            exit(EXIT_FAILURE);
        }

        tmp[l++] = '\n';
        tmp[l] = '\0';
        file_pool_write(file_array[i], tmp, l);
    }

    s64 write_ts = timeus();

    // j=L=64 times, i=n times, add a line in file i, i=n (reversed) add a line in file i

    for(int j = 0; j < L; ++j)
    {
        for(int i = 0; i < n; ++i)
        {
            int l = snformat(tmp, sizeof(tmp), "File %i Line %i\n", i, j * 2);
            file_pool_tell(file_array[i], &lines_positions[i * (L * 2) + j * 2]);
            file_pool_write(file_array[i], tmp, l);
        }

        for(int i = n - 1; i >= 0; --i)
        {
            int l = snformat(tmp, sizeof(tmp), "File %i Line %i\n", i, j * 2 + 1);
            file_pool_tell(file_array[i], &lines_positions[i * (L * 2) + j * 2 + 1]);
            file_pool_write(file_array[i], tmp, l);
        }
    }

    s64 seekread_ts = timeus();

    for(int i = 0; i < n; ++i)
    {
        ssize_t p = file_pool_seek(file_array[i], 0, SEEK_SET);
        if(p != 0)
        {
            formatln("file_pool_seek(#%i, 0, SEEK_SET) failed with %r", (ya_result)p);
            return (ya_result)p;
        }

        snformat(tmp, sizeof(tmp), DIR_PREFIX "myfile-%06i.txt\n", i);
        read_line(file_array[i], tmp2, sizeof(tmp2));
        if(strcmp(tmp, tmp2) != 0)
        {
            formatln("failed to read-back the lines:\n%s!=%s", tmp, tmp2);
            return ERROR;
        }
    }

    s64 read_ts = timeus();

    for(int j = 0; j < L; ++j)
    {
        for(int i = 0; i < n; ++i)
        {
            snformat(tmp, sizeof(tmp), "File %i Line %i\n", i, j * 2);
            read_line(file_array[i], tmp2, sizeof(tmp2));
            if(strcmp(tmp, tmp2) != 0)
            {
                formatln("failed to read-back the lines:\n%s!=%s", tmp, tmp2);
                return ERROR;
            }
        }

        for(int i = n - 1; i >= 0; --i)
        {
            snformat(tmp, sizeof(tmp), "File %i Line %i\n", i, j * 2 + 1);
            read_line(file_array[i], tmp2, sizeof(tmp2));
            if(strcmp(tmp, tmp2) != 0)
            {
                formatln("failed to read-back the lines:\n%s!=%s", tmp, tmp2);
                return ERROR;
            }
        }
    }

    s64 readbackwards_ts = timeus();

    for(int i = 0; i < n; ++i)
    {
        for(int j = L * 2 - 1; j >= 0; --j)
        {
            snformat(tmp, sizeof(tmp), "File %i Line %i\n", i, j);
            file_pool_seek(file_array[i], lines_positions[i * (L * 2) + j], SEEK_SET);
            read_line(file_array[i], tmp2, sizeof(tmp2));
            if(strcmp(tmp, tmp2) != 0)
            {
                formatln("failed to read-backwards-back the lines:\n%s!=%s", tmp, tmp2);
                return ERROR;
            }
        }
    }

    s64 close_ts = timeus();

    for(int i = 0; i < n; ++i)
    {
        file_pool_close(file_array[i]);
        file_array[i] = 0;
    }

    s64 closedwrite_ts = timeus();

    for(int i = 0; i < P; ++i)
    {
        int l = snformat(tmp, sizeof(tmp), DIR_PREFIX "myfile-%06i.txt", i);
        file_array[i] = file_pool_open(fp, tmp);
        l = snformat(tmp, sizeof(tmp), "File %i close test start write\n", i);
        file_pool_write(file_array[i], tmp, l);
        file_pool_close(file_array[i]);
    }

    for(int i = 0; i < P; ++i)
    {
        int l = snformat(tmp, sizeof(tmp), DIR_PREFIX "myfile-%06i.txt", i);
        file_array[i] = file_pool_open(fp, tmp);
        l = snformat(tmp, sizeof(tmp), "File %i close test middle .\n", i);
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

    formatln("create=%6.4fs\n"
             "write=%6.4fs\n"
             "seek-read=%6.4fs\n"
             "read=%6.4fs\n"
             "read-backwards=%6.4fs\n"
             "close=%6.4fs\n",
            create_time, write_time, seekread_time, read_time, readbackwards_time, close_time);

    return SUCCESS;
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    dnscore_init();
    
    ya_result ret = filepool_test();

    formatln("test returned with: %r", ret);
    flushout();
    
    dnscore_finalize();
    
    return (EXIT_SUCCESS);
}
