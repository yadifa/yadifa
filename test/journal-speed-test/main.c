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

#include <dnscore/fdtools.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/buffer_output_stream.h>

#define JOURNAL_CJF_BASE 1

#include <dnsdb/zdb.h>
#include <dnsdb/zdb_utils.h>
#include <dnsdb/journal-cjf-common.h>
#include <dnsdb/journal-cjf-page-cache.h>
#include <dnsdb/journal-jnl.h>
#include <dnsdb/rrsig.h>

static ya_result
jnl_read_from_serial(journal *jnl, u32 serial_from, dns_resource_record *rr, const char *filepath)
{
    s64 ts_begin = timeus();

    input_stream is;

    ya_result ret;

    ret = journal_get_ixfr_stream_at_serial(jnl, serial_from, &is, rr);

    s64 ts_opened = timeus();

    if(FAIL(ret))
    {
        formatln("; jnl: '%s' file cannot read from its announced first serial %i : %r", filepath, serial_from, ret);
        return ERROR;
    }

    for(;;)
    {
        ret = dns_resource_record_read(rr, &is);

        if(ret <= 0)
        {
            if(FAIL(ret))
            {
                formatln("; jnl: '%s' failed to read next record: %r", filepath,  ret);
            }

            break;
        }
    }

    s64 ts_end = timeus();

    double t_open = (ts_opened - ts_begin) / 1000000.0;
    double t_read = (ts_end - ts_opened) / 1000000.0;
    double t_total = (ts_end - ts_begin) / 1000000.0;

    formatln("serial: %9u open: %9.6fs read: %9.6fs total: %9.6fs", serial_from, t_open, t_read, t_total);

    return SUCCESS;
}

static void
jnl_speed_test(const char *filepath)
{
    journal *jnl = NULL;
    const char *filename = strrchr(filepath, '/');
    size_t filename_len;
    dns_resource_record rr;
    ya_result ret;
    u32 serial_from = 0;
    u32 serial_to = 0;

    u8 origin[MAX_DOMAIN_LENGTH];

    if(filename == NULL)
    {
        filename = filepath;
    }
    else
    {
        ++filename;
    }

    filename_len = strlen(filename);
    if(filename_len < 5)
    {
        formatln("; jnl: '%s' name is too small to parse", filepath);
        return;
    }
/*
    if(memcmp(&filename[filename_len - 4], ".jnl", 4) != 0)
    {
        formatln("jnl: '%s' does not end with .jnl", filepath);
        return;
    }
*/
    if(FAIL(ret = cstr_to_dnsname_with_check_len(origin, filename, filename_len - 4)))
    {
        formatln("; jnl: '%s' cannot be parsed for origin: %r", filepath, ret);
        return;
    }


    if(FAIL(ret = journal_jnl_open_file(&jnl, filepath, origin, FALSE)))
    {
        formatln("; jnl: '%s' file cannot be opened as a journal: %r", filepath, ret);
        return;
    }

    ++jnl->rc;

    if(FAIL(ret = journal_get_serial_range(jnl, &serial_from, &serial_to)))
    {
        formatln("; jnl: '%s' file cannot get serial range: %r", filepath, ret);
        return;
    }

    dns_resource_record_init(&rr);

    formatln("; jnl: '%s' serial range: %u to %u", filepath, serial_from, serial_to);

    if((serial_to + 1) == serial_from)
    {
        formatln("; jnl: '%s' serial range looks funny", filepath, serial_from, serial_to);
        return;
    }

    // forward read

    for(u32 serial = serial_from; serial_le(serial, serial_to); ++serial)
    {
        jnl_read_from_serial(jnl, serial, &rr, filepath);
    }

    // backward read

    for(u32 serial = serial_to; serial_ge(serial, serial_from); --serial)
    {
        jnl_read_from_serial(jnl, serial, &rr, filepath);
    }

    dns_resource_record_finalize(&rr);

    journal_release(jnl);
}

/*
 * 
 */
int main(int argc, char** argv)
{
    dnscore_init();
    zdb_init();

    for(int i = 1; i < argc; ++i)
    {
        jnl_speed_test(argv[i]);
    }

    zdb_finalize();
    dnscore_finalize();
    return (EXIT_SUCCESS);
}
