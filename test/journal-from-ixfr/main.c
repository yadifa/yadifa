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

/** @defgroup test
 *  @ingroup test
 *  @brief skeleton file
 * 
 * skeleton test program, will not be installed with a "make install"
 * 
 * To create a new test based on the skeleton:
 * 
 * _ copy the folder
 * _ replace "skeleton" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 * _ add the test to the CMakeLists.txt from the tests directory
 *
 */

#define ZDB_JOURNAL_CODE 1

#include <dnscore/dnscore.h>
#include <dnscore/format.h>
#include <dnsdb/journal-jnl.h>
#include <dnsdb/journal.h>
#include <dnscore/zone_reader.h>
#include <dnscore/zone_reader_text.h>
#include <dnsdb/zdb.h>

ya_result
journal_generator(const char *jnlfilepath, const u8 *origin, const char *ixfrfilepath)
{
    journal *jnl = NULL;
    input_stream is;
    output_stream os;
    ya_result ret;
    zone_reader zr;

    if(FAIL(ret =  zone_reader_text_open(ixfrfilepath, &zr)))
    {
        formatln("jnl: '%s' file cannot be opened as a IXFR source: %r", ixfrfilepath, ret);
        return ret;
    }

    resource_record first_entry;
    resource_record entry;
    resource_record_init(&first_entry);

    if(FAIL(ret = zone_reader_read_record(&zr, &first_entry)))
    {
        return ret;
    }

    if(first_entry.type != TYPE_SOA)
    {
        return ERROR; // expected SOA
    }

    resource_record_init(&entry);

    bytearray_output_stream_init(&os, NULL, 0);

    int soa_count = 0;

    bool end_soa_armed = FALSE;

    /*
    u32 serial_from;
    */
    u32 serial_to;

    rr_soa_get_serial(first_entry.rdata, first_entry.rdata_size, &serial_to);

    for(;;)
    {

        // now read and write until SOA matches first SOA

        if(FAIL(ret = zone_reader_read_record(&zr, &entry)))
        {
            if(ret == ZONEFILE_INVALID_TYPE)
            {
                // ignore
                continue;
            }

            return ret;
        }

        if(entry.type == TYPE_SOA)
        {
            u32 serial = 0;
            rr_soa_get_serial(entry.rdata, entry.rdata_size, &serial);
            formatln("SOA with serial %u", serial);

            if(!resource_record_equals(&entry, &first_entry))
            {
                /*
                if(soa_count == 0)
                {
                    serial_from = serial;
                }
                */
                ++soa_count;
            }
            else
            {
                if(!end_soa_armed)
                {
                    ++soa_count;
                    end_soa_armed = TRUE;
                }
                else
                {
                    break;
                }
            }
        }
        else  if((entry.type == TYPE_TSIG) || (entry.type == TYPE_OPT))
        {
            // ignore
            continue;
        }

        if(FAIL(ret = output_stream_write_dnsname(&os, entry.name)))
        {
            return ret;
        }

        if(FAIL(ret = output_stream_write_u16(&os, entry.type)))
        {
            return ret;
        }

        if(FAIL(ret = output_stream_write_u16(&os, entry.class)))
        {
            return ret;
        }

        if(FAIL(ret = output_stream_write_nu32(&os, entry.ttl)))
        {
            return ret;
        }

        if(FAIL(ret = output_stream_write_nu16(&os, entry.rdata_size)))
        {
            return ret;
        }

        if(FAIL(ret = output_stream_write(&os, entry.rdata, entry.rdata_size)))
        {
            return ret;
        }
    }

    if((soa_count & 1) != 0)
    {
        return ERROR;
    }

    bytearray_input_stream_init(&is, bytearray_output_stream_buffer(&os), bytearray_output_stream_size(&os), FALSE);

    if(FAIL(ret = journal_jnl_open_file(&jnl, jnlfilepath, origin, TRUE)))
    {
        formatln("jnl: '%s' file cannot be opened as a journal: %r", jnlfilepath, ret);
        return ret;
    }

    jnl->vtbl->maximum_size_update(jnl, MAX_U32);

    u32 first_serial = 0;
    if(ISOK(ret = jnl->vtbl->get_first_serial(jnl, &first_serial)))
    {
        jnl->vtbl->minimum_serial_update(jnl, first_serial);
    }
    else
    {
        formatln("could not get first serial: %r", ret);
    }

    s64 previous_size = filesize(jnlfilepath);

    formatln("jnl: previous size: %lli", previous_size);

    if(FAIL(ret = jnl->vtbl->append_ixfr_stream(jnl, &is)))
    {
        formatln("jnl: append failed with: %r\n", ret);
    }

    s64 current_size = filesize(jnlfilepath);

    formatln("jnl: current size: %lli", current_size);

    input_stream_close(&is);
    output_stream_close(&os);

    jnl->vtbl->close(jnl);

    return SUCCESS;
}

int
main(int argc, char *argv[])
{
    ya_result ret;

    if(argc != 4)
    {
        printf("%s file..cjf origin ixfr.text.file\n"
               "\n", argv[0]);
        puts("This program takes a text file that looks like an IXFR :\n"
             "\n"
             "\tfqdn SOA x y last-serial ...\n"
             "\tfqdn SOA x y from-serial ...\n"
             "\tfqdn SOA x y from-serial+1 ...\n"
             "\t...\n"
             "\tfqdn SOA x y last-serial ...\n"
             "\n"
             "and appends it to a journal, creating it if needed.\n"
             "It's meant to test various case and sizes of journals.\n"
             "\n");

        return EXIT_FAILURE;
    }

    u8 origin[256];

    if(FAIL(ret = cstr_to_dnsname(origin, argv[2])))
    {
        formatln("error: %r", ret);
        return EXIT_FAILURE;
    }

    /* initializes the core library */
    dnscore_init();
    zdb_init();

    if(FAIL(ret = journal_generator(argv[1], origin, argv[3])))
    {
        formatln("failed: %r", ret);
    }

    flushout();
    flusherr();
    fflush(NULL);

    zdb_finalize();
    dnscore_finalize();

    return EXIT_SUCCESS;
}
