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
#include <dnscore/logger_channel_stream.h>

#define MODE_JNL 0
#define MODE_CJF 1
#define MODE_AXFR 2

static bool g_dump = FALSE;
static bool g_generate_update_files = FALSE;
static bool g_clean_mode = FALSE;
static int g_mode = MODE_JNL;

static const char *default_channel = "stdout default";

struct logger_name_handle_s
{
    const char *name;
    logger_handle **handlep;
};

static const struct logger_name_handle_s logger_name_handles[] =
    {
        {"system", &g_system_logger},
        {"database", &g_database_logger},
        {NULL, NULL}
    };

static void
config_logger_setdefault()
{
    logger_start();

    output_stream stdout_os;
    logger_channel *stdout_channel;

    fd_output_stream_attach(&stdout_os, dup_ex(1));
    stdout_channel = logger_channel_alloc();
    logger_channel_stream_open(&stdout_os, FALSE, stdout_channel);
    logger_channel_register(default_channel, stdout_channel);

    for(const struct logger_name_handle_s *name_handle = logger_name_handles; name_handle->name != NULL; name_handle++)
    {
        logger_handle_create(name_handle->name, name_handle->handlep);
#if !DEBUG
        logger_handle_add_channel(name_handle->name, MSG_PROD_MASK, default_channel);
#else
        logger_handle_add_channel(name_handle->name, MSG_ALL_MASK, default_channel);
#endif
    }

#if DEBUG
    log_debug("logging to stdout");
#endif
}

static int cjf_read_page_hdr(int fd, off_t ofs, journal_cjf_page_tbl_header *page)
{
    off_t pos = lseek(fd, ofs, SEEK_SET);
    if(pos != ofs)
    {
        return -1;
    }
    
    ssize_t n = readfully(fd, page, JOURNAL_CJF_PAGE_HEADER_SIZE);
    if(n != JOURNAL_CJF_PAGE_HEADER_SIZE)
    {
        return -2;
    }

    return 1;    
}

struct journal_cjf_page
{
    journal_cjf_page_tbl_header hdr;
    journal_cjf_page_tbl_item item[0x200];
    u32 pos;
    u32 end;
    u32 serial_from;
    u32 serial_to;
};
typedef struct journal_cjf_page journal_cjf_page;

static int cjf_scan_page(int fd, u32 ofs)
{
    static const u8 PAGE_MAGIC_ARRAY[4] = {'P', 'A', 'G', 'E'};
    u8 tmp[512];

    off_t pos = lseek(fd, ofs, SEEK_SET);
    
    if(pos != ofs)
    {
        formatln("; could not seek position %u: %r", ofs, ERRNO_ERROR);
        return -1;
    }
    
    int o = 0;
    
    for(;;)
    {
        int n = read(fd, tmp, sizeof(tmp));
        if(n < 0)
        {
            if(errno != EINTR)
            {
                return -1;
            }
            
            continue;
        }
        if(n == 0)
        {
            return -2;
        }
        
        for(int i = 0; i < n; ++i)
        {
            char c  = (char)tmp[i];
            if(c != PAGE_MAGIC_ARRAY[o])
            {
                o = 0;
            }
            else
            {
                ++o;
                if(o == 4)
                {
                    return pos + i - 3;
                }
            }
        }
        
        pos += n;
    }
}

static int cjf_read_page(int fd, u32 ofs, journal_cjf_page **out_page)
{
    journal_cjf_page_tbl_header hdr;
    
    if(cjf_read_page_hdr(fd, ofs, &hdr) > 0)
    {
        if(hdr.magic == CJF_PAGE_MAGIC)
        {
            formatln("; page @%u=%x", ofs, ofs);
            formatln(";   next: @%u=%x,", hdr.next_page_offset, hdr.next_page_offset);
            formatln(";   end : @%u=%x", hdr.stream_end_offset, hdr.stream_end_offset);
            formatln(";   item: %u/%u", hdr.count, hdr.size);
     
            if(hdr.size > 0x200)
            {
                formatln("; page size is most likely wrong");
                return -3;
            }
            
            if(hdr.count > hdr.size)
            {
                formatln("; item count is most likely wrong");
                return -4;
            }
            
            journal_cjf_page *page;
            MALLOC_OR_DIE(journal_cjf_page*, page, sizeof(journal_cjf_page), GENERIC_TAG);
            page->hdr = hdr;
            page->pos = ofs;
            ssize_t item_size = CJF_SECTION_INDEX_SLOT_SIZE * hdr.size;
            ssize_t n = readfully(fd, &page->item, item_size);
            if(n != item_size)
            {
                free(page);
                formatln("; could not read page: expected %lli but got %lli", item_size, n);
                return -5;
            }
            
            u32 e = lseek(fd, 0, SEEK_CUR);
            u32 l = hdr.stream_end_offset;
            
            if((hdr.count > 0) && (page->item[0].stream_file_offset != e))
            {
                formatln("; page @%u=%x: item[%3i] starts at %u=%x when %u=%x was expected", ofs, ofs, 0, page->item[0].stream_file_offset, page->item[0].stream_file_offset, e, e);
            }
            
            for(u16 i = 0; i < hdr.count; ++i)
            {
                u32 o = page->item[i].stream_file_offset;
                /*
                if(o >= e)
                {
                    formatln("page @%u=%x: item[%3i] starts at %u=%x when %u=%x was expected", ofs, ofs, i, o, o, e, e);
                }
                */
                if(o > l)
                {
                    formatln("; page @%u=%x: item[%3i] ends at %u=%x after %u=%x limit", ofs, ofs, i, o, o, l, l);
                }
            }
            
            for(u16 i = 1; i < hdr.count; ++i)
            {
                if(serial_ge(page->item[i - 1].ends_with_serial, page->item[i].ends_with_serial))
                {
                    formatln("; page @%u=%x: item[%3i] serial = %u <= %u", ofs, ofs, i, page->item[i].ends_with_serial, page->item[i - 1].ends_with_serial);
                }
            }
            
            *out_page = page;
            
            return 1; // page makes sense
        }
        else
        {
            formatln("; page @%u=%x has wrong magic", ofs, ofs);
            return -4;
        }
    }
    
    return -5;
}

static int cjf_read_page_records(int fd, journal_cjf_page *page)
{
    off_t exp = page->pos + JOURNAL_CJF_PAGE_HEADER_SIZE + CJF_SECTION_INDEX_SLOT_SIZE * page->hdr.size;
    off_t pos = lseek(fd, exp, SEEK_SET);
    
    if(pos != exp)
    {
        return -1;
    }
    
    // read all records and match them to the page data
    
    input_stream fis;
    input_stream bis;
    ya_result ret;
    
    fd_input_stream_attach(&fis, fd);  
    buffer_input_stream_init(&bis, &fis, 4096);
    dns_resource_record rr;
    dns_resource_record_init(&rr);
    
    int soa_count = 0;
    int line_count = -1;
    u32 serial;
    u32 serial_from = 0;
    u32 serial_to = 0;
    ya_result return_value = ERROR;
    
    for(;;)
    {
        if((ret = dns_resource_record_read(&rr, &bis)) <= 0)
        {
            // no more record (error or end of stream)
            if(g_dump)
            {
                formatln("$");
            }
            break;
        }
                
        if(soa_count == 0)
        {
            if(rr.tctr.qtype != TYPE_SOA)
            {
                formatln("; page @%u=%x record stream does not start by an SOA (%{dnsrr})", page->pos, page->pos, &rr);
                break;
            }
        }
        
        if(line_count >= page->hdr.count)
        {
            formatln("; page @%u=%x line %i @%u=%x successfully scanned a record %{dnsrr} outside of line bounds", page->pos, page->pos, line_count, pos, pos, &rr);
        }
        
        if(rr.tctr.qtype == TYPE_SOA)
        {
            ya_result err = rr_soa_get_serial(rr.rdata, rr.rdata_size, &serial);
            if(FAIL(err))
            {
                formatln("; page @%u=%x line %i @%u=%x could not get serial from first SOA: %r", page->pos, page->pos, line_count, pos, pos, err);
                break;
            }
            
            ++soa_count;
            
            if((soa_count & 1) != 0)
            {
                ++line_count;
                
                if(line_count < page->hdr.count)
                {
                    // odd
                    u32 e = page->item[line_count].stream_file_offset;

                    if(e != pos)
                    {
                        formatln("; page @%u=%x line %i @%u=%x does not start at the expected position %u=%x", page->pos, page->pos, line_count, pos, pos, e, e);
                    }

                    serial_from = serial;

                    if(line_count > 0)
                    {
                        if(serial_from != serial_to)
                        {
                            formatln("; page @%u=%x line %i @%u=%x serial %u does not match previous serial %u", page->pos, page->pos, line_count, pos, pos, serial_from, serial_to);
                        }
                    }
                    else
                    {
                        page->serial_from = serial_from;
                    }
                }
                else
                {
                    formatln("; page @%u=%x line %i @%u=%x successfully scanned an SOA %{dnsrr} outside of line bounds", page->pos, page->pos, line_count, pos, pos, &rr);
                }
            }
            else
            {
                // even
                
                serial_to = serial;
                
                page->serial_to = serial_to;
                
                if(line_count < page->hdr.count)
                {                
                    return_value = SUCCESS;

                    if(serial_ge(serial_from, serial_to))
                    {
                        formatln("; page @%u=%x line %i @%u=%x serial %u not follow previous serial %u", page->pos, page->pos, line_count, pos, pos, serial_from, serial_to);
                    }

                    if(serial_to != page->item[line_count].ends_with_serial)
                    {
                        formatln("; page @%u=%x line %i @%u=%x serial %u not end at expected value %u", page->pos, page->pos, line_count, pos, pos, serial_from, serial_to);
                    }
                }
                else
                {
                    formatln("; page @%u=%x line %i @%u=%x successfully scanned an SOA %{dnsrr} outside of line bounds", page->pos, page->pos, line_count, pos, pos, &rr);
                }
            }
        }
        
        if(g_dump)
        {
            rdata_desc rdatadesc={rr.tctr.qtype, rr.rdata_size, rr.rdata};
            
            formatln("%c | %{dnsname} %i %{dnstype} %{dnsclass} %{rdatadesc}",
                    (soa_count&1)?'-':'+',
                    rr.name,
                    ntohl(rr.tctr.ttl),
                    &rr.tctr.qtype,
                    &rr.tctr.qclass,
                    &rdatadesc);
            
            // formatln("%c | %{dnsrr}", (soa_count&1)?'-':'+', &rr);
        }
        
        pos += ret;
    }
    
    page->end = pos;
    
    formatln("; page @%u=%x streams covering serials %u to %u ended at position %u", page->pos, page->pos, page->serial_from, page->serial_to, page->end);
    
    dns_resource_record_clear(&rr);
    
    fd_input_stream_detach(buffer_input_stream_get_filtered(&bis));
    input_stream_close(&bis);
    
    return return_value;
}

#define PAGES_MAX 256

struct journal_cjf_page_tbl_entry
{
    journal_cjf_page_tbl_header hdr;
    int group;
};

typedef struct journal_cjf_page_tbl_entry journal_cjf_page_tbl_entry;

static int cjf_scan(const char *name)
{
    int fd;
    cjf_header hdr;

    fd = open_ex(name, O_RDONLY);
    
    if(fd < 0)
    {
        return -1;
    }
    
    formatln("; '%s' opened", name);
    
    s64 size = filesize(name);
    if(size <= (s64)CJF_HEADER_REAL_SIZE)
    {
        close_ex(fd);
        return -2;
    }
    
    ssize_t n = readfully(fd, &hdr, CJF_HEADER_REAL_SIZE);
    
    if(n != CJF_HEADER_REAL_SIZE)
    {
        close_ex(fd);
        return -3;
    }
    
    if(hdr.magic_plus_version != CJF_CJF0_MAGIC)
    {
        close_ex(fd);
        return -4;
    }
    
    formatln("; serial from %u to %u", hdr.serial_begin, hdr.serial_end);
    formatln("; first page starts at %u", hdr.first_index_offset);
    formatln("; page index starts at %u", hdr.table_index_offset);
    formatln("; last SOA starts at %u", hdr.last_soa_offset);
    formatln("; the last page ends before %u", hdr.last_page_offset_next);
    
    if(hdr.flags & JOURNAL_CFJ_FLAGS_OTHER_ENDIAN)
    {
        println("; other-endian: 1");
        close_ex(fd);
        return -5;
    }
    if(hdr.flags & JOURNAL_CFJ_FLAGS_MY_ENDIAN)
    {
        println("; my-endian: 1");
    }
    if(hdr.flags & JOURNAL_CFJ_FLAGS_NOT_EMPTY)
    {
        println("; empty: 1");
    }
    if(hdr.flags & JOURNAL_CFJ_FLAGS_DIRTY)
    {
        println("; dirty: 1");
    }
    if(hdr.flags & JOURNAL_CFJ_FLAGS_UNINITIALISED)
    {
        println("; not-initialised: 1");
    }
    
    // read a page, scan the records.
    
    u32 page_ofs = CJF_HEADER_REAL_SIZE;
    
    journal_cjf_page *page;
    
    for(;;)
    {
        if(cjf_read_page(fd, page_ofs, &page) >= 0)
        {
            // got a page
            // scan the records and match them to the page
                        
            if(ISOK(cjf_read_page_records(fd, page)))
            {
                page_ofs = page->end;
            }
            else
            {
                // try to scan page from just after
                ++page_ofs;
            }
        }
        else
        {
            // broken page
            // try to find the next magic "PAGE" in the file

            int next = cjf_scan_page(fd, page_ofs + 1);
            if(next > 0)
            {
                formatln("; page candidate at %u=%x", next, next);
                page_ofs = next;
            }
            else
            {
                formatln("; no more page candidate found");
                break;
            }
        }
    }
    
    close_ex(fd);
    
    return 0;
}

static void
axfr_scan(const char *filename)
{
    input_stream is;
    ya_result ret;
    
    dns_resource_record rr;
    
    if(FAIL(ret = file_input_stream_open(&is, filename)))
    {
        formatln("; %s: %r", filename, ret);
        return;
    }
    
    buffer_input_stream_init(&is, &is, 4096);
    
    dns_resource_record_init(&rr);
    
    for(int i = 0;; ++i)
    {
        if((ret = dns_resource_record_read(&rr, &is)) <= 0)
        {
            if(ret < 0)
            {
                formatln("; %s: record %i: %r", filename, i, ret);
            }
            break;
        }

        if((rr.tctr.qtype == TYPE_SOA) && (i > 0))
        {
            continue;
        }
        
        formatln("%{dnszrr}", &rr);
    }
    
    dns_resource_record_clear(&rr);
}

static void
jnl_scan(const char *filepath)
{
    journal *jnl = NULL;
    const char *filename = strrchr(filepath, '/');
    input_stream is;
    size_t filename_len;
    dns_resource_record rr;
    dns_resource_record last_soa_rr;
    ya_result ret;
    u32 serial_from = 0;
    u32 serial_to = 0;
    u32 update_file_index = 0;
    output_stream fos;
    bool fos_ready = FALSE;

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

    if(FAIL(ret = journal_get_ixfr_stream_at_serial(jnl, serial_from, &is, &rr)))
    {
        formatln("; jnl: '%s' file cannot read from its announced first serial %i : %r", filepath, serial_from, ret);
        return;
    }

    if(g_clean_mode)
    {
        dns_resource_record_init(&last_soa_rr);
        ret = journal_get_last_soa(jnl, &last_soa_rr);
        formatln("%{dnsrr}", &last_soa_rr);
    }

    char mode = '+';

    for(;;)
    {
        ret = dns_resource_record_read(&rr, &is);

        if(ret <= 0)
        {
            if(FAIL(ret))
            {
                formatln("; jnl: '%s' failed to read next record: %r", filepath,  ret);
            }
            else
            {
                formatln("; jnl: '%s' end of file", filepath);
            }

            break;
        }

        if(rr.tctr.qtype == TYPE_SOA)
        {
            mode ^= ('+'^'-');

            if(g_generate_update_files)
            {
                if(mode == '+')
                {
                    if(fos_ready)
                    {
                        osformatln(&fos, "show\nsend");
                        output_stream_close(&fos);
                        fos_ready = FALSE;
                    }
                }
            }
        }

        if(g_clean_mode)
        {
            formatln("%{dnsrr}", &rr);
        }
        else
        {
            formatln("%c %{dnsrr}", mode, &rr);
        }

        if(g_generate_update_files)
        {
            switch(rr.tctr.qtype)
            {
                case TYPE_SOA:
                case TYPE_NSEC:
                case TYPE_NSEC3:
                case TYPE_NSEC3PARAM:
                {
                    break;
                }
                default:
                {
                    if(mode == '-')
                    {
                        if(rr.tctr.qtype != TYPE_RRSIG)
                        {
                            if(!fos_ready)
                            {
                                char name[280];
                                snformat(name, sizeof(name), "%{dnsname}..update-%08i.txt", origin, update_file_index++);
                                file_output_stream_create(&fos, name, 0644);
                                buffer_output_stream_init(&fos, &fos, 4096);
                                osformatln(&fos, "zone %{dnsname}\nclass IN\nttl 86400", origin);
                                fos_ready = TRUE;
                            }

                            osformatln(&fos, "update del %{dnsrr}", &rr);
                        }
                    }
                    else
                    {
                        if((rr.tctr.qtype != TYPE_RRSIG) || ((rr.tctr.qtype == TYPE_RRSIG) && (rrsig_get_type_covered_from_rdata(rr.rdata, rr.rdata_size) == TYPE_DNSKEY)))
                        {
                            if(!fos_ready)
                            {
                                char name[280];
                                snformat(name, sizeof(name), "%{dnsname}..update-%08i.txt", origin, update_file_index++);
                                file_output_stream_create(&fos, name, 0644);
                                buffer_output_stream_init(&fos, &fos, 4096);
                                osformatln(&fos, "zone %{dnsname}\nclass IN\nttl 86400", origin);
                                fos_ready = TRUE;
                            }

                            osformatln(&fos, "update add %{dnsrr}", &rr);
                        }
                    }

                    break;
                }
            }
        }
    }

    if(g_clean_mode)
    {
        formatln("%{dnsrr}", &last_soa_rr);
        dns_resource_record_finalize(&last_soa_rr);
    }

    dns_resource_record_finalize(&rr);

    journal_release(jnl);

    formatln("; jnl: '%s' released", filepath);
}

/*
 * 
 */
int main(int argc, char** argv)
{
    dnscore_init();
    zdb_init();

    config_logger_setdefault();

    for(int i = 1; i < argc; ++i)
    {
        if(strcmp(argv[i], "-dump") == 0)
        {
            g_dump = TRUE;
            continue;
        }
        
        if(strcmp(argv[i], "-axfr") == 0)
        {
            g_mode = MODE_AXFR;
            continue;
        }
        
        if(strcmp(argv[i], "-cjf") == 0)
        {
            g_mode = MODE_CJF;
            continue;
        }

        if(strcmp(argv[i], "-jnl") == 0)
        {
            g_mode = MODE_JNL;
            continue;
        }

        if(strcmp(argv[i], "-clean") == 0)
        {
            g_clean_mode= TRUE;
            continue;
        }

        if(strcmp(argv[i], "-genupdate") == 0)
        {
            g_generate_update_files = TRUE;
            continue;
        }
        
        switch(g_mode)
        {
            case MODE_JNL:
            {
                formatln("scanning '%s' (jnl)", argv[i]);
                jnl_scan(argv[i]);
                break;
            }
            case MODE_CJF:
            {
                formatln("scanning '%s' (cjf)", argv[i]);
                cjf_scan(argv[i]);
                break;
            }
            case MODE_AXFR:
            {
                axfr_scan(argv[i]);
                break;
            }
        }
        
    }

    zdb_finalize();
    dnscore_finalize();
    return (EXIT_SUCCESS);
}
