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
 *  @brief journal_fusion file
 * 
 * journal_fusion test program, will not be installed with a "make install"
 * 
 * Reads a journal and writes an alternative version where pages are merged.
 * This is meant test slave behaviour with what happens with the TLD from a
 * certain European country.
 *
 */

#include <dnscore/dnscore.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/ptr_set.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/ctrl-rfc.h>
#include <dnscore/fdtools.h>
#include <dnscore/logger.h>

#include <dnsdb/zdb.h>
#define ZDB_JOURNAL_CODE 1

#include <dnsdb/journal-cjf.h>
#include <dnsdb/zdb-zone-path-provider.h>

#define CJF_READ_DUMP 0
#define LOG_ENABLE 1

#if JOURNAL_CJF_ENABLED

#if LOG_ENABLE

extern logger_handle *g_system_logger;
extern logger_handle *g_database_logger;

static void logger_setup()
{
    logger_init();
    logger_start();

    logger_handle_create("system", &g_system_logger);
    logger_handle_create("database", &g_database_logger);
    logger_handle_create_to_stdout("system", MSG_WARN_MASK);
    logger_handle_create_to_stdout("database", MSG_WARN_MASK);
}

#endif

static ya_result
dummy_database_info_provider(const u8 *origin, zdb_zone_info_provider_data *data, u32 flags)
{
    ya_result ret = ERROR;
    switch(flags)
    {
        case ZDB_ZONE_INFO_PROVIDER_STORED_SERIAL:
        {
            data->_u32 = 0;
            ret = SUCCESS;
            break;
        }
        case ZDB_ZONE_INFO_PROVIDER_MAX_JOURNAL_SIZE:
        {
            // get the zone desc and check

            data->_u64 = MAX_U32;
            ret = SUCCESS;
            
            break;
        }
        case ZDB_ZONE_INFO_PROVIDER_ZONE_TYPE:
        {
            // get the zone desc and check
            
            data->_u8 = ZT_MASTER;
            ret = SUCCESS;
            
            break;
        }
        case ZDB_ZONE_INFO_PROVIDER_STORE_TRIGGER:
        {
            ret = SUCCESS;
            break;
        }
        case ZDB_ZONE_INFO_PROVIDER_STORE_NOW:
        {
            ret = SUCCESS;
            break;
        }
        case ZDB_ZONE_INFO_PROVIDER_STORE_IN_PROGRESS:
        {
            ret = 0;
            break;
        }
        default:
        {
            ret = ERROR;
            break;
        }
    }
    
    return ret;
}

int
main(int argc, char *argv[])
{
    if(argc != 2)
    {
        fprintf(stderr, "%s filename.cjf\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    /* initializes the core library */
    dnscore_init();
    zdb_init();
    
    zdb_zone_info_set_provider(dummy_database_info_provider);
    
    const char *filename = argv[1];
    journal *src = NULL;
    journal *dst = NULL;
    ya_result ret;
    
    if(ISOK(ret = journal_cjf_open_file(&src, filename, (const u8*)"", FALSE)))
    {
        u32 first_serial;
        u32 last_serial;
        
        src->rc = 1;
        
        journal_get_first_serial(src, &first_serial);
        journal_get_last_serial(src, &last_serial);
        
        if(first_serial != last_serial)
        {
            ptr_set rr_add = PTR_SET_CUSTOM(ptr_set_dns_resource_record_node_compare);
            ptr_set rr_del = PTR_SET_CUSTOM(ptr_set_dns_resource_record_node_compare);
            input_stream is;
            
            dns_resource_record del_soa_rr;
            dns_resource_record add_soa_rr;
            dns_resource_record rr;
            dns_resource_record_init(&del_soa_rr);
            dns_resource_record_init(&add_soa_rr);
            dns_resource_record_init(&rr);
            
            if(ISOK(ret = journal_get_ixfr_stream_at_serial(src, first_serial, &is, NULL)))
            {
                if(FAIL(ret = dns_resource_record_read(&del_soa_rr, &is)))
                {
                    journal_release(src);
                    
                    formatln("failed to read first record: %r", ret);
                    return EXIT_FAILURE;
                }
                
                // got the first SOA (-)
                ptr_set *rr_set_other = &rr_add;
                ptr_set *rr_set_current = &rr_del;
                bool mode_del = TRUE;
                char mode = '-';
                
                formatln("%c %{dnsrr}", mode, &del_soa_rr);
                
                if(del_soa_rr.tctr.qtype != TYPE_SOA)
                {
                    journal_release(src);
                    
                    formatln("expected SOA record but got %{dnsrr}", &del_soa_rr);
                    return EXIT_FAILURE;
                }
                
                for(;;)
                {
                    if((ret = dns_resource_record_read(&rr, &is)) > 0)
                    {
                        // read all the following records (-+)
                        
                        if(rr.tctr.qtype != TYPE_SOA)
                        {                           
                            // if the record is not an SOA, remove it from the other set
                            //                              add it to the current set
                            
                            ptr_node *node = ptr_set_find(rr_set_other, &rr);
                            
                            if(node != NULL)
                            {
#if CJF_READ_DUMP
                                formatln("%c %{dnsrr} overrides the other", mode, &rr);
#endif
                                dns_resource_record *rr_key = (dns_resource_record*)node->key;
                                ptr_set_delete(rr_set_other, &rr);
                                dns_resource_record_clear(rr_key);
                                ZFREE_OBJECT(rr_key);
                            }
                            else
                            {
#if CJF_READ_DUMP
                                if(mode_del && (rr.tctr.qtype == TYPE_NSEC3))
                                {
                                    formatln("%c %{dnsrr} does not overrides the other (%p)", mode, &rr, rr_set_other);
                                    flushout();
                                    ptr_set_find(rr_set_other, &rr);
                                    logger_flush();
                                }
#endif
                                node = ptr_set_insert(rr_set_current, &rr);
                            
                                if(node->value == NULL)
                                {
                                    dns_resource_record *rr_copy;
                                    ZALLOC_OBJECT_OR_DIE(rr_copy, dns_resource_record, GENERIC_TAG);
                                    dns_resource_init_from_record(rr_copy, &rr);
                                    node->key = rr_copy;
                                    node->value = rr_copy;
#if CJF_READ_DUMP
                                    formatln("%c %{dnsrr} (%p -> %p (%{dnsrr}))", mode, &rr, rr_set_current, node, rr_copy);
#endif
                                }
                                else
                                {
#if CJF_READ_DUMP
                                    formatln("%c %{dnsrr} (%p -> %p already contains it))", mode, &rr, rr_set_current, node);
#endif
                                }
                            }
                        }
                        else
                        {
                            if(mode_del)
                            {
                                // if the record is an SOA, keep it and switch to reading all the +
                                
                                dns_resource_set_from_record(&add_soa_rr, &rr);
                                rr_set_current = &rr_add;
                                rr_set_other = &rr_del;
                                mode_del = FALSE;
                                mode = '+';
                            }
                            else
                            {
                                // if the record is an SOA, switch to reading all the -
                                
                                rr_set_current = &rr_del;
                                rr_set_other = &rr_add;
                                mode_del = TRUE;
                                mode = '-';
                            }
                            
                            formatln("%c %{dnsrr}", mode, &rr);
                        }
                    }
                    else
                    {
                        formatln("no more records in journal %s: %r", filename, ret);
                        
                        break;
                    }
                }
                
                journal_release(src);
                                
                if(ISOK(ret) && !mode_del)
                {
                    // ended in "add" mode, as expected
                    
    
#if LOG_ENABLE
                    logger_setup();
#endif
                    
                    char copy_filename[PATH_MAX];
                    
                    snprintf(copy_filename, sizeof(copy_filename), "%s.compressed.cjf", filename);
                    
                    unlink(copy_filename);
                    
                    if(ISOK(ret = journal_cjf_open_file(&dst, copy_filename, del_soa_rr.name, TRUE)))
                    {
                        output_stream ixfr_stream_dst;
                        
                        dst->rc = 1;
                        
                        bytearray_output_stream_init_ex(&ixfr_stream_dst, NULL, 0, BYTEARRAY_DYNAMIC);
                        
                        dns_resource_record_write(&del_soa_rr, &ixfr_stream_dst);
                        
                        FOREACH_PTR_SET(dns_resource_record*, rr, &rr_del)
                        {
                            dns_resource_record_write(rr, &ixfr_stream_dst);
                            dns_resource_record_clear(rr);
                            ZFREE_OBJECT(rr);
                        }
                        
                        dns_resource_record_write(&add_soa_rr, &ixfr_stream_dst);
                        
                        FOREACH_PTR_SET(dns_resource_record*, rr, &rr_add)
                        {
                            dns_resource_record_write(rr, &ixfr_stream_dst);
                            dns_resource_record_clear(rr);
                            ZFREE_OBJECT(rr);
                        }
                        
                        output_stream_flush(&ixfr_stream_dst);
                        
                        input_stream ixfr_stream_src;
                        bytearray_input_stream_init(&ixfr_stream_src,
                                bytearray_output_stream_buffer(&ixfr_stream_dst), bytearray_output_stream_size(&ixfr_stream_dst), FALSE);
                        
                        {
                            snprintf(copy_filename, sizeof(copy_filename), "%s.ixfr", filename);
                            output_stream os;
                            if(ISOK(file_output_stream_create(&os, copy_filename, 0640)))
                            {
                                for(;;)
                                {
                                    ret = input_stream_read(&ixfr_stream_src, (u8*)copy_filename, sizeof(copy_filename));
                                    if(ret > 0)
                                    {
                                        output_stream_write(&os, copy_filename, ret);
                                    }
                                    else
                                    {
                                        break;
                                    }
                                }
                            }
                            output_stream_close(&os);
                            bytearray_input_stream_reset(&ixfr_stream_src);
                        }

                        journal_append_ixfr_stream(dst, &ixfr_stream_src);
                        
                        input_stream_close(&ixfr_stream_src);
                        output_stream_close(&ixfr_stream_dst);
                        
                        journal_release(dst);
                    }
                    else
                    {
                        formatln("could not create journal %s: %r", copy_filename, ret);
                    }
                }
                else
                {
                    if(FAIL(ret))
                    {
                        formatln("failed to read the journal: %r", ret);
                    }
                    else
                    {
                        formatln("journal did not end in an 'add' phase");
                    }
                }
            }
        }
        else
        {
            journal_release(src);
        }
    }
    else
    {
        formatln("could not open journal %s: %r", filename, ret);
    }

    flushout();
    flusherr();
    fflush(NULL);

    zdb_finalize();
    dnscore_finalize();

    return EXIT_SUCCESS;
}

#else

int main()
{
    return 0;
}

#endif
