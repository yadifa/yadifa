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
 *  @brief test
 */

#include <dnscore/dnscore.h>
#include <dnscore/dnsname.h>
#include <dnscore/format.h>
#include <dnscore/base64.h>
#include <dnscore/tsig.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/message.h>
#include <dnscore/config_settings.h>
#include <dnscore/random.h>
#include <dnscore/packet_reader.h>

static const value_name_table hmac_digest_enum[]=
{
    {HMAC_MD5   , "hmac-md5"    },
    {HMAC_SHA1  , "hmac-sha1"   },
    {HMAC_SHA224, "hmac-sha224" },
    {HMAC_SHA256, "hmac-sha256" },
    {HMAC_SHA384, "hmac-sha384" },
    {HMAC_SHA512, "hmac-sha512" },
    {HMAC_MD5   , "md5"    },
    {HMAC_SHA1  , "sha1"   },
    {HMAC_SHA224, "sha224" },
    {HMAC_SHA256, "sha256" },
    {HMAC_SHA384, "sha384" },
    {HMAC_SHA512, "sha512" },
    {0, NULL}
};


static void help()
{
    println("parameters: domain [server-ip=127.0.0.1] [tsig-name tsig-base64 [tsig-type=md5]] [wait-before-exit-seconds]");
    flushout();
}

int message_answer_verify(message_data *mesg);

// ya_result tsig_register(const u8 *name, const u8 *mac, u16 mac_size, u8 mac_algorithm);

// domain
// ip (default 127.0.0.1)
// tsig base64 (default none)
// tsig type (default md5)

static const u16 tsig_variable_class_ttl[3] = {CLASS_ANY, 0, 0};

int
main(int argc, char *argv[])
{
    output_stream os;
    input_stream is;
    host_address *ip = NULL;
    u8 *hmac = NULL;
    size_t hmac_size = 0;
    tsig_item *tsig = NULL;
    tsig_hmac_t tsig_hmac = NULL;
    const u8* tsig_algorithm_name = (const u8*)"?";
    u32 tsig_algorithm_name_size = 0;
    u32 hmac_algorithm = 0;
    int query_mac_size = 0;
    ya_result ret;
    u32 timeout_s = 10; // seconds
    int soa_count = 0;
    int soa_rdata_size = 0;
    int tmp_size;
    int program_exit_code = EXIT_FAILURE;
    int pause_before_exit_seconds = 0;
    
    u8 fqdn[256];
    u8 hmac_name[256];
    u8 query_mac[1024];
    u8 soa_rdata[1024];
    u8 tmp[1024];
    
    //
    
    for(int i = 0; i < argc; ++i)
    {
        printf("%s ", argv[i]);
    }
    puts("");
    fflush(NULL);
    
    //
    
    /* initializes the core library */
    dnscore_init();

    if(argc < 2)
    {
        help();
        return EXIT_FAILURE;
    }
    
    if(FAIL(ret = cstr_to_dnsname_with_check(fqdn, argv[1])))
    {
        formatln("%s is an invalid fqdn: %r", argv[1], ret);
        help();
        return EXIT_FAILURE;
    }
    
    if(argc >= 3)
    {
        anytype defaults = {._8u8={CONFIG_HOST_LIST_FLAGS_DEFAULT,1,0,0,0,0,0,0}};

        if(FAIL(ret = config_set_host_list(argv[2], &ip, defaults)))
        {
            formatln("%s is an invalid ip: %r", argv[2], ret);
            help();
            return EXIT_FAILURE;
        }

        if(ip->port == 0)
        {
            ip->port = NU16(53);
        }
    }

    if(argc >= 4)
    {
        pause_before_exit_seconds = 0;

        if(sscanf(argv[argc - 1], "%i", &pause_before_exit_seconds) == 1)
        {
            if(pause_before_exit_seconds < 0)
            {
                pause_before_exit_seconds = 0;
            }
            --argc;
        }
    }

    formatln(";; will pause for %i seconds before exit", pause_before_exit_seconds);
    
    if(argc >= 5)
    {    
        if(FAIL(ret = cstr_to_dnsname_with_check(hmac_name, argv[3])))
        {
            formatln("%s is an invalid fqdn: %r", argv[3], ret);
            help();
            return EXIT_FAILURE;
        }

        size_t b64len = strlen(argv[4]);
        size_t rawlen = BASE64_DECODED_SIZE(b64len);
        
        hmac = (u8*)malloc(rawlen);
        
        if(hmac == NULL) abort();
        
        if(FAIL(ret = base64_decode(argv[4], b64len, hmac)))
        {
            formatln("%s cannot be decoded as base64: %r", ret);
            help();
            return EXIT_FAILURE;
        }
        
        hmac_size = ret;
        hmac_algorithm = HMAC_MD5;
    
        if(argc >= 6)
        {
            if(FAIL(ret = value_name_table_get_value_from_casename(hmac_digest_enum, argv[5], &hmac_algorithm)))
            {
                formatln("%s is not a known hmac algorithm: %r", ret);
                help();
                return EXIT_FAILURE;
            }
        }
        
        if(FAIL(ret = tsig_register(hmac_name, hmac, hmac_size, hmac_algorithm)))
        {
            formatln("cannot register the key: %r", ret);
            help();
            return EXIT_FAILURE;
        }
        
        tsig = tsig_get(hmac_name);
        
        tsig_algorithm_name = tsig_get_algorithm_name(hmac_algorithm);
        tsig_algorithm_name_size = dnsname_len(tsig_algorithm_name);
        
        print(";; new tsig: ");
        osprint_dump(termout, hmac, hmac_size, 32, OSPRINT_DUMP_BASE16);
        println("");
        
        tsig_hmac = tsig_hmac_allocate();

        if(tsig_hmac == NULL)
        {
            return EXIT_FAILURE;
        }

        if(FAIL(ret = hmac_init(tsig_hmac, hmac, hmac_size, hmac_algorithm)))
        {
            hmac_free(tsig_hmac);
            return ret;
        }
    }
    
    random_ctx rndctx = random_init_auto();
    
    message_data *query = message_new_instance();
    
    message_make_query(query, (u16)random_next(rndctx), fqdn, TYPE_AXFR, CLASS_IN);
    
    message_data *answer = query; // message_new_instance();
    // for UDP listeners only : message_reset_control(answer);
    
    if(tsig != NULL)
    {
        message_sign_query(query, tsig);
        
        // corrupt the digest
        //
        // this failing proves the server agrees with us (by failing)
        //
        // message_get_buffer(query)[message_get_size(query) - 7]++;
        //
        
        query_mac_size = message_tsig_mac_get_size(query);
        if((size_t)query_mac_size > sizeof(query_mac))
        {
            formatln("query_mac_size = %i > %i", query_mac_size, sizeof(query_mac));
            return EXIT_FAILURE;
        }
        
        message_tsig_mac_copy(query, query_mac);
    }

    if(FAIL(ret = tcp_input_output_stream_connect_host_address(ip, &is, &os, timeout_s)))
    {
        formatln("tcp connection to %{hostaddr} failed: %r", ip, ret);
        return EXIT_FAILURE;
    }
    
    if(FAIL(ret = message_write_tcp(query, &os)))      
    {
        formatln("query write failed: %r", ret);
        
        input_stream_close(&is);
        output_stream_close(&os);
        return EXIT_FAILURE;
    }
    
    formatln(";; Query\n;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;");
    
    message_print_format_dig(termout, message_get_buffer_const(query), message_get_size(query), 15, 0);
    
    flushout();
    
    message_tcp_serial_reset(answer);
    
    for(int packet_num = 0; soa_count < 2; ++packet_num)
    {
        formatln("\n;; Answer %i\n;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;", packet_num);
        
        if(FAIL(ret = message_read_tcp(answer, &is)))
        {
            formatln("answer read failed: %r", ret);
            break;
        }
        
        if(ret == 0)
        {
            formatln("\n;; The End");
            break;
        }

        usleep(50000);
        
        message_print_format_dig(termout, message_get_buffer_const(answer), message_get_size(answer), 1, 0);
        /*
        if(FAIL(ret = message_answer_verify(answer)))
        {
            formatln(";;\n;; %r\n;;\n", ret);
            break;
        }
        */
        
        // decode the message
        
        if(tsig_hmac != NULL)
        {
            bool got_tsig = FALSE;
            
            if(message_get_additional_count_ne(answer) != 0)
            {            
                packet_unpack_reader_data purd;

                packet_reader_init_from_message(&purd, answer);

                u16 qr = message_get_query_count(answer);

                for(u16 i = qr; i > 0; --i)
                {
                    packet_reader_skip_fqdn(&purd);
                    packet_reader_skip(&purd, 4);
                }

                u16 an = message_get_answer_count(answer);
                u16 ns = message_get_authority_count(answer);
                u16 ar = message_get_additional_count(answer);

                struct type_class_ttl_rdlen *tctr;

                for(u16 i = an + ns; i > 0; --i)
                {
                    tmp_size = packet_reader_read_fqdn(&purd, tmp, sizeof(tmp));

                    tctr = (struct type_class_ttl_rdlen*)packet_reader_get_next_u8_ptr_const(&purd);

                    packet_reader_skip(&purd, 10);

                    if(soa_count != 0)
                    {
                        if(tctr->qtype != TYPE_SOA)
                        {
                            packet_reader_skip(&purd, ntohs(tctr->rdlen));
                        }
                        else
                        {
                            tmp_size = packet_reader_read_rdata(&purd, TYPE_SOA, ntohs(tctr->rdlen), tmp, sizeof(tmp));

                            if(tmp_size == soa_rdata_size)
                            {
                                if(memcmp(tmp, soa_rdata, soa_rdata_size) == 0)
                                {
                                    formatln(";; last SOA");
                                    ++soa_count;
                                }
                            }
                        }
                    }
                    else
                    {
                        if(tctr->qtype != TYPE_SOA)
                        {
                            formatln("expected SOA, got %{dnstype}", &tctr->qtype);

                            goto critical_failure;
                        }

                        soa_rdata_size = packet_reader_read_rdata(&purd, TYPE_SOA, ntohs(tctr->rdlen), soa_rdata, sizeof(soa_rdata));
                        ++soa_count;
                    }
                }

                // at the additional section

                for(u16 i = ar; i > 0; --i)
                {
                    u32 current_record_offset;
                    s32 tsig_name_size;
                    u32 time_lo;
                    u16 time_hi;
                    u16 fudge;
                    u16 mac_size;

                    u8* mac;
                    unsigned int digest_size;
                    u32 algorithm_name_size;

                    u16 original_id;
                    u16 error_code;
                    u16 other_size;

                    u8* other;

                    u8 tsig_name[256];
                    u8 algorithm_name[256];
                    u8 digest[64];

                    current_record_offset = purd.offset;

                    tsig_name_size = packet_reader_read_fqdn(&purd, tsig_name, sizeof(tsig_name));

                    tctr = (struct type_class_ttl_rdlen*)packet_reader_get_next_u8_ptr_const(&purd);

                    if(tctr->qtype == TYPE_TSIG)
                    {
                        got_tsig = TRUE;

                        packet_reader_skip(&purd, 10);
                        if(ar != 1)
                        {
                            formatln(";;\n;; TSIG IS NOT THE LAST RECORD\n;;");
                            goto critical_failure;
                        }

                        algorithm_name_size = packet_reader_read_fqdn(&purd, algorithm_name, sizeof(algorithm_name));
                        (void)algorithm_name_size;

                        if(!dnsname_equals(tsig_algorithm_name, algorithm_name))
                        {
                            formatln(";;\n;; TSIG algorithm mismatch: expected %{dnsname} != %{dnsname}\n;;", tsig_algorithm_name, algorithm_name);
                            goto critical_failure;
                        }

                        packet_reader_read_u16(&purd, &time_hi);
                        packet_reader_read_u32(&purd, &time_lo);
                        packet_reader_read_u16(&purd, &fudge);
                        packet_reader_read_u16(&purd, &mac_size);

                        mac = (u8*)packet_reader_get_next_u8_ptr_const(&purd);

                        packet_reader_skip(&purd, ntohs(mac_size));
                        packet_reader_read_u16(&purd, &original_id);
                        packet_reader_read_u16(&purd, &error_code);
                        packet_reader_read_u16(&purd, &other_size);

                        other = (u8*)packet_reader_get_next_u8_ptr_const(&purd);

                        packet_reader_skip(&purd, ntohs(other_size));

                        if(packet_num == 0)
                        {
                            // Request MAC

                            formatln("digest: +mac: ");
                            u16 query_mac_size_ne = htons(query_mac_size);
                            osprint_dump(termout, &query_mac_size_ne, 2, 0, OSPRINT_DUMP_BASE16);
                            println("");
                            osprint_dump(termout, query_mac, query_mac_size, 32, OSPRINT_DUMP_BASE16);
                            println("");
                            hmac_update(tsig_hmac, &query_mac_size_ne, 2);
                            hmac_update(tsig_hmac, query_mac, query_mac_size);
                        }

                        // DNS Message

                        message_sub_additional_count(answer, 1);
                        formatln("digest: +message: ");
                        if(current_record_offset <= 64)
                        {
                            osprint_dump(termout, message_get_buffer_const(answer), current_record_offset, 32, OSPRINT_DUMP_BASE16|OSPRINT_DUMP_TEXT);
                        }
                        else
                        {
                            osprint_dump(termout, message_get_buffer_const(answer), 32, 32, OSPRINT_DUMP_BASE16|OSPRINT_DUMP_TEXT);
                            println("\n...");
                            osprint_dump(termout, message_get_buffer_const(answer) + current_record_offset - 32, 32, 32, OSPRINT_DUMP_BASE16|OSPRINT_DUMP_TEXT);
                        }
                        println("");

                        message_set_id(answer, original_id);
                        hmac_update(tsig_hmac, message_get_buffer_const(answer), current_record_offset);
                        message_add_additional_count(answer, 1);

                        if(packet_num == 0)
                        {
                            // TSIG Variables

                            format("digest: +variables: \n        name: ");
                            osprint_dump(termout, tsig_name, tsig_name_size, 32, OSPRINT_DUMP_BASE16|OSPRINT_DUMP_TEXT);
                            print("\n class + ttl: ");
                            osprint_dump(termout, tsig_variable_class_ttl, 6, 32, OSPRINT_DUMP_BASE16);
                            print("\n   algorithm: ");
                            osprint_dump(termout, tsig_algorithm_name, tsig_algorithm_name_size, 32, OSPRINT_DUMP_BASE16|OSPRINT_DUMP_TEXT);
                            print("\n        time: ");
                            osprint_dump(termout, &time_hi, 2, 0, OSPRINT_DUMP_BASE16);
                            osprint_dump(termout, &time_lo, 4, 0, OSPRINT_DUMP_BASE16);
                            print("\n       fudge: ");
                            osprint_dump(termout, &fudge, 2, 0, OSPRINT_DUMP_BASE16);
                            print("\n  error code: ");
                            osprint_dump(termout, &error_code, 2, 0, OSPRINT_DUMP_BASE16);
                            print("\n  other size: ");
                            osprint_dump(termout, &other_size, 2, 0, OSPRINT_DUMP_BASE16);
                            print("\n       other: ");
                            osprint_dump(termout, other, ntohs(other_size), 0, OSPRINT_DUMP_BASE16);
                            println("");

                            hmac_update(tsig_hmac, tsig_name, tsig_name_size);
                            hmac_update(tsig_hmac, tsig_variable_class_ttl, 6);
                            hmac_update(tsig_hmac, tsig_algorithm_name, tsig_algorithm_name_size);
                            hmac_update(tsig_hmac, &time_hi, 2);
                            hmac_update(tsig_hmac, &time_lo, 4);
                            hmac_update(tsig_hmac, &fudge, 2);
                            hmac_update(tsig_hmac, &error_code, 2);
                            hmac_update(tsig_hmac, &other_size, 2);
                            hmac_update(tsig_hmac, other, ntohs(other_size));
                        }
                        else
                        {
                            format("digest: +timers: \n");
                            osprint_dump(termout, &time_hi, 2, 0, OSPRINT_DUMP_BASE16);
                            osprint_dump(termout, &time_lo, 4, 0, OSPRINT_DUMP_BASE16);
                            osprint_dump(termout, &fudge, 2, 0, OSPRINT_DUMP_BASE16);
                            hmac_update(tsig_hmac, &time_hi, 2);
                            hmac_update(tsig_hmac, &time_lo, 4);
                            hmac_update(tsig_hmac, &fudge, 2);
                            println("");
                        }

                        digest_size = sizeof(digest);
                        if(hmac_final(tsig_hmac, digest, &digest_size) != 1)
                        {
                            formatln("tsig_hmac_final failed");
                            goto critical_failure;
                        }

                        if(digest_size != ntohs(mac_size))
                        {
                            formatln("digest size mismatch");
                            goto critical_failure;
                        }

                        if(memcmp(digest, mac, digest_size) != 0)
                        {
                            formatln("digest value mismatch");
                            format("expected: ");
                            osprint_dump(termout, mac, digest_size, 32, OSPRINT_DUMP_BASE16);
                            println("");
                            format("computed: ");
                            osprint_dump(termout, digest, digest_size, 32, OSPRINT_DUMP_BASE16);
                            println("");

                            if(FAIL(ret = message_answer_verify(answer)))
                            {
                                formatln(";;\n;; %r\n;;\n", ret);
                                break;
                            }

                            goto critical_failure;
                        }

                        formatln(";; digest value verified");
                        
                        hmac_free(tsig_hmac);
                        
                        if(soa_count < 2)
                        {
                            print(";; new tsig: ");
                            osprint_dump(termout, hmac, hmac_size, 32, OSPRINT_DUMP_BASE16);
                            println("");
                            
                            tsig_hmac = tsig_hmac_allocate();

                            if(tsig_hmac == NULL)
                            {
                                formatln("failed to allocate TSIG_HMAC");
                                goto critical_failure;
                            }

                            if(FAIL(hmac_init(tsig_hmac, hmac, hmac_size, hmac_algorithm)))
                            {
                                hmac_free(tsig_hmac);
                                formatln("failed to init TSIG HMAC for algorithm %i", hmac_algorithm);
                                goto critical_failure;
                            }

                            u16 digest_size_ne = htons(digest_size);

                            formatln("digest: +digest: ");

                            osprint_dump(termout, &digest_size_ne, 2, 0, OSPRINT_DUMP_BASE16);
                            osprint_dump(termout, digest, digest_size, 0, OSPRINT_DUMP_BASE16);
                            hmac_update(tsig_hmac, &digest_size_ne, 2);
                            hmac_update(tsig_hmac, digest, digest_size);
                        }
                        else
                        {
                            program_exit_code = EXIT_SUCCESS;
                        }
                    }
                    else
                    {
                        packet_reader_skip(&purd, 10 + ntohs(tctr->rdlen));
                    }
                }
            } // #AN > 0
            
            if(!got_tsig)
            {
                // digest the whole message
                
                // DNS Message
                    
                    formatln("digest: +message: ");
                    if(message_get_size(answer) <= 64)
                    {
                        osprint_dump(termout, message_get_buffer_const(answer), message_get_size(answer), 32, OSPRINT_DUMP_BASE16|OSPRINT_DUMP_TEXT);
                    }
                    else
                    {
                        osprint_dump(termout, message_get_buffer_const(answer), 32, 32, OSPRINT_DUMP_BASE16|OSPRINT_DUMP_TEXT);
                        println("\n...");
                        osprint_dump(termout, message_get_buffer_const(answer) + message_get_size(answer) - 32, 32, 32, OSPRINT_DUMP_BASE16|OSPRINT_DUMP_TEXT);
                    }
                    println("");
            }
            
        } // TSIG handling
       
        message_tcp_serial_increment(answer);
    }

critical_failure:

    if(pause_before_exit_seconds > 0)
    {
        formatln("pausing for %i seconds", pause_before_exit_seconds);
        s64 until = pause_before_exit_seconds;
        until *= 1000000ULL;
        until += timeus();
        s64 now;
        while((now = timeus()) < until)
        {
            usleep(until - now);
        }
    }

    input_stream_close(&is);
    output_stream_close(&os);
    
    puts((program_exit_code == EXIT_SUCCESS)?"SUCCESS":"FAILURE");
    
    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return program_exit_code;
}
