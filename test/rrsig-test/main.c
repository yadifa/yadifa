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
 *
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
#include <dnscore/nsec3-hash.h>
#include <dnscore/base32hex.h>
#include <dnscore/xfr_input_stream.h>
#include <dnscore/timems.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/dnskey-keyring.h>
#include <dnscore/message_verify_rrsig.h>

#include <dnscore/logger.h>
#include <dnscore/logger_channel_stream.h>

#define VERBOSE 1
#define TIMEOUT 3    // seconds
#define LOADFIRST 0

#define LOG_ENABLE 0 // enable dnscore system log to get
static int verbose = VERBOSE;

static dnskey_keyring zone_keyring = EMPTY_DNSKEY_KEYRING;

#if LOG_ENABLE


static void logger_setup()
{
    logger_init();
    logger_start();
    
    logger_handle_create_to_stdout("system", MSG_ALL_MASK);
}

#endif

static void
zone_keyring_init(const host_address *ip, const u8 *zone_fqdn)
{
    dnskey_keyring_add_from_nameserver(&zone_keyring, ip, zone_fqdn);
}

static ya_result
message_verify_rrsig_callback(const message_data *mesg,
        const struct dnskey_keyring *keyring, const message_verify_rrsig_result_s *result, void *args)
{
    (void)mesg;
    (void)keyring;
    (void)args;
    switch(result->result_type)
    {
        case MESSAGE_VERIFY_RRSIG_RESULT_TYPE_VERIFY:
        {
            format_writer fw = {message_verify_rrsig_format_handler, &result->data.detail->result};

            formatln("DNSKEY: RRSIG: %{dnstype}: %{dnsname}+%03hhu+%05hu: %w", &result->ctype, result->data.detail->signer_name, result->data.detail->algorithm, ntohs(result->data.detail->tag), &fw);

            if(result->ctype == TYPE_DNSKEY)
            {
                if((result->data.detail->result & MESSAGE_VERIFY_RRSIG_VERIFIED) != 0)
                {
                     formatln("DNSKEY: DNSKEY have been verified by this key");
                }
            }
            
            break;
        }
        case MESSAGE_VERIFY_RRSIG_RESULT_TYPE_SUMMARY:
        {
            formatln("DNSKEY: RRSIG: %{dnstype}: verifiable=%hhu verified=%hhu wrong=%hhu", &result->ctype, result->data.summary->verifiable_count, result->data.summary->verified_count, result->data.summary->wrong_count);
            
            if(result->ctype == TYPE_DNSKEY)
            {
                if(result->data.summary->verified_count > 0)
                {
                    formatln("DNSKEY: DNSKEY have been verified and will be added to the keyring");
                }
                else
                {
                    formatln("DNSKEY: DNSKEY have not been verified");
                    
                    // SECURETEST
                    
                    return MESSAGE_VERIFY_RRSIG_FEEDBACK_ERROR;
                }
            }
            
            break;
        }
    }
    
    return MESSAGE_VERIFY_RRSIG_FEEDBACK_CONTINUE;
}

static ya_result
rrsig_test(const host_address *ip, const u8 *zone_fqdn, const u8 *fqdn, u16 qtype)
{
    if(dnskey_keyring_isempty(&zone_keyring))
    {
        formatln("error: %{dnsname}: keyring is empty", zone_fqdn);
        return ERROR;
    }

    random_ctx rndctx = random_init_auto();
    message_data* mesg = message_new_instance();
    ya_result ret;

    u64 start = timeus();
    u64 stop;
    double dt;
    
    message_edns0_setmaxsize(4096);

    u16 id = (u16)random_next(rndctx);
    message_make_query_ex(mesg, id, fqdn, qtype, CLASS_IN, MESSAGE_EDNS0_DNSSEC);

    if(ISOK(ret = message_query(mesg, ip)))
    {
        stop = timeus();
        
        dt = stop - start;
        dt /= 1000.0;
        
        formatln("%{dnsname} %{dnstype}: query took %.3fms", fqdn, &qtype, dt);
        
        if(verbose)
        {
            message_print_format_dig(termout, message_get_buffer_const(mesg), message_get_size(mesg), 15, 0);
        }

        if((message_get_rcode(mesg) == RCODE_NOERROR) || (message_get_rcode(mesg) == RCODE_NXDOMAIN))
        {
            if(!dnskey_keyring_isempty(&zone_keyring))
            {
                
                if(ISOK(ret = message_verify_rrsig(mesg, &zone_keyring, message_verify_rrsig_callback, NULL)))
                {
                    formatln("%{dnsname} %{dnstype}: query verified", fqdn, &qtype);
                }
                else
                {
                    formatln("%{dnsname} %{dnstype}: query verification failed: %r (RCODE=%s)", fqdn, &qtype, ret, dns_message_rcode_get_name(message_get_rcode(mesg)));

                    message_print_format_dig(termout, message_get_buffer_const(mesg), message_get_size(mesg), 15, 0);
                }
            }
            else
            {
                formatln("%{dnsname}: keyring is empty", zone_fqdn, &qtype);
            }
        }
        else
        {
            formatln("error: %{dnsname} %{dnstype}: query failed with: RCODE=%s", fqdn, &qtype, dns_message_rcode_get_name(message_get_rcode(mesg)));
        }
    }
    else
    {
        formatln("error: %{dnsname} %{dnstype}: network failed with: %r (%i)", fqdn, &qtype, ret, ret);
    }
      
    message_free(mesg);
    random_finalize(rndctx);
    
    return ret;
}

static ya_result
zone_forall(const host_address *ip, const u8 *zone_fqdn)
{
    random_ctx rndctx = random_init_auto();
    message_data *query = message_new_instance();
    message_make_query(query, (u16)random_next(rndctx), zone_fqdn, TYPE_AXFR, CLASS_IN);

    /*
     * connect & send
     */

    input_stream xfris;
    input_stream is;
    output_stream os;
#if LOADFIRST
    output_stream baos;
    input_stream bais;
#endif
    u8 *fqdn;
    ya_result ret;
    int fd;
    int soa_count = 0;
    
    // connect
    u16 rtype;
    u16 rclass;
    s32 rttl;
    u16 rdata_size;
    u8 brol_fqdn[256];
#if LOADFIRST
    u8 prev_fqdn[256];
#endif
    
    brol_fqdn[0] = 4;
    brol_fqdn[1] = 'b';
    brol_fqdn[2] = 'r';
    brol_fqdn[3] = 'o';
    brol_fqdn[4] = 'l';
    
    fqdn = &brol_fqdn[5];
    
    input_stream_set_sink(&is);
    input_stream_set_sink(&xfris);
    output_stream_set_sink(&os);
    
#if LOADFIRST
    output_stream_set_sink(&baos);
    input_stream_set_sink(&bais);
#endif
    
    if(FAIL(ret = tcp_input_output_stream_connect_host_address(ip, &is, &os, 3)))
    {
        goto zone_forall_cleanup;
    }

    if(FAIL(ret = message_write_tcp(query, &os)))
    {
        goto zone_forall_cleanup;
    }
    
    output_stream_flush(&os);

    fd = fd_input_stream_get_filedescriptor(&is);

    tcp_set_sendtimeout(fd, TIMEOUT, 0);
    tcp_set_recvtimeout(fd, TIMEOUT, 0);

    if(FAIL(ret = xfr_input_stream_init(&xfris, zone_fqdn, &is, query, 0, XFR_ALLOW_AXFR)))
    {
        goto zone_forall_cleanup;
    }

#if LOADFIRST
    bytearray_output_stream_init_ex(&baos, NULL, 0x10000000, BYTEARRAY_DYNAMIC);
#endif
    
    int record_count = 0;
        
    while(soa_count < 2)
    {
        if(FAIL(ret = input_stream_read_dnsname(&xfris, fqdn)))
        {
            break;
        }
        
        if(FAIL(ret = input_stream_read_u16(&xfris, &rtype)))
        {
            break;
        }
        
        if(rtype == TYPE_SOA)
        {
            ++soa_count;
        }
        
        if(FAIL(ret = input_stream_read_u16(&xfris, &rclass)))
        {
            break;
        }
        
        if(FAIL(ret = input_stream_read_u32(&xfris, (u32*)&rttl)))
        {
            break;
        }
        
        if(FAIL(ret = input_stream_read_u16(&xfris, &rdata_size)))
        {
            break;
        }
        
        rdata_size = ntohs(rdata_size);
        
        if(FAIL(ret = input_stream_skip(&xfris, rdata_size)))
        {
            break;
        }

#if LOADFIRST
        if(!dnsname_equals(fqdn, prev_fqdn))
        {
            output_stream_write_u8(&baos, 0xff);
            output_stream_write_dnsname(&baos, fqdn);
        }
        else
        {
            dnsname_copy(prev_fqdn, fqdn);
        }
        output_stream_write_u8(&baos, 0xfe);
        output_stream_write_u16(&baos, rtype);
#else   
        // got a name from the zone
        
        if(FAIL(ret = rrsig_test(ip, zone_fqdn, fqdn, rtype)))
        {
            formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, fqdn, &rtype, ret);
        }
        
        if(FAIL(ret = rrsig_test(ip, zone_fqdn, brol_fqdn, rtype)))
        {
            formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, brol_fqdn, &rtype, ret);
        }
        
        if((record_count < 64) || ((record_count % 97) == 0))
        {
            if(FAIL(ret = rrsig_test(ip, zone_fqdn, fqdn, 65535 - record_count)))
            {
                formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, fqdn, &rtype, ret);
            }

            if(FAIL(ret = rrsig_test(ip, zone_fqdn, brol_fqdn, 65535 - record_count)))
            {
                formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, brol_fqdn, &rtype, ret);
            }
        }
        
        ++record_count;
#endif
    }

#if LOADFIRST
    // now the stream can be replayed

    bytearray_input_stream_init(&bais, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos), FALSE);
    while(bytearray_input_stream_remaining(&bais) > 0)
    {
        u16 rcode;
        u8 code;
        input_stream_read_u8(&bais, &code);
        switch(code)
        {
            case 0xff:
            {
                input_stream_read_dnsname(&bais, fqdn);
                break;
            }
            case 0xfe:
            {
                input_stream_read_u16(&bais, &rcode);

                // got a name from the zone
                
                if(FAIL(ret = rrsig_test(ip, zone_fqdn, fqdn, rtype)))
                {
                    formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, fqdn, &rtype, ret);
                }
                
                if(FAIL(ret = rrsig_test(ip, zone_fqdn, brol_fqdn, rtype)))
                {
                    formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, brol_fqdn, &rtype, ret);
                }
                
                if((record_count < 64) || ((record_count % 97) == 0))
                {
                    if(FAIL(ret = rrsig_test(ip, zone_fqdn, fqdn, 65535 - record_count)))
                    {
                        formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, fqdn, &rtype, ret);
                    }

                    if(FAIL(ret = rrsig_test(ip, zone_fqdn, brol_fqdn, 65535 - record_count)))
                    {
                        formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, brol_fqdn, &rtype, ret);
                    }
                }

                ++record_count;

                break;
            }
            default:
            {
                formatln("ERROR: unexpected code %x", code);
                goto zone_forall_cleanup;
            }
        }
    }
#endif
                
zone_forall_cleanup:
                
#if LOADFIRST
    input_stream_close(&bais);
    output_stream_close(&baos);
#endif
                            
    input_stream_close(&xfris);
    input_stream_close(&is);
    output_stream_close(&os);
                            
    message_free(query);
    return ret;
}

static ya_result
zone_for_all_in_axfr(const host_address *ip, const u8 *zone_fqdn, const char *filename)
{
    input_stream is;
    dns_resource_record rr;
    ya_result ret;
    
    if(FAIL(ret = file_input_stream_open(&is, filename)))
    {
        return ret;
    }

    buffer_input_stream_init(&is, &is, 4096);
    
    dns_resource_record_init(&rr);
    
    int record_count = 0;
        
    for(int soa_count = 0; soa_count < 2;)
    {
        if(FAIL(ret = dns_resource_record_read(&rr, &is)))
        {
            break;
        }
        
        if(rr.tctr.qtype == TYPE_SOA)
        {
            ++soa_count;
        }
        
        if(FAIL(ret = rrsig_test(ip, zone_fqdn, rr.name, rr.tctr.qtype)))
        {
            formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, rr.name, &rr.tctr.qtype, ret);
        }
                
        ++record_count;
    }

    dns_resource_record_clear(&rr);
    input_stream_close(&is);
    return ret;
}

static void help()
{
    println("parameters: server-ip zone [axfr-image-path]|[fqdn type]*");
    flushout();
}

int
main(int argc, char *argv[])
{
    host_address *ip = NULL;
    ya_result ret;
    u16 query_type;
    u8 zone_fqdn[256];
    u8 fqdn[256];
    
    /* initialises the core library */
    dnscore_init();
    
    if(argc < 3)
    {
        help();
        return EXIT_FAILURE;
    }
    
    anytype defaults = {._8u8={CONFIG_HOST_LIST_FLAGS_DEFAULT,128,0,0,0,0,0,0}};
    if(FAIL(ret = config_set_host_list(argv[1], &ip, defaults)))
    {
        formatln("%s is an invalid ip: %r", argv[1], ret);
        help();
        return EXIT_FAILURE;
    }

    if(ip->port == 0)
    {
        ip->port = NU16(53);
    }

    if(FAIL(ret = cstr_to_dnsname_with_check(zone_fqdn, argv[2])))
    {
        formatln("%s is an invalid zone: %r", argv[2], ret);
        help();
        return EXIT_FAILURE;
    }

#if LOG_ENABLE
    logger_setup();
#endif
    
    if(argc >= 5)
    {
        zone_keyring_init(ip, zone_fqdn);
        
        for(int i = 3; i < argc; i += 2)
        {
            if(FAIL(ret = cstr_to_dnsname_with_check(fqdn, argv[i])))
            {
                formatln("%s is an invalid fqdn: %r", argv[i], ret);
                help();
                return EXIT_FAILURE;
            }
    
            
            if(FAIL(ret = dns_type_from_case_name(argv[i + 1], &query_type)))
            {
                formatln("%s is an invalid type: %r", argv[i + 1], ret);
                help();
                return EXIT_FAILURE;
            }

            if(ISOK(ret = rrsig_test(ip, zone_fqdn, fqdn, query_type)))
            {
                println("SUCCESS");
            }
            else
            {
                formatln("FAILURE % r", ret);
            }
        }
    }
    else if(argc == 4)
    {
        zone_keyring_init(ip, zone_fqdn);
        
        // expects a path
        zone_for_all_in_axfr(ip, zone_fqdn, argv[3]);
    }
    else // argc == 3
    {
        zone_keyring_init(ip, zone_fqdn);
        
        ret = zone_forall(ip, zone_fqdn);
        
        if(FAIL(ret))
        {
            formatln("zone_forall(%{hostaddr}, %{dnsname}) failed with %r", ip, zone_fqdn, ret);
        }
    }

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return ISOK(ret)?EXIT_SUCCESS:EXIT_FAILURE;
}
