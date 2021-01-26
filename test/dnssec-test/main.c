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

#include <sys/time.h>

#include <dnscore/dnscore-config.h>

#include <dnscore/dnscore.h>
#include <dnscore/threaded_dll_cw.h>
#include <dnscore/threaded-qsl-cw.h>
#include <dnscore/thread_pool.h>

#include <dnscore/message_verify_rrsig.h>
#include <dnscore/dns-udp.h>
#include <dnscore/dnsname.h>
#include <dnscore/message.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/packet_reader.h>
#include <dnscore/base64.h>
#include <dnscore/parsing.h>

#define SELF_SIGNED 1

static dns_udp_settings_s dns_udp_settings =
{
    6000000,//DNS_UDP_TIMEOUT_US,
    65536,//DNS_UDP_SEND_RATE,
    1000000,//DNS_UDP_SEND_BANDWIDTH,
    DNS_UDP_RECV_BANDWIDTH,
    64,//DNS_UDP_SEND_QUEUE,
    1,//DNS_UDP_PORT_COUNT_OVERRIDE,        // parallel tasks
    3,//DNS_UDP_RETRY_COUNT,
    DNS_UDP_PER_DNS_RATE,
    DNS_UDP_PER_DNS_BANDWIDTH,
    DNS_UDP_PER_DNS_FREQ_MIN,
    1,
    DNS_UDP_CALLBACK_QUEUE_SIZE,
    DNS_UDP_CALLBACK_THREAD_COUNT,
    DNS_UDP_TCP_THREAD_POOL_SIZE,
    TRUE    // fallback on timeout
};

smp_int q_count = SMP_INT_INITIALIZER;

dnskey_keyring g_keyring;

static ya_result
dnssec_quality_check_dnskey_verify_rrsig_callback(const message_data *mesg, const struct dnskey_keyring *keyring, const message_verify_rrsig_result_s *result, void *args)
{
    (void)mesg;
    (void)keyring;
    (void)args;
    //const dns_simple_message_s *msg = (const dns_simple_message_s*)args;
      
    switch(result->result_type)
    {
        case MESSAGE_VERIFY_RRSIG_RESULT_TYPE_VERIFY:
        {
            osformatln(termout,"DNSKEY: RRSIG: %{dnstype}: %{dnsname}+%03hhu+%05hu: %hhx", &result->ctype, result->data.detail->signer_name, result->data.detail->algorithm, ntohs(result->data.detail->tag), result->data.detail->result);
            
            /*
            #define MESSAGE_VERIFY_RRSIG_NOTSIGNED  1
            #define MESSAGE_VERIFY_RRSIG_WRONG      2
            #define MESSAGE_VERIFY_RRSIG_VERIFIED   4
            #define MESSAGE_VERIFY_RRSIG_TIMEFRAME  8
            #define MESSAGE_VERIFY_RRSIG_NOKEY     16
            */
            
            if(result->ctype == TYPE_DNSKEY)
            {
                if((result->data.detail->result & MESSAGE_VERIFY_RRSIG_VERIFIED) != 0)
                {
                    osformatln(termout,"DNSKEY: DNSKEY have been verified by this key");
                }
                else
                {
                    if((result->data.detail->result & MESSAGE_VERIFY_RRSIG_NOTSIGNED) != 0)
                    {
                        osformatln(termout,"DNSKEY: DNSKEY is not signed");
                    }
                    if((result->data.detail->result & MESSAGE_VERIFY_RRSIG_TIMEFRAME) != 0)
                    {
                        osformatln(termout,"DNSKEY: DNSKEY signature outside its validity period");
                    }
                    if((result->data.detail->result & MESSAGE_VERIFY_RRSIG_NOKEY) != 0)
                    {
                        osformatln(termout,"DNSKEY: DNSKEY no signing key has been found");
                    }
                    if((result->data.detail->result & MESSAGE_VERIFY_RRSIG_WRONG) != 0)
                    {
                        osformatln(termout,"DNSKEY: DNSKEY signature is wrong");
                    }
                }
            }
            
            break;
        }
        case MESSAGE_VERIFY_RRSIG_RESULT_TYPE_SUMMARY:
        {
            osformatln(termout,"DNSKEY: RRSIG: %{dnstype}: verifiable=%hhu verified=%hhu wrong=%hhu", &result->ctype, result->data.summary->verifiable_count, result->data.summary->verified_count, result->data.summary->wrong_count);
            
            if(result->ctype == TYPE_DNSKEY)
            {
                if(result->data.summary->verified_count > 0)
                {
                    osformatln(termout,"DNSKEY: DNSKEY have been verified and will be added to the keyring");
                }
                else
                {
                    osformatln(termout,"DNSKEY: DNSKEY have not been verified");
                    
                    // SECURETEST

                    return MESSAGE_VERIFY_RRSIG_FEEDBACK_ERROR;
                }
            }
            
            break;
        }
    }
    
    return MESSAGE_VERIFY_RRSIG_FEEDBACK_CONTINUE;
}

static dns_resource_record*
dnskey_record_build_from_key(const u8 *domain, u16 keyflags, u8 keyproto, u8 keyalg, char* base64key)
{
    u8 keyrdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES + 4];
        
    keyrdata[0] = keyflags >> 8;
    keyrdata[1] = keyflags;
    keyrdata[2] = keyproto;
    keyrdata[3] = keyalg;
    
    parse_remove_spaces(base64key);
    
    size_t len = strlen(base64key);
    
    if(BASE64_DECODED_SIZE(len) > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
    {
        osformatln(termout,"ds_record_build_from_key: key size too big");
        return NULL;
    }
        
    ya_result keyrdata_size = base64_decode(base64key, len, &keyrdata[4]);
    
    if(FAIL(keyrdata_size))
    {
        osformatln(termout,"ds_record_build_from_key: base64 decode failed: %r", keyrdata_size);
        
        if(keyrdata_size == PARSEB64_ERROR)
        {
            //log_memdump_ex(MODULE_MSG_HANDLE, LOG_ERR, base64key, len, 32, OSPRINT_DUMP_HEX|OSPRINT_DUMP_TEXT);
        }
        return NULL;
    }
    
    keyrdata_size += 4;
    
    dns_resource_record *rr = dns_resource_record_new_instance();
    dns_resource_record_ensure_size(rr, keyrdata_size);
    rr->name_len = dnsname_copy(rr->name, domain);
    rr->rdata_size = keyrdata_size;
    memcpy(rr->rdata, keyrdata, rr->rdata_size);    
    rr->tctr.qtype = TYPE_DNSKEY;
    rr->tctr.qclass = CLASS_IN;
    rr->tctr.ttl = ntohl(86400);
    rr->tctr.rdlen = htons(rr->rdata_size);
    return rr;
}

                         //"AwEAAcnNMhq9Dbimzx5TPG3RuB19auBXrK1tyENIvq4768mju02Z9w/gIvDZrSUr7HA/vVMIT35bXWbNvIjyI4lRHCbmZmGkQvWDbaHV243pLV3aEmywIi5IhHjhNR283dg8oKnzHiz49aS1HjfTsvSKirHhqB5s/js37IiNAc2VxVTIldANqS6dmA7XNcVxtxKMA+cRomsN2EYEuwKmU37bgCz0OgRP90ce+SugXHEGmNeRda0hLiGsZMCTIXU5kOWeUNwMbbcAbKRDVsgLURZTbMZG7kTa2JHkT8M7ErDYWsx8Y+g5HW3+yv2sPiycINqgGwvxx1IK7qvijZdMFYEQJqLbWrbFUHfiayy9Za4NgpGRTJQVsDAv0RNy2p0kPbv2rYujH25zKLfPU704UX3faHeXJnRNDaIfw5qzBZx82tNmCXUyC6RwhIXcSJOYvYf1K6886NFlKF3o8+cilUlwZSAjq4V7v3qS3QPNCyEVbgbg5xlY0r5+maXmYcojzztD4/MPlf+yHIRP/ss5tdBRr1Z3ixXHKBUmt+xH9PJ0hdc+I8OUb4QE9DH0DEeZpDSLmQdzMkYY0ega3hSxMxgiYspl/VbIeg98zrAU3iQv2IWfN0VxArBbHJIQ6vOwI5k23u4YI5hhnpyu2C/0I/KjQoQ7NNX4uoo4dtKCTqYSUQ7t"
static char key_base64[] = "AwEAAcnNMhq9Dbimzx5TPG3RuB19auBXrK1tyENIvq4768mju02Z9w/gIvDZrSUr7HA/vVMIT35bXWbNvIjyI4lRHCbmZmGkQvWDbaHV243pLV3aEmywIi5IhHjhNR283dg8oKnzHiz49aS1HjfTsvSKirHhqB5s/js37IiNAc2VxVTIldANqS6dmA7XNcVxtxKMA+cRomsN2EYEuwKmU37bgCz0OgRP90ce+SugXHEGmNeRda0hLiGsZMCTIXU5kOWeUNwMbbcAbKRDVsgLURZTbMZG7kTa2JHkT8M7ErDYWsx8Y+g5HW3+yv2sPiycINqgGwvxx1IK7qvijZdMFYEQJqLbWrbFUHfiayy9Za4NgpGRTJQVsDAv0RNy2p0kPbv2rYujH25zKLfPU704UX3faHeXJnRNDaIfw5qzBZx82tNmCXUyC6RwhIXcSJOYvYf1K6886NFlKF3o8+cilUlwZSAjq4V7v3qS3QPNCyEVbgbg5xlY0r5+maXmYcojzztD4/Mplf+yHIRP/ss5tdBRr1Z3ixXHKBUmt+xH9PJ0hdc+I8OUb4QE9DH0DEeZpDSLmQdzMkYY0ega3hSxMxgiYspl/VbIeg98zrAU3iQv2IWfN0VxArBbHJIQ6vOwI5k23u4YI5hhnpyu2C/0I/KjQoQ7NNX4uoo4dtKCTqYSUQ7t";

static void answers_process_cb(struct async_message_s *amsg)
{
    dns_simple_message_s* msg = (dns_simple_message_s*)amsg->args;
    ya_result ret;
    
    osformatln(termout,"answer: @%{hostaddr} %{dnsname} %{dnstype} %{dnsclass}: %r", msg->name_server, msg->fqdn, &msg->qtype, &msg->qclass, amsg->error_code);
    
    if(ISOK(amsg->error_code))
    {
        const message_data *mesg;
        if((mesg = dns_udp_simple_message_get_answer(msg)) != NULL)
        {
            // get key
            // verify message
            osformatln(termout, "answer: got a message");
            
#if SELF_SIGNED
            packet_unpack_reader_data pr;
            packet_reader_init_from_message(&pr, mesg);
            packet_reader_skip_fqdn(&pr);   // query
            packet_reader_skip(&pr, 4);

            u16 r_type;
            u16 r_class;
            s32 r_ttl;
            u16 r_rdata_size;            
            u8 r_fqdn[256];
            u8 r_rdata[8192];
            
            while(ISOK(ret = packet_reader_read_fqdn(&pr, r_fqdn, sizeof(r_fqdn))))
            {
                packet_reader_read_u16(&pr, &r_type);
                packet_reader_read_u16(&pr, &r_class);
                packet_reader_read_u32(&pr, (u32*)&r_ttl);
                packet_reader_read_u16(&pr, &r_rdata_size);
                packet_reader_read(&pr, r_rdata, ntohs(r_rdata_size)); // exact

                if(r_type == TYPE_DNSKEY)
                {
                    // add to keyring
                    
                    char r_fqdn_ascii[256];
                    dnsname_to_cstr(r_fqdn_ascii, r_fqdn);
                    
                    dnssec_key *key;
                    
                    if(ISOK(ret = dnskey_new_from_rdata(r_rdata, ntohs(r_rdata_size), r_fqdn, &key)))
                    {
                        u16 tag = dnskey_get_tag_from_rdata(r_rdata, ntohs(r_rdata_size));
                        osformatln(termout, "dnssec: @%{hostaddr} %{dnsname} %{dnstype} %{dnsclass}: generated key: %d", msg->name_server, msg->fqdn, &msg->qtype, &msg->qclass, tag);
                        if(ISOK(ret = dnskey_keyring_add(&g_keyring, key)))
                        {
                            osformatln(termout, "dnssec: @%{hostaddr} %{dnsname} %{dnstype} %{dnsclass}: added key: %d", msg->name_server, msg->fqdn, &msg->qtype, &msg->qclass, tag);
                        }
                        else
                        {
                            osformatln(termout, "dnssec: @%{hostaddr} %{dnsname} %{dnstype} %{dnsclass}: already got key: %d", msg->name_server, msg->fqdn, &msg->qtype, &msg->qclass, tag);
                            dnskey_release(key);
                        }
                    }                    
                }
            }
#endif
            dns_resource_record* dnskey_rr = dnskey_record_build_from_key(msg->fqdn, 256, 3, 8, key_base64);
            
            if(ISOK(ret = message_verify_rrsig(mesg, &g_keyring, dnssec_quality_check_dnskey_verify_rrsig_callback, msg)))
            {
                osformatln(termout, "answer: got a valid signed message");
            }
            else
            {
                osformatln(termout, "answer: got a badly signed message (or not at all)");
            }

            dns_resource_record_free(dnskey_rr);
        }
    }
    
    smp_int_dec(&q_count);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    static const char *servers[] =
    {
        "79.140.41.233",
        "83.149.68.6",
        "84.38.68.60",
        //"2001:1af8:3100:b010::1:1",
        //"2001:4d88:2000:45::d00f",
        //"2a00:5080:1:1a::1",
        NULL
    };
    
    char *domain = "antweiler.eu.";
    ya_result ret;
    
    dnscore_init();
    
    dnskey_keyring_init(&g_keyring);
    
    dns_udp_handler_configure(&dns_udp_settings);
    
    async_message_pool_init();
    
    if(ISOK(ret = dns_udp_handler_init()))
    {
        if(ISOK(ret = dns_udp_handler_start()))
        {            
            // do the job
            
            u8 fqdn[256];
            
            cstr_to_dnsname(fqdn, domain);
            
            for(int i = 0; servers[i] != NULL; i++)
            {
                host_address *srv = NULL;
                anytype host_parms = {._8u8={CONFIG_HOST_LIST_FLAGS_DEFAULT,255,0,0,0,0,0,0}};
                if(ISOK(ret = config_set_host_list(servers[i], &srv, host_parms)))
                {
                    smp_int_inc(&q_count);
                    srv->port = htons(53);
                    dns_udp_send_simple_message(srv, fqdn, TYPE_DNSKEY, CLASS_IN, DNS_SIMPLE_MESSAGE_FLAGS_DNSSEC, answers_process_cb, NULL);
                    osformatln(termout, "queued query to %{hostaddr}", srv);
                }
            }
            
            while(smp_int_get(&q_count) != 0)
            {
                sleep(1);
            }
            
            flushout();
            flusherr();
            
            dns_udp_handler_stop();
        }
        
        dns_udp_handler_finalize();
        
        async_message_pool_finalize();
    }
    /*
    ya_result message_verify_rrsig(const message_data *mesg, struct dnskey_keyring *keyring, message_verify_rrsig_result *feedback, void *args);
    */
    flushout();
    flusherr();

    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
