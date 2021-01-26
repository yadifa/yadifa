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

#ifndef __MESSAGE_VERIFY_H__
#define __MESSAGE_VERIFY_H__

#include <dnscore/message.h>
#include <dnscore/dnskey-keyring.h>

#define MESSAGE_VERIFY_RRSIG_NOTSIGNED  1
#define MESSAGE_VERIFY_RRSIG_WRONG      2
#define MESSAGE_VERIFY_RRSIG_VERIFIED   4
#define MESSAGE_VERIFY_RRSIG_TIMEFRAME  8
#define MESSAGE_VERIFY_RRSIG_NOKEY     16

// CANNOT BE BIGGER THAN 32 BITS

struct message_verify_rrsig_type_summary_s
{
    u8 verifiable_count;    // verified + wrong
    u8 unverifiable_count;  // unknown key
    u8 verified_count;
    u8 wrong_count;
};

typedef struct message_verify_rrsig_type_summary_s message_verify_rrsig_type_summary_s;

struct message_verify_rrsig_detail_s
{
    // this part MUST match the 18 bytes of wire image of an RRSIG
    
    u16 type_covered;
    u8 algorithm;
    u8 labels;
    u32 original_ttl;
    
    u32 expiration;
    u32 inception;          // 16 bytes
    u16 tag;                // 18
    
    //
    
    u16 signature_size;     // 20
    u8  result;             // 21
    u8  section;            // 22
                            // 23 24 are currently lost to memory alignment
    const u8 *signer_name;
    const u8 *signature;
    const u8 *fqdn;
};

typedef struct message_verify_rrsig_detail_s message_verify_rrsig_detail_s;

#define MESSAGE_VERIFY_RRSIG_RESULT_TYPE_SUMMARY 0
#define MESSAGE_VERIFY_RRSIG_RESULT_TYPE_VERIFY  1

#define MESSAGE_VERIFY_RRSIG_FEEDBACK_CONTINUE  0
#define MESSAGE_VERIFY_RRSIG_FEEDBACK_STOP      1
#define MESSAGE_VERIFY_RRSIG_FEEDBACK_ERROR     2     

struct message_verify_rrsig_result_s
{   
    union
    {
        message_verify_rrsig_type_summary_s *summary;
        message_verify_rrsig_detail_s *detail;
        void *any;
    } data;
    
    u8 result_type;
    u8 section;
    u16 ctype;
};

typedef struct message_verify_rrsig_result_s message_verify_rrsig_result_s;

void message_verify_rrsig_format_handler(const void *result_u8_ptr, output_stream *os, s32, char, bool, void* reserved_for_method_parameters);

/**
 * The feedback function is called while the message signature are verified.
 * It can return a feedback to continue or stop processing, or to give an error
 * to the original caller.
 * 
 * MESSAGE_VERIFY_RRSIG_FEEDBACK_CONTINUE
 * MESSAGE_VERIFY_RRSIG_FEEDBACK_STOP
 * MESSAGE_VERIFY_RRSIG_FEEDBACK_ERROR
 * 
 */

typedef ya_result message_verify_rrsig_result(const message_data *mesg, const struct dnskey_keyring *keyring, const message_verify_rrsig_result_s *result, void *args);

ya_result message_verify_rrsig(const message_data *mesg, struct dnskey_keyring *keyring, message_verify_rrsig_result *feedback, void *args);

#endif // __MESSAGE_VERIFY_H__
