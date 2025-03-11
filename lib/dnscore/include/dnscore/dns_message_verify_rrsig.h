/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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

#ifndef __MESSAGE_VERIFY_H__
#define __MESSAGE_VERIFY_H__

#include <dnscore/dns_message.h>
#include <dnscore/dnskey_keyring.h>

#define MESSAGE_VERIFY_RRSIG_NOTSIGNED 1
#define MESSAGE_VERIFY_RRSIG_WRONG     2
#define MESSAGE_VERIFY_RRSIG_VERIFIED  4
#define MESSAGE_VERIFY_RRSIG_TIMEFRAME 8
#define MESSAGE_VERIFY_RRSIG_NOKEY     16

// CANNOT BE BIGGER THAN 32 BITS

struct dns_message_verify_rrsig_type_summary_s
{
    uint8_t verifiable_count;   // verified + wrong
    uint8_t unverifiable_count; // unknown key
    uint8_t verified_count;
    uint8_t wrong_count;
};

typedef struct dns_message_verify_rrsig_type_summary_s dns_message_verify_rrsig_type_summary_t;

struct dns_message_verify_rrsig_detail_s
{
    // this part MUST match the 18 bytes of wire image of an RRSIG

    uint16_t type_covered;
    uint8_t  algorithm;
    uint8_t  labels;
    uint32_t original_ttl;

    uint32_t expiration;
    uint32_t inception; // 16 bytes
    uint16_t tag;       // 18

    //

    uint16_t signature_size; // 20
    uint8_t  result;         // 21
    uint8_t  section;        // 22
                             // 23 24 are currently lost to memory alignment
    const uint8_t *signer_name;
    const uint8_t *signature;
    const uint8_t *fqdn;
};

typedef struct dns_message_verify_rrsig_detail_s dns_message_verify_rrsig_detail_t;

#define MESSAGE_VERIFY_RRSIG_RESULT_TYPE_SUMMARY 0
#define MESSAGE_VERIFY_RRSIG_RESULT_TYPE_VERIFY  1

#define MESSAGE_VERIFY_RRSIG_FEEDBACK_CONTINUE   0
#define MESSAGE_VERIFY_RRSIG_FEEDBACK_STOP       1
#define MESSAGE_VERIFY_RRSIG_FEEDBACK_ERROR      2

struct dns_message_verify_rrsig_result_s
{
    union
    {
        dns_message_verify_rrsig_type_summary_t *summary;
        dns_message_verify_rrsig_detail_t       *detail;
        void                                    *any;
    } data;

    uint8_t  result_type;
    uint8_t  section;
    uint16_t ctype;
};

typedef struct dns_message_verify_rrsig_result_s dns_message_verify_rrsig_result_t;

void                                             dns_message_verify_rrsig_format_handler(const void *result_u8_ptr, output_stream_t *os, int32_t, char, bool, void *reserved_for_method_parameters);

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

typedef ya_result dns_message_verify_rrsig_result(const dns_message_t *mesg, const struct dnskey_keyring_s *keyring, const dns_message_verify_rrsig_result_t *result, void *args);

ya_result         dns_message_verify_rrsig(const dns_message_t *mesg, struct dnskey_keyring_s *keyring, dns_message_verify_rrsig_result *feedback, void *args);

#endif // __MESSAGE_VERIFY_H__
