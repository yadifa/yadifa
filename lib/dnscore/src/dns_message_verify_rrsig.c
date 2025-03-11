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

#include "dnscore/dnscore_config.h"
#include "dnscore/sys_types.h"
#include "dnscore/dns_message_verify_rrsig.h"
#include <dnscore/dns_packet_reader.h>
#include "dnscore/format.h"
#include "dnscore/ptr_treemap.h"
#include "dnscore/logger.h"

extern logger_handle_t *g_system_logger;
#define MODULE_MSG_HANDLE        g_system_logger

#define TYPE_FQDN_HAS_RECORDS    1
#define TYPE_FQDN_HAS_SIGNATURES 2
// #define TYPE_FQDN_HAS_VERIFIED_SIGNATURES       4
// #define TYPE_FQDN_HAS_WRONG_SIGNATURES          8
// #define TYPE_FQDN_HAS_UNKNOWN_SIGNATURES       16

#define RRSVFQDN_TAG             0x4e44514656535252
#define MSGVRDTT_TAG             0x545444525647534d

void dns_message_verify_rrsig_format_handler(const void *result_u8_ptr, output_stream_t *os, int32_t p0, char p1, bool p2, void *reserved_for_method_parameters)
{
    (void)p0;
    (void)p1;
    (void)p2;
    (void)reserved_for_method_parameters;

    uint8_t            flag = *(uint8_t *)result_u8_ptr;
    static const char *separator = ",";
    int                separator_size = 0;

    if(flag & MESSAGE_VERIFY_RRSIG_NOTSIGNED)
    {
        output_stream_write(os, "not-signed", 10);
        separator_size = 1;
    }
    if(flag & MESSAGE_VERIFY_RRSIG_WRONG)
    {
        output_stream_write(os, separator, separator_size);
        output_stream_write(os, "wrong", 5);
        separator_size = 1;
    }
    if(flag & MESSAGE_VERIFY_RRSIG_VERIFIED)
    {
        output_stream_write(os, separator, separator_size);
        output_stream_write(os, "verified", 8);
        separator_size = 1;
    }
    if(flag & MESSAGE_VERIFY_RRSIG_TIMEFRAME)
    {
        output_stream_write(os, separator, separator_size);
        output_stream_write(os, "wrong-time-frame", 16);
        separator_size = 1;
    }
    if(flag & MESSAGE_VERIFY_RRSIG_NOKEY)
    {
        output_stream_write(os, separator, separator_size);
        output_stream_write(os, "no-key", 6);
    }
}

static int32_t message_verify_rrsig_compute_digest(bytes_verifier_t *verifier, const uint8_t *owner, uint16_t rtype, uint16_t rclass, const uint8_t *rrsig_rdata, uint32_t rrsig_rdata_size, ptr_vector_t *rrset_canonised_rdata)
{
    log_debug6("message_verify_rrsig_compute_digest(%p, %{dnsname},%{dnstype},%{dnsclass},@%p,%u,@%p)", verifier, owner, &rtype, &rclass, rrsig_rdata, rrsig_rdata_size, rrset_canonised_rdata);

    uint8_t rr_header[2 + 2 + 4];

    if(rrsig_rdata_size < RRSIG_RDATA_HEADER_LEN)
    {
        return INCORRECT_RDATA;
    }

    if(rtype != GET_U16_AT(rrsig_rdata[0]))
    {
        return RRSIG_COVERED_TYPE_DIFFERS;
    }

    int32_t  owner_len = dnsname_len(owner);

    uint32_t rttl = GET_U32_AT(rrsig_rdata[4]);

    SET_U16_AT(rr_header[0], rtype);
    SET_U16_AT(rr_header[2], rclass);
    SET_U32_AT(rr_header[4], rttl);

    /*
     * Type covered | algorithm | labels | original_ttl | exp | inception | tag | origin
     *
     */

    uint32_t rrsig_rdata_prefix_size = RRSIG_RDATA_HEADER_LEN + dnsname_len(&rrsig_rdata[RRSIG_RDATA_HEADER_LEN]);

    verifier->vtbl->update(verifier, rrsig_rdata, rrsig_rdata_prefix_size);

#if DEBUG
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, rrsig_rdata, rrsig_rdata_prefix_size, 32);
#endif

    for(int_fast32_t i = 0; i <= rrset_canonised_rdata->offset; i++)
    {
        verifier->vtbl->update(verifier, owner, owner_len);

#if DEBUG
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, owner, owner_len, 32);
#endif

        verifier->vtbl->update(verifier, rr_header, sizeof(rr_header));

#if DEBUG
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, rr_header, sizeof(rr_header), 32);
#endif

        uint8_t *rdata_size_rdata = (uint8_t *)rrset_canonised_rdata->data[i];
        uint16_t rdata_size = ntohs(GET_U16_AT(rdata_size_rdata[0]));
        verifier->vtbl->update(verifier, rdata_size_rdata, rdata_size + 2);

#if DEBUG
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, rdata_size_rdata, rdata_size + 2, 32);
#endif
    }

    /*
     * Retrieve the digest
     */

    return SUCCESS;
}

static int message_verify_canonize_sort_rdata_compare(const void *a, const void *b)
{
    uint8_t *ptr_a = (uint8_t *)a;
    uint8_t *ptr_b = (uint8_t *)b;

    uint16_t rr_a_size = ntohs(GET_U16_AT(ptr_a[0]));
    uint16_t rr_b_size = ntohs(GET_U16_AT(ptr_b[0]));

    int      ret;

    ptr_a += 2;
    ptr_b += 2;

    int diff_len = rr_a_size;
    diff_len -= rr_b_size;

    if(diff_len != 0)
    {
        uint16_t len = MIN(rr_a_size, rr_b_size);

        ret = memcmp(ptr_a, ptr_b, len);

        if(ret == 0)
        {
            ret = diff_len;
        }
    }
    else
    {
        ret = memcmp(ptr_a, ptr_b, rr_a_size);
    }

    return ret;
}

static ya_result message_verify_rrsig_result_default_handler(const dns_message_t *mesg, const struct dnskey_keyring_s *keyring, const dns_message_verify_rrsig_result_t *result, void *args)
{
    (void)mesg;
    (void)keyring;
    (void)result;
    (void)args;

    return MESSAGE_VERIFY_RRSIG_FEEDBACK_CONTINUE;
}

static void message_verify_rrsig_free_rrset(void *data) { free(data); }

static int  message_verify_rrsig_node_compare(const void *key_a, const void *key_b)
{
    const uint8_t *fqdn_a = key_a;
    const uint8_t *fqdn_b = key_b;

    int32_t        type_a = GET_U16_AT_P(fqdn_a);
    int32_t        type_b = GET_U16_AT_P(fqdn_b);

    int32_t        ret = type_a - type_b;

    if(ret == 0)
    {
        fqdn_a += 2;
        fqdn_b += 2;

        ret = dnsname_compare(fqdn_a, fqdn_b);
    }

    return ret;
}

static void message_verify_rrsig_init(ptr_treemap_t *section_type_fqdn)
{
    ptr_treemap_init(section_type_fqdn);
    section_type_fqdn->compare = message_verify_rrsig_node_compare;
}

static void message_verify_rrsig_set_flag(ptr_treemap_t *section_type_fqdn, const uint8_t *type_record_fqdn, uint32_t type_record_fqdn_len, uint8_t flag_bits)
{
    // create the type-fqdn entry if needed
    ptr_treemap_node_t *type_fqdn_node = ptr_treemap_find(section_type_fqdn, type_record_fqdn);
    if(type_fqdn_node == NULL)
    {
#if DEBUG
        log_debug7("message_verify_rrsig: new node %{dnsname} %{dnstype}", type_record_fqdn + 2, type_record_fqdn);
#endif

        uint8_t *type_record_fqdn_copy;
        MALLOC_OR_DIE(uint8_t *, type_record_fqdn_copy, type_record_fqdn_len, RRSVFQDN_TAG);
        memcpy(type_record_fqdn_copy, type_record_fqdn, type_record_fqdn_len);
        type_fqdn_node = ptr_treemap_insert(section_type_fqdn, type_record_fqdn_copy);
        type_fqdn_node->value = NULL; // has records, has verified signatures, has wrong signatures, has unknown signatures

        // the next phase will scan for each of there types instead
    }
    intptr_t flag = (intptr_t)type_fqdn_node->value;

#if DEBUG
    log_debug7("message_verify_rrsig: set node %{dnsname} %{dnstype} %x => %x", type_record_fqdn + 2, type_record_fqdn, flag, flag | flag_bits);
#endif

    flag |= flag_bits;
    type_fqdn_node->value = (void *)flag;
}

static void message_verify_rrsig_clear_callback(ptr_treemap_node_t *type_fqdn_node) { free(type_fqdn_node->key); }

static void message_verify_rrsig_clear(ptr_treemap_t *section_type_fqdn)
{
    // create the type-fqdn entry if needed
    ptr_treemap_callback_and_finalise(section_type_fqdn, message_verify_rrsig_clear_callback);
}

/**
 *
 * @param mesg
 * @param keyring
 * @param feedback see the definition of message_verify_rrsig_result
 * @param args argument for the feedback function
 * @return
 */

ya_result dns_message_verify_rrsig(const dns_message_t *mesg, struct dnskey_keyring_s *keyring, dns_message_verify_rrsig_result *feedback, void *args)
{
    // for the answer, authority and additional sections
    //   count the RRSIG in the section for which we have a key
    //   for all rrset but the RRSIG one
    //     if the rrset has no signature
    //       feedback ...
    //     elseif the rrset has at least one signature that can be verified
    //       for each non-verifiable signature
    //         feedback ...
    //       rof
    //       canonize the rrset
    //       for each verifiable signature
    //         verify the signature
    //         feedback ...
    //       rof
    //     fi
    //   rof
    // rof

    if(keyring == NULL)
    {
        return 0;
    }

    dns_message_verify_rrsig_result_t result;
    time_t                            now;
    uint32_t                          total_wrong_signatures = 0;
    ya_result                         return_code;
    dns_packet_reader_t               pr;
    ya_result                         feedback_result = MESSAGE_VERIFY_RRSIG_FEEDBACK_CONTINUE;
    uint32_t                          type_record_fqdn_len;
    uint8_t                           type_record_fqdn[2 + 256];
    uint8_t                           record_buffer[8192];

    if(feedback == NULL)
    {
        feedback = message_verify_rrsig_result_default_handler;
    }

    result.data.any = NULL;
    result.result_type = 0;
    result.section = 0;
    result.ctype = 0;

    dns_packet_reader_init_from_message(&pr, mesg);

    for(uint16_t qd_count = dns_message_get_query_count(mesg); qd_count != 0; --qd_count)
    {
        if(FAIL(return_code = dns_packet_reader_skip_fqdn(&pr)))
        {
            return return_code;
        }

        if(FAIL(return_code = dns_packet_reader_skip(&pr, 4)))
        {
            return return_code;
        }
    }

    now = time(NULL);

    // for sections

    for(uint_fast8_t section = 1; section < 3; section++) // addtitionals are not processed
    {
        result.section = section;
        result.ctype = TYPE_NONE;

        uint32_t      section_start = pr.packet_offset;

        ptr_treemap_t section_type_fqdn;
        message_verify_rrsig_init(&section_type_fqdn);

        for(uint_fast16_t count = dns_message_get_section_count(mesg, section); count > 0; --count)
        {
            // count RRSIG / types

            if(FAIL(return_code = dns_packet_reader_read_fqdn(&pr, &type_record_fqdn[2], sizeof(type_record_fqdn) - 2)))
            {
                message_verify_rrsig_clear(&section_type_fqdn);

                return return_code;
            }

            type_record_fqdn_len = return_code + 2;

            uint16_t rtype;

            if(FAIL(return_code = dns_packet_reader_read_u16(&pr, &rtype)))
            {
                message_verify_rrsig_clear(&section_type_fqdn);

                return return_code;
            }

            if(FAIL(return_code = dns_packet_reader_skip(&pr, 2 + 4)))
            {
                message_verify_rrsig_clear(&section_type_fqdn);

                return return_code;
            }

            // FQDN + TYPE ( + CLASS ) = key of what can be signed

            uint16_t rdata_size;

            if(FAIL(return_code = dns_packet_reader_read_u16(&pr, &rdata_size)))
            {
                message_verify_rrsig_clear(&section_type_fqdn);

                return return_code;
            }

            rdata_size = ntohs(rdata_size);

            if(rtype == TYPE_RRSIG)
            {
                if(rdata_size < RRSIG_RDATA_HEADER_LEN)
                {
                    message_verify_rrsig_clear(&section_type_fqdn);

                    return INCORRECT_RDATA;
                }

                uint16_t ctype;

                if(FAIL(return_code = dns_packet_reader_read_u16(&pr, &ctype))) // exact
                {
                    message_verify_rrsig_clear(&section_type_fqdn);

                    return return_code;
                }

                if(ctype == TYPE_RRSIG)
                {
                    message_verify_rrsig_clear(&section_type_fqdn);

                    return RRSIG_UNSUPPORTED_COVERED_TYPE;
                }

                if(FAIL(return_code = dns_packet_reader_skip(&pr, rdata_size - 2)))
                {
                    message_verify_rrsig_clear(&section_type_fqdn);

                    return return_code;
                }

                SET_U16_AT_P(type_record_fqdn, ctype);
                message_verify_rrsig_set_flag(&section_type_fqdn, type_record_fqdn, type_record_fqdn_len, TYPE_FQDN_HAS_SIGNATURES);
            }
            else
            {
                if(FAIL(return_code = dns_packet_reader_skip(&pr, rdata_size)))
                {
                    message_verify_rrsig_clear(&section_type_fqdn);

                    return return_code;
                }

                SET_U16_AT_P(type_record_fqdn, rtype);
                message_verify_rrsig_set_flag(&section_type_fqdn, type_record_fqdn, type_record_fqdn_len, TYPE_FQDN_HAS_RECORDS);
            }
        } // count

        // at most 5956 records (beside the query) in a message

        // all the records of the section have been parsed (once)
        // signatures have been counted (verifiable & unknown)

        // for each type encountered ...

        dns_message_verify_rrsig_type_summary_t type_info = {0, 0, 0, 0};

        ptr_treemap_iterator_t                  section_types_fqdn_iter;

        ptr_treemap_iterator_init(&section_type_fqdn, &section_types_fqdn_iter);
        while(ptr_treemap_iterator_hasnext(&section_types_fqdn_iter))
        {
            ptr_treemap_node_t *types_fqdn_node = ptr_treemap_iterator_next_node(&section_types_fqdn_iter);

            const uint8_t      *type_fqdn = (uint8_t *)types_fqdn_node->key;
            uint16_t            ctype = GET_U16_AT_P(type_fqdn);
            type_fqdn += 2;
            uint8_t flags = (uint8_t)(intptr_t)types_fqdn_node->value; // double cast just to explicitly show what is happening

#if DEBUG
            log_debug6("message_verify_rrsig: %{dnsname} %{dnstype} (%x)", type_fqdn, &ctype, flags);
#endif

            result.ctype = ctype;

            if((flags & (TYPE_FQDN_HAS_RECORDS | TYPE_FQDN_HAS_SIGNATURES)) != (TYPE_FQDN_HAS_RECORDS | TYPE_FQDN_HAS_SIGNATURES))
            {
                // no signatures or no records

                if(flags & TYPE_FQDN_HAS_SIGNATURES)
                {
                    // not signed
                }
                else
                {
                    // signature without record ?
                }

                continue;
            }

            // all/some verifiable : report the verified ones
            // build the RRSET (canonised)
            // verify

            // =>

            // rewind to the beginning of the section

            pr.packet_offset = section_start;

            ptr_vector_t rrset = PTR_VECTOR_EMPTY;

            for(uint_fast16_t count = dns_message_get_section_count(mesg, section); count > 0; --count)
            {
                // count RRSIG / types

                if(ISOK(return_code = dns_packet_reader_read_record(&pr, record_buffer, sizeof(record_buffer))))
                {
                    uint8_t *fqdn = record_buffer;

                    if(dnsname_equals(fqdn, type_fqdn))
                    {
                        struct type_class_ttl_rdlen_s *tctr = (struct type_class_ttl_rdlen_s *)&fqdn[dnsname_len(fqdn)];

                        if(tctr->rtype == ctype) // and fqdn is good ...
                        {
                            // append the record data to the array

                            uint8_t *rdata = (uint8_t *)tctr;
                            rdata += 10;

                            uint8_t *rdata_network_size_rdata;
                            uint16_t rdata_size = ntohs(tctr->rdlen);

                            MALLOC_OR_DIE(uint8_t *, rdata_network_size_rdata, rdata_size + 2, MSGVRDTT_TAG);
                            SET_U16_AT(rdata_network_size_rdata[0], tctr->rdlen);
                            memcpy(&rdata_network_size_rdata[2], rdata, rdata_size);

                            ptr_vector_append(&rrset, rdata_network_size_rdata);
                        }
                    }
                }
                else
                {
                    ptr_vector_callback_and_clear(&rrset, message_verify_rrsig_free_rrset);
                    ptr_vector_finalise(&rrset);

                    message_verify_rrsig_clear(&section_type_fqdn);

                    return return_code; // impossible at this point
                }
            }

            // rrset contains all the RDATA for the fqdn/type

            ptr_vector_qsort(&rrset, message_verify_canonize_sort_rdata_compare);

#if DEBUG
            for(int_fast32_t i = 0; i <= rrset.offset; i++)
            {
                uint8_t *rdata = rrset.data[i];
                uint16_t rdata_size = ntohs(GET_U16_AT(rdata[0]));
                rdata += 2;
                rdata_desc_t rdatadesc = {ctype, rdata_size, rdata};
                log_debug6(" + %{typerdatadesc}", &rdatadesc);
            }
#endif
            // we know the label & cie
            // we have the rdata on canonized order
            // now ... verify

            uint32_t saved_offset = pr.packet_offset;

            // rewind to the beginning of the section

            pr.packet_offset = section_start;

            for(uint_fast16_t count = dns_message_get_section_count(mesg, section); count > 0; --count)
            {
                // get RRSIG covering RRSET

                if(ISOK(return_code = dns_packet_reader_read_record(&pr, record_buffer, sizeof(record_buffer))))
                {
                    uint8_t                       *fqdn = record_buffer;
                    struct type_class_ttl_rdlen_s *tctr = (struct type_class_ttl_rdlen_s *)&fqdn[dnsname_len(fqdn)];

                    if((tctr->rtype == TYPE_RRSIG) && dnsname_equals(type_fqdn, fqdn))
                    {
                        // append the record data to the array

                        uint16_t rdata_size = ntohs(tctr->rdlen);

                        uint8_t *rdata = (uint8_t *)tctr;
                        rdata += 10;

                        if((GET_U16_AT(rdata[0]) == ctype) && (rdata_size > RRSIG_RDATA_HEADER_LEN)) // if type covered is the one we are processing ...
                        {
#if DEBUG
                            rdata_desc_t rdatadesc = {TYPE_RRSIG, rdata_size, rdata};
                            log_debug6("with %{dnsname} %{typerdatadesc}", fqdn, &rdatadesc);
#endif
                            dns_message_verify_rrsig_detail_t rrsig_header;

                            memcpy(&rrsig_header, rdata, RRSIG_RDATA_HEADER_LEN);
                            rrsig_header.result = 0;
                            rrsig_header.section = section;
                            rrsig_header.signer_name = &rdata[RRSIG_RDATA_HEADER_LEN];
                            rrsig_header.fqdn = fqdn;

                            result.data.detail = &rrsig_header;
                            result.result_type = MESSAGE_VERIFY_RRSIG_RESULT_TYPE_VERIFY;

                            uint32_t inception = ntohl(rrsig_header.inception);
                            uint32_t expiration = ntohl(rrsig_header.expiration);

                            if((now >= inception) && (now <= expiration))
                            {
                                uint16_t  tag = ntohs(rrsig_header.tag);

                                dnskey_t *key = dnskey_keyring_acquire(keyring, rrsig_header.algorithm, tag, rrsig_header.signer_name);

                                if(key != NULL)
                                {
                                    type_info.verifiable_count++;

                                    bytes_verifier_t verifier;
                                    key->vtbl->verifier_init(key, &verifier);

                                    return_code = message_verify_rrsig_compute_digest(&verifier, fqdn, ctype, tctr->rclass, rdata, rdata_size, &rrset);
                                    if(ISOK(return_code))
                                    {
                                        uint32_t rrsig_signer_name_len = dnsname_len(rrsig_header.signer_name);
                                        uint32_t rrsig_header_len = RRSIG_RDATA_HEADER_LEN + rrsig_signer_name_len;

                                        uint8_t *signature = &rdata[rrsig_header_len];
                                        uint32_t signature_len = rdata_size - rrsig_header_len;

                                        if(verifier.vtbl->verify(&verifier, signature, signature_len))
                                        {
                                            // verified signature with origin/algorithm/tag

                                            type_info.verified_count++;
                                            rrsig_header.result |= MESSAGE_VERIFY_RRSIG_VERIFIED;
                                        }
                                        else
                                        {
                                            // corrupted/wrong signature with origin/algorithm/tag

                                            total_wrong_signatures++;

                                            type_info.wrong_count++;
                                            rrsig_header.result |= MESSAGE_VERIFY_RRSIG_WRONG;
                                        }
                                    }
                                    else
                                    {
                                        type_info.wrong_count++;
                                    }

                                    verifier.vtbl->finalise(&verifier);

                                    dnskey_release(key);
                                }
                                else
                                {
                                    type_info.unverifiable_count++;

                                    rrsig_header.result |= MESSAGE_VERIFY_RRSIG_NOKEY;
                                }
                            }
                            else
                            {
                                // wrong time frame

                                type_info.wrong_count++;

                                rrsig_header.result |= MESSAGE_VERIFY_RRSIG_TIMEFRAME;
                            }

                            if(feedback(mesg, keyring, &result, args) != MESSAGE_VERIFY_RRSIG_FEEDBACK_CONTINUE)
                            {
                                break;
                            }
                        }
                    }
                }
            } // for each signature covering the type

            // break goes here

            pr.packet_offset = saved_offset;

            ptr_vector_callback_and_clear(&rrset, message_verify_rrsig_free_rrset);
            ptr_vector_finalise(&rrset);

        } // for all types/fqdn

        // summary of the results for the type

        result.data.summary = &type_info;
        result.result_type = MESSAGE_VERIFY_RRSIG_RESULT_TYPE_SUMMARY;

        if((feedback_result = feedback(mesg, keyring, &result, args)) != MESSAGE_VERIFY_RRSIG_FEEDBACK_CONTINUE)
        {
            // ends the section loop
            // section = 4;
            // breaks the current loop

            message_verify_rrsig_clear(&section_type_fqdn);

            break;
        }

        // clear the types of the section

        message_verify_rrsig_clear(&section_type_fqdn);

    } // for all sections

    // done

    if((total_wrong_signatures == 0) && (feedback_result != MESSAGE_VERIFY_RRSIG_FEEDBACK_ERROR))
    {
        return SUCCESS;
    }
    else
    {
        return RRSIG_VERIFICATION_FAILED;
    }
}
