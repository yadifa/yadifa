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

#include "keyroll.h"
#include <dnscore/timems.h>
#include <dnscore/thread_pool.h>
#include <dnscore/dnskey-signature.h>
#include <dnscore/packet_reader.h>
#include <dnscore/dnskey-keyring.h>
#include <dnscore/packet_writer.h>
#include <dnscore/parsing.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/base64.h>
#include <dnscore/parser.h>
#include <dnscore/zone_reader_text.h>
#include <dnscore/logger.h>
#include <dnsdb/dnssec-keystore.h>
#include <dnscore/server-setup.h>

#include "dnssec-policy.h"
#include "buildinfo.h"

#define TTL 86400
#define RRSIG_ANTEDATING 86400  // sign from the day before
#define DNSKEY_DEACTIVATION_MARGIN 86400

#define UPDATE_SUBCOMMAND_ADD    0
#define UPDATE_SUBCOMMAND_DELETE 1

#define RECORD_SIZE_MAX (2 + 1 + 1 + 4 + 4 + 4 + 2 + 256 + 1024)

#define MODULE_MSG_HANDLE g_keyroll_logger

#define NEXT_SIGNATURE_EPOCH_MARGIN 57 // one minute should be enough, and adding a non-minute multiple makes is easier to notice

logger_handle *g_keyroll_logger = LOGGER_HANDLE_SINK;

static bool keyroll_dryrun_mode = FALSE;

u32 keyroll_deactivation_margin(u32 activate_epoch, u32 deactivate_epoch, u32 delete_epoch)
{
    u32 margin;
#if 1
    s64 total_activated_time = deactivate_epoch;
    total_activated_time -= activate_epoch;
    if(total_activated_time >= 0)
    {
        s64 total_lingering_time = delete_epoch;
        total_lingering_time -= deactivate_epoch;

        if(total_lingering_time < 0)
        {
            log_err("keyroll: inverted activated and deactivated epoch");

            margin = DNSKEY_DEACTIVATION_MARGIN;
        }
        else if(total_lingering_time / 2 > DNSKEY_DEACTIVATION_MARGIN)
        {
            margin = DNSKEY_DEACTIVATION_MARGIN;
        }
        else
        {
            margin = total_lingering_time / 2;
        }
    }
    else
    {
        log_err("keyroll: inverted activated and deactivated epoch");

        margin = DNSKEY_DEACTIVATION_MARGIN;
    }
#else
    margin = 57;
#endif

    u32 remainder = margin % 60;
    margin -= remainder;
    margin += 57;
    if(margin < 60)
    {
        margin += 60;
    }

    log_debug("keyroll_deactivation_margin: %u", DNSKEY_DEACTIVATION_MARGIN);

    return margin;
}

ya_result keyroll_step_delete(keyroll_step_t *step);

//static const char *token_delmiter = " \t\r\n";

static int keyroll_dns_resource_record_ptr_vector_qsort_callback(const void *a, const void *b)
{
    const dns_resource_record *ra = (const dns_resource_record*)a;
    const dns_resource_record *rb = (const dns_resource_record*)b;

    int ret = dns_resource_record_compare(ra, rb);

    return ret;
}

void
keyroll_errors_register()
{
    error_register(KEYROLL_ERROR_BASE, "KEYROLL_ERROR_BASE");
    error_register(KEYROLL_EXPECTED_IDENTICAL_RECORDS, "KEYROLL_EXPECTED_IDENTICAL_RECORDS");
    error_register(KEYROLL_EXPECTED_IDENTICAL_SIZE_RRSETS, "KEYROLL_EXPECTED_IDENTICAL_SIZE_RRSETS");
    error_register(KEYROLL_EXPECTED_DNSKEY_OR_RRSIG, "KEYROLL_EXPECTED_DNSKEY_OR_RRSIG");
    error_register(KEYROLL_UPDATE_SUBCOMMAND_ERROR, "KEYROLL_UPDATE_SUBCOMMAND_ERROR");
    error_register(KEYROLL_HOLE_IN_TIMELINE, "KEYROLL_HOLE_IN_TIMELINE");
    error_register(KEYROLL_MUST_REINITIALIZE, "KEYROLL_MUST_REINITIALIZE");
}

ya_result
keyroll_init(keyroll_t* keyroll, const u8 *domain, const char *plan_path, const char *keys_path, const host_address *server, bool generation_mode)
{
    ya_result ret = SUCCESS;
    memset(keyroll, 0, sizeof(keyroll_t));
    keyroll->ksk_parameters.algorithm = DNSKEY_ALGORITHM_RSASHA256_NSEC3;
    keyroll->ksk_parameters.size = /*4096*/2048;
    keyroll->ksk_parameters.activate_after = 86400;
    keyroll->ksk_parameters.deactivate_after = 86400 + 86400*366;
    keyroll->ksk_parameters.delete_after = 86400 + 86400*366 + 86400;
    keyroll->ksk_parameters.estimated_signing_time = 86400;
    keyroll->zsk_parameters.algorithm = DNSKEY_ALGORITHM_RSASHA256_NSEC3;
    keyroll->zsk_parameters.size = 2048;
    keyroll->zsk_parameters.activate_after = 86400;
    keyroll->zsk_parameters.deactivate_after = 86400 + 86400*31;
    keyroll->zsk_parameters.delete_after = 86400 + 86400*31 + 86400;
    keyroll->zsk_parameters.estimated_signing_time = 86400 * 7;

    keyroll->update_apply_verify_retries = 60;        // if an update wasn't applied successfully, retry CHECKING this amount of times
    keyroll->update_apply_verify_retries_delay = 1;  // time between the above retries
    keyroll->match_verify_retries = 60;        // if there is not match, retry checking this amount of times
    keyroll->match_verify_retries_delay = 1;  // time between the above retries

    keyroll->generation_mode = generation_mode;

    asformat(&keyroll->plan_path, "%s/%{dnsname}", plan_path, domain);

    if(generation_mode)
    {
        if(FAIL(ret = mkdir_ex(keyroll->plan_path, 0700, 0)))
        {
            log_err("keyroll: %{dnsname}: could not create directory: '%s'", domain, keyroll->plan_path);
            free(keyroll->plan_path);
            keyroll->plan_path = NULL;
            return ret;
        }

        asformat(&keyroll->private_keys_path, "%s/%{dnsname}" YKEYROLL_KSK_SUFFIX, plan_path, domain);

        if(FAIL(ret = mkdir_ex(keyroll->private_keys_path, 0700, 0)))
        {
            log_err("keyroll: %{dnsname}: could not create directory: '%s'", domain, keyroll->private_keys_path);
            free(keyroll->plan_path);
            keyroll->plan_path = NULL;
            free(keyroll->private_keys_path);
            keyroll->private_keys_path = NULL;
            return ret;
        }

        dnssec_keystore_add_domain(domain, keyroll->private_keys_path);
    }
    else
    {
        if(FAIL(ret = file_is_directory(keyroll->plan_path)))
        {
            log_err("keyroll: %{dnsname}: could not find directory: '%s'", domain, keyroll->plan_path);
        }
    }

    keyroll->keys_path = strdup(keys_path);
    keyroll->domain = dnsname_zdup(domain);
    keyroll->domain = dnsname_zdup(domain);
    keyroll->server = host_address_copy(server);
    keyroll->keyring = dnskey_keyring_new();

    return ret;
}

static void
keyroll_finalize_steps_delete_callback(u64_node *node)
{
    keyroll_step_t *step = (keyroll_step_t*)node->value;
    keyroll_step_delete(step);
}

void
keyroll_finalize(keyroll_t *keyroll)
{
    if(keyroll != NULL)
    {
        free(keyroll->private_keys_path);
        keyroll->private_keys_path = NULL;
        free(keyroll->plan_path);
        keyroll->plan_path = NULL;
        free(keyroll->keys_path);
        keyroll->keys_path = NULL;

        if(keyroll->domain != NULL)
        {
            dnsname_zfree(keyroll->domain);
            keyroll->domain = NULL;
        }

        if(keyroll->server != NULL)
        {
            host_address_delete(keyroll->server);
            keyroll->server = NULL;
        }

        if(keyroll->keyring != NULL)
        {
            dnskey_keyring_free(keyroll->keyring);
            keyroll->keyring = NULL;
        }

        u64_set_callback_and_destroy(&keyroll->steps, keyroll_finalize_steps_delete_callback);

        memset(keyroll, 0, sizeof(keyroll_t));
    }
}

ya_result
keyroll_fetch_public_keys_from_server(keyroll_t* keyroll)
{
    ya_result ret;

    const u8 *domain = keyroll->domain;
    const host_address *server = keyroll->server;

/*
    memset(keyroll, 0, sizeof(keyroll_t));

    asformat(&keyroll->plan_path, "%s/%{dnsname}", plan_path, domain);
    if(FAIL(ret = mkdir_ex(keyroll->plan_path, 0700, 0)))
    {
        free(keyroll->plan_path);
        return ret;
    }

    keyroll->keys_path = strdup(keys_path);
    keyroll->private_keys_path = strdup(private_keys_path);

    dnssec_keystore_add_domain(domain, private_keys_path);
*/
    message_data *mesg = message_new_instance();
    dnskey_keyring *keyring = keyroll->keyring;

    //u8 fqdn[MAX_DOMAIN_LENGTH];
    //message_set_edns0(mesg, TRUE);

    message_make_query(mesg, rand(), domain, TYPE_DNSKEY, CLASS_IN);

    if(ISOK(ret = message_query(mesg, server)))
    {
        // extract DNSKEY (and maybe their RRSIG)
        struct packet_unpack_reader_data pr;
        packet_reader_init_from_message(&pr, mesg);

        // ensure there is exactly one answer
        // skip the matching query content, or fail

        if(ISOK(ret = (message_get_query_count(mesg) == 1)?SUCCESS:ERROR) &&
           ISOK(ret = packet_reader_skip_query(&pr, domain, TYPE_DNSKEY, CLASS_IN)))
        {
            u16 answer_count = message_get_answer_count(mesg);

            if(answer_count > 0)
            {
                size_t buffer_size = 0x20000;
                u8 *buffer;
                MALLOC_OBJECT_ARRAY_OR_DIE(buffer, u8, buffer_size, GENERIC_TAG);

                dns_resource_record rr;
                dns_resource_record_init(&rr);

                for(u16 i = 0; i < answer_count; ++i)
                {
                    if(FAIL(ret = packet_reader_read_dns_resource_record(&pr, &rr)))
                    {
                        break;
                    }

                    if(rr.tctr.qtype == TYPE_DNSKEY)
                    {
                        dnssec_key *key;
                        if(FAIL(ret = dnskey_new_from_rdata(rr.rdata, rr.rdata_size, domain, &key)))
                        {
                            break;
                        }

                        // got one key

                        if(FAIL(ret = dnskey_keyring_add(keyring, key)))
                        {
                            // e.g.: collision
                            dnskey_release(key);
                        }
                    }

                    dns_resource_record_clear(&rr);
                }

                dns_resource_record_finalize(&rr);

                free(buffer);
            }
        }
    }

    message_free(mesg);

    return ret;
}

ya_result
keyroll_init_from_server(keyroll_t* keyroll, const u8 *domain, const char *plan_path, const char *keys_path, const host_address *server)
{
    ya_result ret;

    if(FAIL(ret = keyroll_init(keyroll, domain, plan_path, keys_path, server, TRUE)))
    {
        return ret;
    }

    ret = keyroll_fetch_public_keys_from_server(keyroll);

    if(FAIL(ret))
    {
        keyroll_finalize(keyroll);
    }

    return ret;
}

ya_result
keyroll_update_apply_verify_retries_set(keyroll_t* keyroll, u32 retries, u32 delay)
{
    if(retries * delay < 3600)
    {
        keyroll->update_apply_verify_retries = retries;
        keyroll->update_apply_verify_retries_delay = delay;
        return SUCCESS;
    }
    else
    {
        return CONFIG_VALUE_OUT_OF_RANGE;
    }
}

ya_result
keyroll_match_verify_retries_set(keyroll_t* keyroll, u32 retries, u32 delay)
{
    if(retries * delay < 3600)
    {
        keyroll->match_verify_retries = retries;
        keyroll->match_verify_retries_delay = delay;
        return SUCCESS;
    }
    else
    {
        return CONFIG_VALUE_OUT_OF_RANGE;
    }
}

typedef struct keyroll_file_item_s
{
    char *name;
    u8 *data;
    size_t size;
    bool name_allocated;
    bool data_allocated;
} keyroll_file_item_t;

typedef struct keyroll_file_s
{
    u8 *data;
    size_t data_size;
    output_stream baos;
    input_stream bais;
} keyroll_file_t;

void keyroll_file_init(keyroll_file_t *kf)
{
    kf->data = NULL;
    kf->data_size = 0;
    output_stream_set_void(&kf->baos);
    input_stream_set_void(&kf->bais);
}

void keyroll_file_write_start(keyroll_file_t *kf)
{
    bytearray_output_stream_init_ex(&kf->baos, kf->data, kf->data_size, BYTEARRAY_DYNAMIC);
}

void keyroll_file_write(keyroll_file_t *kf, const char* filename, const void *data, size_t data_size)
{
    size_t filename_len = strlen(filename) + 1; // +1 for the terminator
    output_stream_write_u8(&kf->baos, filename_len);
    output_stream_write(&kf->baos, filename, filename_len);

    output_stream_write_u16(&kf->baos, data_size);
    output_stream_write(&kf->baos, data, data_size);
}

void keyroll_file_write_stop(keyroll_file_t *kf)
{
    kf->data_size = bytearray_output_stream_size(&kf->baos);
    kf->data = bytearray_output_stream_detach(&kf->baos);
    output_stream_close(&kf->baos);
}

static ya_result
input_stream_create_from_base64_text(input_stream* is, const char *text, const char* text_limit)
{
    ya_result ret;
    output_stream baos;
    char tmp[128];
    u8 decoded[128];

    bytearray_output_stream_init(&baos, NULL, 0);

    for(;;)
    {
        int i;
        for(i = 0; (i < (int)sizeof(tmp)) && (text < text_limit); ++text)
        {
            char c = *text;

            if(base64_character_set_contains(c))
            {
                tmp[i++] = c;
            }
        }

        if(i == 0)
        {
            break;
        }

        ya_result n = base64_decode(tmp, i, decoded);

        if(FAIL(n))
        {
            ret = n;
            output_stream_close(&baos);
            return ret;
        }

        output_stream_write(&baos, decoded, n);
    }

    bytearray_input_stream_init(is, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos), TRUE);
    bytearray_output_stream_detach(&baos);
    ret = bytearray_input_stream_size(is);

    return ret;
}

static ya_result
keyroll_parse_record(parser_s *parser, dns_resource_record **rrp)
{
    ya_result ret;

    s32 rttl;
    s32 rdata_size =  RECORD_SIZE_MAX;
    u16 rtype;
    u8 fqdn[MAX_DOMAIN_LENGTH];
    u8 rdata[RECORD_SIZE_MAX];   // enough for a 8192 bits key

    // parse the domain (must match)

    if(FAIL(ret = parser_copy_next_fqdn(parser, fqdn)))
    {
        return ret;
    }

    // parse the TTL

    if(FAIL(ret = parser_copy_next_ttl(parser, &rttl)))
    {
        return ret;
    }

    // parse the type (should be DNSKEY or RRSIG)

    if(FAIL(ret = parser_copy_next_type(parser, &rtype)))
    {
        return ret;
    }

    if((rtype == TYPE_DNSKEY) || (rtype == TYPE_RRSIG))
    {
        // parse the rdata using zone_reader_text_copy_rdata

        if(FAIL(ret = parser_concat_next_tokens(parser)))
        {
            return ret;
        }

        char *rdata_text = (char*)parser_text(parser);
        int rdata_text_size = parser_text_length(parser);

        ret = zone_reader_text_len_copy_rdata(rdata_text, rdata_text_size, rtype, rdata, rdata_size, fqdn);

        if(ISOK(ret))
        {
            rdata_size = ret;
            if(rtype == TYPE_RRSIG)
            {
                if(rrsig_get_type_covered_from_rdata(rdata, rdata_size) != TYPE_DNSKEY)
                {
                    return INVALID_STATE_ERROR;
                }
            }

            *rrp = dns_resource_record_new_instance();
            dns_resource_record_init_record(*rrp, fqdn, rtype, CLASS_IN, rttl, rdata_size, rdata);
        }
    }
    else
    {
        // error
        ret = KEYROLL_EXPECTED_DNSKEY_OR_RRSIG;
    }

    return ret;
}

static ya_result
keyroll_plan_step_load(keyroll_t *keyroll, const char *file)
{
    keyroll_step_t *step = NULL;
    input_stream fis;
    s64 epochus;
    ya_result ret;

    // keyroll file

    // load file

    // read the whole file in memory
    // read it line by line

    struct parser_s parser;

    char full_path[PATH_MAX];

    if(FAIL(ret = parser_init(&parser,
                              "",                            // by 2
                              "",                            // by 2
                              "",                            // by 1
                              " \r\t",                       // by 1
                              "\\")))                        // by 1
    {
        return ret;
    }

    log_debug("parsing '%s'", file);

    snformat(full_path, sizeof(full_path), "%s/%s", keyroll->plan_path, file);

    ret = file_input_stream_open(&fis, full_path);

    if(ISOK(ret))
    {
        if(ISOK(ret = parser_push_stream(&parser, &fis)))
        {
            // start to parse
            // it's always:
            // command words
            // parameters

            dnskey_keyring *kr = dnskey_keyring_new();

            char command[32];

            for(;;)
            {
                if(FAIL(ret = parser_copy_next_word(&parser, command, sizeof(command))))
                {
                    if(step != NULL)
                    {
                        if(ret == PARSER_REACHED_END_OF_LINE)
                        {
                            continue;
                        }

                        if(ret == PARSER_REACHED_END_OF_FILE)
                        {
                            ret = SUCCESS;
                        }
                    }

                    break;
                }

                int n = ret;

                if(step == NULL)
                {
                    if((n == 7) && (memcmp(command, "epochus", 7) == 0))
                    {
                        char epochus_buffer[24];

                        if(FAIL(ret = parser_copy_next_word(&parser, epochus_buffer, sizeof(epochus_buffer))))
                        {
                            break;
                        }

                        n = ret;

                        if(FAIL(ret = parse_u64_check_range_len_base10(epochus_buffer, n, (u64*)&epochus, 0, MAX_S64)))
                        {
                            break;
                        }

                        step = keyroll_get_step(keyroll, epochus);
                    }
                    else
                    {
                        log_err("parsing '%s': the first keyword of a step should be 'epochus', not '%s'", file, command);
                        ret = PARSESTRING_ERROR;

                        break;
                    }
                }
                else // step != NULL
                {
                    if((n == 6) && (memcmp(command, "dateus", 6) == 0))
                    {
                        // human readable, epochus check

                        char date_buffer[16];
                        char time_buffer[20];

                        if(FAIL(ret = parser_copy_next_word(&parser, date_buffer, sizeof(date_buffer))))
                        {
                            break;
                        }

                        if(FAIL(ret = parser_copy_next_word(&parser, time_buffer, sizeof(time_buffer))))
                        {
                            break;
                        }

                        char datetime_check[64];
                        char datetime_check2[64];
                        snformat(datetime_check, sizeof(datetime_check), "%llU", step->epochus);
                        strcpy(datetime_check2, date_buffer);
                        strcat(datetime_check2, " ");
                        strcat(datetime_check2, time_buffer);

                        if(strcmp(datetime_check, datetime_check2) != 0)
                        {
                            flushout();
                            osformatln(termerr, "'%s' does not match '%s' (%lli)", datetime_check, datetime_check2, step->epochus);
                            flusherr();
                            log_err("'%s' does not match '%s' (%lli)", datetime_check, datetime_check2, step->epochus);
                            ret = INVALID_STATE_ERROR;
                            break;
                        }
                    }
                    else if((n == 7) && (memcmp(command, "actions", 7) == 0))
                    {
                        // human readable, implies some of the commands that will follow

                        for(;;)
                        {
                            ret = parser_next_word(&parser);

                            if(FAIL(ret))
                            {
                                break;
                            }
                        }

                        if(ret == PARSER_REACHED_END_OF_LINE)
                        {
                            continue;
                        }
                        else
                        {
                            break;
                        }
                    }
                    else if((n == 5) && (memcmp(command, "debug", 5) == 0))
                    {
                        // human readable, implies some of the commands that will follow

                        for(;;)
                        {
                            ret = parser_next_word(&parser);

                            if(FAIL(ret))
                            {
                                break;
                            }
                        }

                        if(ret == PARSER_REACHED_END_OF_LINE)
                        {
                            continue;
                        }
                        else
                        {
                            break;
                        }
                    }
                    else if((n == 7) && (memcmp(command, "version", 7) == 0))
                    {
                        // version, ignored

                        for(;;)
                        {
                            ret = parser_next_word(&parser);

                            if(FAIL(ret))
                            {
                                break;
                            }
                        }

                        if(ret == PARSER_REACHED_END_OF_LINE)
                        {
                            continue;
                        }
                        else
                        {
                            break;
                        }
                    }
                    else if( ((n == 3) && (memcmp(command, "add", 3) == 0)) || ((n == 3) && (memcmp(command, "del", 3) == 0)) )
                    {
                        // filename base64 of a file
                        char file_name[MAX_DOMAIN_TEXT_LENGTH + 2];
                        char domain_name[MAX_DOMAIN_TEXT_LENGTH + 2];

                        if(FAIL(ret = parser_copy_next_word(&parser, file_name, sizeof(file_name))))
                        {
                            break;
                        }

                        if(ret < 16) // name has to be a bare minimal size 1 + 1 + 4 + 6 + (4,8) = (15,19)
                        {
                            ret = PARSESTRING_ERROR;
                            break;
                        }

                        if(step == NULL)
                        {
                            return INVALID_STATE_ERROR;
                        }

                        n = ret;

    //                  line += n;

                        // everything else is the base64 encoding of a file

                        u32 algorithm;
                        u32 tag;

                        if(sscanf(file_name, "K%255[^+]+%03u+%05u.", domain_name, &algorithm, &tag) != 3)
                        {
                            ret = PARSESTRING_ERROR;
                            break;
                        }

                        bool is_public = (memcmp(&file_name[n - 4], ".key", 4) == 0);
                        bool is_private = !is_public && (memcmp(&file_name[n - 8], ".private", 8) == 0);

                        if(command[0] == 'd')
                        {
                            // delete

                            ptr_vector_append(&step->file_del, strdup(file_name));

                            if(FAIL(ret = parser_concat_next_tokens_nospace(&parser)))
                            {
                                break;
                            }
                        }
                        else
                        {
                            // add
                            if(FAIL(ret = parser_concat_next_tokens_nospace(&parser)))
                            {
                                break;
                            }

                            input_stream bais;

                            if(FAIL(ret = input_stream_create_from_base64_text(&bais, parser_text(&parser), &parser_text(&parser)[parser_text_length(&parser)])))
                            {
                                break;
                            }

                            if(is_public)
                            {
                                dnssec_key *key;
                                if(ISOK(ret = dnskey_new_public_key_from_stream(&bais, &key)))
                                {
                                    dnskey_keyring_add(kr, key);
                                    dnskey_release(key);
                                }
                                else
                                {
                                    log_err("failed to get new public key from stream: %r", ret);
                                }

                                // keep a copy of the added file

                                ptr_node *node = ptr_set_insert(&step->file_add, file_name);
                                if(node->value == NULL)
                                {
                                    node->key = strdup(file_name);
                                    input_stream *is;
                                    ZALLOC_OBJECT_OR_DIE(is, input_stream, GENERIC_TAG);
                                    input_stream_create_from_base64_text(is, parser_text(&parser), &parser_text(&parser)[parser_text_length(&parser)]);
                                    node->value = is;
                                }
                                else
                                {
                                    // already exists
                                    ret = INVALID_STATE_ERROR;
                                    break;
                                }

                                //
                            }
                            else if(is_private)
                            {
                                dnssec_key *key = dnskey_keyring_acquire(kr, algorithm, tag, keyroll->domain);

                                ret = dnskey_add_private_key_from_stream(&bais, key, NULL, dnskey_get_algorithm(key));

                                log_debug("adding key to keystore: %i, %i, create=%llU publish=%llU activate=%llU deactivate=%llU unpublish=%llU",
                                         dnskey_get_algorithm(key),
                                         ntohs(dnskey_get_flags(key)),
                                         ONE_SECOND_US * dnskey_get_created_epoch(key),
                                         ONE_SECOND_US * dnskey_get_publish_epoch(key),
                                         ONE_SECOND_US * dnskey_get_activate_epoch(key),
                                         ONE_SECOND_US * dnskey_get_inactive_epoch(key),
                                         ONE_SECOND_US * dnskey_get_delete_epoch(key));
#if 0
                                if(dnskey_get_publish_epoch(key) == 0)
                                {
                                    keyroll_set_timing_steps(keyroll, key, FALSE);

                                    log_debug("------ key to keystore: %i, %i, create=%llU publish=%llU activate=%llU deactivate=%llU unpublish=%llU",
                                              dnskey_get_algorithm(key),
                                              ntohs(dnskey_get_flags(key)),
                                              ONE_SECOND_US * dnskey_get_created_epoch(key),
                                              ONE_SECOND_US * dnskey_get_publish_epoch(key),
                                              ONE_SECOND_US * dnskey_get_activate_epoch(key),
                                              ONE_SECOND_US * dnskey_get_inactive_epoch(key),
                                              ONE_SECOND_US * dnskey_get_delete_epoch(key));
                                }
#endif
                                dnssec_keystore_add_key(key);
        /*
                                if(command[0] == 'd')
                                {
                                    ptr_vector_append(&step->dnskey_del, key);
                                    dnskey_acquire(key);
                                }
                                else
                                {
                                    ptr_vector_append(&step->dnskey_add, key);
                                    dnskey_acquire(key);
                                }
        */
                                step->dirty = FALSE;

                                if(is_public || (is_private && (dnskey_get_flags(key) != DNSKEY_FLAGS_KSK)))
                                {
                                    // keep a copy of the added file

                                    ptr_node *node = ptr_set_insert(&step->file_add, file_name);
                                    if(node->value == NULL)
                                    {
                                        char *name = strdup(file_name);
                                        node->key = name;

                                        input_stream *is;
                                        ZALLOC_OBJECT_OR_DIE(is, input_stream, GENERIC_TAG);
                                        input_stream_create_from_base64_text(is, parser_text(&parser), &parser_text(&parser)[parser_text_length(&parser)]);

                                        node->value = is;
                                    }
                                    else
                                    {
                                        ret = INVALID_STATE_ERROR;
                                        break;
                                    }

                                    //
                                }

                                dnskey_release(key);
                            }
                            else
                            {
                                ret = PARSESTRING_ERROR;
                            }
                        }

                        if(FAIL(ret))
                        {
                            break;
                        }
                    }
                    else if((n == 6) && (memcmp(command, "update", 6) == 0))
                    {
                        // the list of nsupdate commands (add and delete)

                        char subcommand[16];

                        if(FAIL(ret = parser_copy_next_word(&parser, subcommand, sizeof(subcommand))))
                        {
                            break;
                        }

                        n = ret;

                        int subcommand_type;

                        if((n == 3) && (memcmp(subcommand, "add", 3) == 0))
                        {
                            subcommand_type = UPDATE_SUBCOMMAND_ADD;
                        }
                        else if((n == 6) && (memcmp(subcommand, "delete", 6) == 0))
                        {
                            subcommand_type = UPDATE_SUBCOMMAND_DELETE;
                        }
                        else
                        {
                            ret = KEYROLL_UPDATE_SUBCOMMAND_ERROR;
                            break;
                        }

                        // parse the record

                        dns_resource_record *rr = NULL;

                        if(ISOK(ret = keyroll_parse_record(&parser, &rr)))
                        {
                            log_debug("update add %{dnszrr}", rr);

                            if(subcommand_type == UPDATE_SUBCOMMAND_ADD)
                            {
                                switch(rr->tctr.qtype) // scan-build false positive (ISOK => rr not NULL)
                                {
                                    case TYPE_RRSIG:
                                    {
                                        u16 tag = rrsig_get_key_tag_from_rdata(rr->rdata, rr->rdata_size);
                                        //u8 algorithm = rrsig_get_algorithm_from_rdata(rr->rdata, rr->rdata_size);
                                        dnssec_key *key = dnssec_keystore_acquire_key_from_fqdn_with_tag(keyroll->domain, tag);
                                        if(key != NULL)
                                        {
                                            if(dnskey_get_flags(key) == DNSKEY_FLAGS_KSK)
                                            {
                                                u32 valid_from = rrsig_get_valid_from_from_rdata(rr->rdata, rr->rdata_size);
                                                u32 valid_until = rrsig_get_valid_until_from_rdata(rr->rdata, rr->rdata_size);
                                                if(!dnskey_has_explicit_activate(key))
                                                {
                                                    dnskey_set_activate_epoch(key, valid_from + RRSIG_ANTEDATING * 2);
                                                }
                                                if(!dnskey_has_explicit_deactivate(key))
                                                {
                                                    dnskey_set_inactive_epoch(key, valid_until);
                                                }
                                            }
                                            ptr_vector_append(&step->rrsig_add, rr);
                                            dnskey_release(key);
                                        }
                                        else
                                        {
                                            ptr_vector_append(&step->rrsig_add, rr);
                                        }
                                        break;
                                    }
                                    case TYPE_DNSKEY:
                                    {
                                        // if the key is a KZK, load its private key if it's available

                                        dnssec_key *key = NULL;

                                        if(keyroll->generation_mode && (DNSKEY_FLAGS_FROM_RDATA(rr->rdata) == DNSKEY_FLAGS_KSK))
                                        {
                                            ret = dnssec_keystore_load_private_key_from_rdata(rr->rdata, rr->rdata_size, rr->name, &key);
                                            if(ISOK(ret))
                                            {
                                                if(!dnskey_is_private(key))
                                                {
                                                    log_err("parsing '%s': private file for key signing key K%{dnsname}+%03i+%05i is missing", file,
                                                            dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key));
                                                    ret = ERROR;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            ret = dnssec_keystore_load_public_key_from_rdata(rr->rdata, rr->rdata_size, rr->name, &key);
                                        }

                                        if(FAIL(ret))
                                        {
                                            if(key != NULL)
                                            {
                                                dnskey_release(key);
                                            }

                                            rdata_desc rdatadesc = {TYPE_DNSKEY, rr->rdata_size, rr->rdata};
                                            flushout();
                                            osformatln(termerr, "parsing '%s': unable to load key: %{dnsname} IN %{typerdatadesc}: %r", file, rr->name, &rdatadesc, ret);
                                            flusherr();
                                            log_err("parsing '%s': unable to load key: %{dnsname} IN %{typerdatadesc}: %r", file, rr->name, &rdatadesc, ret);
                                            return ret;
                                        }

                                        // ignore duplicates

                                        for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_add); ++i)
                                        {
                                            dnssec_key *keyi = (dnssec_key*)ptr_vector_get(&step->dnskey_add, i);
                                            if(dnskey_equals(keyi, key))
                                            {
                                                dnskey_release(key);
                                                key = NULL;
                                                break;
                                            }
                                        }

                                        if(key != NULL)
                                        {
                                            if(dnskey_get_publish_epoch(key) == 0)
                                            {
                                                dnskey_set_publish_epoch(key, step->epochus / ONE_SECOND_US);
                                            }

                                            ptr_vector_append(&step->dnskey_add, key);
                                        }

                                        dns_resource_record_free(rr);
                                        break;
                                    }
                                    default:
                                    {
                                        log_warn("parsing '%s': unexpected add record type: %{dnszrr}", file, rr);

                                        dns_resource_record_free(rr);
                                        break;
                                    }
                                }
                            }
                            else // UPDATE_SUBCOMMAND_DELETE
                            {
                                switch(rr->tctr.qtype) // scan-build false positive (ISOK => rr not NULL)
                                {
                                    case TYPE_DNSKEY:
                                    {
                                        // if the key is a KZK, load its private key if it's available


                                        dnssec_key *key = NULL;

                                        if(keyroll->generation_mode && (DNSKEY_FLAGS_FROM_RDATA(rr->rdata) == DNSKEY_FLAGS_KSK))
                                        {
                                            ret = dnssec_keystore_load_private_key_from_rdata(rr->rdata, rr->rdata_size, rr->name, &key);

                                            if(ISOK(ret))
                                            {
                                                if(!dnskey_is_private(key))
                                                {
                                                    log_err("parsing '%s': private file for key signing key K%{dnsname}+%03i+%05i is missing", file,
                                                            dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key));
                                                    ret = ERROR;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            ret = dnssec_keystore_load_public_key_from_rdata(rr->rdata, rr->rdata_size, rr->name, &key);
                                        }

                                        if(FAIL(ret))
                                        {
                                            rdata_desc rdatadesc = {TYPE_DNSKEY, rr->rdata_size, rr->rdata};
                                            flushout();
                                            osformatln(termerr, "parsing '%s': unable to load key: %{dnsname} IN %{typerdatadesc}: %r", file, rr->name, &rdatadesc, ret);
                                            flusherr();
                                            log_err("parsing '%s': unable to load key: %{dnsname} IN %{typerdatadesc}: %r", file, rr->name, &rdatadesc, ret);
                                            return ret;
                                        }

                                        // ignore duplicates

                                        for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_del); ++i)
                                        {
                                            dnssec_key *keyi = (dnssec_key*)ptr_vector_get(&step->dnskey_del, i);
                                            if(dnskey_equals(keyi, key))
                                            {
                                                dnskey_release(key);
                                                key = NULL;
                                                break;
                                            }
                                        }

                                        if(key != NULL)
                                        {
                                            if(!dnskey_has_explicit_delete(key))
                                            {
                                                dnskey_set_delete_epoch(key, step->epochus / ONE_SECOND_US);
                                            }

                                            ptr_vector_append(&step->dnskey_del, key);
                                        }

                                        dns_resource_record_free(rr);
                                        break;
                                    }
                                    default:
                                    {
                                        log_warn("parsing '%s': unexpected del record type: %{dnszrr}", file, rr);

                                        dns_resource_record_free(rr);
                                        break;
                                    }
                                }
                            }
                        }
                        else
                        {
                            // error
                            ret = ERROR;
                            break;
                        }
                    }
                    else if((n == 6) && (memcmp(command, "expect", 6) == 0))
                    {
                        // if the master is queried after this step,
                        // these are the records that should be returned in the answer

                        // parse record

                        dns_resource_record *rr = NULL;

                        if(ISOK(ret = keyroll_parse_record(&parser, &rr)))
                        {
                            ptr_vector_append(&step->expect, rr);
                            log_debug("expect %{dnszrr}", rr);
                        }
                        else
                        {
                            // error
                            ret = ERROR;
                            break;
                        }
                    }
                    else if((n == 9) && (memcmp(command, "endresult", 9) == 0))
                    {
                        // if the master is queried after this step,
                        // these are the records that should be returned in the answer

                        // parse record

                        dns_resource_record *rr = NULL;

                        if(ISOK(ret = keyroll_parse_record(&parser, &rr)))
                        {
                            ptr_vector_append(&step->endresult, rr);
                            log_debug("expect %{dnszrr}", rr);
                        }
                        else
                        {
                            // error
                            ret = ERROR;
                            break;
                        }
                    }
                    else
                    {
                        log_err("parsing '%s': unexpected keyword '%s'", file, command);
                        ret = PARSESTRING_ERROR;
                        break;
                    }
                } // endif step != NULL

                ret = parser_expect_eol(&parser);

                if(FAIL(ret))
                {
                    break;
                }
            }

            parser_pop_stream(&parser);
        }
        else
        {
            log_err("parsing '%s': could not push stream of file '%s'", file, full_path);
        }

        input_stream_close(&fis);

        if(ISOK(ret))
        {
            if(step != NULL)
            {
                ptr_vector_qsort(&step->expect, keyroll_dns_resource_record_ptr_vector_qsort_callback);
                ptr_vector_qsort(&step->endresult, keyroll_dns_resource_record_ptr_vector_qsort_callback);
            }
            else
            {
                ret = INVALID_STATE_ERROR;
            }
        }
        else
        {
            log_err("parsing '%s': keyroll_plan_step_load: failure: %r", file, ret);
        }
    }
    else
    {
        log_err("parsing '%s': could not open stream for file '%s'", file, full_path);
    }

    parser_finalize(&parser);

    return ret;
}

static ya_result
keyroll_purge_step_readdir_forall_callback(const char *basedir, const char* file, u8 filetype, void *args)
{
    if(filetype == DT_REG)
    {
        const char *domain = (char*)args;
        size_t domain_len = strlen(domain);
        size_t name_len = strlen(file);
        if(name_len > domain_len)
        {
            if(memcmp(&file[name_len - domain_len], domain, domain_len) == 0)
            {
                if(unlink_ex(basedir, file) < 0)
                {
                    ya_result ret = ERRNO_ERROR;
                    flushout();
                    osformatln(termerr, "failed to delete '%s': %r", file, ret);
                    log_err("failed to delete '%s': %r", file, ret);
                    flusherr();
                    return ret;
                }
            }
        }
    }

    return READDIR_CALLBACK_CONTINUE;
}

static ya_result
keyroll_purge_key_readdir_forall_callback(const char *basedir, const char* file, u8 filetype, void *args)
{
    (void)args;
    if(filetype == DT_REG)
    {
        size_t name_len = strlen(file);
        if((name_len > 8) && (memcmp(&file[name_len - 8], ".private", 8) == 0))
        {
            if(unlink_ex(basedir, file) < 0)
            {
                ya_result ret = ERRNO_ERROR;
                flushout();
                osformatln(termerr, "failed to delete '%s': %r", file, ret);
                flusherr();
                log_err("failed to delete '%s': %r", file, ret);
                return ret;
            }
        }
        else if((name_len > 4) && (memcmp(&file[name_len - 4], ".key", 4) == 0))
        {
            if(unlink_ex(basedir, file) < 0)
            {
                ya_result ret = ERRNO_ERROR;
                flushout();
                osformatln(termerr, "failed to delete '%s': %r", file, ret);
                flusherr();
                log_err("failed to delete '%s': %r", file, ret);
                return ret;
            }
        }

    }

    return READDIR_CALLBACK_CONTINUE;
}

ya_result
keyroll_plan_purge(keyroll_t *keyroll)
{
    ya_result ret;

    char domain[MAX_DOMAIN_TEXT_LENGTH];

    dnsname_to_cstr(domain, keyroll->domain);

    if(ISOK(ret = readdir_forall(keyroll->plan_path, keyroll_purge_step_readdir_forall_callback, domain)))
    {
        ret = readdir_forall(keyroll->private_keys_path, keyroll_purge_key_readdir_forall_callback, NULL);
    }
    return ret;
}

static ya_result
keyroll_plan_load_readdir_forall_callback(const char *basedir, const char *file, u8 filetype, void *args)
{
    (void)basedir;
    (void)args;
    s64 epochus;

    u32 year, month, day;
    u32 hours, minutes, seconds;
    u32 microseconds;

    char fqdn[256];

#ifndef WIN32
    if(filetype == DT_CHR)
    {
        return READDIR_CALLBACK_CONTINUE;
    }
#endif

    if(sscanf(file, "%04u-%02u-%02u-%02u:%02u:%02u.%06uZ_%016lli_%255s.keyroll",
              &year, &month, &day,
              &hours, &minutes, &seconds,
              &microseconds,
              &epochus,
              fqdn) == 9)
    {
        char date_check[64];
        snformat(date_check, sizeof(date_check), "%llU", epochus);
        size_t date_check_len = strlen(date_check);
        date_check[10] = '-';
        if(memcmp(file, date_check, date_check_len) == 0)
        {
            ptr_vector *files = (ptr_vector*)args;
            ptr_vector_append(files, strdup(file));
        }
        else
        {
            formatln("ERROR: date for %lli should start '%s' but its '%s'", epochus, date_check, file);
            flushout();
            return INVALID_STATE_ERROR;
        }
    }

    return SUCCESS;
}

static int keyroll_plan_load_ptr_vector_qsort_callback(const void *a, const void *b)
{
    int ret = strcmp((char*)a, (char*)b);
    return ret;
}

/**
 * Loads a plan from disk. (all the steps)
 * Loads KSK private keys if they are available.
 */

ya_result
keyroll_plan_load(keyroll_t *keyroll)
{
    // reload all private keys (KSK in this case)

    dnssec_keystore_reload_domain(keyroll->domain);

    ptr_vector files;
    ptr_vector_init_ex(&files, 1024);
    ya_result ret = readdir_forall(keyroll->plan_path, keyroll_plan_load_readdir_forall_callback, &files);
    if(ISOK(ret))
    {
        ptr_vector_qsort(&files, keyroll_plan_load_ptr_vector_qsort_callback);

        for(int i = 0; i <= ptr_vector_last_index(&files); ++i)
        {
            char *file = (char*)ptr_vector_get(&files, i);

            if(FAIL(ret = keyroll_plan_step_load(keyroll, file)))
            {
                log_err("failed to load '%s' : %r", file, ret);
                break;
            }
        }
    }
    for(int i = 0; i <= ptr_vector_last_index(&files); ++i)
    {
        char *file = (char*)ptr_vector_get(&files, i);
        free(file);
    }
    ptr_vector_destroy(&files);
    return ret;
}

keyroll_step_t* keyroll_step_new_instance()
{
    keyroll_step_t *step;
    ZALLOC_OBJECT_OR_DIE(step, keyroll_step_t, GENERIC_TAG);
    memset(step, 0 ,sizeof(keyroll_step_t));
    step->keyroll = NULL;
    step->epochus = 0;
    ptr_vector_init_empty(&step->dnskey_del);
    ptr_vector_init_empty(&step->dnskey_add);
    ptr_vector_init_empty(&step->rrsig_add);
    ptr_vector_init_empty(&step->expect);
    ptr_vector_init_empty(&step->endresult);
    ptr_set_init(&step->file_add);
    step->file_add.compare = ptr_set_asciizp_node_compare;
    ptr_vector_init_empty(&step->file_del);
    //u32_set_init(&step->dnskey_set);
    step->fingerprint = 0;
    step->from_merge = FALSE;
    return step;
}

static void
keyroll_step_delete_dnskey_callback(void *key_)
{
    dnssec_key *key = (dnssec_key*)key_;
    dnskey_release(key);
}

static void
keyroll_step_delete_dns_resource_record_callback(void *rr_)
{
    dns_resource_record *rr = (dns_resource_record*)rr_;
    dns_resource_record_free(rr);
}

static void
keyroll_step_delete_file_add_callback(ptr_node *node)
{
    free(node->key);
    input_stream *is = (input_stream*)node->value;
    input_stream_close(is);
    ZFREE_OBJECT(is);
}

static void
keyroll_step_delete_file_del_callback(void *str_)
{
    free(str_);
}

ya_result
keyroll_step_delete(keyroll_step_t *step)
{
    if(step != NULL)
    {
        ptr_vector_callback_and_destroy(&step->dnskey_del, keyroll_step_delete_dnskey_callback);
        ptr_vector_callback_and_destroy(&step->dnskey_add, keyroll_step_delete_dnskey_callback);
        ptr_vector_callback_and_destroy(&step->rrsig_add, keyroll_step_delete_dns_resource_record_callback);
        ptr_vector_callback_and_destroy(&step->expect, keyroll_step_delete_dns_resource_record_callback);
        ptr_vector_callback_and_destroy(&step->endresult, keyroll_step_delete_dns_resource_record_callback);
        ptr_set_callback_and_destroy(&step->file_add, keyroll_step_delete_file_add_callback);
        ptr_vector_callback_and_destroy(&step->file_del, keyroll_step_delete_file_del_callback);

        step->keyroll = NULL;
        step->epochus = 0;

        ZFREE_OBJECT(step);
    }

    return SUCCESS;
}


/**
 * Returns the step at the given epoch, or create an empty one
 */

keyroll_step_t*
keyroll_get_step(keyroll_t *keyroll, s64 epochus)
{
    u64_node* node = u64_set_insert(&keyroll->steps, epochus);
    if(node->value != NULL)
    {
        return (keyroll_step_t*)node->value;
    }
    else
    {
        keyroll_step_t *step = keyroll_step_new_instance();

        step->keyroll = keyroll;
        step->epochus = epochus;
        node->value = step;

        return step;
    }
}

/**
 * Merges two consecutive steps.
 */

ya_result
keyroll_step_merge(keyroll_step_t *into, keyroll_step_t *step)
{
    if(into->keyroll == NULL)
    {
        into->keyroll = step->keyroll;
    }
    else if(into->keyroll != step->keyroll)
    {
        return INVALID_STATE_ERROR;
    }

    if(into->epochus < step->epochus)
    {
        into->epochus = step->epochus;
    }
    else
    {
        return INVALID_STATE_ERROR;
    }

    into->from_merge = TRUE;

    for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_del); ++i)
    {
        dnssec_key *keyi = (dnssec_key*)ptr_vector_get(&step->dnskey_del, i);
        bool not_added_anymore = FALSE;

        for(int j = 0; j <= ptr_vector_last_index(&into->dnskey_add); ++j)
        {
            dnssec_key *keyj = (dnssec_key*)ptr_vector_get(&into->dnskey_add, j);

            if(dnskey_equals(keyi, keyj))
            {
                log_info("DNSKEY K%{dnsname}+%03d+%05d not added anymore", dnskey_get_domain(keyj), dnskey_get_algorithm(keyj), dnskey_get_tag_const(keyj));
                ptr_vector_end_swap(&into->dnskey_add, j);
                ptr_vector_pop(&into->dnskey_add);
                dnskey_release(keyj);
                not_added_anymore = TRUE;
            }
        }

        if(!not_added_anymore)
        {
            dnskey_acquire(keyi);
            ptr_vector_append(&into->dnskey_del, keyi);
        }
    }

    for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_add); ++i)
    {
        dnssec_key *keyi = (dnssec_key*)ptr_vector_get(&step->dnskey_add, i);
        dnskey_acquire(keyi);
        ptr_vector_append(&into->dnskey_add, keyi);
        log_info("DNSKEY K%{dnsname}+%03d+%05d added", dnskey_get_domain(keyi), dnskey_get_algorithm(keyi), dnskey_get_tag_const(keyi));
    }

    if((ptr_vector_last_index(&step->dnskey_add) >= 0) || (ptr_vector_last_index(&step->dnskey_del) >= 0))
    {
        // if any DNSKEY is added/removed, then no current RRSIG is valid

        for(int i = 0; i <= ptr_vector_last_index(&into->rrsig_add); ++i)
        {
            dns_resource_record *rr = (dns_resource_record*)ptr_vector_get(&into->rrsig_add, i);
            dns_resource_record_free(rr);
        }

        ptr_vector_clear(&into->rrsig_add);
    }

    for(int i = 0; i <= ptr_vector_last_index(&step->rrsig_add); ++i)
    {
        dns_resource_record *rr = (dns_resource_record*)ptr_vector_get(&step->rrsig_add, i);
        dns_resource_record *rr_copy = dns_resource_record_new_instance();
        dns_resource_init_from_record(rr_copy, rr);
        ptr_vector_append(&into->rrsig_add, rr_copy);
    }

    for(int i = 0; i <= ptr_vector_last_index(&into->expect); ++i)
    {
        dns_resource_record *rr = (dns_resource_record*)ptr_vector_get(&into->expect, i);
        dns_resource_record_free(rr);
    }

    ptr_vector_clear(&into->expect);

    for(int i = 0; i <= ptr_vector_last_index(&step->expect); ++i)
    {
        dns_resource_record *rr = (dns_resource_record*)ptr_vector_get(&step->expect, i);
        dns_resource_record *rr_copy = dns_resource_record_new_instance();
        dns_resource_init_from_record(rr_copy, rr);
        ptr_vector_append(&into->expect, rr_copy);
    }

    ptr_vector_clear(&into->endresult);

    for(int i = 0; i <= ptr_vector_last_index(&step->endresult); ++i)
    {
        dns_resource_record *rr = (dns_resource_record*)ptr_vector_get(&step->endresult, i);
        dns_resource_record *rr_copy = dns_resource_record_new_instance();
        dns_resource_init_from_record(rr_copy, rr);
        ptr_vector_append(&into->endresult, rr_copy);
    }

    for(int i = 0; i <= ptr_vector_last_index(&step->file_del); ++i)
    {
        char *filename = (char*)ptr_vector_get(&step->file_del, i);
        //bool not_added_anymore = FALSE;

        ptr_node *node = ptr_set_find(&into->file_add, filename);
        if(node != NULL)
        {
            log_info("'%s' not added anymore", filename);

            char *key = (char*)node->key;
            input_stream *is = (input_stream*)node->value; // VS false positive: 'is' cannot be NULL or the node would not exist
            input_stream_close(is);
            ZFREE_OBJECT(is);
            node->value = NULL;
            ptr_set_delete(&into->file_add, filename);
            free(key);

            //not_added_anymore = TRUE;
        }

        // always delete first, as there can be any kind of obsolete files
        //if(!not_added_anymore)
        {
            ptr_vector_append(&into->file_del, strdup(filename));
        }
    }

    ptr_set_iterator iter;
    ptr_set_iterator_init(&step->file_add, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        char *filename = node->key;

        ptr_node *into_node = ptr_set_insert(&into->file_add, filename);
        if(into_node->value == NULL)
        {
            log_info("'%s' will be added", filename);

            // clone the data
            into_node->key = strdup(filename);
            into_node->value = bytearray_input_stream_clone((input_stream*)node->value);
        }
        else
        {
            log_warn("'%s' is a duplicate file add entry", filename);
        }
    }

    return SUCCESS;
}

/**
 * Queries the server for its current state (DNSKEY + RRSIG DNSKEY records)
 *
 * Appends found dns_resource_record* to the ptr_vector
 *
 * The ptr_vector is expected to be initialised and empty, or at the very least only filled with
 * dns_resource_record*
 *
 */

ya_result
keyroll_dnskey_state_query(const keyroll_t *keyroll, ptr_vector *current_dnskey_rrsig_rr)
{
    ya_result ret;
    message_data *mesg = message_new_instance();
    message_make_query_ex(mesg, rand(), keyroll->domain, TYPE_DNSKEY, CLASS_IN, MESSAGE_EDNS0_DNSSEC);

    if(ISOK(ret = message_query_tcp_with_timeout(mesg, keyroll->server, KEYROLL_QUERY_TIMEOUT_S)))
    {
        // extract dnskey + rrsig
        if(message_isauthoritative(mesg))
        {
            packet_unpack_reader_data purd;

            packet_reader_init_from_message(&purd, mesg);

            //u16 qc = message_get_query_count(mesg);
            u16 an = message_get_answer_count(mesg);
            u16 ns = message_get_authority_count(mesg);
            //u16 ar = message_get_additional_count(mesg);

            int total = an;
            total += ns;

            packet_reader_skip_query_section(&purd);

            for(int i = 0 ; i < total; ++i)
            {
                dns_resource_record *rr = dns_resource_record_new_instance();

                if(FAIL(ret = packet_reader_read_dns_resource_record(&purd, rr)))
                {
                    dns_resource_record_free(rr);
                    break;
                }

                if(rr->tctr.qtype == TYPE_DNSKEY)
                {
                    ptr_vector_append(current_dnskey_rrsig_rr, rr);
                }
                else if((rr->tctr.qtype == TYPE_RRSIG) && (rrsig_get_type_covered_from_rdata(rr->rdata, rr->rdata_size) == TYPE_DNSKEY))
                {
                    ptr_vector_append(current_dnskey_rrsig_rr, rr);
                }
            }

            if(ISOK(ret))
            {
                ptr_vector_qsort(current_dnskey_rrsig_rr, keyroll_dns_resource_record_ptr_vector_qsort_callback);
            }
        }
        else
        {
            log_err("message_query_tcp_with_timeout(mesg, %{hostaddr}, %i) server is not authoritative", keyroll->server, KEYROLL_QUERY_TIMEOUT_S);
            // server is not authoritative
            ret = INVALID_STATE_ERROR;
        }
    }
    else
    {
        log_err("message_query_tcp_with_timeout(mesg, %{hostaddr}, %i) returned %r", keyroll->server, KEYROLL_QUERY_TIMEOUT_S, ret);
    }

    message_free(mesg);

    return ret;
}

/**
 * Releases the memory used by dns_resource_record* in the ptr_vector
 */

void
keyroll_dnskey_state_destroy(ptr_vector *current_dnskey_rrsig_rr)
{
    for(int i = 0; i <= ptr_vector_last_index(current_dnskey_rrsig_rr); ++i)
    {
        dns_resource_record *rr = (dns_resource_record*)ptr_vector_get(current_dnskey_rrsig_rr, i);
        dns_resource_record_free(rr);
    }
    ptr_vector_clear(current_dnskey_rrsig_rr);
    //
    ptr_vector_destroy(current_dnskey_rrsig_rr);
}

/**
 * Compares the expected state at a given step with the state on the server
 * (queried with keyroll_dnskey_state_query)
 *
 * Returns SUCCESS iff it's a match.
 */

ya_result
keyroll_step_expects_matched(const keyroll_step_t *step, const ptr_vector *dnskey_rrsig_rr)
{
    // ensure a perfect match between expected records and whatever is in dnskey_rrsig_rr
    // both ptr_vector are sorted

    if(ptr_vector_last_index(&step->expect) == ptr_vector_last_index(dnskey_rrsig_rr))
    {
        for(int i = 0; i <= ptr_vector_last_index(dnskey_rrsig_rr); ++i)
        {
            dns_resource_record *ra = ptr_vector_get(&step->expect, i);
            dns_resource_record *rb = ptr_vector_get(dnskey_rrsig_rr, i);

            if(dns_resource_record_compare(ra, rb) != 0)
            {
                return KEYROLL_EXPECTED_IDENTICAL_RECORDS;
            }
        }

        return SUCCESS;
    }

    return KEYROLL_EXPECTED_IDENTICAL_SIZE_RRSETS;
}

/**
 * Compares the end-result state at a given step with the state on the server
 * (queried with keyroll_dnskey_state_query)
 *
 * Returns SUCCESS iff it's a match.
 */

ya_result
keyroll_step_endresult_matched(const keyroll_step_t *step, const ptr_vector *dnskey_rrsig_rr)
{
    // ensure a perfect match between end-result records and whatever is in dnskey_rrsig_rr
    // both ptr_vector are sorted

    if(ptr_vector_last_index(&step->endresult) == ptr_vector_last_index(dnskey_rrsig_rr))
    {
        for(int i = 0; i <= ptr_vector_last_index(dnskey_rrsig_rr); ++i)
        {
            dns_resource_record *ra = ptr_vector_get(&step->endresult, i);
            dns_resource_record *rb = ptr_vector_get(dnskey_rrsig_rr, i);

            if(dns_resource_record_compare(ra, rb) != 0)
            {
                return KEYROLL_EXPECTED_IDENTICAL_RECORDS;
            }
        }

        return SUCCESS;
    }

    return KEYROLL_EXPECTED_IDENTICAL_SIZE_RRSETS;
}

/**
 * Plays a step on the server
 *
 * @param step the step to play
 * @param delete_all_dnskey delete all keys on the server.
 */

ya_result
keyroll_step_play(const keyroll_step_t *step, bool delete_all_dnskey)
{
    char path[PATH_MAX];

    // delete the files

    for(int i = 0; i <= ptr_vector_last_index(&step->file_del); ++i)
    {
        const char *name = (char*)ptr_vector_get(&step->file_del, i);

        // delete the file from he right directory

        log_info("%{dnsname}: deleting file: '%s'", step->keyroll->domain, name);

        unlink_ex(step->keyroll->keys_path, name);
    }

    // copy the files

    ya_result ret;
    ptr_set_iterator iter;
    ptr_set_iterator_init(&step->file_add, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        const char *name = (char*)node->key;

        // copy the input stream in the right directory

        snformat(path, sizeof(path), "%s/%s", step->keyroll->keys_path, name);

        int n = strlen(name);
        bool is_private_key_file = (n > 8) && (memcmp(&name[n - 8], ".private", 8) == 0);

        log_info("%{dnsname}: creating file: '%s'", step->keyroll->domain, path);

        output_stream os;
        if(ISOK(ret = file_output_stream_create(&os, path, 0640)))
        {
            input_stream *is = (input_stream*)node->value;

            bytearray_input_stream_reset(is);

            if(is_private_key_file)
            {

                // read the file line by line
                // remove Publish and Delete lines

                for(;;)
                {
                    ret = input_stream_read_line(is, path, sizeof(path));
                    if(ISOK(ret))
                    {
                        if(ret == 0)
                        {
                            break;
                        }

                        if(memcmp(path, "Publish:", 8) == 0)
                        {
                            continue;
                        }
                        else if(memcmp(path, "Delete:", 7) == 0)
                        {
                            continue;
                        }

                        output_stream_write(&os, path, ret);
                    }
                    else
                    {
                        log_err("keyroll step failure reading bytes for: '%s'", path);
                        break;
                    }
                }
            }
            else
            {
                for(;;)
                {
                    ret = input_stream_read(is, path, sizeof(path));

                    if(ISOK(ret))
                    {
                        if(ret == 0)
                        {
                            break;
                        }

                        output_stream_write(&os, path, ret);
                    }
                    else
                    {
                        log_err("keyroll step failure reading bytes for: '%s'", path);
                        break;
                    }
                }
            }

            output_stream_close(&os);

            if(FAIL(ret))
            {
                return ret;
            }
        }
        else
        {
            log_err("keyroll could not create file '%s'", path);
            return ret;
        }
    }

    if((ptr_vector_size(&step->dnskey_del) + ptr_vector_size(&step->dnskey_add) + ptr_vector_size(&step->rrsig_add)) == 0)
    {
        // nothing to do

        return SUCCESS;
    }

    // build an update packet
    // commit update packet
    // optionally check the server for an expected match

    message_data *mesg = message_new_instance();
    message_data *answer = message_new_instance();
    struct packet_writer pw;
    message_make_dnsupdate_init(mesg, rand(), step->keyroll->domain, CLASS_IN, 65535, &pw);

    if(delete_all_dnskey)
    {
        log_info("%{dnsname}: all previous DNSKEY will be removed", step->keyroll->domain);
        message_make_dnsupdate_delete_rrset(mesg, &pw, step->keyroll->domain, TYPE_DNSKEY);
    }

    for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_del); ++i)
    {
        dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_del, i);
        message_make_dnsupdate_delete_dnskey(mesg, &pw, key);
    }

    for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_add); ++i)
    {
        dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_add, i);
        message_make_dnsupdate_add_dnskey(mesg, &pw, key, DNSKEY_TTL_DEFAULT);
    }

    for(int i = 0; i <= ptr_vector_last_index(&step->rrsig_add); ++i)
    {
        dns_resource_record *rrsig = (dns_resource_record*)ptr_vector_get(&step->rrsig_add, i);
        message_make_dnsupdate_add_dns_resource_record(mesg, &pw, rrsig);
    }

    if(ISOK(ret = message_make_dnsupdate_finalize(mesg, &pw)))
    {
        // message has been properly built

        message_log(g_keyroll_logger, LOG_INFO, mesg);

        bool dnskey_rrsig_needed = (ptr_vector_last_index(&step->dnskey_del) >= 0) || (ptr_vector_last_index(&step->dnskey_add) >= 0);
        bool dnskey_rrsig_added = (ptr_vector_last_index(&step->rrsig_add) >= 0);

        if(dnskey_rrsig_needed && !dnskey_rrsig_added)
        {
            log_err("%s%{dnsname}: internal state error: no DNSKEY RRSIG added while the DNSKEY rrset is being modified", "<INTERVENTION> ", step->keyroll->domain);
            dnscore_shutdown();
            return INVALID_STATE_ERROR;
        }

        if(!keyroll_dryrun_mode)
        {
            ret = STOPPED_BY_APPLICATION_SHUTDOWN;

            int loops = 0; // only used to display a message once (tries most errors forever)

            u32 apply_verify_try_count = 0;

            while(!dnscore_shuttingdown())
            {
                if(ISOK(ret = message_query_tcp_with_timeout_ex(mesg, step->keyroll->server, answer, KEYROLL_QUERY_TIMEOUT_S)))
                {
                    log_info("%{dnsname}: sent message to %{hostaddr}", step->keyroll->domain, step->keyroll->server);

                    if(message_get_status(answer) == FP_RCODE_NOERROR)
                    {
                        log_info("%{dnsname}: %{hostaddr} server replied it did the update", step->keyroll->domain, step->keyroll->server);

                        // now let's check if the server said the truth

                        ptr_vector current_dnskey_rrsig_rr;
                        ptr_vector_init_ex(&current_dnskey_rrsig_rr, 32);
                        if(ISOK(ret = keyroll_dnskey_state_query(step->keyroll, &current_dnskey_rrsig_rr)))
                        {
                            // current_dnskey_rrsig_rr contains the records currently on the server

                            ya_result matched_expectations = keyroll_step_endresult_matched(step, &current_dnskey_rrsig_rr);

                            log_info("%{dnsname}: current step (%llU) should result in:", step->keyroll->domain, step->epochus);

                            for(int i = 0; i <= ptr_vector_last_index(&step->endresult); ++i)
                            {
                                log_info("%{dnszrr}", ptr_vector_get(&step->endresult, i));
                            }

                            log_info("%{dnsname}: server (%{hostaddr}) update resulted in:", step->keyroll->domain, step->keyroll->server);

                            for(int i = 0; i <= ptr_vector_last_index(&current_dnskey_rrsig_rr); ++i)
                            {
                                log_info("%{dnszrr}", ptr_vector_get(&current_dnskey_rrsig_rr, i));
                            }

                            if(ISOK(matched_expectations))
                            {
                                log_info("%{dnsname}: update was applied successfully", step->keyroll->domain);
                            }
                            else
                            {
                                ++apply_verify_try_count;

                                log_err("%{dnsname}: update was not applied successfully (try %i/%i)", step->keyroll->domain, apply_verify_try_count, step->keyroll->update_apply_verify_retries + 1);

                                // 1 vs 1 => must do
                                if(apply_verify_try_count <= step->keyroll->update_apply_verify_retries)
                                {
                                    // ret = EAGAIN; // unused
                                    usleep_ex(ONE_SECOND_US * step->keyroll->update_apply_verify_retries_delay);
                                    continue;
                                }
                                else
                                {
                                    log_err("%{dnsname}: update was not applied successfully, no retry left.", step->keyroll->domain);
                                    ret = KEYROLL_MUST_REINITIALIZE;
                                }
                            }
                        }

                        keyroll_dnskey_state_destroy(&current_dnskey_rrsig_rr);

                        break;
                    }

                    log_err("%{dnsname}: %{hostaddr} server replied with an error: %s", step->keyroll->domain, step->keyroll->server, dns_message_rcode_get_name(message_get_status(answer)));

                    ret = MAKE_DNSMSG_ERROR(message_get_status(answer));
                    break;
                }

                if(!((ret == MAKE_ERRNO_ERROR(ETIMEDOUT)) || (ret == MAKE_ERRNO_ERROR(EAGAIN) || (ret == UNEXPECTED_EOF))))
                {
                    log_notice("%{dnsname}: sending message to %{hostaddr} failed: %r", step->keyroll->domain, step->keyroll->server, ret);
                    break;
                }

                if(!dnscore_shuttingdown())
                {
                    log_warn("%{dnsname}: sending message to %{hostaddr} failed: %r (retrying in one second)", step->keyroll->domain, step->keyroll->server, ret);
                    sleep(1);

                    if(++loops == 1) // show the message exactly once
                    {
                        if(ret != UNABLE_TO_COMPLETE_FULL_READ)
                        {
                            message_log(MODULE_MSG_HANDLE, MSG_INFO, mesg);
                        }
                    }
                }

                ret = STOPPED_BY_APPLICATION_SHUTDOWN;
            }
        }
        else
        {
            log_warn("%{dnsname}: dryrun mode : no update has been sent", step->keyroll->domain);
        }
    }

    message_free(answer);
    message_free(mesg);

    return ret;
}

/**
 * Plays all the steps in a given epoch range.
 */

ya_result
keyroll_step_play_range_ex(const keyroll_t *keyroll, s64 seek_from , s64 now, bool delete_all_dnskey, keyroll_step_t **first_stepp)
{
    if(seek_from > now)
    {
        log_err("%{dnsname}: play range from the future to the past (%llU to %llU)", keyroll->domain, seek_from, now);
        return INVALID_ARGUMENT_ERROR;
    }

    ya_result ret;

    keyroll_step_t *first_step = keyroll_get_next_step_from(keyroll, seek_from);

    if(first_step == NULL)
    {
        log_info("%{dnsname}: play range has no first step", keyroll->domain);
        return INVALID_STATE_ERROR;
    }

    log_info("%{dnsname}: first step epoch is %llU", keyroll->domain, first_step->epochus);

    if(first_step->epochus > now)
    {
        if(first_stepp != NULL)
        {
            *first_stepp = first_step;
        }

        log_info("%{dnsname}: play range will not play %llU as its first step as it's after %llU", keyroll->domain, first_step->epochus, now);
        return SUCCESS;
    }

    log_info("%{dnsname}: play range from %llU", keyroll->domain, first_step->epochus);

    keyroll_step_t *merge = keyroll_step_new_instance();
    // if a merge occurs, it's important to log it in case something goes wrong
    log_info("%{dnsname}: -------------------------------------------", keyroll->domain);
    log_info("%{dnsname}: merging step:", keyroll->domain);
    log_info("%{dnsname}: -------------------------------------------", keyroll->domain);
    keyroll_step_print(merge);
    log_info("%{dnsname}: -------------------------------------------", keyroll->domain);
    log_info("%{dnsname}: with step:", keyroll->domain);
    log_info("%{dnsname}: -------------------------------------------", keyroll->domain);
    keyroll_step_print(first_step);
    logger_flush();
    keyroll_step_merge(merge, first_step);
    log_info("%{dnsname}: -------------------------------------------", keyroll->domain);
    log_info("%{dnsname}: resulting in:", keyroll->domain);
    log_info("%{dnsname}: -------------------------------------------", keyroll->domain);
    keyroll_step_print(merge);

    s64 tick = first_step->epochus;
    while(tick < now)
    {
        keyroll_step_t *next_step = keyroll_get_next_step_from(keyroll, tick + 1);
        if((next_step == NULL) || (next_step->epochus > now))
        {
            break;
        }

        log_info("%{dnsname}: then with step:", keyroll->domain);
        log_info("%{dnsname}: -------------------------------------------", keyroll->domain);
        keyroll_step_print(next_step);
        // logger_flush();
        keyroll_step_merge(merge, next_step);
        log_info("%{dnsname}: -------------------------------------------", keyroll->domain);
        log_info("%{dnsname}: resulting in:", keyroll->domain);
        log_info("%{dnsname}: -------------------------------------------", keyroll->domain);
        keyroll_step_print(merge);
        tick = next_step->epochus;
    }

    log_info("%{dnsname}: play range ends up with the step: ", keyroll->domain);
    log_info("%{dnsname}: -------------------------------------------", keyroll->domain);
    keyroll_step_print(merge);
    log_info("%{dnsname}: -------------------------------------------", keyroll->domain);
    logger_flush();

    if(FAIL(ret = keyroll_step_play(merge, delete_all_dnskey)))
    {
        log_err("%{dnsname}: play range step execute failed: %r", keyroll->domain, ret);
    }

    if(first_stepp != NULL)
    {
        *first_stepp = merge;
    }

    return ret;
}

/**
 * Plays all the steps in a given epoch range.
 */

ya_result
keyroll_step_play_range(const keyroll_t *keyroll, s64 seek_from , s64 now)
{
    ya_result ret;
    ret = keyroll_step_play_range_ex(keyroll, seek_from, now, FALSE, NULL);
    return ret;
}

/**
 * Plays the first step of a plan if it's before a given epoch.
 * If the first step is in the future, it's not played.
 * Returns the first step in the parameter.
 * Returns an error code.
 */

ya_result
keyroll_play_first_step(const keyroll_t *keyroll, s64 now, keyroll_step_t **first_stepp)
{
    ya_result ret;
    ret = keyroll_step_play_range_ex(keyroll, 0 , now, TRUE, first_stepp);
    return ret;
}

/**
 * Scans the plan for the step matching the given state
 *
 * Returns the matching step or NULL
 */

keyroll_step_t*
keyroll_step_scan_matching_expectations(const keyroll_t *keyroll, ptr_vector *current_dnskey_rrsig_rr)
{
    s64 t = 0;

    for(;;)
    {
        keyroll_step_t *step = keyroll_get_next_step_from(keyroll, t);

        if(step == NULL)
        {
            return NULL;
        }

        ya_result ret = keyroll_step_expects_matched(step, current_dnskey_rrsig_rr);

        if(ret == SUCCESS)
        {
            return step;
        }

        t = step->epochus + 1;
    }
}

/**
 * Returns the step being active at the given epoch or NULL if there is no such step.
 * If a step starts at the given epoch, it's the one returned.
 */

keyroll_step_t*
keyroll_get_current_step_at(const keyroll_t *keyroll, s64 epochus)
{
    u64_node* node = u64_set_find_key_or_prev(&keyroll->steps, epochus);

    if(node != NULL)
    {
        return (keyroll_step_t*)node->value;
    }
    else
    {
        return NULL;
    }
}

/**
 * Returns the next step to be active from the given epoch or NULL if there is no such step.
 * If a step starts at the given epoch, it's the one returned.
 */

keyroll_step_t*
keyroll_get_next_step_from(const keyroll_t *keyroll, s64 epochus)
{
    u64_node* node = u64_set_find_key_or_next(&keyroll->steps, epochus);

    if(node != NULL)
    {
        return (keyroll_step_t*)node->value;
    }
    else
    {
        return NULL;
    }
}

/**
 * Generates a DNSKEY to be published at the given epoch.
 * The DNSKEY can be set as a KSK or ZSK using the ksk parameter.
 * This function creates steps at the various time fields of the key.
 */

ya_result
keyroll_generate_dnskey(keyroll_t *keyroll, s64 publication_epochus, bool ksk)
{
    dnssec_key *key = NULL;
    ya_result ret;
    const keyroll_key_parameters_t *kp = ksk?&keyroll->ksk_parameters:&keyroll->zsk_parameters;
    s64 *next_deactivationp = ksk?&keyroll->ksk_next_deactivation:&keyroll->zsk_next_deactivation;

    char name[MAX_DOMAIN_TEXT_LENGTH];

    if(FAIL(ret = dnsname_to_cstr(name, keyroll->domain)))
    {
        return ret;
    }

    log_info("%{dnsname}: generating %cSK key to publish at %llU", keyroll->domain, ksk?'K':'Z', publication_epochus);

    if(ISOK(ret = dnskey_newinstance(
        kp->size,
        kp->algorithm,
        ksk?(DNSKEY_FLAG_ZONEKEY | DNSKEY_FLAG_KEYSIGNINGKEY):DNSKEY_FLAG_ZONEKEY,
        name, &key)))
    {
        log_info("%{dnsname}: generated %cSK key to publish at %llU", keyroll->domain, ksk?'K':'Z', publication_epochus);
        //u16 tag = dnskey_get_tag(key);

        keyroll_step_t* publication_step = keyroll_get_step(keyroll, publication_epochus);
        publication_step->keyroll_action |= /*KeyrollAction::*/Publish;
        ptr_vector_append(&publication_step->dnskey_add, key);
        dnskey_acquire(key);
        publication_step->dirty = TRUE;
        dnskey_set_publish_epoch(key, publication_epochus / ONE_SECOND_US);

        s64 activate_epochus = publication_epochus + ONE_SECOND_US * kp->activate_after;
        keyroll_step_t *activation_step = keyroll_get_step(keyroll, activate_epochus);
        activation_step->keyroll_action |= /*KeyrollAction::*/Activate;
        activation_step->dirty = TRUE;
        dnskey_set_activate_epoch(key, activate_epochus / ONE_SECOND_US);

        s64 deactivate_epochus = publication_epochus + ONE_SECOND_US * kp->deactivate_after;
        keyroll_step_t *deactivation_step = keyroll_get_step(keyroll, deactivate_epochus);
        deactivation_step->keyroll_action |= /*KeyrollAction::*/Deactivate;
        deactivation_step->dirty = TRUE;

        s64 unpublish_epochus = publication_epochus + ONE_SECOND_US * kp->delete_after;

        time_t deactivate_epoch_margin = keyroll_deactivation_margin(dnskey_get_activate_epoch(key), deactivate_epochus / ONE_SECOND_US, unpublish_epochus / ONE_SECOND_US);
        time_t deactivate_epoch = (deactivate_epochus/ ONE_SECOND_US) + deactivate_epoch_margin;

        dnskey_set_inactive_epoch(key, deactivate_epoch);

        if(*next_deactivationp < deactivation_step->epochus)
        {
            *next_deactivationp = deactivation_step->epochus;
        }

        keyroll_step_t *unpublication_step = keyroll_get_step(keyroll, unpublish_epochus);
        ptr_vector_append(&unpublication_step->dnskey_del, key);
        dnskey_acquire(key);
        unpublication_step->keyroll_action |= /*KeyrollAction::*/Unpublish;
        unpublication_step->dirty = TRUE;
        time_t unpublish_epoch = MAX(unpublish_epochus / ONE_SECOND_US, deactivate_epoch);
        dnskey_set_delete_epoch(key, unpublish_epoch);
/*
        formatln("created key: tag=%i, algorithm=%i, flags=%i, create=%U publish=%U activate=%U deactivate=%U unpublish=%U",
                 dnskey_get_tag(key),
                 dnskey_get_algorithm(key),
                 ntohs(dnskey_get_flags(key)),
                 dnskey_get_created_epoch(key),
                 dnskey_get_publish_epoch(key),
                 dnskey_get_activate_epoch(key),
                 dnskey_get_inactive_epoch(key),
                 dnskey_get_delete_epoch(key));
*/
        dnskey_release(key); // the original reference
    }
    else
    {
        log_info("%{dnsname}: failed to generate %cSK key to publish at %llU: %r", keyroll->domain, ksk?'K':'Z', publication_epochus, ret);
    }

    return ret;
}

s64
keyroll_set_timing_steps(keyroll_t *keyroll, dnssec_key *key, bool dirty)
{
    s64 publication_epochus = ONE_SECOND_US * dnskey_get_publish_epoch(key);
    keyroll_step_t* publication_step = keyroll_get_step(keyroll, publication_epochus);
    publication_step->keyroll_action |= /*KeyrollAction::*/Publish;

    ptr_vector_append(&publication_step->dnskey_add, key);
    dnskey_acquire(key);

    publication_step->dirty = dirty;
    dnskey_set_publish_epoch(key, publication_epochus / ONE_SECOND_US);

    s64 activate_epochus = ONE_SECOND_US * dnskey_get_activate_epoch(key);
    keyroll_step_t *activation_step = keyroll_get_step(keyroll, activate_epochus);
    activation_step->keyroll_action |= /*KeyrollAction::*/Activate;
    activation_step->dirty = dirty;
    dnskey_set_activate_epoch(key, activate_epochus / ONE_SECOND_US);

    s64 deactivate_epochus = ONE_SECOND_US * dnskey_get_inactive_epoch(key);
    keyroll_step_t *deactivation_step = keyroll_get_step(keyroll, deactivate_epochus);
    deactivation_step->keyroll_action |= /*KeyrollAction::*/Deactivate;
    deactivation_step->dirty = dirty;

    s64 unpublish_epochus = ONE_SECOND_US * dnskey_get_delete_epoch(key);

    time_t deactivate_epoch_margin = keyroll_deactivation_margin(dnskey_get_activate_epoch(key), deactivate_epochus / ONE_SECOND_US, unpublish_epochus / ONE_SECOND_US);

    time_t deactivation_epoch = (deactivate_epochus / ONE_SECOND_US) + deactivate_epoch_margin;
    dnskey_set_inactive_epoch(key, deactivation_epoch);

    keyroll_step_t *unpublication_step = keyroll_get_step(keyroll, unpublish_epochus);
    ptr_vector_append(&unpublication_step->dnskey_del, key);
    dnskey_acquire(key);
    unpublication_step->keyroll_action |= /*KeyrollAction::*/Unpublish;
    unpublication_step->dirty = dirty;
    time_t unpublish_epoch = MAX(unpublish_epochus / ONE_SECOND_US, deactivation_epoch);
    dnskey_set_delete_epoch(key, unpublish_epoch);

    return deactivate_epochus;
}

/**
 * Generates a DNSKEY to be published at the given epoch.
 * The DNSKEY can be set as a KSK or ZSK using the ksk parameter.
 * This functions requires the time fields to be set manually.
 * This function creates steps at the various time fields of the key.
 */

ya_result
keyroll_generate_dnskey_ex(keyroll_t *keyroll, u32 size, u8 algorithm,
        s64 creation_epochus,
        s64 publication_epochus,
        s64 activate_epochus,
        s64 deactivate_epochus,
        s64 unpublish_epochus,
        bool ksk,
        dnssec_key **out_keyp)
{
    dnssec_key *key = NULL;
    ya_result ret;

    if((keyroll == NULL) || (keyroll->domain == NULL))
    {
        return INVALID_STATE_ERROR;
    }

    //formatln("%{dnsname}: generate %s key %llU %llU %llU %llU %llU", keyroll->domain, (ksk?"KSK":"ZSK"), creation_epochus, publication_epochus, activate_epochus, deactivate_epochus,unpublish_epochus);

    s64 *next_deactivationp = ksk?&keyroll->ksk_next_deactivation:&keyroll->zsk_next_deactivation;

    char name[MAX_DOMAIN_TEXT_LENGTH];

    if(FAIL(ret = dnsname_to_cstr(name, keyroll->domain)))
    {
        return ret;
    }

    log_info("%{dnsname}: generating %cSK key to publish at %llU", keyroll->domain, ksk?'K':'Z', publication_epochus);

    while(!dnscore_shuttingdown()) // while there are tag collisions
    {
        if(ISOK(ret = dnskey_newinstance(
            size,
            algorithm,
            ksk?(DNSKEY_FLAG_ZONEKEY | DNSKEY_FLAG_KEYSIGNINGKEY):DNSKEY_FLAG_ZONEKEY,
            name, &key)))
        {
            dnssec_key *previous_key_with_same_tag = dnssec_keystore_acquire_key_from_fqdn_with_tag(dnskey_get_domain(key), dnskey_get_tag(key));
            if(previous_key_with_same_tag != NULL)
            {
                log_notice("%{dnsname}: a tag collision happened creating a %cSK key. Discarding and trying again.", keyroll->domain, ksk?'K':'Z', keyroll->domain);
                dnskey_release(previous_key_with_same_tag);
                dnskey_release(key);

                ret = DNSSEC_ERROR_DUPLICATEKEY; // actually the tag is a duplicate ...
                continue;
            }

            log_info("%{dnsname}: generated %cSK key to publish at %llU", keyroll->domain, ksk?'K':'Z', publication_epochus);
            //u16 tag = dnskey_get_tag(key);

            dnskey_set_created_epoch(key, creation_epochus / ONE_SECOND_US);

            keyroll_step_t* publication_step = keyroll_get_step(keyroll, publication_epochus);
            publication_step->keyroll_action |= /*KeyrollAction::*/Publish;
            ptr_vector_append(&publication_step->dnskey_add, key);
            dnskey_acquire(key);
            publication_step->dirty = TRUE;
            dnskey_set_publish_epoch(key, publication_epochus / ONE_SECOND_US);

            keyroll_step_t *activation_step = keyroll_get_step(keyroll, activate_epochus);
            activation_step->keyroll_action |= /*KeyrollAction::*/Activate;
            activation_step->dirty = TRUE;
            dnskey_set_activate_epoch(key, activate_epochus / ONE_SECOND_US);

            time_t deactivate_epoch_margin = keyroll_deactivation_margin(dnskey_get_activate_epoch(key), deactivate_epochus / ONE_SECOND_US, unpublish_epochus / ONE_SECOND_US);

            time_t deactivate_epoch = (deactivate_epochus / ONE_SECOND_US) + deactivate_epoch_margin;

            keyroll_step_t *deactivation_step = keyroll_get_step(keyroll, deactivate_epoch * ONE_SECOND_US);
            deactivation_step->keyroll_action |= /*KeyrollAction::*/Deactivate;
            deactivation_step->dirty = TRUE;

            dnskey_set_inactive_epoch(key, deactivate_epoch);

            if(*next_deactivationp < deactivate_epochus)
            {
                *next_deactivationp = deactivate_epochus;
            }

            keyroll_step_t *unpublication_step = keyroll_get_step(keyroll, unpublish_epochus);
            ptr_vector_append(&unpublication_step->dnskey_del, key);
            dnskey_acquire(key);
            unpublication_step->keyroll_action |= /*KeyrollAction::*/Unpublish;
            unpublication_step->dirty = TRUE;
            time_t unpublish_epoch = MAX(unpublish_epochus / ONE_SECOND_US, deactivate_epoch);
            dnskey_set_delete_epoch(key, unpublish_epoch);
            dnssec_keystore_add_key(key);
#if DEBUG
            log_debug("created key: domain=%{dnsname}, tag=%i, algorithm=%i, flags=%i, create=%U publish=%U activate=%U deactivate=%U unpublish=%U",
                     dnskey_get_domain(key),
                     dnskey_get_tag(key),
                     dnskey_get_algorithm(key),
                     ntohs(dnskey_get_flags(key)),
                     dnskey_get_created_epoch(key),
                     dnskey_get_publish_epoch(key),
                     dnskey_get_activate_epoch(key),
                     dnskey_get_inactive_epoch(key),
                     dnskey_get_delete_epoch(key));
            logger_flush();
#endif
            dnskey_release(key); // the original reference
        }
        else
        {   // note: %llU => prints UTC time
            log_err("%{dnsname}: failed to generate %cSK key to publish at %llU: %r", keyroll->domain, ksk?'K':'Z', publication_epochus, ret);
        }

        break;
    } // while(!dnscore_isshuttingdown())

    if(ISOK(ret) && (out_keyp != NULL))
    {
        dnskey_acquire(key);
        *out_keyp = key;
    }

    return ret;
}

/**
 * Generates a plan using a DNSSEC policy.
 */

ya_result
keyroll_plan_with_policy(keyroll_t *keyroll, s64 generate_from, s64 generate_until, const char* policy_name)
{
    dnssec_policy *policy = dnssec_policy_acquire_from_name(policy_name);

    if(policy == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    ya_result ret;

    ret = dnssec_policy_process(keyroll, policy, generate_from, generate_until);

    // dnssec_policy_date_init_from_epoch

    return ret;
}

static u32
keyroll_key_hash(dnssec_key *key)
{
    u32 key_hash = dnskey_get_flags(key);
    key_hash <<= 5;
    key_hash |= dnskey_get_algorithm(key);
    key_hash <<= 16;
    key_hash |= dnskey_get_tag(key);
    return key_hash;
}

static void
keyroll_print_u32_set_destroy_callback(u32_node *node)
{
    dnssec_key *key = (dnssec_key*)node->value;
    dnskey_release(key);
}

void
keyroll_step_print(keyroll_step_t *step)
{
    log_info("================================");
    log_info("At %llU = %llu", step->epochus, step->epochus);
    log_info("================================");

    log_info("- update -----------------------");

    for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_del); ++i)
    {
        dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_del, i);
        log_info("del record K%{dnsname}+%03u+%05d %-5i bits %cSK %U => %U => %U => %U", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key),
                 dnskey_get_size(key), ((dnskey_get_flags(key)&DNSKEY_FLAG_KEYSIGNINGKEY)!=0)?'K':'Z', dnskey_get_publish_epoch(key), dnskey_get_activate_epoch(key),
                 dnskey_get_inactive_epoch(key), dnskey_get_delete_epoch(key));
    }

    for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_add); ++i)
    {
        dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_add, i);
        log_info("add record K%{dnsname}+%03u+%05d %-5i bits %cSK %U => %U => %U => %U", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key),
                 dnskey_get_size(key), ((dnskey_get_flags(key)&DNSKEY_FLAG_KEYSIGNINGKEY)!=0)?'K':'Z', dnskey_get_publish_epoch(key), dnskey_get_activate_epoch(key),
                 dnskey_get_inactive_epoch(key), dnskey_get_delete_epoch(key));
    }

    for(int i = 0; i <= ptr_vector_last_index(&step->rrsig_add); ++i)
    {
        dns_resource_record *rr = (dns_resource_record*)ptr_vector_get(&step->rrsig_add, i);
        log_info("add record %{dnsrr}", rr);
    }

    for(int i = 0; i <= ptr_vector_last_index(&step->expect); ++i)
    {
        dns_resource_record *rr = (dns_resource_record*)ptr_vector_get(&step->expect, i);
        log_info("expects record %{dnsrr}", rr);
    }

    for(int i = 0; i <= ptr_vector_last_index(&step->file_del); ++i)
    {
        char *filename = (char*)ptr_vector_get(&step->file_del, i);
        log_info("delete file '%s'", filename);
    }

    ptr_set_iterator iter;
    ptr_set_iterator_init(&step->file_add, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        char *filename = (char*)node->key;
        log_info("create file '%s'", filename);
    }
}

#define log_print_info(...) log_info(__VA_ARGS__);formatln(__VA_ARGS__)
#define log_print_warn(...) log_warn(__VA_ARGS__);formatln("WARNING: " __VA_ARGS__)

/**
 * Prints a plan.
 */

ya_result
keyroll_print(keyroll_t *keyroll, output_stream *os)
{
    ya_result ret = SUCCESS;

    u32_set current;
    u32_set_init(&current);

    s64 ksk_next_deactivation = 0;
    s64 zsk_next_deactivation = 0;

    u64_set_iterator iter;
    u64_set_iterator_init(&keyroll->steps, &iter);

    if(!u64_set_iterator_hasnext(&iter))
    {
        osprintln(os, "*** ERROR *** No steps have been loaded");
        return INVALID_STATE_ERROR;
    }

    while(u64_set_iterator_hasnext(&iter))
    {
        u64_node *step_node = u64_set_iterator_next_node(&iter);
        keyroll_step_t *step = (keyroll_step_t*)step_node->value;

        if(step == NULL)
        {
            osformatln(os, "*** ERROR *** Empty step at %llU", step_node->key);
            continue;
        }

        osprintln(os, "================================================================================");
        osformatln(os, "At %llU (epoch %llu)", step->epochus, step->epochus);
        osprintln(os, "================================================================================");

        time_t now = (time_t)(step->epochus / ONE_SECOND_US);

        osprintln(os, "DNS updates:");
        osprintln(os, "------------");

        for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_del); ++i)
        {
            dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_del, i);
            formatln("del K%{dnsname}+%03u+%05d %-5i bits %cSK publish at %U, activate at %U, deactivate at %U, unpublish at %U",
                   dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key),
                     dnskey_get_size(key), ((dnskey_get_flags(key)&DNSKEY_FLAG_KEYSIGNINGKEY)!=0)?'K':'Z',
                     dnskey_get_publish_epoch(key), dnskey_get_activate_epoch(key),
                     dnskey_get_inactive_epoch(key), dnskey_get_delete_epoch(key));

            u32 key_hash = keyroll_key_hash(key);
            u32_node *node = u32_set_find(&current, key_hash);
            if(node != NULL)
            {
                dnssec_key *node_key = (dnssec_key*)node->value;
                dnskey_release(node_key);
                u32_set_delete(&current, key_hash);
            }
            else
            {
                osprintln(os, "*** WARNING *** Key isn't in the current set");
            }
        }

        for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_add); ++i)
        {
            dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_add, i);
            osformatln(os, "add K%{dnsname}+%03u+%05d %-5i bits %cSK publish at %U, activate at %U, deactivate at %U, unpublish at %U",
                    dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key),
                    dnskey_get_size(key), ((dnskey_get_flags(key)&DNSKEY_FLAG_KEYSIGNINGKEY)!=0)?'K':'Z',
                    dnskey_get_publish_epoch(key), dnskey_get_activate_epoch(key),
                    dnskey_get_inactive_epoch(key), dnskey_get_delete_epoch(key));

            u32 key_hash = keyroll_key_hash(key);
            u32_node *node = u32_set_find(&current, key_hash);
            if(node == NULL)
            {
                node = u32_set_insert(&current, key_hash);
                node->value = key;
                dnskey_acquire(key);
            }
            else
            {
                osprintln(os, "*** WARNING *** Key is in the current set already");
            }
        }

        osprintln(os, "DNS state:");
        osprintln(os, "----------");

        {
            bool has_active_ksk = FALSE;
            bool has_active_zsk = FALSE;

            u32_set_iterator iter;
            u32_set_iterator_init(&current, &iter);
            while(u32_set_iterator_hasnext(&iter))
            {
                u32_node *node = u32_set_iterator_next_node(&iter);
                dnssec_key *key = (dnssec_key*)node->value;
                bool published = dnskey_is_published(key, now);
                bool activated = dnskey_is_activated(key, now);
                bool deactivated = dnskey_is_deactivated(key, now);
                bool unpublished = dnskey_is_unpublished(key, now);

                if((dnskey_get_flags(key) & DNSKEY_FLAG_KEYSIGNINGKEY) != 0)
                {
                    has_active_ksk |= activated;
                    ksk_next_deactivation = ONE_SECOND_US * dnskey_get_inactive_epoch(key);
                }
                else
                {
                    has_active_zsk |= activated;
                    zsk_next_deactivation = ONE_SECOND_US * dnskey_get_inactive_epoch(key);
                }

                osformatln(os, "=== K%{dnsname}+%03u+%05d %cSK %c %c %c %c", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key),
                         ((dnskey_get_flags(key)&DNSKEY_FLAG_KEYSIGNINGKEY)!=0)?'K':'Z',
                         (published?'P':'-'),
                         (activated?'A':'-'),
                         (deactivated?'D':'-'),
                         (unpublished?'U':'-')          // this one should not appear
                    );
            }

            for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_del); ++i)
            {
                dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_del, i);
                osformatln(os, "=== K%{dnsname}+%03u+%05d %cSK - - D U", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key),
                               ((dnskey_get_flags(key)&DNSKEY_FLAG_KEYSIGNINGKEY)!=0)?'K':'Z');
            }

        }

        flushout();
    }

    if((ksk_next_deactivation > 0) || (zsk_next_deactivation > 0))
    {
        osprintln(os, "- wrapping up ------------------");

        if(ksk_next_deactivation > 0)
        {
            osformatln(os, "Next KSK will need to be active way before %llU", ksk_next_deactivation);
        }

        if(zsk_next_deactivation > 0)
        {
            osformatln(os, "Next ZSK will need to be active way before %llU", zsk_next_deactivation);
        }
    }

    u32_set_callback_and_destroy(&current, keyroll_print_u32_set_destroy_callback);

    return ret;
}

/**
 * Prints a plan.
 */

ya_result
keyroll_print_json(keyroll_t *keyroll, output_stream *os)
{
    ya_result ret = SUCCESS;

    if((keyroll == NULL) || (os == NULL))
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    u32_set current;
    u32_set_init(&current);

    s64 ksk_next_deactivation = 0;
    s64 zsk_next_deactivation = 0;

    u64_set_iterator iter;
    u64_set_iterator_init(&keyroll->steps, &iter);

    if(!u64_set_iterator_hasnext(&iter))
    {
        return INVALID_STATE_ERROR;
    }

    osformatln(os, "{\"domain\": \"%{dnsname}\", \"steps\": [", keyroll->domain);

    const char *step_separator = "";
    while(u64_set_iterator_hasnext(&iter))
    {
        u64_node *step_node = u64_set_iterator_next_node(&iter);
        keyroll_step_t *step = (keyroll_step_t*)step_node->value;

        osformat(os, step_separator);
        step_separator = ", ";

        if(step == NULL)
        {
            log_print_info("*** ERROR *** EMPTY STEP AT %llU", step_node->key);
            osformat(os, "{\"time\": \"%llU\", \"epoch\": %llu}\n", step_node->key, step_node->key);
            continue;
        }

        time_t now = (time_t)(step->epochus / ONE_SECOND_US);

        osformat(os, "{\"time\": \"%llU\", \"epochUs\": %llu, \"updates\": [", step_node->key, step_node->key);

        const char *update_separator = "";

        for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_del); ++i)
        {
            dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_del, i);

            osformat(os, "%s{\"operation\": \"delete\", \"algorithm\": %u, \"tag\": %u, \"size\": %u, \"flags\": \"%cZK\", "
                         "\"publish\": \"%lU\", "
                         "\"activate\": \"%lU\", "
                         "\"deactivate\": \"%lU\", "
                         "\"unpublish\": \"%lU\", "
                         "\"publishEpoch\": \"%llu\", "
                         "\"activateEpoch\": \"%llu\", "
                         "\"deactivateEpoch\": \"%llu\", "
                         "\"unpublishEpoch\": \"%llu\""
                         "}\n",
                     update_separator,
                     dnskey_get_algorithm(key), dnskey_get_tag(key),
                     dnskey_get_size(key), ((dnskey_get_flags(key)&DNSKEY_FLAG_KEYSIGNINGKEY)!=0)?'K':'Z',
                     time_to_timeus(dnskey_get_publish_epoch(key)), time_to_timeus(dnskey_get_activate_epoch(key)),
                     time_to_timeus(dnskey_get_inactive_epoch(key)), time_to_timeus(dnskey_get_delete_epoch(key)),
                     dnskey_get_publish_epoch(key), dnskey_get_activate_epoch(key),
                     dnskey_get_inactive_epoch(key), dnskey_get_delete_epoch(key));

            update_separator = ", ";

            u32 key_hash = keyroll_key_hash(key);
            u32_node *node = u32_set_find(&current, key_hash);
            if(node != NULL)
            {
                dnssec_key *node_key = (dnssec_key*)node->value;
                dnskey_release(node_key);
                u32_set_delete(&current, key_hash);
            }
            else
            {
                // log_print_warn("key isn't in the current set");
            }
        }

        for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_add); ++i)
        {
            dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_add, i);

            osformat(os, "%s{\"operation\": \"add\", \"algorithm\": %u, \"tag\": %u, \"size\": %u, \"flags\": \"%cZK\", "
                         "\"publish\": \"%lU\", "
                         "\"activate\": \"%lU\", "
                         "\"deactivate\": \"%lU\", "
                         "\"unpublish\": \"%lU\", "
                         "\"publishEpoch\": \"%llu\", "
                         "\"activateEpoch\": \"%llu\", "
                         "\"deactivateEpoch\": \"%llu\", "
                         "\"unpublishEpoch\": \"%llu\""
                         "}\n",
                     update_separator,
                     dnskey_get_algorithm(key), dnskey_get_tag(key),
                     dnskey_get_size(key), ((dnskey_get_flags(key)&DNSKEY_FLAG_KEYSIGNINGKEY)!=0)?'K':'Z',
                     time_to_timeus(dnskey_get_publish_epoch(key)), time_to_timeus(dnskey_get_activate_epoch(key)),
                     time_to_timeus(dnskey_get_inactive_epoch(key)), time_to_timeus(dnskey_get_delete_epoch(key)),
                     dnskey_get_publish_epoch(key), dnskey_get_activate_epoch(key),
                     dnskey_get_inactive_epoch(key), dnskey_get_delete_epoch(key));

            update_separator = ", ";

            u32 key_hash = keyroll_key_hash(key);
            u32_node *node = u32_set_find(&current, key_hash);
            if(node == NULL)
            {
                node = u32_set_insert(&current, key_hash);
                node->value = key;
                dnskey_acquire(key);
            }
            else
            {
                //log_print_warn("key is in the current set already");
            }
        }

        osformat(os, "], \"keyState\": [");

        const char *keystate_separator = "";

        {
            bool has_active_ksk = FALSE;
            bool has_active_zsk = FALSE;

            u32_set_iterator iter;
            u32_set_iterator_init(&current, &iter);
            while(u32_set_iterator_hasnext(&iter))
            {
                u32_node *node = u32_set_iterator_next_node(&iter);
                dnssec_key *key = (dnssec_key*)node->value;
                bool published = dnskey_is_published(key, now);
                bool activated = dnskey_is_activated(key, now);
                bool deactivated = dnskey_is_deactivated(key, now);
                bool unpublished = dnskey_is_unpublished(key, now);

                if((dnskey_get_flags(key) & DNSKEY_FLAG_KEYSIGNINGKEY) != 0)
                {
                    has_active_ksk |= activated;
                    ksk_next_deactivation = ONE_SECOND_US * dnskey_get_inactive_epoch(key);
                }
                else
                {
                    has_active_zsk |= activated;
                    zsk_next_deactivation = ONE_SECOND_US * dnskey_get_inactive_epoch(key);
                }

                osformat(os, "%s{\"algorithm\": %u, \"tag\": %u, \"flags\": \"%cSK\", \"published\": %s, \"activated\": %s, \"deactivated\": %s, \"unpublished\": %s}\n",
                         keystate_separator,
                         dnskey_get_algorithm(key), dnskey_get_tag(key),
                         ((dnskey_get_flags(key)&DNSKEY_FLAG_KEYSIGNINGKEY)!=0)?'K':'Z',
                         (published?"true":"false"),
                         (activated?"true":"false"),
                         (deactivated?"true":"false"),
                         (unpublished?"true":"false")
                         );
                keystate_separator = ", ";
            }

            for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_del); ++i)
            {
                dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_del, i);
                osformat(os, "%s{\"algorithm\": %u, \"tag\": %u, \"flags\": \"%cSK\", \"published\": false, \"activated\": false, \"deactivated\": true, \"unpublished\": true}\n",
                         keystate_separator,
                         dnskey_get_algorithm(key), dnskey_get_tag(key),
                         ((dnskey_get_flags(key)&DNSKEY_FLAG_KEYSIGNINGKEY)!=0)?'K':'Z'
                );
                keystate_separator = ", ";
            }
        }
        osformat(os,"]}");
    }

    osformat(os,"], \"followUp\": {\"nextKeySigningKeyActivationRequiredAt\": \"%llU\", \"nextZoneSigningKeyActivationRequiredAt\": \"%llU\"}",
             ksk_next_deactivation,
             zsk_next_deactivation
             );

    osformatln(os, "}\n");

    u32_set_callback_and_destroy(&current, keyroll_print_u32_set_destroy_callback);

    return ret;
}



/**
 * Stores the plan on disk (several files, private KSK files, ...)
 */

ya_result
keyroll_store(keyroll_t *keyroll)
{
    ya_result ret = SUCCESS;

    u32_set current;
    u32_set_init(&current);

    ptr_vector expected_rrsig;
    ptr_vector_init_ex(&expected_rrsig, 16);

    output_stream baos;
    output_stream previous_end_result_os;
    char file_path[PATH_MAX];
    u8 *rdata = (u8*)file_path;     // both buffers can coexist

    bytearray_output_stream_init(&baos, NULL, 8192);

    bytearray_output_stream_init(&previous_end_result_os, NULL, 8192);

    u64_set_iterator iter;
    u64_set_iterator_init(&keyroll->steps, &iter);
    while(u64_set_iterator_hasnext(&iter))
    {
        u64_node *node = u64_set_iterator_next_node(&iter);
        keyroll_step_t *step = (keyroll_step_t*)node->value;

        if(step == NULL)
        {
            continue;
        }

        if(!step->dirty)
        {
            continue;
        }

        // look for the next signature update

        s32 next_signature_update_epoch = MAX_S32;

        for(keyroll_step_t *next_step = step; ;)
        {
            next_step = keyroll_get_next_step_from(keyroll, next_step->epochus + 1);

            if(next_step == NULL)
            {
                break;
            }

            if((ptr_vector_size(&next_step->dnskey_add) + ptr_vector_size(&next_step->dnskey_del)) > 0)
            {
                next_signature_update_epoch = (next_step->epochus / ONE_SECOND_US);

                next_signature_update_epoch = (s32)MIN((s64)next_signature_update_epoch + NEXT_SIGNATURE_EPOCH_MARGIN, (s64)MAX_S32);

                break;
            }
        }

        bool has_zsk = FALSE;
        bool has_ksk = FALSE;

        for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_add); ++i)
        {
            dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_add, i);
            has_ksk |= (dnskey_get_flags(key) == DNSKEY_FLAGS_KSK);
            has_zsk |= (dnskey_get_flags(key) == DNSKEY_FLAGS_ZSK);
        }

        snformat(file_path, sizeof(file_path) - 16, "%s/%llU_%016lli_%{dnsname}", keyroll->plan_path, node->key, node->key, keyroll->domain);
        for(int i = 0; file_path[i] != '\0'; ++i)
        {
            if(file_path[i] == ' ')
            {
                file_path[i] = '-';
            }
        }

        log_info("storing '%s'", file_path);

        output_stream fos;
        ret = file_output_stream_create(&fos, file_path, 0644);
        if(FAIL(ret))
        {
            log_info("failed to create '%s': %r", file_path, ret);
            return ret;
        }

        buffer_output_stream_init(&fos, &fos, 4096);

        osformatln(&fos, "epochus %llu", step->epochus);
        osformatln(&fos, "dateus %llU", step->epochus);
        osprintln(&fos, "version " YKEYROLL_VERSION);
        osprint(&fos, "actions");

        if(step->keyroll_action != 0)
        {
            if(step->keyroll_action & Publish) // add commands
            {
                osprint(&fos, " publish");
            }
            if(step->keyroll_action & Activate)
            {
                osprint(&fos, " activate");
            }
            if(step->keyroll_action & Deactivate)
            {
                osprint(&fos, " deactivate");
            }
            if(step->keyroll_action & Unpublish) // delete commands
            {
                osprint(&fos, " unpublish");
            }
        }
        else
        {
            osprint(&fos, " none");
        }
        osprintln(&fos, "");

        {
            u8 *previous_end_result_text = bytearray_output_stream_buffer(&previous_end_result_os);
            u32 previous_end_result_size = bytearray_output_stream_size(&previous_end_result_os);
            output_stream_write(&fos, previous_end_result_text, previous_end_result_size);
            bytearray_output_stream_reset(&previous_end_result_os);
        }

        for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_del); ++i)
        {
            dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_del, i);
            if(dnskey_get_flags(key) == DNSKEY_FLAGS_ZSK)
            {
                osformat(&fos, "del K%{dnsname}+%03u+%05d.key ", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key));
                bytearray_output_stream_reset(&baos);
                dnskey_store_public_key_to_stream(key, &baos);
                osprint_base64(&fos, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos));
                osprintln(&fos, "");

#define NOTHING_TO_SEE_HERE_BASE64 "IyBub3RoaW5nIHRvIHNlZSBoZXJlCg=="

                osformatln(&fos, "del K%{dnsname}+%03u+%05d.private " NOTHING_TO_SEE_HERE_BASE64, dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key));
            }
            else
            {
                // the file is not supposed to be transferred : there is nothing to delete
            }
        }

        for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_add); ++i)
        {
            dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_add, i);

            if(dnskey_get_flags(key) == DNSKEY_FLAGS_ZSK)
            {
                osformat(&fos, "add K%{dnsname}+%03u+%05d.key ", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key));
                bytearray_output_stream_reset(&baos);
                dnskey_store_public_key_to_stream(key, &baos);
                osprint_base64(&fos, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos));
                osprintln(&fos, "");

                osformat(&fos, "add K%{dnsname}+%03u+%05d.private ", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key));
                bytearray_output_stream_reset(&baos);
                dnskey_store_private_key_to_stream(key, &baos);
                osprint_base64(&fos, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos));
                osprintln(&fos, "");

                osformatln(&fos, "debug tag=%i flags=%s created=%U publish=%U activate=%U deactivate=%U unpublish=%U",
                    dnskey_get_tag(key), ((dnskey_get_flags(key) == DNSKEY_FLAGS_KSK)?"KSK":"ZSK"),
                    dnskey_get_created_epoch(key), dnskey_get_publish_epoch(key),
                    dnskey_get_activate_epoch(key), dnskey_get_inactive_epoch(key),
                    dnskey_get_delete_epoch(key));
            }
            else
            {
                // store the private key separately

                dnssec_keystore_add_domain(keyroll->domain, keyroll->private_keys_path);

                if(FAIL(ret = dnssec_keystore_store_private_key(key)))
                {
                    log_err("could not store private key-signing key");
                    return ret;
                }

                if(FAIL(ret = dnssec_keystore_store_public_key(key)))
                {
                    log_err("could not store public key-signing key");
                    return ret;
                }
            }
        }

        bool has_changes = (ptr_vector_size(&step->dnskey_del) + ptr_vector_size(&step->dnskey_add)) > 0;

        if(has_changes)
        {
            // signatures will be cleared as soon as this happens (change(s) in the DNSKEY rrset)
/*
            // now the rrsig is held by the step

            for(int i = 0; i <= ptr_vector_last_index(&expected_rrsig); ++i)
            {
                dns_resource_record *rrsig = (dns_resource_record*)ptr_vector_get(&expected_rrsig, i);
                dns_resource_record_finalize(rrsig);
            }
*/
            ptr_vector_clear(&expected_rrsig);

            // the DNSKEY records to delete

            for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_del); ++i)
            {
                dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_del, i);

                int rdata_size = key->vtbl->dnssec_key_writerdata(key, rdata, PATH_MAX);
                rdata_desc dnskeyrdata = {TYPE_DNSKEY, rdata_size, rdata};

                osformatln(&fos, "update delete %{dnsname} %i %{typerdatadesc}", keyroll->domain, TTL, &dnskeyrdata);

                u32 key_hash = keyroll_key_hash(key);
                u32_node *node = u32_set_find(&current, key_hash);
                if(node != NULL)
                {
                    dnssec_key *node_key = (dnssec_key*)node->value;
                    dnskey_release(node_key);
                    u32_set_delete(&current, key_hash);
                }
            }

            // the DNSKEY records to add

            for(int i = 0; i <= ptr_vector_last_index(&step->dnskey_add); ++i)
            {
                dnssec_key *key = (dnssec_key*)ptr_vector_get(&step->dnskey_add, i);

                int rdata_size = key->vtbl->dnssec_key_writerdata(key, rdata, PATH_MAX);
                rdata_desc dnskeyrdata = {TYPE_DNSKEY, rdata_size, rdata};

                osformatln(&fos, "update add %{dnsname} %i %{typerdatadesc}", keyroll->domain, TTL, &dnskeyrdata);

                u32 key_hash = keyroll_key_hash(key);
                u32_node *node = u32_set_find(&current, key_hash);
                if(node == NULL)
                {
                    node = u32_set_insert(&current, key_hash);
                    node->value = key;
                    dnskey_acquire(key);
                }
            }

            // the RRSIG records to add

            {
                struct resource_record_view rrv;
                dnskey_signature ds;

                // the signature should cover the earliest key deletion
                // the signature should cover the earliest ksk deactivation

                dns_resource_record *rrsig;

                // build the set of records

                ptr_vector rrset;
                ptr_vector_init(&rrset);

                u32_set_iterator iter;
                u32_set_iterator_init(&current, &iter);
                while(u32_set_iterator_hasnext(&iter))
                {
                    u32_node *node = u32_set_iterator_next_node(&iter);
                    dnssec_key *key = (dnssec_key*)node->value;

                    int rdata_size = key->vtbl->dnssec_key_writerdata(key, rdata, PATH_MAX);
                    rdata_desc dnskeyrdata = {TYPE_DNSKEY, rdata_size, rdata};
                    osformatln(&fos, "endresult %{dnsname} %i %{typerdatadesc}", keyroll->domain, TTL, &dnskeyrdata);
                    osformatln(&previous_end_result_os, "expect %{dnsname} %i %{typerdatadesc}", keyroll->domain, TTL, &dnskeyrdata);

                    dns_resource_record *rr = dns_resource_record_new_instance();
                    dnskey_init_dns_resource_record(key, TTL, rr);

                    ptr_vector_append(&rrset, rr);
                }

                // for all active KSK, generate a signature

                u32_set_iterator_init(&current, &iter);
                while(u32_set_iterator_hasnext(&iter))
                {
                    u32_node *node = u32_set_iterator_next_node(&iter);
                    dnssec_key *key = (dnssec_key*)node->value;

                    if(dnskey_get_flags(key) == DNSKEY_FLAGS_KSK)
                    {
                        dns_resource_record_resource_record_view_init(&rrv);
                        dnskey_signature_init(&ds);
                        s32 from = (step->epochus / ONE_SECOND_US) - RRSIG_ANTEDATING;     // sign from the day before

                        log_debug("%{dnsname}: %llT signing DNSKEY RRSET with key %hu, inactive at %T (%T)",
                                  keyroll->domain, step->epochus, dnskey_get_tag(key),
                                  dnskey_get_inactive_epoch(key), next_signature_update_epoch);

                        if(dnskey_get_inactive_epoch(key) > next_signature_update_epoch)
                        {
                            log_debug("%{dnsname}: %llT key %hu is inactive at %T which is after the planned expiration time %T",
                                      keyroll->domain, step->epochus, dnskey_get_tag(key),
                                      dnskey_get_inactive_epoch(key), next_signature_update_epoch);
                        }

                        s32 to = MAX(dnskey_get_inactive_epoch(key), next_signature_update_epoch);

                        log_info("signing from %U to %U", from, to);

                        dnskey_signature_set_view(&ds, &rrv);
                        dnskey_signature_set_validity(&ds, from, to);
                        dnskey_signature_set_rrset_reference(&ds, &rrset);
                        ret = dnskey_signature_sign(&ds, key, (void**)&rrsig);
                        dnskey_signature_finalize(&ds);

                        if(FAIL(ret))
                        {
                            log_info("signature failed: %r", ret);
                            return ret;
                        }

                        osformatln(&fos, "update add %{dnszrr}", rrsig);

                        ptr_vector_append(&step->rrsig_add, rrsig);

                        ptr_vector_append(&expected_rrsig, rrsig);
                    }
                }

                for(int i = 0; i <= ptr_vector_last_index(&rrset); ++i)
                {
                    dns_resource_record *rr = (dns_resource_record*)ptr_vector_get(&rrset, i);
                    dns_resource_record_free(rr);
                }

                ptr_vector_destroy(&rrset);
            } // current set sub-block
        } // has changes
        else
        {
            u32_set_iterator iter;
            u32_set_iterator_init(&current, &iter);
            while(u32_set_iterator_hasnext(&iter))
            {
                u32_node *node = u32_set_iterator_next_node(&iter);
                dnssec_key *key = (dnssec_key*)node->value;

                int rdata_size = key->vtbl->dnssec_key_writerdata(key, rdata, PATH_MAX);
                rdata_desc dnskeyrdata = {TYPE_DNSKEY, rdata_size, rdata};

                osformatln(&fos, "endresult %{dnsname} %i %{typerdatadesc}", keyroll->domain, TTL, &dnskeyrdata);
                osformatln(&previous_end_result_os, "expect %{dnsname} %i %{typerdatadesc}", keyroll->domain, TTL, &dnskeyrdata);
            }
        }

        for(int i = 0; i <= ptr_vector_last_index(&expected_rrsig); ++i)
        {
            dns_resource_record *rrsig = (dns_resource_record*)ptr_vector_get(&expected_rrsig, i);
            osformatln(&fos, "endresult %{dnszrr}", rrsig);
            osformatln(&previous_end_result_os, "expect %{dnszrr}", rrsig);
        }

        output_stream_close(&fos);

        flushout();
    }

/*
    // now the rrsig is held by the step

    for(int i = 0; i <= ptr_vector_last_index(&expected_rrsig); ++i)
    {
        dns_resource_record *rrsig = (dns_resource_record*)ptr_vector_get(&expected_rrsig, i);
        dns_resource_record_finalize(rrsig);
    }
*/
    ptr_vector_destroy(&expected_rrsig);

    u32_set_callback_and_destroy(&current, keyroll_print_u32_set_destroy_callback);

    return ret;
}

/**
 *
 */

ya_result
keyroll_get_state_find_match_and_play(const keyroll_t *keyrollp, s64 now, const keyroll_step_t *current_step, const keyroll_step_t **matched_stepp)
{
    // check the expected set with the server
    // do a query for all DNSKEY + RRSIG and compare with the step

    ya_result ret = STOPPED_BY_APPLICATION_SHUTDOWN;

    u32 match_verify_try_count = 0;

    ptr_vector current_dnskey_rrsig_rr;
    ptr_vector_init_ex(&current_dnskey_rrsig_rr, 32);
    while(!dnscore_shuttingdown() && ISOK(ret = keyroll_dnskey_state_query(keyrollp, &current_dnskey_rrsig_rr)))
    {
        // current_dnskey_rrsig_rr contains the records currently on the server

        ya_result matched_expectations = keyroll_step_expects_matched(current_step, &current_dnskey_rrsig_rr);

        log_info("current step (%llU) expects to start from:", current_step->epochus);

        for(int i = 0; i <= ptr_vector_last_index(&current_step->expect); ++i)
        {
            log_info("%{dnszrr}", ptr_vector_get(&current_step->expect, i));
        }

        log_info("server (%{hostaddr}) has:", keyrollp->server);

        for(int i = 0; i <= ptr_vector_last_index(&current_dnskey_rrsig_rr); ++i)
        {
            log_info("%{dnszrr}", ptr_vector_get(&current_dnskey_rrsig_rr, i));
        }

        if(ISOK(matched_expectations))
        {
            log_debug("zone %{dnsname}: expectations are matched", current_step->keyroll->domain);

            keyroll_dnskey_state_destroy(&current_dnskey_rrsig_rr); // leads to an exit

            ret = keyroll_step_play(current_step, FALSE);

            if(matched_stepp != NULL)
            {
                *matched_stepp = current_step;
            }

            return ret;
        }
        else
        {
            log_warn("zone %{dnsname} expectations are NOT matched", current_step->keyroll->domain);

            bool nameserver_has_no_dnskey = (ptr_vector_last_index(&current_dnskey_rrsig_rr) < 0);

            if(nameserver_has_no_dnskey)
            {
                keyroll_dnskey_state_destroy(&current_dnskey_rrsig_rr); // leads to an exit

                // there are no keys on the server (and implicitely, some were expected)
                // so we start playing from the start until now

                keyroll_step_t *first_step;

                if(FAIL(ret = keyroll_play_first_step(keyrollp, now, &first_step)))
                {
                    return ret;
                }

                // now play all the steps until the one we are supposed to be currently in

                ret = keyroll_step_play_range(keyrollp, first_step->epochus + 1 , now);

                log_info("zone %{dnsname}: done replaying steps: %r", current_step->keyroll->domain, ret);

                return ret;
            }
            else
            {
                log_info("zone %{dnsname}: scanning for a match", current_step->keyroll->domain);

                keyroll_step_t* step = keyroll_step_scan_matching_expectations(keyrollp, &current_dnskey_rrsig_rr);

                keyroll_dnskey_state_destroy(&current_dnskey_rrsig_rr); // leads to an exit or loops

                if(step == NULL)
                {
                    log_info("zone %{dnsname}: no match found, looking for first step after %llU", current_step->keyroll->domain, now);

                    keyroll_step_t *first_step;

                    if(FAIL(ret = keyroll_play_first_step(keyrollp, now, &first_step)))
                    {
                        if(ret == MAKE_ERRNO_ERROR(EPERM))
                        {
                            log_err("zone %{dnsname}: failed to find step: %r (%i:%i)", current_step->keyroll->domain, ret, getuid(), getgid());
                        }
                        else
                        {
                            log_err("zone %{dnsname}: failed to play step: %r", current_step->keyroll->domain, ret);
                        }

                        ++match_verify_try_count;

                        if(ret == MAKE_DNSMSG_ERROR(RCODE_SERVFAIL))
                        {
                            log_err("%{dnsname}: server cannot apply the update at the moment (try %i/%i)", current_step->keyroll->domain, match_verify_try_count, current_step->keyroll->match_verify_retries);
                        }
                        else
                        {
                            log_err("%{dnsname}: could not find a match (try %i/%i)", current_step->keyroll->domain, match_verify_try_count, current_step->keyroll->match_verify_retries);
                        }

                        // 1 vs 1 => must do
                        if(match_verify_try_count <= current_step->keyroll->match_verify_retries)
                        {
                            if(!dnscore_shuttingdown())
                            {
                                usleep_ex(ONE_SECOND_US * current_step->keyroll->match_verify_retries_delay);
                            }

                            ptr_vector_init_ex(&current_dnskey_rrsig_rr, 32); // because the array was destroyed
                            ret = STOPPED_BY_APPLICATION_SHUTDOWN;
                            continue;
                        }
                        else
                        {
                            return ret;
                        }
                    }

                    step = first_step;
                }
                else
                {
                    log_info("zone %{dnsname}: match found at %llU", current_step->keyroll->domain, step->epochus);
                    keyroll_step_print(step);
                    log_info("--------------");
                }

                if(now >= step->epochus + 1)
                {
                    log_info("zone %{dnsname}: will play range from %llU until %llU", current_step->keyroll->domain, step->epochus + 1, now);

                    ret = keyroll_step_play_range(keyrollp, step->epochus + 1 , now);

                    log_info("zone %{dnsname}: done replaying steps: %r", current_step->keyroll->domain, ret);
                }
                else
                {
                    log_info("zone %{dnsname}: no range to replay", current_step->keyroll->domain);
                }

                // will end with a return ret;
            } // endif
        } // endif

        break;
    }

    return ret;
}

void
keyroll_set_dryrun_mode(bool enabled)
{
    keyroll_dryrun_mode = enabled;
}
