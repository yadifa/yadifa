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

#define REST_SERVER_C 1

#include "rest_server.h"
#include "config_settings.h"
#include "keyroll.h"

#include <dnscore/simple_http_server.h>
#include <dnscore/json.h>
#include <dnscore/config_settings.h>
#include <dnscore/parsing.h>

#define REST_SERVER_CONFIG_SECTION "rest-server"

extern int64_t           g_start_epoch;
extern const char *const g_mode;
extern config_t          g_config;
extern mutex_t           g_keyroll_state_mtx;
extern ptr_treemap_t     g_keyroll_state;

#define CONFIG_TYPE rest_server_config_t
CONFIG_BEGIN(rest_server_config_section_desc)
CONFIG_HOST_LIST(listen, "0.0.0.0 port 8080")
CONFIG_STRING(realm, "yakeyrolld")
CONFIG_U32_RANGE(nonce_duration_ms, "5000", 1, 300000)
CONFIG_U32_RANGE(rate_limit_ms, "1", 1, 300000)
CONFIG_BOOL(enabled, "0")
CONFIG_STRING_ARRAY(user, NULL, 1024)
CONFIG_END(rest_server_config_section_desc)

rest_server_config_t        g_rest_server_config;

static simple_rest_server_t srs = SIMPLE_REST_SERVER_UNINITIALISED;

static ya_result            config_rest_server_section_postprocess(struct config_section_descriptor_s *csd, config_error_t *cfgerr)
{
    (void)csd;
    (void)cfgerr;

    for(int_fast32_t i = 0; i <= ptr_vector_last_index(&g_rest_server_config.user); ++i)
    {
        char *user_token = ptr_vector_get(&g_rest_server_config.user, i);
        // formatln("http: user=%s", user_token);
        char *token = (char *)parse_next_char_equals(user_token, ':');
        if(*token == ':')
        {
            *token = '\0';
            ++token;
            http_user_account_add_ex(user_token, token);
        }
        else
        {
            formatln("invalid user token '%s'", user_token);
        }
    }

    http_user_account_realm_set(g_rest_server_config.realm);

    return SUCCESS;
}

ya_result config_register_rest_server(uint8_t priority)
{
    ptr_vector_init(&g_rest_server_config.user);
    ya_result                         ret = config_register_struct(REST_SERVER_CONFIG_SECTION, rest_server_config_section_desc, &g_rest_server_config, priority++);
    config_section_descriptor_t      *section_desc = config_section_get_descriptor(REST_SERVER_CONFIG_SECTION);
    config_section_descriptor_vtbl_s *vtbl = (config_section_descriptor_vtbl_s *)section_desc->vtbl;
    vtbl->postprocess = config_rest_server_section_postprocess;
    return ret;
}

static ya_result rest_server_health(const struct simple_rest_server_page *page, output_stream_t *os, const simple_rest_server_page_writer_args *args)
{
    (void)page;
    (void)args;

    static const char *const keyroll_status_name[3] = {"OK", "Error", "Reset"};

    http_header_code(os, 200);

    http_header_content_type_application_json(os);
    http_header_transfer_encoding_chunked(os);
    http_header_date_now(os);
    http_header_close(os);

    json_t json = json_object_new_instance();
    json_object_add_string(json, (const uint8_t *)"mode", (const uint8_t *)g_mode);
    json_t  system = json_object_new_instance();

    int64_t uptime = (timeus() - g_start_epoch) / 1000000;

    json_object_add_number_s64(system, (const uint8_t *)"uptime", uptime);
    json_object_add(json, (const uint8_t *)"system", system);

    json_t                keyrolls = json_object_new_instance();

    enum keyroll_status_t status = KEYROLL_STATUS_OK;

    mutex_lock(&g_keyroll_state_mtx);
    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&g_keyroll_state, &iter);
    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
        keyroll_state_t    *keyroll_status = (keyroll_state_t *)node->value;
        json_t              keyroll = json_object_new_instance();
        char                tmp[256];
        cstr_init_with_dnsname(tmp, keyroll_status->domain);
        json_object_add_ascii_string(keyroll, "domain", tmp);
        json_object_add_number_s64(keyroll, (const uint8_t *)"next-epoch-us", keyroll_status->next_operation);
        snformat(tmp, sizeof(tmp), "%llU", keyroll_status->next_operation);
        json_object_add_ascii_string(keyroll, "next-datetime", tmp);
        json_object_add_number_s64(keyroll, (const uint8_t *)"retries", keyroll_status->errors);
        json_object_add_number_s64(keyroll, (const uint8_t *)"retry-countdown", keyroll_status->retry_countdown);
        json_object_add_number_s64(keyroll, (const uint8_t *)"last-retry-epoch-us", keyroll_status->last_error_epoch);
        snformat(tmp, sizeof(tmp), "%llU", keyroll_status->last_error_epoch);
        json_object_add_ascii_string(keyroll, "last-retry-datetime", tmp);
        json_object_add_number_s64(keyroll, (const uint8_t *)"reinitialisations", keyroll_status->reinitialisations);
        json_object_add_number_s64(keyroll, (const uint8_t *)"last-reinitialisation-epoch-us", keyroll_status->last_reinitialisation_epoch);
        snformat(tmp, sizeof(tmp), "%llU", keyroll_status->last_reinitialisation_epoch);
        json_object_add_ascii_string(keyroll, "last-reinitialisation-datetime", tmp);
        json_object_add_ascii_string(keyroll, "state", keyroll_status_name[keyroll_status->status]);
        status = MAX(status, keyroll_status->status);
        json_object_add(keyrolls, (const uint8_t *)"keyroll", keyroll);
    }
    mutex_unlock(&g_keyroll_state_mtx);
    json_object_add(json, (const uint8_t *)"keyrolls", keyrolls);
    json_object_add_ascii_string(json, "status", keyroll_status_name[status]);

    char *answer = json_to_string(json);
    int   answer_size = strlen(answer);

    http_write_chunk(os, answer, answer_size);
    http_write_chunk_close(os);

    json_delete(json);

    free(answer);

    return SUCCESS;
}

static ya_result rest_server_info(const struct simple_rest_server_page *page, output_stream_t *os, const simple_rest_server_page_writer_args *args)
{
    (void)page;
    (void)args;

    http_header_code(os, 200);

    http_header_content_type_application_json(os);
    http_header_transfer_encoding_chunked(os);
    http_header_date_now(os);
    http_header_close(os);

    json_t json = json_object_new_instance();

    json_t application = json_object_new_instance();
    json_object_add_ascii_string(application, "name", "keyroll");
    json_object_add_ascii_string(application, "version,", YKEYROLL_VERSION);
    json_object_add(json, (const uint8_t *)"application", application);

    json_t build = json_object_new_instance();
    json_object_add_ascii_string(build, "buildDateTime", __DATE__ " " __TIME__);
    json_object_add(json, (const uint8_t *)"build", build);

    json_t settings = json_object_new_instance();

    json_t domains = json_array_new_instance();
    for(int_fast32_t i = 0; i <= ptr_vector_last_index(&g_config.domains); ++i)
    {
        const char *domain = ptr_vector_get(&g_config.domains, i);
        json_array_add_string(domains, (const uint8_t *)domain);
    }
    json_object_add(settings, (const uint8_t *)"domains", domains);

    json_object_add_ascii_string(settings, "configuration-file-path", g_config.configuration_file_path);
    json_object_add_ascii_string(settings, "log-path", g_config.log_path);
    json_object_add_ascii_string(settings, "keys-path", g_config.keys_path);
    json_object_add_ascii_string(settings, "plan-path", g_config.plan_path);
    json_object_add_ascii_string(settings, "pid-path", g_config.pid_path);
    json_object_add_ascii_string(settings, "pid-file", g_config.pid_file);
    json_object_add_ascii_string(settings, "generate-from", g_config.generate_from);
    json_object_add_ascii_string(settings, "generate-until", g_config.generate_until);
    json_object_add_ascii_string(settings, "policy-name", g_config.policy_name);

    char server_str[272];
    host_address_to_str(g_config.server, server_str, sizeof(server_str), HOST_ADDRESS_TO_STR_FULLPORT);
    json_object_add_ascii_string(settings, "server", server_str);

    json_object_add_number_s64(settings, (const uint8_t *)"uid", g_config.uid);
    json_object_add_number_s64(settings, (const uint8_t *)"gid", g_config.gid);
    json_object_add_number_s64(settings, (const uint8_t *)"timeout", g_config.timeout);
    json_object_add_number_s64(settings, (const uint8_t *)"ttl", g_config.ttl);

    json_object_add_number_s64(settings, (const uint8_t *)"update-apply-verify-retries", g_config.update_apply_verify_retries);
    json_object_add_number_s64(settings, (const uint8_t *)"update-apply-verify-retries-delay", g_config.update_apply_verify_retries_delay);

    json_object_add_number_s64(settings, (const uint8_t *)"match-verify-retries", g_config.match_verify_retries);
    json_object_add_number_s64(settings, (const uint8_t *)"match-verify-retries-delay", g_config.match_verify_retries_delay);

    json_object_add_number_s64(settings, (const uint8_t *)"roll-step-limit-override", g_config.roll_step_limit_override);

    json_object_add_boolean(settings, (const uint8_t *)"reset", g_config.reset);
    json_object_add_boolean(settings, (const uint8_t *)"purge", g_config.purge);
    json_object_add_boolean(settings, (const uint8_t *)"dryrun", g_config.dryrun);
    json_object_add_boolean(settings, (const uint8_t *)"wait-for-yadifad", g_config.wait_for_yadifad);
    json_object_add_boolean(settings, (const uint8_t *)"daemonise", g_config.daemonise);
    json_object_add_boolean(settings, (const uint8_t *)"print-plan", g_config.print_plan);
    json_object_add_boolean(settings, (const uint8_t *)"user-confirmation", g_config.user_confirmation);

    json_object_add(json, (const uint8_t *)"settings", settings);

    char *answer = json_to_string(json);
    int   answer_size = strlen(answer);

    http_write_chunk(os, answer, answer_size);
    http_write_chunk_close(os);

    json_delete(json);

    free(answer);

    return SUCCESS;
}

ya_result rest_server_init()
{
    ya_result        ret;

    struct addrinfo *addr = NULL;

    if(ISOK(ret = host_address2addrinfo(g_rest_server_config.listen, &addr)))
    {
        if(ISOK(ret = simple_rest_server_init(&srs, addr)))
        {
            simple_rest_server_page_register_ex(&srs, "health", rest_server_health, NULL, false, true);
            simple_rest_server_page_register_ex(&srs, "info", rest_server_info, NULL, true, true);
        }
    }
    return ret;
}

ya_result rest_server_start()
{
    ya_result ret;
    if(ISOK(ret = simple_rest_server_start(&srs)))
    {
    }
    return ret;
}

ya_result rest_server_stop()
{
    ya_result ret;

    if(ISOK(ret = simple_rest_server_stop(&srs)))
    {
    }
    return ret;
}

void rest_server_finalise() { simple_rest_server_finalize(&srs); }
