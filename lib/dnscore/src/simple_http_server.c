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

/**-----------------------------------------------------------------------------
 * @defgroup dnspacket DNS Messages
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore_config.h"

#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>

#if HAS_HTTPS
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#endif

#include "dnscore/fdtools.h"
#include "dnscore/ptr_vector.h"
#include "dnscore/logger.h"
#include "dnscore/config_cmdline.h"
#include "dnscore/config_settings.h"
#include "dnscore/pid.h"
#include "dnscore/service.h"
#include "dnscore/thread_pool.h"
#include "dnscore/cmdline.h"
#include "dnscore/tcp_io_stream.h"
#include "dnscore/ptr_treemap.h"
#include "dnscore/socket_server.h"
#include "dnscore/zalloc.h"
#include "dnscore/network.h"
#include "dnscore/bytearray_output_stream.h"
#include "dnscore/parsing.h"
#include "dnscore/pcg_basic.h"

#include "dnscore/simple_http_server.h"
#include "dnscore/base64.h"
#include "dnscore/digest.h"
#include "dnscore/base16.h"

#include "dnscore/uri.h"

#define SIMPLE_REST_SERVER_CLIENT_LINE_SIZE      4096
#define SIMPLE_REST_SERVER_CLIENT_LISTEN_BACKLOG 30

#define SRSTCLNT_TAG                             0x544e4c4354535253
#define SRSTPAGE_TAG                             0x4547415054535253

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

extern logger_handle_t *g_system_logger;
#define MODULE_MSG_HANDLE        g_system_logger

#define IP_NONCE_TIMEOUT_DEFAULT (ONE_SECOND_US * 5)
#define IP_RATE_TIMEOUT_DEFAULT  (ONE_SECOND_US * 1)

static const char  g_realm_default[] = "YADIFA";
static const char *g_realm = g_realm_default;

static int64_t     g_nonce_validity_time_us = IP_NONCE_TIMEOUT_DEFAULT;
static int64_t     g_rate_limit_delay_us = IP_RATE_TIMEOUT_DEFAULT;

struct simple_rest_server_client_s
{
    simple_rest_server_t *srs;
    socketaddress_t       sa;
    socklen_t             sa_len;
    int                   sockfd;
};

typedef struct simple_rest_server_client_s simple_rest_server_client_t;

struct http_user_account_s
{
    char   *name;
    char   *md5_name_realm_password;
    char   *nonce_token;
    int64_t nonce_token_epoch;
};

typedef struct http_user_account_s http_user_account_t;

struct http_authenticate_s
{
    char nonce[BASE64_ENCODED_SIZE(32) + 1]; // sha ts +
    // char *algorithm; MD5
};

static ptr_treemap_t http_user_account_map = {NULL, ptr_treemap_asciizp_node_compare};
static mutex_t       http_user_account_map_mtx = MUTEX_INITIALIZER;
static int64_t       g_nonce_timeout_us = ONE_SECOND_US * 300; // five minutes

static ptr_treemap_t ip_nonce_map = {NULL, ptr_treemap_socketaddress_node_compare};
static mutex_t       ip_nonce_map_mtx = MUTEX_INITIALIZER;

static ptr_treemap_t ip_rate_map = {NULL, ptr_treemap_socketaddress_node_compare};
static mutex_t       ip_rate_map_mtx = MUTEX_INITIALIZER;

/**
 *
 * realm
 *
 */

void http_user_account_realm_set(const char *realm)
{
    if(g_realm != g_realm_default)
    {
        free((char *)g_realm); // is a strdup(x)
    }
    if(realm != g_realm_default)
    {
        g_realm = strdup(realm);
    }
    else
    {
        g_realm = g_realm_default;
    }
}

const char *http_user_account_realm_get() { return g_realm; }

/**
 *
 * http_user_account
 *
 */

void http_user_account_add_ex(const char *name, const char *md5_name_realm_password)
{
    http_user_account_t *user_account;
    mutex_lock(&http_user_account_map_mtx);
    ptr_treemap_node_t *node = ptr_treemap_insert(&http_user_account_map, (char *)name);
    if(node->value == NULL)
    {
        ZALLOC_OBJECT_OR_DIE(user_account, http_user_account_t, GENERIC_TAG);
        user_account->name = strdup(name);
        user_account->md5_name_realm_password = strdup(md5_name_realm_password);

        node->key = user_account->name;
        node->value = user_account;
    }
    else
    {
        http_user_account_t *user_account = (http_user_account_t *)node->value;
        free(user_account->md5_name_realm_password);
        user_account->md5_name_realm_password = strdup(md5_name_realm_password);
    }
    mutex_unlock(&http_user_account_map_mtx);
}

ya_result http_user_authentication_token_compute(const char *name, const char *realm, const char *password, char *digest_text, size_t digest_text_size)
{
    if(digest_text_size >= MD5_DIGEST_LENGTH * 2 + 1)
    {
        digest_t ctx;
        uint8_t  digest[MD5_DIGEST_LENGTH];
        digest_md5_init(&ctx);
        char *name_realm_password;
        int   name_realm_password_len = asnformat(&name_realm_password, 1024, "%s:%s:%s", name, realm, password);
        digest_update(&ctx, name_realm_password, name_realm_password_len);
        digest_final_copy_bytes(&ctx, digest, sizeof(digest));
        base16_encode(digest, sizeof(digest), digest_text);
        digest_text[MD5_DIGEST_LENGTH * 2] = '\0';
        return SUCCESS;
    }
    else
    {
        return INVALID_ARGUMENT_ERROR;
    }
}

void http_user_account_add(const char *name, const char *realm, const char *password)
{
    char digest_text[MD5_DIGEST_LENGTH * 2 + 1];
    http_user_authentication_token_compute(name, realm, password, digest_text, sizeof(digest_text));
    http_user_account_add_ex(name, digest_text);
}

void http_user_account_del(const char *name)
{
    mutex_lock(&http_user_account_map_mtx);
    ptr_treemap_node_t *node = ptr_treemap_find(&http_user_account_map, (char *)name);
    if(node != NULL)
    {
        http_user_account_t *user_account = (http_user_account_t *)node->value;
        ptr_treemap_delete(&http_user_account_map, name);
        free(user_account->name);
        free(user_account->md5_name_realm_password);
        ZFREE_OBJECT(user_account);
    }
    mutex_unlock(&http_user_account_map_mtx);
}

const char *http_user_account_authentication_get(const char *name)
{
    char *authentication = NULL;
    mutex_lock(&http_user_account_map_mtx);
    ptr_treemap_node_t *node = ptr_treemap_find(&http_user_account_map, (char *)name);
    if(node != NULL)
    {
        http_user_account_t *user_account = (http_user_account_t *)node->value;
        authentication = user_account->md5_name_realm_password;
    }
    mutex_unlock(&http_user_account_map_mtx);
    return authentication;
}

const char *http_user_account_nonce_get(const char *name, int64_t *nonce_token_epochp)
{
    char *nonce_token = NULL;
    mutex_lock(&http_user_account_map_mtx);
    ptr_treemap_node_t *node = ptr_treemap_find(&http_user_account_map, (char *)name);
    if(node != NULL)
    {
        http_user_account_t *user_account = (http_user_account_t *)node->value;
        nonce_token = user_account->nonce_token;
        if(nonce_token_epochp != NULL)
        {
            *nonce_token_epochp = user_account->nonce_token_epoch;
        }
    }
    mutex_unlock(&http_user_account_map_mtx);
    return nonce_token;
}

bool http_user_account_nonce_set(const char *name, const char *nonce_token)
{
    bool ret = false;
    mutex_lock(&http_user_account_map_mtx);
    ptr_treemap_node_t *node = ptr_treemap_find(&http_user_account_map, (char *)name);
    if(node != NULL)
    {
        http_user_account_t *user_account = (http_user_account_t *)node->value;
        free(user_account->nonce_token);
        user_account->nonce_token = strdup(nonce_token);
        user_account->nonce_token_epoch = timeus();
        ret = true;
    }
    mutex_unlock(&http_user_account_map_mtx);
    return ret;
}

/**
 *
 * ip_nonce
 *
 */

struct ip_nonce_s
{
    socketaddress_t sa;
    int64_t         timestamp;
    char            nonce[];
};

typedef struct ip_nonce_s ip_nonce_t;

/**
 * Sets the time a nonce is valid after returning a 401.
 */

void ip_nonce_validity_time_set(int64_t microseconds)
{
    if(microseconds > 0)
    {
        g_nonce_validity_time_us = microseconds;
    }
}

int64_t     ip_nonce_limit_get() { return g_nonce_validity_time_us; }

static void ip_nonce_set(socketaddress_t *sa, const char *nonce)
{
    mutex_lock(&ip_nonce_map_mtx);
    ptr_treemap_node_t *node = ptr_treemap_insert(&ip_nonce_map, sa);
    free(node->value);
    size_t      nonce_len = strlen(nonce) + 1;
    ip_nonce_t *ip_nonce = (ip_nonce_t *)malloc(offsetof(ip_nonce_t, nonce) + nonce_len);
    ip_nonce->sa = *sa;
    ip_nonce->timestamp = timeus();
    memcpy(ip_nonce->nonce, nonce, nonce_len);
    node->key = &ip_nonce->sa;
    node->value = ip_nonce;
    mutex_unlock(&ip_nonce_map_mtx);
}

static void ip_nonce_delete_nolock(socketaddress_t *sa)
{
    ptr_treemap_node_t *node = ptr_treemap_find(&ip_nonce_map, sa);
    ip_nonce_t         *ip_nonce = (ip_nonce_t *)node->value;
    ptr_treemap_delete(&ip_nonce_map, sa);
    free(ip_nonce);
}

static void ip_nonce_clear(socketaddress_t *sa)
{
    mutex_lock(&ip_nonce_map_mtx);
    ip_nonce_delete_nolock(sa);

    ptr_vector_t to_delete;
    ptr_vector_init_empty(&to_delete);

    int64_t                now = timeus();

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&ip_nonce_map, &iter);
    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
        ip_nonce_t         *ip_nonce = (ip_nonce_t *)node->value;
        if(now - ip_nonce->timestamp > g_nonce_validity_time_us)
        {
            ptr_vector_append(&to_delete, node->key);
        }
    }

    for(int_fast32_t i = 0; i < ptr_vector_last_index(&to_delete); ++i)
    {
        socketaddress_t *sa = (socketaddress_t *)ptr_vector_get(&to_delete, i);
        ip_nonce_delete_nolock(sa);
    }

    mutex_unlock(&ip_nonce_map_mtx);
}

static bool ip_nonce_equals(socketaddress_t *sa, const char *nonce)
{
    bool ret;
    mutex_lock(&ip_nonce_map_mtx);
    ptr_treemap_node_t *node = ptr_treemap_find(&ip_nonce_map, sa);
    if(node != NULL)
    {
        ip_nonce_t *ip_nonce = (ip_nonce_t *)node->value;
        ret = strcmp(ip_nonce->nonce, nonce) == 0;
    }
    else
    {
        ret = false;
    }
    mutex_unlock(&ip_nonce_map_mtx);
    return ret;
}

/**
 *
 * ip_rate
 *
 */

struct ip_rate_s
{
    socketaddress_t sa;
    int64_t         timestamp;
};

typedef struct ip_rate_s ip_rate_t;

/**
 * Sets the minimum time between two queries from a given IP to any rate-limited page.
 */

void ip_rate_limit_set(int64_t microseconds)
{
    if(microseconds > 0)
    {
        g_rate_limit_delay_us = microseconds;
    }
}

int64_t ip_rate_limit_get() { return g_rate_limit_delay_us; }

/**
 * Tells if the specific address had recent activity.
 * Cleans-up the IP rate map.
 */

static bool ip_rate_is_limited(socketaddress_t *sa)
{
    bool    ret;
    int64_t now = timeus();
    mutex_lock(&ip_rate_map_mtx);
    ptr_treemap_node_t *node = ptr_treemap_insert(&ip_rate_map, sa);
    if(node->value != NULL)
    {
        ip_rate_t *ip_rate = (ip_rate_t *)node->value;
        // check the timestamp
        int64_t d = now - ip_rate->timestamp;
        ret = d < g_rate_limit_delay_us;
        if(!ret)
        {
            ip_rate->timestamp = now;
        }
    }
    else
    {
        ip_rate_t *ip_rate = (ip_rate_t *)malloc(sizeof(ip_rate_t));
        ip_rate->sa = *sa;
        ip_rate->timestamp = now;
        node->key = &ip_rate->sa;
        node->value = ip_rate;
        ret = false;
    }

    // cleanup

    ptr_vector_t to_delete;
    ptr_vector_init_empty(&to_delete);

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&ip_rate_map, &iter);
    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
        ip_rate_t          *ip_rate = (ip_rate_t *)node->value;
        if(now - ip_rate->timestamp > g_rate_limit_delay_us)
        {
            ptr_vector_append(&to_delete, ip_rate);
        }
    }

    for(int_fast32_t i = 0; i < ptr_vector_last_index(&to_delete); ++i)
    {
        ip_rate_t *ip_rate = (ip_rate_t *)ptr_vector_get(&to_delete, i);
        ptr_treemap_delete(&ip_rate_map, &ip_rate->sa);
        free(ip_rate);
    }

    mutex_unlock(&ip_rate_map_mtx);
    return ret;
}

/**
 */

void header_parameters_init(ptr_treemap_t *kv_set)
{
    kv_set->root = NULL;
    kv_set->compare = ptr_treemap_asciizp_node_compare;
}

static void header_parameters_free_callback(ptr_treemap_node_t *node) { free(node->key); }

void        header_parameters_free(ptr_treemap_t *kv_set) { ptr_treemap_callback_and_finalise(kv_set, header_parameters_free_callback); }

ya_result   header_parameters_decode(ptr_treemap_t *kv_set, const char *text)
{
    // name=["]value["], ...

    for(;;)
    {
        text = parse_skip_spaces(text);
        const char *name = text;
        text = parse_next_char_equals(text, '=');
        if(*text != '=')
        {
            header_parameters_free(kv_set);
            return PARSE_ERROR;
        }
        const char *name_limit = text;
        const char *value = parse_skip_spaces(text + 1);
        const char *value_limit;
        if(*value == '"')
        {
            ++value;
            value_limit = parse_next_char_equals(value, '"');
            if(*value_limit != '"')
            {
                header_parameters_free(kv_set);
                return PARSE_ERROR;
            }
            text = value_limit + 1;
        }
        else
        {
            value_limit = parse_next_char_equals(value + 1, ',');
            text = value_limit;
        }
        size_t name_len = name_limit - name;
        size_t value_len = value_limit - value;
        size_t name_value_len = name_len + 1 + value_len + 1;
        char  *name_value;
        MALLOC_OBJECT_ARRAY_OR_DIE(name_value, char, name_value_len, GENERIC_TAG);
        char *k = name_value;
        memcpy(k, name, name_len);
        name_value[name_len] = '\0';
        char *v = &name_value[name_len + 1];
        memcpy(v, value, value_len);
        v[value_len] = '\0';
        ptr_treemap_node_t *node = ptr_treemap_insert(kv_set, k);
        node->value = v;

        if((*text == '\0') || (*text == '\r') || (*text == '\n'))
        {
            break;
        }

        if(*text != ',')
        {
            header_parameters_free(kv_set);
            return PARSE_ERROR;
        }
        ++text;
    }

    return SUCCESS;
}

const char *header_parameters_get(ptr_treemap_t *kv_set, const char *name)
{
    ptr_treemap_node_t *node = ptr_treemap_find(kv_set, name);
    if(node != NULL)
    {
        return (const char *)node->value;
    }
    return NULL;
}

/**
 * Sends the "HTTP/1.1 [code]" header.
 * Where [code] is
 *   200 -- success
 *   or anything else from https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
 * @param os
 * @param code the
 * @return
 */

ya_result http_header_code(output_stream_t *os, int code)
{
    ya_result ret;

    if(ISOK(ret = output_stream_write_fully(os, "HTTP/1.1 ", 9)))
    {
        if(ISOK(ret = osformat(os, "%i", code)))
        {
            ret = output_stream_write_fully(os, "\r\n", 2);
        }
    }

    return ret;
}

void http_authenticate_set_nonce(struct http_authenticate_s *authenticate)
{
    uint64_t ts = timeus() * 0x100010001ULL;
    uint8_t  nonce[32];
    SET_U64_AT(nonce[0], ts);
    for(size_t i = 8; i < sizeof(nonce); i += 4)
    {
        SET_U32_AT(nonce[i], pcg32_random());
    }
    uint32_t len = base64_encode(nonce, sizeof(nonce), &authenticate->nonce[0]);
    authenticate->nonce[len] = '\0';
}

static void http_authenticate(output_stream_t *os, simple_rest_server_client_t *client)
{
    struct http_authenticate_s authenticate;
    http_authenticate_set_nonce(&authenticate);
    ip_nonce_set(&client->sa, authenticate.nonce);
    osformat(os, "WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\", qpop=\"auth\"\r\n", g_realm, authenticate.nonce);
}

static ya_result http_authorization(const char *authorisation, simple_rest_server_client_t *client)
{
    ptr_treemap_t kv_set;
    ya_result     ret;

    const char   *parameters = parse_next_blank(authorisation);
    if(memcmp(authorisation, "Digest", parameters - authorisation) != 0)
    {
        return PARSE_ERROR;
    }

    header_parameters_init(&kv_set);

    if(ISOK(ret = header_parameters_decode(&kv_set, parameters)))
    {
        const char *response = header_parameters_get(&kv_set, "response");

        if((response == NULL) || (strlen(response) != MD5_DIGEST_LENGTH * 2))
        {
            header_parameters_free(&kv_set);
            return INVALID_STATE_ERROR;
        }

        const char *username = header_parameters_get(&kv_set, "username");

        if(username == NULL)
        {
            header_parameters_free(&kv_set);
            return INVALID_STATE_ERROR;
        }

        const char *a1_hex = http_user_account_authentication_get(username);

        if(a1_hex == NULL)
        {
            header_parameters_free(&kv_set);
            return INVALID_STATE_ERROR;
        }

        const char *nonce = header_parameters_get(&kv_set, "nonce");

        if(nonce == NULL)
        {
            header_parameters_free(&kv_set);
            return INVALID_STATE_ERROR;
        }

        log_debug("nonce=%s", nonce);

        bool        nonce_valid = false;

        int64_t     expected_nonce_epoch;
        const char *expected_nonce = http_user_account_nonce_get(username, &expected_nonce_epoch);
        if(expected_nonce != NULL)
        {
            log_debug("expected_nonce=%s", expected_nonce);

            // differs or is too old

            nonce_valid = ((strcmp(expected_nonce, nonce) == 0) && ((expected_nonce_epoch - timeus()) > g_nonce_timeout_us));
        }
        // else no expected nonce (a.k.a nonce not valid)

        if(!nonce_valid)
        {
            log_debug("%{sockaddr} nonce is not valid", &client->sa);

            // no nonce set for this account
            if(ip_nonce_equals(&client->sa, nonce))
            {
                log_debug("%{sockaddr} nonce matched", &client->sa);
                // all good
                ip_nonce_clear(&client->sa);
            }
            else
            {
                log_debug("%{sockaddr} nonce not matched", &client->sa);
                header_parameters_free(&kv_set);
                return INVALID_STATE_ERROR;
            }
        }

        const char *realm = header_parameters_get(&kv_set, "realm");
        const char *uri = header_parameters_get(&kv_set, "uri");
        const char *pop = header_parameters_get(&kv_set, "pop");

        const char *cnonce = NULL;
        const char *nc = NULL;

        if((realm != NULL) && (nonce != NULL) && (uri != NULL))
        {
            if(pop != NULL)
            {
                log_debug("http: pop != NULL");

                cnonce = header_parameters_get(&kv_set, "cnonce");
                nc = header_parameters_get(&kv_set, "nc");

                if((nc != NULL) && (cnonce != NULL))
                {
                    header_parameters_free(&kv_set);
                    return INVALID_STATE_ERROR;
                }
            }

            char    *a2_text;
            char    *text;

            digest_t ctx;

            uint8_t  a2[MD5_DIGEST_LENGTH];

            char     a2_hex[MD5_DIGEST_LENGTH * 2];

            char     expected_digest[MD5_DIGEST_LENGTH];

            asnformat(&a2_text, 1024, "GET:%s", uri);

            digest_md5_init(&ctx);
            digest_update(&ctx, a2_text, strlen(a2_text));
            digest_final_copy_bytes(&ctx, a2, sizeof(a2));
            digest_final(&ctx);

            free(a2_text);

            base16_encode_lc(a2, sizeof(a2), a2_hex);

            if(pop != NULL)
            {
                asnformat(&text, 1024, "%s:%s:%s:%s", nonce, nc, cnonce,
                          pop); // cnonce & nc are always initialised if pop != NULL
            }
            else
            {
                asnformat(&text, 1024, ":%s:", nonce);
            }

            digest_md5_init(&ctx);
            digest_update(&ctx, a1_hex, strlen(a1_hex));
            digest_update(&ctx, text, strlen(text));
            digest_update(&ctx, a2_hex, sizeof(a2_hex));
            digest_final_copy_bytes(&ctx, expected_digest, sizeof(expected_digest));
            digest_final(&ctx);

            free(text);

            // compare the expected digest to the response

            uint8_t response_text[MD5_DIGEST_LENGTH];

            ret = base16_decode(response, strlen(response), response_text);

            if(FAIL(ret))
            {
                header_parameters_free(&kv_set);
                return INVALID_STATE_ERROR;
            }

            ret = memcmp(response_text, expected_digest, MD5_DIGEST_LENGTH);

            if(ret == 0)
            {
                if(expected_nonce == NULL)
                {
                    http_user_account_nonce_set(username, nonce);
                }
                return SUCCESS;
            }
            else
            {
                return INVALID_STATE_ERROR;
            }
        }
        else
        {
            ret = INVALID_STATE_ERROR;
        }
    }

    header_parameters_free(&kv_set);

    return ret;
}

/**
 * Sends a header field.
 *
 * name: value\r\n
 *
 * @param os
 * @param name
 * @param name_len
 * @param value
 * @param value_len
 * @return
 */

ya_result http_header_field(output_stream_t *os, const char *name, size_t name_len, const char *value, size_t value_len)
{
    ya_result ret;

    if(ISOK(ret = output_stream_write_fully(os, name, name_len)))
    {
        if(ISOK(ret = output_stream_write_fully(os, ": ", 2)))
        {
            if(ISOK(ret = output_stream_write_fully(os, value, value_len)))
            {
                ret = output_stream_write_fully(os, "\r\n", 2);
            }
        }
    }

    return ret;
}

/**
 * Sends the host header field.
 *
 * @param os
 * @param host
 * @param host_len
 * @return
 */

ya_result http_header_host(output_stream_t *os, const char *host, size_t host_len)
{
    ya_result ret = http_header_field(os, "Host", 4, host, host_len);

    return ret;
}

/**
 * Sends the Content-Type header field.
 *
 * @param os
 * @param content_type
 * @param content_type_len
 * @return
 */

ya_result http_header_content_type(output_stream_t *os, const char *content_type, size_t content_type_len)
{
    ya_result ret = http_header_field(os, "Content-Type", 12, content_type, content_type_len);

    return ret;
}

/**
 * Sends the application/octet-stream Content-Type header field.
 *
 * @param os
 * @return
 */

ya_result http_header_content_type_application_octet_stream(output_stream_t *os)
{
    ya_result ret = http_header_content_type(os, "application/octet-stream", 24);

    return ret;
}

/**
 * Sends the application/json Content-Type header field.
 *
 * @param os
 * @return
 */

ya_result http_header_content_type_application_json(output_stream_t *os)
{
    ya_result ret = http_header_content_type(os, "application/json", 16);

    return ret;
}

/**
 * Sends the text/html;charset=UTF-8 Content-Type header field.
 *
 * @param os
 * @return
 */

ya_result http_header_content_type_text_html_utf8(output_stream_t *os)
{
    ya_result ret = http_header_content_type(os, "text/html;charset=UTF-8", 23);

    return ret;
}

/**
 * Sends the Transfer-Encoding header field.
 *
 * @param os
 * @param transfer_encoding
 * @param transfer_encoding_len
 * @return
 */

ya_result http_header_transfer_encoding(output_stream_t *os, const char *transfer_encoding, size_t transfer_encoding_len)
{
    ya_result ret = http_header_field(os, "Transfer-Encoding", 17, transfer_encoding, transfer_encoding_len);

    return ret;
}

/**
 * Sends Transfer-Encoding as "chunked".
 *
 * @param os
 * @return
 */

ya_result http_header_transfer_encoding_chunked(output_stream_t *os)
{
    ya_result ret = http_header_transfer_encoding(os, "chunked", 7);

    return ret;
}

/**
 * Sends the Content-Length field.
 *
 * @param os
 * @param length
 * @return
 */

ya_result http_header_content_length(output_stream_t *os, size_t length)
{
    char      length_as_text[16];
    ya_result n = snformat(length_as_text, sizeof(length_as_text), "%llu", length);
    ya_result ret = http_header_field(os, "Content-Length", 14, length_as_text, n);

    return ret;
}

/**
 * Sends the Date header field.
 *
 * @param os
 * @param date
 * @param date_len
 * @return
 */

ya_result http_header_date(output_stream_t *os, const char *date, size_t date_len)
{
    ya_result ret = http_header_field(os, "Date", 4, date, date_len);

    return ret;
}

/**
 * Sends the current date in RFC5322 format.
 *
 * @param os
 * @return
 */

ya_result http_header_date_now(output_stream_t *os)
{
    char      date_buffer[32];

    ya_result date_buffer_len = time_epoch_as_rfc5322(time(NULL), date_buffer, sizeof(date_buffer)); // only fails if the buffer is < 29 bytes long

    ya_result ret = http_header_date(os, date_buffer, date_buffer_len);

    return ret;
}

/**
 * Closes the header.
 *
 * @param os
 * @return
 */

ya_result http_header_close(output_stream_t *os)
{
    ya_result ret = output_stream_write_fully(os, "\r\n", 2);

    return ret;
}

/**
 * Sends a chunk length (Transfer-Encoding: chunked)
 *
 * MUST be followed by the announced amount of bytes, then
 * http_write_chunk_end(os) must be called
 *
 * @param os
 * @param data
 * @param size
 * @return
 */

ya_result http_write_chunk_begin(output_stream_t *os, size_t size)
{
    ya_result ret;

    ret = osformat(os, "%llx\r\n", size);

    return ret;
}

/**
 * Sends a chunk (Transfer-Encoding: chunked)
 *
 * Ends a block started with the http_write_chunk_begin() call
 * Note that the last chunk is sent using http_write_chunk_close(os)
 *
 * @param os
 * @param data
 * @param size
 * @return
 */

ya_result http_write_chunk_end(output_stream_t *os)
{
    ya_result ret;

    ret = output_stream_write_fully(os, "\r\n", 2);

    return ret;
}

/**
 * Sends a chunk (Transfer-Encoding: chunked)
 *
 * Note that the last chunk is sent using http_write_chunk_close(os)
 *
 * @param os
 * @param data
 * @param size
 * @return
 */

ya_result http_write_chunk(output_stream_t *os, const void *data, size_t size)
{
    ya_result ret;

    if(ISOK(ret = osformat(os, "%llx\r\n", (int64_t)size)))
    {
        if(size > 0)
        {
            if(ISOK(ret = output_stream_write_fully(os, data, size)))
            {
                ret = output_stream_write_fully(os, "\r\n", 2);
            }
        }
    }

    return ret;
}

/**
 * Sends a chunk terminator
 *
 * @param os
 * @return
 */

ya_result http_write_chunk_close(output_stream_t *os)
{
    ya_result ret = output_stream_write_fully(os, "0\r\n\r\n", 5);

    return ret;
}

/**
 * Sends content.
 *
 * The size must match Content-Length
 *
 * @param os
 * @param data
 * @param size
 * @return
 */

ya_result http_write_content(output_stream_t *os, const void *data, size_t size)
{
    ya_result ret = output_stream_write_fully(os, data, size);

    return ret;
}

static simple_rest_server_client_t *simple_rest_server_client_new_instance(simple_rest_server_t *srs)
{
    simple_rest_server_client_t *client;

    ZALLOC_OBJECT_OR_DIE(client, simple_rest_server_client_t, SRSTCLNT_TAG);
    client->srs = srs;
    client->sa_len = sizeof(client->sa);
    client->sockfd = -1;

    mutex_lock(&srs->mtx);
    ++srs->client_current_count;
    mutex_unlock(&srs->mtx);

    return client;
}

static void simple_rest_server_client_reset(simple_rest_server_client_t *client)
{
    client->sa_len = sizeof(client->sa);
    client->sockfd = -1;
}

static void simple_rest_server_client_delete(simple_rest_server_client_t *client)
{
    if(client != NULL)
    {
        mutex_lock(&client->srs->mtx);
        --client->srs->client_current_count;
        cond_notify(&client->srs->cond);
        mutex_unlock(&client->srs->mtx);

        socketclose_ex(client->sockfd);
        ZFREE_OBJECT(client);
    }
}

static int simple_rest_server_main(struct service_worker_s *worker);

ya_result  simple_rest_server_init(simple_rest_server_t *srs, struct addrinfo *addr)
{
    static const int           on = 1;

    socket_server_opensocket_t socket;
    ya_result                  ret;

    if(FAIL(ret = socket_server_opensocket_init(&socket, addr, SOCK_STREAM)))
    {
        return ret;
    }

    socket_server_opensocket_setopt(&socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#if defined(SO_REUSEPORT)
    socket_server_opensocket_setopt(&socket, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif

    int sockfd = socket_server_opensocket_open(&socket);

    if(FAIL(sockfd))
    {
        return sockfd;
    }

    mutex_init(&srs->mtx);
    cond_init(&srs->cond);

    ptr_treemap_init(&srs->path_page_set);
    srs->path_page_set.compare = ptr_treemap_asciizp_node_compare;

    srs->thread_pool = NULL;
    static struct service_s s = UNINITIALIZED_SERVICE;
    srs->service = s;

    service_init(&srs->service, simple_rest_server_main, "rest");
    service_args_set(&srs->service, srs);

    srs->client_current_count = 0;

    srs->sockfd = sockfd;

    return SUCCESS;
}

static simple_rest_server_page *simple_rest_server_page_new_instance(const char *path, simple_rest_server_page_writer *page_writer, void *page_private)
{
    simple_rest_server_page *page;

    ZALLOC_OBJECT_OR_DIE(page, simple_rest_server_page, SRSTPAGE_TAG);
    page->path = strdup(path);
    page->writer = page_writer;
    page->private = page_private;
    page->rc = 1;
    return page;
}

static void simple_rest_server_page_delete(simple_rest_server_page *page)
{
    if(page != NULL)
    {
        free(page->path);
        ZFREE_OBJECT(page);
    }
}
static void simple_rest_server_page_acquire_nolock(simple_rest_server_t *srs, simple_rest_server_page *page)
{
    (void)srs;
    ++page->rc;
}
#if UNUSED_DONT_REMOVE_YET
static void simple_rest_server_page_acquire(simple_rest_server *srs, simple_rest_server_page *page)
{
    mutex_lock(&srs->mtx);
    simple_rest_server_page_acquire_nolock(srs, page);
    mutex_unlock(&srs->mtx);
}
#endif
static void simple_rest_server_page_release(simple_rest_server_t *srs, simple_rest_server_page *page)
{
    mutex_lock(&srs->mtx);

    if(--page->rc == 0)
    {
        ptr_treemap_delete(&srs->path_page_set, page->path);

        mutex_unlock(&srs->mtx);

        simple_rest_server_page_delete(page);
    }
    else
    {
        mutex_unlock(&srs->mtx);
    }
}

static ya_result simple_rest_server_page_release_with_path(simple_rest_server_t *srs, const char *path)
{
    simple_rest_server_page *page;

    mutex_lock(&srs->mtx);

    ptr_treemap_node_t *node = ptr_treemap_find(&srs->path_page_set, path);

    if((node != NULL) && (node->value != NULL))
    {
        page = (simple_rest_server_page *)node->value;

        if(--page->rc == 0)
        {
            ptr_treemap_delete(&srs->path_page_set, path);

            mutex_unlock(&srs->mtx);

            simple_rest_server_page_delete(page);
        }
        else
        {
            mutex_unlock(&srs->mtx);
        }

        return SUCCESS;
    }
    else
    {
        return ERROR;
    }
}

ya_result simple_rest_server_page_register_ex(simple_rest_server_t *srs, const char *path, simple_rest_server_page_writer *page_writer, void *page_private, bool access_protected, bool rate_limited)
{
    simple_rest_server_page *page = simple_rest_server_page_new_instance(path, page_writer, page_private);
    page->access_protected = access_protected;
    page->rate_limited = rate_limited;

    bool inserted = false;

    mutex_lock(&srs->mtx);
    ptr_treemap_node_t *node = ptr_treemap_insert(&srs->path_page_set, page->path);
    if(node->value == NULL)
    {
        node->value = page;
        inserted = true;
    }
    mutex_unlock(&srs->mtx);

    if(inserted)
    {
        return SUCCESS;
    }
    else
    {
        simple_rest_server_page_delete(page);

        return ERROR;
    }
}

ya_result simple_rest_server_page_register(simple_rest_server_t *srs, const char *path, simple_rest_server_page_writer *page_writer, void *page_private)
{
    ya_result ret = simple_rest_server_page_register_ex(srs, path, page_writer, page_private, false, false);
    return ret;
}

ya_result simple_rest_server_page_unregister(simple_rest_server_t *srs, const char *path)
{
    ya_result ret = simple_rest_server_page_release_with_path(srs, path);

    return ret;
}

static void simple_rest_server_destroy_callback(ptr_treemap_node_t *node)
{
    if(node->value != NULL)
    {
        simple_rest_server_page *page = (simple_rest_server_page *)node->value;
        simple_rest_server_page_delete(page);
    }
}

void simple_rest_server_finalize(simple_rest_server_t *srs)
{
    service_stop(&srs->service);
    service_wait(&srs->service);

    mutex_lock(&srs->mtx);
    ptr_treemap_callback_and_finalise(&srs->path_page_set, simple_rest_server_destroy_callback);
    mutex_unlock(&srs->mtx);

    cond_finalize(&srs->cond);
    mutex_destroy(&srs->mtx);

    socketclose_ex(srs->sockfd);

    srs->sockfd = -1;
}

void simple_rest_server_threadpool_set(simple_rest_server_t *srs, struct thread_pool_s *tp)
{
    mutex_lock(&srs->mtx);
    srs->thread_pool = tp;
    mutex_unlock(&srs->mtx);
}

struct thread_pool_s *simple_rest_server_threadpool_get(simple_rest_server_t *srs)
{
    mutex_lock(&srs->mtx);
    struct thread_pool_s *tp = srs->thread_pool;
    mutex_unlock(&srs->mtx);

    return tp;
}

ya_result simple_rest_server_start(simple_rest_server_t *srs)
{
    ya_result ret = service_start(&srs->service);
    return ret;
}

ya_result simple_rest_server_stop(simple_rest_server_t *srs)
{
    ya_result ret = service_stop(&srs->service);
    return ret;
}

/**
 * Gets the HTTP header field of the query
 *
 * @param args
 * @param key
 *
 * @return the value for the key
 */

const char *simple_rest_server_page_writer_args_get_header_field(const simple_rest_server_page_writer_args *args, const char *key)
{
    ptr_treemap_node_t *node = ptr_treemap_find(&args->header_name_value_set, key);
    if(node != NULL && node->value != NULL)
    {
        return (const char *)node->value;
    }
    else
    {
        return NULL;
    }
}

/**
 * Gets the HTTP URI field of the query
 *
 * @param args
 * @param key
 *
 * @return the value for the key
 */

const char *simple_rest_server_page_writer_args_get_uri_arg(const simple_rest_server_page_writer_args *args, const char *key)
{
    ptr_treemap_node_t *node = ptr_treemap_find(&args->uri_name_value_set, key);
    if(node != NULL && node->value != NULL)
    {
        return (const char *)node->value;
    }
    else
    {
        return NULL;
    }
}

/**
 * Gets the HTTP URI field of the query
 *
 * @param args
 * @param key
 * @param default_value
 *
 * @return the value for the key or default if there was no value
 */

const char *simple_rest_server_page_writer_args_get_uri_arg_with_default(const simple_rest_server_page_writer_args *args, const char *key, const char *default_value)
{
    const char *value = simple_rest_server_page_writer_args_get_uri_arg(args, key);
    if(value == NULL)
    {
        value = default_value;
    }
    return value;
}

/**
 * Gets the HTTP URI field of the query and convert it to an integer
 *
 * @param args
 * @param key
 * @param valuep a pointer to an int64_t that will contain the value
 *
 * @return SUCCESS if the value has been properly parsed, otherwise an error code
 */

ya_result simple_rest_server_page_writer_args_get_uri_int_arg(const simple_rest_server_page_writer_args *args, const char *key, int64_t *valuep)
{
    ptr_treemap_node_t *node = ptr_treemap_find(&args->uri_name_value_set, key);
    if(node != NULL && node->value != NULL)
    {
        const char *value_text = (const char *)node->value;
        char       *end_ptr = NULL;
        long long   value = strtoll(value_text, &end_ptr, 10);
        int         err = errno;
        if(end_ptr > value_text)
        {
            if(valuep != NULL)
            {
                *valuep = value;
            }

            if(err != ERANGE)
            {
                return SUCCESS;
            }
            else
            {
                return MAKE_ERRNO_ERROR(err);
            }
        }
        else
        {
            return ERROR;
        }
    }
    else
    {
        return ERROR;
    }
}

/**
 * Gets the HTTP URI field of the query and convert it to an integer
 *
 * @param args
 * @param key
 * @param valuep a pointer to an int64_t that will contain the value
 *
 */

void simple_rest_server_page_writer_args_get_uri_int_arg_with_default(const simple_rest_server_page_writer_args *args, const char *key, int64_t *valuep, int64_t default_value)
{
    ya_result ret;
    ret = simple_rest_server_page_writer_args_get_uri_int_arg(args, key, valuep);
    if(FAIL(ret))
    {
        if(valuep != NULL)
        {
            *valuep = default_value;
        }
    }
}

static ya_result simple_rest_server_client_answer_uri(void *args, const char *name, const char *value)
{
    simple_rest_server_page_writer_args *srspwa = (simple_rest_server_page_writer_args *)args;

    if(name != NULL)
    {
        ptr_treemap_t      *uri_parameters_set = (ptr_treemap_t *)&srspwa->uri_name_value_set;
        ptr_treemap_node_t *node = ptr_treemap_insert(uri_parameters_set, (void *)name);
        if(node->value == NULL)
        {
            node->key = strdup(name);
            node->value = strdup(value);
        }
    }
    else
    {
        srspwa->path = strdup(value);
    }
    return SUCCESS;
}

static void simple_rest_server_client_answer_destroy_callback(ptr_treemap_node_t *node)
{
    if(node->value != NULL)
    {
        free(node->key);
        free(node->value);
    }
}

static bool simple_rest_server_client_return_page(simple_rest_server_page *page, output_stream_t *os, simple_rest_server_page_writer_args *args, simple_rest_server_client_t *client)
{
    bool rate_limited = page->rate_limited && ip_rate_is_limited(&client->sa);
    if(!rate_limited)
    {
        page->writer(page, os, args);
    }
    else
    {
        // do nothing
    }
    return rate_limited;
}

static void simple_rest_server_client_answer(simple_rest_server_client_t *client)
{
    input_stream_t                      is;
    output_stream_t                     os;
    simple_rest_server_page            *page = NULL;
    simple_rest_server_page_writer_args args;

    ya_result                           ret;
    int                                 line_index;

    char                                line[SIMPLE_REST_SERVER_CLIENT_LINE_SIZE];

    // read the input

    fd_input_stream_attach(&is, client->sockfd);
    fd_output_stream_attach_noclose(&os, client->sockfd); // we don't want to close the file descriptor twice

    ptr_treemap_init(&args.uri_name_value_set);
    args.uri_name_value_set.compare = ptr_treemap_asciizp_node_compare;
    ptr_treemap_init(&args.header_name_value_set);
    args.header_name_value_set.compare = ptr_treemap_asciizp_node_compare;

    for(line_index = 0;; ++line_index)
    {
        if((ret = input_stream_read_line(&is, line, sizeof(line))) <= 0)
        {
            // unexpected eof
            log_err("http: unexpected eof");
            break;
        }

        --ret;

        while((ret >= 0) && (line[ret] <= ' '))
        {
            --ret;
        }

        ++ret;

        if(ret == 0)
        {
            // details have been gathered, now answer

            if(page != NULL)
            {
                if(page->access_protected)
                {
                    ptr_treemap_node_t *node = ptr_treemap_find(&args.header_name_value_set, "Authorization");
                    if(node != NULL)
                    {
                        // verify the auth
                        ret = http_authorization((char *)node->value, client);
                        if(ret == SUCCESS)
                        {
                            simple_rest_server_client_return_page(page, &os, &args, client);
                        }
                        else // if((ret == INVALID_STATE_ERROR) || (ret == PARSE_ERROR))
                        {
                            http_header_code(&os, 401);
                            http_authenticate(&os, client);
                            http_header_close(&os);
                            // http_write_chunk(&os, NULL, 0);
                            // http_write_chunk_close(&os);
                        }
                    }
                    else
                    {
                        // ask for an auth

                        http_header_code(&os, 401);
                        http_authenticate(&os, client);
                        http_header_close(&os);
                        // http_write_chunk(&os, NULL, 0);
                        // http_write_chunk_close(&os);
                    }
                }
                else
                {
                    simple_rest_server_client_return_page(page, &os, &args, client);
                }
                break;
            }
        }

        line[ret] = '\0';

        log_debug("http: parsing [%i] '%s'", line_index, line);

        // begins with 'GET ' ?
        // ends with ' HTTP/1.1' ?

        if(line_index == 0)
        {
            if((ret >= 9) && (memcmp(line, "GET ", 4) == 0) && (memcmp(&line[ret - 9], " HTTP/1.1", 9) == 0))
            {
                ya_result uri_err = uri_path_decode(&line[4], &line[ret - 9], simple_rest_server_client_answer_uri, &args);

                if(FAIL(uri_err))
                {
                    line[ret - 9] = '\0';

                    log_err("http: could not parse uri '%s'", &line[4]);

                    break;
                }

                // early cut: check if the page is registered

                mutex_lock(&client->srs->mtx);
                const char *path = args.path;

                while(*path == '/')
                {
                    ++path;
                }

                // get the page

                ptr_treemap_node_t *node = ptr_treemap_find(&client->srs->path_page_set, path);

                if((node != NULL) && (node->value != NULL))
                {
                    page = (simple_rest_server_page *)node->value;
                    simple_rest_server_page_acquire_nolock(client->srs, page);
                    mutex_unlock(&client->srs->mtx);
                }
                else
                {
                    static const char error_404[] = "<html><body><h0>404 not found.</h0></body></html>";

                    mutex_unlock(&client->srs->mtx);

                    http_header_code(&os, 404);
                    http_header_host(&os, "localhost", 9);
                    http_header_date_now(&os);
                    http_header_content_length(&os, sizeof(error_404) - 1);
                    http_header_close(&os);
                    http_write_content(&os, error_404, sizeof(error_404) - 1);

                    log_err("http: '%s': path not found", args.path);

                    break;
                }
            }
            else
            {
                log_err("http: query '%s' not supported", line);
                break;
            }
        }
        else
        {
            char *name_end = strchr(line, ':');

            if(name_end == NULL)
            {
                log_err("http: cannot parse '%s'", line);
                break;
            }

            *name_end++ = '\0';

            const char         *name = line;
            const char         *value = parse_skip_spaces(name_end);

            ptr_treemap_node_t *node = ptr_treemap_insert(&args.header_name_value_set, (void *)name);
            if(node->value == NULL)
            {
                node->key = strdup(name);
                node->value = strdup(value);

                log_debug("http: key='%s' value='%s'", node->key, node->value);
            }
        }
    }

    ptr_treemap_callback_and_finalise(&args.uri_name_value_set, simple_rest_server_client_answer_destroy_callback);
    ptr_treemap_callback_and_finalise(&args.header_name_value_set, simple_rest_server_client_answer_destroy_callback);

    if(page != NULL)
    {
        simple_rest_server_page_release(client->srs, page);
    }

    output_stream_close(&os);
    input_stream_close(&is);
}

static void simple_rest_server_client_answer_thread(void *client_parm)
{
    simple_rest_server_client_t *client = (simple_rest_server_client_t *)client_parm;
    simple_rest_server_client_answer(client);
    simple_rest_server_client_delete(client);
}

static int simple_rest_server_main(struct service_worker_s *worker)
{
    simple_rest_server_t *srs = (simple_rest_server_t *)service_args_get(worker->service);

    if(FAIL(listen(srs->sockfd, SIMPLE_REST_SERVER_CLIENT_LISTEN_BACKLOG)))
    {
        return ERRNO_ERROR;
    }

    simple_rest_server_client_t *client = simple_rest_server_client_new_instance(srs);

    service_set_servicing(worker);

    tcp_set_recvtimeout(srs->sockfd, 1, 0);

    while(service_should_run(worker))
    {
        int client_sockfd = accept_ex(srs->sockfd, &client->sa.sa, &client->sa_len);

        if(client_sockfd < 0)
        {
            int err = errno;

#if EAGAIN != EWOULDBLOCK
            if(!((err == EINTR) || (err == EAGAIN) || (err == EWOULDBLOCK)))
            {
                log_err("failure to accept: %r", MAKE_ERRNO_ERROR(err));
            }
#else
            if(!((err == EINTR) || (err == EAGAIN)))
            {
                log_err("failure to accept: %r", MAKE_ERRNO_ERROR(err));
            }
#endif

            continue;
        }

        client->sockfd = client_sockfd;

        if(srs->thread_pool != NULL)
        {
            if(ISOK(thread_pool_try_enqueue_call(srs->thread_pool, simple_rest_server_client_answer_thread, client, NULL, "rest-client")))
            {
                client = simple_rest_server_client_new_instance(srs);
            }
            else
            {
                simple_rest_server_client_answer(client);
                simple_rest_server_client_reset(client);
            }
        }
        else
        {
            simple_rest_server_client_answer(client);
            simple_rest_server_client_reset(client);
        }
    }

    service_set_stopping(worker);

    simple_rest_server_client_delete(client); // do this first

    mutex_lock(&srs->mtx);
    while(srs->client_current_count > 0)
    {
        cond_timedwait(&srs->cond, &srs->mtx, ONE_SECOND_US); // 1 sec
    }
    mutex_unlock(&srs->mtx);

    return SUCCESS;
}

/** @} */
