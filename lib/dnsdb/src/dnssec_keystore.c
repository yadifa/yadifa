/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 * @defgroup dnskey DNSSEC keys functions
 * @ingroup dnsdbdnssec
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnsdb/dnsdb_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
// #include <strings.h>
#include <arpa/inet.h>

#include <dnscore/thread.h>

#include <dnscore/base64.h>
#include <dnscore/format.h>
#include <dnscore/timeformat.h>
#include <dnscore/zalloc.h>
#include <dnscore/string_set.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/dnskey_keyring.h>

#include <dnscore/ptr_treemap.h>
#include <dnscore/u32_treemap.h>

#include <dnscore/fdtools.h>
#include <sys/stat.h>

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/dnssec.h"
#include "dnsdb/dnssec_config.h"
#include "dnsdb/dnssec_keystore.h"

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle_t *g_dnssec_logger;

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ZDB_KEYSTORE_ORIGIN_TAG                      0x4e494749524f534b

#define DNSKEY_FILE_FORMAT                           "K%s+%03d+%05d"

// if the key is irrelevant and yadifad is self-managing, then a deactivated key can be removed after this time elapsed

#define AUTOMATIC_DEACTIVATED_DNSKEY_UNPUBLISH_DELAY 86400

static int dnssec_keystore_keys_node_compare(const void *, const void *);

#define DNSSEC_KEYSTORE_EMPTY                                                                                                                                                                                                                  \
    {PTR_TREEMAP_CUSTOM(ptr_treemap_nullable_asciizp_node_compare), PTR_TREEMAP_CUSTOM(dnssec_keystore_keys_node_compare), PTR_TREEMAP_CUSTOM(ptr_treemap_nullable_dnsname_node_compare) /*, NULL*/, MUTEX_INITIALIZER}

// typedef btree dnssec_keystore;

/**
 * After carefully weighting the advantages and disadvantages,
 * the maintenance of the keys will go through a new keystore
 *
 * The keystore will contain all the paths it is supposed to scan and how many times a path has been added
 * ie: once for the "global" setting, once for each zone it is specifically set on
 * These paths are mandatory to avoid doing a lot of IOs when a simple scan can answer all our questions
 *
 * The keystore will contain all the keys by their name alg and tag.
 * Probably something like tag + ( alg << 16 ), the idea being to use unassigned bits [9;14] of the flags
 * Actually the name + tag should be enough.
 *
 * The keystore will contain a list of the keys for each zone, by their name
 */

#define KSDOMAIN_TAG 0x4e49414d4f44534b

struct dnssec_keystore_domain_s
{
    uint8_t    *fqdn;            // domain name
    uint64_t    keys_scan_epoch; // last time the keys have been refreshed
    const char *keys_path;       // path where to find the keys of the domain
    dnskey_t   *key_chain;       // list of keys for the domain
};

typedef struct dnssec_keystore_domain_s dnssec_keystore_domain_s;

struct dnssec_keystore
{
    ptr_treemap_t paths;   // path -> count : each path of the keystore and the number of domains using it
    ptr_treemap_t keys;    // name+alg+tag -> key
    ptr_treemap_t domains; // name -> dnssec_keystore_domain_s
    // const char *default_path;
    mutex_t lock; // mutex
};

typedef struct dnssec_keystore dnssec_keystore;

static const char             *g_keystore_path = DNSSEC_DEFAULT_KEYSTORE_PATH;
static dnssec_keystore         g_keystore = DNSSEC_KEYSTORE_EMPTY;

#define KEY_HASH(key)                        ((((hashcode)key->tag) << 16) | key->flags | (key->algorithm << 1))
#define TAG_FLAGS_ALGORITHM_HASH(t_, f_, a_) ((((hashcode)t_) << 16) | (f_) | ((a_) << 1))

static int dnssec_keystore_keys_node_compare(const void *node_a, const void *node_b)
{
    dnskey_t *k_a = (dnskey_t *)node_a;
    dnskey_t *k_b = (dnskey_t *)node_b;
    ya_result ret;

    ret = dnskey_get_algorithm(k_a) - dnskey_get_algorithm(k_b);

    if(ret == 0)
    {
        ret = dnskey_get_tag(k_a) - dnskey_get_tag(k_b);

        if(ret == 0)
        {
            ret = dnsname_compare(dnskey_get_domain(k_a), dnskey_get_domain(k_b));
        }
    }

    return ret;
}

/**
 *
 * Initialises the keystore
 *
 * @param ks
 */

void dnssec_keystore_init(/*dnssec_keystore *ks*/)
{
    /*
    dnssec_keystore *ks = &g_keystore;
    ks->paths.root = NULL;
    ks->paths.compare = ptr_treemap_nullable_asciizp_node_compare;
    ks->keys.root = NULL;
    ks->keys.compare = dnssec_keystore_keys_node_compare;
    ks->domains.root = NULL;
    ks->domains.compare =  ptr_treemap_nullable_dnsname_node_compare;
    mutex_init(&ks->lock);
    */
}

static dnssec_keystore_domain_s *dnssec_keystore_get_domain_nolock(dnssec_keystore *ks, const uint8_t *domain)
{
    ptr_treemap_node_t *d_node = ptr_treemap_find(&ks->domains, domain);

    return (dnssec_keystore_domain_s *)((d_node != NULL) ? d_node->value : NULL);
}

static dnssec_keystore_domain_s *dnssec_keystore_get_domain(dnssec_keystore *ks, const uint8_t *domain)
{
    mutex_lock(&ks->lock);
    dnssec_keystore_domain_s *ret = dnssec_keystore_get_domain_nolock(ks, domain); // locked
    mutex_unlock(&ks->lock);
    return ret;
}

static ya_result dnssec_keystore_get_key_path_with_parameters_and_domain(const char *fqdn, uint8_t algorithm, uint16_t tag, char *buffer, size_t buffer_size, dnssec_keystore_domain_s *domain, bool private)
{
    ya_result ret;
    if((fqdn == NULL) || (buffer == NULL))
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    if(buffer_size > PATH_MAX)
    {
        buffer_size = PATH_MAX;
    }

    const char *path = ((domain != NULL) && (domain->keys_path != NULL)) ? domain->keys_path : g_keystore_path;
    if(path != NULL)
    {
        if((ret = snprintf(buffer, buffer_size, "%s/" DNSKEY_FILE_FORMAT ".%s", path, fqdn, algorithm, tag, private ? "private" : "key")) >= (ya_result)buffer_size)
        {
            /* Path bigger than PATH_MAX */
            return DNSSEC_ERROR_KEYSTOREPATHISTOOLONG;
        }
    }
    else
    {
        ret = INVALID_STATE_ERROR; // the keystore path or the domain paths are supposed to be set
    }

    return ret;
}

static ya_result dnssec_keystore_get_key_path_with_domain(dnskey_t *key, char *buffer, size_t buffer_size, dnssec_keystore_domain_s *domain, bool private)
{
    ya_result ret;
    if(key == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    dnskey_get_tag(key); // updates the tag field if needed
    ret = dnssec_keystore_get_key_path_with_parameters_and_domain(key->origin, key->algorithm, key->tag, buffer, buffer_size, domain, private);

    return ret;
}

ya_result dnssec_keystore_get_key_path_with_parameters(const char *fqdn_text, uint8_t algorithm, uint16_t tag, char *buffer, size_t buffer_size, bool private)
{
    ya_result ret;
    uint8_t   fqdn[DOMAIN_LENGTH_MAX];
    if(ISOK(ret = dnsname_init_with_cstr(fqdn, fqdn_text)))
    {
        dnssec_keystore_domain_s *domain = dnssec_keystore_get_domain(&g_keystore, fqdn);
        ret = dnssec_keystore_get_key_path_with_parameters_and_domain(fqdn_text, algorithm, tag, buffer, buffer_size, domain, private);
    }
    return ret;
}

ya_result dnssec_keystore_get_key_path(dnskey_t *key, char *buffer, size_t buffer_size, bool is_private)
{
    dnssec_keystore_domain_s *domain = dnssec_keystore_get_domain(&g_keystore, key->owner_name);
    ya_result                 ret = dnssec_keystore_get_key_path_with_domain(key, buffer, buffer_size, domain, is_private);
    return ret;
}

ya_result dnssec_keystore_delete_key_files(dnskey_t *key)
{
    ya_result ret0, ret1;
    char      path[PATH_MAX];

    if(ISOK(ret0 = dnssec_keystore_get_key_path(key, path, sizeof(path), true)))
    {
        unlink(path);
    }
    if(ISOK(ret1 = dnssec_keystore_get_key_path(key, path, sizeof(path), true)))
    {
        unlink(path);
    }
    if(FAIL(ret0))
    {
        return ret0;
    }
    return ret1;
}
/**
 * Adds the knowledge of domain<->path
 * Set path to NULL to use the default value
 *
 * Can overwrite a previous value
 *
 * @param ks
 * @param domain
 * @param path
 */

static dnssec_keystore_domain_s *dnssec_keystore_add_domain_nolock(dnssec_keystore *ks, const uint8_t *domain, const char *path)
{
    // insert or get the domain in the collection

    ptr_treemap_node_t       *d_node = ptr_treemap_insert(&ks->domains, (uint8_t *)domain);
    dnssec_keystore_domain_s *d;

    if(d_node->value == NULL)
    {
        // insert : setup

        ZALLOC_OBJECT_OR_DIE(d, dnssec_keystore_domain_s, KSDOMAIN_TAG);
        d->fqdn = dnsname_zdup(domain);
        d_node->key = d->fqdn;
        d->keys_scan_epoch = 0;
        d->keys_path = NULL;
        d->key_chain = NULL;
        d_node->value = d;
    }
    else
    {
        // get : has the keys path changed ?

        d = (dnssec_keystore_domain_s *)d_node->value;

        if(d->keys_path != NULL)
        {
            // tests for NULL or equality

            if((path == d->keys_path) || ((path != NULL) && (strcmp(path, d->keys_path) == 0)))
            {
                // it has not changed : nothing to do
                return d;
            }

            // it has changed : reduce previous count

            ptr_treemap_node_t *node = ptr_treemap_find(&ks->paths, (char *)d->keys_path);
            yassert(node != NULL);

            node->value = (void *)(((intptr_t)node->value) - 1);

            if(node->value == NULL)
            {
                char *key = (char *)node->key;
                ptr_treemap_delete(&ks->paths, path);
                free(key);
            }

            // the previous path is fully removed, the new value will be assigned, if needs to be, at the next step

            d->keys_path = NULL;
            d->keys_scan_epoch = 0;
        }
    }

    if(path != NULL)
    {
        ptr_treemap_node_t *p_node = ptr_treemap_insert(&ks->paths, (char *)path);
        if(p_node->value == NULL)
        {
            p_node->key = strdup(path);
        }
        p_node->value = (void *)(((intptr_t)p_node->value) + 1);

        d->keys_path = (const char *)p_node->key;
        d->keys_scan_epoch = 0;
    }

    return d;
}

void dnssec_keystore_add_domain(/*dnssec_keystore *ks, */ const uint8_t *domain, const char *path)
{
    dnssec_keystore *ks = &g_keystore;
    mutex_lock(&ks->lock);
    dnssec_keystore_add_domain_nolock(ks, domain, path);
    mutex_unlock(&ks->lock);
}

/**
 * Remove the knowledge of domain<->path
 *
 * @param ks
 * @param domain
 * @param path
 */

void dnssec_keystore_remove_domain_nolock(/*dnssec_keystore *ks, */ const uint8_t *domain, const char *path)
{
    (void)domain;
    dnssec_keystore    *ks = &g_keystore;
    ptr_treemap_node_t *node = ptr_treemap_find(&ks->paths, path);
    if(node != NULL)
    {
        node->value = (void *)(((intptr_t)node->value) - 1);

        if(node->value == NULL)
        {
            char *key = (char *)node->key;
            ptr_treemap_delete(&ks->paths, path);
            free(key);
        }
    }
}

void dnssec_keystore_remove_domain(/*dnssec_keystore *ks, */ const uint8_t *domain, const char *path)
{
    (void)domain;
    dnssec_keystore *ks = &g_keystore;
    mutex_lock(&ks->lock);
    dnssec_keystore_remove_domain_nolock(domain, path);
    mutex_unlock(&ks->lock);
}

/**
 *
 * Add a key to the keystore, do nothing if the key is already known
 *
 * RC ok
 *
 * @param ks
 * @param key
 */

static bool dnssec_keystore_add_key_nolock(dnssec_keystore *ks, dnskey_t *key)
{
    const uint8_t            *domain = dnskey_get_domain(key);
    dnssec_keystore_domain_s *kd;

    kd = dnssec_keystore_get_domain_nolock(ks, domain); // caller nolock
    if(kd == NULL)
    {
        kd = dnssec_keystore_add_domain_nolock(ks, domain, NULL);

        yassert(kd != NULL);
    }

    // Add a reference in the keys collection

    ptr_treemap_node_t *key_node = ptr_treemap_insert(&ks->keys, key);

    if(key_node->value == NULL)
    {
        // new one
        key_node->value = key;
        dnskey_acquire(key); // RC for the above collection

        // Add a reference in the domain keys collection
        // insert, sorted by tag value

        dnskey_add_to_chain(key, &kd->key_chain); // RC

        return true;
    }
    // else already known

    return false;
}

/**
 *
 * Replace a key from the keystore, release the replaced key
 *
 * RC ok
 *
 * @param ks
 * @param key
 */

static bool dnssec_keystore_replace_key_nolock(dnssec_keystore *ks, dnskey_t *key)
{
    const uint8_t            *domain = dnskey_get_domain(key);
    dnssec_keystore_domain_s *kd;

    kd = dnssec_keystore_get_domain_nolock(ks, domain); // caller nolock
    if(kd == NULL)
    {
        kd = dnssec_keystore_add_domain_nolock(ks, domain, NULL);

        yassert(kd != NULL);
    }

    // Add a reference in the keys collection

#if HAS_EDF // specific debug for me
    uint64_t start = timeus();
#endif
    ptr_treemap_node_t *key_node = ptr_treemap_insert(&ks->keys, key);
#if HAS_EDF // specific debug for me
    uint64_t stop = timeus();
    log_debug("dnssec_keystore_add_key_nolock: inserted key in %lluus", key->tag, stop - start);
#endif

    dnskey_t *old_key = (dnskey_t *)key_node->value;

    if(old_key != key)
    {
        if(old_key != NULL)
        {
            dnskey_remove_from_chain(old_key, &kd->key_chain);
            dnskey_release(old_key);
        }

        dnskey_acquire(key);
        key_node->value = key;

        // Add a reference in the domain keys collection
        // insert, sorted by tag value

        dnskey_add_to_chain(key, &kd->key_chain); // RC

        return true;
    }
    // else already known

    return false;
}

/**
 *
 * Add a key to the keystore, do nothing if a key with the same tag and algorithm is
 * in the keystore for that domain already
 *
 * RC ok
 *
 * @param ks
 * @param key
 *
 * @return true iff the key was added
 */

bool dnssec_keystore_add_key(dnskey_t *key)
{
    dnssec_keystore *ks = &g_keystore;
    mutex_lock(&ks->lock);
    bool ret = dnssec_keystore_add_key_nolock(ks, key); // RC // locked
    mutex_unlock(&ks->lock);
    return ret;
}

/**
 *
 * Replace a key from the keystore, release the replaced key
 *
 * RC ok
 *
 * @param ks
 * @param key
 *
 * @return true iff the key was added
 */

bool dnssec_keystore_replace_key(dnskey_t *key)
{
    dnssec_keystore *ks = &g_keystore;
    mutex_lock(&ks->lock);
    bool ret = dnssec_keystore_replace_key_nolock(ks, key); // RC // locked
    mutex_unlock(&ks->lock);
    return ret;
}

/**
 *
 * Removes a key from the keystore
 * If the key is found, it is returned acquired (still has to be released)
 *
 * RC ok
 *
 * @param ks
 * @param key
 * @return the instance of the key from the keystore, or NULL if the key was not found
 */

static dnskey_t *dnssec_keystore_remove_key_nolock(dnssec_keystore *ks, dnskey_t *key)
{
    dnskey_t           *ret_key = NULL;

    ptr_treemap_node_t *key_node = ptr_treemap_find(&ks->keys, key);

    if(key_node != NULL)
    {
        ret_key = (dnskey_t *)key_node->value;
        ptr_treemap_delete(&ks->keys, key);
        // no not release as it will be returned

        const uint8_t            *domain = dnskey_get_domain(key);

        dnssec_keystore_domain_s *kd = dnssec_keystore_get_domain_nolock(ks, domain); // caller nolock

        if(kd != NULL)
        {
            // remove, sorted by tag value

            dnskey_remove_from_chain(key, &kd->key_chain); // RC
        }
    }
    // else already known

    return ret_key;
}

/**
 *
 * Removes a key from the keystore
 * If the key is found, it is returned acquired (still requires release)
 *
 * RC ok
 *
 * @param ks
 * @param key
 *
 * @return the instance of the key from the keystore, or NULL if the key was not found
 */

dnskey_t *dnssec_keystore_remove_key(dnskey_t *key)
{
    dnssec_keystore *ks = &g_keystore;
    mutex_lock(&ks->lock);
    dnskey_t *ret_key = dnssec_keystore_remove_key_nolock(ks, key); // RC // locked
    mutex_unlock(&ks->lock);
    return ret_key;
}

/**
 * Removes a key from the keystore, if possible.
 * Renames both key files adding suffix of the creation time plus bak
 * Does not return any error code as it's a best effort kind of thing.
 *
 * @param key
 */

void dnssec_keystore_delete_key(dnskey_t *key)
{
    dnssec_keystore_domain_s *domain;
    char                      clean_origin[DOMAIN_LENGTH_MAX];

    const uint8_t            *fqdn = key->owner_name;
    const uint8_t             algorithm = key->algorithm;
    const uint16_t            tag = key->tag;

    /* Load from the disk, add to the keystore */

    domain = dnssec_keystore_get_domain(&g_keystore, fqdn);
    cstr_init_with_dnsname(clean_origin, fqdn);

    format_writer_t epoch_writer = {packedepoch_format_handler_method, (void *)(intptr_t)key->epoch_created};

    char            path[PATH_MAX];
    char            path_new[PATH_MAX];

    // PRIVATE

    ya_result ret;

    ret = dnssec_keystore_get_key_path_with_domain(key, path, sizeof(path), domain, true);

    if(ISOK(ret) && (snformat(path_new, sizeof(path_new), "%s.%w.bak", path, &epoch_writer) < PATH_MAX))
    {
        log_debug("dnskey-keystore: %{dnsname}: delete: private key file is '%s'", fqdn, path);

        if(file_exists(path))
        {
            dnskey_t *key_from_file = NULL;

            ret = dnskey_new_private_key_from_file(path, &key_from_file); // RC

            if(ISOK(ret))
            {
                if(dnskey_equals(key, key_from_file))
                {
                    log_info(
                        "dnskey-keystore: %{dnsname}: delete: private key file content matches key: renaming file '%s' "
                        "to '%s'",
                        fqdn,
                        path,
                        path_new);

                    if(rename(path, path_new) < 0)
                    {
                        ret = ERRNO_ERROR;
                        log_err("dnskey-keystore: %{dnsname}: delete: could not rename file '%s' to '%s': %r", fqdn, path, path_new, ret);
                    }
                }
                else
                {
                    log_info(
                        "dnskey-keystore: %{dnsname}: delete: private key file content does not matches key: renaming "
                        "file '%s' to '%s'",
                        fqdn,
                        path,
                        path_new);
                }

                dnskey_release(key_from_file);
                key_from_file = NULL;
            }
            else
            {
                log_err("dnskey-keystore: %{dnsname}: delete: could not read key from private key file '%s': %r", fqdn, path, ret);
            }
        }
        else
        {
            log_info("dnskey-keystore: %{dnsname}: delete: private key file '%s' does not exists", fqdn, path);
        }
    }
    else
    {
        log_err("dnskey-keystore: %{dnsname}: delete: K%s+%03d+%05d private key file path size would be too big", fqdn, clean_origin, algorithm, tag);
    }

    // PUBLIC

    ret = dnssec_keystore_get_key_path_with_domain(key, path, sizeof(path), domain, false);

    if(ISOK(ret) && (snformat(path_new, sizeof(path_new), "%s.%w.bak", path, &epoch_writer) < PATH_MAX))
    {
        log_debug("dnskey-keystore: %{dnsname}: delete: public key file is '%s'", fqdn, path);

        if(file_exists(path))
        {
            dnskey_t *key_from_file = NULL;

            ret = dnskey_new_public_key_from_file(path, &key_from_file); // RC

            if(ISOK(ret))
            {
                if(dnskey_public_equals(key, key_from_file))
                {
                    log_info(
                        "dnskey-keystore: %{dnsname}: delete: public key file content matches key: renaming file '%s' "
                        "to '%s'",
                        fqdn,
                        path,
                        path_new);

                    if(rename(path, path_new) < 0)
                    {
                        ret = ERRNO_ERROR;
                        log_err("dnskey-keystore: %{dnsname}: delete: could not rename file '%s' to '%s': %r", fqdn, path, path_new, ret);
                    }
                }
                else
                {
                    log_info(
                        "dnskey-keystore: %{dnsname}: delete: public key file content does not matches key: renaming "
                        "file '%s' to '%s'",
                        fqdn,
                        path,
                        path_new);
                }

                dnskey_release(key_from_file);
                key_from_file = NULL;
            }
            else
            {
                log_err("dnskey-keystore: %{dnsname}: delete: could not read key from public key file '%s': %r", fqdn, path, ret);
            }
        }
        else
        {
            log_info("dnskey-keystore: %{dnsname}: delete: public key file '%s' does not exists", fqdn, path);
        }
    }
    else
    {
        log_err("dnskey-keystore: %{dnsname}: delete: K%s+%03d+%05d public key file path size would be too big", fqdn, clean_origin, algorithm, tag);
    }

    dnskey_t *keystore_key = dnssec_keystore_remove_key(key);
    if(keystore_key != NULL)
    {
        dnskey_release(keystore_key);
        keystore_key = NULL;
    }
}

/**
 *
 * Retrieves a key from the keystore
 *
 * RC ok
 *
 * @param ks
 * @param domain
 * @param tag
 * @return
 */

static dnskey_t *dnssec_keystore_acquire_key_from_fqdn_nolock(dnssec_keystore *ks, const uint8_t *domain, uint16_t tag)
{
    dnskey_t                 *key = NULL;

    dnssec_keystore_domain_s *kd = dnssec_keystore_get_domain_nolock(ks, domain); // caller nolock
    if(kd != NULL)
    {
        key = kd->key_chain;

        while(key != NULL)
        {
            uint16_t key_tag = dnskey_get_tag(key);
            if(key_tag == tag)
            {
                break;
            }

            key = key->next;
        }

        if(key != NULL)
        {
            dnskey_acquire(key);
        }
    }

    return key;
}

/**
 *
 * Retrieves a key from the keystore
 *
 * RC ok
 *
 * @param ks
 * @param domain
 * @param tag
 * @return
 */

dnskey_t *dnssec_keystore_acquire_key_from_fqdn_with_tag(const uint8_t *domain, uint16_t tag)
{
    dnssec_keystore *ks = &g_keystore;
    mutex_lock(&ks->lock);
    dnskey_t *key = dnssec_keystore_acquire_key_from_fqdn_nolock(ks, domain, tag); // RC // locked
    mutex_unlock(&ks->lock);

    return key;
}

/**
 *
 * Retrieves a key from the keystore
 *
 * RC ok
 *
 * @param ks
 * @param domain
 * @param tag
 * @return
 */

dnskey_t *dnssec_keystore_acquire_key_from_rdata(const uint8_t *domain, const uint8_t *rdata, uint16_t rdata_size)
{
    dnssec_keystore *ks = &g_keystore;
    uint16_t         tag = dnskey_get_tag_from_rdata(rdata, rdata_size);
    mutex_lock(&ks->lock);
    dnskey_t *key = dnssec_keystore_acquire_key_from_fqdn_nolock(ks, domain, tag); // RC // locked
    mutex_unlock(&ks->lock);

    return key;
}

/**
 * Returns the nth key from the domain or NULL if no such key exist
 *
 * RC ok
 *
 * @return a dnskey
 */

dnskey_t *dnssec_keystore_acquire_key_from_fqdn_at_index(const uint8_t *domain, int index)
{
    dnssec_keystore *ks = &g_keystore;
    dnskey_t        *key = NULL;
    mutex_lock(&ks->lock);
    dnssec_keystore_domain_s *ks_domain = dnssec_keystore_get_domain_nolock(ks, domain); // locked
    if(ks_domain != NULL)
    {
        key = ks_domain->key_chain;
        while(index > 0 && key != NULL)
        {
            key = key->next;
            --index;
        }
        if(key != NULL)
        {
            dnskey_acquire(key);
        }
    }
    mutex_unlock(&ks->lock);
    return key;
}

/**
 * Returns true iff the key is contained in the key store.
 *
 * @return true iff the key is contained in the key store.
 */

bool dnssec_keystore_contains_key(dnskey_t *contained_key)
{
    const uint8_t   *domain = dnskey_get_domain(contained_key);
    dnssec_keystore *ks = &g_keystore;
    dnskey_t        *key = NULL;
    mutex_lock(&ks->lock);
    dnssec_keystore_domain_s *ks_domain = dnssec_keystore_get_domain_nolock(ks, domain); // locked
    if(ks_domain != NULL)
    {
        key = ks_domain->key_chain;
        while(key != NULL)
        {
            if(dnskey_public_equals(key, contained_key))
            {
                mutex_unlock(&ks->lock);
                return true;
            }
            key = key->next;
        }
    }
    mutex_unlock(&ks->lock);
    return false;
}

bool dnssec_keystore_has_any_ksk(const uint8_t *domain)
{
    dnssec_keystore *ks = &g_keystore;
    dnskey_t        *key = NULL;
    bool             ret = false;
    mutex_lock(&ks->lock);
    dnssec_keystore_domain_s *kd = dnssec_keystore_get_domain_nolock(ks, domain); // locked
    if(kd != NULL)
    {
        key = kd->key_chain;

        while(key != NULL)
        {
            if(dnskey_get_flags(key) == (DNSKEY_FLAG_ZONEKEY | DNSKEY_FLAG_KEYSIGNINGKEY))
            {
                ret = true;
            }

            key = key->next;
        }
    }

    mutex_unlock(&ks->lock);

    return ret;
}

bool dnssec_keystore_has_activated_ksk(const uint8_t *domain, time_t attime)
{
    dnssec_keystore *ks = &g_keystore;
    dnskey_t        *key = NULL;
    bool             ret = false;
    mutex_lock(&ks->lock);
    dnssec_keystore_domain_s *kd = dnssec_keystore_get_domain_nolock(ks, domain); // locked
    if(kd != NULL)
    {
        key = kd->key_chain;

        while(key != NULL)
        {
            if(dnskey_get_flags(key) == (DNSKEY_FLAG_ZONEKEY | DNSKEY_FLAG_KEYSIGNINGKEY))
            {
                if(dnskey_is_activated(key, attime))
                {
                    ret = true;
                    break;
                }
            }

            key = key->next;
        }
    }

    mutex_unlock(&ks->lock);

    return ret;
}

bool dnssec_keystore_has_activated_zsk(const uint8_t *domain, time_t attime)
{
    dnssec_keystore *ks = &g_keystore;
    dnskey_t        *key = NULL;
    bool             ret = false;
    mutex_lock(&ks->lock);
    dnssec_keystore_domain_s *kd = dnssec_keystore_get_domain_nolock(ks, domain); // locked
    if(kd != NULL)
    {
        key = kd->key_chain;

        while(key != NULL)
        {
            if(dnskey_get_flags(key) == DNSKEY_FLAG_ZONEKEY)
            {
                if(dnskey_is_activated(key, attime))
                {
                    ret = true;
                    break;
                }
            }

            key = key->next;
        }
    }

    mutex_unlock(&ks->lock);

    return ret;
}

/**
 * Returns true iff the key for theddomain+algorithm+tag is active at 'now'
 *
 * @param domain
 * @param algorithm
 * @param tag
 * @param now
 *
 * @return
 */

bool dnssec_keystore_has_usable_ksk(const uint8_t *domain, time_t attime)
{
    dnssec_keystore *ks = &g_keystore;
    dnskey_t        *key = NULL;
    bool             ret = false;
    mutex_lock(&ks->lock);
    dnssec_keystore_domain_s *kd = dnssec_keystore_get_domain_nolock(ks, domain); // locked
    if(kd != NULL)
    {
        key = kd->key_chain;

        while(key != NULL)
        {
            if(dnskey_is_private(key) && (dnskey_get_flags(key) == (DNSKEY_FLAG_ZONEKEY | DNSKEY_FLAG_KEYSIGNINGKEY)))
            {
                if(dnskey_is_activated(key, attime))
                {
                    ret = true;
                    break;
                }
            }

            key = key->next;
        }
    }

    mutex_unlock(&ks->lock);

    return ret;
}

/**
 * Acquires all the currently activated keys and store them to the appropriate
 * KSK or ZSK collection ptr_vector.
 *
 * @param domain
 * @param ksks
 * @param zsks
 * @return
 */

bool dnssec_keystore_has_usable_zsk(const uint8_t *domain, time_t attime)
{
    dnssec_keystore *ks = &g_keystore;
    dnskey_t        *key = NULL;
    bool             ret = false;
    mutex_lock(&ks->lock);
    dnssec_keystore_domain_s *kd = dnssec_keystore_get_domain_nolock(ks, domain); // locked
    if(kd != NULL)
    {
        key = kd->key_chain;

        while(key != NULL)
        {
            if(dnskey_is_private(key) && (dnskey_get_flags(key) == DNSKEY_FLAG_ZONEKEY))
            {
                if(dnskey_is_activated(key, attime))
                {
                    ret = true;
                    break;
                }
            }

            key = key->next;
        }
    }

    mutex_unlock(&ks->lock);

    return ret;
}

int dnssec_keystore_acquire_publish_delete_keys_from_fqdn_to_vectors(const uint8_t *domain, ptr_vector_t *publish_keys, ptr_vector_t *delete_keys)
{
    time_t now = time(NULL);

    for(int_fast32_t i = 0;; ++i)
    {
        dnskey_t *key = dnssec_keystore_acquire_key_from_fqdn_at_index(domain, i);

        if(key == NULL)
        {
            log_debug1("dnskey-keystore: acquiring activated key %{dnsname}: no other key available", domain);
            break;
        }

        if((key->status & DNSKEY_KEY_IS_IN_ZONE) == 0)
        {
            if(dnskey_has_explicit_publish_or_delete(key))
            {
                if(dnskey_is_published(key, now))
                {
                    if((publish_keys != NULL) && (ptr_vector_search_ptr_index(publish_keys, key) < 0))
                    {
                        ptr_vector_append(publish_keys, key);
                    }
                    else
                    {
                        dnskey_release(key);
                    }
                    continue;
                }

                if(dnskey_is_unpublished(key, now))
                {
                    if((delete_keys != NULL) && (ptr_vector_search_ptr_index(delete_keys, key) < 0))
                    {
                        ptr_vector_append(delete_keys, key);
                    }
                    else
                    {
                        dnskey_release(key);
                    }
                    continue;
                }
            }
            else if(dnskey_has_activate_or_deactivate(key))
            {
                if(dnskey_is_activated(key, now))
                {
                    if((publish_keys != NULL) && (ptr_vector_search_ptr_index(publish_keys, key) < 0))
                    {
                        ptr_vector_append(publish_keys, key);
                    }
                    else
                    {
                        dnskey_release(key);
                    }
                    continue;
                }
                if(dnskey_is_deactivated(key, MAX((int64_t)now - AUTOMATIC_DEACTIVATED_DNSKEY_UNPUBLISH_DELAY, 0)))
                {
                    if((delete_keys != NULL) && (ptr_vector_search_ptr_index(delete_keys, key) < 0))
                    {
                        ptr_vector_append(delete_keys, key);
                    }
                    else
                    {
                        dnskey_release(key);
                    }
                    continue;
                }
            }
        }

        dnskey_release(key);
    }

    int ret = 0;

    if(publish_keys != NULL)
    {
        ret += ptr_vector_size(publish_keys);
    }

    if(delete_keys != NULL)
    {
        ret += ptr_vector_size(delete_keys);
    }

    return ret;
}

/**
 * Releases all the keys from a vector.
 *
 * @param keys
 */

void dnssec_keystore_release_keys_from_vector(ptr_vector_t *keys)
{
    for(int_fast32_t i = 0; i <= ptr_vector_last_index(keys); ++i)
    {
        dnskey_t *key = (dnskey_t *)ptr_vector_get(keys, i);

        log_debug("dnskey-keystore: releasing key %{dnsname}", dnskey_get_domain(key));

        dnskey_release(key);
    }
}

/**
 *
 * Retrieves a key from the keystore
 *
 * RC ok
 *
 * @param ks
 * @param domain
 * @param tag
 * @return
 */

static dnskey_t *dnssec_keystore_acquire_key_from_name_nolock(dnssec_keystore *ks, const char *domain, uint16_t tag)
{
    dnskey_t *key = NULL;
    uint8_t   fqdn[DOMAIN_LENGTH_MAX];

    if(ISOK(dnsname_init_with_cstr(fqdn, domain)))
    {
        key = dnssec_keystore_acquire_key_from_fqdn_nolock(ks, fqdn, tag); // RC // caller nolock
    }

    return key;
}

/**
 *
 * Retrieves a key from the keystore
 *
 * RC ok
 *
 * @param ks
 * @param domain
 * @param tag
 * @return
 */

dnskey_t *dnssec_keystore_acquire_key_from_name(const char *domain, uint16_t tag)
{
    dnskey_t *key = NULL;
    uint8_t   fqdn[DOMAIN_LENGTH_MAX];

    if(ISOK(dnsname_init_with_cstr(fqdn, domain)))
    {
        key = dnssec_keystore_acquire_key_from_fqdn_with_tag(fqdn, tag); // RC
    }

    return key;
}

/**
 * Returns the nth key from the domain or NULL if no such key exist
 *
 * RC ok
 *
 * @return a dnskey
 */

dnskey_t *dnssec_keystore_acquire_key_from_name_by_index(const char *domain, int idx)
{
    dnskey_t *key = NULL;
    uint8_t   fqdn[DOMAIN_LENGTH_MAX];

    if(ISOK(dnsname_init_with_cstr(fqdn, domain)))
    {
        key = dnssec_keystore_acquire_key_from_fqdn_at_index(fqdn, idx); // RC
    }

    return key;
}

struct dnssec_keystore_reload_readdir_callback_s
{
    dnssec_keystore *ks;
    const char      *domain;
    int              private_update;
};

typedef struct dnssec_keystore_reload_readdir_callback_s dnssec_keystore_reload_readdir_callback_s;

static ya_result                                         dnssec_keystore_reload_readdir_callback_nolock(const char *basedir, const char *filename, uint8_t filetype, void *args_)
{
    if((filetype == DT_REG) && (filename[0] != 'K'))
    {
        return SUCCESS;
    }

    dnssec_keystore_reload_readdir_callback_s *args = (dnssec_keystore_reload_readdir_callback_s *)args_;

    dnssec_keystore                           *ks = args->ks;

    int                                        algorithm;
    int                                        tag;
    char                                       extension[16];
    char                                       domain[256];
    char                                       file[PATH_MAX + 1];

    size_t                                     dlen = strlen(basedir);
    size_t                                     flen = strlen(filename);

    if(dlen + flen >= sizeof(file))
    {
        log_err("path too long for '%s'/'%s'", basedir, filename);
        return INVALID_PATH;
    }
    memset(extension, 0, sizeof(extension)); // to shut-up valgrind
    memcpy(file, basedir, dlen);
    if(file[dlen - 1] != '/')
    {
        file[dlen++] = '/';
    }
    memcpy(&file[dlen], filename, flen + 1);

    if(sscanf(filename, "K%255[^+]+%03d+%05d.%15s", domain, &algorithm, &tag, extension) == 4)
    {
        domain[255] = '\0'; // ensure the 256th char is '\0'
        if((args->domain == NULL) || (strcmp(domain, args->domain) == 0))
        {
            if(memcmp(extension, "private", 8) == 0)
            {
                log_debug("found private key file for domain '%s' with tag %i and algorithm %i", domain, tag, algorithm);
                int64_t ts;

                if(ISOK(file_mtime(file, &ts)))
                {
                    // get the key with that domain/tag
                    // @note 20150907 edf -- work in progress

                    dnskey_t *current_key = dnssec_keystore_acquire_key_from_name_nolock(ks, domain, tag); // RC // caller nolock
                    if(current_key != NULL)
                    {
                        // check if it has to be reloaded
                        if(current_key->timestamp >= ts)
                        {
                            // ignore this file (already got it)

                            dnskey_release(current_key);

                            return SUCCESS;
                        }

                        log_info("DNSKEY from file '%s' was modified (expected %lT, got %lT)", filename, current_key->timestamp, ts);
                    }

                    dnskey_t *key;

                    // remove the key from the keystore, load the key from disk

                    log_debug("dnssec_keystore_reload_readdir_callback: opening file '%s'", file);

                    ya_result ret;

                    if(ISOK(ret = dnskey_new_private_key_from_file(file, &key)))
                    {
                        bool is_missing_any_smart_field = !dnskey_has_explicit_publish_and_delete(key) || !dnskey_has_explicit_activate(key) || !dnskey_has_explicit_deactivate(key);
                        bool has_no_smart_field = dnskey_has_explicit_publish_or_delete(key) && dnskey_has_explicit_activate(key) && dnskey_has_explicit_deactivate(key);

                        if(has_no_smart_field)
                        {
                            log_info("key from '%s' has no smart fields", file);
                        }
                        else if(is_missing_any_smart_field)
                        {
                            log_info("key from '%s' is missing some smart fields", file);
                        }
#if DEBUG
                        log_debug1("dnssec_keystore_reload_readdir_callback: private key generated from file '%s'", file);
#endif
                        // compare the cryptographic parts of the key (the public key is enough) and
                        // overwrite the timestamps iff they are the same, else ... refuse to break security

                        if(current_key != NULL)
                        {
                            if(dnskey_equals(current_key, key))
                            {
#if DEBUG
                                log_debug1("dnssec_keystore_reload_readdir_callback: file '%s' has already been loaded", file);
#endif
                                current_key->epoch_created = key->epoch_created;
                                current_key->epoch_publish = key->epoch_publish;
                                current_key->epoch_activate = key->epoch_activate;

                                current_key->epoch_inactive = key->epoch_inactive;
                                current_key->epoch_delete = key->epoch_delete;
                                current_key->timestamp = key->timestamp;
                                current_key->status &= ~(DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH | DNSKEY_KEY_HAS_SMART_FIELD_DELETE | DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE | DNSKEY_KEY_HAS_SMART_FIELD_INACTIVE);
                                current_key->status |= key->status & (DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH | DNSKEY_KEY_HAS_SMART_FIELD_DELETE | DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE | DNSKEY_KEY_HAS_SMART_FIELD_INACTIVE);
                            }
                            else
                            {
                                // update
#if DEBUG
                                log_debug1("dnssec_keystore_reload_readdir_callback: file '%s' updated a key", file);
#endif
                                current_key->epoch_created = key->epoch_created;
                                current_key->epoch_publish = key->epoch_publish;
                                current_key->epoch_activate = key->epoch_activate;

                                current_key->epoch_inactive = key->epoch_inactive;
                                current_key->epoch_delete = key->epoch_delete;
                                current_key->timestamp = key->timestamp;

                                current_key->status &= ~(DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH | DNSKEY_KEY_HAS_SMART_FIELD_DELETE | DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE | DNSKEY_KEY_HAS_SMART_FIELD_INACTIVE);
                                current_key->status |= key->status & (DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH | DNSKEY_KEY_HAS_SMART_FIELD_DELETE | DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE | DNSKEY_KEY_HAS_SMART_FIELD_INACTIVE);

                                // update key re-signature scheduling
                            }

                            dnskey_release(current_key);
                        }
                        else
                        {
                            // add the new key
#if DEBUG
                            log_debug1("dnssec_keystore_reload_readdir_callback: file '%s' generated a new key", file);
#endif
                            dnssec_keystore_add_key_nolock(ks, key); // RC // caller nolock

                            // also : the key should be put in the zone and signature should be scheduled
                        }

                        dnskey_release(key);
                        ++args->private_update; // one key was modified (it's timings at the very least)
#if DEBUG
                        log_debug1("dnssec_keystore_reload_readdir_callback: file '%s' successfully read", file);
#endif
                    }
                    else
                    {
                        log_debug("could not read '%s': %r (missing public .key file ?)", file, ret);
                    }
                }
                else
                {
                    log_err("could not access '%s': %r", file, ERRNO_ERROR);
                }
            } // else this is not a private key file
        }
        else
        {
            log_debug("ignoring key file %s (%s != %s)", filename, domain, args->domain);
        }
    }
    else
    {
        log_debug("ignoring file %s", filename);
    }

    return SUCCESS; // invalid file name, but it's irrelevant for this
}

/**
 *
 * (Re)loads keys found in the paths of the keystore
 *
 * @return
 */

ya_result dnssec_keystore_reload()
{
    // scan all directories

    //   for each key found, load and propose it to the domain
    //     if the key has changed ...
    //       timings: remove the previous alarms (?)
    //       removed: ?
    //       added:   update alarms (?)

    dnssec_keystore                          *ks = &g_keystore;
    ya_result                                 ret;

    dnssec_keystore_reload_readdir_callback_s args = {ks, NULL, 0};

    mutex_lock(&ks->lock);

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&ks->paths, &iter);
    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *path_node = ptr_treemap_iterator_next_node(&iter);
        const char         *path = (const char *)path_node->key;
        if(FAIL(ret = readdir_forall(path, dnssec_keystore_reload_readdir_callback_nolock, &args)))
        {
            log_err("dnssec keystore reload: an error occurred reading key directory '%s': %r", path, ret);
        }
    }

    if(FAIL(ret = readdir_forall(g_keystore_path, dnssec_keystore_reload_readdir_callback_nolock, &args)))
    {
        log_err("dnssec keystore reload: an error occurred reading key directory '%s': %r", g_keystore_path, ret);
    }

    mutex_unlock(&ks->lock);

    if(ISOK(ret))
    {
        ret = args.private_update;
    }

    return ret;
}

/**
 *
 * (Re)loads keys found in the path of the keystore for the specified domain
 *
 * @param fqdn
 * @return
 */

ya_result dnssec_keystore_reload_domain(const uint8_t *fqdn)
{
    // scan all directories

    //   for each key found, load and propose it to the domain
    //     if the key has changed ...
    //       timings: remove the previous alarms (?)
    //       removed: ?
    //       added:   update alarms (?)

    log_debug("dnskey-keystore: %{dnsname}: reload domain: scanning for keys", fqdn);

    dnssec_keystore *ks = &g_keystore;
    ya_result        ret = SUCCESS;

    mutex_lock(&ks->lock);

    dnssec_keystore_domain_s *keystore_domain = dnssec_keystore_get_domain_nolock(ks, fqdn); // locked

    ret = DNSSEC_ERROR_NO_KEY_FOR_DOMAIN; // no key for domain

    if(keystore_domain != NULL)
    {
        char domain[DOMAIN_LENGTH_MAX];

        cstr_init_with_dnsname(domain, fqdn);

        dnssec_keystore_reload_readdir_callback_s args = {ks, domain, 0};

        const char                               *path = keystore_domain->keys_path;

        if(path == NULL)
        {
            path = g_keystore_path;
        }

        struct stat st;
        filestat(path, &st);

#if __windows__
        int64_t mod_time = st.st_mtime;
#elif IS_DARWIN_OS
        int64_t mod_time = st.st_mtimespec.tv_sec;
        mod_time *= 1000000000LL;
        mod_time += st.st_mtimespec.tv_nsec;
#else
        int64_t mod_time = st.st_mtim.tv_sec;
        mod_time *= 1000000000LL;
        mod_time += st.st_mtim.tv_nsec;
#endif

        if((uint64_t)mod_time > keystore_domain->keys_scan_epoch)
        {
            if(ISOK(ret = readdir_forall(path, dnssec_keystore_reload_readdir_callback_nolock, &args)))
            {
                ret = args.private_update;

                keystore_domain->keys_scan_epoch = mod_time;
            }
            else
            {
                log_err("dnssec keystore: %{dnsname} reload domain: an error occurred reading key directory '%s': %r", fqdn, path, ret);

                if(keystore_domain->key_chain != NULL)
                {
                    ret = 0;
                }
            }
        }
        else
        {
            log_debug("dnssec keystore: %{dnsname} reload domain: no need to scan key directory '%s' again", fqdn, path);

            ret = 0;
        }
    }

    mutex_unlock(&ks->lock);

    return ret;
}

// sanitises an origin

static void dnssec_keystore_origin_copy_sanitize(char *target, const char *origin)
{
    if(origin == NULL)
    {
        target[0] = '.';
        target[1] = '\0';
        return;
    }

    int origin_len = strlen(origin);

    if(origin_len == 0)
    {
        target[0] = '.';
        target[1] = '\0';
        return;
    }

    if(origin[origin_len - 1] == '.')
    {
        origin_len++;
        MEMCOPY(target, origin, origin_len);
    }
    else
    {
        MEMCOPY(target, origin, origin_len);
        target[origin_len++] = '.';
        target[origin_len] = '\0';
    }
}

const char        *dnssec_keystore_getpath() { return g_keystore_path; }

static const char *dnssec_default_keystore_path = DNSSEC_DEFAULT_KEYSTORE_PATH;

void               dnssec_keystore_resetpath()
{
    /*
     * cast to void to avoid the -Wstring-compare warning
     */

    if(((void *)g_keystore_path) != ((void *)dnssec_default_keystore_path))
    {
        free((void *)g_keystore_path);
        g_keystore_path = dnssec_default_keystore_path;
    }
}

void dnssec_keystore_setpath(const char *path)
{
    dnssec_keystore_resetpath();

    if(path != NULL)
    {
        g_keystore_path = strdup(path);
    }
}
/*
void
dnssec_keystore_destroy_paths_cb(ptr_treemap_node_t *node)
{
    free(node->key);
}
*/

static void dnssec_keystore_destroy_domains_cb(ptr_treemap_node_t *node)
{
    dnssec_keystore_domain_s *d = (dnssec_keystore_domain_s *)node->value;
    dnsname_zfree(d->fqdn);
    d->fqdn = NULL;
    ZFREE_OBJECT(d);
    // d->keys_path is a pointer to a key in g_keystore.paths
    // d->key_chain should have been emptied by now
}

void dnssec_keystore_finalise()
{
    log_debug("dnskey-keystore: clearing-up");

    mutex_lock(&g_keystore.lock);

    while(!ptr_treemap_isempty(&g_keystore.keys))
    {
        ptr_treemap_node_t *key_node = g_keystore.keys.root;
        dnskey_t           *key = (dnskey_t *)key_node->key;

        if(key != NULL)
        {
            log_debug("dnskey-keystore: %{dnsname} +%03d+%05d/%d status=%x rc=%i (%p)", dnskey_get_domain(key), key->algorithm, key->tag, ntohs(key->flags), key->status, key->rc, key);

            dnskey_t *ret_key = dnssec_keystore_remove_key_nolock(&g_keystore, key); // locked
            dnskey_release(ret_key);
        }
        else
        {
            break;
        }
    }

    ptr_treemap_callback_and_finalise(&g_keystore.domains, dnssec_keystore_destroy_domains_cb);

    mutex_unlock(&g_keystore.lock);
}

/**
 * Generates a private key, store in the keystore
 *  The caller is expected to create a resource record with this key and add
 *  it to the owner.
 *
 * @param algorithm the DNSKEY algorithm
 * @param size the size of the key. Not all algoritms are taking it into account.
 * @param flags the DNSKEY flags
 * @param origin the domain of the key
 * @param smart_fields all the smart fields to set, don't forget to set the "fields" field to tell which fields are
 * valid
 * @param out_key the generated key
 * @returns an error code
 *
 */

ya_result dnssec_keystore_new_key(uint8_t algorithm, uint32_t size, uint16_t flags, const char *origin, dnskey_smart_fields_t *smart_fields, dnskey_t **out_key)
{
    ya_result ret;

    dnskey_t *key = NULL;

    char      clean_origin[DOMAIN_LENGTH_MAX];
    uint8_t   fqdn[DOMAIN_LENGTH_MAX];

    /* sanitise the origin name */

    dnssec_keystore_origin_copy_sanitize(clean_origin, origin);
    dnsname_init_with_cstr(fqdn, clean_origin);

    /**
     * @note if 65536 keys exist then this function will loop forever
     */

    for(;;)
    {
        switch(algorithm)
        {
            case DNSKEY_ALGORITHM_RSASHA1:
            case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
            case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
            case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            {
                if(FAIL(ret = dnskey_rsa_newinstance(size, algorithm, flags, clean_origin, &key)))
                {
                    return ret;
                }

                break;
            }
#if DNSCORE_HAS_DSA_SUPPORT
            case DNSKEY_ALGORITHM_DSASHA1:
            case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
            {
                if(FAIL(ret = dnskey_dsa_newinstance(size, algorithm, flags, clean_origin, &key)))
                {
                    return ret;
                }

                break;
            }
#endif
#if DNSCORE_HAS_ECDSA_SUPPORT
            case DNSKEY_ALGORITHM_ECDSAP256SHA256:
            case DNSKEY_ALGORITHM_ECDSAP384SHA384:
            {
                if(FAIL(ret = dnskey_ecdsa_newinstance(size, algorithm, flags, clean_origin, &key)))
                {
                    return ret;
                }

                break;
            }
#endif
#if DNSCORE_HAS_EDDSA_SUPPORT
            case DNSKEY_ALGORITHM_ED25519:
            case DNSKEY_ALGORITHM_ED448:
            {
                if(FAIL(ret = dnskey_eddsa_newinstance(size, algorithm, flags, clean_origin, &key)))
                {
                    return ret;
                }

                break;
            }
#endif
#if DNSCORE_HAS_OQS_SUPPORT
            case DNSKEY_ALGORITHM_DILITHIUM2:
            case DNSKEY_ALGORITHM_DILITHIUM3:
            case DNSKEY_ALGORITHM_DILITHIUM5:
            case DNSKEY_ALGORITHM_FALCON512:
            case DNSKEY_ALGORITHM_FALCON1024:
            case DNSKEY_ALGORITHM_FALCONPAD512:
            case DNSKEY_ALGORITHM_FALCONPAD1024:
            case DNSKEY_ALGORITHM_SPHINCSSHA2128F:
            case DNSKEY_ALGORITHM_SPHINCSSHA2128S:
            case DNSKEY_ALGORITHM_SPHINCSSHA2192F:
            case DNSKEY_ALGORITHM_SPHINCSSHA2192S:
            case DNSKEY_ALGORITHM_SPHINCSSHA2256F:
            case DNSKEY_ALGORITHM_SPHINCSSHA2256S:
            case DNSKEY_ALGORITHM_SPHINCSSHAKE128F:
            case DNSKEY_ALGORITHM_SPHINCSSHAKE128S:
            case DNSKEY_ALGORITHM_SPHINCSSHAKE192F:
            case DNSKEY_ALGORITHM_SPHINCSSHAKE192S:
            case DNSKEY_ALGORITHM_SPHINCSSHAKE256F:
            case DNSKEY_ALGORITHM_SPHINCSSHAKE256S:
            case DNSKEY_ALGORITHM_MAYO1:
            case DNSKEY_ALGORITHM_MAYO2:
            case DNSKEY_ALGORITHM_MAYO3:
            case DNSKEY_ALGORITHM_MAYO5:
            case DNSKEY_ALGORITHM_CROSS_RSDP128BALANCED:
            case DNSKEY_ALGORITHM_CROSS_RSDP128FAST:
            case DNSKEY_ALGORITHM_CROSS_RSDP128SMALL:
            case DNSKEY_ALGORITHM_CROSS_RSDP192BALANCED:
            case DNSKEY_ALGORITHM_CROSS_RSDP192FAST:
            case DNSKEY_ALGORITHM_CROSS_RSDP192SMALL:
            case DNSKEY_ALGORITHM_CROSS_RSDP256BALANCED:
            // case DNSKEY_ALGORITHM_CROSS_RSDP256FAST:
            case DNSKEY_ALGORITHM_CROSS_RSDP256SMALL:
            case DNSKEY_ALGORITHM_CROSS_RSDPG128BALANCED:
            case DNSKEY_ALGORITHM_CROSS_RSDPG128FAST:
            case DNSKEY_ALGORITHM_CROSS_RSDPG128SMALL:
            case DNSKEY_ALGORITHM_CROSS_RSDPG192BALANCED:
            case DNSKEY_ALGORITHM_CROSS_RSDPG192FAST:
            case DNSKEY_ALGORITHM_CROSS_RSDPG192SMALL:
            case DNSKEY_ALGORITHM_CROSS_RSDPG256BALANCED:
            case DNSKEY_ALGORITHM_CROSS_RSDPG256FAST:
            case DNSKEY_ALGORITHM_CROSS_RSDPG256SMALL:
            {
                if(FAIL(ret = dnskey_postquantumsafe_newinstance(size, algorithm, flags, clean_origin, &key)))
                {
                    return ret;
                }

                break;
            }
#endif
#ifdef DNSKEY_ALGORITHM_DUMMY
            case DNSKEY_ALGORITHM_DUMMY:
            {
                if(FAIL(return_value = dnskey_dummy_newinstance(size, algorithm, flags, clean_origin, &key)))
                {
                    return return_value;
                }
            }
#endif
            default:
            {
                return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
            }
        }

        if(smart_fields != NULL)
        {
            if(smart_fields->fields & DNSKEY_KEY_HAS_SMART_FIELD_CREATED)
            {
                dnskey_set_created_epoch(key, smart_fields->created_epoch);
            }
            if(smart_fields->fields & DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH)
            {
                dnskey_set_publish_epoch(key, smart_fields->publish_epoch);
            }
            if(smart_fields->fields & DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE)
            {
                dnskey_set_activate_epoch(key, smart_fields->activate_epoch);
            }
            if(smart_fields->fields & DNSKEY_KEY_HAS_SMART_FIELD_INACTIVE)
            {
                dnskey_set_inactive_epoch(key, smart_fields->deactivate_epoch);
            }
            if(smart_fields->fields & DNSKEY_KEY_HAS_SMART_FIELD_DELETE)
            {
                dnskey_set_delete_epoch(key, smart_fields->unpublish_epoch);
            }
        }

        dnskey_t *same_tag_key = NULL;

        dnskey_get_tag(key); // updates the tag field if needed

        if(ISOK(ret = dnssec_keystore_load_private_key_from_parameters(algorithm, key->tag, flags, fqdn, &same_tag_key))) // key properly released
        {
            dnskey_release(same_tag_key); // the key already exists in the keystore : tag collision

            if(dnscore_shuttingdown()) // else it may loop forever
            {
                return STOPPED_BY_APPLICATION_SHUTDOWN;
            }
        }
        else
        {
            // the key already exists in the keystore

            if(ISOK(ret = dnssec_keystore_store_private_key(key)))
            {
                if(ISOK(ret = dnssec_keystore_store_public_key(key)))
                {
                    dnssec_keystore_add_key(key);
                }
                else
                {
                    dnssec_keystore_delete_key_files(key);
                }
            }

            if(FAIL(ret))
            {
                dnssec_keystore_remove_key(key);
                dnskey_release(key);
                key = NULL;
            }

            break;
        }

        dnskey_release(key);
    }

    *out_key = key;

    return ret;
}

/**
 * Loads a public key from the rdata, store in the keystore, then sets out_key to point to it
 *
 * RC ok
 *
 * @param rdata
 * @param rdata_size
 * @param origin
 * @param out_key
 * @return
 */

ya_result dnssec_keystore_load_public_key_from_rdata(const uint8_t *rdata, uint16_t rdata_size, const uint8_t *fqdn, dnskey_t **out_key)
{
    // u16 flags = DNSKEY_FLAGS_FROM_RDATA(rdata);
    // uint8_t algorithm = rdata[3];

    uint16_t  tag = dnskey_get_tag_from_rdata(rdata, rdata_size);

    ya_result ret = SUCCESS;

    dnskey_t *key = dnssec_keystore_acquire_key_from_fqdn_with_tag(fqdn, tag);

    if(key == NULL)
    {
        if(ISOK(ret = dnskey_new_from_rdata(rdata, rdata_size, fqdn, &key))) // RC
        {
            if(!dnssec_keystore_add_key(key)) // RC
            {
                dnskey_release(key);

                key = dnssec_keystore_acquire_key_from_fqdn_with_tag(fqdn, tag);

                if(key == NULL) // should not happen
                {
                    ret = ERROR;
                }
            }
        }
    }

    *out_key = key; // already RCed at instantiation

    return ret;
}

/**
 *  Loads a private key from the disk or the keystore, then returns it.
 *  NOTE: If the key already existed as a public-only key, the public version is released.
 *
 * RC ok
 *
 * @param algorithm
 * @param tag
 * @param flags
 * @param origin
 * @param out_key
 * @return the number of keys loaded by the call (1 or 0) or an error code
 */

ya_result dnssec_keystore_load_private_key_from_rdata(const uint8_t *rdata, uint16_t rdata_size, const uint8_t *fqdn, dnskey_t **out_key)
{
    if(rdata_size < 4)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    uint16_t  tag = dnskey_get_tag_from_rdata(rdata, rdata_size);
    uint16_t  flags = GET_U16_AT_P(rdata);
    uint8_t   algorithm = rdata[3];

    ya_result ret = dnssec_keystore_load_private_key_from_parameters(algorithm, tag, flags, fqdn, out_key);

    return ret;
}

/**
 *  Loads a private key from the disk or the keystore, then returns it.
 *  NOTE: If the key already existed as a public-only key, the public version is released.
 *
 * RC ok
 *
 * @param algorithm
 * @param tag
 * @param flags
 * @param origin
 * @param out_key
 * @return SUCCESS if a key is loaded, 1 if the key was already loaded, or an error code
 */

ya_result dnssec_keystore_load_private_key_from_parameters(uint8_t algorithm, uint16_t tag, uint16_t flags, const uint8_t *fqdn, dnskey_t **out_key)
{
    dnskey_t *key = dnssec_keystore_acquire_key_from_fqdn_with_tag(fqdn, tag);
    ya_result ret;
    bool      has_public_key = false;

    *out_key = NULL;

    if(key != NULL && !dnskey_is_private(key))
    {
        log_debug("dnskey_load_private: %{dnsname} +%03d+%05d/%d is not private", fqdn, algorithm, tag, ntohs(flags));

        has_public_key = true;
        dnskey_release(key);
        key = NULL;
    }

    if(key == NULL)
    {
        // the key is not loaded already

        /* Load from the disk, add to the keystore */

        char fqdn_text[DOMAIN_TEXT_BUFFER_SIZE];
        cstr_init_with_dnsname(fqdn_text, fqdn);

        char path[PATH_MAX];
        path[0] = '\0';

        if(FAIL(ret = dnssec_keystore_get_key_path_with_parameters(fqdn_text, algorithm, tag, path, sizeof(path), true)))
        {
            /* Path bigger than PATH_MAX */
            return ret;
        }

        log_debug("dnskey_load_private: %{dnsname} +%03d+%05d/%d: opening file '%s'", fqdn, algorithm, tag, ntohs(flags), path);

        ret = dnskey_new_private_key_from_file(path, &key); // RC

        if(ISOK(ret))
        {
            if(has_public_key)
            {
                /*
                 * remove the old (public) version
                 */

                log_debug("dnskey_load_private: %{dnsname} +%03d+%05hd/%hd: replacing previous version with loaded key", fqdn, algorithm, tag, ntohs(flags));

                dnssec_keystore_replace_key(key); // RC
            }
            else
            {
                log_debug("dnskey_load_private: %{dnsname} +%03d+%05hd/%hd: adding loaded key", fqdn, algorithm, tag, ntohs(flags));

                dnssec_keystore_add_key(key); // RC
            }

            log_info("dnssec: loaded private key: %{dnsname} +%03d+%05hd/%hd from '%s'", fqdn, algorithm, tag, ntohs(flags), path);

            *out_key = key;
            ret = 1; // newly loaded
        }
        else
        {
            log_debug("dnskey_load_private: %{dnsname} +%03d+%05hd/%hd: could not load the key: %r", fqdn, algorithm, tag, ntohs(flags), ret);
        }
    }
    else
    {
        *out_key = key;
        ret = 0; // already loaded
    }

    return ret;
}

ya_result dnssec_keystore_store_private_key(dnskey_t *key)
{
    ya_result ret;
    char      path[PATH_MAX];

    if(key == NULL || key->key.any == NULL || key->origin == NULL || !dnskey_is_private(key))
    {
        return DNSSEC_ERROR_INCOMPLETEKEY;
    }

    if(FAIL(ret = dnssec_keystore_get_key_path(key, path, sizeof(path), true)))
    {
        return ret;
    }

    switch(key->algorithm)
    {
        case DNSKEY_ALGORITHM_RSASHA1:
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
        case DNSKEY_ALGORITHM_DSASHA1:
        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_ECDSAP256SHA256:
        case DNSKEY_ALGORITHM_ECDSAP384SHA384:
        case DNSKEY_ALGORITHM_ED25519:
        case DNSKEY_ALGORITHM_ED448:
#ifdef DNSKEY_ALGORITHM_DUMMY
        case DNSKEY_ALGORITHM_DUMMY:
#endif
        {
            break;
        }
        default:
        {
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
        }
    }

    ret = dnskey_store_private_key_to_file(key, path);

    return ret;
}

ya_result dnssec_keystore_store_public_key(dnskey_t *key)
{
    ya_result ret;
    char      path[PATH_MAX];

    dnskey_get_tag(key); // updates the tag field if needed

    if(FAIL(ret = dnssec_keystore_get_key_path(key, path, sizeof(path), false)))
    {
        /* Path bigger than PATH_MAX */
        return ret;
    }

    FILE *f;

    if((f = fopen(path, "w+b")) == NULL)
    {
        return DNSSEC_ERROR_UNABLETOCREATEKEYFILES;
    }

    uint32_t    lc = 1;
    const char *p = key->origin;
    char        c;
    while((c = *p) != '\0')
    {
        if(c == '.')
        {
            lc++;
        }
        p++;
    }

    fprintf(f, "%s IN DNSKEY %u %u %u ", key->origin, ntohs(key->flags), lc, key->algorithm);

    uint8_t *rdata;
    uint32_t rdata_size = key->vtbl->dnskey_rdatasize(key);

    MALLOC_OR_DIE(uint8_t *, rdata, rdata_size, DNSKEY_RDATA_TAG);

    /* store the RDATA */

    key->vtbl->dnskey_writerdata(key, rdata, rdata_size);

    char     b64[BASE64_ENCODED_SIZE(4096)];

    uint8_t *ptr = rdata + 4;
    rdata_size -= 4;

    uint32_t n = base64_encode(ptr, rdata_size, b64);
    if(fwrite(b64, n, 1, f) == 1)
    {
        ret = SUCCESS;
    }
    else
    {
        ret = DNSSEC_ERROR_KEYWRITEERROR;
    }

    fprintf(f, "\n");

    free(rdata);

    fclose(f);

    if(FAIL(ret))
    {
        unlink(path);
    }

    return ret;
}

/**
 * Adds all the valid keys of the domain in the keyring
 *
 * @param fqdn the domain name
 * @param at_time the epoch at which the test is done ie: time(NULL)
 * @param kr the target keyring
 */

uint32_t dnssec_keystore_add_valid_keys_from_fqdn(const uint8_t *fqdn, time_t at_time, struct dnskey_keyring_s *kr)
{
    dnssec_keystore *ks = &g_keystore;
    uint32_t         count = 0;
    mutex_lock(&ks->lock);
    dnssec_keystore_domain_s *ks_domain = dnssec_keystore_get_domain_nolock(ks, fqdn); // locked
    if(ks_domain != NULL)
    {
        dnskey_t *key = ks_domain->key_chain;

        while(key != NULL)
        {
            time_t from = (key->epoch_activate == 0) ? 1 : key->epoch_activate;
            time_t to = (key->epoch_inactive == 0) ? INT32_MAX : key->epoch_inactive;
            if(from <= at_time && to >= at_time)
            {
                if(ISOK(dnskey_keyring_add(kr, key)))
                {
                    ++count;
                }
            }

            key = key->next;
        }
    }
    mutex_unlock(&ks->lock);
    return count;
}

/**
 * Returns all the active keys, chained in a single linked list whose nodes need to be freed,
 *
 * @param zone
 * @param out_keys
 * @param out_ksk_count
 * @param out_zsk_count
 * @return
 */

ya_result zdb_zone_get_active_keys(zdb_zone_t *zone, dnskey_sll **out_keys, int *out_ksk_count, int *out_zsk_count)
{
    ya_result                  ret = SUCCESS;
    int                        ksk_count = 0;
    int                        zsk_count = 0;

    zdb_resource_record_set_t *dnskey_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_DNSKEY); // zone is locked

    if(dnskey_rrset == NULL)
    {
        if(out_ksk_count != NULL)
        {
            *out_ksk_count = 0;
        }

        if(out_zsk_count != NULL)
        {
            *out_zsk_count = 0;
        }

        if(out_keys != NULL)
        {
            *out_keys = NULL;
        }

        return DNSSEC_ERROR_RRSIG_NOZONEKEYS;
    }

    dnskey_sll                      *keys = NULL;

    zdb_resource_record_set_iterator iter;
    zdb_resource_record_set_iterator_init(dnskey_rrset, &iter);
    while(zdb_resource_record_set_iterator_has_next(&iter))
    {
        zdb_resource_record_data_t *dnskey_record = zdb_resource_record_set_iterator_next(&iter);

        uint8_t                     algorithm = DNSKEY_ALGORITHM(dnskey_record);
        uint16_t                    tag = DNSKEY_TAG(dnskey_record);
        uint16_t                    flags = DNSKEY_FLAGS(dnskey_record);

        if((flags != DNSKEY_FLAGS_KSK) && (flags != DNSKEY_FLAGS_ZSK))
        {
            // ignore the key
            log_debug("rrsig: %{dnsname}: key with private key algorithm=%d tag=%05d flags=%3d is ignored (flags)", zone->origin, algorithm, tag, ntohs(flags));

            continue;
        }

        dnskey_t *priv_key;
        // from disk or from global keyring
        ret = dnssec_keystore_load_private_key_from_parameters(algorithm, tag, flags, zone->origin, &priv_key); // converted, key put in a collection or released

        if(ISOK(ret))
        {
            yassert(priv_key != NULL);

            if(dnskey_is_activated(priv_key, time(NULL)))
            {
                log_debug("rrsig: %{dnsname}: private key algorithm=%d tag=%05d flags=%3d is active", zone->origin, algorithm, tag, ntohs(flags));

                /*
                 * We can sign with this key : chain it
                 */

                if(flags == DNSKEY_FLAGS_KSK)
                {
                    ++ksk_count;
                }
                else if(flags == DNSKEY_FLAGS_ZSK)
                {
                    ++zsk_count;
                }
                else
                {
                    // not a KSK nor a ZSK
                }

                if(out_keys != NULL)
                {
                    dnskey_sll *key_node;
                    ZALLOC_OBJECT_OR_DIE(key_node, dnskey_sll, DNSSEC_KEY_SLL_TAG);
                    key_node->next = keys;
                    key_node->key = priv_key;
                    keys = key_node;
                }
                else
                {
                    dnskey_release(priv_key);
                }
            }
            else
            {
                log_debug("rrsig: %{dnsname}: private key algorithm=%d tag=%05d flags=%3d is not active", zone->origin, algorithm, tag, ntohs(flags));
                dnskey_release(priv_key);
            }
        }
        else
        {
            yassert(priv_key == NULL);
        }
    }

    if(out_ksk_count != NULL)
    {
        *out_ksk_count = ksk_count;
    }

    if(out_zsk_count != NULL)
    {
        *out_zsk_count = zsk_count;
    }

    if(out_keys != NULL)
    {
        *out_keys = keys;
    }

    ret = ksk_count + zsk_count;

    return ret;
}

/**
 *
 * @param keys
 */

void zdb_zone_release_active_keys(dnskey_sll *keys)
{
    while(keys != NULL)
    {
        dnskey_release(keys->key);
        dnskey_sll *tmp = keys;
        keys = keys->next;
        ZFREE_OBJECT(tmp);
    }
}

/** @} */
