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
 * @defgroup dnskey DNSSEC keys functions
 * @ingroup dnsdbdnssec
 * @brief
 *
 *  The dnssec keystore handles loading and updating of keys system-wide.
 *
 *  It is required for an efficient key management and smart signing.
 *
 *  It has knowledge of how to find keys for a zone.
 *  It has the responsibility to update the keys when asked.
 *
 *  Its responsibilities may be extended to notify the system about timings.
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include <dnscore/sys_types.h>
#include <dnscore/dnskey.h>
#include <dnsdb/zdb_zone.h>

#if !ZDB_HAS_DNSSEC_SUPPORT
#error "Please do not include dnssec_keystore.h if ZDB_HAS_DNSSEC_SUPPORT is 0 (Not NSEC3 nor NSEC)"
#endif

#ifdef __cplusplus
extern "C"
{
#endif

struct dnssec_keystore;

/**
 *
 * Initialises the keystore
 *
 * @param ks
 */

void dnssec_keystore_init();

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

void dnssec_keystore_add_domain(const uint8_t *domain, const char *path);

/**
 * Remove the knowledge of domain<->path
 *
 * @param ks
 * @param domain
 * @param path
 */

void dnssec_keystore_remove_domain(const uint8_t *domain, const char *path);

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

bool dnssec_keystore_add_key(dnskey_t *key);

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

bool dnssec_keystore_replace_key(dnskey_t *key);

/**
 *
 * Removes a key from the keystore
 * Does not releases the key
 *
 * RC ok
 *
 * @param ks
 * @param key
 *
 * @return the instance of the key from the keystore, or NULL if the key was not found
 */

dnskey_t *dnssec_keystore_remove_key(dnskey_t *key);

/**
 * Removes a key from the keystore, if possible.
 * Renames both key files adding suffix of the creation time plus bak
 * Does not return any error code as it's a best effort kind of thing.
 *
 * @param key
 */

void dnssec_keystore_delete_key(dnskey_t *key);

/**
 *
 * Retrieves a key from the keystore
 *
 * RC ok
 *
 * @param ks
 * @param domain
 * @param tag
 * @return the key or NULL if it does not exist
 */

dnskey_t *dnssec_keystore_acquire_key_from_fqdn_with_tag(const uint8_t *domain, uint16_t tag);

/**
 * Returns the nth key from the domain or NULL if no such key exist
 *
 * RC ok
 *
 * @return a dnskey
 */

dnskey_t *dnssec_keystore_acquire_key_from_fqdn_at_index(const uint8_t *domain, int idx);

/**
 * Returns true iff the domain has a KSK.
 */

bool dnssec_keystore_has_any_ksk(const uint8_t *domain);

/**
 * Returns true iff the domain has an activaed KSK loaded.
 */

bool dnssec_keystore_has_activated_ksk(const uint8_t *domain, time_t attime);

bool dnssec_keystore_has_activated_zsk(const uint8_t *domain, time_t attime);

/**
 * Returns true iff the domain has an activaed KSK with its private part loaded.
 */

bool dnssec_keystore_has_usable_ksk(const uint8_t *domain, time_t attime);

bool dnssec_keystore_has_usable_zsk(const uint8_t *domain, time_t attime);

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

bool dnssec_keystore_is_key_active(const uint8_t *domain, uint8_t algorithm, uint16_t tag, time_t now);

/**
 * Acquires all the currently activated keys and store them to the appropriate
 * KSK or ZSK collection ptr_vector.
 *
 * @param domain
 * @param ksks
 * @param zsks
 * @return
 */

int dnssec_keystore_acquire_activated_keys_from_fqdn_to_vectors(const uint8_t *domain, ptr_vector_t *ksks, ptr_vector_t *zsks);

/**
 * Acquires all the currently publishable keys and store them to the appropriate
 * KSK or ZSK collection ptr_vector.
 *
 * If no publish/delete field is available, uses active/inactive fields instead.
 * No fields means no action.
 *
 * @param domain
 * @param ksks
 * @param zsks
 * @return
 */

int dnssec_keystore_acquire_published_keys_from_fqdn_to_vectors(const uint8_t *domain, ptr_vector_t *ksks, ptr_vector_t *zsks);

/**
 * Acquires all the keys that should be published and deleted and store them to the appropriate collection ptr_vector.
 *
 * If no publish/delete field is available, uses active/inactive fields instead.
 * No fields means no action.
 *
 * @param domain
 * @param ksks
 * @param zsks
 * @return
 */

int dnssec_keystore_acquire_publish_delete_keys_from_fqdn_to_vectors(const uint8_t *domain, ptr_vector_t *publish_keys, ptr_vector_t *delete_keys);
/**
 * Releases all the keys from a vector.
 *
 * @param keys
 */

void dnssec_keystore_release_keys_from_vector(ptr_vector_t *keys);

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

dnskey_t *dnssec_keystore_acquire_key_from_name(const char *domain, uint16_t tag);

/**
 * Returns the nth key from the domain or NULL if no such key exist
 *
 * RC ok
 *
 * @return a dnskey
 */

dnskey_t *dnssec_keystore_acquire_key_from_name_by_index(const char *domain, int idx);

/**
 *
 * (Re)loads keys found in the paths of the keystore
 *
 * @param ks
 * @return
 */

ya_result dnssec_keystore_reload();

/**
 *
 * (Re)loads keys found in the path of the keystore for the specified domain
 *
 * @param fqdn
 * @return
 */

ya_result dnssec_keystore_reload_domain(const uint8_t *fqdn);

/**
 * Adds all the valid keys of the domain in the keyring
 *
 * @param fqdn the domain name
 * @param at_time the epoch at which the test is done ie: time(NULL)
 * @param kr the target keyring
 *
 * @return the number of keys effectively added in the keyring
 */

struct dnskey_keyring_s;

uint32_t dnssec_keystore_add_valid_keys_from_fqdn(const uint8_t *fqdn, time_t at_time, struct dnskey_keyring_s *kr);

////////////////////////////////////////////////////////

void        dnssec_keystore_resetpath();

const char *dnssec_keystore_getpath();
void        dnssec_keystore_setpath(const char *path);

/*
ya_result	dnssec_keystore_add(dnskey_t *key);
dnssec_key*	dnssec_keystore_get(uint8_t algorithm, uint16_t tag, uint16_t flags,const char *origin);
dnssec_key*	dnssec_keystore_remove(uint8_t algorithm, uint16_t tag, uint16_t flags,const char *origin);
*/
void dnssec_keystore_finalise();

struct dnskey_smart_fields_s
{
    uint32_t created_epoch;
    uint32_t publish_epoch;
    uint32_t activate_epoch;
    uint32_t deactivate_epoch;
    uint32_t unpublish_epoch;
    uint32_t fields;
};

typedef struct dnskey_smart_fields_s dnskey_smart_fields_t;

/**
 * Generates a private key, store in the keystore
 * The caller is expected to create a resource record with this key and add it to the owner.
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

ya_result dnssec_keystore_new_key(uint8_t algorithm, uint32_t size, uint16_t flags, const char *origin, dnskey_smart_fields_t *smart_fields, dnskey_t **out_key);

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

ya_result dnssec_keystore_load_public_key_from_rdata(const uint8_t *rdata, uint16_t rdata_size, const uint8_t *origin, dnskey_t **out_key);

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
 * @return SUCCESS if a key was loaded, 1 if the key was already loaded, or an error code
 */

ya_result dnssec_keystore_load_private_key_from_rdata(const uint8_t *rdata, uint16_t rdata_size, const uint8_t *fqdn, dnskey_t **out_key);

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
 * @return SUCCESS if a key was loaded, 1 if the key was already loaded, or an error code
 */

ya_result dnssec_keystore_load_private_key_from_parameters(uint8_t algorithm, uint16_t tag, uint16_t flags, const uint8_t *fqdn, dnskey_t **out_key);

ya_result dnssec_keystore_get_key_path(dnskey_t *key, char *buffer, size_t buffer_size, bool is_private);

/// does not remove the key from the keyring (so only call this if you know what you are doing)

ya_result dnssec_keystore_delete_key_files(dnskey_t *key);

/** Writes the key into g_keystore_path (which should be changed to whatever is the right path of the key */
ya_result dnssec_keystore_store_private_key(dnskey_t *key);

/** Writes the key into g_keystore_path (which should be changed to whatever is the right path of the key */
ya_result dnssec_keystore_store_public_key(dnskey_t *key);
/*
void dnskey_addrecord_to_zone(dnskey_t *key, zdb_zone* zone);
*/

/**
 * Returns the nth key from the domain or NULL if no such key exist
 *
 * RC ok
 *
 * @return a dnskey
 */

dnskey_t *dnssec_keystore_acquire_key_from_fqdn_at_index(const uint8_t *domain, int index);

/**
 * Returns true iff the key is contained in the key store.
 *
 * @return true iff the key is contained in the key store.
 */

bool dnssec_keystore_contains_key(dnskey_t *contained_key);

/**
 * Returns all the active keys, chained in a single linked list whose nodes need to be freed,
 *
 * @param zone
 * @param out_keys
 * @param out_ksk_count
 * @param out_zsk_count
 * @return
 */

ya_result zdb_zone_get_active_keys(zdb_zone_t *zone, dnskey_sll **out_keys, int *out_ksk_count, int *out_zsk_count);

/**
 *
 * @param keys
 */

void zdb_zone_release_active_keys(dnskey_sll *keys);

#ifdef __cplusplus
}
#endif

/** @} */
