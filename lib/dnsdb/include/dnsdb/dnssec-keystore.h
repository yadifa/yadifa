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

/** @defgroup dnskey DNSSEC keys functions
 *  @ingroup dnsdbdnssec
 *  @brief 
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
 */

#pragma once

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <openssl/engine.h>

#include <dnscore/sys_types.h>
#include <dnscore/dnskey.h>
#include <dnsdb/zdb_zone.h>

#if !ZDB_HAS_DNSSEC_SUPPORT
#error "Please do not include dnssec_keystore.h if ZDB_HAS_DNSSEC_SUPPORT is 0 (Not NSEC3 nor NSEC)"
#endif


#ifdef	__cplusplus
extern "C" {
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

void dnssec_keystore_add_domain(const u8 *domain, const char *path);

/**
 * Remove the knowledge of domain<->path
 * 
 * @param ks
 * @param domain
 * @param path
 */

void dnssec_keystore_remove_domain(const u8 *domain, const char *path);

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
 * @return TRUE iff the key was added
 */

bool dnssec_keystore_add_key(dnssec_key *key);

/**
 * 
 * Replace a key from the keystore, release the replaced key
 * 
 * RC ok
 * 
 * @param ks
 * @param key
 * 
 * @return TRUE iff the key was added
 */

bool dnssec_keystore_replace_key(dnssec_key *key);

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

dnssec_key *dnssec_keystore_remove_key(dnssec_key *key);

/**
 * Removes a key from the keystore, if possible.
 * Renames both key files adding suffix of the creation time plus bak
 * Does not return any error code as it's a best effort kind of thing.
 * 
 * @param key
 */

void dnssec_keystore_delete_key(dnssec_key *key);

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

dnssec_key *dnssec_keystore_acquire_key_from_fqdn_with_tag(const u8 *domain, u16 tag);

/**
 * Returns the nth key from the domain or NULL if no such key exist
 * 
 * RC ok
 * 
 * @return a dnskey
 */

dnssec_key *dnssec_keystore_acquire_key_from_fqdn_by_index(const u8 *domain, int idx);

/**
 * Returns TRUE iff the domain has an activaed KSK with its private part loaded.
 */

bool dnssec_keystore_has_usable_ksk(const u8 *domain, time_t attime);

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

bool dnssec_keystore_is_key_active(const u8 *domain, u8 algorithm, u16 tag, time_t now);

/**
 * Acquires all the currently activated keys and store them to the appropriate
 * KSK or ZSK collection ptr_vector.
 * 
 * @param domain
 * @param ksks
 * @param zsks
 * @return 
 */

int dnssec_keystore_acquire_activated_keys_from_fqdn_to_vectors(const u8 *domain, ptr_vector *ksks, ptr_vector *zsks);

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

int dnssec_keystore_acquire_published_keys_from_fqdn_to_vectors(const u8 *domain, ptr_vector *ksks, ptr_vector *zsks);

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

int dnssec_keystore_acquire_publish_delete_keys_from_fqdn_to_vectors(const u8 *domain, ptr_vector *publish_keys, ptr_vector *delete_keys);
/**
 * Releases all the keys from a vector.
 * 
 * @param keys
 */

void dnssec_keystore_release_keys_from_vector(ptr_vector *keys);

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

dnssec_key *dnssec_keystore_acquire_key_from_name(const char *domain, u16 tag);

/**
 * Returns the nth key from the domain or NULL if no such key exist
 * 
 * RC ok
 * 
 * @return a dnskey
 */

dnssec_key *dnssec_keystore_acquire_key_from_name_by_index(const char *domain, int idx);

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

ya_result dnssec_keystore_reload_domain(const u8 *fqdn);

/**
 * Adds all the valid keys of the domain in the keyring
 * 
 * @param fqdn the domain name
 * @param at_time the epoch at which the test is done ie: time(NULL)
 * @param kr the target keyring
 * 
 * @return the number of keys effectively added in the keyring
 */

u32 dnssec_keystore_add_valid_keys_from_fqdn(const u8 *fqdn, time_t at_time, struct dnskey_keyring *kr);

////////////////////////////////////////////////////////

void dnssec_keystore_resetpath();

const char *dnssec_keystore_getpath();
void dnssec_keystore_setpath(const char* path);

/*
ya_result	dnssec_keystore_add(dnssec_key* key);
dnssec_key*	dnssec_keystore_get(u8 algorithm,u16 tag,u16 flags,const char *origin);
dnssec_key*	dnssec_keystore_remove(u8 algorithm,u16 tag,u16 flags,const char *origin);
*/
void dnssec_keystore_destroy();
 
/** Generates a private key, store in the keystore */
ya_result dnssec_keystore_new_key(u8 algorithm, u32 size, u16 flags, const char *origin, dnssec_key **out_key);


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

ya_result dnssec_keystore_load_public_key_from_rdata(const u8 *rdata, u16 rdata_size, const u8 *origin, dnssec_key **out_key);

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

ya_result dnssec_keystore_load_private_key_from_rdata(const u8 *rdata, u16 rdata_size, const u8 *fqdn, dnssec_key **out_key);

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

ya_result	dnssec_keystore_load_private_key_from_parameters(u8 algorithm, u16 tag, u16 flags, const u8 *fqdn, dnssec_key **out_key);

/** Writes the key into g_keystore_path (which should be changed to whatever is the right path of the key */
ya_result	dnssec_keystore_store_private_key(dnssec_key *key);

/** Writes the key into g_keystore_path (which should be changed to whatever is the right path of the key */
ya_result	dnssec_keystore_store_public_key(dnssec_key *key);
/*
void		dnssec_key_addrecord_to_zone(dnssec_key* key, zdb_zone* zone);
*/

dnssec_key     *dnssec_keystore_acquire_key_from_fqdn_at_index(const u8 *domain, int index);

/**
 * Returns all the active keys, chained in a single linked list whose nodes need to be freed,
 * 
 * @param zone
 * @param out_keys
 * @param out_ksk_count
 * @param out_zsk_count
 * @return 
 */

ya_result zdb_zone_get_active_keys(zdb_zone *zone, dnssec_key_sll **out_keys, int *out_ksk_count, int *out_zsk_count);

/**
 * 
 * @param keys
 */

void zdb_zone_release_active_keys(dnssec_key_sll *keys);

#ifdef	__cplusplus
}
#endif

/** @} */

