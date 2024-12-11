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
 * @defgroup dnskey DNSSEC keyring functions
 * @ingroup dnsdbdnssec
 * @brief
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnscore/dnskey.h>
#include <dnscore/host_address.h>

/**
 * A collection of keys for a given domain.
 * Keys are discriminated by their key ID.
 * Key ID being unique per domain, this is not a limitation.
 */

struct dnskey_keyring_s
{
    mutex_t       mtx;
    u32_treemap_t tag_to_key;
};

typedef struct dnskey_keyring_s dnskey_keyring_t;

#define EMPTY_DNSKEY_KEYRING {MUTEX_INITIALIZER, U32_TREEMAP_EMPTY}

/**
 * Collection of keys.
 * Uses RC mechanisms.
 * One keyring per domain.
 *
 * @param ks
 * @return
 */

ya_result dnskey_keyring_init(dnskey_keyring_t *ks);
void      dnskey_keyring_finalize(dnskey_keyring_t *ks);
ya_result dnskey_keyring_add(dnskey_keyring_t *ks, dnskey_t *key);
ya_result dnskey_keyring_add_from_nameserver(dnskey_keyring_t *ks, const host_address_t *ha, const uint8_t *domain);
bool      dnskey_keyring_remove(dnskey_keyring_t *ks, uint8_t algorithm, uint16_t tag, const uint8_t *domain);

#define KEYRING_TAG 0x00474e4952494548

static inline dnskey_keyring_t *dnskey_keyring_new()
{
    dnskey_keyring_t *ks;
    ZALLOC_OBJECT_OR_DIE(ks, dnskey_keyring_t, KEYRING_TAG);
    dnskey_keyring_init(ks);
    return ks;
}

static inline void dnskey_keyring_free(dnskey_keyring_t *ks)
{
    if(ks != NULL)
    {
        dnskey_keyring_finalize(ks);
        ZFREE_OBJECT(ks);
    }
}

/**
 *
 * Returns true iff the keyring contains a key matching the parameters
 *
 * @param ks
 * @param algorithm
 * @param tag
 * @param domain
 * @return
 */

bool      dnskey_keyring_has_key(dnskey_keyring_t *ks, uint8_t algorithm, uint16_t tag, const uint8_t *domain);
dnskey_t *dnskey_keyring_acquire(dnskey_keyring_t *ks, uint8_t algorithm, uint16_t tag, const uint8_t *domain);
void      dnskey_keyring_destroy(dnskey_keyring_t *ks);
bool      dnskey_keyring_isempty(dnskey_keyring_t *ks);

dnskey_t *dnskey_keyring_acquire_key_at_index(dnskey_keyring_t *ks, int index);

/** @} */
