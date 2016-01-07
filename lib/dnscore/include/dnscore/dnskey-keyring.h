/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2016, EURid. All rights reserved.
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
/** @defgroup dnskey DNSSEC keyring functions
 *  @ingroup dnsdbdnssec
 *  @brief 
 *
 *
 * @{
 */

#pragma once

#include <dnscore/dnskey.h>

struct dnskey_keyring
{
    mutex_t mtx;
    u32_set tag_to_key;
};

typedef struct dnskey_keyring dnskey_keyring;

#define EMPTY_DNSKEY_KEYRING {MUTEX_INITIALIZER, U32_SET_EMPTY };

ya_result   dnskey_keyring_init(dnskey_keyring *ks);
ya_result   dnskey_keyring_add(dnskey_keyring *ks, dnssec_key* key);
dnssec_key *dnskey_keyring_get(dnskey_keyring *ks, u8 algorithm, u16 tag, const u8 *domain);
dnssec_key *dnskey_keyring_remove(dnskey_keyring *ks, u8 algorithm, u16 tag, const u8 *domain);
void	    dnskey_keyring_destroy(dnskey_keyring *ks);

/** @} */
