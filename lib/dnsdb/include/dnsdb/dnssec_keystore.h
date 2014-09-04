/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
 * @{
 */
/*----------------------------------------------------------------------------*/
#ifndef _DNSSEC_KEYSTORE_H
#define	_DNSSEC_KEYSTORE_H

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <openssl/engine.h>

#include <dnscore/sys_types.h>
#include <dnscore/dnskey.h>

//#include <dnsdb/btree.h>
#include <dnsdb/zdb_zone.h>

#if ZDB_HAS_DNSSEC_SUPPORT == 0
#error "Please do not include dnssec_keystore.h if ZDB_HAS_DNSSEC_SUPPORT is 0 (Not NSEC3 nor NSEC)"
#endif


#ifdef	__cplusplus
extern "C" {
#endif
    
/**
 * Notes about the keyring:
 * 
 * It can handle keys from multiple domains.
 * It is not designed to hold thousands of keys.
 * Keys are referenced by their TAG, grouped in lists.
 * 
 */

typedef btree dnssec_keystore;

void		dnssec_keystore_resetpath();

const char*	dnssec_keystore_getpath();
void		dnssec_keystore_setpath(const char* path);

ya_result	dnssec_keystore_add(dnssec_key* key);
dnssec_key*	dnssec_keystore_get(u8 algorithm,u16 tag,u16 flags,const char *origin);
dnssec_key*	dnssec_keystore_remove(u8 algorithm,u16 tag,u16 flags,const char *origin);
void		dnssec_keystore_destroy();

bool		dnssec_key_equals(dnssec_key* a,dnssec_key* b);

/** Generates a private key, store in the keystore */
ya_result       dnssec_key_createnew(u8 algorithm,u32 size,u16 flags,const char *origin, dnssec_key **out_key);

/** Removes the key from the keystore, then deletes it */
void		dnssec_key_free(dnssec_key* key);

/** Load a public key from the rdata, then return it */

ya_result       dnskey_load_public(const u8 *rdata, u16 rdata_size, const char* origin, dnssec_key **out_key);

/**
 *  Load a private key from the disk or the keystore, then return it.
 *  NOTE: If the key already existed as a public-only key, the public version is destroyed.
 */
ya_result	dnssec_key_load_private(u8 algorithm, u16 tag,u16 flags,const char* origin, dnssec_key **out_key);
ya_result	dnssec_key_store_private(dnssec_key* key);
ya_result	dnssec_key_store_dnskey(dnssec_key* key);

void		dnssec_key_addrecord(zdb_zone* zone, dnssec_key* key);

#ifdef	__cplusplus
}
#endif

#endif	/* _DNSSEC_KEYSTORE_H */

    /*    ------------------------------------------------------------    */

/** @} */

