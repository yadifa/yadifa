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
* DOCUMENTATION */
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
#include <dnsdb/btree.h>
#include <dnsdb/zdb_zone.h>

#if ZDB_DNSSEC_SUPPORT == 0
#error "Please do not include dnssec_keystore.h if ZDB_DNSSEC_SUPPORT is 0 (Not NSEC3 nor NSEC)"
#endif


#ifdef	__cplusplus
extern "C" {
#endif

#define DNSKEY_RDATA_TAG 0x445259454b534e44 /* DNSKEYRD */

typedef struct dnssec_key_vtbl dnssec_key_vtbl;


typedef struct dnssec_key_contextmethods dnssec_key_contextmethods;


struct dnssec_key_vtbl;

union dnssec_key_key_types
{
    void* any;
    RSA* rsa;
    DSA* dsa;
};

typedef union dnssec_key_key_types dnssec_key_key_types;

typedef struct dnssec_key dnssec_key;


/* Hash should be tag<<8 | algorithm */
struct dnssec_key
{
    struct dnssec_key* next;
    dnssec_key_vtbl* vtbl;
    char* origin;
    u8* owner_name;		/* = zone origin */

    dnssec_key_key_types key;	/* RSA* or DSA* */
    int	    nid;		/* NID_sha1, NID_md5 */

    u16 flags;
    u16 tag;
    u8 algorithm;
    bool is_private;    /* Because I'll probably allow to put public keys here, later ... */

    /*
     * Later, add a list of (wannabe) signers and for each of these
     * if said signature has been verified, not verified or is wrong
     */
};

typedef struct dnssec_key_sll dnssec_key_sll;


struct dnssec_key_sll
{
    struct dnssec_key_sll* next;
    dnssec_key* key;
};

typedef void dnskey_key_free_method(dnssec_key* key);
typedef u32 dnskey_key_rdatasize_method(dnssec_key* key);
typedef u32 dnskey_key_writerdata_method(dnssec_key* key,u8* output);
typedef ya_result dnssec_key_sign_digest_method(dnssec_key* key,u8* digest,u32 digest_len,u8* output);
typedef bool dnssec_key_verify_digest_method(dnssec_key* key,u8* digest,u32 digest_len,u8* signature,u32 signature_len);

struct dnssec_key_vtbl
{
    dnssec_key_sign_digest_method* dnssec_key_sign_digest;
    dnssec_key_verify_digest_method* dnssec_key_verify_digest;
    dnskey_key_rdatasize_method* dnskey_key_rdatasize;
    dnskey_key_writerdata_method* dnskey_key_writerdata;
    dnskey_key_free_method* dnskey_key_free;
};

typedef btree dnssec_keystore;

void		dnssec_keystore_resetpath();

const char*	dnssec_keystore_getpath();
void		dnssec_keystore_setpath(const char* path);

ya_result	dnssec_keystore_add(dnssec_key* key);
dnssec_key*	dnssec_keystore_get(u8 algorithm,u16 tag,u16 flags,const char *origin);
dnssec_key*	dnssec_keystore_remove(u8 algorithm,u16 tag,u16 flags,const char *origin);
void		dnssec_keystore_destroy();

bool		dnssec_key_equals(dnssec_key* a,dnssec_key* b);

/* Tool */
dnssec_key*	dnssec_key_newemptyinstance(u8 algorithm,u16 flags,const char *origin);

/** Generates a private key, store in the keystore */
ya_result   dnssec_key_createnew(u8 algorithm,u32 size,u16 flags,const char *origin, dnssec_key **out_key);

/** Removes the key from the keystore, then deletes it */
void		dnssec_key_free(dnssec_key* key);

/** Load a public key from the rdata, then return it */

ya_result   dnskey_load_public(const u8 *rdata, u16 rdata_size, const char* origin, dnssec_key **out_key);

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

