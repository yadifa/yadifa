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
 *
 * @{
 */
#ifndef _DNSKEY_H
#define	_DNSKEY_H

#include <arpa/inet.h>
#include <openssl/engine.h>

#include <dnscore/sys_types.h>
#include <dnscore/rfc.h>
#include <dnscore/dnssec_errors.h>
#include <dnscore/u32_set.h>
#include <dnscore/digest.h>
#include <dnscore/mutex.h>

#define DNSSEC_MINIMUM_KEY_SIZE     512
#define DNSSEC_MAXIMUM_KEY_SIZE     (8192 + 128)

#define DNSSEC_DEFAULT_KEYSTORE_PATH    "."

#define DNSSEC_MINIMUM_KEY_SIZE_BYTES   ((DNSSEC_MINIMUM_KEY_SIZE+7)/8)
#define DNSSEC_MAXIMUM_KEY_SIZE_BYTES   ((DNSSEC_MAXIMUM_KEY_SIZE+7)/8)

#ifdef WORDS_BIGENDIAN
#define DNSKEY_FLAGS_KSK 0x0101 // NATIVE
#define DNSKEY_FLAGS_ZSK 0x0100 // NATIVE
#else
#define DNSKEY_FLAGS_KSK 0x0101 // NATIVE
#define DNSKEY_FLAGS_ZSK 0x0001 // NATIVE
#endif



/*
 * Extract fields from a packed record
 *
 */

#define DNSKEY_FLAGS(x__)      (ntohs(GET_U16_AT((x__).rdata_start[0]))) /// @todo 20140523 edf -- optimisation : NATIVEFLAGS
#define DNSKEY_PROTOCOL(x__)   ((x__).rdata_start[2])
#define DNSKEY_ALGORITHM(x__)  ((x__).rdata_start[3])

/*
 * Computes the key tag from a packed record
 */

#define DNSKEY_TAG(x__)        (dnskey_getkeytag(&(x__).rdata_start[0],(x__).rdata_size))

#ifdef	__cplusplus
extern "C"
{
#endif
    
#define DNSKEY_RDATA_TAG 0x445259454b534e44 /* DNSKEYRD */
    
struct structdescriptor
{
    const char* name;
    size_t address;
    int type;
};

#define STRUCTDESCRIPTOR_BN 1

struct dnssec_key_vtbl;
typedef struct dnssec_key_vtbl dnssec_key_vtbl;

typedef struct dnssec_key_contextmethods dnssec_key_contextmethods;


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
    const dnssec_key_vtbl* vtbl;
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
typedef bool dnssec_key_equals_method(dnssec_key* key_a,dnssec_key* key_b);
typedef const struct structdescriptor *dnssec_key_get_fields_descriptor_method(dnssec_key* key);
//typedef bool dnssec_key_is_private_method(dnssec_key* key);

struct dnssec_key_vtbl
{
    dnssec_key_sign_digest_method* dnssec_key_sign_digest;
    dnssec_key_verify_digest_method* dnssec_key_verify_digest;
    dnskey_key_rdatasize_method* dnskey_key_rdatasize;
    dnskey_key_writerdata_method* dnskey_key_writerdata;
    dnskey_key_free_method* dnskey_key_free;
    dnssec_key_equals_method* dnssec_key_equals;
    dnssec_key_get_fields_descriptor_method* dnssec_key_get_fields_descriptor;
    //dnssec_key_is_private_method* dnssec_key_is_private;
    const char *__class__;
};

dnssec_key *dnskey_newemptyinstance(u8 algorithm,u16 flags,const char *origin);

ya_result dnskey_new_from_rdata(const u8 *rdata, u16 rdata_size, const char *origin, dnssec_key **out_key);

void dnskey_free(dnssec_key *key);

/** Key tag */
u16 dnskey_getkeytag(const u8* dnskey_rdata,u32 dnskey_rdata_size);

static inline u16 dnskey_get_flags_from_rdata(const u8* dnskey_rdata)
{
    return GET_U16_AT_P(dnskey_rdata);
}

static inline u8 dnskey_get_protocol_from_rdata(const u8* dnskey_rdata)
{
    return dnskey_rdata[2];
}

static inline u8 dnskey_get_algorithm_from_rdata(const u8* dnskey_rdata)
{
    return dnskey_rdata[3];
}

/** Key tag */
unsigned int dnskey_getkeytag_reference(unsigned char key[],  /* the RDATA part of the DNSKEY RR */
                                        unsigned int keysize  /* the RDLENGTH */
                                       );

ya_result dnskey_digest_init(digest_s *ctx, u8 algorithm);

ya_result dnskey_generate_ds_rdata(u8 digest_type, const u8 *dnskey_fqdn, const u8 *dnskey_rdata,u16 dnskey_rdata_size, u8 *out_rdata);

/*----------------------------------------------------------------------------*/

struct dnskey_keyring
{
    mutex_t mtx;
    u32_set tag_to_key;
};

typedef struct dnskey_keyring dnskey_keyring;

#define EMPTY_DNSKEY_KEYRING {MUTEX_INITIALIZER, U32_SET_EMPTY };

ya_result       dnskey_keyring_init(dnskey_keyring *ks);
ya_result	dnskey_keyring_add(dnskey_keyring *ks, dnssec_key* key);
dnssec_key*	dnskey_keyring_get(dnskey_keyring *ks, u8 algorithm, u16 tag, const u8 *domain);
dnssec_key*	dnskey_keyring_remove(dnskey_keyring *ks, u8 algorithm, u16 tag, const u8 *domain);
void		dnskey_keyring_destroy(dnskey_keyring *ks);



static inline u16 ds_get_wire_keytag_from_rdata(const u8 *rdata)
{
    u16 ds_keytag = GET_U16_AT_P(rdata);
    return ds_keytag;
}

static inline u16 ds_get_keytag_from_rdata(const u8 *rdata)
{
    u16 ds_keytag = ntohs(ds_get_wire_keytag_from_rdata(rdata));
    return ds_keytag;
}

static inline u8 ds_get_algorithm_from_rdata(const u8 *rdata)
{
    u8  ds_algorithm = rdata[2];
    return ds_algorithm;
}

static inline u8 ds_get_digesttype_from_rdata(const u8 *rdata)
{
    u8  ds_digesttype = rdata[3];
    return ds_digesttype;
}

/// tool function

ya_result dnskey_write_bignum_as_base64(FILE *f_, BIGNUM* num_, u8 *tmp_in_, u32 tmp_in_size, char *tmp_out_, u32 tmp_out_size);


#ifdef	__cplusplus
}
#endif

#endif	/* _DNSKEY_H */


/** @} */

/*----------------------------------------------------------------------------*/

