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

#define DNSKEY_TAG(x__)        (dnskey_get_key_tag_from_rdata(&(x__).rdata_start[0],(x__).rdata_size))

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


union dnssec_key_data
{
    void* any;
    RSA* rsa;
    DSA* dsa;

};

typedef union dnssec_key_data dnssec_key_data;

typedef struct dnssec_key dnssec_key;

#define DNSKEY_KEY_IS_PRIVATE       1
#define DNSKEY_KEY_TAG_SET          2 // not always needed
#define DNSKEY_KEY_IS_FROM_DISK     4 // for generated keys
#define DNSKEY_KEY_IS_MARKED        8 // for marking a key (key manager update algorithm)
#define DNSKEY_KEY_IS_VALID        16 // the key is public with all its fields set

/* Hash should be tag<<8 | algorithm */
struct dnssec_key
{
    struct dnssec_key* next;
    const dnssec_key_vtbl* vtbl;
    char* origin;
    u8* owner_name;		// = zone origin

    dnssec_key_data key;	// RSA* or DSA*
    s64     timestamp;          // The time the key has been loaded from disk (to avoid reloading)
    int	    nid;		// NID_sha1, NID_md5
    
    u32 epoch_created;
    u32 epoch_publish;          // if not published yet, at that time, it needs to be added in the zone
    u32 epoch_activate;         // if not activated yet, at that time, it needs to be used for signatures
    u32 epoch_revoke;           // not handled yet
    u32 epoch_inactive;         // if active, at that time, it needs to stop being used for signatures
    u32 epoch_delete;           // if still in the zone, at that time, it needs to be removed from the zone
    
    u16 flags;
    u16 tag;
    u8 algorithm;
    int status;
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

/**
 * Generate a (public) key using the RDATA
 * 
 * @param rdata
 * @param rdata_size
 * @param origin
 * @param out_key
 * @return 
 */

ya_result dnskey_new_from_rdata(const u8 *rdata, u16 rdata_size, const char *origin, dnssec_key **out_key);

void dnskey_free(dnssec_key *key);

u16 dnssec_key_get_tag(dnssec_key *key);
u8 dnssec_key_get_algorithm(dnssec_key *key);
const u8 *dnssec_key_get_domain(dnssec_key *key);
bool dnssec_key_is_private(dnssec_key *key);

/**
 * Adds/Remove a key from a key chain.
 * The 'next' field of the key is used.
 * A key can only be in one chain at a time.
 * This is meant to be used in the keystore.
 * 
 * @param keyp
 */

void dnskey_key_add_in_chain(dnssec_key *key, dnssec_key **keyp);

/**
 * Adds/Remove a key from a key chain.
 * The 'next' field of the key is used.
 * A key can only be in one chain at a time.
 * This is meant to be used in the keystore.
 * 
 * @param keyp
 */

void dnskey_key_remove_from_chain(dnssec_key *key, dnssec_key **keyp);

/** Key tag */
u16 dnskey_get_key_tag_from_rdata(const u8* dnskey_rdata,u32 dnskey_rdata_size);

// For compatibility with <= 2.1.4
static inline u16 dnskey_getkeytag(const u8* dnskey_rdata,u32 dnskey_rdata_size)
{
    u16 ret = dnskey_get_key_tag_from_rdata(dnskey_rdata, dnskey_rdata_size);
    return ret;
}

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
unsigned int dnskey_get_key_tag_from_rdata_reference(unsigned char key[],  /* the RDATA part of the DNSKEY RR */
                                                     unsigned int keysize  /* the RDLENGTH */
                                                    );

/**
 * Generate the RDATA of a DS records using the RDATA from a DSNKEY record
 * 
 * @param digest_type the type of DS
 * @param dnskey_fqdn the domain of the record
 * @param dnskey_rdata the rdata of the DNSKEY
 * @param dnskey_rdata_size the size of the rdata of the DNSKEY
 * @param out_rdata the output buffer that has to be the right size (known given digest_type)
 * @return 
 */

ya_result dnskey_generate_ds_rdata(u8 digest_type, const u8 *dnskey_fqdn, const u8 *dnskey_rdata,u16 dnskey_rdata_size, u8 *out_rdata);

/**
 * 
 * Compares two keys for equality
 * 
 * @param a
 * @param b
 * @return 
 */

bool dnssec_key_equals(dnssec_key* a, dnssec_key* b);

///////////////////////////////////////////////////////////////////////////////

ya_result dnskey_digest_init(digest_s *ctx, u8 algorithm);

/**
 * 
 * @param f_ output file
 * @param num_ the number to write
 * @param tmp_in_ temporary buffer
 * @param tmp_in_size temporary buffer size
 * @param tmp_out_ output buffer
 * @param tmp_out_size output buffer size
 * @return 
 */

ya_result dnskey_write_bignum_as_base64(FILE *f_, const BIGNUM* num_, u8 *tmp_in_, u32 tmp_in_size, char *tmp_out_, u32 tmp_out_size);

/**
 * Returns the most relevant publication time.
 * 
 * publish > activate > created > now
 * 
 * @param key
 * @return 
 */

u32 dnskey_get_publish_epoch(dnssec_key *key);

/**
 * Returns the most relevant activation time.
 * 
 * activate > publish > created > now
 * 
 * @param key
 * @return 
 */

u32 dnskey_get_activate_epoch(dnssec_key *key);

/**
 * Returns the most relevant revocation time.
 * 
 * revoke > never
 * 
 * @param key
 * @return 
 */

u32 dnskey_get_revoke_epoch(dnssec_key *key);

/**
 * Returns the most relevant inactivation time.
 * 
 * inactive > delete > never
 * 
 * @param key
 * @return 
 */

u32 dnskey_get_inactive_epoch(dnssec_key *key);

/**
 * Returns the most relevant delete time.
 * 
 * delete > inactive > never
 * 
 * @param key
 * @return 
 */

u32 dnskey_get_delete_epoch(dnssec_key *key);

///////////////////////////////////////////////////////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////

#ifdef	__cplusplus
}
#endif

#endif	/* _DNSKEY_H */


/** @} */

/*----------------------------------------------------------------------------*/

