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
 *  @ingroup dnscore
 *  @brief 
 *
 *
 * @{
 */
#ifndef _DNSKEY_H
#define	_DNSKEY_H

#include <arpa/inet.h>
#include <dnscore/sys_types.h>
#include <dnscore/rfc.h>
#include <dnscore/dnssec_errors.h>
#include <dnscore/u32_set.h>
#include <dnscore/digest.h>
#include <dnscore/mutex.h>
#include <dnscore/output_stream.h>
#include "dns_resource_record.h"

#define DNSSEC_MINIMUM_KEY_SIZE     512             // bits
#define DNSSEC_MAXIMUM_KEY_SIZE     (8192 + 128)    // bits

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

#define DNSKEY_FLAGS_FROM_RDATA(x__) (GET_U16_AT(((u8*)(x__))[0]))

#define DNSKEY_FLAGS(x__)      (GET_U16_AT((x__).rdata_start[0]))
#define DNSKEY_PROTOCOL(x__)   ((x__).rdata_start[2])
#define DNSKEY_ALGORITHM(x__)  ((x__).rdata_start[3])

/*
 * Computes the key tag from a packed record
 */

#define DNSKEY_TAG(x__)        (dnskey_get_tag_from_rdata(&(x__).rdata_start[0],(x__).rdata_size))

#ifdef	__cplusplus
extern "C"
{
#endif
    
#define DNSKEY_RDATA_TAG 0x445259454b534e44 /* DNSKEYRD */

#define DNSKEY_FEATURE_NSEC_CAPABLE     1
#define DNSKEY_FEATURE_NSEC3_CAPABLE    2
#define DNSKEY_FEATURE_ZONE_SIGNATURE  16

#define DNSKEY_FEATURE_ZONE_NSEC   (DNSKEY_FEATURE_NSEC_CAPABLE|DNSKEY_FEATURE_ZONE_SIGNATURE)
#define DNSKEY_FEATURE_ZONE_NSEC3  (DNSKEY_FEATURE_NSEC3_CAPABLE|DNSKEY_FEATURE_ZONE_SIGNATURE)
#define DNSKEY_FEATURE_ZONE_MODERN (DNSKEY_FEATURE_NSEC_CAPABLE|DNSKEY_FEATURE_NSEC3_CAPABLE|DNSKEY_FEATURE_ZONE_SIGNATURE)

struct dnskey_features
{
    const char **names;
    u16 size_bits_min;
    u16 size_bits_max;
    u16 size_bits_ksk_default;
    u16 size_bits_zsk_default;
    u16 size_multiple;
    u8 algorithm;
    u8 usage;
};

typedef struct dnskey_features dnskey_features;

struct dnskey_raw_field_s
{
    u8 *buffer;
    u32 size;
};

typedef struct dnskey_raw_field_s dnskey_raw_field_t;

#define STRUCTDESCRIPTOR_NONE   0
#define STRUCTDESCRIPTOR_BN     1
#define STRUCTDESCRIPTOR_U16    2
#define STRUCTDESCRIPTOR_RAW    3

struct dnskey_field_access
{
    //const char* name;
    const char name[24];
    size_t relative;
    int type;
};

typedef struct dnskey_field_access dnskey_field_access;

struct parser_s;

ya_result dnskey_field_access_parse(const struct dnskey_field_access *sd, void *base, struct parser_s *p);
ya_result dnskey_field_access_print(const struct dnskey_field_access *sd, const void *base, output_stream *os);

struct dnssec_key_vtbl;
typedef struct dnssec_key_vtbl dnssec_key_vtbl;

typedef struct dnssec_key_contextmethods dnssec_key_contextmethods;

#ifdef SSL_API

union dnssec_key_data
{
    void* any;
    RSA* rsa;
    DSA* dsa;
#if HAS_ECDSA_SUPPORT
    EC_KEY* ec;
#endif
#if HAS_EDDSA_SUPPORT
    EVP_PKEY* ed;
#endif
};

#else
union dnssec_key_data
{
    void* any;
};

#endif

typedef union dnssec_key_data dnssec_key_data;

typedef struct dnssec_key dnssec_key;

typedef ya_result dnskey_algorithm_newinstance(u32 size, u8 algorithm, u16 flags, const char* origin, dnssec_key** out_key);

#define DNSKEY_KEY_IS_PRIVATE               0x0001
#define DNSKEY_KEY_TAG_SET                  0x0002 // not always needed
#define DNSKEY_KEY_IS_FROM_DISK             0x0004 // for generated keys
#define DNSKEY_KEY_IS_MARKED                0x0008 // for marking a key (key manager update algorithm)
#define DNSKEY_KEY_IS_VALID                 0x0010 // the key is public with all its fields set
#define DNSKEY_KEY_IS_IN_ZONE               0x0020 // the key is at the apex of its zone
#define DNSKEY_KEY_IS_ACTIVE                0x0040 // the key is already used for signature
#define DNSKEY_KEY_PUBLISH_ARMED            0x0080
#define DNSKEY_KEY_ACTIVATE_ARMED           0x0100
#define DNSKEY_KEY_DEACTIVATE_ARMED         0x0200
#define DNSKEY_KEY_DELETE_ARMED             0x0400

#define DNSKEY_KEY_HAS_SMART_FIELD_CREATED  0x0800
#define DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH  0x1000
#define DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE 0x2000
#define DNSKEY_KEY_HAS_SMART_FIELD_INACTIVE 0x4000
#define DNSKEY_KEY_HAS_SMART_FIELD_DELETE   0x8000

/* Hash should be tag<<8 | algorithm */
struct dnssec_key
{
    struct dnssec_key *next;
    const dnssec_key_vtbl *vtbl;
    char *origin;
    u8 *owner_name;		// = zone origin

    dnssec_key_data key;	// RSA* or DSA* or any crypto-lib specific pointer
    s64     timestamp;      // the file modification time of the private key (to avoid reloading)
    int	    nid;            // NID_sha1, NID_md5
    volatile int rc;
    
    time_t epoch_created;
    time_t epoch_publish;   // if not published yet, at that time, it needs to be added in the zone
    time_t epoch_activate;  // if not activated yet, at that time, it needs to be used for signatures
    time_t epoch_inactive;  // if active, at that time, it needs to stop being used for signatures
    time_t epoch_delete;    // if still in the zone, at that time, it needs to be removed from the zone
    
    u16 flags;
    u16 tag;
    u8 algorithm;
    u32 status;             // Is the key "private", has the tag been computed, ...

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

typedef void dnssec_key_free_method(dnssec_key *key);
typedef u32 dnssec_key_rdatasize_method(const dnssec_key *key);
typedef u32 dnssec_key_writerdata_method(const dnssec_key *key, u8 *output, size_t output_size);
typedef ya_result dnssec_key_sign_digest_method(const dnssec_key *key, const u8 *digest, u32 digest_len, u8 *output);
typedef bool dnssec_key_verify_digest_method(const dnssec_key *key, const u8 *digest, u32 digest_len, const u8 *signature, u32 signature_len);
typedef bool dnssec_key_equals_method(const dnssec_key *key_a, const dnssec_key *key_b);
typedef ya_result dnssec_key_private_print_fields_method(dnssec_key *key, output_stream *os);
typedef u32 dnssec_key_size_method(const dnssec_key *key);

struct dnssec_key_vtbl
{
    dnssec_key_sign_digest_method *dnssec_key_sign_digest;
    dnssec_key_verify_digest_method *dnssec_key_verify_digest;
    dnssec_key_rdatasize_method *dnssec_key_rdatasize;
    dnssec_key_writerdata_method *dnssec_key_writerdata;
    dnssec_key_free_method *dnssec_key_free;
    dnssec_key_equals_method *dnssec_key_equals;
    dnssec_key_private_print_fields_method *dnssec_key_print_fields;
    dnssec_key_size_method *dnssec_key_size;
    const char *__class__;
};

struct dnskey_field_parser;

typedef ya_result dnskey_field_parser_parse_field_method(struct dnskey_field_parser *, struct parser_s *);
typedef ya_result dnskey_field_parser_set_key_method(struct dnskey_field_parser *, dnssec_key *);
typedef void dnskey_field_parser_finalize_method(struct dnskey_field_parser *);

struct dnskey_field_parser_vtbl
{
    dnskey_field_parser_parse_field_method *parse_field;
    dnskey_field_parser_set_key_method *set_key;
    dnskey_field_parser_finalize_method *finalise;
    const char *__class__;
};

struct dnskey_field_parser
{
    void *data;
    const struct dnskey_field_parser_vtbl *vtbl;
};

typedef struct dnskey_field_parser dnskey_field_parser;


/**
 * Initialises internal structures
 */

void dnskey_init();

/**
 * Initialises an empty instance of a DNSKEY
 * No cryptographic content is put in the key.
 * Needs further setup.
 * 
 * @param algorithm the algorithm of the key.
 * @param flags the flags of the key
 * @param origin the origin of the key
 * 
 * @return a pointer to an empty instance (no real key attached) of a key.
 */

dnssec_key *dnskey_newemptyinstance(u8 algorithm,u16 flags,const char *origin);

/**
 * Generate a (public) key using the RDATA
 * 
 * @param rdata
 * @param rdata_size
 * @param origin
 * @param out_key points to  a pointer for the instantiated key
 * 
 * @return an error code (success or error)
 */

ya_result dnskey_new_from_rdata(const u8 *rdata, u16 rdata_size, const u8 *origin, dnssec_key **out_key);

/**
 * Increases the reference count on a dnssec_key
 * 
 * @param key
 */

void dnskey_acquire(dnssec_key *key);

/**
 * Releases the reference count on a dnssec_key.
 * Uses the tag, flags, algorithm, origin and key content.
 * 
 * @param a
 * @param b
 */

void dnskey_release(dnssec_key *key);

/**
 * 
 * Compares two keys for equality on a cryptographic point of view
 * Uses the tag, flags, algorithm and origin.
 * 
 * @param a
 * @param b
 * 
 * @return TRUE iff the keys are the same.
 */

bool dnskey_equals(const dnssec_key *a, const dnssec_key *b);

/**
 * 
 * Compares two keys for equality on a cryptographic point of view
 * Uses the tag, flags, algorithm, origin and public key content.
 * 
 * @param a
 * @param b
 * 
 * @return TRUE iff the keys are the same.
 */

bool dnskey_public_equals(const dnssec_key *a, const dnssec_key *b);

/**
 * Returns TRUE if the tag and algorithm of the rdata are matching the ones of the key.
 * 
 * @param key
 * @param rdata
 * @param rdata_size
 * @return 
 */

bool dnskey_matches_rdata(const dnssec_key *key, const u8 *rdata, u16 rdata_size);

/**
 * Returns TRUE if an only if the tag has already been computed and
 * stored in the dnssec key.
 * 
 * @param key
 * @return TRUE iff the tag is already known
 */

static inline bool dnssec_key_tag_field_set(const dnssec_key *key)
{
    return (key->status & DNSKEY_KEY_TAG_SET) != 0;
}

/**
 * Returns the key tag.
 * The key tag generated by this function is stored in the dnssec key to
 * make further calls instant.  This is why the parameter is not "const".
 * 
 * @param key
 * @return 
 */

u16 dnskey_get_tag(dnssec_key *key);

/**
 * Returns the key tag.
 * If the key tag is not cached in the key, computes it.
 * The tag is not cached in the key after this call.
 * 
 * @param key
 * @return 
 */

u16 dnskey_get_tag_const(const dnssec_key *key);

/**
 * Returns the algorithm of the key.
 * 
 * @param key
 * @param keyp
 */

u8 dnskey_get_algorithm(const dnssec_key *key);

/**
 * Returns a pointer to the domain of the key.
 * 
 * @param key
 * @return 
 */

const u8 *dnskey_get_domain(const dnssec_key *key);

/**
 * Returns TRUE if and only if the key is a private key.
 * 
 * @return TRUE iff the key is private.
 */

bool dnskey_is_private(const dnssec_key *key);

/**
 * Adds/Remove a key from a key chain.
 * The 'next' field of the key is used.
 * A key can only be in one chain at a time.
 * This is meant to be used in the keystore.
 * 
 * RC ok
 * 
 * @param keyp
 */

void dnskey_add_to_chain(dnssec_key *key, dnssec_key **keyp);

/**
 * Adds/Remove a key from a key chain.
 * The 'next' field of the key is used.
 * A key can only be in one chain at a time.
 * This is meant to be used in the keystore.
 * 
 * RC ok
 * 
 * @param keyp
 */

void dnskey_remove_from_chain(dnssec_key *key, dnssec_key **keyp);

/**
 * Generates a key tag from the DNSKEY RDATA wire
 * 
 * @param dnskey_rdata
 * @param dnskey_rdata_size
 * @return 
 */

u16 dnskey_get_tag_from_rdata(const u8 *dnskey_rdata, u32 dnskey_rdata_size);

/**
 * Returns the flag of a dnskey from its rdata
 * 
 * @param dnskey rdata
 * 
 * @return 
 */

static inline u16 dnskey_get_flags_from_rdata(const u8 *dnskey_rdata)
{
    return GET_U16_AT_P(dnskey_rdata);
}

/**
 * Returns the protocol of a dnskey from its rdata
 * 
 * @param dnskey rdata
 * 
 * @return 
 */

static inline u8 dnskey_get_protocol_from_rdata(const u8 *dnskey_rdata)
{
    return dnskey_rdata[2];
}

/**
 * Returns the algorithm of a dnskey from its rdata
 * 
 * @param dnskey rdata
 * 
 * @return 
 */

static inline u8 dnskey_get_algorithm_from_rdata(const u8 *dnskey_rdata)
{
    return dnskey_rdata[3];
}

/**
 * Reference implementation function to generate a key tag from the DNSKEY RDATA wire
 * 
 * @param dnskey_rdata
 * @param dnskey_rdata_size
 * @return 
 */

unsigned int dnskey_get_tag_from_rdata_reference(unsigned char key[],  /* the RDATA part of the DNSKEY RR */
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
 * Initialises the context for a key algorithm.
 * 
 * @param ctx
 * @param algorithm
 * @return 
 */

ya_result dnskey_digest_init(digest_s *ctx, u8 algorithm);

/**
 * 
 * @param os output stream
 * @param num the number to write
 * @return 
 */

ya_result dnskey_write_bignum_as_base64_to_stream(const BIGNUM *num, output_stream *os);

void dnskey_set_created_epoch(dnssec_key *key, time_t t);

/**
 * Returns the most relevant publication time.
 * 
 * publish > activate > created > now
 * 
 * @param key
 * @return 
 */

time_t dnskey_get_publish_epoch(const dnssec_key *key);
void dnskey_set_publish_epoch(dnssec_key *key, time_t t);

/**
 * Returns the most relevant activation time.
 * 
 * activate > publish > created > now
 * 
 * @param key
 * @return 
 */

time_t dnskey_get_activate_epoch(const dnssec_key *key);
void dnskey_set_activate_epoch(dnssec_key *key, time_t t);

/**
 * Returns the most relevant revocation time.
 * 
 * revoke > never
 * 
 * @param key
 * @return 
 */

time_t dnskey_get_revoke_epoch(const dnssec_key *key);
void dnskey_set_revoke_epoch(dnssec_key *key, time_t t);

/**
 * Returns the most relevant inactivation time.
 * 
 * inactive > delete > never
 * 
 * @param key
 * @return 
 */

time_t dnskey_get_inactive_epoch(const dnssec_key *key);
void dnskey_set_inactive_epoch(dnssec_key *key, time_t t);

/**
 * Returns the most relevant delete time.
 * 
 * delete > inactive > never
 * 
 * @param key
 * @return 
 */

time_t dnskey_get_delete_epoch(const dnssec_key *key);
void dnskey_set_delete_epoch(dnssec_key *key, time_t t);

ya_result dnskey_new_public_key_from_stream(input_stream *is, dnssec_key** keyp);

/**
 * Loads a public key from a file.
 * 
 * ie: Keu.+007+12345.key
 * 
 * RC ok
 * 
 * @param filename
 * @param keyp
 * @return 
 */

ya_result dnskey_new_public_key_from_file(const char *filename, dnssec_key **keyp);

ya_result dnskey_add_private_key_from_stream(input_stream *is, dnssec_key *key, const char* path, u8 algorithm);

/**
 * Loads a private key from a file.
 *  
 * ie: Keu.+007+12345.private
 * 
 * The public key must be in the same folder as the private key.
 * 
 * ie: Keu.+007+12345.key
 * 
 * RC ok
 * 
 * @param filename
 * @param keyp
 * @return 
 */

ya_result dnskey_new_private_key_from_file(const char *filename, dnssec_key **keyp);

/**
 * Returns the keytag from its DS rdata in network order
 * 
 * @param rdata
 * @return 
 */

static inline u16 ds_get_wire_keytag_from_rdata(const u8 *rdata)
{
    u16 ds_keytag = GET_U16_AT_P(rdata);
    return ds_keytag;
}

/**
 * Returns the keytag from its DS rdata
 * 
 * @param rdata
 * @return 
 */

static inline u16 ds_get_keytag_from_rdata(const u8 *rdata)
{
    u16 ds_keytag = ntohs(ds_get_wire_keytag_from_rdata(rdata));
    return ds_keytag;
}

/**
 * Returns the algorithm from its DS rdata
 * 
 * @param rdata
 * @return 
 */

static inline u8 ds_get_algorithm_from_rdata(const u8 *rdata)
{
    u8  ds_algorithm = rdata[2];
    return ds_algorithm;
}

/**
 * Returns the digest algorithm from its DS rdata
 * 
 * @param rdata
 * @return 
 */

static inline u8 ds_get_digesttype_from_rdata(const u8 *rdata)
{
    u8  ds_digesttype = rdata[3];
    return ds_digesttype;
}

/**
 *
 * Save the private part of a key to a stream
 *
 * @param key
 * @param filename
 * @return
 */

void dnskey_store_private_key_to_stream(dnssec_key *key, output_stream *os);

/**
 * 
 * Save the private part of a key to a file with the given name
 * 
 * @param key
 * @param filename
 * @return 
 */

ya_result dnskey_store_private_key_to_file(dnssec_key *key, const char *filename);

/**
 *
 * Save the public part of a key to a stream
 *
 * @param key
 * @param filename
 * @return
 */

ya_result dnskey_store_public_key_to_stream(dnssec_key *key, output_stream *os);

/**
 * 
 * Save the public part of a key to a file with the given name
 * 
 * @param key
 * @param filename
 * @return 
 */

ya_result dnskey_store_public_key_to_file(dnssec_key *key, const char *filename);

/**
 * Save the private part of a key to a dir
 * 
 * @param key
 * @param dirname
 * @return 
 */

ya_result dnskey_store_private_key_to_dir(dnssec_key *key, const char *dirname);

/**
 * 
 * Saves the public part of the key in a dir
 * 
 * @param key
 * @param dirname
 * @return 
 */

ya_result dnskey_store_public_key_to_dir(dnssec_key *key, const char *dirname);

/**
 * Save both parts of the key to the directory.
 * 
 * @param key
 * @param dir
 * 
 * @return an error code
 */

ya_result dnskey_store_keypair_to_dir(dnssec_key *key, const char *dir);

ya_result dnskey_delete_public_key_from_dir(dnssec_key *key, const char *dirname);
ya_result dnskey_delete_private_key_from_dir(dnssec_key *key, const char *dirname);
ya_result dnskey_delete_keypair_from_dir(dnssec_key *key, const char *dirname);

bool dnskey_is_expired(const dnssec_key *key, time_t now);
bool dnskey_is_expired_now(const dnssec_key *key);
bool dnskey_is_revoked(const dnssec_key *key);
int dnskey_get_size(const dnssec_key *key);
u16 dnskey_get_flags(const dnssec_key *key);
void dnskey_state_enable(dnssec_key *key, u32 status);
void dnskey_state_disable(dnssec_key *key, u32 status);
u32 dnskey_state_get(const dnssec_key *key);

/**
 * Returns true if the key is supposed to have been added in the zone at the chosen time already.
 * 
 * @param key
 * @param t
 * @return 
 */

bool dnskey_is_published(const dnssec_key *key, time_t t);

/**
 * Returns true if the key is supposed to have been removed from the zone at the chosen time already.
 * 
 * @param key
 * @param t
 * @return 
 */

bool dnskey_is_unpublished(const dnssec_key *key, time_t t);

/**
 * Returns true if the key is supposed to be used for signatures.
 * 
 * @param key
 * @param t
 * @return 
 */

bool dnskey_is_activated(const dnssec_key *key, time_t t);

/**
 * Assumes we are in 'leniency' seconds in the future for activation (and in the present for deactivation)
 */

bool dnskey_is_activated_lenient(const dnssec_key *key, time_t t, u32 leniency);

/**
 * Returns true if the key must not be used for signatures anymore.
 * 
 * @param key
 * @param t
 * @return 
 */

bool dnskey_is_deactivated(const dnssec_key *key, time_t t);

static inline time_t dnskey_get_created_epoch(const dnssec_key *key)
{
    return key->epoch_created;
}

bool  dnskey_has_explicit_publish(const dnssec_key *key);

bool  dnskey_has_explicit_delete(const dnssec_key *key);

bool dnskey_has_explicit_activate(const dnssec_key *key);

bool dnskey_has_explicit_deactivate(const dnssec_key *key);

bool  dnskey_has_explicit_publish_or_delete(const dnssec_key *key);

bool dnskey_has_explicit_publish_and_delete(const dnssec_key *key);

bool dnskey_has_activate_and_deactivate(const dnssec_key *key);

bool dnskey_has_explicit_publish_or_delete(const dnssec_key *key);

bool dnskey_has_activate_or_deactivate(const dnssec_key *key);

ya_result dnskey_newinstance(u32 size, u8 algorithm, u16 flags, const char* origin, dnssec_key** out_key);

u8  dnskey_supported_algorithm_count();

const dnskey_features* dnskey_supported_algorithm_by_index(u8 index);

const dnskey_features* dnskey_supported_algorithm(u8 algorithm);

void dnskey_init_dns_resource_record(dnssec_key *key, s32 ttl, dns_resource_record *rr);

#ifdef	__cplusplus
}
#endif

#endif	/* _DNSKEY_H */

/** @} */
