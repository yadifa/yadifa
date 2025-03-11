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
 * @ingroup dnscore
 * @brief
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <arpa/inet.h>
#include <dnscore/sys_types.h>
#include <dnscore/rfc.h>
#include <dnscore/dnssec_errors.h>
#include <dnscore/u32_treemap.h>
#include <dnscore/openssl.h>
#include <dnscore/digest.h>
#include <dnscore/mutex.h>
#include <dnscore/output_stream.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/crypto.h>

#define DNSSEC_MINIMUM_KEY_SIZE       512    // bits
#define DNSSEC_MAXIMUM_KEY_SIZE       524256 // bits

#define DNSSEC_DEFAULT_KEYSTORE_PATH  "."

#define DNSSEC_MINIMUM_KEY_SIZE_BYTES ((DNSSEC_MINIMUM_KEY_SIZE + 7) / 8)
#define DNSSEC_MAXIMUM_KEY_SIZE_BYTES ((DNSSEC_MAXIMUM_KEY_SIZE + 7) / 8)

#if WORDS_BIGENDIAN
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

#define DNSKEY_FLAGS_FROM_RDATA(x__) (GET_U16_AT(((uint8_t *)(x__))[0]))

#define DNSKEY_FLAGS(x__)            (GET_U16_AT_P(zdb_resource_record_data_rdata_const(x__)))
#define DNSKEY_PROTOCOL(x__)         (zdb_resource_record_data_rdata_const(x__)[2])
#define DNSKEY_ALGORITHM(x__)        (zdb_resource_record_data_rdata_const(x__)[3])

/*
 * Computes the key tag from a packed record
 */

#define DNSKEY_TAG(x__)              (dnskey_get_tag_from_rdata(zdb_resource_record_data_rdata_const(x__), zdb_resource_record_data_rdata_size(x__)))

#ifdef __cplusplus
extern "C"
{
#endif

#define DNSKEY_RDATA_TAG              0x445259454b534e44 /* DNSKEYRD */

#define DNSKEY_FEATURE_NSEC_CAPABLE   1
#define DNSKEY_FEATURE_NSEC3_CAPABLE  2
#define DNSKEY_FEATURE_ZONE_SIGNATURE 16

#define DNSKEY_FEATURE_ZONE_NSEC      (DNSKEY_FEATURE_NSEC_CAPABLE | DNSKEY_FEATURE_ZONE_SIGNATURE)
#define DNSKEY_FEATURE_ZONE_NSEC3     (DNSKEY_FEATURE_NSEC3_CAPABLE | DNSKEY_FEATURE_ZONE_SIGNATURE)
#define DNSKEY_FEATURE_ZONE_MODERN    (DNSKEY_FEATURE_NSEC_CAPABLE | DNSKEY_FEATURE_NSEC3_CAPABLE | DNSKEY_FEATURE_ZONE_SIGNATURE)

struct dnskey_features_s
{
    const char **names;
    uint16_t     size_bits_min;
    uint16_t     size_bits_max;
    uint16_t     size_bits_ksk_default;
    uint16_t     size_bits_zsk_default;
    uint16_t     size_multiple;
    uint8_t      algorithm;
    uint8_t      usage;
};

typedef struct dnskey_features_s dnskey_features_t;

struct dnskey_raw_field_s
{
    uint8_t *buffer;
    uint32_t size;
};

typedef struct dnskey_raw_field_s dnskey_raw_field_t;

#if UNUSED
void dnskey_raw_field_bytes(dnskey_raw_field_t *field);
#endif

#ifdef OSSL_PARAM_BN
#define OSSL_PARAM_RAW(name__, raw_field__) OSSL_PARAM_BN(name__, (raw_field__)->buffer, (raw_field__)->size)
#endif

static inline bool dnskey_raw_field_empty(dnskey_raw_field_t *drf) { return (drf == NULL) || (drf->buffer == NULL); }

void               dnskey_raw_field_clean_finalize(dnskey_raw_field_t *drf);

#define STRUCTDESCRIPTOR_NONE 0
#define STRUCTDESCRIPTOR_BN   1
// #define STRUCTDESCRIPTOR_U16    2 // undefined disables code
#define STRUCTDESCRIPTOR_RAW  3
// #define STRUCTDESCRIPTOR_REVRAW 4 // undefined disables code

struct dnskey_field_access_s
{
    const char name[24];
    size_t     relative;
    int        type;
};

typedef struct dnskey_field_access_s dnskey_field_access_t;

struct parser_s;

ya_result dnskey_field_access_parse(const struct dnskey_field_access_s *sd, void *base, struct parser_s *p);
ya_result dnskey_field_access_print(const struct dnskey_field_access_s *sd, const void *base, output_stream_t *os);

struct dnskey_vtbl;
typedef struct dnskey_vtbl           dnskey_vtbl;

typedef struct dnskey_contextmethods dnskey_contextmethods;

#ifdef SSL_API

union dnskey_data
{
    void *any;
#if SSL_API_GE_300 || DNSCORE_HAS_EDDSA_SUPPORT
    EVP_PKEY *evp_key;
#endif
#if SSL_API_LT_300
    RSA    *rsa;
    DSA    *dsa;
    EC_KEY *ec;
#endif
};

#else
union dnskey_data
{
    void *any;
};

#endif

typedef union dnskey_data dnskey_data;

typedef struct dnskey_s   dnskey_t;

typedef ya_result         dnskey_algorithm_newinstance(uint32_t size, uint8_t algorithm, uint16_t flags, const char *origin, dnskey_t **out_key);

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

struct bytes_signer_s;

typedef int32_t bytes_signer_update_method(struct bytes_signer_s *, const void *, uint32_t);
typedef int32_t bytes_signer_sign_method(struct bytes_signer_s *, void *, uint32_t *);
typedef int32_t bytes_signer_finalise_method(struct bytes_signer_s *);

struct bytes_signer_vtbl
{
    bytes_signer_update_method   *update;
    bytes_signer_sign_method     *sign;
    bytes_signer_finalise_method *finalise;
};

struct bytes_signer_s
{
    void                           *dctx;
    void                           *kctx;
    const struct bytes_signer_vtbl *vtbl;
};

typedef struct bytes_signer_s bytes_signer_t;

struct bytes_verifier_s;

typedef int32_t bytes_verifier_update_method(struct bytes_verifier_s *, const void *, uint32_t);
typedef bool    bytes_verifier_verify_method(struct bytes_verifier_s *, const void *, uint32_t);
typedef int32_t bytes_verifier_finalise_method(struct bytes_verifier_s *);

struct bytes_verifier_vtbl
{
    bytes_verifier_update_method   *update;
    bytes_verifier_verify_method   *verify;
    bytes_verifier_finalise_method *finalise;
};

struct bytes_verifier_s
{
    void                             *dctx;
    void                             *kctx;
    const struct bytes_verifier_vtbl *vtbl;
};

typedef struct bytes_verifier_s bytes_verifier_t;

/* Hash should be tag<<8 | algorithm */
struct dnskey_s
{
    struct dnskey_s   *next;
    const dnskey_vtbl *vtbl;
    char              *origin;
    uint8_t           *owner_name; // = zone origin

    dnskey_data        key;       // RSA* or DSA* or any crypto-lib specific pointer
    int64_t            timestamp; // the file modification time of the private key (to avoid reloading)
    int                nid;       // NID_sha1, NID_md5
    atomic_int         rc;

    time_t             epoch_created;
    time_t             epoch_publish;  // if not published yet, at that time, it needs to be added in the zone
    time_t             epoch_activate; // if not activated yet, at that time, it needs to be used for signatures
    time_t             epoch_inactive; // if active, at that time, it needs to stop being used for signatures
    time_t             epoch_delete;   // if still in the zone, at that time, it needs to be removed from the zone

    uint16_t           flags;
    uint16_t           tag;
    uint8_t            algorithm;
    uint32_t           status; // Is the key "private", has the tag been computed, ...

    /*
     * Later, add a list of (wannabe) signers and for each of these
     * if said signature has been verified, not verified or is wrong
     */
};

typedef struct dnskey_sll dnskey_sll;

struct dnskey_sll
{
    struct dnskey_sll *next;
    dnskey_t          *key;
};

typedef void      dnskey_free_method(dnskey_t *key);
typedef uint32_t  dnskey_rdatasize_method(const dnskey_t *key);
typedef uint32_t  dnskey_writerdata_method(const dnskey_t *key, uint8_t *output, size_t output_size);
typedef ya_result dnskey_sign_digest_method(const dnskey_t *key, const uint8_t *digest, uint32_t digest_len, uint8_t *output);
typedef bool      dnskey_verify_digest_method(const dnskey_t *key, const uint8_t *digest, uint32_t digest_len, const uint8_t *signature, uint32_t signature_len);
typedef bool      dnskey_equals_method(const dnskey_t *key_a, const dnskey_t *key_b);
typedef ya_result dnskey_private_print_fields_method(dnskey_t *key, output_stream_t *os);
typedef uint32_t  dnskey_size_method(const dnskey_t *key);

typedef ya_result dnskey_signer_init_method(dnskey_t *key, bytes_signer_t *signer);
typedef ya_result dnskey_verifier_init_method(dnskey_t *key, bytes_verifier_t *verifier);

struct dnskey_signer_s;

typedef ya_result dnskey_signer_update_method(struct dnskey_signer_s *signer, const uint8_t *buffer, uint32_t buffer_len);
typedef ya_result dnskey_signer_final_method(struct dnskey_signer_s *signer, uint8_t *signature, uint32_t signature_len);

struct dnskey_vtbl
{
    dnskey_signer_init_method          *signer_init;
    dnskey_verifier_init_method        *verifier_init;

    dnskey_rdatasize_method            *dnskey_rdatasize;
    dnskey_writerdata_method           *dnskey_writerdata;
    dnskey_free_method                 *dnskey_free;
    dnskey_equals_method               *dnskey_equals;
    dnskey_private_print_fields_method *dnskey_print_fields;
    dnskey_size_method                 *dnskey_size;

    const char                         *__class__;
};

struct dnskey_field_parser;

typedef ya_result dnskey_field_parser_parse_field_method(struct dnskey_field_parser *, struct parser_s *);
typedef ya_result dnskey_field_parser_set_key_method(struct dnskey_field_parser *, dnskey_t *);
typedef void      dnskey_field_parser_finalize_method(struct dnskey_field_parser *);

struct dnskey_field_parser_vtbl
{
    dnskey_field_parser_parse_field_method *parse_field;
    dnskey_field_parser_set_key_method     *set_key;
    dnskey_field_parser_finalize_method    *finalise;
    const char                             *__class__;
};

struct dnskey_field_parser
{
    void                                  *data;
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

dnskey_t *dnskey_newemptyinstance(uint8_t algorithm, uint16_t flags, const char *origin);

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

ya_result dnskey_new_from_rdata(const uint8_t *rdata, uint16_t rdata_size, const uint8_t *origin, dnskey_t **out_key);

/**
 * Increases the reference count on a dnssec_key
 *
 * @param key
 */

void dnskey_acquire(dnskey_t *key);

/**
 * Releases the reference count on a dnssec_key.
 * Uses the tag, flags, algorithm, origin and key content.
 *
 * @param a
 * @param b
 */

void dnskey_release(dnskey_t *key);

/**
 *
 * Compares two keys for equality on a cryptographic point of view
 * Uses the tag, flags, algorithm and origin.
 *
 * @param a
 * @param b
 *
 * @return true iff the keys are the same.
 */

bool dnskey_equals(const dnskey_t *a, const dnskey_t *b);

/**
 *
 * Compares two keys for equality on a cryptographic point of view
 * Uses the tag, flags, algorithm, origin and public key content.
 *
 * @param a
 * @param b
 *
 * @return true iff the keys are the same.
 */

bool dnskey_public_equals(const dnskey_t *a, const dnskey_t *b);

/**
 * Returns true if the tag and algorithm of the rdata are matching the ones of the key.
 *
 * @param key
 * @param rdata
 * @param rdata_size
 * @return
 */

bool dnskey_matches_rdata(const dnskey_t *key, const uint8_t *rdata, uint16_t rdata_size);

/**
 * Returns true if an only if the tag has already been computed and
 * stored in the dnssec key.
 *
 * @param key
 * @return true iff the tag is already known
 */

static inline bool dnskey_tag_field_set(const dnskey_t *key) { return (key->status & DNSKEY_KEY_TAG_SET) != 0; }

/**
 * Returns the key tag.
 * The key tag generated by this function is stored in the dnssec key to
 * make further calls instant.  This is why the parameter is not "const".
 *
 * @param key
 * @return
 */

uint16_t dnskey_get_tag(dnskey_t *key);

/**
 * Returns the key tag.
 * If the key tag is not cached in the key, computes it.
 * The tag is not cached in the key after this call.
 *
 * @param key
 * @return
 */

uint16_t dnskey_get_tag_const(const dnskey_t *key);

/**
 * Returns the algorithm of the key.
 *
 * @param key
 * @param keyp
 */

uint8_t dnskey_get_algorithm(const dnskey_t *key);

/**
 * Returns a pointer to the domain of the key.
 *
 * @param key
 * @return
 */

const uint8_t *dnskey_get_domain(const dnskey_t *key);

/**
 * Returns true if and only if the key is a private key.
 *
 * @return true iff the key is private.
 */

bool dnskey_is_private(const dnskey_t *key);

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

void dnskey_add_to_chain(dnskey_t *key, dnskey_t **keyp);

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

void dnskey_remove_from_chain(dnskey_t *key, dnskey_t **keyp);

/**
 * Generates a key tag from the DNSKEY RDATA wire
 *
 * @param dnskey_rdata
 * @param dnskey_rdata_size
 * @return
 */

uint16_t dnskey_get_tag_from_rdata(const uint8_t *dnskey_rdata, uint32_t dnskey_rdata_size);

/**
 * Returns the flag of a dnskey from its rdata
 *
 * @param dnskey rdata
 *
 * @return
 */

static inline uint16_t dnskey_get_flags_from_rdata(const uint8_t *dnskey_rdata) { return GET_U16_AT_P(dnskey_rdata); }

/**
 * Returns the protocol of a dnskey from its rdata
 *
 * @param dnskey rdata
 *
 * @return
 */

static inline uint8_t dnskey_get_protocol_from_rdata(const uint8_t *dnskey_rdata) { return dnskey_rdata[2]; }

/**
 * Returns the algorithm of a dnskey from its rdata
 *
 * @param dnskey rdata
 *
 * @return
 */

static inline uint8_t dnskey_get_algorithm_from_rdata(const uint8_t *dnskey_rdata) { return dnskey_rdata[3]; }

/**
 * Reference implementation function to generate a key tag from the DNSKEY RDATA wire
 *
 * @param dnskey_rdata
 * @param dnskey_rdata_size
 * @return
 */

unsigned int dnskey_get_tag_from_rdata_reference(unsigned char key[],  /* the RDATA part of the DNSKEY RR */
                                                 unsigned int  keysize /* the RDLENGTH */
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

ya_result dnskey_generate_ds_rdata(uint8_t digest_type, const uint8_t *dnskey_fqdn, const uint8_t *dnskey_rdata, uint16_t dnskey_rdata_size, uint8_t *out_rdata);

/**
 * Initialises the context for a key algorithm.
 *
 * @param ctx
 * @param algorithm
 * @return
 */

ya_result dnskey_digest_init(digest_t *ctx, uint8_t algorithm);

#if OPENSSL_VERSION_MAJOR < 3
/**
 *
 * @param os output stream
 * @param num the number to write
 * @return
 */

ya_result dnskey_write_bignum_as_base64_to_stream(const BIGNUM *num, output_stream_t *os);
#endif

ya_result dnskey_store_private_key_to_stream(dnskey_t *key, output_stream_t *os);

void      dnskey_set_created_epoch(dnskey_t *key, time_t t);

/**
 * Returns the most relevant publication time.
 *
 * publish > activate > created > now
 *
 * @param key
 * @return
 */

time_t dnskey_get_publish_epoch(const dnskey_t *key);
void   dnskey_set_publish_epoch(dnskey_t *key, time_t t);

/**
 * Returns the most relevant activation time.
 *
 * activate > publish > created > now
 *
 * @param key
 * @return
 */

time_t dnskey_get_activate_epoch(const dnskey_t *key);
void   dnskey_set_activate_epoch(dnskey_t *key, time_t t);

/**
 * Returns the most relevant revocation time.
 *
 * revoke > never
 *
 * @param key
 * @return
 */

time_t dnskey_get_revoke_epoch(const dnskey_t *key);
void   dnskey_set_revoke_epoch(dnskey_t *key, time_t t);

/**
 * Returns the most relevant inactivation time.
 *
 * inactive > delete > never
 *
 * @param key
 * @return
 */

time_t dnskey_get_inactive_epoch(const dnskey_t *key);
void   dnskey_set_inactive_epoch(dnskey_t *key, time_t t);

/**
 * Returns the most relevant delete time.
 *
 * delete > inactive > never
 *
 * @param key
 * @return
 */

time_t    dnskey_get_delete_epoch(const dnskey_t *key);
void      dnskey_set_delete_epoch(dnskey_t *key, time_t t);

ya_result dnskey_new_public_key_from_stream(input_stream_t *is, dnskey_t **keyp);

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

ya_result dnskey_new_public_key_from_file(const char *filename, dnskey_t **keyp);

ya_result dnskey_add_private_key_from_stream(input_stream_t *is, dnskey_t *key, const char *path, uint8_t algorithm);

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

ya_result dnskey_new_private_key_from_file(const char *filename, dnskey_t **keyp);

/**
 * Returns the keytag from its DS rdata in network order
 *
 * @param rdata
 * @return
 */

static inline uint16_t ds_get_wire_keytag_from_rdata(const uint8_t *rdata)
{
    uint16_t ds_keytag = GET_U16_AT_P(rdata);
    return ds_keytag;
}

/**
 * Returns the keytag from its DS rdata
 *
 * @param rdata
 * @return
 */

static inline uint16_t ds_get_keytag_from_rdata(const uint8_t *rdata)
{
    uint16_t ds_keytag = ntohs(ds_get_wire_keytag_from_rdata(rdata));
    return ds_keytag;
}

/**
 * Returns the algorithm from its DS rdata
 *
 * @param rdata
 * @return
 */

static inline uint8_t ds_get_algorithm_from_rdata(const uint8_t *rdata)
{
    uint8_t ds_algorithm = rdata[2];
    return ds_algorithm;
}

/**
 * Returns the digest algorithm from its DS rdata
 *
 * @param rdata
 * @return
 */

static inline uint8_t ds_get_digesttype_from_rdata(const uint8_t *rdata)
{
    uint8_t ds_digesttype = rdata[3];
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

ya_result dnskey_store_private_key_to_stream(dnskey_t *key, output_stream_t *os);

/**
 *
 * Save the private part of a key to a file with the given name
 *
 * @param key
 * @param filename
 * @return
 */

ya_result dnskey_store_private_key_to_file(dnskey_t *key, const char *filename);

/**
 *
 * Save the public part of a key to a stream
 *
 * @param key
 * @param filename
 * @return
 */

ya_result dnskey_store_public_key_to_stream(dnskey_t *key, output_stream_t *os);

/**
 *
 * Save the public part of a key to a file with the given name
 *
 * @param key
 * @param filename
 * @return
 */

ya_result dnskey_store_public_key_to_file(dnskey_t *key, const char *filename);

/**
 * Save the private part of a key to a dir
 *
 * @param key
 * @param dirname
 * @return
 */

ya_result dnskey_store_private_key_to_dir(dnskey_t *key, const char *dirname);

/**
 *
 * Saves the public part of the key in a dir
 *
 * @param key
 * @param dirname
 * @return
 */

ya_result dnskey_store_public_key_to_dir(dnskey_t *key, const char *dirname);

/**
 * Save both parts of the key to the directory.
 *
 * @param key
 * @param dir
 *
 * @return an error code
 */

ya_result dnskey_store_keypair_to_dir(dnskey_t *key, const char *dir);

ya_result dnskey_delete_public_key_from_dir(dnskey_t *key, const char *dirname);
ya_result dnskey_delete_private_key_from_dir(dnskey_t *key, const char *dirname);
ya_result dnskey_delete_keypair_from_dir(dnskey_t *key, const char *dirname);

bool      dnskey_is_expired(const dnskey_t *key, time_t now);
bool      dnskey_is_expired_now(const dnskey_t *key);
bool      dnskey_is_revoked(const dnskey_t *key);
int       dnskey_get_size(const dnskey_t *key);
uint16_t  dnskey_get_flags(const dnskey_t *key);
void      dnskey_state_enable(dnskey_t *key, uint32_t status);
void      dnskey_state_disable(dnskey_t *key, uint32_t status);
uint32_t  dnskey_state_get(const dnskey_t *key);

/**
 * Returns true if the key is supposed to have been added in the zone at the chosen time already.
 *
 * @param key
 * @param t
 * @return
 */

bool dnskey_is_published(const dnskey_t *key, time_t t);

/**
 * Returns true if the key is supposed to have been removed from the zone at the chosen time already.
 *
 * @param key
 * @param t
 * @return
 */

bool dnskey_is_unpublished(const dnskey_t *key, time_t t);

/**
 * Returns true if the key is supposed to be used for signatures.
 *
 * @param key
 * @param t
 * @return
 */

bool dnskey_is_activated(const dnskey_t *key, time_t t);

/**
 * Assumes we are in 'leniency' seconds in the future for activation (and in the present for deactivation)
 */

bool dnskey_is_activated_lenient(const dnskey_t *key, time_t t, uint32_t leniency);

/**
 * Returns true if the key must not be used for signatures anymore.
 *
 * @param key
 * @param t
 * @return
 */

bool                     dnskey_is_deactivated(const dnskey_t *key, time_t t);

static inline time_t     dnskey_get_created_epoch(const dnskey_t *key) { return key->epoch_created; }

bool                     dnskey_has_explicit_publish(const dnskey_t *key);

bool                     dnskey_has_explicit_delete(const dnskey_t *key);

bool                     dnskey_has_explicit_activate(const dnskey_t *key);

bool                     dnskey_has_explicit_deactivate(const dnskey_t *key);

bool                     dnskey_has_explicit_publish_or_delete(const dnskey_t *key);

bool                     dnskey_has_explicit_publish_and_delete(const dnskey_t *key);

bool                     dnskey_has_activate_and_deactivate(const dnskey_t *key);

bool                     dnskey_has_explicit_publish_or_delete(const dnskey_t *key);

bool                     dnskey_has_activate_or_deactivate(const dnskey_t *key);

ya_result                dnskey_newinstance(uint32_t size, uint8_t algorithm, uint16_t flags, const char *origin, dnskey_t **out_key);

uint8_t                  dnskey_supported_algorithm_count();

const dnskey_features_t *dnskey_supported_algorithm_by_index(uint8_t index);

const dnskey_features_t *dnskey_supported_algorithm(uint8_t algorithm);

void                     dnskey_init_dns_resource_record(dnskey_t *key, int32_t ttl, dns_resource_record_t *rr);

#ifdef __cplusplus
}
#endif

/** @} */
