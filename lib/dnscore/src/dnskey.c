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

/** 
 *  @defgroup dnskey DNSSEC keys functions
 *  @ingroup dnsdbdnssec
 *  @addtogroup dnskey DNSKEY functions
 *  @brief
 *
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnscore/dnscore-config.h"

#define DNSCORE_DNSKEY_C 1

#include <arpa/inet.h>
#include <ctype.h>
#include <sys/stat.h>
#include <dnscore/dns_resource_record.h>
#include "dnscore/openssl.h"
#include "dnscore/dnsname.h"
#include "dnscore/dnskey.h"
#include "dnscore/dnskey_rsa.h"
#include "dnscore/dnskey_dsa.h"
#if HAS_ECDSA_SUPPORT
#include "dnscore/dnskey_ecdsa.h"
#endif
#if HAS_EDDSA_SUPPORT
#include "dnscore/dnskey_eddsa.h"
#endif
#ifdef DNSKEY_ALGORITHM_DUMMY
#include "dnscore/dnskey_dummy.h"
#endif
#include "dnscore/digest.h"
#include "dnscore/base64.h"
#include "dnscore/string_set.h"
#include "dnscore/file_input_stream.h"
#include "dnscore/file_output_stream.h"
#include "dnscore/buffer_output_stream.h"
#include "dnscore/parser.h"
#include "dnscore/zalloc.h"
#include "dnscore/logger.h"
#include "dnscore/fdtools.h"
#include "dnscore/mutex.h"
#include "dnscore/timeformat.h"

extern logger_handle* g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#define ZDB_DNSKEY_TAG          0x59454b534e44
#define ZDB_DNSKEY_NAME_TAG     0x454d414e59454b

#define ORIGNDUP_TAG 0x5055444e4749524f

// dumps key acquisition/release
#define DUMP_ACQUIRE_RELEASE_STACK_TRACE 0

static string_set dnssec_key_load_private_keywords_set = STRING_SET_EMPTY;

#define DNSKEY_FIELD_ALGORITHM 1
#define DNSKEY_FIELD_FORMAT    2
#define DNSKEY_FIELD_CREATED   3
#define DNSKEY_FIELD_PUBLISH   4
#define DNSKEY_FIELD_ACTIVATE  5

#define DNSKEY_FIELD_INACTIVE  7
#define DNSKEY_FIELD_DELETE    8
#define DNSKEY_FIELD_ENGINE    9

static value_name_table dnssec_key_load_private_keywords_common_names[] =
{
    {DNSKEY_FIELD_ALGORITHM,    "Algorithm"},
    {DNSKEY_FIELD_FORMAT,       "Private-key-format"},
    {DNSKEY_FIELD_CREATED,      "Created"},
    {DNSKEY_FIELD_PUBLISH,      "Publish"},
    {DNSKEY_FIELD_ACTIVATE,     "Activate"},

    {DNSKEY_FIELD_INACTIVE,     "Inactive"},
    {DNSKEY_FIELD_DELETE,       "Delete"},
    {DNSKEY_FIELD_ENGINE,       "Engine"},
    {0, NULL}
};

static group_mutex_t dnskey_rc_mtx = GROUP_MUTEX_INITIALIZER;

static const char *rsamd5_names[] = {DNSKEY_ALGORITHM_RSAMD5_NAME,"1", NULL};
static const char *dsasha1_names[] = {DNSKEY_ALGORITHM_DSASHA1_NAME,"3", NULL};
static const char *rsasha1_names[] = {DNSKEY_ALGORITHM_RSASHA1_NAME,"5", NULL};
static const char *dsasha1nsec3_names[] = {DNSKEY_ALGORITHM_DSASHA1_NSEC3_NAME,"6", NULL};
static const char *rsasha1nsec3_names[] = {DNSKEY_ALGORITHM_RSASHA1_NSEC3_NAME,"7", NULL};
static const char *rsasha256_names[] = {DNSKEY_ALGORITHM_RSASHA256_NSEC3_NAME,"8", NULL};
static const char *rsasha512_names[] = {DNSKEY_ALGORITHM_RSASHA512_NSEC3_NAME,"10", NULL};
#if HAS_ECDSA_SUPPORT
static const char *ecdsap256sha256_names[] = {DNSKEY_ALGORITHM_ECDSAP256SHA256_NAME,"13", NULL};
static const char *ecdsap384sha384_names[] = {DNSKEY_ALGORITHM_ECDSAP384SHA384_NAME,"14", NULL};
#endif
#if HAS_EDDSA_SUPPORT
static const char *ed25619_names[] = { DNSKEY_ALGORITHM_ED25519_NAME, "15", NULL};
static const char *ed448_names[] = { DNSKEY_ALGORITHM_ED448_NAME, "16", NULL};
#endif
#ifdef DNSKEY_ALGORITHM_DUMMY
static const char *dnskey_dummy_names[] = {DNSKEY_ALGORITHM_DUMMY_NAME,"254", NULL};
#endif
//static const char *empty_names[] = {NULL};

static const struct dnskey_features dnskey_supported_algorithms[] =
{
    //{NULL, 0, 0, 0, 0, 0, 0, 0}, // 0
    {
        rsamd5_names,
        512,4096,
        2048,
        1024,
        1,
        DNSKEY_ALGORITHM_RSAMD5,
        DNSKEY_FEATURE_ZONE_NSEC
    },
    //{NULL, 0, 0, 0, 0, 0, 0, 0}, // 2
    {
        dsasha1_names,
        512,1024,
        1024,
        1024,
        64,
        DNSKEY_ALGORITHM_DSASHA1,
        DNSKEY_FEATURE_ZONE_NSEC
    },
    //{NULL, 0, 0, 0, 0, 0, 0, 0}, // 4
    {
        rsasha1_names,
        512,4096,
        2048,
        1024,
        1,
        DNSKEY_ALGORITHM_RSASHA1,
        DNSKEY_FEATURE_ZONE_NSEC
    },
    {
        dsasha1nsec3_names,
        512,1024,
        1024,
        1024,
        64,
        DNSKEY_ALGORITHM_DSASHA1_NSEC3,
        DNSKEY_FEATURE_ZONE_NSEC3
    },
    {
        rsasha1nsec3_names,
        512,4096,
        2048,
        1024,
        1,
        DNSKEY_ALGORITHM_RSASHA1_NSEC3,
        DNSKEY_FEATURE_ZONE_NSEC3
    },
    {
        rsasha256_names,
        512,4096,
        2048,
        1024,
        1,
        DNSKEY_ALGORITHM_RSASHA256_NSEC3,
        DNSKEY_FEATURE_ZONE_MODERN
    },
    //{NULL, 0, 0, 0, 0, 0, 0, 0}, // 9
    {
        rsasha512_names,
        1024,4096,
        2048,
        1024,
        1,
        DNSKEY_ALGORITHM_RSASHA512_NSEC3,
        DNSKEY_FEATURE_ZONE_MODERN
    },
    //{NULL, 0, 0, 0, 0, 0, 0, 0}, // 11
    //{NULL, 0, 0, 0, 0, 0, 0, 0}, // 12
#if HAS_ECDSA_SUPPORT
    {
        ecdsap256sha256_names,
        256,256,
        256,
        256,
        1,
        DNSKEY_ALGORITHM_ECDSAP256SHA256,
        DNSKEY_FEATURE_ZONE_MODERN
    },
    {
        ecdsap384sha384_names,
        384,384,
        384,
        384,
        1,
        DNSKEY_ALGORITHM_ECDSAP384SHA384,
        DNSKEY_FEATURE_ZONE_MODERN
    },
#else
    //{NULL, 0, 0, 0, 0, 0, 0, 0}, // 13
    //{NULL, 0, 0, 0, 0, 0, 0, 0}, // 14
#endif
#if HAS_EDDSA_SUPPORT
        {
        ed25619_names,
        0,0,
        0,
        0,
        1,
        DNSKEY_ALGORITHM_ED25519,
        DNSKEY_FEATURE_ZONE_MODERN
    },
    {
        ed448_names,
        0,0,
        0,
        0,
        1,
        DNSKEY_ALGORITHM_ED448,
        DNSKEY_FEATURE_ZONE_MODERN
    },
#else
    //{NULL, 0, 0, 0, 0, 0, 0, 0}, // 15
    //{NULL, 0, 0, 0, 0, 0, 0, 0}, // 16
#endif
#ifdef DNSKEY_ALGORITHM_DUMMY
    {
        dnskey_dummy_names,
        16,16,
        16,
        16,
        16,
        DNSKEY_ALGORITHM_DUMMY,
        DNSKEY_FEATURE_ZONE_MODERN
    },
#endif
    /*
    {   // terminator
        empty_names,
        0,0,
        0,
        0,
        0,
        0
    }*/
};

static const char *
dnskey_get_algorithm_name_from_value(int alg)
{
    switch(alg)
    {
        case DNSKEY_ALGORITHM_RSAMD5:
            return "RSAMD5";
        case DNSKEY_ALGORITHM_DIFFIE_HELLMAN:
            return "DH";
        case DNSKEY_ALGORITHM_DSASHA1:
            return "DSASHA1";
        case DNSKEY_ALGORITHM_RSASHA1:
            return "RSASHA1";
        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
            return "NSEC3DSA";
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
            return "NSEC3RSASHA1";
        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
            return "RSASHA256";
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            return "RSASHA512";
        case DNSKEY_ALGORITHM_GOST:
            return "ECCGOST";
        case DNSKEY_ALGORITHM_ECDSAP256SHA256:
            return "ECDSAP256SHA256";
        case DNSKEY_ALGORITHM_ECDSAP384SHA384:
            return "ECDSAP384SHA384";
        case DNSKEY_ALGORITHM_ED25519:
            return "ED25519";
        case DNSKEY_ALGORITHM_ED448:
            return "ED448";
#ifdef DNSKEY_ALGORITHM_DUMMY
        case DNSKEY_ALGORITHM_DUMMY:
            return "DUMMY";
#endif
        default:
            return "?";
    }
}

static ya_result
dnskey_field_parser_dummy_parse_field(struct dnskey_field_parser *parser, struct parser_s *p)
{
    (void)parser;
    (void)p;
    return FEATURE_NOT_IMPLEMENTED_ERROR;
}

static ya_result
dnskey_field_parser_dummy_set_key(struct dnskey_field_parser *parser, dnssec_key *key)
{
    (void)parser;
    (void)key;
    return FEATURE_NOT_IMPLEMENTED_ERROR;
}

static void
dnskey_field_parser_dummy_finalize_method(struct dnskey_field_parser *parser)
{
    (void)parser;
}

struct dnskey_field_parser_vtbl dnskey_field_dummy_parser =
{
    dnskey_field_parser_dummy_parse_field,
    dnskey_field_parser_dummy_set_key,
    dnskey_field_parser_dummy_finalize_method,
    "DUMMY"
};

ya_result
dnskey_field_access_parse(const struct dnskey_field_access *sd, void *base, parser_s *p)
{
    ya_result ret = INVALID_STATE_ERROR;

    u32 label_len = parser_text_length(p);
    const char *label = parser_text(p);
    bool parsed_it = FALSE;
    u8 tmp_out[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];
    
    for(; sd->type != STRUCTDESCRIPTOR_NONE; sd++)
    {
        switch(sd->type)
        {
            case STRUCTDESCRIPTOR_BN:
            {
                if(memcmp(label, sd->name, label_len) == 0)
                {
                    BIGNUM **bnp = (BIGNUM**)(((u8*)base) + sd->relative);

                    ret = parser_next_word(p);

                    if((*bnp != NULL) || FAIL(ret))
                    {
                        return ret;
                    }

                    u32 word_len = parser_text_length(p);
                    const char *word = parser_text(p);

                    ya_result n = base64_decode(word, word_len, tmp_out);

                    if(FAIL(n))
                    {
                        log_err("dnskey: unable to decode field %s", sd->name);
                        return n;
                    }

                    *bnp = BN_bin2bn(tmp_out, n, NULL);

                    if(*bnp == NULL)
                    {
                        log_err("dnskey: unable to get big number from field %s", sd->name);
                        return DNSSEC_ERROR_BNISNULL;
                    }

                    parsed_it = TRUE;

                    goto dnskey_field_access_parse_loop_exit;
                }

                break;
            }
            case STRUCTDESCRIPTOR_RAW:
            {
                if(memcmp(label, sd->name, label_len) == 0)
                {
                    dnskey_raw_field_t *raw = (dnskey_raw_field_t*)(((u8*)base) + sd->relative);

                    ret = parser_next_word(p);

                    if((raw->buffer != NULL) || FAIL(ret))
                    {
                        return ret;
                    }

                    u32 word_len = parser_text_length(p);
                    const char *word = parser_text(p);

                    ya_result n = base64_decode(word, word_len, tmp_out);

                    if(FAIL(n))
                    {
                        log_err("dnskey: unable to decode field %s", sd->name);
                        return n;
                    }

                    ZALLOC_OBJECT_ARRAY_OR_DIE(raw->buffer, u8, n, GENERIC_TAG);
                    memcpy(raw->buffer, tmp_out, n);
                    raw->size = n;

                    parsed_it = TRUE;

                    goto dnskey_field_access_parse_loop_exit;
                }
                break;
            }
        }
    } /* for each possible field */
dnskey_field_access_parse_loop_exit:
    if(!parsed_it)
    {
        return SUCCESS; // unknown keyword (ignore)
    }
            
    return ret;
}

ya_result
dnskey_field_access_print(const struct dnskey_field_access *sd, const void *base, output_stream *os)
{
    ya_result ret = SUCCESS;
    
    for(; sd->type != STRUCTDESCRIPTOR_NONE; sd++)
    {
        switch(sd->type)
        {
            case STRUCTDESCRIPTOR_BN:
            {
                const u8 *bn_ptr_ptr = (((const u8*)base) + sd->relative);
                const BIGNUM **bn = (const BIGNUM**)bn_ptr_ptr;

                if(bn != NULL)
                {
                    osformat(os, "%s: ", sd->name);
                    dnskey_write_bignum_as_base64_to_stream(*bn, os);
                    osprintln(os, "");
                }
                break;
            }
            case STRUCTDESCRIPTOR_RAW:
            {
                const u8 *bn_ptr_ptr = (((const u8*)base) + sd->relative);
                const dnskey_raw_field_t *raw = (const dnskey_raw_field_t *)bn_ptr_ptr;

                osformat(os, "%s: ", sd->name);

                char buffer[1024];
                u32 encoded_size = BASE64_ENCODED_SIZE(raw->size);
                if(encoded_size > sizeof(buffer))
                {
                    return BUFFER_WOULD_OVERFLOW;
                }
                u32 n = base64_encode(raw->buffer, raw->size, buffer);
                output_stream_write(os, buffer, n);
                osprintln(os, "");
                break;
            }
            case STRUCTDESCRIPTOR_U16:
            {
                const u8 *bn_ptr_ptr = (((const u8*)base) + sd->relative);
                const u16 *valuep = (const u16 *)bn_ptr_ptr;
                osformat(os, "%s: %hu", sd->name, *valuep);
                break;
            }
        }
    }
    
    return ret;
}

/*

unsigned long ac;     * assumed to be 32 bits or larger *
int i;                * loop index *

for ( ac = 0, i = 0; i < keysize; ++i )
       ac += (i & 1) ? key[i] : key[i] << 8;
ac += (ac >> 16) & 0xFFFF;
return ac & 0xFFFF;

=>

s=0;
s+=key[0]
s+=key[1]<<8
s+=key[2]
s+=key[3]<<8

Basically it's a sum of little-endian unsigned 16 bits words
And the reference implementation does not match the definition.

"ignoring any carry bits" Yes ? So this is wrong : ac += (i & 1) ? key[i] : key[i] << 8;
The least significant byte will have the add carry bit carried to the most signiticant byte.

 */

/**
 * Generates a key tag from the DNSKEY RDATA wire
 * 
 * @param dnskey_rdata
 * @param dnskey_rdata_size
 * @return 
 */

u16
dnskey_get_tag_from_rdata(const u8* dnskey_rdata, u32 dnskey_rdata_size)
{
    u32 sum = 0;
    u32 sumh = 0;
    while(dnskey_rdata_size > 1)
    {
        sumh += *dnskey_rdata++;
        sum += *dnskey_rdata++;
        dnskey_rdata_size -= 2;
    }
    if(dnskey_rdata_size != 0)
    {
        sumh += *dnskey_rdata++;
    }
    sum += sumh << 8;
    sum += sum >> 16;

    return (u16)sum;
}



/**
 * Initialises the context for a key algorithm.
 * 
 * @param ctx
 * @param algorithm
 * @return 
 */

ya_result
dnskey_digest_init(digest_s *ctx, u8 algorithm)
{
    switch(algorithm)
    {
        case DNSKEY_ALGORITHM_DSASHA1:
        case DNSKEY_ALGORITHM_RSASHA1:
        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
            digest_sha1_init(ctx);
            break;
        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
        case DNSKEY_ALGORITHM_ECDSAP256SHA256:
            digest_sha256_init(ctx);
            break;
        case DNSKEY_ALGORITHM_ECDSAP384SHA384:
            digest_sha384_init(ctx);
            break;
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            digest_sha512_init(ctx);
            break;
#if HAS_EDDSA_SUPPORT
        case DNSKEY_ALGORITHM_ED25519:
        case DNSKEY_ALGORITHM_ED448:
            digest_rawdata_init(ctx);
            break;
#endif
#ifdef DNSKEY_ALGORITHM_DUMMY
        case DNSKEY_ALGORITHM_DUMMY:
            break;
#endif
        default:
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }
    
    return SUCCESS;
}

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

ya_result
dnskey_generate_ds_rdata(u8 digest_type, const u8 *dnskey_fqdn, const u8 *dnskey_rdata,u16 dnskey_rdata_size, u8 *out_rdata)
{
    digest_s ctx;
    
    s32 digest_size;    
    
    switch(digest_type)
    {
        case DS_DIGEST_SHA1:
            digest_sha1_init(&ctx);
            break;
        case DS_DIGEST_SHA256:
            digest_sha256_init(&ctx);
            break;
        default:
            return DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM;
    }
    
    digest_size = digest_get_size(&ctx);
        
    u16 tag = dnskey_get_tag_from_rdata(dnskey_rdata, dnskey_rdata_size);
    u8 algorithm = dnskey_rdata[3];
    
    digest_update(&ctx, dnskey_fqdn, dnsname_len(dnskey_fqdn));
    digest_update(&ctx, dnskey_rdata, dnskey_rdata_size);
    
    out_rdata[0] = tag >> 8;
    out_rdata[1] = tag;
    out_rdata[2] = algorithm;
    out_rdata[3] = digest_type;

    digest_final_copy_bytes(&ctx, &out_rdata[4], digest_size); // generates DS record : safe use

    return 4 + digest_size;
}

/**
 * Sanitises an text origin and returns a zallocated copy of it
 * 
 * @param origin
 * @return a sanitized zallocated copy of origin
 */

static char*
dnskey_origin_zdup_sanitize(const char* origin)
{
    char* ret;

    if(origin == NULL)
    {
        ZALLOC_OBJECT_ARRAY_OR_DIE(ret, char, 2, ORIGNDUP_TAG);
        ret[0] = '.';
        ret[1] = '\0';
        return ret;
    }

    int origin_len = strlen(origin);

    if(origin_len == 0)
    {
        ZALLOC_OBJECT_ARRAY_OR_DIE(ret, char, 2, ORIGNDUP_TAG);
        ret[0] = '.';
        ret[1] = '\0';
        return ret;
    }

    if(origin[origin_len - 1] == '.')
    {
        origin_len++;
        ZALLOC_OBJECT_ARRAY_OR_DIE(ret, char, origin_len, ORIGNDUP_TAG);
        //MEMCOPY(ret, origin, origin_len);
        for(int i = 0; i < origin_len; i++)
        {
            ret[i] = tolower(origin[i]);
        }
    }
    else
    {
        ZALLOC_OBJECT_ARRAY_OR_DIE(ret, char, (origin_len + 2), ORIGNDUP_TAG);
        //MEMCOPY(ret, origin, origin_len);
        for(int i = 0; i < origin_len; i++)
        {
            ret[i] = tolower(origin[i]);
        }
        ret[origin_len++] = '.'; // VS false positive (nonsense)
        ret[origin_len] = '\0';
    }

    return ret;
}

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

dnssec_key*
dnskey_newemptyinstance(u8 algorithm, u16 flags, const char *origin)
{
    yassert(origin != NULL);

    char *origin_copy = dnskey_origin_zdup_sanitize(origin);

    u8 *owner_name = dnsname_zdup_from_name(origin_copy);
    if(owner_name == NULL)
    {
        log_err("dnskey_newemptyinstance(%hhu, %hx, %s = '%s'): origin parameter is not a domain name", algorithm, flags, origin, origin_copy);
        ZFREE_ARRAY(origin_copy, strlen(origin_copy) + 1);
        return NULL;
    }

    dnssec_key* key;
    
    ZALLOC_OBJECT_OR_DIE( key, dnssec_key, ZDB_DNSKEY_TAG);
    ZEROMEMORY(key, sizeof(dnssec_key));
    
    key->origin = origin_copy;

    /* origin is allocated with ZALLOC using ZALLOC_STRING_OR_DIE
     * In this mode, the byte before the pointer is the size of the string.
     */

    key->owner_name = owner_name;
    
    key->rc = 1;
    
    key->epoch_created = 0;
    key->epoch_publish = 0;
    key->epoch_activate = 0;

    /*
    key->epoch_inactive = 0;
    key->epoch_delete = 0;
    */
    key->flags = flags;
    key->algorithm = algorithm;
    /*key->status = 0;*/
    /*key->key.X=....*/
    /*key->tag=00000*/
    /*key->is_private=TRUE;*/
    
    log_debug("dnskey_newemptyinstance: %{dnsname} +%03d+-----/%d status=%x rc=%i (%p)", dnskey_get_domain(key), key->algorithm, ntohs(key->flags), key->status, key->rc, key);

    return key;
}

/**
 * Increases the reference count on a dnssec_key
 * 
 * @param key
 */

#if DUMP_ACQUIRE_RELEASE_STACK_TRACE
static void dnskey_acquire_debug()
{
    stacktrace st = debug_stacktrace_get();
    debug_stacktrace_log_with_prefix(MODULE_MSG_HANDLE, MSG_DEBUG, st, "dnskey_acquire: ");
}

static void dnskey_release_debug()
{
    stacktrace st = debug_stacktrace_get();
    debug_stacktrace_log_with_prefix(MODULE_MSG_HANDLE, MSG_DEBUG, st, "dnskey_release: ");
}
#endif

void
dnskey_acquire(dnssec_key *key)
{
    yassert(key->rc > 0);
    log_debug("dnskey_acquire: %{dnsname} +%03d+%05d/%d status=%x rc=%i (%p)", dnskey_get_domain(key), key->algorithm, key->tag, ntohs(key->flags), key->status, key->rc + 1, key);
    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    ++key->rc;
#if DUMP_ACQUIRE_RELEASE_STACK_TRACE
    dnskey_acquire_debug();
#endif 
    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
}

/**
 * Releases the reference count on a dnssec_key.
 * If the reference count reaches zero, destroys the key.
 * 
 * @param a
 * @param b
 */

void
dnskey_release(dnssec_key *key)
{   
    yassert(key != NULL && key->rc > 0);
    
    log_debug("dnskey_release: %{dnsname} +%03d+%05d/%d status=%x rc=%i (%p)", dnskey_get_domain(key), key->algorithm, key->tag, ntohs(key->flags), key->status, key->rc - 1, key);
    
#if DUMP_ACQUIRE_RELEASE_STACK_TRACE
    dnskey_release_debug();
#endif

    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    if(--key->rc == 0)
    {
        group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
        
#if DEBUG
        if(key->next != NULL)
        {
            // log_err("dnskey_release(%p): a key should be detached from its list before destruction", key);
            logger_flush();
            abort();
        }
#endif
        
        if(key->vtbl != NULL)
        {
            key->vtbl->dnssec_key_free(key);
        }

        ZFREE_ARRAY(key->origin, strlen(key->origin) + 1); // +1 because the 0 has to be taken in account too (duh!)
        dnsname_zfree(key->owner_name);
#if DEBUG
        memset(key, 0xfe, sizeof(dnssec_key));
#endif
        ZFREE(key, dnssec_key);
    }
    else
    {
        group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    }
}

/**
 * Generate a (public) key using the RDATA
 * 
 * RC ok
 * 
 * @param rdata
 * @param rdata_size
 * @param origin
 * @param out_key points to  a pointer for the instantiated key
 * 
 * @return an error code (success or error)
 */

ya_result
dnskey_new_from_rdata(const u8 *rdata, u16 rdata_size, const u8 *fqdn, dnssec_key **out_key)
{
    if(out_key == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    ya_result return_value;    
    u8 algorithm = rdata[3];
    char origin[MAX_DOMAIN_LENGTH];
    
    dnsname_to_cstr(origin, fqdn);
    
    *out_key = NULL;

    switch(algorithm)
    {
        case DNSKEY_ALGORITHM_RSASHA1:
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            return_value = dnskey_rsa_loadpublic(rdata, rdata_size, origin, out_key); // RC
            break;
            
        case DNSKEY_ALGORITHM_DSASHA1:
        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
            return_value = dnskey_dsa_loadpublic(rdata, rdata_size, origin, out_key); // RC
            break;
#if HAS_ECDSA_SUPPORT
        case DNSKEY_ALGORITHM_ECDSAP256SHA256:
        case DNSKEY_ALGORITHM_ECDSAP384SHA384:
            return_value = dnskey_ecdsa_loadpublic(rdata, rdata_size, origin, out_key); // RC
            break;
#endif
#if HAS_EDDSA_SUPPORT
        case DNSKEY_ALGORITHM_ED25519:
        case DNSKEY_ALGORITHM_ED448:
            return_value = dnskey_eddsa_loadpublic(rdata, rdata_size, origin, out_key); // RC
            break;
#endif
#ifdef DNSKEY_ALGORITHM_DUMMY
        case DNSKEY_ALGORITHM_DUMMY:
            return_value = dnskey_dummy_loadpublic(rdata, rdata_size, origin, out_key);
            break;
#endif
        default:
            return_value = DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
            break;
    }
    
    return return_value;
}

/**
 * Writes a BIGNUM integer to a stream
 */

ya_result
dnskey_write_bignum_as_base64_to_stream(const BIGNUM *num, output_stream *os)
{
    u8 *buffer;
    char *buffer2;
    u8 buffer_[4096];
    char buffer2_[4096];
    
    if(num == NULL)
    {
        return DNSSEC_ERROR_BNISNULL;
    }

    u32 n = BN_num_bytes(num);
    u32 m = BASE64_ENCODED_SIZE(n);
    
    if(n <= sizeof(buffer_))
    {
        buffer = buffer_;
    }
    else
    {
        MALLOC_OBJECT_ARRAY_OR_DIE(buffer, u8, n, TMPBUFFR_TAG);
        //buffer = (u8*)malloc(n);
    }
    
    if(m <= sizeof(buffer2_))
    {
        buffer2 = buffer2_;
    }
    else
    {
        MALLOC_OBJECT_ARRAY_OR_DIE(buffer2, char, m, TMPBUFFR_TAG);
        //buffer2 = (char*)malloc(m);
    }
    
    BN_bn2bin(num, buffer);
    
    u32 o = base64_encode(buffer,n,buffer2);
    
    yassert(o <= m);
    
    output_stream_write(os, buffer2, o);
    
    if(buffer != buffer_) free(buffer);
    if(buffer2 != buffer2_) free(buffer2);
    
    return SUCCESS;
}

/**
 * Returns the most relevant publication time.
 * 
 * publish > activate > created > now
 * 
 * @param key
 * @return 
 */

time_t
dnskey_get_publish_epoch(const dnssec_key *key)
{
    u32 ret;

    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_READ);

    if(key->epoch_publish != 0)
    {
        ret = key->epoch_publish;
    }
    else if(key->epoch_activate != 0)
    {
        ret = key->epoch_activate;
    }
    else if(key->epoch_created != 0)
    {
        ret = key->epoch_created;
    }
    else
    {
        ret = 0; // of course, the last if/else could be replaced by ret = key->epoch_created
    }

    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_READ);
    
    return ret;
}

void
dnskey_set_created_epoch(dnssec_key *key, time_t t)
{
    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    key->epoch_created = t;
    key->status |= DNSKEY_KEY_HAS_SMART_FIELD_CREATED;
    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
}

void
dnskey_set_publish_epoch(dnssec_key *key, time_t t)
{
    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    key->epoch_publish = t;
    key->status |= DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH;
    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
}

/**
 * Returns the most relevant activation time.
 * 
 * activate > publish > created > now
 * 
 * @param key
 * @return 
 */

time_t
dnskey_get_activate_epoch(const dnssec_key *key)
{
    u32 ret;

    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);

    if(key->epoch_activate != 0)
    {
        ret = key->epoch_activate;
    }
    else if(key->epoch_publish != 0)
    {
        ret = key->epoch_publish;
    }
    else if(key->epoch_created != 0)
    {
        ret = key->epoch_created;
    }
    else
    {
        ret = 0;
    }

    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    
    return ret;
}

void
dnskey_set_activate_epoch(dnssec_key *key, time_t t)
{
    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    key->epoch_activate = t;
    key->status |= DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE;
    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
}




/**
 * Returns the most relevant inactivation time.
 * 
 * inactive > delete > never
 * 
 * @param key
 * @return 
 */

time_t
dnskey_get_inactive_epoch(const dnssec_key *key)
{
    u32 ret;

    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);

    if(key->epoch_inactive != 0)
    {
        ret = key->epoch_inactive;
    }
    else if(key->epoch_activate != 0)
    {
        // if activation was a lie, inactivation is one too anyway
        if((key->epoch_created != 0) && (key->epoch_delete > key->epoch_created))
        {
            s64 leniency = (key->epoch_delete - key->epoch_created) / 4;

            if(leniency > 86400)
            {
                leniency = 86400;
            }

            s64 inactive_epoch = key->epoch_delete - leniency;

            if(inactive_epoch > MAX_S32) inactive_epoch = MAX_S32;
            ret = (s32)inactive_epoch;
        }
        else
        {
            ret = MAX_S32;
        }
    }
    else
    {
        ret = MAX_S32; // don't use MAX_U32 here
    }

    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    
    return ret;
}

void
dnskey_set_inactive_epoch(dnssec_key *key, time_t t)
{
    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    key->epoch_inactive = t;
    key->status |= DNSKEY_KEY_HAS_SMART_FIELD_INACTIVE;
    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
}

/**
 * Returns the most relevant delete time.
 * 
 * delete > inactive > never
 * 
 * @param key
 * @return 
 */

time_t
dnskey_get_delete_epoch(const dnssec_key *key)
{
    u32 ret;

    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_READ);
    
    if(key->epoch_delete != 0)
    {
        ret = key->epoch_delete;
    }
    else if(key->epoch_publish == 0)
    {
        // if publication was a lie, delete is one too anyway
        if((key->epoch_created != 0) && (key->epoch_inactive > key->epoch_activate))
        {
            s64 leniency = (key->epoch_inactive - key->epoch_activate) / 4;

            if(leniency > 86400)
            {
                leniency = 86400;
            }

            s64 delete_epoch = key->epoch_inactive + leniency;

            if(delete_epoch > MAX_S32) delete_epoch = MAX_S32;
            ret = (s32)delete_epoch;
        }
        else
        {
            ret = MAX_S32;
        }
    }
    else
    {
        ret = MAX_S32; // don't use MAX_U32 here
    }

    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_READ);
    
    return ret;
}

void
dnskey_set_delete_epoch(dnssec_key *key, time_t t)
{
    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    key->epoch_delete= t;
    key->status |= DNSKEY_KEY_HAS_SMART_FIELD_DELETE;
    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
}

/**
 * 
 * Compares two keys for equality on a cryptographic point of view
 * Uses the tag, flags, algorithm, origin and key content.
 * 
 * @param a
 * @param b
 * 
 * @return TRUE iff the keys are the same.
 */

bool
dnskey_equals(const dnssec_key* a, const dnssec_key* b)
{
    if(a == b)
    {
        return TRUE;
    }
    
    if(dnssec_key_tag_field_set(a) && dnssec_key_tag_field_set(b))
    {
       if(a->tag != b->tag)
       {
           return FALSE;
       }
    }

    if((a->flags == b->flags) && (a->algorithm == b->algorithm))
    {
        /* Compare the origin */

        if(strcmp(a->origin, b->origin) == 0)
        {
            /* Compare the content of the key */
            
            return a->vtbl->dnssec_key_equals(a, b);
        }
    }

    return FALSE;
}

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

bool
dnskey_public_equals(const dnssec_key *a, const dnssec_key *b)
{
    if(a == b)
    {
        return TRUE;
    }
    
    if(dnssec_key_tag_field_set(a) && dnssec_key_tag_field_set(b))
    {
       if(a->tag != b->tag)
       {
           return FALSE;
       }
    }

    if((a->flags == b->flags) && (a->algorithm == b->algorithm))
    {
        /* Compare the origin */

        if(strcmp(a->origin, b->origin) == 0)
        {
            /* Compare the content of the key */
            
            u8 rdata_a[4096];
            u8 rdata_b[4096];
            
            u32 rdata_a_size = a->vtbl->dnssec_key_writerdata(a, rdata_a, sizeof(rdata_a));
            u32 rdata_b_size = b->vtbl->dnssec_key_writerdata(b, rdata_b, sizeof(rdata_b));
            
            if(rdata_a_size == rdata_b_size)
            {
                bool ret = (memcmp(rdata_a, rdata_b, rdata_a_size) == 0);
                return ret;
            }
        }
    }

    return FALSE;
}

/**
 * Returns TRUE if the tag and algorithm of the rdata are matching the ones of the key.
 * 
 * @param key
 * @param rdata
 * @param rdata_size
 * @return 
 */

bool
dnskey_matches_rdata(const dnssec_key *key, const u8 *rdata, u16 rdata_size)
{
     if(dnskey_get_algorithm(key) == rdata[3])
     {
        u16 key_tag = dnskey_get_tag_const(key);
        u16 rdata_tag = dnskey_get_tag_from_rdata(rdata, rdata_size);
        
        return key_tag == rdata_tag;
     }
     
     return FALSE;
}

u16
dnskey_get_tag(dnssec_key *key)
{
    if((dnskey_state_get(key) & DNSKEY_KEY_TAG_SET) == 0)
    {
        u8 rdata[2048];

        u32 rdata_size = key->vtbl->dnssec_key_writerdata(key, rdata, sizeof(rdata));
        
        yassert(rdata_size <= 2048);
        
        u16 tag = dnskey_get_tag_from_rdata(rdata, rdata_size);
        
        group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
        key->tag = tag;
        key->status |= DNSKEY_KEY_TAG_SET;
        group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    }
    
    return key->tag;
}

u16
dnskey_get_tag_const(const dnssec_key *key)
{
    u16 tag;
    
    if(key->status & DNSKEY_KEY_TAG_SET)
    {
        tag = key->tag;
    }
    else
    {
        u8 rdata[2048];

        u32 rdata_size = key->vtbl->dnssec_key_writerdata(key, rdata, sizeof(rdata));
        
        yassert(rdata_size <= 2048);
        
        tag = dnskey_get_tag_from_rdata(rdata, rdata_size);
    }
    
    return tag;
}

u8
dnskey_get_algorithm(const dnssec_key *key)
{
    return key->algorithm;
}

const u8 *
dnskey_get_domain(const dnssec_key *key)
{
    if(key != NULL)
    {
        return key->owner_name;
    }
    else
    {
        return (const u8*)"\004NULL";
    }
}

bool
dnskey_is_private(const dnssec_key *key)
{
    return (key->status & DNSKEY_KEY_IS_PRIVATE) != 0;
}

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

void
dnskey_add_to_chain(dnssec_key *key, dnssec_key **prevp)
{
    yassert(key->next == NULL);
    
    u16 key_tag = dnskey_get_tag(key);

    while(*prevp != NULL)
    {
        if(dnskey_get_tag(*prevp) > key_tag)
        {
            key->next = *prevp;
            *prevp = key;
            dnskey_acquire(key);
            return;
        }

        prevp = &((*prevp)->next);
    }

    // append

    *prevp = key;
    
    dnskey_acquire(key);
    
    key->next = NULL;
}

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

void
dnskey_remove_from_chain(dnssec_key *key, dnssec_key **prevp)
{   
    u16 key_tag = dnskey_get_tag(key);

    while(*prevp != NULL)
    {
        u16 tag;
        if((tag = dnskey_get_tag(*prevp)) >= key_tag)
        {
            if(tag == key_tag)
            {
                dnssec_key *key_to_release = *prevp;
                *prevp = (*prevp)->next;
                // now (and only now) the next field can (and must) be cleared
                key_to_release->next = NULL;
                dnskey_release(key_to_release);
            }

            break;
        }

        prevp = &((*prevp)->next);
    }
}

ya_result
dnskey_new_public_key_from_stream(input_stream *is, dnssec_key** keyp)
{
    parser_s parser;
    ya_result ret;
    u16 rclass;
    u16 rtype;
    u16 flags;
    u16 rdata_size;
    char origin[MAX_DOMAIN_LENGTH + 1];
    u8 fqdn[MAX_DOMAIN_LENGTH];
    u8 rdata[1024 + 4];

    parser_init(&parser, "\"\"''", "()", ";#", "\040\t\r", "\\");
    parser.close_last_stream = FALSE;
    parser_push_stream(&parser, is);

    for(;;)
    {
        if(ISOK(ret = parser_next_token(&parser)))
        {
            if(!(ret & PARSER_WORD))
            {
                if(ret & (PARSER_COMMENT|PARSER_EOL))
                {
                    continue;
                }

                if(ret & PARSER_EOF)
                {
                    input_stream *completed_stream = parser_pop_stream(&parser);
                    input_stream_close(completed_stream);
                    ret = UNEXPECTED_EOF;
                    break;
                }
                continue;
            }
        }

        const char *text = parser_text(&parser);
        u32 text_len = parser_text_length(&parser);
        memcpy(origin, text, text_len);
        origin[text_len] = '\0';

        if(FAIL(ret = cstr_to_dnsname_with_check_len(fqdn, text, text_len)))
        {
            break;
        }

        if(FAIL(ret = parser_copy_next_class(&parser, &rclass)))
        {
            break;
        }

        if(rclass != CLASS_IN)
        {
            // not IN
            ret = DNSSEC_ERROR_EXPECTED_CLASS_IN;
            break;
        }

        if(FAIL(ret = parser_copy_next_type(&parser, &rtype)))
        {
            break;
        }

        if(rtype != TYPE_DNSKEY)
        {
            // not DNSKEY
            ret = DNSSEC_ERROR_EXPECTED_TYPE_DNSKEY;
            break;
        }

        if(FAIL(ret = parser_copy_next_u16(&parser, &flags)))
        {
            break;
        }

        flags = htons(flags); // need to fix the endianness
        SET_U16_AT_P(rdata, flags);

        // protocol (8 bits integer)

        if(FAIL(ret = parser_copy_next_u8(&parser, &rdata[2])))
        {
            break;
        }

        // algorithm (8 bits integer)

        if(FAIL(ret = parser_copy_next_u8(&parser, &rdata[3])))
        {
            break;
        }

        // key (base64)

        if(FAIL(ret = parser_concat_next_tokens_nospace(&parser)))
        {
            break;
        }

        if(BASE64_DECODED_SIZE(ret) > (int)sizeof(rdata) - 4)
        {
            // overflow
            ret = DNSSEC_ERROR_UNEXPECTEDKEYSIZE;
            break;
        }

        if(FAIL(ret = base64_decode(parser_text(&parser), parser_text_length(&parser), &rdata[4])))
        {
            break;
        }

        if(ret > 1024)
        {
            ret = DNSSEC_ERROR_KEYISTOOBIG;
            break;
        }

        rdata_size = 4 + ret;

        ret = dnskey_new_from_rdata(rdata, rdata_size, fqdn, keyp); // RC

        break;
    }

    parser_finalize(&parser);

    return ret;
}

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

ya_result
dnskey_new_public_key_from_file(const char *filename, dnssec_key** keyp)
{
    input_stream is;
    ya_result ret;

    
    if(keyp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    *keyp = NULL;
    
    if(ISOK(ret = file_input_stream_open(&is, filename)))
    {
        ret = dnskey_new_public_key_from_stream(&is, keyp);
        input_stream_close(&is);
    }

    return ret;    
}

ya_result
dnskey_add_private_key_from_stream(input_stream *is, dnssec_key *key, const char* path, u8 algorithm)
{
    dnskey_field_parser dnskey_parser = {NULL, &dnskey_field_dummy_parser};
    parser_s parser;
    s64 timestamp;
    u32 smart_fields = 0;
    ya_result ret;
    u8 parsed_algorithm;

    if(path == NULL)
    {
        path = "";
    }

    // in case of error, the timestamp is set to 0

    fd_mtime(fd_input_stream_get_filedescriptor(is), &timestamp);

    if(ISOK(ret = parser_init(&parser,
                              "",      // by 2
                              "",      // by 2
                              "#;",    // by 1
                              " \t\r:", // by 1
                              ""       // by 1
    )))
    {
        parser.close_last_stream = FALSE;

        parser_push_stream(&parser, is);

        for(;;)
        {
            // get the next token

            if(ISOK(ret = parser_next_token(&parser)))
            {
                if(!(ret & PARSER_WORD))
                {
                    if(ret & (PARSER_COMMENT|PARSER_EOL))
                    {
                        continue;
                    }
                }
                if(ret & PARSER_EOF)
                {
                    break;
                }
            }

            // u32 label_len = parser_text_length(&parser);
            const char *label = parser_text(&parser);
            // makes the word asciiz (need to be undone)
            parser_text_asciiz(&parser);
#if DEBUG
            log_debug("dnskey: parsing %s::%s", path, label);
#endif
            string_node *node = string_set_find(&dnssec_key_load_private_keywords_set, label);
            // makes the word asciiz (need to be undone)
            parser_text_unasciiz(&parser);

            if(node != NULL)
            {
                // push to management

                // parse next word

                if(FAIL(ret = parser_next_word(&parser)))
                {
                    break;
                }

                u32 word_len = parser_text_length(&parser);
                const char *word = parser_text(&parser);

                switch(node->value)
                {
                    case DNSKEY_FIELD_ALGORITHM:
                    {
                        if(ISOK(ret = parser_get_u8(word, word_len, &parsed_algorithm)))
                        {
                            if(algorithm == 0)
                            {
                                algorithm = parsed_algorithm;
                            }
                            else if(parsed_algorithm != algorithm)
                            {
                                log_err("dnssec: error parsing %s: expected algorithm version %i, got %i", path, algorithm, parsed_algorithm);
                                ret = DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
                            }

                            parser_expect_eol(&parser);
                        }
                        break;
                    }
                    case DNSKEY_FIELD_FORMAT:
                    {
                        ret = DNSSEC_ERROR_FILE_FORMAT_VERSION;

                        if(word[0] == 'v')
                        {
                            if(word[1] == '1')
                            {
                                if(word[2] == '.')
                                {
                                    // let's assume all 1.x are compatible
                                    ret = SUCCESS;
                                    break;
                                }
                            }
                        }

                        // makes the word asciiz (need to be undone)
                        parser_text_asciiz(&parser);
                        log_err("dnssec: error parsing %s: expected format v1.x, got %s", path, word);
                        parser_text_unasciiz(&parser);
                        break;
                    }
                    case DNSKEY_FIELD_CREATED:
                    {
                        if(ISOK(ret = parse_yyyymmddhhmmss_check_range_len(word, word_len, &key->epoch_created)))
                        {
                            smart_fields |= DNSKEY_KEY_HAS_SMART_FIELD_CREATED;
                        }
                        break;
                    }
                    case DNSKEY_FIELD_PUBLISH:
                    {
                        if(ISOK(ret = parse_yyyymmddhhmmss_check_range_len(word, word_len, &key->epoch_publish)))
                        {
                            smart_fields |= DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH;
                        }
                        break;
                    }
                    case DNSKEY_FIELD_ACTIVATE:
                    {
                        if(ISOK(ret = parse_yyyymmddhhmmss_check_range_len(word, word_len, &key->epoch_activate)))
                        {
                            smart_fields |= DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE;
                        }
                        break;
                    }

                    case DNSKEY_FIELD_INACTIVE:
                    {
                        if(ISOK(ret = parse_yyyymmddhhmmss_check_range_len(word, word_len, &key->epoch_inactive)))
                        {
                            smart_fields |= DNSKEY_KEY_HAS_SMART_FIELD_INACTIVE;
                        }
                        break;
                    }
                    case DNSKEY_FIELD_DELETE:
                    {
                        if(ISOK(ret = parse_yyyymmddhhmmss_check_range_len(word, word_len, &key->epoch_delete)))
                        {
                            smart_fields |= DNSKEY_KEY_HAS_SMART_FIELD_DELETE;
                        }
                        break;
                    }
                    case DNSKEY_FIELD_ENGINE:
                    {
                        // a base64 encoded null-terminated engine name (ie: "pkcs11")

                        break;
                    }
                    default:
                    {
                        log_err("dnssec: internal error: %s set as %i defined but not handled", node->key, node->value);
                        ret = DNSSEC_ERROR_FIELD_NOT_HANDLED;
                    }
                }

                if(FAIL(ret))
                {
                    if(ret != /**/ ERROR)
                    {
                        log_err("dnssec: error parsing %s: failed to parse value of field %s: %r", path, node->key, ret);
                    }
                    break;
                }

                while(FAIL(parser_expect_eol(&parser)))
                {
                    log_warn("dnssec: expected end of line");
                }
            }
            else
            {
                if(dnskey_parser.data == NULL)
                {
                    switch(algorithm)
                    {
                        case DNSKEY_ALGORITHM_RSASHA1:
                        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
                        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
                        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
                        {
                            dnskey_rsa_parse_init(&dnskey_parser);
                            break;
                        }
                        case DNSKEY_ALGORITHM_DSASHA1:
                        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
                        {
                            dnskey_dsa_parse_init(&dnskey_parser);
                            break;
                        }
#if HAS_ECDSA_SUPPORT
                        case DNSKEY_ALGORITHM_ECDSAP256SHA256:
                        case DNSKEY_ALGORITHM_ECDSAP384SHA384:
                        {
                            dnskey_ecdsa_parse_init(&dnskey_parser);
                            break;
                        }
#endif
#if HAS_EDDSA_SUPPORT
                        case DNSKEY_ALGORITHM_ED25519:
                        case DNSKEY_ALGORITHM_ED448:
                        {
                            dnskey_eddsa_parse_init(&dnskey_parser);
                            break;
                        }
#endif
#ifdef DNSKEY_ALGORITHM_DUMMY
                        case DNSKEY_ALGORITHM_DUMMY:
                        {
                            dnskey_dummy_parse_init(&dnskey_parser);
                            break;
                        }
#endif
                        default:
                        {
                            ret = DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
                            goto dnskey_new_private_key_from_file_failure;  /// *** GOTO *** ///
//                              break;
                        }
                    }
                }

                ret = dnskey_parser.vtbl->parse_field(&dnskey_parser, &parser);

                if(FAIL(ret))
                {
                    log_err("dnssec: error parsing key %s: %r", path, ret);
                    break;
                }

                while(FAIL(parser_expect_eol(&parser)))
                {
                    log_warn("dnssec: expected end of line");
                }
            }

            // if failed push to expected algorithm
            // else issue a warning
            // note the last modification time of the file, for management
            // close
        } // for(;;)

        if(ISOK(ret))
        {
            if(FAIL(ret = dnskey_parser.vtbl->set_key(&dnskey_parser, key)))
            {
                log_err("dnssec: %s cannot be read as a private key", path);
            }

            key->status |= smart_fields;

            switch(smart_fields & (DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH|DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE))
            {
                case DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH:
                {
                    key->epoch_activate = key->epoch_publish;
                    break;
                }
                case DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE:
                {
                    key->epoch_publish = key->epoch_activate;
                    break;
                }
            }
        }

        dnskey_new_private_key_from_file_failure:

        dnskey_parser.vtbl->finalise(&dnskey_parser);
        parser_finalize(&parser);   // also closes the stream

        if(ISOK(ret))
        {
            if(!dnskey_is_private(key))
            {
                log_err("dnssec: %s is not a valid private key", path);
                ret = DNSSEC_ERROR_KEYRING_KEY_IS_NOT_PRIVATE;
            }
        }

        if(ISOK(ret))
        {
            key->timestamp = timestamp;
        }
        else
        {
            dnskey_release(key);
            key = NULL;
        }
   }

    return ret;
}

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

ya_result
dnskey_new_private_key_from_file(const char *filename, dnssec_key **keyp)
{
    dnssec_key *key;

    ya_result ret;
    //u32 smart_fields = 0;
    int path_len;
    int algorithm = -1;
    int tag;
    //u8 parsed_algorithm;
    //bool ext_is_private;
    char extension[16];
    char domain[256];
    u8 origin[256];
    char path[PATH_MAX];
    
    if(keyp == NULL)
    {
        return INVALID_ARGUMENT_ERROR;
    }
    
    const char *name = strrchr(filename,'/');
    if(name == NULL)
    {
        name = filename;
    }
    else
    {
        ++name;
    }
    
    if(sscanf(name, "K%255[^+]+%03d+%05d.%15s", domain, &algorithm, &tag, extension) != 4)
    {
        log_err("dnssec: don't know how to parse key file name: '%s'", filename);
        return PARSESTRING_ERROR;
    }
    
    if(FAIL(ret = cstr_to_dnsname_with_check(origin, domain)))
    {
        log_err("dnssec: could not parse domain name from file name: '%s': %r", filename, ret);
        return ret;
    }
    
    path_len = strlen(filename);
    
    if(memcmp(extension, "private", 7) == 0)
    {
        //ext_is_private = TRUE;
        path_len -= 7;
    }
    else if(memcmp(extension, "key", 3) == 0)
    {
        //ext_is_private = FALSE;
        path_len -= 3;
    }
    else
    {
        log_err("dnssec: expected .private or .key extension for the file: '%s': %r", filename);
        return INVALID_STATE_ERROR;
    }
    
    memcpy(path, filename, path_len);
    
    // first open the public key file, to get the flags
    
    memcpy(&path[path_len], "key", 4);
    if(FAIL(ret = dnskey_new_public_key_from_file(path, &key))) // RC
    {
        return ret;
    }
    
    // then open the private key file
    
    key->nid = 0; // else it will not be editable // scan-build false positive. key cannot be NULL.
    
    memcpy(&path[path_len], "private", 8);
    
    // open parser
    input_stream is;
    if(ISOK(ret = file_input_stream_open(&is, filename)))
    {
        ret = dnskey_add_private_key_from_stream(&is, key, path, algorithm);
        input_stream_close(&is);
    }
    
    *keyp = key;
    
    return ret;
}

/**
 *
 * Save the private part of a key to a stream
 *
 * @param key
 * @param filename
 * @return
 */

void
dnskey_store_private_key_to_stream(dnssec_key *key, output_stream *os)
{
    yassert(os != NULL);
    yassert(key != NULL);

    const char *key_algorithm_name = dnskey_get_algorithm_name_from_value(key->algorithm);

    // basic fields

    osformatln(os, "Private-key-format: v1.3");
    osformatln(os, "Algorithm: %i (%s)", key->algorithm, key_algorithm_name);

    // internal fields

    key->vtbl->dnssec_key_print_fields(key, os);

    // time fields : all are stored as an UTC YYYYMMDDhhmmss

    format_writer epoch = {packedepoch_format_handler_method, NULL};

    if(key->epoch_created != 0)
    {
        epoch.value = (void*)(intptr)key->epoch_created;
        osformatln(os, "Created: %w", &epoch);
    }

    if(key->epoch_publish != 0)
    {
        epoch.value = (void*)(intptr)key->epoch_publish;
        osformatln(os, "Publish: %w", &epoch);
    }

    if(key->epoch_activate != 0)
    {
        epoch.value = (void*)(intptr)key->epoch_activate;
        osformatln(os, "Activate: %w", &epoch);
    }

    if(key->epoch_inactive != 0)
    {
        epoch.value = (void*)(intptr)key->epoch_inactive;
        osformatln(os, "Inactive: %w", &epoch);
    }

    if(key->epoch_delete != 0)
    {
        epoch.value = (void*)(intptr)key->epoch_delete;
        osformatln(os, "Delete: %w", &epoch);
    }

}

/**
 * 
 * Save the private part of a key to a file with the given name
 * 
 * @param key
 * @param filename
 * @return 
 */

ya_result
dnskey_store_private_key_to_file(dnssec_key *key, const char *filename)
{
    yassert(filename != NULL);
    yassert(key != NULL);
    
    output_stream os;
    ya_result ret;
        
    if(ISOK(ret = file_output_stream_create(&os, filename, 0644)))
    {
        buffer_output_stream_init(&os, &os, 4096);

        dnskey_store_private_key_to_stream(key, &os);

        output_stream_close(&os);
        
        ret = SUCCESS;
    }
    
    return ret;
}

/**
 *
 * Save the public part of a key to a stream
 *
 * @param key
 * @param filename
 * @return
 */

ya_result
dnskey_store_public_key_to_stream(dnssec_key *key, output_stream *os)
{
    u8 rdata[2048];

    if(key->vtbl->dnssec_key_rdatasize(key) < sizeof(rdata))
    {
        int rdata_size = key->vtbl->dnssec_key_writerdata(key, rdata, sizeof(rdata));
        rdata_desc dnskeyrdata = {TYPE_DNSKEY, rdata_size, rdata};

        osformatln(os, "; This is a key, keyid %d, for domain %{dnsname}", dnskey_get_tag(key), key->owner_name);
        osformatln(os, "%{dnsname} IN %{typerdatadesc}", key->owner_name, &dnskeyrdata);

        return SUCCESS;
    }
    else
    {
        return BUFFER_WOULD_OVERFLOW;
    }
}

/**
 * 
 * Save the public part of a key to a file with the given name
 * 
 * @param key
 * @param filename
 * @return 
 */

ya_result
dnskey_store_public_key_to_file(dnssec_key *key, const char *filename)
{
    ya_result ret;

    if(key->vtbl->dnssec_key_rdatasize(key) < 2048)
    {
        output_stream os;

        if(ISOK(ret = file_output_stream_create(&os, filename, 0644)))
        {
            if(FAIL(ret = dnskey_store_public_key_to_stream(key, &os)))
            {
                unlink(filename);
            }
            output_stream_close(&os);
        }
    }
    else
    {
        ret = DNSSEC_ERROR_KEYISTOOBIG; // key too big (should never happen)
    }
    
    return ret;
}

/**
 * Save the private part of a key to a dir
 * 
 * @param key
 * @param dirname
 * @return 
 */

ya_result
dnskey_store_private_key_to_dir(dnssec_key *key, const char *dirname)
{
    ya_result ret;
    char filename[PATH_MAX];
    
    if(ISOK(ret = snformat(filename, sizeof(filename), "%s/K%{dnsname}+%03d+%05d.private",
            dirname,
            key->owner_name,
            key->algorithm,
            dnskey_get_tag(key)
            )))
    {
        ret = file_exists(filename);
    
        if(ret == 0)
        {
            ret = dnskey_store_private_key_to_file(key, filename);
        }
        else
        {
            // cannot create the file because it exists already or the path is not accessible
            ret = DNSSEC_ERROR_CANNOT_WRITE_NEW_FILE;
        }
    }
    
    return ret;
}

/**
 * 
 * Saves the public part of the key in a dir
 * 
 * @param key
 * @param dirname
 * @return 
 */

ya_result
dnskey_store_public_key_to_dir(dnssec_key *key, const char *dirname)
{
    ya_result ret;
    char filename[PATH_MAX];
    
    if(ISOK(ret = snformat(filename, sizeof(filename), "%s/K%{dnsname}+%03d+%05d.key",
            dirname,
            key->owner_name,
            key->algorithm,
            dnskey_get_tag(key)
            )))
    {
        ret = file_exists(filename);
    
        if(ret == 0)
        {
            ret = dnskey_store_public_key_to_file(key, filename);
        }
        else
        {
            // cannot create the file because it exists already or the path is not accessible
            ret = DNSSEC_ERROR_CANNOT_WRITE_NEW_FILE;
        }
    }
    
    return ret;
}

/**
 * Save both parts of the key to the directory.
 * 
 * @param key
 * @param dir
 * 
 * @return an error code
 */

ya_result
dnskey_store_keypair_to_dir(dnssec_key *key, const char *dir)
{
    ya_result ret;
    
    if(ISOK(ret = dnskey_store_public_key_to_dir(key, dir)))
    {
        ret = dnskey_store_private_key_to_dir(key, dir);
    }
    
    return ret;
}

ya_result
dnskey_delete_public_key_from_dir(dnssec_key *key, const char *dirname)
{
    ya_result ret;
    char filename[PATH_MAX];

    if(ISOK(ret = snformat(filename, sizeof(filename), "%s/K%{dnsname}+%03d+%05d.key",
                           dirname,
                           key->owner_name,
                           key->algorithm,
                           dnskey_get_tag(key)
    )))
    {
        unlink(filename);
        ret = ERRNO_ERROR;
    }

    return ret;
}

ya_result
dnskey_delete_private_key_from_dir(dnssec_key *key, const char *dirname)
{
    ya_result ret;
    char filename[PATH_MAX];

    if(ISOK(ret = snformat(filename, sizeof(filename), "%s/K%{dnsname}+%03d+%05d.private",
                           dirname,
                           key->owner_name,
                           key->algorithm,
                           dnskey_get_tag(key)
    )))
    {
        unlink(filename);
        ret = ERRNO_ERROR;
    }

    return ret;
}

ya_result
dnskey_delete_keypair_from_dir(dnssec_key *key, const char *dirname)
{
    ya_result ret1 = dnskey_delete_public_key_from_dir(key, dirname);
    ya_result ret2 = dnskey_delete_private_key_from_dir(key, dirname);
    if((ret1 != MAKE_ERRNO_ERROR(EACCES)) && (ret2 != MAKE_ERRNO_ERROR(EACCES)))
    {
        return SUCCESS;
    }
    else
    {
        return MAKE_ERRNO_ERROR(EACCES);
    }
}

bool
dnskey_is_expired(const dnssec_key *key, time_t now)
{
    return (key->epoch_delete != 0 && key->epoch_delete < now) || (key->epoch_inactive != 0 && key->epoch_inactive < now);
}

bool
dnskey_is_expired_now(const dnssec_key *key)
{
    time_t now = time(NULL);
    bool ret = dnskey_is_expired(key, now);
    return ret;
}

int
dnskey_get_size(const dnssec_key *key)
{
    int bits_size = key->vtbl->dnssec_key_size(key);
    return bits_size;
}

u16
dnskey_get_flags(const dnssec_key *key)
{
    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_READ);
    u16 flags = key->flags;
    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_READ);
    return flags;
}

void
dnskey_state_enable(dnssec_key *key, u32 status)
{
    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    key->status |= status;
    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
}

void
dnskey_state_disable(dnssec_key *key, u32 status)
{
    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    key->status &= ~status;
    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
}

u32
dnskey_state_get(const dnssec_key *key)
{
    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_READ);
    u32 state = key->status;
    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_READ);
    return state;
}

/**
 * Initialises internal info.
 */

void
dnskey_init()
{
    if(dnssec_key_load_private_keywords_set == STRING_SET_EMPTY)
    {
        for(int i = 0; dnssec_key_load_private_keywords_common_names[i].data != NULL; i++)
        {
            string_node *node = string_set_insert(&dnssec_key_load_private_keywords_set, dnssec_key_load_private_keywords_common_names[i].data);
            node->value = dnssec_key_load_private_keywords_common_names[i].id;
        }
    }
}

void
dnskey_finalize()
{
    string_set_destroy(&dnssec_key_load_private_keywords_set);
}

/**
 * Returns true if the key is supposed to have been added in the zone at the chosen time already.
 * 
 * @param key
 * @param t
 * @return 
 */

bool
dnskey_is_published(const dnssec_key *key, time_t t)
{
    // there is a publish time and it has occurred

    if(dnskey_has_explicit_publish(key) && (key->epoch_publish <= t))
    {
        bool ret = !dnskey_is_unpublished(key, t);
        return ret;
    }
    
    // there is no publish time

    return !dnskey_is_unpublished(key, t);
}

/**
 * Returns true if the key is supposed to have been removed from the zone at the chosen time already.
 * 
 * @param key
 * @param t
 * @return 
 */

bool
dnskey_is_unpublished(const dnssec_key *key, time_t t)
{
    // true if and only if there is a removal time that occurred already 
    
    return dnskey_has_explicit_delete(key) && (key->epoch_delete <= t);
}

/**
 * Returns true if the key is supposed to be used for signatures.
 * 
 * @param key
 * @param t
 * @return 
 */

bool
dnskey_is_activated(const dnssec_key *key, time_t t)
{
    // there is a active time and it has occurred

    if(dnskey_has_explicit_activate(key))
    {
        group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_READ);
        time_t epoch_activate = key->epoch_activate;
        group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_READ);
        if(epoch_activate <= t) // activation time passed
        {
            bool ret = !dnskey_is_deactivated(key, t);  // not deactivated yet ?
            return ret;
        }

        return FALSE;   // not active yet
    }
    else
    {
        // no activation defined : active at publication time but only until deactivation

        return dnskey_is_published(key, t) && !dnskey_is_deactivated(key, t);
    }
}

/**
 * Assumes we are in 'leniency' seconds in the future for activation (and in the present for deactivation)
 */

bool
dnskey_is_activated_lenient(const dnssec_key *key, time_t t, u32 leniency)
{
    // there is a active time and it has occurred

    if(dnskey_has_explicit_activate(key))
    {
        group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_READ);
        time_t epoch_activate = key->epoch_activate;
        group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_READ);
        if(epoch_activate <= t + leniency) // activation time passed
        {
            bool ret = !dnskey_is_deactivated(key, t);  // not deactivated yet ?
            return ret;
        }

        return FALSE;   // not active yet
    }
    else
    {
        // no activation defined : active at publication time but only until deactivation

        return dnskey_is_published(key, t) && !dnskey_is_deactivated(key, t);
    }
}

/**
 * Returns true if the key must not be used for signatures anymore.
 * 
 * @param key
 * @param t
 * @return 
 */

bool
dnskey_is_deactivated(const dnssec_key *key, time_t t)
{
    // there is a inactive time and it has occurred

    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_READ);
    time_t epoch_inactive = key->epoch_inactive;
    group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_READ);

    if(epoch_inactive > 0)
    {
        return (epoch_inactive <= t);
    }
    else
    {
        // the key has to be activated and not deleted

        return dnskey_is_unpublished(key, t);
    }
}

bool
dnskey_has_explicit_publish(const dnssec_key *key)
{
    return (dnskey_state_get(key) & DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH) != 0;
}

bool
dnskey_has_explicit_delete(const dnssec_key *key)
{
    return (dnskey_state_get(key) & DNSKEY_KEY_HAS_SMART_FIELD_DELETE) != 0;
}

bool
dnskey_has_explicit_publish_or_delete(const dnssec_key *key)
{
    return (dnskey_state_get(key) & (DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH|DNSKEY_KEY_HAS_SMART_FIELD_DELETE)) != 0;
}

bool
dnskey_has_explicit_publish_and_delete(const dnssec_key *key)
{
    return (dnskey_state_get(key) & (DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH|DNSKEY_KEY_HAS_SMART_FIELD_DELETE)) == (DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH|DNSKEY_KEY_HAS_SMART_FIELD_DELETE);
}

bool
dnskey_has_explicit_activate(const dnssec_key *key)
{
    return (dnskey_state_get(key) & DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE) != 0;
}

bool
dnskey_has_explicit_deactivate(const dnssec_key *key)
{
    return (dnskey_state_get(key) & DNSKEY_KEY_HAS_SMART_FIELD_INACTIVE) != 0;
}

bool
dnskey_has_activate_and_deactivate(const dnssec_key *key)
{
    return (dnskey_state_get(key) & (DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE|DNSKEY_KEY_HAS_SMART_FIELD_INACTIVE)) == (DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE|DNSKEY_KEY_HAS_SMART_FIELD_INACTIVE);
}

bool
dnskey_has_activate_or_deactivate(const dnssec_key *key)
{
    return (dnskey_state_get(key) & (DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE|DNSKEY_KEY_HAS_SMART_FIELD_INACTIVE)) != 0;
}

u8
dnskey_supported_algorithm_count()
{
    return sizeof(dnskey_supported_algorithms)/sizeof(dnskey_supported_algorithms[0]);
}

const dnskey_features*
dnskey_supported_algorithm_by_index(u8 index)
{
    if(index < dnskey_supported_algorithm_count())
    {
        const dnskey_features* ret = &dnskey_supported_algorithms[index];
        return ret;
    }

    return NULL;
}

const dnskey_features*
dnskey_supported_algorithm(u8 algorithm)
{
    for(int i = 0; i < dnskey_supported_algorithm_count(); ++i)
    {
        const dnskey_features* ret = &dnskey_supported_algorithms[i];
        if(ret->algorithm == algorithm)
        {
            return ret;
        }
    }

    return NULL;
}

ya_result dnskey_newinstance(u32 size, u8 algorithm, u16 flags, const char* origin, dnssec_key** out_key)
{
    if(size > DNSSEC_MAXIMUM_KEY_SIZE)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }

    ya_result ret;

    switch(algorithm)
    {
        case DNSKEY_ALGORITHM_RSASHA1:
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            ret = dnskey_rsa_newinstance(size, algorithm, flags, origin, out_key);
            break;
        case DNSKEY_ALGORITHM_DSASHA1:
        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
            ret = dnskey_dsa_newinstance(size, algorithm, flags, origin, out_key);
            break;
#if HAS_ECDSA_SUPPORT
        case DNSKEY_ALGORITHM_ECDSAP256SHA256:
        case DNSKEY_ALGORITHM_ECDSAP384SHA384:
            ret = dnskey_ecdsa_newinstance(size, algorithm, flags, origin, out_key);
            break;
#endif
#if HAS_EDDSA_SUPPORT
        case DNSKEY_ALGORITHM_ED25519:
        case DNSKEY_ALGORITHM_ED448:
            ret = dnskey_eddsa_newinstance(size, algorithm, flags, origin, out_key);
            break;
#endif
#ifdef DNSKEY_ALGORITHM_DUMMY
        case DNSKEY_ALGORITHM_DUMMY:
            ret = dnskey_dummy_newinstance(size, algorithm, flags, origin, out_key);
            break;
#endif
        default:
            ret = DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
            break;
    }

    if(ISOK(ret))
    {
        time_t now = time(NULL);
        group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
        (*out_key)->epoch_created = now;
        (*out_key)->status |= DNSKEY_KEY_HAS_SMART_FIELD_CREATED;
        group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    }

    return ret;
}

void
dnskey_init_dns_resource_record(dnssec_key *key, s32 ttl, dns_resource_record *rr)
{
    u8 rdata[8191];
    u32 rdata_size = key->vtbl->dnssec_key_writerdata(key, rdata, sizeof(rdata));
    dns_resource_record_init_record(rr, dnskey_get_domain(key), TYPE_DNSKEY, CLASS_IN, ttl, rdata_size, rdata);
}

/** @} */
