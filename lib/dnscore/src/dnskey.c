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
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/stat.h>

#include "openssl/sha.h"
#include "dnscore/dnsname.h"
#include "dnscore/dnskey.h"
#include "dnscore/dnskey_rsa.h"
#include "dnscore/dnskey_dsa.h"
#if HAS_ECDSA_SUPPORT
#include "dnscore/dnskey_ecdsa.h"
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
        default:
            return "?";
    }
}

static ya_result
dnskey_field_parser_dummy_parse_field(struct dnskey_field_parser *parser, struct parser_s *p)
{
    (void)parser;
    (void)p;
    return ERROR;
}

static ya_result
dnskey_field_parser_dummy_set_key(struct dnskey_field_parser *parser, dnssec_key *key)
{
    (void)parser;
    (void)key;
    return ERROR;
}

static void
dnskey_field_parser_dummy_finalise_method(struct dnskey_field_parser *parser)
{
    (void)parser;
}

struct dnskey_field_parser_vtbl dnskey_field_dummy_parser =
{
    dnskey_field_parser_dummy_parse_field,
    dnskey_field_parser_dummy_set_key,
    dnskey_field_parser_dummy_finalise_method,
    "DUMMY"
};

ya_result
dnskey_field_access_parse(const struct dnskey_field_access *sd, void *base, parser_s *p)
{
    ya_result ret = ERROR;

    u32 label_len = parser_text_length(p);
    const char *label = parser_text(p);
    bool parsed_it = FALSE;
    u8 tmp_out[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];
    
    for(; sd->name != NULL; sd++)
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
            
            break;
        }
    } /* for each possible field */
    
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
    
    for(; sd->name != NULL; sd++)
    {
        const u8 *bn_ptr_ptr = (((const u8*)base) + sd->relative);
        const BIGNUM **bn = (const BIGNUM**)bn_ptr_ptr;
        
        if(bn != NULL)
        {
            osformat(os, "%s: ", sd->name);
            dnskey_write_bignum_as_base64_to_stream(*bn, os);
            osprintln(os, "");
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
dnskey_get_key_tag_from_rdata(const u8* dnskey_rdata, u32 dnskey_rdata_size)
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
 * Reference implementation function to generate a key tag from the DNSKEY RDATA wire
 * 
 * @param dnskey_rdata
 * @param dnskey_rdata_size
 * @return 
 */

unsigned int
dnskey_get_key_tag_from_rdata_reference(unsigned char key[], /* the RDATA part of the DNSKEY RR */
                           unsigned int keysize /* the RDLENGTH */
                           )
{
    unsigned long ac; /* assumed to be 32 bits or larger */
    int i; /* loop index */

    for(ac = 0, i = 0; i < keysize; ++i)
        ac += (i & 1) ? key[i] : key[i] << 8;
    ac += (ac >> 16) & 0xFFFF;
    return ac & 0xFFFF;
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
        
    u16 tag = dnskey_get_key_tag_from_rdata(dnskey_rdata, dnskey_rdata_size);
    u8 algorithm = dnskey_rdata[3];
    
    digest_update(&ctx, dnskey_fqdn, dnsname_len(dnskey_fqdn));
    digest_update(&ctx, dnskey_rdata, dnskey_rdata_size);
    
    out_rdata[0] = tag >> 8;
    out_rdata[1] = tag;
    out_rdata[2] = algorithm;
    out_rdata[3] = digest_type;

    digest_final(&ctx, &out_rdata[4], digest_size);
    
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
        ZALLOC_ARRAY_OR_DIE(char*, ret, 2, ORIGNDUP_TAG);
        ret[0] = '.';
        ret[1] = '\0';
        return ret;
    }

    int origin_len = strlen(origin);

    if(origin_len == 0)
    {
        ZALLOC_ARRAY_OR_DIE(char*, ret, 2, ORIGNDUP_TAG);
        ret[0] = '.';
        ret[1] = '\0';
        return ret;
    }

    if(origin[origin_len - 1] == '.')
    {
        origin_len++;
        ZALLOC_ARRAY_OR_DIE(char*, ret, origin_len, ORIGNDUP_TAG);
        //MEMCOPY(ret, origin, origin_len);
        for(int i = 0; i < origin_len; i++)
        {
            ret[i] = tolower(origin[i]);
        }
    }
    else
    {
        ZALLOC_ARRAY_OR_DIE(char*, ret, origin_len + 2, ORIGNDUP_TAG);
        //MEMCOPY(ret, origin, origin_len);
        for(int i = 0; i < origin_len; i++)
        {
            ret[i] = tolower(origin[i]);
        }
        ret[origin_len++] = '.';
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

    dnssec_key* key;
    
    ZALLOC_OR_DIE(dnssec_key*, key, dnssec_key, ZDB_DNSKEY_TAG);
    ZEROMEMORY(key, sizeof(dnssec_key));
    
    key->origin = dnskey_origin_zdup_sanitize(origin);

    /* origin is allocated with ZALLOC using ZALLOC_STRING_OR_DIE
     * In this mode, the byte before the pointer is the size of the string.
     */

    key->owner_name = dnsname_zdup_from_name(key->origin);
    
    key->rc = 1;

    key->epoch_created = time(NULL);
    key->epoch_publish = key->epoch_created;
    key->epoch_activate = key->epoch_created;

    key->epoch_inactive = 0;
    key->epoch_delete = 0;
    
    key->flags = flags;
    key->algorithm = algorithm;

    /*key->key.X=....*/
    /*key->tag=00000*/
    /*key->is_private=TRUE;*/

    return key;
}

/**
 * Increases the reference count on a dnssec_key
 * 
 * @param key
 */

void
dnskey_acquire(dnssec_key *key)
{
    yassert(key->rc > 0);
    log_debug("dnskey_acquire(%p=%i)", key, key->rc+1);
#if DUMP_ACQUIRE_RELEASE_STACK_TRACE
    debug_log_stacktrace(MODULE_MSG_HANDLE,LOG_DEBUG,"dnskey_acquire");
#endif
    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    ++key->rc;
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
    log_debug("dnskey_release(%p=%i)", key, key->rc-1);
#if DUMP_ACQUIRE_RELEASE_STACK_TRACE
    debug_log_stacktrace(MODULE_MSG_HANDLE,LOG_DEBUG,"dnskey_release");
#endif
    group_mutex_lock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
    if(--key->rc == 0)
    {
        group_mutex_unlock(&dnskey_rc_mtx, GROUP_MUTEX_WRITE);
        
#ifdef DEBUG
        if(key->next != NULL)
        {
            // log_err("dnskey_release(%p): a key should be detached from its list before destruction", key);
            logger_flush();
            abort();
        }
#endif
        
        if(key->vtbl != NULL)
        {
            key->vtbl->dnskey_key_free(key);
        }
        ZFREE_ARRAY(key->origin, strlen(key->origin) + 1); // +1 because the 0 has to be taken in account too (duh!)
        dnsname_zfree(key->owner_name);
#ifdef DEBUG
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
        buffer = (u8*)malloc(n);
    }
    
    if(m <= sizeof(buffer2_))
    {
        buffer2 = buffer2_;
    }
    else
    {
        buffer2 = (char*)malloc(m);
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

u32
dnskey_get_publish_epoch(const dnssec_key *key)
{
    u32 ret;
    
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
    
    return ret;
}

/**
 * Returns the most relevant activation time.
 * 
 * activate > publish > created > now
 * 
 * @param key
 * @return 
 */

u32
dnskey_get_activate_epoch(const dnssec_key *key)
{
    u32 ret;
    
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
    
    return ret;
}



/**
 * Returns the most relevant inactivation time.
 * 
 * inactive > delete > never
 * 
 * @param key
 * @return 
 */

u32
dnskey_get_inactive_epoch(const dnssec_key *key)
{
    u32 ret;
    
    if(key->epoch_inactive != 0)
    {
        ret = key->epoch_inactive;
    }
    else if(key->epoch_delete != 0)
    {
        ret = key->epoch_delete;
    }
    else
    {
        ret = MAX_U32;
    }
    
    return ret;
}

/**
 * Returns the most relevant delete time.
 * 
 * delete > inactive > never
 * 
 * @param key
 * @return 
 */

u32
dnskey_get_delete_epoch(const dnssec_key *key)
{
    u32 ret;
    
    if(key->epoch_delete != 0)
    {
        ret = key->epoch_delete;
    }
    else if(key->epoch_inactive != 0)
    {
        ret = key->epoch_inactive;
    }
    else
    {
        ret = MAX_U32;
    }
    
    return ret;
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
dnssec_key_equals(const dnssec_key* a, const dnssec_key* b)
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
dnssec_key_public_equals(const dnssec_key *a, const dnssec_key *b)
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
            
            u32 rdata_a_size = a->vtbl->dnskey_key_writerdata(a, rdata_a);
            u32 rdata_b_size = b->vtbl->dnskey_key_writerdata(b, rdata_b);
            
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
     if(dnssec_key_get_algorithm(key) == rdata[3])
     {
        u16 key_tag = dnssec_key_get_tag_const(key);
        u16 rdata_tag = dnskey_get_key_tag_from_rdata(rdata, rdata_size);
        
        return key_tag == rdata_tag;
     }
     
     return FALSE;
}

u16
dnssec_key_get_tag(dnssec_key *key)
{
    if((key->status & DNSKEY_KEY_TAG_SET) == 0)
    {

        u8 rdata[2048];

        u32 rdata_size = key->vtbl->dnskey_key_writerdata(key, rdata);
        

        yassert(rdata_size <= 2048);
        
        u16 tag = dnskey_get_key_tag_from_rdata(rdata, rdata_size);
        


        key->tag = tag;
        key->status |= DNSKEY_KEY_TAG_SET;
    }
    
    return key->tag;
}

u16
dnssec_key_get_tag_const(const dnssec_key *key)
{
    u16 tag;
    
    if(key->status & DNSKEY_KEY_TAG_SET)
    {
        tag = key->tag;
    }
    else
    {
        u8 rdata[2048];

        u32 rdata_size = key->vtbl->dnskey_key_writerdata(key, rdata);
        
        yassert(rdata_size <= 2048);
        
        tag = dnskey_get_key_tag_from_rdata(rdata, rdata_size);
    }
    
    return tag;
}

u8
dnssec_key_get_algorithm(const dnssec_key *key)
{
    return key->algorithm;
}

const const u8 *
dnssec_key_get_domain(const dnssec_key *key)
{
    return key->owner_name;
}

bool
dnssec_key_is_private(const dnssec_key *key)
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
dnskey_key_add_in_chain(dnssec_key *key, dnssec_key **prevp)
{
    yassert(key->next == NULL);
    
    u16 key_tag = dnssec_key_get_tag(key);

    while(*prevp != NULL)
    {
        if(dnssec_key_get_tag(*prevp) > key_tag)
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
dnskey_key_remove_from_chain(dnssec_key *key, dnssec_key **prevp)
{   
    u16 key_tag = dnssec_key_get_tag(key);

    while(*prevp != NULL)
    {
        u16 tag;
        if((tag = dnssec_key_get_tag(*prevp)) >= key_tag)
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
    parser_s parser;
    input_stream is;
    ya_result ret;
    u16 rclass;
    u16 rtype;
    u16 flags;
    u16 rdata_size;
    char origin[MAX_DOMAIN_LENGTH + 1];
    u8 fqdn[MAX_DOMAIN_LENGTH];
    u8 rdata[1024 + 4];
    
    if(keyp == NULL)
    {
        return ERROR;
    }
    
    *keyp = NULL;
    
    if(ISOK(ret = file_input_stream_open(&is, filename)))
    {
        parser_init(&parser, "\"\"''", "()", ";#", "\040\t\r", "\\");
        parser_push_stream(&parser, &is);
        
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
                ret = ERROR;
                break;
            }
            
            if(FAIL(ret = parser_copy_next_type(&parser, &rtype)))
            {
                break;
            }

            if(rtype != TYPE_DNSKEY)
            {
                // not DNSKEY
                ret = ERROR;
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
            
            if(BASE64_DECODED_SIZE(ret) > sizeof(rdata) - 4)
            {
                // overflow
                ret = ERROR;
                break;
            }

            if(FAIL(ret = base64_decode(parser_text(&parser), parser_text_length(&parser), &rdata[4])))
            {
                break;
            }
            
            if(ret > 1024)
            {
                ret = ERROR;
                break;
            }
            
            rdata_size = 4 + ret;
            
            ret = dnskey_new_from_rdata(rdata, rdata_size, fqdn, keyp); // RC
            
            break;
        }
        
        parser_finalize(&parser);
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
    dnskey_field_parser dnskey_parser = {NULL, &dnskey_field_dummy_parser};
    
    ya_result ret;
    int path_len;
    int algorithm = -1;
    int tag;
    u8 parsed_algorithm;
    //bool ext_is_private;
    char extension[16];
    char domain[256];
    u8 origin[256];
    char path[PATH_MAX];
    
    if(keyp == NULL)
    {
        return ERROR;
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
        return ERROR;
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
        return ERROR;
    }
    
    memcpy(path, filename, path_len);
    
    // first open the public key file, to get the flags
    
    memcpy(&path[path_len], "key", 4);
    if(FAIL(ret = dnskey_new_public_key_from_file(path, &key))) // RC
    {
        return ret;
    }
    
    // then open the private key file
    
    key->nid = 0; // else it will not be editable
    
    memcpy(&path[path_len], "private", 8);
    
    /// @todo 201604130929 edf -- for different engines, the loading will have to first store every unknown field as a BIGNUM, then instantiate a key of the algorithm with the engine, then provides the value to the key
    
    // open parser
    input_stream is;
    if(ISOK(ret = file_input_stream_open(&is, filename)))
    {
        parser_s parser;
        s64 timestamp;
        
        // in case of error, the timestamp is set to 0
        
        fd_mtime(fd_input_stream_get_filedescriptor(&is), &timestamp);
        
        if(ISOK(ret = parser_init(&parser,
            "",      // by 2
            "",      // by 2
            "#;",    // by 1
            " \t\r:", // by 1
            ""       // by 1            
            )))
        {
            parser_push_stream(&parser, &is);

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
#ifdef DEBUG
                log_debug("dnskey: parsing %s::%s", path, label);
#endif
                string_node *node = string_set_avl_find(&dnssec_key_load_private_keywords_set, label);
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
                                if(parsed_algorithm != algorithm)
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
                            ret = ERROR;

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
                            ret = parse_yyyymmddhhmmss_check_range_len(word, word_len, &key->epoch_created);
                            break;
                        }
                        case DNSKEY_FIELD_PUBLISH:
                        {
                            ret = parse_yyyymmddhhmmss_check_range_len(word, word_len, &key->epoch_publish);
                            break;
                        }
                        case DNSKEY_FIELD_ACTIVATE:
                        {
                            ret = parse_yyyymmddhhmmss_check_range_len(word, word_len, &key->epoch_activate);
                            break;
                        }

                        case DNSKEY_FIELD_INACTIVE:
                        {
                            ret = parse_yyyymmddhhmmss_check_range_len(word, word_len, &key->epoch_inactive);
                            break;
                        }
                        case DNSKEY_FIELD_DELETE:
                        {
                            ret = parse_yyyymmddhhmmss_check_range_len(word, word_len, &key->epoch_delete);
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
                            ret = ERROR;
                        }
                    }

                    if(FAIL(ret))
                    {
                        if(ret != ERROR)
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
                        ret = SUCCESS;
                        
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
                            default:
                            {
                                ret = DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
                                break;
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
            }
            
            dnskey_parser.vtbl->finalise(&dnskey_parser);
            parser_finalize(&parser);   // also closes the stream

            if(ISOK(ret))
            {
                if(!dnssec_key_is_private(key))
                {
                    log_err("dnssec: %s is not a valid private key", path);
                    ret = ERROR;
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
        else
        {
            input_stream_close(&is);
        }
    }
    
    *keyp = key;
    
    return ret;
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
dnskey_save_private_key_to_file(dnssec_key *key, const char *filename)
{
    yassert(filename != NULL);
    yassert(key != NULL);
    
    output_stream os;
    ya_result ret;
        
    if(ISOK(ret = file_output_stream_create(&os, filename, 0644)))
    {
        buffer_output_stream_init(&os, &os, 4096);
        
        const char *key_algorithm_name = dnskey_get_algorithm_name_from_value(key->algorithm);
        
        // basic fields
        
        osformatln(&os, "Private-key-format: v1.3");
        osformatln(&os, "Algorithm: %i (%s)", key->algorithm, key_algorithm_name);
        
        // internal fields
       
        key->vtbl->dnssec_key_print_fields(key, &os);
                
        // time fields : all are stored as an UTC YYYYMMDDhhmmss
        
        format_writer epoch = {packedepoch_format_handler_method, NULL};
        
        if(key->epoch_created != 0)
        {
            epoch.value = (void*)(intptr)key->epoch_created;
            osformatln(&os, "Created: %w", &epoch);
        }
        
        if(key->epoch_publish != 0)
        {
            epoch.value = (void*)(intptr)key->epoch_publish;
            osformatln(&os, "Publish: %w", &epoch);
        }
        
        if(key->epoch_activate != 0)
        {
            epoch.value = (void*)(intptr)key->epoch_activate;
            osformatln(&os, "Activate: %w", &epoch);
        }
        
        if(key->epoch_inactive != 0)
        {
            epoch.value = (void*)(intptr)key->epoch_inactive;
            osformatln(&os, "Inactive: %w", &epoch);
        }
        
        if(key->epoch_delete != 0)
        {
            epoch.value = (void*)(intptr)key->epoch_delete;
            osformatln(&os, "Delete: %w", &epoch);
        }

        
        output_stream_close(&os);
        
        ret = SUCCESS;
    }
    
    return ret;
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
dnskey_save_public_key_to_file(dnssec_key *key, const char *filename)
{
    ya_result ret;
    u8 rdata[2048];
    
    if(key->vtbl->dnskey_key_rdatasize(key) < sizeof(rdata))
    {
        output_stream os;
        int rdata_size = key->vtbl->dnskey_key_writerdata(key, rdata);

        if(ISOK(ret = file_output_stream_create(&os, filename, 0644)))
        {                
            rdata_desc dnskeyrdata = {TYPE_DNSKEY, rdata_size, rdata};
            
            osformatln(&os, "; This is a key, keyid %d, for domain %{dnsname}", dnssec_key_get_tag(key), key->owner_name);
            osformatln(&os, "%{dnsname} IN %{typerdatadesc}", key->owner_name, &dnskeyrdata);
            output_stream_close(&os);
        }
    }
    else
    {
        ret = ERROR; // key too big (should never happen)
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
dnskey_save_private_key_to_dir(dnssec_key *key, const char *dirname)
{
    ya_result ret;
    char filename[PATH_MAX];
    
    if(ISOK(ret = snformat(filename, sizeof(filename), "%s/K%{dnsname}+%03d+%05d.private",
            dirname,
            key->owner_name,
            key->algorithm,
            dnssec_key_get_tag(key)
            )))
    {
        ret = file_exists(filename);
    
        if(ret == 0)
        {
            ret = dnskey_save_private_key_to_file(key, filename);
        }
        else
        {
            // cannot create the file because it exists already or the path is not accessible
            ret = ERROR;
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
dnskey_save_public_key_to_dir(dnssec_key *key, const char *dirname)
{
    ya_result ret;
    char filename[PATH_MAX];
    
    if(ISOK(ret = snformat(filename, sizeof(filename), "%s/K%{dnsname}+%03d+%05d.key",
            dirname,
            key->owner_name,
            key->algorithm,
            dnssec_key_get_tag(key)
            )))
    {
        ret = file_exists(filename);
    
        if(ret == 0)
        {
            ret = dnskey_save_public_key_to_file(key, filename);
        }
        else
        {
            // cannot create the file because it exists already or the path is not accessible
            ret = ERROR;
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
dnskey_save_keypair_to_dir(dnssec_key *key, const char *dir)
{
    ya_result ret;
    
    if(ISOK(ret = dnskey_save_public_key_to_dir(key, dir)))
    {
        ret = dnskey_save_private_key_to_dir(key, dir);
    }
    
    return ret;
}

bool
dnskey_is_expired(const dnssec_key *key)
{
    time_t now = time(NULL);
    return (key->epoch_delete != 0 && key->epoch_delete < now) || (key->epoch_inactive != 0 && key->epoch_inactive < now);
}



int
dnskey_get_size(const dnssec_key *key)
{
    int bits_size = key->vtbl->dnskey_key_size(key);
    return bits_size;
}

u16
dnssec_key_get_flags(const dnssec_key *key)
{
    return key->flags;
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
            string_node *node = string_set_avl_insert(&dnssec_key_load_private_keywords_set, dnssec_key_load_private_keywords_common_names[i].data);
            node->value = dnssec_key_load_private_keywords_common_names[i].id;
        }
    }
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
    
    if((key->epoch_publish != 0) && (key->epoch_publish <= t))
    {
        bool ret = !dnskey_is_unpublished(key, t);
        return ret;
    }
    
    // there is no publish time

    return FALSE;
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
    
    return ((key->epoch_delete != 0) && (key->epoch_delete < t));
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
    // there is a actuve time and it has occurred
    
    if((key->epoch_activate != 0) && (key->epoch_activate <= t))
    {
        bool ret = !dnskey_is_deactivated(key, t);
        return ret;
    }
    
    // there is no publish time

    return FALSE;
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

    return ((key->epoch_inactive != 0) && (key->epoch_inactive < t));
}

/** @} */

/*----------------------------------------------------------------------------*/
