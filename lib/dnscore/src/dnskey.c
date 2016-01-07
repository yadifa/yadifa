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

#include "openssl/sha.h"
#include "dnscore/dnsname.h"
#include "dnscore/dnskey.h"
#include "dnscore/dnskey_rsa.h"
#include "dnscore/dnskey_dsa.h"
#include "dnscore/digest.h"
#include "dnscore/base64.h"

#define ZDB_DNSKEY_TAG          0x59454b534e44
#define ZDB_DNSKEY_NAME_TAG     0x454d414e59454b

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
            digest_sha256_init(ctx);
            break;
            
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            digest_sha512_init(ctx);
            break;
            
        default:
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }
    
    return SUCCESS;
}

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

// sanitises an origin

static char*
origin_dup_sanitize(const char* origin)
{
    char* ret;

    if(origin == NULL)
    {
        MALLOC_OR_DIE(char*, ret, 2, GENERIC_TAG);
        ret[0] = '.';
        ret[1] = '\0';
        return ret;
    }

    int origin_len = strlen(origin);

    if(origin_len == 0)
    {
        MALLOC_OR_DIE(char*, ret, 2, GENERIC_TAG);
        ret[0] = '.';
        ret[1] = '\0';
        return ret;
    }

    if(origin[origin_len - 1] == '.')
    {
        origin_len++;
        MALLOC_OR_DIE(char*, ret, origin_len, GENERIC_TAG);
        //MEMCOPY(ret, origin, origin_len);
        for(int i = 0; i < origin_len; i++)
        {
            ret[i] = tolower(origin[i]);
        }
    }
    else
    {
        MALLOC_OR_DIE(char*, ret, origin_len + 2, GENERIC_TAG);
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

/*
 * Creates an empty key, it will then have to be initialized with a "real" key
 */

dnssec_key*
dnskey_newemptyinstance(u8 algorithm, u16 flags, const char *origin)
{
    yassert(origin != NULL);

    dnssec_key* key;
    MALLOC_OR_DIE(dnssec_key*, key, sizeof(dnssec_key), ZDB_DNSKEY_TAG);
    ZEROMEMORY(key, sizeof(dnssec_key));
    
    key->origin = origin_dup_sanitize(origin);

    /* origin is allocated with ZALLOC using ZALLOC_STRING_OR_DIE
     * In this mode, the byte before the pointer is the size of the string.
     */

    MALLOC_OR_DIE(u8*, key->owner_name, cstr_get_dnsname_len(key->origin), ZDB_DNSKEY_NAME_TAG);
    cstr_to_dnsname(key->owner_name, key->origin);

    key->epoch_created = MAX_U32;
    key->epoch_publish = MAX_U32;
    key->epoch_activate = MAX_U32;
    key->epoch_revoke = MAX_U32;
    key->epoch_inactive = MAX_U32;
    key->epoch_delete = MAX_U32;
    
    key->flags = flags;
    key->algorithm = algorithm;

    /*key->key.X=....*/
    /*key->tag=00000*/
    /*key->is_private=TRUE;*/

    return key;
}

ya_result
dnskey_new_from_rdata(const u8 *rdata, u16 rdata_size, const char *origin, dnssec_key **out_key)
{
    if(out_key == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    //u16 flags = ntohs(GET_U16_AT(rdata[0]));
    u8 algorithm = rdata[3];

    ya_result return_value;
    
    *out_key = NULL;

    switch(algorithm)
    {
        case DNSKEY_ALGORITHM_RSASHA1:
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            return_value = rsa_loadpublic(rdata, rdata_size, origin, out_key);
            break;
            
        case DNSKEY_ALGORITHM_DSASHA1:
        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
            return_value = dsa_loadpublic(rdata, rdata_size, origin, out_key);
            break;
            
        default:
            return_value = DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
            break;
    }
    
    return return_value;
}
void
dnskey_free(dnssec_key *key)
{
#ifdef DEBUG
    if(key->next != NULL)
    {
        // log_err("dnskey_free(%p): a key should be detached from its list before destruction", key);
        logger_flush();
        abort();
    }
#endif
    if(key->vtbl != NULL)
    {
        key->vtbl->dnskey_key_free(key);
    }
    free(key->origin);
    free(key->owner_name);
#ifdef DEBUG
    memset(key, 0xfe, sizeof(dnssec_key));
#endif
    free(key);
}

ya_result
dnskey_write_bignum_as_base64(FILE *f_, const BIGNUM* num_, u8 *tmp_in_, u32 tmp_in_size, char *tmp_out_, u32 tmp_out_size)
{
    if(num_ == NULL)
    {
        return DNSSEC_ERROR_BNISNULL;
    }

    u32 n = BN_num_bytes(num_);
    
    if(n > tmp_in_size)
    {
        return DNSSEC_ERROR_BNISBIGGERTHANBUFFER;
    }

    BN_bn2bin(num_, tmp_in_);
    n = base64_encode(tmp_in_,n,tmp_out_);
    if((n = fwrite(tmp_out_,n,1,f_))!=1)
    {
        return DNSSEC_ERROR_KEYWRITEERROR;
    }
    
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
dnskey_get_publish_epoch(dnssec_key *key)
{
    u32 ret = 0;
    
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
        ret = time(NULL);
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
dnskey_get_activate_epoch(dnssec_key *key)
{
    u32 ret = 0;
    
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
        ret = time(NULL);
    }
    
    return ret;
}

/**
 * Returns the most relevant revocation time.
 * 
 * revoke > never
 * 
 * @param key
 * @return 
 */

u32
dnskey_get_revoke_epoch(dnssec_key *key)
{
    u32 ret = 0;
    
    if(key->epoch_revoke != 0)
    {
        ret = key->epoch_revoke;
    }
    else
    {
        ret = MAX_U32;
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
dnskey_get_inactive_epoch(dnssec_key *key)
{
    u32 ret = 0;
    
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
dnskey_get_delete_epoch(dnssec_key *key)
{
    u32 ret = 0;
    
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
 * Compares two keys for equality
 * 
 * @param a
 * @param b
 * @return 
 */

bool
dnssec_key_equals(dnssec_key* a, dnssec_key* b)
{
    if(a == b)
    {
        return TRUE;
    }

    if((a->tag == b->tag) && (a->flags == b->flags) && (a->algorithm == b->algorithm))
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

u16
dnssec_key_get_tag(dnssec_key *key)
{
    if((key->status & DNSKEY_KEY_TAG_SET) == 0)
    {
        u8 rdata[2048];

        u32 rdata_size = key->vtbl->dnskey_key_writerdata(key, rdata);
        u16 tag = dnskey_get_key_tag_from_rdata(rdata, rdata_size);

        key->tag = tag;
        key->status |= DNSKEY_KEY_TAG_SET;
    }
    
    return key->tag;
}

u8
dnssec_key_get_algorithm(dnssec_key *key)
{
    return key->algorithm;
}

const u8 *
dnssec_key_get_domain(dnssec_key *key)
{
    return key->owner_name;
}

bool
dnssec_key_is_private(dnssec_key *key)
{
    return (key->status & DNSKEY_KEY_IS_PRIVATE) != 0;
}

/**
 * Adds/Remove a key from a key chain.
 * The 'next' field of the key is used.
 * A key can only be in one chain at a time.
 * This is meant to be used in the keystore.
 * 
 * @param keyp
 */

void
dnskey_key_add_in_chain(dnssec_key *key, dnssec_key **prevp)
{
    u16 key_tag = dnssec_key_get_tag(key);

    while(*prevp != NULL)
    {
        if(dnssec_key_get_tag(*prevp) > key_tag)
        {
            key->next = *prevp;
            *prevp = key;
            return;
        }

        prevp = &((*prevp)->next);
    }

    // append

    *prevp = key;
    key->next = NULL;
}

/**
 * Adds/Remove a key from a key chain.
 * The 'next' field of the key is used.
 * A key can only be in one chain at a time.
 * This is meant to be used in the keystore.
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
                *prevp = (*prevp)->next;
                // now (and only now) the next field can (and must) be cleared
                key->next = NULL;
            }

            break;
        }

        prevp = &((*prevp)->next);
    }
}

/** @} */

/*----------------------------------------------------------------------------*/
