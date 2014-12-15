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
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>

#include <pthread.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>

#include <dnscore/base64.h>

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/dnssec.h"
#include "dnsdb/dnssec_config.h"
#include "dnsdb/dnssec_keystore.h"

#include "dnsdb/zdb_alloc.h"

#include "dnsdb/zdb_listener.h"

#include <dnscore/format.h>

#define MODULE_MSG_HANDLE g_dnssec_logger

extern logger_handle *g_dnssec_logger;

#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

#define ZDB_KEYSTORE_ORIGIN_TAG 0x4e494749524f534b

#define OAT_PRIVATE_FORMAT "K%s+%03d+%05i.private"
#define OAT_DNSKEY_FORMAT "K%s+%03d+%05i.key"

static const char* g_keystore_path = DNSSEC_DEFAULT_KEYSTORE_PATH;
static dnssec_keystore g_keystore = NULL;
static pthread_mutex_t keystore_mutex = PTHREAD_MUTEX_INITIALIZER;

#define KEY_HASH(key) ((((hashcode)key->tag)<<16)|key->flags|(key->algorithm<<1))
#define TAG_FLAGS_ALGORITHM_HASH(t_,f_,a_) ((((hashcode)t_)<<16)|(f_)|((a_)<<1))

// sanitises an origin

static void
origin_copy_sanitize(char* target, const char* origin)
{
    if(origin == NULL)
    {
        target[0] = '.';
        target[1] = '\0';
        return;
    }

    int origin_len = strlen(origin);

    if(origin_len == 0)
    {
        target[0] = '.';
        target[1] = '\0';
        return;
    }

    if(origin[origin_len - 1] == '.')
    {
        origin_len++;
        MEMCOPY(target, origin, origin_len);
    }
    else
    {
        MEMCOPY(target, origin, origin_len);
        target[origin_len++] = '.';
        target[origin_len] = '\0';
    }
}

const char*
dnssec_keystore_getpath()
{
    return g_keystore_path;
}

static const char* dnssec_default_keystore_path = DNSSEC_DEFAULT_KEYSTORE_PATH;

void
dnssec_keystore_resetpath()
{
    /*
     * cast to void to avoid the -Wstring-compare warning
     */
    
    if(((void*)g_keystore_path) != ((void*)dnssec_default_keystore_path))
    {
        free((void*)g_keystore_path);
        g_keystore_path = dnssec_default_keystore_path;
    }
}

void
dnssec_keystore_setpath(const char* path)
{
    dnssec_keystore_resetpath();

    if(path != NULL)
    {
        g_keystore_path = strdup(path);
    }
}

ya_result
dnssec_keystore_add(dnssec_key* key)
{
    yassert(key != NULL);

    pthread_mutex_lock(&keystore_mutex);

    dnssec_key** head = (dnssec_key**)btree_insert(&g_keystore, KEY_HASH(key));

    /* head will NEVER be NULL */

    /*
     * Look for a dup
     */

    dnssec_key* tmp = *head;

    while(tmp != NULL)
    {
        if(dnssec_key_equals(key, tmp))
        {
            /* Already in ... */

#ifdef DEBUG
            formatln("dnssec_keystore_add: duplicate key %{dnsname} %u %u", key->owner_name, key->flags, key->tag);
#endif

            pthread_mutex_unlock(&keystore_mutex);

            return (key == tmp) ? SUCCESS : DNSSEC_ERROR_DUPLICATEKEY;
        }

        tmp = tmp->next;
    }

    key->next = *head;
    *head = key;

    pthread_mutex_unlock(&keystore_mutex);

    return SUCCESS;
}

dnssec_key*
dnssec_keystore_get(u8 algorithm, u16 tag, u16 flags, const char *origin)
{
    pthread_mutex_lock(&keystore_mutex);

    dnssec_key* head = (dnssec_key*)btree_find(&g_keystore, TAG_FLAGS_ALGORITHM_HASH(tag, flags, algorithm));

    if(head == NULL)
    {
        pthread_mutex_unlock(&keystore_mutex);

        return NULL;
    }

    char clean_origin[MAX_DOMAIN_LENGTH];

    origin_copy_sanitize(clean_origin, origin);

    while(head != NULL)
    {
        if(strcmp(head->origin, clean_origin) == 0)
        {
            break;
        }

        head = head->next;
    }

    pthread_mutex_unlock(&keystore_mutex);

    return head;
}

dnssec_key*
dnssec_keystore_remove(u8 algorithm, u16 tag, u16 flags, const char *origin)
{
    hashcode hash = TAG_FLAGS_ALGORITHM_HASH(tag, flags, algorithm);

    pthread_mutex_lock(&keystore_mutex);

    dnssec_key** head = (dnssec_key**)btree_findp(&g_keystore, hash);

    if(head == NULL)
    {
        pthread_mutex_unlock(&keystore_mutex);

        return NULL;
    }

    dnssec_key* ret_sll = NULL;

    dnssec_key* tmp = *head;

    if(tmp != NULL)
    {
        dnssec_key* prev = NULL;
        char clean_origin[MAX_DOMAIN_LENGTH];

        origin_copy_sanitize(clean_origin, origin);

        do
        {
            if(strcmp(tmp->origin, clean_origin) == 0)
            {
                /* MATCH : remove from the list, add in the return list */
                if(prev == NULL)
                {
                    *head = tmp->next;
                }
                else
                {
                    prev->next = tmp->next;
                }

                tmp->next = ret_sll;
                ret_sll = tmp;
                tmp = tmp->next;
                continue;
            }

            prev = tmp;
            tmp = tmp->next;
        }
        while(tmp != NULL);
    }

    if(*head == NULL)
    {
        /* Delete the node */

        btree_delete(&g_keystore, hash);
    }

    pthread_mutex_unlock(&keystore_mutex);

    return ret_sll;
}

static void
dnssec_keystore_destroy_callback(void* data)
{
    dnssec_key *key = (dnssec_key*)data;

    while(key != NULL)
    {
        dnssec_key *next = key->next;
        key->next = NULL;
        dnskey_free(key);
        key = next;
    }
}

void
dnssec_keystore_destroy()
{
    pthread_mutex_lock(&keystore_mutex);

    btree_callback_and_destroy(g_keystore, dnssec_keystore_destroy_callback);
    g_keystore = NULL;

    pthread_mutex_unlock(&keystore_mutex);
}

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

/** Generates a private key, store in the keystore
 *  The caller is supposed to create a resource record with this key and add
 *  it to the owner.
 */

ya_result
dnssec_key_createnew(u8 algorithm, u32 size, u16 flags, const char *origin, dnssec_key **out_key)
{
    ya_result return_value;
    
    dnssec_key* key = NULL;

    char clean_origin[MAX_DOMAIN_LENGTH];
    
    /* sanitise the origin name */

    origin_copy_sanitize(clean_origin, origin);
    
    /**
     * @note if 65536 keys exist then this function will loop forever
     */

    for(;;)
    {
        switch(algorithm)
        {
            case DNSKEY_ALGORITHM_RSASHA1:
            case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
            case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
            case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            {
                if(FAIL(return_value = rsa_newinstance(size, algorithm, flags, clean_origin, &key)))
                {
                    return return_value;
                }

                break;
            }
            case DNSKEY_ALGORITHM_DSASHA1:
            case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
            {
                if(FAIL(return_value = dsa_newinstance(size, algorithm, flags, clean_origin, &key)))
                {
                    return return_value;
                }

                break;
            }
            default:
            {
                return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
            }
        }

        dnssec_key* same_tag_key;
        
        if(ISOK(return_value = dnssec_key_load_private(algorithm, key->tag, flags, clean_origin, &same_tag_key)))
        {
            dnssec_keystore_add(key);
            break;
        }
        
        /**
         * @note The error here should be the one derived from errno : file not found
         */
        
        ZFREE_STRING(key->owner_name);
        ZFREE_STRING(key->origin);

        key->vtbl->dnskey_key_free(key);

        ZFREE(key, dnssec_key);
    }
    
    *out_key = key;

    return SUCCESS;
}

void
dnssec_key_free(dnssec_key* key)
{
    if(key != NULL)
    {
        dnssec_keystore_remove(key->algorithm, key->tag, key->flags, key->origin);

        ZFREE_STRING(key->owner_name);
        ZFREE_STRING(key->origin);

        key->vtbl->dnskey_key_free(key);

        ZFREE(key, dnssec_key);
    }
}

ya_result
dnskey_load_public(const u8 *rdata, u16 rdata_size, const char *origin, dnssec_key **out_key)
{
    u16 flags = ntohs(GET_U16_AT(rdata[0]));
    u8 algorithm = rdata[3];

    u16 tag = dnskey_getkeytag(rdata, rdata_size);
    
    ya_result return_value = SUCCESS;
    
    dnssec_key* key = dnssec_keystore_get(algorithm, tag, flags, origin);

    if(key == NULL)
    {
        if(ISOK(return_value = dnskey_new_from_rdata(rdata, rdata_size, origin, &key)))
        {
            dnssec_keystore_add(key);
        }
    }
    
    *out_key = key;

    return return_value;
}

/** Load a private key from the disk or the keystore, then return it */
ya_result
dnssec_key_load_private(u8 algorithm, u16 tag, u16 flags, const char* origin, dnssec_key **out_key)
{
    dnssec_key* key = dnssec_keystore_get(algorithm, tag, flags, origin);
    ya_result return_value = ERROR;
    bool has_public_key = FALSE;
    
    *out_key = NULL;
    
    if(key != NULL && ! key->is_private)
    {
        has_public_key = TRUE;
        key = NULL;
    }

    if(key == NULL)
    {
        char clean_origin[MAX_DOMAIN_LENGTH];

        origin_copy_sanitize(clean_origin, origin);

        /* Load from the disk, add to the keystore */

        char path[MAX_PATH];
        if(snprintf(path, MAX_PATH, "%s/" OAT_PRIVATE_FORMAT, g_keystore_path, clean_origin, algorithm, tag) >= MAX_PATH)
        {
            /* Path bigger than MAX_PATH */
            return BIGGER_THAN_MAX_PATH;
        }

        log_debug("dnssec_key_load_private: opening file %s", path);

        FILE *f;
        
        if((f = fopen(path, "rb")) == NULL)
        {
            return ERRNO_ERROR;
        }

        switch(algorithm)
        {            
            case DNSKEY_ALGORITHM_RSASHA1:
            case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
            case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
            case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            {
                return_value = rsa_loadprivate(f, algorithm, flags, clean_origin, &key);

                break;
            }
            case DNSKEY_ALGORITHM_DSASHA1:
            case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
            {
                return_value = dsa_loadprivate(f, algorithm, flags, clean_origin, &key);

                break;
            }
            default:
            {
                return_value = DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
            }
        }

        fclose(f);

        if(ISOK(return_value))
        {
            if(has_public_key)
            {
                /*
                 * remove the old (public) version
                 */

                dnssec_keystore_remove(algorithm, tag, flags, origin);
            }
            
            dnssec_keystore_add(key);
            
            *out_key = key;
        }
    }
    else
    {
        *out_key = key;
        return_value = SUCCESS;
    }

    return return_value;
}

ya_result
dnssec_key_store_private(dnssec_key* key)
{
    char path[MAX_PATH];

    if(key == NULL || key->key.any == NULL || key->origin == NULL || !key->is_private)
    {
        return DNSSEC_ERROR_INCOMPLETEKEY;
    }

    if(snprintf(path, MAX_PATH, "%s/" OAT_PRIVATE_FORMAT, g_keystore_path, key->origin, key->algorithm, key->tag) >= MAX_PATH)
    {
        /* Path bigger than MAX_PATH */
        return DNSSEC_ERROR_KEYSTOREPATHISTOOLONG;
    }

    switch(key->algorithm)
    {
        case DNSKEY_ALGORITHM_RSASHA1:
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
        case DNSKEY_ALGORITHM_DSASHA1:
        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
        {
            break;
        }
        default:
        {
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
        }
    }
    
    FILE* f;

    if((f = fopen(path, "w+b")) == NULL)
    {
        return DNSSEC_ERROR_UNABLETOCREATEKEYFILES;
    }
    
    u8 tmp_in[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];
    char tmp_out[BASE64_ENCODED_SIZE(DNSSEC_MAXIMUM_KEY_SIZE_BYTES)];

    void* base = key->key.any;
    
    /* Modulus */

    fprintf(f, "Private-key-format: v1.2\nAlgorithm: %i (?)", key->algorithm); /// @todo 20140523 edf -- think about handling v1.3

    const struct structdescriptor *sd = key->vtbl->dnssec_key_get_fields_descriptor(key);
    
    ya_result return_code = ERROR;
    
    while(sd->name != NULL)
    {
        fprintf(f, "%s: ", sd->name);
        
        BIGNUM **valuep = (BIGNUM**)&(((u8*)base)[sd->address]);
        
        //WRITE_BIGNUM_AS_BASE64(f, *valuep, tmp_in, tmp_out);
        
        if(FAIL(return_code = dnskey_write_bignum_as_base64(f, *valuep, tmp_in, sizeof(tmp_in), tmp_out, sizeof(tmp_out))))
        {
            break;
        }
        
        fputs("\n", f);
        
        sd++;
    }

    fclose(f);

    return return_code;
}

ya_result
dnssec_key_store_dnskey(dnssec_key* key)
{
    char path[MAX_PATH];

    if(snprintf(path, MAX_PATH, "%s/"OAT_DNSKEY_FORMAT, g_keystore_path, key->origin, key->algorithm, key->tag) >= MAX_PATH)
    {
        return DNSSEC_ERROR_KEYSTOREPATHISTOOLONG;
    }

    FILE* f;

    if((f = fopen(path, "w+b")) == NULL)
    {
        return DNSSEC_ERROR_UNABLETOCREATEKEYFILES;
    }

    u32 lc = 1;
    const char* p = key->origin;
    char c;
    while((c = *p) != '\0')
    {
        if(c == '.')
        {
            lc++;
        }
        p++;
    }

    fprintf(f, "%s IN DNSKEY %u %u %u ", key->origin, key->flags, lc, key->algorithm);

    u8* rdata;
    u32 rdata_size = key->vtbl->dnskey_key_rdatasize(key);

    MALLOC_OR_DIE(u8*, rdata, rdata_size, DNSKEY_RDATA_TAG);

    /* store the RDATA */

    key->vtbl->dnskey_key_writerdata(key, rdata);

    char b64[64];
    u8* ptr = rdata;

    while(rdata_size >= 48)
    {
        base64_encode(ptr, 48, b64);
        if(fwrite(b64, 64, 1, f) != 1)
        {
            fclose(f);
            return DNSSEC_ERROR_KEYWRITEERROR;
        }
        rdata_size -= 48;
    }

    if(rdata_size > 0)
    {
        u32 n = base64_encode(ptr, rdata_size, b64);
        if(fwrite(b64, n, 1, f) != 1)
        {
            fclose(f);
            return DNSSEC_ERROR_KEYWRITEERROR;
        }
    }

    free(rdata);

    fclose(f);

    return SUCCESS;
}

/*
dnssec_key* dnskey_key_clone_container(dnssec_key* original_key)
{
    dnssec_key* key;
    ZALLOC_OR_DIE(dnssec_key*, key, dnssec_key, ZDB_DNSKEY_TAG);
    MEMCOPY(key, original_key, sizeof (dnssec_key));
    key->next = NULL;
    return key;
}

dnssec_key* dnskey_key_destroy_container(dnssec_key* key)
{
    ZFREE(key, dnssec_key);
}
 */
void
dnssec_key_addrecord(zdb_zone* zone, dnssec_key* key)
{
    zdb_packed_ttlrdata* dnskey;

    u32 rdata_size = key->vtbl->dnskey_key_rdatasize(key) + 4;

    ZDB_RECORD_ZALLOC_EMPTY(dnskey, 86400, rdata_size);
    u8* rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(dnskey);

    SET_U16_AT(rdata[0], htons(key->flags)); /// @todo 20140523 edf -- DNSKEY NATIVEFLAGS
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = key->algorithm;
    key->vtbl->dnskey_key_writerdata(key, &rdata[4]);

    /*
     * The DNSKEY record is done
     * Add it without dups
     */

    if(!zdb_record_insert_checked(&zone->apex->resource_record_set, TYPE_DNSKEY, dnskey)) /* FB done */
    {
        /* It's a dup */

        ZDB_RECORD_ZFREE(dnskey);

        return;
    }

#if ZDB_CHANGE_FEEDBACK_SUPPORT != 0
    /*
     * Update ICMTL.
     *
     * NOTE: the zdb_rr_label set of functions are zdb_listener-aware but the zdb_record ones are not.
     * That's why this one needs a call to the listener.
     *
     */

    zdb_ttlrdata unpacked_ttlrdata;
    unpacked_ttlrdata.rdata_pointer = &dnskey->rdata_start[0];
    unpacked_ttlrdata.rdata_size = dnskey->rdata_size;
    unpacked_ttlrdata.ttl = dnskey->ttl;
    u8 * origin_vector[1] = {zone->origin};
    zdb_listener_notify_add_record(origin_vector, 0, TYPE_DNSKEY, &unpacked_ttlrdata);
#endif
}
/*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/

