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

/*
#include <arpa/inet.h>
#include <ctype.h>
*/

#include "dnscore/dnscore-config.h"
#include "dnscore/dnskey-keyring.h"

ya_result
dnskey_keyring_init(dnskey_keyring *ks)
{
    u32_set_avl_init(&ks->tag_to_key);
    mutex_init(&ks->mtx);
    return SUCCESS;
}

ya_result
dnskey_keyring_add(dnskey_keyring *ks, dnssec_key* key)
{
    u32 hash = key->algorithm;
    hash <<= 16;
    hash |= key->tag;
    
    mutex_lock(&ks->mtx);
    u32_node *node = u32_set_avl_insert(&ks->tag_to_key, hash);
    
    if(node->value == NULL)
    {
        node->value = key;
        
        mutex_unlock(&ks->mtx);
        
        return SUCCESS;
    }
    else
    {
        mutex_unlock(&ks->mtx);
        
        return DNSSEC_ERROR_KEYRING_ALGOTAG_COLLISION;
    }
}

dnssec_key*
dnskey_keyring_get(dnskey_keyring *ks, u8 algorithm, u16 tag, const u8 *domain)
{
    u32 hash = algorithm;
    hash <<= 16;
    hash |= tag;
    
    mutex_lock(&ks->mtx);
    
    u32_node *node = u32_set_avl_find(&ks->tag_to_key, hash);
    
    if(node != NULL)
    {
        dnssec_key *key = (dnssec_key*)node->value;
        
        mutex_unlock(&ks->mtx);

        if((key != NULL) && dnsname_equals(key->owner_name, domain))
        {
            return key;
        }
    }
    else
    {
        mutex_unlock(&ks->mtx);
    }
    
    return NULL;
}

dnssec_key*
dnskey_keyring_remove(dnskey_keyring *ks, u8 algorithm, u16 tag, const u8 *domain)
{
    u32 hash = algorithm;
    hash <<= 16;
    hash |= tag;
    
    mutex_unlock(&ks->mtx);
    
    u32_node *node = u32_set_avl_find(&ks->tag_to_key, hash);
    
    if(node != NULL)
    {    
        dnssec_key *key = (dnssec_key*)node->value;
        
        mutex_unlock(&ks->mtx);

        if((key != NULL) && dnsname_equals(key->owner_name, domain))
        {
            u32_set_avl_delete(&ks->tag_to_key, hash);
            
            return key;
        }
    }
    else
    {
        mutex_unlock(&ks->mtx);
    }
    
    return NULL;
}

static void
dnskey_keyring_destroy_callback(void *node_keyp)
{
    u32_node *node = (u32_node*)node_keyp;
    dnssec_key *key = (dnssec_key*)node->value;
    dnssec_key *key_next;
    while(key != NULL)
    {
        key_next = key->next;
        key->next = NULL;
        dnskey_free(key);
        key = key_next;
    }
}

void
dnskey_keyring_destroy(dnskey_keyring *ks)
{
    mutex_lock(&ks->mtx);
    u32_set_avl_callback_and_destroy(&ks->tag_to_key, dnskey_keyring_destroy_callback);
    mutex_unlock(&ks->mtx);
    
    mutex_destroy(&ks->mtx);
}

/** @} */
