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

/*
#include <arpa/inet.h>
#include <ctype.h>
*/

#include "dnscore/dnscore-config.h"
#include "dnscore/dnskey-keyring.h"
#include "dnscore/logger.h"
#include "dnscore/message.h"
#include "dnscore/packet_reader.h"

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

ya_result
dnskey_keyring_init(dnskey_keyring *ks)
{
    u32_set_init(&ks->tag_to_key);
    mutex_init(&ks->mtx);
    return SUCCESS;
}

static void
dnskey_keyring_finalize_callback(u32_node *node)
{
    dnssec_key* key;
    key = (dnssec_key*)node->value;
    dnskey_release(key);
    node->value = NULL;
}

void
dnskey_keyring_finalize(dnskey_keyring *ks)
{
    u32_set_callback_and_destroy(&ks->tag_to_key, dnskey_keyring_finalize_callback);
    mutex_destroy(&ks->mtx);
}

ya_result
dnskey_keyring_add(dnskey_keyring *ks, dnssec_key* key)
{
    u32 hash = key->algorithm;
    hash <<= 16;
    hash |= key->tag;
    
    mutex_lock(&ks->mtx);
    u32_node *node = u32_set_insert(&ks->tag_to_key, hash);
    
    if(node->value == NULL)
    {
        dnskey_acquire(key);
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

ya_result
dnskey_keyring_add_from_nameserver(dnskey_keyring *ks, const host_address *ha, const u8 *domain)
{
    message_data *query = message_new_instance();
    ya_result ret;
    
    log_debug("%{dnsname}: fetching public keys from %{hostaddr}", domain, ha);
    
    message_make_query(query, (u16)rand(), domain, TYPE_DNSKEY, CLASS_IN);

    if(ISOK(ret = message_query(query, ha)))
    {
        if(message_get_rcode(query) == RCODE_OK)
        {
            log_debug("%{dnsname}: %{hostaddr} answered", domain, ha);

            if(message_get_query_count(query) == 1)
            {
                u16 answers;
                
                if((answers = message_get_answer_count(query)) > 0)
                {
                    // extract all keys
                    packet_unpack_reader_data purd;
                    packet_reader_init_from_message(&purd, query);

                    packet_reader_skip_fqdn(&purd);
                    packet_reader_skip(&purd, 4);

                    int keys_added = 0;
                    
                    for(u16 i = 0; i < answers; ++i)
                    {
                        dnssec_key *key = NULL;
                        u16 rtype;
                        u16 rclass;
                        s32 rttl;
                        u16 rdata_size;
                        u8 rdata[1024];

                        packet_reader_read_fqdn(&purd, rdata, sizeof(rdata));
                        
                        if(dnslabel_equals_ignorecase_left(domain, rdata))
                        {
                            packet_reader_read_u16(&purd, &rtype);
                            packet_reader_read_u16(&purd, &rclass);
                            packet_reader_read_s32(&purd, &rttl);
                            packet_reader_read_u16(&purd, &rdata_size);
                            rdata_size = ntohs(rdata_size);

                            if(rtype == TYPE_DNSKEY)
                            {
                                if(ISOK(ret = packet_reader_read_rdata(&purd, rtype, rdata_size, rdata, rdata_size)))
                                {                        
                                    if(ISOK(ret = dnskey_new_from_rdata(rdata, rdata_size, domain, &key)))
                                    {
                                        if(ISOK(ret = dnskey_keyring_add(ks, key)))
                                        {
                                            log_info("%{dnsname}: %{hostaddr} added dnskey %{dnsname}: +%03d+%05d/%d added",
                                                    domain, ha,
                                                    dnskey_get_domain(key), dnskey_get_algorithm(key),
                                                    dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)));
                                            
                                            ++keys_added;
                                        }
                                        else
                                        {
                                            log_warn("%{dnsname}: %{hostaddr} failed to add dnskey %{dnsname}: +%03d+%05d/%d: %r",
                                                    domain, ha,
                                                    dnskey_get_domain(key), dnskey_get_algorithm(key),
                                                    dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)), ret);
                                        }

                                        dnskey_release(key);
                                    }
                                    else
                                    {
                                        log_warn("%{dnsname}: %{hostaddr} cannot convert rdata to a dnskey: %r", domain, ha, ret);
                                    }
                                }
                                else
                                {
                                    log_warn("%{dnsname}: %{hostaddr} cannot parse rdata: %r", domain, ha, ret);
                                }
                            }
                            else
                            {
                                // not a DNSKEY: skip

                                packet_reader_skip(&purd, rdata_size);
                            }
                        }
                        else
                        {
                            log_warn("%{dnsname}: %{hostaddr} wrong domain for key: %{dnsname}", domain, ha, rdata);
                        }
                    } // for all records in answer
                    
                    ret = keys_added;
                }
                else
                {
                    log_debug("%{dnsname}: %{hostaddr} has no keys", domain, ha);
                }
            }
            else
            {
                log_err("%{dnsname}: %{hostaddr} message is broken (QR != 1)", domain, ha);
            }
        }
        else
        {
            log_err("%{dnsname}: %{hostaddr} answered with rcode %s", domain, ha, dns_message_rcode_get_name(message_get_rcode(query)));
        }
    }
    else
    {
        log_err("%{dnsname}: %{hostaddr} query error: %r", domain, ha, ret);
    }
    
    message_free(query);
    
    return ret;
}

bool
dnskey_keyring_remove(dnskey_keyring *ks, u8 algorithm, u16 tag, const u8 *domain)
{
    u32 hash = algorithm;
    hash <<= 16;
    hash |= tag;
    
    mutex_lock(&ks->mtx);
    
    u32_node *node = u32_set_find(&ks->tag_to_key, hash);
    
    if(node != NULL)
    {    
        dnssec_key *key = (dnssec_key*)node->value;
        
        if((key != NULL) && dnsname_equals(key->owner_name, domain))
        {
            dnskey_release(key);
            u32_set_delete(&ks->tag_to_key, hash);
            mutex_unlock(&ks->mtx);
            
            return TRUE;
        }
    }
    
    mutex_unlock(&ks->mtx);
    
    return FALSE;
}

dnssec_key*
dnskey_keyring_acquire(dnskey_keyring *ks, u8 algorithm, u16 tag, const u8 *domain)
{
    u32 hash = algorithm;
    hash <<= 16;
    hash |= tag;
    
    mutex_lock(&ks->mtx);
    
    u32_node *node = u32_set_find(&ks->tag_to_key, hash);
    
    if(node != NULL)
    {
        dnssec_key *key = (dnssec_key*)node->value;
        
        if((key != NULL) && dnsname_equals(key->owner_name, domain))
        {
            dnskey_acquire(key);        
            mutex_unlock(&ks->mtx);
            return key;
        }
    }

    mutex_unlock(&ks->mtx);
    
    return NULL;
}

dnssec_key*
dnskey_keyring_acquire_by_index(dnskey_keyring *ks, u8 algorithm, u16 tag, const u8 *domain)
{
    u32 hash = algorithm;
    hash <<= 16;
    hash |= tag;

    mutex_lock(&ks->mtx);

    u32_node *node = u32_set_find(&ks->tag_to_key, hash);

    if(node != NULL)
    {
        dnssec_key *key = (dnssec_key*)node->value;

        if((key != NULL) && dnsname_equals(key->owner_name, domain))
        {
            dnskey_acquire(key);
            mutex_unlock(&ks->mtx);
            return key;
        }
    }

    mutex_unlock(&ks->mtx);

    return NULL;
}

/**
 * 
 * Returns TRUE iff the keyring contains a key matching the parameters
 * 
 * @param ks
 * @param algorithm
 * @param tag
 * @param domain
 * @return 
 */

bool
dnskey_keyring_has_key(dnskey_keyring *ks, u8 algorithm, u16 tag, const u8 *domain)
{
    u32 hash = algorithm;
    hash <<= 16;
    hash |= tag;
    
    mutex_lock(&ks->mtx);
    
    u32_node *node = u32_set_find(&ks->tag_to_key, hash);
    
    if(node != NULL)
    {
        dnssec_key *key = (dnssec_key*)node->value;
        
        if((key != NULL) && dnsname_equals(key->owner_name, domain))
        {
            mutex_unlock(&ks->mtx);
            return TRUE;
        }
    }

    mutex_unlock(&ks->mtx);
    
    return FALSE;
}

static void
dnskey_keyring_destroy_callback(u32_node *node)
{
    /// @note mutex has been locked by the caller

    dnssec_key *key = (dnssec_key*)node->value;
    dnskey_release(key);
}

void
dnskey_keyring_destroy(dnskey_keyring *ks)
{
    mutex_lock(&ks->mtx);
    u32_set_callback_and_destroy(&ks->tag_to_key, dnskey_keyring_destroy_callback);
    mutex_unlock(&ks->mtx);
    
    mutex_destroy(&ks->mtx);
}

bool
dnskey_keyring_isempty(dnskey_keyring *ks)
{
    mutex_lock(&ks->mtx);
    bool ret = u32_set_isempty(&ks->tag_to_key);
    mutex_unlock(&ks->mtx);
    return ret;
}

dnssec_key *
dnskey_keyring_acquire_key_at_index(dnskey_keyring *ks, int index)
{
    u32_set_iterator iter;
    u32_set_iterator_init(&ks->tag_to_key, &iter);
    while(u32_set_iterator_hasnext(&iter))
    {
        u32_node *node = u32_set_iterator_next_node(&iter);
        if(--index < 0)
        {
            dnssec_key *key = (dnssec_key*)node->value;
            dnskey_acquire(key);
            return key;
        }
    }
    return NULL;
}

/** @} */
