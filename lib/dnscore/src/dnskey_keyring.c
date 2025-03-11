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
 * @ingroup dnsdbdnssec
 *  @addtogroup dnskey DNSKEY functions
 * @brief
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES

 #include <arpa/inet.h>
#include <ctype.h>
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include "dnscore/dnskey_keyring.h"
#include "dnscore/logger.h"
#include "dnscore/dns_message.h"
#include <dnscore/dns_packet_reader.h>

#define MODULE_MSG_HANDLE g_system_logger

ya_result dnskey_keyring_init(dnskey_keyring_t *ks)
{
    u32_treemap_init(&ks->tag_to_key);
    mutex_init(&ks->mtx);
    return SUCCESS;
}

static void dnskey_keyring_finalize_callback(u32_treemap_node_t *node)
{
    /// @note mutex has been locked by the caller
    dnskey_t *key;
    key = (dnskey_t *)node->value;
    dnskey_release(key);
    node->value = NULL;
}

void dnskey_keyring_finalize(dnskey_keyring_t *ks)
{
    mutex_lock(&ks->mtx);
    u32_treemap_callback_and_finalise(&ks->tag_to_key, dnskey_keyring_finalize_callback);
    mutex_unlock(&ks->mtx);
    mutex_destroy(&ks->mtx);
}

ya_result dnskey_keyring_add(dnskey_keyring_t *ks, dnskey_t *key)
{
    uint32_t hash = key->algorithm;
    hash <<= 16;
    hash |= key->tag;

    mutex_lock(&ks->mtx);
    u32_treemap_node_t *node = u32_treemap_insert(&ks->tag_to_key, hash);

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

ya_result dnskey_keyring_add_from_nameserver(dnskey_keyring_t *ks, const host_address_t *ha, const uint8_t *domain)
{
    dns_message_t *query = dns_message_new_instance();
    ya_result      ret;

    log_debug("%{dnsname}: fetching public keys from %{hostaddr}", domain, ha);

    dns_message_make_query(query, (uint16_t)rand(), domain, TYPE_DNSKEY, CLASS_IN);

    if(ISOK(ret = dns_message_query(query, ha)))
    {
        if(dns_message_get_rcode(query) == RCODE_OK)
        {
            log_debug("%{dnsname}: %{hostaddr} answered", domain, ha);

            if(dns_message_get_query_count(query) == 1)
            {
                uint16_t answers;

                if((answers = dns_message_get_answer_count(query)) > 0)
                {
                    // extract all keys
                    dns_packet_reader_t purd;
                    dns_packet_reader_init_from_message(&purd, query);

                    dns_packet_reader_skip_fqdn(&purd); // checked below
                    dns_packet_reader_skip(&purd, 4);   // checked below

                    if(!dns_packet_reader_eof(&purd))
                    {
                        int keys_added = 0;

                        for(uint_fast16_t i = 0; i < answers; ++i)
                        {
                            dnskey_t *key = NULL;
                            uint16_t  rtype;
                            uint16_t  rclass;
                            int32_t   rttl;
                            uint16_t  rdata_size;
                            uint8_t   rdata[1024];

                            if(FAIL(dns_packet_reader_read_fqdn(&purd, rdata, sizeof(rdata))))
                            {
                                log_info("%{dnsname}: %{hostaddr} message FORMERR)", domain, ha);
                                keys_added = MAKE_RCODE_ERROR(RCODE_FORMERR);
                                break;
                            }

                            if(dnslabel_equals_ignorecase_left(domain, rdata))
                            {
                                if(dns_packet_reader_available(&purd) <= 10)
                                {
                                    log_info("%{dnsname}: %{hostaddr} message FORMERR)", domain, ha);
                                    keys_added = MAKE_RCODE_ERROR(RCODE_FORMERR);
                                    break;
                                }

                                // unchecked because we did just that

                                dns_packet_reader_read_u16_unchecked(&purd, &rtype);      // checked
                                dns_packet_reader_read_u16_unchecked(&purd, &rclass);     // checked
                                dns_packet_reader_read_s32_unchecked(&purd, &rttl);       // checked
                                dns_packet_reader_read_u16_unchecked(&purd, &rdata_size); // checked

                                rdata_size = ntohs(rdata_size);

                                if(rtype == TYPE_DNSKEY)
                                {
                                    if(ISOK(ret = dns_packet_reader_read_rdata(&purd, rtype, rdata_size, rdata, rdata_size)))
                                    {
                                        if(ISOK(ret = dnskey_new_from_rdata(rdata, rdata_size, domain, &key)))
                                        {
                                            if(ISOK(ret = dnskey_keyring_add(ks, key)))
                                            {
                                                log_info(
                                                    "%{dnsname}: %{hostaddr} added dnskey %{dnsname}: +%03d+%05d/%d "
                                                    "added",
                                                    domain,
                                                    ha,
                                                    dnskey_get_domain(key),
                                                    dnskey_get_algorithm(key),
                                                    dnskey_get_tag_const(key),
                                                    ntohs(dnskey_get_flags(key)));

                                                ++keys_added;
                                            }
                                            else
                                            {
                                                log_warn(
                                                    "%{dnsname}: %{hostaddr} failed to add dnskey %{dnsname}: "
                                                    "+%03d+%05d/%d: %r",
                                                    domain,
                                                    ha,
                                                    dnskey_get_domain(key),
                                                    dnskey_get_algorithm(key),
                                                    dnskey_get_tag_const(key),
                                                    ntohs(dnskey_get_flags(key)),
                                                    ret);
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

                                    if(FAIL(dns_packet_reader_skip(&purd, rdata_size)))
                                    {
                                        log_info("%{dnsname}: %{hostaddr} message FORMERR)", domain, ha);
                                        keys_added = MAKE_RCODE_ERROR(RCODE_FORMERR);
                                        break;
                                    }
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
                        ret = MAKE_RCODE_ERROR(RCODE_FORMERR);
                    }
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
            log_err("%{dnsname}: %{hostaddr} answered with rcode %s", domain, ha, dns_message_rcode_get_name(dns_message_get_rcode(query)));
        }
    }
    else
    {
        log_err("%{dnsname}: %{hostaddr} query error: %r", domain, ha, ret);
    }

    dns_message_delete(query);

    return ret;
}

bool dnskey_keyring_remove(dnskey_keyring_t *ks, uint8_t algorithm, uint16_t tag, const uint8_t *domain)
{
    uint32_t hash = algorithm;
    hash <<= 16;
    hash |= tag;

    mutex_lock(&ks->mtx);

    u32_treemap_node_t *node = u32_treemap_find(&ks->tag_to_key, hash);

    if(node != NULL)
    {
        dnskey_t *key = (dnskey_t *)node->value;

        if((key != NULL) && dnsname_equals(key->owner_name, domain))
        {
            dnskey_release(key);
            u32_treemap_delete(&ks->tag_to_key, hash);
            mutex_unlock(&ks->mtx);

            return true;
        }
    }

    mutex_unlock(&ks->mtx);

    return false;
}

dnskey_t *dnskey_keyring_acquire(dnskey_keyring_t *ks, uint8_t algorithm, uint16_t tag, const uint8_t *domain)
{
    uint32_t hash = algorithm;
    hash <<= 16;
    hash |= tag;

    mutex_lock(&ks->mtx);

    u32_treemap_node_t *node = u32_treemap_find(&ks->tag_to_key, hash);

    if(node != NULL)
    {
        dnskey_t *key = (dnskey_t *)node->value;

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
 * Returns true iff the keyring contains a key matching the parameters
 *
 * @param ks
 * @param algorithm
 * @param tag
 * @param domain
 * @return
 */

bool dnskey_keyring_has_key(dnskey_keyring_t *ks, uint8_t algorithm, uint16_t tag, const uint8_t *domain)
{
    uint32_t hash = algorithm;
    hash <<= 16;
    hash |= tag;

    mutex_lock(&ks->mtx);

    u32_treemap_node_t *node = u32_treemap_find(&ks->tag_to_key, hash);

    if(node != NULL)
    {
        dnskey_t *key = (dnskey_t *)node->value;

        if((key != NULL) && dnsname_equals(key->owner_name, domain))
        {
            mutex_unlock(&ks->mtx);
            return true;
        }
    }

    mutex_unlock(&ks->mtx);

    return false;
}

bool dnskey_keyring_isempty(dnskey_keyring_t *ks)
{
    mutex_lock(&ks->mtx);
    bool ret = u32_treemap_isempty(&ks->tag_to_key);
    mutex_unlock(&ks->mtx);
    return ret;
}

static void dnskey_keyring_destroy_callback(u32_treemap_node_t *node)
{
    /// @note mutex has been locked by the caller

    dnskey_t *key = (dnskey_t *)node->value;
    dnskey_release(key);
}

void dnskey_keyring_destroy(dnskey_keyring_t *ks)
{
    mutex_lock(&ks->mtx);
    u32_treemap_callback_and_finalise(&ks->tag_to_key, dnskey_keyring_destroy_callback);
    mutex_unlock(&ks->mtx);

    mutex_destroy(&ks->mtx);
}

dnskey_t *dnskey_keyring_acquire_key_at_index(dnskey_keyring_t *ks, int index)
{
    u32_treemap_iterator_t iter;
    u32_treemap_iterator_init(&ks->tag_to_key, &iter);
    while(u32_treemap_iterator_hasnext(&iter))
    {
        u32_treemap_node_t *node = u32_treemap_iterator_next_node(&iter);
        if(--index < 0)
        {
            dnskey_t *key = (dnskey_t *)node->value;
            dnskey_acquire(key);
            return key;
        }
    }
    return NULL;
}

/** @} */
