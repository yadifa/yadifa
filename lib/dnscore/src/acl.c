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
 * @defgroup acl Access Control List
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <netinet/in.h>

#include <dnscore/logger.h>
logger_handle_t *g_acl_logger = LOGGER_HANDLE_SINK;
#define MODULE_MSG_HANDLE g_acl_logger
#include <dnscore/mutex.h>
#include <dnscore/parsing.h>
#include <dnscore/base64.h>
#include <dnscore/dns_message.h>
#include <dnscore/format.h>
#include <dnscore/zalloc.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/ptr_treemap.h>

#if !DNSCORE_HAS_ACL_SUPPORT
#error "ACL support should not be compiled in"
#endif

#include <dnscore/acl.h>
#include <dnscore/acl_config.h>
#include <dnscore/counter_output_stream.h>

#define ADRMITEM_TAG    0x4d4554494d524441
#define ACLENTRY_TAG    0x5952544e454c4341
#define ACLBASE_TAG     0x455341424c4341

#define ACL_DEBUG_FULL  0
#define ACL_DEBUG_FLUSH 0 // enabling this will greatly slow down the zone configuration

#define ACL_DEBUG_ARC   0

#if !DEBUG
#undef ACL_DEBUG_FULL
#define ACL_DEBUG_FULL 0
#endif

/*
 * 2011/10/18 : EDF: disabling the debug because it makes the legitimate error output unreadable.
 */

#if !ACL_DEBUG_FLUSH
#define logger_flush(...)
#endif

#define AMITSIGK_TAG     0x4b47495354494d41
#define AMITSIGN_TAG     0x4e47495354494d41

#define STR(x)           ((x) != NULL) ? (x) : "NULL"

#define IS_IPV4_ITEM(x_) (((x_)->match == amim_ipv4) || ((x_)->match == amim_ipv4_not))
#define IS_IPV6_ITEM(x_) (((x_)->match == amim_ipv6) || ((x_)->match == amim_ipv6_not))
#if DNSCORE_HAS_TSIG_SUPPORT
#define IS_TSIG_ITEM(x_) (((x_)->match == amim_tsig) || ((x_)->match == amim_tsig_not))
#endif
#define IS_ANY_ITEM(x_)                                (((x_)->match == amim_any) || ((x_)->match == amim_none))
#define IS_NONE_ITEM(x_)                               (((x_)->match == amim_any) || ((x_)->match == amim_none))

#define IS_IPV4_ITEM_MATCH(x_)                         ((x_)->match == amim_ipv4)
#define IS_IPV6_ITEM_MATCH(x_)                         ((x_)->match == amim_ipv6)
#define IS_TSIG_ITEM_MATCH(x_)                         ((x_)->match == amim_tsig)
#define IS_ANY_ITEM_MATCH(x_)                          ((x_)->match == amim_any)
#define IS_NONE_ITEM_MATCH(x_)                         ((x_)->match == amim_none)

#define IS_IPV4_ITEM_MATCH_NOT(x_)                     ((x_)->match == amim_ipv4_not)
#define IS_IPV6_ITEM_MATCH_NOT(x_)                     ((x_)->match == amim_ipv6_not)
#define IS_TSIG_ITEM_MATCH_NOT(x_)                     ((x_)->match == amim_tsig_not)
#define IS_ANY_ITEM_MATCH_NOT(x_)                      ((x_)->match == amim_none)
#define IS_NONE_ITEM_MATCH_NOT(x_)                     ((x_)->match == amim_any)

#define ACL_ADDRESS_MATCH_SET_TO_STREAM_PRINT_ANY_NONE 0

/*
 * Contains all the definitions from the <acl> section
 */

// <editor-fold defaultstate="collapsed" desc="DEBUG-ONLY FUNCTIONS">

#if DEBUG

#if ACL_DEBUG_FULL
static const char *query_access_filter_type_name[18] = {"RRI", "ARI", "4RI", "RAI", "AAI", "4AI", "R6I", "A6I", "46I", "RRT", "ART", "4RT", "RAT", "AAT", "4AT", "R6T", "A6T", "46T"};
#endif

static void amim_ipv4_print(ptr_vector_t *ipv4v)
{
#if ACL_DEBUG_FULL
    address_match_item **itemp = (address_match_item **)ipv4v->data;
    int32_t              idx = 0;

#if DEBUG
    log_debug7("\tipv4@%p", (void *)itemp);
    logger_flush();
#endif

    while(idx <= ipv4v->offset)
    {
        uint8_t *ip = itemp[idx]->parameters.ipv4.address.bytes;
        uint8_t *mask = itemp[idx]->parameters.ipv4.mask.bytes;

#if DEBUG
        log_debug7("\t\t[%hhu.%hhu.%hhu.%hhu/%hhu.%hhu.%hhu.%hhu (%hu) %c]", ip[0], ip[1], ip[2], ip[3], mask[0], mask[1], mask[2], mask[3], itemp[idx]->parameters.ipv4.maskbits, (itemp[idx]->parameters.ipv4.rejects == 0) ? 'a' : 'r');
        logger_flush();
#endif

        idx++;
    }
#else
    (void)ipv4v;
#endif
}

static void amim_ipv6_print(ptr_vector_t *ipv6v)
{
#if ACL_DEBUG_FULL
    address_match_item **itemp = (address_match_item **)ipv6v->data;
    int32_t              idx = 0;

#if DEBUG
    log_debug7("\tipv6@%p", (void *)itemp);
    logger_flush();
#endif

    while(idx <= ipv6v->offset)
    {
        uint8_t *ip = itemp[idx]->parameters.ipv6.address.bytes;
        uint8_t *mask = itemp[idx]->parameters.ipv6.mask.bytes;

#if DEBUG
        log_debug7(
            "\t\t[%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx/"
            "%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx (%hi) %c]",
            ip[0],
            ip[1],
            ip[2],
            ip[3],
            ip[4],
            ip[5],
            ip[6],
            ip[7],
            ip[8],
            ip[9],
            ip[10],
            ip[11],
            ip[12],
            ip[13],
            ip[14],
            ip[15],
            mask[0],
            mask[1],
            mask[2],
            mask[3],
            mask[4],
            mask[5],
            mask[6],
            mask[7],
            mask[8],
            mask[9],
            mask[10],
            mask[11],
            mask[12],
            mask[13],
            mask[14],
            mask[15],
            itemp[idx]->parameters.ipv6.maskbits,
            (itemp[idx]->parameters.ipv6.rejects == 0) ? 'a' : 'r');
        logger_flush();
#endif

        idx++;
    }
#else
    (void)ipv6v;
#endif
}

#if DNSCORE_HAS_TSIG_SUPPORT
static void amim_tsig_print(ptr_vector_t *tsigv)
{
#if ACL_DEBUG_FULL
    address_match_item **itemp = (address_match_item **)tsigv->data;
    int32_t              idx = 0;

#if DEBUG
    log_debug7("\ttsig@%p", (void *)itemp);
    logger_flush();
#endif

    while(idx <= tsigv->offset)
    {
        uint8_t *name = itemp[idx]->parameters.tsig.name;

#if DEBUG
        log_debug7("\t\t%{dnsname}", name);
        logger_flush();
#endif

        idx++;
    }
#else
    (void)tsigv;
#endif
}
#endif // TSIG SUPPORT

#endif

// </editor-fold>

int        acl_address_match_item_compare(const address_match_item_t *a, const address_match_item_t *b);

static int acl_address_match_item_compare_node(const void *key_a, const void *key_b)
{
    int ret = acl_address_match_item_compare((const address_match_item_t *)key_a, (const address_match_item_t *)key_b);
    return ret;
}

static int acl_entry_compare_node(const void *key_a, const void *key_b)
{
    const char *a = (const char *)key_a;
    const char *b = (const char *)key_b;

    int         ret = strcasecmp(a, b);

    return ret;
}

static ptr_treemap_t g_amim_set = PTR_TREEMAP_EMPTY_WITH_COMPARATOR(acl_address_match_item_compare_node);
static ptr_treemap_t g_acl_set = PTR_TREEMAP_EMPTY_WITH_COMPARATOR(acl_entry_compare_node);
static mutex_t       ami_mtx = MUTEX_INITIALIZER;
static uint32_t      g_acl_entry_count = 0;

typedef int          amim_function(address_match_item_t *, void *);

// <editor-fold defaultstate="collapsed" desc="AMIM functions">

static int amim_none(const address_match_item_t *item, const void *data)
{
    (void)item;
    (void)data;
    return AMIM_REJECT;
}

static int amim_any(const address_match_item_t *item, const void *data)
{
    (void)item;
    (void)data;
    return AMIM_ACCEPT;
}

static int amim_ipv4(const address_match_item_t *item, const void *data)
{
    const ipv4_id_t *items = &item->parameters.ipv4;
    const uint32_t  *ip = (const uint32_t *)data;
    return ((items->address.value & items->mask.value) == (*ip & items->mask.value)) ? AMIM_ACCEPT : AMIM_SKIP;
}

static int amim_ipv4_not(const address_match_item_t *item, const void *data) { return -amim_ipv4(item, data); }

static int amim_ipv6(const address_match_item_t *item, const void *data)
{
    const uint64_t  *ipv6_bytes = (const uint64_t *)data;
    const ipv6_id_t *items = &item->parameters.ipv6;
    return (((items->address.lohi[0] & items->mask.lohi[0]) == (ipv6_bytes[0] & items->mask.lohi[0])) && ((items->address.lohi[1] & items->mask.lohi[1]) == (ipv6_bytes[1] & items->mask.lohi[1]))) ? AMIM_ACCEPT : AMIM_SKIP;
}

static int amim_ipv6_not(const address_match_item_t *item, const void *data) { return -amim_ipv6(item, data); }

#if DNSCORE_HAS_TSIG_SUPPORT
static int amim_tsig(const address_match_item_t *item, const void *data)
{
    const dns_message_t *mesg = (const dns_message_t *)data;

    /*
     * The TSIG has already been verified as being valid.  So all we need to know if : is it allowed ?
     */

    // mesg->tsig->tsig->name;
    // log_debug("tsig : %p", message_tsig_get_key(mesg)->name);

    const tsig_key_t *tsig = dns_message_tsig_get_key(mesg);
    if(tsig != NULL)
    {
        if(item->parameters.tsig.mac_algorithm == tsig->mac_algorithm)
        {
            if(item->parameters.tsig.name_size == tsig->name_len)
            {
                if(dnsname_equals(item->parameters.tsig.name, tsig->name))
                {
                    return AMIM_ACCEPT;
                }
            }
        }
    }

    return AMIM_SKIP; /* no match */
}

static int amim_tsig_not(const address_match_item_t *item, const void *data) { return -amim_tsig(item, data); }
#endif

static int amim_reference(const address_match_item_t *item, const void *data)
{
    (void)item;
    (void)data;
    return AMIM_REJECT;
}
// </editor-fold>

static bool acl_count_bits(const uint8_t *bytes, int len, uint32_t *bit_countp)
{
    uint32_t       bit_count = 0;
    const uint8_t *limit = &bytes[len];
    for(; bytes < limit; ++bytes)
    {
        uint8_t b = *bytes;
        if(b == 255)
        {
            bit_count += 8;
        }
        else
        {
            while(b != 0)
            {
                if((b & 0x80) != 0)
                {
                    return false;
                }

                ++bit_count;
                b <<= 1;
            }

            for(++bytes; bytes < limit; ++bytes)
            {
                if(*bytes != 0)
                {
                    return false;
                }
            }

            break;
        }
    }

    *bit_countp = bit_count;

    return true;
}

void acl_match_item_print(const address_match_item_t *item, output_stream_t *os)
{
    if(item == NULL)
    {
        output_stream_write(os, "NULL", 4);
    }
    else if(item->match == amim_none)
    {
        output_stream_write(os, "none", 4);
    }
    else if(item->match == amim_any)
    {
        output_stream_write(os, "any", 3);
    }
    else if(IS_IPV4_ITEM(item))
    {
        uint32_t mask = item->parameters.ipv4.mask.value;
        uint32_t mask_bits = 0;
        bool     broken_mask = false;

        while(mask != 0)
        {
            if((mask & 1) == 0)
            {
                // broken mask
                broken_mask = true;
                break;
            }
            ++mask_bits;
            mask >>= 1;
        }

        if(IS_IPV4_ITEM_MATCH_NOT(item))
        {
            osprint_char(os, '!');
        }

        osformat(os, "%u.%u.%u.%u", (uint32_t)item->parameters.ipv4.address.bytes[0], (uint32_t)item->parameters.ipv4.address.bytes[1], (uint32_t)item->parameters.ipv4.address.bytes[2], (uint32_t)item->parameters.ipv4.address.bytes[3]);
        if(!broken_mask)
        {
            if(mask_bits < 32)
            {
                osformat(os, "/%u", mask_bits);
            }
        }
        else
        {
            osformat(os, "/%u.%u.%u.%u", (uint32_t)item->parameters.ipv4.mask.bytes[0], (uint32_t)item->parameters.ipv4.mask.bytes[1], (uint32_t)item->parameters.ipv4.mask.bytes[2], (uint32_t)item->parameters.ipv4.mask.bytes[3]);
        }
    }
    else if(IS_IPV6_ITEM(item))
    {
        uint32_t            mask_bits = 0;
        bool                broken_mask = !acl_count_bits(item->parameters.ipv6.mask.bytes, 16, &mask_bits);

        struct sockaddr_in6 sa6;
        sa6.sin6_family = AF_INET6;
        memcpy(&sa6.sin6_addr, item->parameters.ipv6.address.bytes, 16);
        osformat(os, "%s%{sockaddrip}", IS_IPV6_ITEM_MATCH_NOT(item) ? "!" : "", &sa6);

        if(!broken_mask)
        {
            if(mask_bits < 128)
            {
                osformat(os, "/%u", mask_bits);
            }
        }
        else
        {
            memcpy(&sa6.sin6_addr, item->parameters.ipv6.mask.bytes, 16);
            osformat(os, "/%{sockaddrip}", &sa6);
        }
    }
    else if((item->match == amim_tsig) || (item->match == amim_tsig_not))
    {
        osformat(os, "%skey %{dnsname}", (item->match == amim_tsig_not) ? "!" : "", item->parameters.tsig.name);
    }
    else
    {
        output_stream_write_u8(os, '?');
    }
}

ya_result acl_match_items_print(address_match_item_t *const *address, address_match_item_t *const *limit, output_stream_t *os)
{
    counter_output_stream_context_t cosd;
    output_stream_t                 cos;
    counter_output_stream_init(&cos, os, &cosd);

    for(address_match_item_t *const *itemp = address; itemp < limit; ++itemp)
    {
        const address_match_item_t *item = *itemp;
        if(itemp != address)
        {
            output_stream_write(&cos, ", ", 2);
        }
        acl_match_item_print(item, &cos);
    }

    return (ya_result)cosd.written_count;
}

// <editor-fold defaultstate="collapsed" desc="RULES SORTING">

#if ACL_SORT_RULES

static int amim_ipv4_sort_callback(const void *a, const void *b)
{
    address_match_item *ia = (address_match_item *)a;
    address_match_item *ib = (address_match_item *)b;

    if(ia->parameters.ipv4.maskbits != ib->parameters.ipv4.maskbits)
    {
        /* Bigger value => more specific tag => before in the sort order */

        return (ib->parameters.ipv4.maskbits - ia->parameters.ipv4.maskbits);
    }

    /*
     * rejects a = 1 & b = 0 => a rejects and b don't => a comes first
     */

    return (ib->parameters.ipv4.rejects - ia->parameters.ipv4.rejects);
}

static void amim_ipv4_sort(ptr_vector_t *ipv4v) { ptr_vector_qsort(ipv4v, amim_ipv4_sort_callback); }

static int  amim_ipv6_sort_callback(const void *a, const void *b)
{
    address_match_item *ia = (address_match_item *)a;
    address_match_item *ib = (address_match_item *)b;

    if(ia->parameters.ipv6.maskbits != ib->parameters.ipv6.maskbits)
    {
        /* Bigger value => more specific tag => before in the sort order */

        return (ib->parameters.ipv6.maskbits - ia->parameters.ipv6.maskbits);
    }

    /*
     * rejects a = 1 & b = 0 => a rejects and b don't => a comes first
     */

    return (ib->parameters.ipv6.rejects - ia->parameters.ipv6.rejects);
}

static void amim_ipv6_sort(ptr_vector_t *ipv6v) { ptr_vector_qsort(ipv6v, amim_ipv6_sort_callback); }

#endif

// </editor-fold>

#define AML_REJECT 0 /* DO NOT CHANGE THESES VALUES */
#define AML_ACCEPT 1 /* DO NOT CHANGE THESES VALUES */
#define AML_FILTER 2 /* DO NOT CHANGE THESES VALUES */

/**
 * Tool that gives the length of the first sequence of bits that are set to 1, from the first byte.
 * Stops at the end or the first bit set to 0.
 */

static inline uint32_t acl_netmask_bit_count(const uint8_t *bytes, uint32_t len)
{
    const uint8_t *const limit = &bytes[len];
    uint32_t             bits = 0;

    while(bytes < limit)
    {
        if(*bytes != 0xff)
        {
            break;
        }

        bits += 8;
        bytes++;
    }

    if(bytes < limit)
    {
        uint8_t c = *bytes;

        while((c & 0x80U) != 0)
        {
            c <<= 1;
            bits++;
        }
    }

    return bits;
}

static bool acl_entry_exists(const char *name)
{
    ptr_treemap_node_t *node = ptr_treemap_find(&g_acl_set, name);
    return node != NULL;
}

static acl_entry_t *acl_entry_get(const char *name)
{
    ptr_treemap_node_t *node = ptr_treemap_find(&g_acl_set, name);
    if(node != NULL)
    {
        return (acl_entry_t *)node->value;
    }
    else
    {
        return NULL;
    }
}

/**
 * Returns the number of registered acl entries.
 *
 * @return the count
 */

uint32_t acl_entry_count() { return g_acl_entry_count; }

/**
 * Initialises an iterator on the acl entries.
 * Values are of type acl_entry_t*
 */

void                acl_entry_iterator_init(ptr_treemap_iterator_t *iter) { ptr_treemap_iterator_init(&g_acl_set, iter); }

static acl_entry_t *acl_entry_new_instance(const char *name)
{
    ptr_treemap_node_t *node = ptr_treemap_insert(&g_acl_set, (char *)name);
    if(node->value == NULL)
    {
        ++g_acl_entry_count;
        acl_entry_t *acl;
        MALLOC_OBJECT_OR_DIE(acl, acl_entry_t, ACLENTRY_TAG);
        ZEROMEMORY(acl, sizeof(acl_entry_t));
        acl->name = strdup(name);
        node->key = (char *)acl->name;
        node->value = acl;
        return acl;
    }

    abort();
}

static void acl_entry_delete(acl_entry_t *acl)
{
    if(ptr_treemap_find(&g_acl_set, acl->name) != NULL)
    {
        --g_acl_entry_count;
    }

    ptr_treemap_delete(&g_acl_set, acl->name);
    free((char *)acl->name);
    free(acl);
}

static inline uint32_t acl_address_match_list_size(const address_match_list_t *aml) { return (aml != NULL) ? (aml->limit - aml->items) : 0; }

static uint32_t        acl_address_match_list_get_type(const address_match_list_t *aml)
{
    if(aml == NULL)
    {
        return AML_REJECT;
    }

    uint32_t n = acl_address_match_list_size(aml);

    switch(n)
    {
        case 0:
        {
            return AML_REJECT;
        }
        case 1:
        {
            if(aml->items[0]->match == amim_none)
            {
                return AML_REJECT;
            }
            else if(aml->items[0]->match == amim_any)
            {
                return AML_ACCEPT;
            }
        }
            FALLTHROUGH // fall through
                default:
            {
                return AML_FILTER;
            }
    }
}

static uint32_t acl_address_match_set_get_type(const address_match_set_t *ams)
{
    /*
     * TSIG cannot be globally accepted nor rejected.
     * It can only be ignored or filtered.
     * So [0;1] => 0 and 2 => 1.
     */

    uint32_t tsig = (acl_address_match_list_get_type(&ams->tsig) >> 1) * 9;

    if(tsig == 0)
    {
        /* no tsig, no modifier here */
        return acl_address_match_list_get_type(&ams->ipv4) + acl_address_match_list_get_type(&ams->ipv6) * 3;
    }
    else
    {
        /*
         * If a tsig is defined and BOTH IPs rules have a size of zero, then both are accepted.
         */

        if(acl_address_match_list_size(&ams->ipv4) + acl_address_match_list_size(&ams->ipv6) == 0)
        {
            return AML_ACCEPT + AML_ACCEPT * 3 + tsig;
        }
        else
        {
            return acl_address_match_list_get_type(&ams->ipv4) + acl_address_match_list_get_type(&ams->ipv6) * 3 + tsig;
        }
    }
}

static address_match_item_t *acl_address_match_item_alloc()
{
    address_match_item_t *ami;

    MALLOC_OBJECT_OR_DIE(ami, address_match_item_t, ADRMITEM_TAG);
    ami->match = NULL;
    ZEROMEMORY(&ami->parameters, sizeof(ami->parameters));
    ami->_rc = 1;

#if ACL_DEBUG_ARC
    log_info("acl: address_match_item@%p allocated", ami);
#endif

    return ami;
}

#if ACL_EXTENDED_FEATURES

static void acl_address_match_item_free(address_match_item *ami)
{
    if(ami != NULL)
    {
        if(ami->match == amim_reference)
        {
            free((void *)ami->parameters.ref.name);
        }
#if DNSCORE_HAS_TSIG_SUPPORT
        else if((ami->match == amim_tsig) || (ami->match == amim_tsig_not))
        {
            free(ami->parameters.tsig.name);
            free(ami->parameters.tsig.known);
        }
#endif

#if DEBUG
        memset(ami, 0xfe, sizeof(address_match_item));
#endif

        free(ami);
    }
}

#endif

static inline void acl_address_match_item_acquire(address_match_item_t *ami)
{
    mutex_lock(&ami_mtx);

#if ACL_DEBUG_ARC
    int32_t rc =
#endif

        ++ami->_rc;
    mutex_unlock(&ami_mtx);

#if ACL_DEBUG_ARC
    log_info("acl: address_match_item@%p acquire: %i", ami, rc);
#endif
}

static inline bool acl_address_match_item_release(address_match_item_t *ami)
{
    assert(ami != NULL);

    mutex_lock(&ami_mtx);

    assert(ami->_rc > 0);

#if !ACL_DEBUG_ARC
    if(--ami->_rc > 0)
#else
    int32_t rc = --ami->_rc;
    if(rc > 0)
#endif
    {
        mutex_unlock(&ami_mtx);

#if ACL_DEBUG_ARC
        log_info("acl: address_match_item@%p release: %i", ami, rc);
#endif
        return false;
    }
    mutex_unlock(&ami_mtx);

#if ACL_DEBUG_ARC
    log_info("acl: address_match_item@%p release: %i", ami, rc);
#endif

#if DEBUG
    uint32_t txt_size;
    char     txt[512];
    txt_size = sizeof(txt);
    acl_address_match_item_to_string(ami, txt, &txt_size);

    if(txt_size <= sizeof(txt))
    {
        log_debug7("acl: destroying '%s' (rc=%i)", txt, ami->_rc);
    }
    else
    {
        log_debug7("acl: destroying @%p (rc=%i)", ami, ami->_rc);
    }
#endif

    // acl_address_match_item_free(ami);

    return true;
}
/*
static int
acl_address_match_item_rc(const address_match_item_t *ami)
{
    mutex_lock(&ami_mtx);
    int ret = ami->_rc;
    mutex_unlock(&ami_mtx);
    return ret;
}
*/
static void acl_address_match_item_vector_finalise(ptr_vector_t *amlv)
{
    for(int_fast32_t i = 0; i <= ptr_vector_last_index(amlv); ++i)
    {
        address_match_item_t *ami = (address_match_item_t *)ptr_vector_get(amlv, i);
        acl_address_match_item_release(ami);
    }
    ptr_vector_finalise(amlv);
}

/**
 * Appends all the address_match_item of the definition (identified by its name)
 * to the array.
 *
 * Returns the number of conversions (0 or 1)
 *
 * @param amlv
 * @param definition_name
 * @return
 */

static ya_result acl_expand_address_match_reference(ptr_vector_t *amlv, const char *definition_name)
{
    ya_result return_value = 0;

#if DEBUG
    log_debug7("acl_expand_address_match_reference(%p, %s)", (void *)amlv, definition_name);
    logger_flush();
#endif

    acl_entry_t *acl = acl_entry_get(definition_name);

    if(acl != NULL)
    {
        address_match_item_t **amip = acl->list.items;

        while(amip < acl->list.limit)
        {
            address_match_item_t *ami = *amip;

            if(ami->match == amim_reference)
            {
                /* recurse */

                if(!ami->parameters.ref.mark)
                {
                    ami->parameters.ref.mark = true;

                    ya_result expand = acl_expand_address_match_reference(amlv, ami->parameters.ref.name);

                    if(expand > 0)
                    {
                        return_value += expand;
                    }
                    else
                    {
                        if(expand == 0)
                        {
                            log_err("acl: expanding '%s': '%s' is undefined", definition_name, ami->parameters.ref.name);
                        }
                        else
                        {
                            log_err("acl: expanding '%s': '%s' cannot be expanded", definition_name, ami->parameters.ref.name);
                        }
                        return_value = S32_MIN; // forces an error
                    }

                    ami->parameters.ref.mark = false;
                }
            }
            else
            {
                acl_address_match_item_acquire(ami);
                ptr_vector_append(amlv, ami);

                return_value++;
            }

            amip++;
        }
    }

    return return_value;
}

/**
 * Puts the ami in a set, or returns the previous identical version of the ami,
 * increases its reference count and dereferences (which should destroy) the
 * ami passed as a parameter.
 *
 * @param ami to store (or get)
 * @return the ami to use
 */

static inline address_match_item_t *acl_address_match_item_collection_get(address_match_item_t *ami)
{
    ptr_treemap_node_t *node = ptr_treemap_insert(&g_amim_set, ami);
    if(node->value == NULL)
    {
        node->value = ami;
        return ami;
    }
    else
    {
        acl_address_match_item_release(ami);
        ami = (address_match_item_t *)node->value;
        acl_address_match_item_acquire(ami);
        return ami;
    }
}

access_control_t *acl_access_control_new_instance()
{
    access_control_t *ret;
    ZALLOC_OBJECT_OR_DIE(ret, access_control_t, ACLBASE_TAG);
    ZEROMEMORY(ret, sizeof(access_control_t));
    ret->_rc = 1;

#if ACL_DEBUG_ARC
    log_debug("acl_access_control_new_instance() %p", ret);
#endif

    return ret;
}

/**
 * Used to build the acl content
 *
 * [!] (ip [/prefix] | key key_id | "acl_name" | { address_match_list } )
 *
 * If use_definitions is true, the definitions will be expanded
 *
 */

static ya_result acl_address_match_list_init_from_text(address_match_list_t *aml, const char *description, bool use_definitions)
{
#if DEBUG
    log_debug7("acl_address_match_list_init_from_text(%p, \"%s\", %i)", (void *)aml, STR(description), use_definitions);
    logger_flush();
#endif

    if(description == NULL)
    {
        return 0; /* successfully parsed 0 descriptors */
    }

    yassert(aml != NULL && aml->items == NULL && aml->limit == NULL);

    const char  *separator = description;
    ptr_vector_t list;
    uint32_t     token_len;

    bool         accept;
    char         token[256];

    ptr_vector_init(&list);

    /*
     * get each ""; token
     * parse the token
     */

    while(*separator != '\0')
    {
        /* Find the first non-separator, non-space, non-zero char */

        while(isspace(*separator))
        {
            separator++;
        }

        /* EOL ? */

        if(*separator == '\0')
        {
            break;
        }

        description = separator;

        while((*separator != ',') && (*separator != ';') && (*separator != '\0'))
        {
            separator++;
        }

        if(description[0] == '\0')
        {
            continue;
        }

        token_len = separator - description;

        while(((*separator == ';') || (*separator == ',')) && (*separator != '\0'))
        {
            separator++;
        }

        if(token_len > sizeof(token) - 1)
        {
            acl_address_match_item_vector_finalise(&list);
            return ACL_TOKEN_SIZE_ERROR; /* token is too big */
        }

        while((token_len > 0) && isspace(description[token_len - 1]))
        {
            token_len--;
        }

        if(token_len == 0)
        {
            continue;
        }

        memcpy(token, description, token_len);
        token[token_len] = '\0';

        description = separator;

        /* We have a token, we can now divide it*/

        char *word = token;

        /* Check for a starting '!' */

        accept = true;

        if(*word == '!')
        {
            accept = false;
            word++;
            word = (char *)parse_skip_spaces(word);
        }

        char *next_word = (char *)parse_next_space(word);

        if(*next_word != '\0')
        {
            *next_word++ = '\0';
            next_word = (char *)parse_skip_spaces(next_word);
        }

        address_match_item_t *ami = NULL;

        if(strcasecmp(word, "key") == 0)
        {
#if DNSCORE_HAS_TSIG_SUPPORT
            /* TSIG : key xxxxx; */

            ami = acl_address_match_item_alloc();
            ami->match = (accept) ? amim_tsig : amim_tsig_not;

            word = next_word;
            next_word = (char *)parse_next_space(next_word);

            if((next_word - word) > (ssize_t)sizeof(token))
            {
                acl_address_match_item_release(ami);
                acl_address_match_item_vector_finalise(&list);
                return ACL_TOKEN_SIZE_ERROR;
            }

            /*
             * Check if the key is known
             */

            uint8_t   dnsname[DOMAIN_LENGTH_MAX];

            ya_result dnsname_len = dnsname_init_check_star_with_cstr(dnsname, word);

            if(FAIL(dnsname_len))
            {
                acl_address_match_item_release(ami);
                acl_address_match_item_vector_finalise(&list);
                return ACL_NAME_PARSE_ERROR;
            }

            tsig_key_t *key = tsig_get(dnsname);

            if(key == NULL)
            {
                log_err("acl: unknown key %{dnsname}", dnsname);

                acl_address_match_item_release(ami);
                acl_address_match_item_vector_finalise(&list);
                return ACL_UNKNOWN_TSIG_KEY;
            }

            ami->parameters.tsig.secret_size = key->mac_size;
            ami->parameters.tsig.name_size = dnsname_len;
            ami->parameters.tsig.mac_algorithm = key->mac_algorithm;

            MALLOC_OR_DIE(uint8_t *, ami->parameters.tsig.known, key->mac_size, AMITSIGK_TAG);
            memcpy(ami->parameters.tsig.known, key->mac, key->mac_size);

            MALLOC_OR_DIE(uint8_t *, ami->parameters.tsig.name, (size_t)dnsname_len, AMITSIGN_TAG);
            memcpy(ami->parameters.tsig.name, dnsname, (size_t)dnsname_len);

            ami = acl_address_match_item_collection_get(ami);
#else
            log_err("acl: unknown key %{dnsname} (not supported)", dnsname);

            return ACL_UNKNOWN_TSIG_KEY; // not supported
#endif
        }
        else if(strcasecmp(word, "none") == 0)
        {
            /* Reject all */

            ami = acl_address_match_item_alloc();
            ami->match = (accept) ? amim_none : amim_any;
            ami = acl_address_match_item_collection_get(ami);
        }
        else if(strcasecmp(word, "any") == 0)
        {
            /* Accept all */

            ami = acl_address_match_item_alloc();
            ami->match = (accept) ? amim_any : amim_none;
            ami = acl_address_match_item_collection_get(ami);
        }
        else /* parse an ipv4 or ipv6, with or without an ipv4, ipv6 or sized bitmask */
        {
            uint8_t  buffer[16];
            bool     mask = false;
            uint32_t bits = 0;

            if(*next_word != '\0')
            {
                log_err("acl: unexpected %s after IP", next_word);
                acl_address_match_item_vector_finalise(&list);
                return ACL_TOO_MANY_TOKENS;
            }

            int   proto = -1;

            char *slash = word;
            while(*slash != '\0')
            {
                if(*slash == '/')
                {
                    *slash++ = '\0';
                    slash = (char *)parse_skip_spaces(slash);
                    mask = true;
                    break;
                }

                slash++;
            }

            if(inet_pton(AF_INET, word, buffer) == 1)
            {
                /* ipv4 */

                proto = AF_INET;

                ami = acl_address_match_item_alloc();
                ami->match = (accept) ? amim_ipv4 : amim_ipv4_not;
                ami->parameters.ipv4.rejects = (accept) ? 0 : 1;

                memcpy(&ami->parameters.ipv4.address.bytes, buffer, 4);

                if(!mask)
                {
                    memset(&ami->parameters.ipv4.mask.bytes, 0xff, 4);
                    ami->parameters.ipv4.maskbits = 32;
                }

                ami = acl_address_match_item_collection_get(ami);
            }
            else if(inet_pton(AF_INET6, word, buffer) == 1)
            {
                /* ipv6 */

                proto = AF_INET6;

                ami = acl_address_match_item_alloc();
                ami->match = (accept) ? amim_ipv6 : amim_ipv6_not;
                ami->parameters.ipv6.rejects = (accept) ? 0 : 1;

                memcpy(&ami->parameters.ipv6.address.bytes, buffer, 16);
                if(!mask)
                {
                    memset(&ami->parameters.ipv6.mask.bytes, 0xff, 16);
                    ami->parameters.ipv6.maskbits = 128;
                }

                ami = acl_address_match_item_collection_get(ami);
            }
            else
            {
                /* It could be a reference:  */

                if(!accept || mask) /* Cannot do a 'not' reference.
                                     * Cannot get a '/' in a reference.
                                     */
                {
                    acl_address_match_item_vector_finalise(&list);
                    return ACL_UNEXPECTED_NEGATION;
                }

                /*
                 * If the acls have already been (fully) defined:
                 * Look for 'word' in the acls and expand it.
                 * Add every ACL entry
                 */

                if(use_definitions)
                {
                    ya_result expand;

                    if((expand = acl_expand_address_match_reference(&list, word)) <= 0)
                    {
                        acl_address_match_item_vector_finalise(&list);

                        if(expand == 0)
                        {
                            log_err("acl: '%s' is undefined", word);
                        }
                        else
                        {
                            log_err("acl: '%s' cannot be expanded", word);
                        }

                        return ACL_UNDEFINED_TOKEN;
                    }
                }
                else /* just store the name */
                {
                    ami = acl_address_match_item_alloc();
                    ami->match = amim_reference;
                    ami->parameters.ref.name = strdup(word);
                    ami->parameters.ref.mark = false;
                    ami = acl_address_match_item_collection_get(ami);

#if DEBUG
                    log_debug7("acl_address_match_list_init_from_text(%p, %s, %u) : adding %p (%s)", (void *)aml, STR(description), use_definitions, (void *)ami, word);
#endif
                    // acquire + release
                    ptr_vector_append(&list, ami);
                }

                continue;
            }

            /*
             * If a raw value has been put in an "allow", then I have to keep track to delete it at shutdown
             */

            if(mask)
            {
                word = slash;

                if(inet_pton(AF_INET, word, buffer) == 1)
                {
                    /* ipv4 */

                    if(proto != AF_INET)
                    {
                        acl_address_match_item_release(ami);
                        return ACL_WRONG_V4_MASK;
                    }

                    ami->match = (accept) ? amim_ipv4 : amim_ipv4_not;

                    memcpy(&ami->parameters.ipv4.mask.bytes, buffer, 4);
                    ami->parameters.ipv4.maskbits = acl_netmask_bit_count(ami->parameters.ipv4.mask.bytes, 4);
                    ami = acl_address_match_item_collection_get(ami);
                }
                else if(inet_pton(AF_INET6, word, buffer) == 1)
                {
                    /* ipv6 */

                    if(proto != AF_INET6)
                    {
                        /* free(ami); */ /* pointless since the cleanup will not be fully done anyway (list) */
                        acl_address_match_item_release(ami);
                        return ACL_WRONG_V6_MASK;
                    }

                    ami->match = (accept) ? amim_ipv6 : amim_ipv6_not;

                    memcpy(&ami->parameters.ipv6.mask.bytes, buffer, 16);
                    ami->parameters.ipv6.maskbits = acl_netmask_bit_count(ami->parameters.ipv4.mask.bytes, 16);
                    ami = acl_address_match_item_collection_get(ami);
                }
                else if(ISOK(parse_u32_check_range(word, &bits, 0, (proto == AF_INET) ? 32 : 128, BASE_10)))
                {
                    ZEROMEMORY(buffer, sizeof(buffer));

                    uint8_t *b = buffer;
                    uint8_t  maskbits = bits;

                    while(bits >= 8)
                    {
                        *b++ = 0xff;
                        bits -= 8;
                    }

                    while(bits > 0)
                    {
                        *b >>= 1;
                        *b |= 0x80;
                        bits--;
                    }

                    if(proto == AF_INET)
                    {
                        memcpy(&ami->parameters.ipv4.mask, buffer, 4);
                        ami->parameters.ipv4.maskbits = maskbits;
                    }
                    else
                    {
                        memcpy(&ami->parameters.ipv6.mask, buffer, 16);
                        ami->parameters.ipv6.maskbits = maskbits;
                    }
                    ami = acl_address_match_item_collection_get(ami);
                }
                else
                {
                    acl_address_match_item_release(ami);
                    return ACL_WRONG_MASK; /* Wrong mask */
                }
            }
            else
            {
                // acl_address_match_item_release(ami);
            }
        } // end of the ipv4 / ipv6 else block

        yassert(ami != NULL);

#if DEBUG
        log_debug7("acl_address_match_list_init_from_text(%p, %s, %u) : adding %p (---)", (void *)aml, STR(description), use_definitions, (void *)ami);
        logger_flush();
#endif

        ptr_vector_append(&list, ami);
    } /* while there is something to parse */

    int32_t count = ptr_vector_size(&list);

    if((count > 0) && (count <= 1024))
    {
        ptr_vector_shrink(&list);

#if DEBUG
        log_debug7("acl_address_match_list_init_from_text(%p, %s, %u) : items at %p", (void *)aml, STR(description), use_definitions, (void *)list.data);
        logger_flush();
#endif

        aml->items = (address_match_item_t **)list.data;
        aml->limit = &aml->items[count];
    }
    else
    {
        // the list is empty
        acl_address_match_item_vector_finalise(&list);

        if(count > 1024)
        {
            return ACL_TOO_MANY_TOKENS;
        }
    }

    return count;
}

ya_result acl_definition_add(const char *name, const char *description)
{
#if DEBUG
    log_debug7("acl_add_definition(%s, %s)", STR(name), STR(description));
    logger_flush();
#endif

    yassert(name != NULL);
    yassert(description != NULL);

    acl_entry_t *acl;
    ya_result    return_code;

    if(acl_entry_exists(name))
    {
        return ACL_DUPLICATE_ENTRY;
    }

    acl = acl_entry_new_instance(name);

    if(FAIL(return_code = acl_address_match_list_init_from_text(&acl->list, description, false)))
    {
        acl_entry_delete(acl);

        return return_code;
    }

#if DEBUG
    log_debug7("acl_add_definition(%s @ %p, %s) list %p items %p", STR(name), (void *)acl, STR(description), (void *)&acl->list, (void *)acl->list.items);
    logger_flush();
#endif

    return SUCCESS;
}

#if ACL_EXTENDED_FEATURES

static void acl_address_match_item_free_ptr(void *ami_)
{
    address_match_item *ami = (address_match_item *)ami_;

    if(!acl_address_match_item_release(ami))
    {
        uint32_t txt_size;
        char     txt[512];
        txt_size = sizeof(txt);
        acl_address_match_item_to_string(ami, txt, &txt_size);

        if(txt_size <= sizeof(txt))
        {
            log_debug7("acl: not destroying '%s' (rc=%i)", txt, ami->_rc);
        }
        else
        {
            log_debug7("acl: not destroying @%p (rc=%i)", ami, ami->_rc);
        }
    }
}

static void acl_definition_free_ptr(void *def)
{
    acl_entry *entry = (acl_entry *)def;

#if DEBUG
    log_debug7("acl_free_definition(%p) : '%s'", def, entry->name);
    logger_flush();
#endif

    free((void *)entry->name);

    address_match_item **amip = entry->list.items;
    address_match_item **limit = entry->list.limit;

    while(amip < limit)
    {
        address_match_item *ami = (*amip++);
        acl_address_match_item_release(ami);
    }

#if DEBUG
    log_debug7("acl_free_definition(%p) items: %p", def, (void *)entry->list.items);
    logger_flush();
#endif

    free(entry->list.items);

    free(entry);
}

#endif

void acl_definitions_free()
{
#if DEBUG
    log_debug7("acl_definitions_free()");
    logger_flush();
#endif
    /*
    log_debug7("acl_definitions_free(): %u amim", ptr_vector_size(&g_amim));
    ptr_vector_callback_and_clear(&g_amim, &acl_address_match_item_free_ptr);
    ptr_vector_finalise(&g_amim);

    log_debug7("acl_definitions_free(): %u acl", ptr_vector_size(&g_acl));
    ptr_vector_callback_and_clear(&g_acl, &acl_definition_free_ptr);
    ptr_vector_finalise(&g_acl);
    */
}

/**
 * Builds an access control using the text descriptors and the acl data.
 * Expands the access control.
 *
 */

ya_result acl_access_control_init_from_text(access_control_t *ac, const char *allow_query, const char *allow_update, const char *allow_update_forwarding, const char *allow_transfer, const char *allow_notify, const char *allow_control)
{
#if DEBUG
    log_debug7("acl_init_access_control_from_text(%p, %s, %s ,%s, %s, %s)", (void *)ac, STR(allow_query), STR(allow_update), STR(allow_update_forwarding), STR(allow_transfer), STR(allow_notify), STR(allow_control));
    logger_flush();
#endif
    ya_result return_code;

    // DO NOT: ZEROMEMORY(ac, sizeof(access_control_t)); as it would destroy the _rc

    ZEROMEMORY(&ac->allow_query, sizeof(address_match_set_t));
    ZEROMEMORY(&ac->allow_update, sizeof(address_match_set_t));
    ZEROMEMORY(&ac->allow_update_forwarding, sizeof(address_match_set_t));
    ZEROMEMORY(&ac->allow_transfer, sizeof(address_match_set_t));
    ZEROMEMORY(&ac->allow_notify, sizeof(address_match_set_t));
    ZEROMEMORY(&ac->allow_control, sizeof(address_match_set_t));
    ac->based_on = NULL;

    if(ISOK(return_code = acl_access_control_item_init_from_text(&ac->allow_query, allow_query)))
    {
        if(ISOK(return_code = acl_access_control_item_init_from_text(&ac->allow_update, allow_update)))
        {
            if(ISOK(return_code = acl_access_control_item_init_from_text(&ac->allow_update_forwarding, allow_update_forwarding)))
            {
                if(ISOK(return_code = acl_access_control_item_init_from_text(&ac->allow_transfer, allow_transfer)))
                {
                    if(ISOK(return_code = acl_access_control_item_init_from_text(&ac->allow_notify, allow_notify)))
                    {
                        return_code = acl_access_control_item_init_from_text(&ac->allow_control, allow_control);
                    }
                }
            }
        }
    }

    return return_code;
}

void acl_address_match_list_clear(address_match_list_t *aml)
{
#if DEBUG
    log_debug7("acl_empties_address_match_list(%p): %p", (void *)aml, (void *)aml->items);
    logger_flush();
#endif

    for(address_match_item_t **amip = aml->items; amip < aml->limit; amip++)
    {
        address_match_item_t *ami = *amip;

        if(acl_address_match_item_release(ami))
        {
            // assert(false);
            /*
            int32_t amim_idx = address_match_item_collection_get_index(ami);

            if(amim_idx >= 0)
            {
                log_debug7("acl_empties_address_match_list(%p): %p is part of amim", (void*)aml,
            address_match_item_rc(ami)); ptr_vector_end_swap(&g_amim, amim_idx); g_amim.offset--;
            }

            address_match_item_release(ami);
            */
        }
    }

#if DEBUG
    if(aml->items != NULL)
    {
        size_t n = (uint8_t *)aml->limit - (uint8_t *)aml->items;
        memset(aml->items, 0xff, n);
    }
#endif

    free(aml->items);

    aml->items = NULL;
    aml->limit = NULL;
}

void acl_address_match_set_clear(address_match_set_t *ams)
{
#if DEBUG
    log_debug7("acl_empties_address_match_set(%p)", (void *)ams);
    logger_flush();
#endif

    acl_address_match_list_clear(&ams->ipv4);
    acl_address_match_list_clear(&ams->ipv6);
    acl_address_match_list_clear(&ams->tsig);
}

void acl_access_control_clear(access_control_t *ac)
{
#if DEBUG
    log_debug7("acl_access_control_clear(%p)", (void *)ac);
    logger_flush();
#endif

    if(ac->_rc == 0)
    {
        return;
    }

    acl_address_match_set_clear(&ac->allow_notify);
    acl_address_match_set_clear(&ac->allow_query);
    acl_address_match_set_clear(&ac->allow_transfer);
    acl_address_match_set_clear(&ac->allow_update);
    acl_address_match_set_clear(&ac->allow_update_forwarding);
    acl_address_match_set_clear(&ac->allow_control);
}

void acl_address_match_list_copy(address_match_list_t *target, const address_match_list_t *aml)
{
    intptr_t n = (intptr_t)(aml->limit - aml->items);

    if(n > 0)
    {
        MALLOC_OBJECT_ARRAY_OR_DIE(target->items, address_match_item_t *, n, ADRMITEM_TAG);
        target->limit = &target->items[n];

        for(intptr_t i = 0; i < n; i++)
        {
            target->items[i] = acl_address_match_item_alloc();
            memcpy(target->items[i], aml->items[i], sizeof(address_match_item_t));
            if(target->items[i]->match == amim_reference)
            {
                target->items[i]->parameters.ref.name = strdup(target->items[i]->parameters.ref.name);
            }
        }
    }
    else
    {
        target->items = NULL;
        target->limit = NULL;
    }
}

void acl_address_match_set_copy(address_match_set_t *target, const address_match_set_t *ams)
{
    acl_address_match_list_copy(&target->ipv4, &ams->ipv4);
    acl_address_match_list_copy(&target->ipv6, &ams->ipv6);
    acl_address_match_list_copy(&target->tsig, &ams->tsig);
}

/**
 * Copies an access control.
 * The destination must not be initialised.
 *
 * @param target will receive the copy
 * @param ac the original
 */

void acl_access_control_copy(access_control_t *target, const access_control_t *ac)
{
    acl_address_match_set_copy(&target->allow_query, &ac->allow_query);
    acl_address_match_set_copy(&target->allow_update, &ac->allow_update);
    acl_address_match_set_copy(&target->allow_update_forwarding, &ac->allow_update_forwarding);
    acl_address_match_set_copy(&target->allow_transfer, &ac->allow_transfer);
    acl_address_match_set_copy(&target->allow_notify, &ac->allow_notify);
    acl_address_match_set_copy(&target->allow_control, &ac->allow_control);
}

/**
 * Increments the reference count of the access control.
 */

void acl_access_control_acquire(access_control_t *ac)
{
#if ACL_DEBUG_ARC
    int32_t rc =
#endif
        ++ac->_rc;
#if ACL_DEBUG_ARC
    log_debug("access_control@%p acquire: %i", ac, rc);
#endif
}

/**
 * Decrements the reference count of the access control.
 * Destroys it if reference count reaches zero.
 */

bool acl_access_control_release(access_control_t *ac)
{
#if !ACL_DEBUG_ARC
    if(--ac->_rc <= 0)
#else
    int32_t rc = --ac->_rc;
    if(rc <= 0)
#endif
    {
#if ACL_DEBUG_ARC
        log_debug("access_control@%p acquire: %i", ac, rc);
#endif
        acl_unmerge_access_control(ac);
        acl_access_control_clear(ac);
        ZFREE_OBJECT(ac);
        return true;
    }
#if ACL_DEBUG_ARC
    log_debug("access_control@%p acquire: %i", ac, rc);
#endif
    return false;
}

/**
 * Initialises an ACL match set (IPv4, IPv6, keys) from a text line.
 *
 * @param ams the ACL match set
 * @param allow_whatever the text description of the ACL match set
 *
 * @return an error code
 */

ya_result acl_access_control_item_init_from_text(address_match_set_t *ams, const char *allow_whatever)
{
#if DEBUG
    log_debug7("acl_build_access_control_item(%p, \"%s\")", ams, STR(allow_whatever));
#endif

    ya_result return_code;

    ZEROMEMORY(ams, sizeof(address_match_set_t));

    if(allow_whatever == NULL)
    {
        return SUCCESS;
    }

    address_match_list_t aml;
    ZEROMEMORY(&aml, sizeof(aml));

    if(ISOK(return_code = acl_address_match_list_init_from_text(&aml, allow_whatever, true)))
    {
        if(aml.items == NULL)
        {
            /*
             * Empty set
             */

#if DEBUG
            log_debug7("acl_build_access_control_item(%p, \"%s\") returning empty set", ams, STR(allow_whatever));
#endif

            return SUCCESS;
        }

        ptr_vector_t ipv4v = PTR_VECTOR_EMPTY;
        ptr_vector_t ipv6v = PTR_VECTOR_EMPTY;

#if DNSCORE_HAS_TSIG_SUPPORT
        ptr_vector_t tsigv = PTR_VECTOR_EMPTY;
#endif
        address_match_item_t **amip = aml.items;

        while(amip < aml.limit)
        {
            address_match_item_t *ami = *amip;

            if(IS_IPV4_ITEM(ami))
            {
                if(((ami->parameters.ipv4.maskbits == 32) || (ami->parameters.ipv4.maskbits == 0)) && (ami->parameters.ipv4.address.value == 0))
                {
                    /* A.K.A any/none IPv4 */
                    //             ^ | &
                    // A  0 => A 0 0 0 0
                    // A ~0 => R 0 1 1 0
                    // R  0 => R 1 0 1 0
                    // R ~0 => A 1 1 1 1

                    //             REJECTS                                 NONE
                    bool rejects = (ami->parameters.ipv4.rejects != 0);
                    bool none = (ami->parameters.ipv4.maskbits != 0);
                    bool xored = (rejects || none) && !(rejects && none);

                    // acl_free_address_match_item(item);
                    // item = alloc_address_match_item();

                    ami->match = (xored) ? amim_none : amim_any;
                }

                acl_address_match_item_acquire(ami);
                ptr_vector_append(&ipv4v, ami);
            }
            else if(IS_IPV6_ITEM(ami))
            {
                if(((ami->parameters.ipv6.maskbits == 128) || (ami->parameters.ipv6.maskbits == 0)) && IPV6_ADDRESS_ALL0(ami->parameters.ipv6.address))
                {
                    /* A.K.A any/none IPv6 */

                    // A  0 => A
                    // A ~0 => R
                    // R  0 => R
                    // R ~0 => A

                    //             REJECTS                                 NONE
                    bool rejects = (ami->parameters.ipv6.rejects != 0);
                    bool none = (ami->parameters.ipv6.maskbits != 0);
                    bool xored = (rejects || none) && !(rejects && none);

                    // acl_free_address_match_item(item);
                    // item = alloc_address_match_item();

                    ami->match = (xored) ? amim_none : amim_any;
                }

                acl_address_match_item_acquire(ami);
                ptr_vector_append(&ipv6v, ami);
            }
#if DNSCORE_HAS_TSIG_SUPPORT
            else if(IS_TSIG_ITEM(ami))
            {
                acl_address_match_item_acquire(ami);
                ptr_vector_append(&tsigv, ami);
            }
#endif
            else /* any or none */
            {
                acl_address_match_item_acquire(ami);
                acl_address_match_item_acquire(ami);
                ptr_vector_append(&ipv4v, ami);
                ptr_vector_append(&ipv6v, ami);
                // ptr_vector_append(&tsigv, item);
            }

            amip++;
        }

        ptr_vector_shrink(&ipv4v);
        ams->ipv4.items = (address_match_item_t **)ipv4v.data;
        ams->ipv4.limit = &ams->ipv4.items[ipv4v.offset + 1];

#if ACL_SORT_RULES
        amim_ipv4_sort(&ipv4v);
#endif

#if DEBUG
        amim_ipv4_print(&ipv4v);
#endif

        ptr_vector_shrink(&ipv6v);
        ams->ipv6.items = (address_match_item_t **)ipv6v.data;
        ams->ipv6.limit = &ams->ipv6.items[ipv6v.offset + 1];

#if ACL_SORT_RULES
        amim_ipv6_sort(&ipv6v);
#endif

#if DEBUG
        amim_ipv6_print(&ipv6v);
#endif

#if DNSCORE_HAS_TSIG_SUPPORT
        ptr_vector_shrink(&tsigv);
        ams->tsig.items = (address_match_item_t **)tsigv.data;
        ams->tsig.limit = &ams->tsig.items[tsigv.offset + 1];

#if DEBUG
        amim_tsig_print(&tsigv);
#endif
#endif
    }

    acl_address_match_list_clear(&aml);

#if DEBUG
    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 0);
    acl_address_match_set_to_stream(&baos, ams);
    output_stream_write_u8(&baos, 0);
    log_debug7("acl_build_access_control_item(%p, \"%s\"): %s", ams, STR(allow_whatever), bytearray_output_stream_buffer(&baos));
    output_stream_close(&baos);
#endif

#if DEBUG
    log_debug7("acl_build_access_control_item(%p, \"%s\") returning {%p,%p,%p}", ams, STR(allow_whatever), ams->ipv4.items, ams->ipv6.items, ams->tsig.items);
#endif

    return return_code;
}

// <editor-fold defaultstate="collapsed" desc="merge">

static void acl_merge_address_match_set(address_match_set_t *dest, const address_match_set_t *src)
{
    if((dest->ipv4.items == NULL) && (dest->ipv6.items == NULL) && (dest->tsig.items == NULL))
    {
        dest->ipv4.items = src->ipv4.items;
        dest->ipv4.limit = src->ipv4.limit;

        dest->ipv6.items = src->ipv6.items;
        dest->ipv6.limit = src->ipv6.limit;

        dest->tsig.items = src->tsig.items;
        dest->tsig.limit = src->tsig.limit;
    }
}

void acl_merge_access_control(access_control_t *dest, access_control_t *src)
{
#if ACL_DEBUG_ARC
    log_debug("acl_merge_access_control(%p, %p)", dest, src);
#endif

    if(dest->based_on != src)
    {
        yassert(dest->based_on == NULL);

        acl_merge_address_match_set(&dest->allow_notify, &src->allow_notify);
        acl_merge_address_match_set(&dest->allow_query, &src->allow_query);
        acl_merge_address_match_set(&dest->allow_transfer, &src->allow_transfer);
        acl_merge_address_match_set(&dest->allow_update, &src->allow_update);
        acl_merge_address_match_set(&dest->allow_update_forwarding, &src->allow_update_forwarding);
        acl_merge_address_match_set(&dest->allow_control, &src->allow_control);

        dest->based_on = src;

        acl_access_control_acquire(src);
    }
}

static void acl_unmerge_address_match_set(address_match_set_t *dest, const address_match_set_t *src)
{
    if(dest->ipv4.items == src->ipv4.items)
    {
        dest->ipv4.items = NULL;
        dest->ipv4.limit = NULL;
    }
    if(dest->ipv6.items == src->ipv6.items)
    {
        dest->ipv6.items = NULL;
        dest->ipv6.limit = NULL;
    }
    if(dest->tsig.items == src->tsig.items)
    {
        dest->tsig.items = NULL;
        dest->tsig.limit = NULL;
    }
}

void acl_unmerge_access_control(access_control_t *dest)
{
#if ACL_DEBUG_ARC
    log_debug("acl_unmerge_access_control(%p)", dest);
#endif

    if(dest->based_on != NULL)
    {
        access_control_t *src = dest->based_on;

        acl_unmerge_address_match_set(&dest->allow_notify, &src->allow_notify);
        acl_unmerge_address_match_set(&dest->allow_query, &src->allow_query);
        acl_unmerge_address_match_set(&dest->allow_transfer, &src->allow_transfer);
        acl_unmerge_address_match_set(&dest->allow_update, &src->allow_update);
        acl_unmerge_address_match_set(&dest->allow_update_forwarding, &src->allow_update_forwarding);
        acl_unmerge_address_match_set(&dest->allow_control, &src->allow_control);

        acl_access_control_release(src);
        dest->based_on = NULL;
    }
} // </editor-fold>

bool             acl_address_match_set_isempty(const address_match_set_t *ams) { return (ams->ipv4.items == NULL) && (ams->ipv6.items == NULL) && (ams->tsig.items == NULL); }

static ya_result acl_address_match_set_check_v4(const address_match_set_t *set, const struct sockaddr_in *ipv4)
{
    ya_result              return_code = 0;

    address_match_item_t **itemp = (address_match_item_t **)set->ipv4.items;

    while(itemp < set->ipv4.limit)
    {
        address_match_item_t *item = *itemp++;

        /*
         * < 0 : rejected (stop)
         * > 0 : accepted (stop)
         * = 0 : didn't matched (continue)
         */

        if((return_code = item->match(item, &ipv4->sin_addr.s_addr)) != AMIM_SKIP)
        {
            break;
        }
    }

    return return_code;
}

static ya_result acl_address_match_set_check_v6(const address_match_set_t *set, const struct sockaddr_in6 *ipv6)
{
    ya_result              return_code = 0;

    address_match_item_t **itemp = (address_match_item_t **)set->ipv6.items;

    while(itemp < set->ipv6.limit)
    {
        address_match_item_t *item = *itemp++;

        /*
         * < 0 : rejected (stop)
         * > 0 : accepted (stop)
         * = 0 : didn't matched (continue)
         */

        if((return_code = item->match(item, ipv6->sin6_addr.s6_addr)) != AMIM_SKIP)
        {
            break;
        }
    }

    return return_code;
}

static ya_result acl_address_match_set_check_tsig(const address_match_set_t *set, const void *message_with_tsig)
{
    ya_result              return_code = 0;

    address_match_item_t **itemp = (address_match_item_t **)set->tsig.items;

    while(itemp < set->tsig.limit)
    {
        address_match_item_t *item = *itemp++;

        /*
         * < 0 : rejected (stop)
         * > 0 : accepted (stop)
         * = 0 : didn't matched (continue)
         */

        if((return_code = item->match(item, message_with_tsig)) != AMIM_SKIP)
        {
            break;
        }
    }

    return return_code;
}

/********************************************************************************************************************************/

// <editor-fold defaultstate="collapsed" desc="check access">

// RRI ARI 4RI

static inline ya_result acl_check_access_filter_RRI(const dns_message_t *mesg, const address_match_set_t *ams)
{
    (void)mesg;
    (void)ams;

    return AMIM_REJECT;
}

static inline ya_result acl_check_access_filter_ARI(const dns_message_t *mesg, const address_match_set_t *ams)
{
    (void)ams;

    return (dns_message_get_sender_sa_family(mesg) == AF_INET) ? AMIM_ACCEPT : AMIM_REJECT;
}

static inline ya_result acl_check_access_filter_4RI(const dns_message_t *mesg, const address_match_set_t *ams)
{
    if(dns_message_get_sender_sa_family(mesg) == AF_INET)
    {
        return acl_address_match_set_check_v4(ams, dns_message_get_sender_sa4(mesg)) - 1; /* -1 to transform ignore to reject */
    }

    return AMIM_REJECT;
}

// RAI AAI 4AI

static inline ya_result acl_check_access_filter_RAI(const dns_message_t *mesg, const address_match_set_t *ams)
{
    (void)ams;

    return (dns_message_get_sender_sa_family(mesg) == AF_INET6) ? AMIM_ACCEPT : AMIM_REJECT;
}

static ya_result acl_check_access_filter_AAI(const dns_message_t *mesg, const address_match_set_t *ams)
{
    (void)mesg;
    (void)ams;

    return AMIM_ACCEPT;
}

static inline ya_result acl_check_access_filter_4AI(const dns_message_t *mesg, const address_match_set_t *ams)
{
    if(dns_message_get_sender_sa_family(mesg) == AF_INET)
    {
        return acl_address_match_set_check_v4(ams, dns_message_get_sender_sa4(mesg)) - 1;
    }
    else
    {
        return AMIM_ACCEPT;
    }
}

// R6I A6I 46I

static inline ya_result acl_check_access_filter_R6I(const dns_message_t *mesg, const address_match_set_t *ams)
{
    if(dns_message_get_sender_sa_family(mesg) == AF_INET6)
    {
        return acl_address_match_set_check_v6(ams, dns_message_get_sender_sa6(mesg)) - 1;
    }

    return AMIM_REJECT;
}

static inline ya_result acl_check_access_filter_A6I(const dns_message_t *mesg, const address_match_set_t *ams)
{
    if(dns_message_get_sender_sa_family(mesg) == AF_INET6)
    {
        return acl_address_match_set_check_v6(ams, dns_message_get_sender_sa6(mesg)) - 1;
    }
    else
    {
        return AMIM_ACCEPT;
    }
}

static inline ya_result acl_check_access_filter_46I(const dns_message_t *mesg, const address_match_set_t *ams)
{
    if(dns_message_get_sender_sa_family(mesg) == AF_INET)
    {
        return acl_address_match_set_check_v4(ams, dns_message_get_sender_sa4(mesg)) - 1;
    }
    else if(dns_message_get_sender_sa_family(mesg) == AF_INET6)
    {
        return acl_address_match_set_check_v6(ams, dns_message_get_sender_sa6(mesg)) - 1;
    }

    return AMIM_REJECT;
}

// TSIG

// RRT ART 4RT

static inline ya_result acl_check_access_filter_RRT(const dns_message_t *mesg, const address_match_set_t *ams)
{
    (void)mesg;
    (void)ams;

    return AMIM_REJECT;
}

static inline ya_result acl_check_access_filter_ART(const dns_message_t *mesg, const address_match_set_t *ams)
{
    if(dns_message_is_additional_section_ptr_set(mesg) && (dns_message_get_sender_sa_family(mesg) == AF_INET))
    {
        return acl_address_match_set_check_tsig(ams, mesg) - 1;
    }

    return AMIM_REJECT;
}

static inline ya_result acl_check_access_filter_4RT(const dns_message_t *mesg, const address_match_set_t *ams)
{
    if(dns_message_is_additional_section_ptr_set(mesg) && (dns_message_get_sender_sa_family(mesg) == AF_INET))
    {
        if(!ACL_REJECTED(acl_address_match_set_check_v4(ams, dns_message_get_sender_sa4(mesg))))
        {
            return acl_address_match_set_check_tsig(ams, mesg) - 1;
        }
    }

    return AMIM_REJECT;
}

// RAT AAT 4AT

static inline ya_result acl_check_access_filter_RAT(const dns_message_t *mesg, const address_match_set_t *ams)
{
    if(dns_message_is_additional_section_ptr_set(mesg) && (dns_message_get_sender_sa_family(mesg) == AF_INET6))
    {
        return acl_address_match_set_check_tsig(ams, mesg) - 1;
    }

    return AMIM_REJECT;
}

static inline ya_result acl_check_access_filter_AAT(const dns_message_t *mesg, const address_match_set_t *ams)
{
    if(dns_message_is_additional_section_ptr_set(mesg))
    {
        return acl_address_match_set_check_tsig(ams, mesg) - 1;
    }

    return AMIM_REJECT;
}

static inline ya_result acl_check_access_filter_4AT(const dns_message_t *mesg, const address_match_set_t *ams)
{
    if(dns_message_is_additional_section_ptr_set(mesg))
    {
        if(dns_message_get_sender_sa_family(mesg) == AF_INET)
        {
            if(ACL_REJECTED(acl_address_match_set_check_v4(ams, dns_message_get_sender_sa4(mesg))))
            {
                return AMIM_REJECT;
            }
        }

        return acl_address_match_set_check_tsig(ams, mesg) - 1;
    }

    return AMIM_REJECT;
}

// R6T A6T 46T

static inline ya_result acl_check_access_filter_R6T(const dns_message_t *mesg, const address_match_set_t *ams)
{
    if(dns_message_is_additional_section_ptr_set(mesg))
    {
        if(dns_message_get_sender_sa_family(mesg) == AF_INET6)
        {
            if(!ACL_REJECTED(acl_address_match_set_check_v6(ams, dns_message_get_sender_sa6(mesg))))
            {

                return acl_address_match_set_check_tsig(ams, mesg) - 1;
            }
        }
    }

    return AMIM_REJECT;
}

static inline ya_result acl_check_access_filter_A6T(const dns_message_t *mesg, const address_match_set_t *ams)
{
    if(dns_message_is_additional_section_ptr_set(mesg))
    {
        if(dns_message_get_sender_sa_family(mesg) == AF_INET6)
        {
            if(ACL_REJECTED(acl_address_match_set_check_v6(ams, dns_message_get_sender_sa6(mesg))))
            {
                return AMIM_REJECT;
            }
        }

        return acl_address_match_set_check_tsig(ams, mesg) - 1;
    }

    return AMIM_REJECT;
}

static inline ya_result acl_check_access_filter_46T(const dns_message_t *mesg, const address_match_set_t *ams)
{
    if(dns_message_is_additional_section_ptr_set(mesg))
    {
        if(dns_message_get_sender_sa_family(mesg) == AF_INET)
        {
            if(ACL_REJECTED(acl_address_match_set_check_v4(ams, dns_message_get_sender_sa4(mesg))))
            {
                return AMIM_REJECT;
            }
        }
        else if(dns_message_get_sender_sa_family(mesg) == AF_INET6)
        {
            if(ACL_REJECTED(acl_address_match_set_check_v6(ams, dns_message_get_sender_sa6(mesg))))
            {
                return AMIM_REJECT;
            }
        }

        return acl_address_match_set_check_tsig(ams, mesg) - 1;
    }

    return AMIM_REJECT;
}

/**
 * Checks if the message is accepted (> 0), rejected (< 0) or ignored (==0)
 *
 * @param mesg the message
 * @param ams the access match set to check the message against.
 *
 * @return return an amim code, use with: ACL_ACCEPTED(amim), ACL_REJECTED(amim), ACL_IGNORED(amim)
 */

ya_result acl_check_access_filter(const dns_message_t *mesg, const address_match_set_t *ams)
{
    ya_result return_code = AMIM_SKIP;

    /*
     * If there the client is on IPvX and IPvX has rules, the default is set to REJECT
     * then the client's address is compared to all the items in the list, returning on a match.
     */

    if(dns_message_get_sender_sa_family(mesg) == AF_INET)
    {
        if(ams->ipv4.items != NULL)
        {
            if(ACL_REJECTED(return_code = acl_address_match_set_check_v4(ams, dns_message_get_sender_sa4(mesg))))
            {
                return return_code;
            }
        }
    }
    else if(dns_message_get_sender_sa_family(mesg) == AF_INET6)
    {
        if(ams->ipv6.items != NULL)
        {
            if(ACL_REJECTED(return_code = acl_address_match_set_check_v6(ams, dns_message_get_sender_sa6(mesg))))
            {
                return return_code;
            }
        }
    }
#if DEBUG
    else
    {
        log_err("acl: unsupported address family %d", dns_message_get_sender_sa_family(mesg));

        return AMIM_REJECT;
    }
#endif

    /*
     * At this point, none of the IPs have been explicitly rejected.
     * If they are accepted
     */

    /*
     * If no address has been matched, then if the rules are holding any TSIG, ...
     */

    if(ams->tsig.items != NULL)
    {
        if(dns_message_is_additional_section_ptr_set(mesg))
        {
            return_code += acl_address_match_set_check_tsig(ams, mesg);
        }
        else
        {
            --return_code;
        }
    }

    return_code--;

    return return_code;
}

// </editor-fold>

/*
 * RRI ARI FRI
 * RAI AAI FAI
 * RFI AFI FFI
 * RRF ARF FRF
 * RAF AAF FAF
 * RFF AFF FFF
 */

#define CAF(x) acl_check_access_filter_##x

static acl_check_access_filter_callback *access_filter_by_type[18] = {
    CAF(RRI), CAF(ARI), CAF(4RI), CAF(RAI), CAF(AAI), CAF(4AI), CAF(R6I), CAF(A6I), CAF(46I), CAF(RRT), CAF(ART), CAF(4RT), CAF(RAT), CAF(AAT), CAF(4AT), CAF(R6T), CAF(A6T), CAF(46T)};

#undef CAF

/**
 * Returns the check access filter callback for an address match set
 *
 * @return the callback
 */

acl_check_access_filter_callback *acl_get_check_access_filter(const address_match_set_t *set)
{
    acl_check_access_filter_callback *cb;

    uint32_t                          t = acl_address_match_set_get_type(set);

    cb = access_filter_by_type[t];

    return cb;
}

/********************************************************************************************************************************/

// <editor-fold defaultstate="collapsed" desc="query access">

/**
 * This macro is a template for the hook function from the allow_query input to the generic input
 * The only hooks that are not using it are the most simple ones (returning ACCEPT or REJECT)
 */

#define CAF_HOOK(x)                                                                                                                                                                                                                            \
    static inline ya_result acl_query_access_filter_##x(const dns_message_t *mesg, const void *extension)                                                                                                                                      \
    {                                                                                                                                                                                                                                          \
        const access_control_t *ac = (const access_control_t *)extension;                                                                                                                                                                      \
        return acl_check_access_filter_##x(mesg, &ac->allow_query);                                                                                                                                                                            \
    }

static ya_result acl_query_access_filter_AAI(const dns_message_t *mesg, const void *extension)
{
    (void)mesg;
    (void)extension;

    return AMIM_ACCEPT;
}

static ya_result acl_query_access_filter_RRI(const dns_message_t *mesg, const void *extension)
{
    (void)mesg;
    (void)extension;

    return AMIM_REJECT;
}

static ya_result acl_query_access_filter_RRT(const dns_message_t *mesg, const void *extension)
{
    (void)mesg;
    (void)extension;

    return AMIM_REJECT;
}

// CAF_HOOK(RRI)
CAF_HOOK(ARI)
CAF_HOOK(4RI)

CAF_HOOK(RAI)
// CAF_HOOK(AAI)
CAF_HOOK(4AI)

CAF_HOOK(R6I)
CAF_HOOK(A6I)
CAF_HOOK(46I)

// CAF_HOOK(RRT)
CAF_HOOK(ART)
CAF_HOOK(4RT)

CAF_HOOK(RAT)
CAF_HOOK(AAT)
CAF_HOOK(4AT)

CAF_HOOK(R6T)
CAF_HOOK(A6T)
CAF_HOOK(46T)

// </editor-fold>

#define QAF(x) acl_query_access_filter_##x

static acl_query_access_filter_callback *query_access_filter_by_type[18] = {
    QAF(RRI), QAF(ARI), QAF(4RI), QAF(RAI), QAF(AAI), QAF(4AI), QAF(R6I), QAF(A6I), QAF(46I), QAF(RRT), QAF(ART), QAF(4RT), QAF(RAT), QAF(AAT), QAF(4AT), QAF(R6T), QAF(A6T), QAF(46T)};

static char *query_access_filter_name[18] = {"RRI", "ARI", "4RI", "RAI", "AAI", "4AI", "R6I", "A6I", "46I", "RRT", "ART", "4RT", "RAT", "AAT", "4AT", "R6T", "A6T", "46T"};

#undef QAF

/**
 * Returns the query check access filter callback for an address match set
 *
 * @return the callback
 */

acl_query_access_filter_callback *acl_get_query_access_filter(const address_match_set_t *set)
{
    acl_query_access_filter_callback *cb;

    uint32_t                          t = acl_address_match_set_get_type(set);

    cb = query_access_filter_by_type[t];

    return cb;
}

ya_result acl_address_match_item_to_stream(output_stream_t *os, const address_match_item_t *ami)
{
    ya_result return_code;

    if(ami == NULL)
    {
        return 0;
    }
    else if(IS_IPV4_ITEM(ami))
    {
        int8_t b = ami->parameters.ipv4.maskbits;
        // int8_t r = ami->parameters.ipv4.rejects;

        struct sockaddr_in ipv4;
        ipv4.sin_addr.s_addr = ami->parameters.ipv4.address.value;
        ipv4.sin_family = AF_INET;

        if(IS_IPV4_ITEM_MATCH(ami))
        {
            return_code = osformat(os, "%{sockaddrip}/%d", &ipv4, b);
        }
        else
        {
            return_code = osformat(os, "!%{sockaddrip}/%d", &ipv4, b);
        }
    }
    else if(IS_IPV6_ITEM(ami))
    {
        int16_t b = ami->parameters.ipv6.maskbits;
        // int8_t r = ami->parameters.ipv6.rejects;

        struct sockaddr_in6 ipv6;
        memcpy((uint8_t *)&ipv6.sin6_addr, ami->parameters.ipv6.address.bytes, 16);
        ipv6.sin6_family = AF_INET6;

        if(IS_IPV6_ITEM_MATCH(ami))
        {
            return_code = osformat(os, "%{sockaddrip}/%d", &ipv6, b);
        }
        else
        {
            return_code = osformat(os, "!%{sockaddrip}/%d", &ipv6, b);
        }
    }
#if DNSCORE_HAS_TSIG_SUPPORT
    else if(IS_TSIG_ITEM(ami))
    {
        if(IS_TSIG_ITEM_MATCH(ami))
        {
            return_code = osformat(os, "key %{dnsname}", ami->parameters.tsig.name);
        }
        else
        {
            return_code = osformat(os, "!key %{dnsname}", ami->parameters.tsig.name);
        }
    }
#endif
    else if(IS_ANY_ITEM(ami))
    {
        if(IS_ANY_ITEM_MATCH(ami))
        {
            // osformat(os, "any [%i]", acl_address_match_item_rc(ami));
            output_stream_write(os, "any", 3);

            return 1;
        }
        else // if(IS_NONE_ITEM_MATCH(ami))
        {
            // osformat(os, "none [%i]", acl_address_match_item_rc(ami));
            output_stream_write(os, "none", 4);

            return 2;
        }
    }
    else
    {
        // return_code = osformat(os, "?");
        output_stream_write(os, "?", 1);
        return -1;
    }
    if(ISOK(return_code))
    {
        // osformat(os, "[%i]", acl_address_match_item_rc(ami));
        return_code = 0;
    }
    return return_code;
}

void acl_address_match_set_to_stream(output_stream_t *os, const address_match_set_t *ams)
{
    address_match_item_t **item;
    address_match_item_t **limit;
    char                  *separator;
#if ACL_ADDRESS_MATCH_SET_TO_STREAM_PRINT_ANY_NONE
    ya_result any_none = 0;
#endif
    ya_result return_code;

    item = ams->ipv4.items;
    limit = ams->ipv4.limit;
    separator = "";

    while(item < limit)
    {
        output_stream_write_text(os, separator);
        return_code = acl_address_match_item_to_stream(os, *item);

#if ACL_ADDRESS_MATCH_SET_TO_STREAM_PRINT_ANY_NONE
        if(return_code > 0)
        {
            any_none |= return_code;
            // break;
        }
#else
        (void)return_code;
#endif

        separator = ",";
        item++;
    }

    item = ams->ipv6.items;
    limit = ams->ipv6.limit;

    while(item < limit)
    {
        output_stream_write_text(os, separator);
        return_code = acl_address_match_item_to_stream(os, *item);

#if ACL_ADDRESS_MATCH_SET_TO_STREAM_PRINT_ANY_NONE
        if(return_code > 0)
        {
            any_none |= return_code;
            // break;
        }
#else
        (void)return_code;
#endif

        separator = ",";
        item++;
    }

    item = ams->tsig.items;
    limit = ams->tsig.limit;

    while(item < limit)
    {
        output_stream_write_text(os, separator);
        return_code = acl_address_match_item_to_stream(os, *item);

#if ACL_ADDRESS_MATCH_SET_TO_STREAM_PRINT_ANY_NONE
        if(return_code > 0)
        {
            any_none |= return_code;
            // break;
        }
#else
        (void)return_code;
#endif

        separator = ",";
        item++;
    }
#if ACL_ADDRESS_MATCH_SET_TO_STREAM_PRINT_ANY_NONE
    if(any_none != 0)
    {
        if(any_none & 1)
        {
            osformat(os, "%sany", separator);
            separator = ",";
        }
        if(any_none & 2)
        {
            osformat(os, "%snone", separator);
        }
    }
#endif
}

ya_result acl_address_match_item_to_string(const address_match_item_t *ami, char *out_txt, uint32_t *out_txt_lenp)
{
    ya_result return_code;

    uint32_t  out_txt_len = *out_txt_lenp;

    if(ami == NULL)
    {
        return_code = snformat(out_txt, out_txt_len, "NULL->REJECT");
    }
    else if(IS_IPV4_ITEM(ami))
    {
        int8_t b = ami->parameters.ipv4.maskbits;
        // int8_t r = ami->parameters.ipv4.rejects;

        struct sockaddr_in ipv4;
        ipv4.sin_addr.s_addr = ami->parameters.ipv4.address.value;
        ipv4.sin_family = AF_INET;

        if(IS_IPV4_ITEM_MATCH(ami))
        {
            return_code = snformat(out_txt, out_txt_len, "[%{sockaddrip}/%d]", &ipv4, b);
        }
        else
        {
            return_code = snformat(out_txt, out_txt_len, "![%{sockaddrip}/%d]", &ipv4, b);
        }
    }
    else if(IS_IPV6_ITEM(ami))
    {
        int16_t b = ami->parameters.ipv6.maskbits;
        // int8_t r = ami->parameters.ipv6.rejects;

        struct sockaddr_in6 ipv6;
        memcpy((uint8_t *)&ipv6.sin6_addr, ami->parameters.ipv6.address.bytes, 16);
        ipv6.sin6_family = AF_INET6;

        if(IS_IPV6_ITEM_MATCH(ami))
        {
            return_code = snformat(out_txt, out_txt_len, "[%{sockaddrip}/%d]", &ipv6, b);
        }
        else
        {
            return_code = snformat(out_txt, out_txt_len, "![%{sockaddrip}/%d]", &ipv6, b);
        }
    }
#if DNSCORE_HAS_TSIG_SUPPORT
    else if(IS_TSIG_ITEM(ami))
    {
        if(IS_TSIG_ITEM_MATCH(ami))
        {
            return_code = snformat(out_txt, out_txt_len, "[%{dnsname}]", ami->parameters.tsig.name);
        }
        else
        {
            return_code = snformat(out_txt, out_txt_len, "![%{dnsname}]", ami->parameters.tsig.name);
        }
    }
#endif
    else if(IS_ANY_ITEM(ami))
    {
        if(IS_ANY_ITEM_MATCH(ami))
        {
            return_code = snformat(out_txt, out_txt_len, "[any]");
        }
        else
        {
            return_code = snformat(out_txt, out_txt_len, "[none]");
        }
    }
    else
    {
        return_code = snformat(out_txt, out_txt_len, "?");
    }

    if(ISOK(return_code))
    {
        *out_txt_lenp = (uint32_t)return_code;
    }

    return return_code;
}

bool acl_address_match_item_equals(const address_match_item_t *a, const address_match_item_t *b)
{
    if(a == b)
    {
        return true;
    }

    if((a == NULL) || (b == NULL))
    {
        return false;
    }

    if(a->match == b->match)
    {
        if((a->match == amim_none) || (a->match == amim_any))
        {
            return true;
        }

        if((a->match == amim_ipv4) || (a->match == amim_ipv4_not))
        {
            return a->parameters.ipv4.address.value == b->parameters.ipv4.address.value;
        }

        if((a->match == amim_ipv6) || (a->match == amim_ipv6_not))
        {
            return (a->parameters.ipv6.address.lohi[0] == b->parameters.ipv6.address.lohi[0]) && (a->parameters.ipv6.address.lohi[1] == b->parameters.ipv6.address.lohi[1]);
        }

#if DNSCORE_HAS_TSIG_SUPPORT
        if((a->match == amim_tsig) || (a->match == amim_tsig_not))
        {
            return (a->parameters.tsig.mac_algorithm == b->parameters.tsig.mac_algorithm) && (a->parameters.tsig.name_size == b->parameters.tsig.name_size) && (a->parameters.tsig.secret_size == b->parameters.tsig.secret_size) &&
                   (memcmp(a->parameters.tsig.name, b->parameters.tsig.name, a->parameters.tsig.name_size) == 0) && (memcmp(a->parameters.tsig.known, b->parameters.tsig.known, a->parameters.tsig.secret_size) == 0);
        }
#endif

        if(a->match == amim_reference)
        {
            return (a->parameters.ref.mark == b->parameters.ref.mark) && (strcmp(a->parameters.ref.name, b->parameters.ref.name) == 0);
        }
    }

    return false;
}

/**
 * Compares two address_match_item_t
 * @param a first item
 * @param b second item
 * @return 0: equals <0: a<b >0: a>b
 *
 */

int acl_address_match_item_compare(const address_match_item_t *a, const address_match_item_t *b)
{
    if(a == b)
    {
        return 0;
    }

    if(a == NULL)
    {
        return -1;
    }
    else if(b == NULL)
    {
        return 1;
    }

    if(a->match != b->match)
    {
        intptr_t d = ((intptr_t)a->match) - ((intptr_t)b->match);
        if(d > 0)
        {
            return 1;
        }
        else
        {
            return -1;
        }
    }

    // same type

    if((a->match == amim_ipv4) || (a->match == amim_ipv4_not))
    {
        return memcmp(&a->parameters.ipv4, &b->parameters.ipv4, sizeof(ipv4_id_t));
    }

    if((a->match == amim_ipv6) || (a->match == amim_ipv6_not))
    {
        return memcmp(&a->parameters.ipv6, &b->parameters.ipv6, sizeof(ipv6_id_t));
    }

#if DNSCORE_HAS_TSIG_SUPPORT
    if((a->match == amim_tsig) || (a->match == amim_tsig_not))
    {
        int d = (int)a->parameters.tsig.mac_algorithm - (int)b->parameters.tsig.mac_algorithm;
        if(d == 0)
        {
            d = (int)a->parameters.tsig.name_size - (int)b->parameters.tsig.name_size;

            if(d == 0)
            {
                d = (int)a->parameters.tsig.secret_size - (int)b->parameters.tsig.secret_size;

                if(d == 0)
                {
                    d = memcmp(a->parameters.tsig.name, b->parameters.tsig.name, a->parameters.tsig.name_size);

                    if(d == 0)
                    {
                        d = memcmp(a->parameters.tsig.known, b->parameters.tsig.known, a->parameters.tsig.secret_size);
                    }
                }
            }
        }
        return d;
    }
#endif

    if(a->match == amim_reference)
    {
        if(a->parameters.ref.mark == b->parameters.ref.mark)
        {
            int ret = strcmp(a->parameters.ref.name, b->parameters.ref.name);
            return ret;
        }

        if(a->parameters.ref.mark)
        {
            return 1;
        }
        else
        {
            return -1;
        }
    }

    // amim_none or amim_any

    return 0;
}

bool acl_address_match_list_equals(const address_match_list_t *a, const address_match_list_t *b)
{
    if(a == b)
    {
        return true;
    }
    if((a == NULL) || (b == NULL))
    {
        return false;
    }

    uint_fast32_t n = acl_address_match_list_size(a);

    if(n == acl_address_match_list_size(b))
    {
        address_match_item_t **a_items = a->items;
        address_match_item_t **b_items = b->items;

        for(uint_fast32_t i = 0; i < n; i++)
        {
            if(!acl_address_match_item_equals(a_items[i], b_items[i]))
            {
                return false;
            }
        }

        return true;
    }

    return false;
}

bool acl_address_match_set_equals(const address_match_set_t *a, const address_match_set_t *b)
{
    if(a == b)
    {
        return true;
    }
    if((a == NULL) || (b == NULL))
    {
        return false;
    }

    return acl_address_match_list_equals(&a->ipv4, &b->ipv4) && acl_address_match_list_equals(&a->ipv6, &b->ipv6) && acl_address_match_list_equals(&a->tsig, &b->tsig);
}

bool acl_address_control_equals(const access_control_t *a, const access_control_t *b)
{
    if(a == b)
    {
#if ACL_DEBUG_FULL
        log_debug("acl_address_control_equals(%p, %p) = true", a, b);
#endif

        return true;
    }
    if((a == NULL) || (b == NULL))
    {
#if ACL_DEBUG_FULL
        log_debug("acl_address_control_equals(%p, %p) = false", a, b);
#endif
        return false;
    }

    bool ret = acl_address_match_set_equals(&a->allow_query, &b->allow_query) && acl_address_match_set_equals(&a->allow_update, &b->allow_update) && acl_address_match_set_equals(&a->allow_update_forwarding, &b->allow_update_forwarding) &&
               acl_address_match_set_equals(&a->allow_transfer, &b->allow_transfer) && acl_address_match_set_equals(&a->allow_notify, &b->allow_notify) && acl_address_match_set_equals(&a->allow_control, &b->allow_control);

#if ACL_DEBUG_FULL
    log_debug("acl_address_control_equals(%p, %p) = %s (deep)", a, b, ret ? "true" : "false");
#endif

    return ret;
}

/**
 * Registers all ACL errors.
 */

void acl_register_errors()
{
    /* ACL */
    error_register(ACL_ERROR_BASE, "ACL_ERROR_BASE");
    error_register(ACL_TOKEN_SIZE_ERROR, "ACL_TOKEN_SIZE_ERROR");
    error_register(ACL_UNEXPECTED_NEGATION, "ACL_UNEXPECTED_NEGATION");
    error_register(ACL_WRONG_V4_MASK, "ACL_WRONG_V4_MASK");
    error_register(ACL_WRONG_V6_MASK, "ACL_WRONG_V6_MASK");
    error_register(ACL_WRONG_MASK, "ACL_WRONG_MASK");
    error_register(ACL_DUPLICATE_ENTRY, "ACL_DUPLICATE_ENTRY");
    error_register(ACL_RESERVED_KEYWORD, "ACL_RESERVED_KEYWORD");
    error_register(ACL_TOO_MANY_TOKENS, "ACL_TOO_MANY_TOKENS");
    error_register(ACL_NAME_PARSE_ERROR, "ACL_NAME_PARSE_ERROR");
    error_register(ACL_UNKNOWN_TSIG_KEY, "ACL_UNKNOWN_TSIG_KEY");
    error_register(ACL_UPDATE_REJECTED, "ACL_UPDATE_REJECTED");
    error_register(ACL_NOTIFY_REJECTED, "ACL_NOTIFY_REJECTED");
    error_register(ACL_UNDEFINED_TOKEN, "ACL_UNDEFINED_TOKEN");
}

/**
 * Returns a name associated to a matcher.  Mostly for debugging purpose.
 */

const char *acl_get_matcher_name(address_match_item_matcher *matcher)
{
    if(matcher == amim_none)
    {
        return "none";
    }
    if(matcher == amim_any)
    {
        return "any";
    }
    if(matcher == amim_ipv4)
    {
        return "ipv4";
    }
    if(matcher == amim_ipv4_not)
    {
        return "!ipv4";
    }
    if(matcher == amim_ipv6)
    {
        return "ipv6";
    }
    if(matcher == amim_ipv6_not)
    {
        return "!ipv6";
    }
    if(matcher == amim_tsig)
    {
        return "key";
    }
    if(matcher == amim_tsig_not)
    {
        return "!key";
    }
    if(matcher == amim_reference)
    {
        return "ref";
    }
    return "?";
}

/**
 * Returns the index of a filter callback.  Mostly for debugging purpose.
 * @return [0;17]
 */

int acl_get_check_access_filter_index(acl_check_access_filter_callback *callback)
{
    for(int i = 0; i < 18; ++i)
    {
        if(access_filter_by_type[i] == callback)
        {
            return i;
        }
    }
    return -1;
}

/**
 * Returns the index of a filter callback.  Mostly for debugging purpose.
 * @return [0;17]
 */

const char *acl_get_check_access_filter_name(acl_check_access_filter_callback *callback)
{
    int index = acl_get_check_access_filter_index(callback);
    if(index >= 0 && index < 18)
    {
        return query_access_filter_name[index];
    }
    return "?";
}

/** @} */
