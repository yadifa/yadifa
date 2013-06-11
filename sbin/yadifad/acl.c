/*-----------------------------------------------------------------------------
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
 * DOCUMENTATION */
/** @defgroup acl Access Control List
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */

#include <stdio.h>
#include <stdlib.h>

#include <netinet/in.h>

#include <dnscore/logger.h>
extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include <dnscore/parsing.h>
#include <dnscore/base64.h>
#include <dnscore/message.h>
#include <dnscore/format.h>

#include "acl.h"

#include "parser.h"

#define ADRMITEM_TAG 0x4d4554494d524441
#define ACLENTRY_TAG 0x5952544e454c4341

#define ACL_DEBUG_FULL 0

#ifndef DEBUG
#undef ACL_DEBUG_FULL
#define ACL_DEBUG_FULL 0
#endif

/*
 * 2011/10/18 : EDF: disabling the debug because it makes the legitimate error output unreadable.
 */


#if ACL_DEBUG_FULL == 0
#undef DEBUGLNF
#undef DEBUGF
#undef OSDEBUG
#undef LDEBUG
#undef OSLDEBUG
#define DEBUGLNF(...)
#define DEBUGF(...)
#define OSDEBUG(...)
#define LDEBUG(...)
#define OSLDEBUG(...)
#endif

#define STR(x) ((x)!=NULL)?(x):"NULL"

/*
 * Contains all the definitions from the <acl> section
 */

// <editor-fold defaultstate="collapsed" desc="DEBUG-ONLY FUNCTIONS">

#ifndef NDEBUG

#if ACL_DEBUG_FULL != 0
static const char* query_access_filter_type_name[18]=
{
 "RRI",  "ARI",  "4RI", 
 "RAI",  "AAI",  "4AI", 
 "R6I",  "A6I",  "46I", 
 "RRT",  "ART",  "4RT", 
 "RAT",  "AAT",  "4AT", 
 "R6T",  "A6T",  "46T"
};
#endif

static void
amim_ipv4_print(ptr_vector *ipv4v)
{
#if ACL_DEBUG_FULL != 0
    address_match_item **itemp = (address_match_item **)ipv4v->data;
    s32 idx = 0;

    osformat(termerr, "\tipv4@%p\n", (void*)itemp);

    while(idx <= ipv4v->offset)
    {
        u8* ip = itemp[idx]->parameters.ipv4.address.bytes;
        u8* mask = itemp[idx]->parameters.ipv4.mask.bytes;

        osformat(termerr, "\t\t[%hhu.%hhu.%hhu.%hhu/%hhu.%hhu.%hhu.%hhu (%hu) %c]\n",
                ip[0], ip[1], ip[2], ip[3],
                mask[0], mask[1], mask[2], mask[3],
                itemp[idx]->parameters.ipv4.maskbits,
                (itemp[idx]->parameters.ipv4.rejects == 0) ? 'a' : 'r');
        idx++;
    }
#endif
}

static void
amim_ipv6_print(ptr_vector *ipv6v)
{
#if ACL_DEBUG_FULL != 0
    address_match_item **itemp = (address_match_item **)ipv6v->data;
    s32 idx = 0;

    osformat(termerr, "\tipv6@%p\n", (void*)itemp);

    while(idx <= ipv6v->offset)
    {
        u8* ip = itemp[idx]->parameters.ipv6.address.bytes;
        u8* mask = itemp[idx]->parameters.ipv6.mask.bytes;

        osformat(termerr, "\t\t[%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx/%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx (%hi) %c]\n",
                ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15],
                mask[0], mask[1], mask[2], mask[3], mask[4], mask[5], mask[6], mask[7], mask[8], mask[9], mask[10], mask[11], mask[12], mask[13], mask[14], mask[15],
                itemp[idx]->parameters.ipv6.maskbits,
                (itemp[idx]->parameters.ipv6.rejects == 0) ? 'a' : 'r');

        idx++;
    }
#endif
}

static void
amim_tsig_print(ptr_vector *tsigv)
{
#if ACL_DEBUG_FULL != 0
    address_match_item **itemp = (address_match_item **)tsigv->data;
    s32 idx = 0;

    osformat(termerr, "\ttsig@%p\n", (void*)itemp);

    while(idx <= tsigv->offset)
    {
        u8* name = itemp[idx]->parameters.tsig.name;
        osformat(termerr, "\t\t%{dnsname}\n", name);
        idx++;
    }
#endif
}

#endif

// </editor-fold>

static ptr_vector g_acl = EMPTY_PTR_VECTOR;
static ptr_vector g_amim = EMPTY_PTR_VECTOR; /* Store the ones defined outside a chain so they can be deleted */


typedef int amim_function(struct address_match_item*, void*);

// <editor-fold defaultstate="collapsed" desc="AMIM functions">

static int
amim_none(struct address_match_item* item, void* data)
{
    return AMIM_REJECT;
}

static int
amim_any(struct address_match_item* item, void* data)
{
    return AMIM_ACCEPT;
}

static int
amim_ipv4(struct address_match_item* item, void* data)
{
    ipv4_id* items = &item->parameters.ipv4;
    u32* ip = (u32*)data;
    return ( (items->address.value & items->mask.value) == (*ip & items->mask.value)) ? AMIM_ACCEPT : AMIM_SKIP;
}

static int
amim_ipv4_not(struct address_match_item *item, void* data)
{
    return -amim_ipv4(item, data);
}

static int
amim_ipv6(struct address_match_item *item, void* data)
{
    u64* ipv6_bytes = (u64*)data;
    ipv6_id* items = &item->parameters.ipv6;
    return (
            ((items->address.lohi[0] & items->mask.lohi[0]) == (ipv6_bytes[0] & items->mask.lohi[0])) &&
            ((items->address.lohi[1] & items->mask.lohi[1]) == (ipv6_bytes[1] & items->mask.lohi[1]))
            ) ? AMIM_ACCEPT : AMIM_SKIP;
}

static int
amim_ipv6_not(struct address_match_item *item, void *data)
{
    return -amim_ipv6(item, data);
}

static int
amim_tsig(struct address_match_item *item, void *data)
{
    message_data *mesg = (message_data*)data;

    /*
     * The TSIG has already been verified as being valid.  So all we need to know if : is it allowed ?
     */

    // mesg->tsig->tsig->name;
    // log_debug("tsig : %p", mesg->tsig.tsig->name);

    const tsig_item *tsig = mesg->tsig.tsig;

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

    return AMIM_SKIP; /* no match */
}

static int
amim_tsig_not(struct address_match_item *item, void *data)
{
    return -amim_tsig(item, data);
}

static int
amim_reference(struct address_match_item *item, void *data)
{
    return AMIM_REJECT;
}// </editor-fold>

// <editor-fold defaultstate="collapsed" desc="RULES SORTING">

#if ACL_SORT_RULES != 0

static int
amim_ipv4_sort_callback(const void *a, const void *b)
{
    address_match_item *ia = *(address_match_item**)a;
    address_match_item *ib = *(address_match_item**)b;

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

static void
amim_ipv4_sort(ptr_vector *ipv4v)
{
    ptr_vector_qsort(ipv4v, amim_ipv4_sort_callback);
}

static int
amim_ipv6_sort_callback(const void *a, const void *b)
{
    address_match_item *ia = *(address_match_item**)a;
    address_match_item *ib = *(address_match_item**)b;

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

static void
amim_ipv6_sort(ptr_vector *ipv6v)
{
    ptr_vector_qsort(ipv6v, amim_ipv6_sort_callback);
}

#endif

// </editor-fold>

#define AML_REJECT 0 /* DO NOT CHANGE THESES VALUES */
#define AML_ACCEPT 1 /* DO NOT CHANGE THESES VALUES */
#define AML_FILTER 2 /* DO NOT CHANGE THESES VALUES */

static inline u32
address_match_list_size(address_match_list *aml)
{
    return (aml != NULL)?aml->limit - aml->items:0;
}

static u32
address_match_list_get_type(address_match_list *aml)
{
    if(aml == NULL)
    {
        return AML_REJECT;
    }
    
    u32 n = address_match_list_size(aml);
        
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
        default:
        {
            return AML_FILTER;
        }
    }
}

static u32
address_match_set_get_type(address_match_set *ams)
{
    /*
     * TSIG cannot be globally accepted nor rejected.
     * It can only be ignored or filtered.
     * So [0;1] => 0 and 2 => 1.
     */
    
    u32 tsig = (address_match_list_get_type(&ams->tsig) >> 1) * 9;
    
    if(tsig == 0)
    {
        /* no tsig, no modifier here */
        return address_match_list_get_type(&ams->ipv4) + address_match_list_get_type(&ams->ipv6) * 3;
    }
    else
    {
        /*
         * If a tsig is defined and BOTH IPs rules have a size of zero, then both are accepted.
         */
        
        if(address_match_list_size(&ams->ipv4) + address_match_list_size(&ams->ipv6) == 0)
        {
            return AML_ACCEPT + AML_ACCEPT * 3 + tsig;
        }
        else
        {
            return address_match_list_get_type(&ams->ipv4) + address_match_list_get_type(&ams->ipv6) * 3 + tsig * 9;
        }
    }
}


#define IS_IPV4_ITEM(x_) (((x_)->match == amim_ipv4)||((x_)->match == amim_ipv4_not))
#define IS_IPV6_ITEM(x_) (((x_)->match == amim_ipv6)||((x_)->match == amim_ipv6_not))
#define IS_TSIG_ITEM(x_) (((x_)->match == amim_tsig)||((x_)->match == amim_tsig_not))
#define IS_ANY_ITEM(x_)  (((x_)->match == amim_any)||((x_)->match == amim_none))
#define IS_NONE_ITEM(x_) (((x_)->match == amim_any)||((x_)->match == amim_none))

#define IS_IPV4_ITEM_MATCH(x_) ((x_)->match == amim_ipv4)
#define IS_IPV6_ITEM_MATCH(x_) ((x_)->match == amim_ipv6)
#define IS_TSIG_ITEM_MATCH(x_) ((x_)->match == amim_tsig)
#define IS_ANY_ITEM_MATCH(x_)  ((x_)->match == amim_any)
#define IS_NONE_ITEM_MATCH(x_) ((x_)->match == amim_none)

#define IS_IPV4_ITEM_MATCH_NOT(x_) ((x_)->match == amim_ipv4_not)
#define IS_IPV6_ITEM_MATCH_NOT(x_) ((x_)->match == amim_ipv6_not)
#define IS_TSIG_ITEM_MATCH_NOT(x_) ((x_)->match == amim_tsig_not)
#define IS_ANY_ITEM_MATCH_NOT(x_)  ((x_)->match == amim_none)
#define IS_NONE_ITEM_MATCH_NOT(x_) ((x_)->match == amim_any)


static address_match_item*
alloc_address_match_item()
{
    address_match_item* item;
    
    MALLOC_OR_DIE(address_match_item*, item, sizeof(address_match_item), ADRMITEM_TAG);
    ZEROMEMORY(item, sizeof (address_match_item));

    return item;
}

static ya_result
acl_expand_address_match_reference(ptr_vector *amlv, const char* word, ptr_vector *acls)
{
    ya_result return_value = 0;
    
    OSDEBUG(termerr,  "acl_expand_address_match_reference(%p, %s, %p)\n", (void*)amlv, word, (void*)acls);

    s32 index = 0;

    while(index <= acls->offset)
    {
        acl_entry* acl = acls->data[index++];

        if(strcasecmp(acl->name, word) == 0)
        {
            address_match_item **itemp = acl->list.items;

            while(itemp < acl->list.limit)
            {
                address_match_item *item = *itemp;

                if(item->match == amim_reference)
                {
                    /* recurse */

                    if(!item->parameters.ref.mark)
                    {
                        item->parameters.ref.mark = TRUE;

                        ya_result expand = acl_expand_address_match_reference(amlv, item->parameters.ref.name, acls);

                        if(expand > 0)
                        {
                            return_value += expand;
                        }
                        else
                        {
                            if(expand == 0)
                            {
                                log_err("acl: expanding '%s': '%s' is undefined", word, item->parameters.ref.name);
                            }
                            else
                            {
                                log_err("acl: expanding '%s': '%s' cannot be expanded", word, item->parameters.ref.name);
                            }
                            return_value = MIN_S32; // forces an error
                        }

                        item->parameters.ref.mark = FALSE;
                    }
                }
                else
                {
                    ptr_vector_append(amlv, *itemp);
                    
                    return_value++;
                }

                itemp++;
            }

            break;
        }
    }

    return return_value;
}

static inline u32
netmask_bit_count(u8 *bytes, u32 len)
{
    u8* limit = &bytes[len];
    u32 bits = 0;

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
        u8 c = *bytes;

        while((c & 0x80) != 0)
        {
            c <<= 1;
            bits++;
        }
    }

    return bits;
}

/**
 * Used to build the acl content
 *
 * [!] (ip [/prefix] | key key_id | "acl_name" | { address_match_list } )
 *
 * If acls is not null, the definitions will be expanded
 *
 */

static ya_result
acl_parse_address_match_list(address_match_list *aml, const char *description, ptr_vector *acls)
{
    OSDEBUG(termerr,  "acl_parse_address_match_list(%p, \"%s\", %p)\n", (void*)aml, STR(description), (void*)acls);

    if(description == NULL)
    {
        return 0; /* successfully parsed 0 descriptors */
    }

    zassert(aml != NULL && aml->items == NULL && aml->limit == NULL);

    const char *separator = description;
    ptr_vector list;
    u32 token_len;
    
    bool accept;
    char token[256];

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

        if(token_len > sizeof (token) - 1)
        {
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

        accept = TRUE;

        if(*word == '!')
        {
            accept = FALSE;
            word++;
            SKIP_WHSPACE(word);
        }

        char *next_word = word;

        SKIP_JUST_WORD(next_word);
        
        if(*next_word != '\0')
        {
            *next_word++ = '\0';
            SKIP_WHSPACE(next_word);
        }

        address_match_item *ami = NULL;
        //address_match_item *not_ami = NULL;

        if(strcasecmp(word, "key") == 0)
        {
            /* TSIG : key xxxxx; */

            ami = alloc_address_match_item();
            ami->match = (accept) ? amim_tsig : amim_tsig_not;
            word = next_word;
            SKIP_JUST_WORD(next_word);

            if(next_word - word > sizeof (token))
            {
                /* free(ami); */ /* pointless since the cleanup will not be fully done anyway (list) */
                return ACL_TOKEN_SIZE_ERROR;
            }

            /*
             * Check if the key is known
             */

            u8 dnsname[MAX_DOMAIN_LENGTH];

            ya_result dnsname_len = cstr_to_dnsname_with_check(dnsname,word);

            if(FAIL(dnsname_len))
            {
                return ACL_NAME_PARSE_ERROR;
            }

            tsig_item *key = tsig_get(dnsname);

            if(key == NULL)
            {
                /* free(ami); */ /* pointless since the cleanup will not be fully done anyway (list) */
                return ACL_UNKNOWN_TSIG_KEY;
            }

            ami->parameters.tsig.secret_size = key->mac_size;
            ami->parameters.tsig.name_size = dnsname_len;
            ami->parameters.tsig.mac_algorithm = key->mac_algorithm;
            memcpy(ami->parameters.tsig.secret, key->mac, key->mac_size);
            memcpy(ami->parameters.tsig.name, dnsname, dnsname_len);
        }
        else if(strcasecmp(word, "none") == 0)
        {
            /* Reject all */

            ami = alloc_address_match_item();
            ami->match = (accept) ? amim_none : amim_any;
        }
        else if(strcasecmp(word, "any") == 0)
        {
            /* Accept all */

            ami = alloc_address_match_item();
            ami->match = (accept) ? amim_any : amim_none;
        }
        else /* parse an ipv4 or ipv6, with or without an ipv4, ipv6 or sized bitmask */
        {
            u8 buffer[16];
            bool mask = FALSE;
            u32 bits = 0;

            int proto = -1;

            char *slash = word;
            while(*slash != '\0')
            {
                if(*slash == '/')
                {
                    *slash++ = '\0';
                    SKIP_WHSPACE(slash);
                    mask = TRUE;
                    break;
                }

                slash++;
            }

            if(inet_pton(AF_INET, word, buffer) == 1)
            {
                /* ipv4 */

                proto = AF_INET;

                ami = alloc_address_match_item();
                ami->match = (accept) ? amim_ipv4 : amim_ipv4_not;
                ami->parameters.ipv4.rejects = (accept) ? 0 : 1;

                memcpy(&ami->parameters.ipv4.address.bytes, buffer, 4);
                
                if(!mask)
                {
                    memset(&ami->parameters.ipv4.mask.bytes, 0xff, 4);
                    ami->parameters.ipv4.maskbits = 32;
                }
            }
            else if(inet_pton(AF_INET6, word, buffer) == 1)
            {
                /* ipv6 */

                proto = AF_INET6;

                ami = alloc_address_match_item();
                ami->match = (accept) ? amim_ipv6 : amim_ipv6_not;
                ami->parameters.ipv6.rejects = (accept) ? 0 : 1;

                memcpy(&ami->parameters.ipv6.address.bytes, buffer, 16);
                if(!mask)
                {
                    memset(&ami->parameters.ipv6.mask.bytes, 0xff, 16);
                    ami->parameters.ipv6.maskbits = 128;
                }
            }
            else
            {
                /* It could be a reference:  */

                if(!accept || mask) /* Cannot do a 'not' reference.
					 * Cannot get a '/' in a reference.
					 */
                {
                    return ACL_UNEXPECTED_NEGATION;
                }

                /*
                 * If the acls have already been (fully) defined:
                 * Look for 'word' in the acls and expand it.
                 * Add every ACL entry
                 */

                if(acls != NULL)
                {
                    ya_result expand;

                    if((expand = acl_expand_address_match_reference(&list, word, acls)) <= 0)
                    {
                        ptr_vector_destroy(&list);

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
                    ami = alloc_address_match_item();
                    ami->match = amim_reference;
                    ami->parameters.ref.name = strdup(word);
                    ami->parameters.ref.mark = FALSE;

                    OSDEBUG(termerr,  "acl_parse_address_match_list(%p, %s, %p) : adding %p (%s)\n",
                            (void*)aml, STR(description), (void*)acls, (void*)ami, word);

                    ptr_vector_append(&list, ami);
                }

                continue;
            }

            /*
             * If a raw value has been put in an "allow", then I have to keep track to delete it at shutdown
             */

            if(acls != NULL)
            {
                ptr_vector_append(&g_amim, ami);
            }

            if(mask)
            {
                word = slash;

                if(inet_pton(AF_INET, word, buffer) == 1)
                {
                    /* ipv4 */

                    if(proto != AF_INET)
                    {
                        /* free(ami); */ /* pointless since the cleanup will not be fully done anyway (list) */
                        return ACL_WRONG_V4_MASK;
                    }

                    ami->match = (accept) ? amim_ipv4 : amim_ipv4_not;

                    memcpy(&ami->parameters.ipv4.mask.bytes, buffer, 4);

                    ami->parameters.ipv4.maskbits = netmask_bit_count(ami->parameters.ipv4.mask.bytes, 4);
                }
                else if(inet_pton(AF_INET6, word, buffer) == 1)
                {
                    /* ipv6 */

                    if(proto != AF_INET6)
                    {
                        /* free(ami); */ /* pointless since the cleanup will not be fully done anyway (list) */
                        return ACL_WRONG_V6_MASK;
                    }

                    ami->match = (accept) ? amim_ipv6 : amim_ipv6_not;

                    memcpy(&ami->parameters.ipv6.mask.bytes, buffer, 16);

                    ami->parameters.ipv6.maskbits = netmask_bit_count(ami->parameters.ipv4.mask.bytes, 16);
                }
                else if(ISOK(parse_u32_check_range(word, &bits, 0, (proto == AF_INET) ? 32 : 128, 10)))
                {
                    ZEROMEMORY(buffer, sizeof (buffer));

                    u8 *b = buffer;
                    u8 maskbits = bits;

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
                }
                else
                {
                    /* free(ami); */ /* pointless since the cleanup will not be fully done anyway (list) */
                    return ACL_WRONG_MASK; /* Wrong mask */
                }
            }
        }

        zassert(ami != NULL);

        OSDEBUG(termerr,  "acl_parse_address_match_list(%p, %s, %p) : adding %p (---)\n",
                (void*)aml, STR(description), (void*)acls, (void*)ami);

        ptr_vector_append(&list, ami);

    } /* while there is something to parse */

    u32 count = list.offset + 1;

    if(count > 0)
    {
        ptr_vector_shrink(&list);

        OSDEBUG(termerr,  "acl_parse_address_match_list(%p, %s, %p) : items at %p\n",
                (void*)aml, STR(description), (void*)acls, (void*)list.data);

        aml->items = (address_match_item**)list.data;
        aml->limit = &aml->items[count];
    }
    else
    {
        ptr_vector_destroy(&list);
    }

    if(count > 1000)
    {
        return ACL_TOO_MUCH_TOKENS;
    }

    return count;
}

ya_result
acl_add_definition(const char* name, const char *description)
{
    OSDEBUG(termerr,  "acl_add_definition(%s, %s)\n", STR(name), STR(description));

    acl_entry *acl;
    ya_result return_code;

    s32 index = 0;
    while(index <= g_acl.offset)
    {
        acl = (acl_entry*)g_acl.data[index++];
        if(strcasecmp(acl->name, name) == 0)
        {
            return ACL_DUPLICATE_ENTRY;
        }
    }
    
    MALLOC_OR_DIE(acl_entry*, acl, sizeof (acl_entry), ACLENTRY_TAG);

    ZEROMEMORY(acl, sizeof (acl_entry));

    if(FAIL(return_code = acl_parse_address_match_list(&acl->list, description, NULL)))
    {
        free(acl);

        return return_code;
    }

    acl->name = strdup(name);

    OSDEBUG(termerr,  "acl_add_definition(%s @ %p, %s) list %p items %p\n", STR(name), (void*)acl, STR(description), (void*)&acl->list, (void*)acl->list.items);

    ptr_vector_append(&g_acl, acl);

    return SUCCESS;
}

static void
acl_free_address_match_item(void *ami_)
{
    address_match_item *ami = (address_match_item*)ami_;

    if(ami->match == amim_reference)
    {
        free((void*)ami->parameters.ref.name);
    }

    free(ami);
}

static void
acl_free_definition(void *def)
{
    OSDEBUG(termerr,  "acl_free_definition(%p)\n", def);

    acl_entry *entry = (acl_entry*)def;

    free((void*)entry->name);

    address_match_item** items = entry->list.items;
    address_match_item** limit = entry->list.limit;

    while(items < limit)
    {
        address_match_item* item = (*items++);

        acl_free_address_match_item(item);
    }

    OSDEBUG(termerr,  "acl_free_definition(%p) items: %p\n", def, (void*)entry->list.items);

    free(entry->list.items);

    free(entry);
}

void
acl_free_definitions()
{
    OSDEBUG(termerr,  "acl_free_definitions()\n");

    ptr_vector_free_empties(&g_amim, &acl_free_address_match_item);
    ptr_vector_destroy(&g_amim);

    ptr_vector_free_empties(&g_acl, &acl_free_definition);
    ptr_vector_destroy(&g_acl);
}

/**
 * Builds an access control using the text descriptors and the acl data.
 * Expands the access control.
 *
 */

ya_result
acl_build_access_control(access_control *ac,
                         const char *allow_query,
                         const char *allow_update,
                         const char *allow_update_forwarding,
                         const char *allow_transfer,
                         const char *allow_notify,
                         const char *allow_control)
{
    OSDEBUG(termerr,  "acl_build_access_control(%p, %s, %s ,%s, %s, %s)\n",
            (void*)ac, STR(allow_query), STR(allow_update), STR(allow_update_forwarding), STR(allow_transfer), STR(allow_notify), STR(allow_control));

    ya_result return_code;

    if(ISOK(return_code = acl_build_access_control_item(&ac->allow_query, allow_query)))
    {
        if(ISOK(return_code = acl_build_access_control_item(&ac->allow_update, allow_update)))
        {
            if(ISOK(return_code = acl_build_access_control_item(&ac->allow_update_forwarding, allow_update_forwarding)))
            {
                if(ISOK(return_code = acl_build_access_control_item(&ac->allow_transfer, allow_transfer)))
                {
                    if(ISOK(return_code = acl_build_access_control_item(&ac->allow_notify, allow_notify)))
                    {
                        return_code = acl_build_access_control_item(&ac->allow_control, allow_control);
                    }
                }
            }
        }
    }

    return return_code;
}

void
acl_emtpies_address_match_list(address_match_list *aml)
{
    OSDEBUG(termerr,  "acl_emtpies_address_match_list(%p) : %p\n", (void*)aml, (void*)aml->items);

#ifndef NDEBUG
    if(aml->items != NULL)
    {
        size_t n = (u8*)aml->limit - (u8*)aml->items;
        memset(aml->items, 0xff, n);
    }
#endif

    free(aml->items);

    aml->items = NULL;
    aml->limit = NULL;
}

void
acl_empties_address_match_set(address_match_set *ams)
{
#ifndef NDEBUG
    OSDEBUG(termerr, "acl_empties_address_match_set(%p)\n", (void*)ams);
#endif

    acl_emtpies_address_match_list(&ams->ipv4);
    acl_emtpies_address_match_list(&ams->ipv6);
    acl_emtpies_address_match_list(&ams->tsig);
}

void
acl_empties_access_control(access_control *ac)
{
    OSDEBUG(termerr, "acl_empties_access_control(%p)\n", (void*)ac);

    acl_empties_address_match_set(&ac->allow_notify);
    acl_empties_address_match_set(&ac->allow_query);
    acl_empties_address_match_set(&ac->allow_transfer);
    acl_empties_address_match_set(&ac->allow_update);
    acl_empties_address_match_set(&ac->allow_update_forwarding);
    acl_empties_address_match_set(&ac->allow_control);
}


void
acl_copy_address_match_list(address_match_list *target, address_match_list* aml)
{
    int n = aml->limit - aml->items;
    
    if(n > 0)
    {
        MALLOC_OR_DIE(address_match_item**, target->items, n * sizeof(address_match_item*), GENERIC_TYPE);
        target->limit = &target->items[n];
        
        for(int i = 0; i < n; i++)
        {
            target->items[i] = alloc_address_match_item();
            memcpy(target->items[i], aml->items[i], sizeof(address_match_item));
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

void
acl_copy_address_match_set(address_match_set *target, address_match_set *ams)
{
    acl_copy_address_match_list(&target->ipv4, &ams->ipv4);
    acl_copy_address_match_list(&target->ipv6, &ams->ipv6);
    acl_copy_address_match_list(&target->tsig, &ams->tsig);
}

void
acl_copy_access_control(access_control *target, access_control *ac)
{
    acl_copy_address_match_set(&target->allow_query, &ac->allow_query);
    acl_copy_address_match_set(&target->allow_update, &ac->allow_update);
    acl_copy_address_match_set(&target->allow_update_forwarding, &ac->allow_update_forwarding);
    acl_copy_address_match_set(&target->allow_transfer, &ac->allow_transfer);
    acl_copy_address_match_set(&target->allow_notify, &ac->allow_notify);
    acl_copy_address_match_set(&target->allow_control, &ac->allow_control);
}

ya_result
acl_build_access_control_item(address_match_set *ams, const char* allow_whatever)
{
#ifdef DEBUG
    OSDEBUG(termerr, "acl_build_access_control_item(%p, \"%s\")\n", ams, STR(allow_whatever));
    flusherr();
#endif
    
    ya_result return_code;

    address_match_list ami;
    ZEROMEMORY(&ami, sizeof (ami));

    if(ISOK(return_code = acl_parse_address_match_list(&ami, allow_whatever, &g_acl)))
    {
        if(ami.items == NULL)
        {
            /*
             * Empty set
             */
            
            return SUCCESS;
        }

        ptr_vector ipv4v = EMPTY_PTR_VECTOR;
        ptr_vector ipv6v = EMPTY_PTR_VECTOR;
        ptr_vector tsigv = EMPTY_PTR_VECTOR;

        address_match_item **itemp = ami.items;

        while(itemp < ami.limit)
        {
            address_match_item *item = *itemp;

            if(IS_IPV4_ITEM(item))
            {
                if(((item->parameters.ipv4.maskbits == 32) || (item->parameters.ipv4.maskbits == 0)) && (item->parameters.ipv4.address.value == 0) )
                {
                    /* A.K.A any/none IPv4 */
                    //             ^ | &
                    // A  0 => A 0 0 0 0
                    // A ~0 => R 0 1 1 0
                    // R  0 => R 1 0 1 0
                    // R ~0 => A 1 1 1 1
                    
                    //             REJECTS                                 NONE
                    bool rejects = (item->parameters.ipv4.rejects != 0);
                    bool none = (item->parameters.ipv4.maskbits != 0);
                    bool xored = (rejects || none) && !(rejects && none);
                    
                    //acl_free_address_match_item(item);
                    //item = alloc_address_match_item();
                    
                    item->match = (xored) ? amim_none : amim_any;
                }

                ptr_vector_append(&ipv4v, item);
            }
            else if(IS_IPV6_ITEM(item))
            {                
                if(((item->parameters.ipv6.maskbits == 128) || (item->parameters.ipv6.maskbits == 0)) && IPV6_ADDRESS_ALL0(item->parameters.ipv6.address))
                {
                    /* A.K.A any/none IPv6 */
                    
                    // A  0 => A
                    // A ~0 => R
                    // R  0 => R
                    // R ~0 => A
                    
                    //             REJECTS                                 NONE
                    bool rejects = (item->parameters.ipv6.rejects != 0);
                    bool none = (item->parameters.ipv6.maskbits != 0);
                    bool xored = (rejects || none) && !(rejects && none);
                    
                    //acl_free_address_match_item(item);
                    //item = alloc_address_match_item();
                    
                    item->match = (xored) ? amim_none : amim_any;
                }
                
                ptr_vector_append(&ipv6v, item);
            }
            else if(IS_TSIG_ITEM(item))
            {
                ptr_vector_append(&tsigv, item);
            }
            else /* any or none */
            {
                ptr_vector_append(&ipv4v, item);
                ptr_vector_append(&ipv6v, item);
                //ptr_vector_append(&tsigv, item);
            }

            itemp++;
        }

        ptr_vector_shrink(&ipv4v);
        ams->ipv4.items = (address_match_item**)ipv4v.data;
        ams->ipv4.limit = &ams->ipv4.items[ipv4v.offset + 1];
        
#if ACL_SORT_RULES != 0
        amim_ipv4_sort(&ipv4v);
#endif

#ifndef NDEBUG
        amim_ipv4_print(&ipv4v);
#endif

        ptr_vector_shrink(&ipv6v);
        ams->ipv6.items = (address_match_item**)ipv6v.data;
        ams->ipv6.limit = &ams->ipv6.items[ipv6v.offset + 1];
        
#if ACL_SORT_RULES != 0
        amim_ipv6_sort(&ipv6v);
#endif

#ifndef NDEBUG
        amim_ipv6_print(&ipv6v);
#endif

        ptr_vector_shrink(&tsigv);        
        ams->tsig.items = (address_match_item**)tsigv.data;
        ams->tsig.limit = &ams->tsig.items[tsigv.offset + 1];
        
#ifndef NDEBUG
        amim_tsig_print(&tsigv);
#endif
    }

    acl_emtpies_address_match_list(&ami);
    
#ifdef DEBUG
#if ACL_DEBUG_FULL != 0
    u32 t =  address_match_set_get_type(ams);
    OSDEBUG(termerr, "=> AMS type: %s (%2d)\n", query_access_filter_type_name[t], t);
    flusherr();
#endif
#endif

    return return_code;
}

// <editor-fold defaultstate="collapsed" desc="merge">

static void
acl_merge_address_match_set(address_match_set *dest, const address_match_set *src)
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

void
acl_merge_access_control(access_control *dest, const access_control *src)
{
    acl_merge_address_match_set(&dest->allow_notify, &src->allow_notify);
    acl_merge_address_match_set(&dest->allow_query, &src->allow_query);
    acl_merge_address_match_set(&dest->allow_transfer, &src->allow_transfer);
    acl_merge_address_match_set(&dest->allow_update, &src->allow_update);
    acl_merge_address_match_set(&dest->allow_update_forwarding, &src->allow_update_forwarding);
    acl_merge_address_match_set(&dest->allow_control, &src->allow_control);
}

static void
acl_unmerge_address_match_set(address_match_set *dest, const address_match_set *src)
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

void
acl_unmerge_access_control(access_control *dest, const access_control *src)
{
    acl_unmerge_address_match_set(&dest->allow_notify, &src->allow_notify);
    acl_unmerge_address_match_set(&dest->allow_query, &src->allow_query);
    acl_unmerge_address_match_set(&dest->allow_transfer, &src->allow_transfer);
    acl_unmerge_address_match_set(&dest->allow_update, &src->allow_update);
    acl_unmerge_address_match_set(&dest->allow_update_forwarding, &src->allow_update_forwarding);
    acl_unmerge_address_match_set(&dest->allow_control, &src->allow_control);
}// </editor-fold>

bool
acl_address_match_set_isempty(address_match_set *ams)
{
    return (ams->ipv4.items == NULL) && (ams->ipv6.items == NULL) && (ams->tsig.items == NULL);
}

static ya_result
acl_address_match_set_check_v4(address_match_set *set, struct sockaddr_in *ipv4)
{
    ya_result return_code = 0;

    address_match_item **itemp = (address_match_item**)set->ipv4.items;

    while(itemp < set->ipv4.limit)
    {
        address_match_item *item = *itemp++;

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

static ya_result
acl_address_match_set_check_v6(address_match_set *set, struct sockaddr_in6 *ipv6)
{
    ya_result return_code = 0;

    address_match_item **itemp = (address_match_item**)set->ipv6.items;

    while(itemp < set->ipv6.limit)
    {
        address_match_item *item = *itemp++;

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

static ya_result
acl_address_match_set_check_tsig(address_match_set *set, void *message_with_tsig)
{
    ya_result return_code = 0;

    address_match_item **itemp = (address_match_item**)set->tsig.items;

    while(itemp < set->tsig.limit)
    {
        address_match_item *item = *itemp++;

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

static inline ya_result
acl_check_access_filter_RRI(message_data *mesg, address_match_set *ams)
{
    return AMIM_REJECT;
}

static inline ya_result
acl_check_access_filter_ARI(message_data *mesg, address_match_set *ams)
{
    return (mesg->other.sa.sa_family == AF_INET)?AMIM_ACCEPT:AMIM_REJECT;
}

static inline ya_result
acl_check_access_filter_4RI(message_data *mesg, address_match_set *ams)
{
    if(mesg->other.sa.sa_family == AF_INET)
    {
        return acl_address_match_set_check_v4(ams, &mesg->other.sa4) - 1; /* -1 to transform ignore to reject */
    }
    
    return AMIM_REJECT;
}

// RAI AAI 4AI

static inline ya_result
acl_check_access_filter_RAI(message_data *mesg, address_match_set *ams)
{
    return (mesg->other.sa.sa_family == AF_INET6)?AMIM_ACCEPT:AMIM_REJECT;
}

static ya_result
acl_check_access_filter_AAI(message_data *mesg, address_match_set *ams)
{
    return AMIM_ACCEPT;
}

static inline ya_result
acl_check_access_filter_4AI(message_data *mesg, address_match_set *ams)
{
    if(mesg->other.sa.sa_family == AF_INET)
    {
        return acl_address_match_set_check_v4(ams, &mesg->other.sa4) - 1;
    }
    else
    {
        return AMIM_ACCEPT;
    }
}

// R6I A6I 46I

static inline ya_result
acl_check_access_filter_R6I(message_data *mesg, address_match_set *ams)
{
    if(mesg->other.sa.sa_family == AF_INET6)
    {
        return acl_address_match_set_check_v6(ams, &mesg->other.sa6) -1;
    }
    
    return AMIM_REJECT;
}

static inline ya_result
acl_check_access_filter_A6I(message_data *mesg, address_match_set *ams)
{
    if(mesg->other.sa.sa_family == AF_INET6)
    {
        return acl_address_match_set_check_v6(ams, &mesg->other.sa6) - 1;
    }
    else
    {
        return AMIM_ACCEPT;
    }
}

static inline ya_result
acl_check_access_filter_46I(message_data *mesg, address_match_set *ams)
{
    if(mesg->other.sa.sa_family == AF_INET)
    {
        return acl_address_match_set_check_v4(ams, &mesg->other.sa4) - 1;
    }
    else
    if(mesg->other.sa.sa_family == AF_INET6)
    {
        return acl_address_match_set_check_v6(ams, &mesg->other.sa6) - 1;
    }
    
    return AMIM_REJECT;
}

// TSIG

// RRT ART 4RT

static inline ya_result
acl_check_access_filter_RRT(message_data *mesg, address_match_set *ams)
{
    return AMIM_REJECT;
}

static inline ya_result
acl_check_access_filter_ART(message_data *mesg, address_match_set *ams)
{
    if((mesg->ar_start != NULL) && (mesg->other.sa.sa_family == AF_INET))
    {
        return acl_address_match_set_check_tsig(ams, mesg) - 1;
    }
    
    return AMIM_REJECT;
}

static inline ya_result
acl_check_access_filter_4RT(message_data *mesg, address_match_set *ams)
{
    if((mesg->ar_start != NULL) && (mesg->other.sa.sa_family == AF_INET))
    {
        if(!ACL_REJECTED(acl_address_match_set_check_v4(ams, &mesg->other.sa4)))
        {
            return acl_address_match_set_check_tsig(ams, mesg) - 1;
        }
    }

    return AMIM_REJECT;
}

// RAT AAT 4AT

static inline ya_result
acl_check_access_filter_RAT(message_data *mesg, address_match_set *ams)
{
    if((mesg->ar_start != NULL) && (mesg->other.sa.sa_family == AF_INET6))
    {
        return acl_address_match_set_check_tsig(ams, mesg) - 1;
    }
    
    return AMIM_REJECT;
}

static inline ya_result
acl_check_access_filter_AAT(message_data *mesg, address_match_set *ams)
{
    if(mesg->ar_start != NULL)
    {
        return acl_address_match_set_check_tsig(ams, mesg) - 1;
    }
    
    return AMIM_REJECT;
}

static inline ya_result
acl_check_access_filter_4AT(message_data *mesg, address_match_set *ams)
{
    if(mesg->ar_start != NULL)
    {
        if(mesg->other.sa.sa_family == AF_INET)
        {
            if(ACL_REJECTED(acl_address_match_set_check_v4(ams, &mesg->other.sa4)))
            {
                return AMIM_REJECT;
            }
        }
    
        return acl_address_match_set_check_tsig(ams, mesg) - 1;
    }
    
    return AMIM_REJECT;
}

// R6T A6T 46T

static inline ya_result
acl_check_access_filter_R6T(message_data *mesg, address_match_set *ams)
{
    if(mesg->ar_start != NULL)
    {
        if(mesg->other.sa.sa_family == AF_INET6)
        {
            if(!ACL_REJECTED(acl_address_match_set_check_v6(ams, &mesg->other.sa6)))
            {

                    return acl_address_match_set_check_tsig(ams, mesg) - 1;
            }
        }
    }
    
    return AMIM_REJECT;
}

static inline ya_result
acl_check_access_filter_A6T(message_data *mesg, address_match_set *ams)
{
    if(mesg->ar_start != NULL)
    {
        if(mesg->other.sa.sa_family == AF_INET6)
        {
            if(ACL_REJECTED(acl_address_match_set_check_v6(ams, &mesg->other.sa6)))
            {
                return AMIM_REJECT;
            }
        }
    
        return acl_address_match_set_check_tsig(ams, mesg) - 1;
    }
        
    return AMIM_REJECT;
}

static inline ya_result
acl_check_access_filter_46T(message_data *mesg, address_match_set *ams)
{
    if(mesg->ar_start != NULL)
    {
        if(mesg->other.sa.sa_family == AF_INET)
        {
            if(ACL_REJECTED(acl_address_match_set_check_v4(ams, &mesg->other.sa4)))
            {
                return AMIM_REJECT;
            }
        }
        else
        if(mesg->other.sa.sa_family == AF_INET6)
        {
            if(ACL_REJECTED(acl_address_match_set_check_v6(ams, &mesg->other.sa6)))
            {
                return AMIM_REJECT;
            }
        }

        return acl_address_match_set_check_tsig(ams, mesg) - 1;
    }

    return AMIM_REJECT;
}

ya_result
acl_check_access_filter(message_data *mesg, address_match_set *ams)
{
    ya_result return_code = AMIM_SKIP;
    
    /*
     * If there the client is on IPvX and IPvX has rules, the default is set to REJECT
     * then the client's address is compared to all the items in the list, returning on a match.
     */
    
    if(mesg->other.sa.sa_family == AF_INET)
    {
        if(ams->ipv4.items != NULL)
        {
            if(ACL_REJECTED(return_code = acl_address_match_set_check_v4(ams, &mesg->other.sa4)))
            {
                return return_code;
            }
        }
    }
    else
    if(mesg->other.sa.sa_family == AF_INET6)
    {
        if(ams->ipv6.items != NULL)
        {
            if(ACL_REJECTED(return_code = acl_address_match_set_check_v6(ams, &mesg->other.sa6)))
            {
                return return_code;
            }
        }
    }
#ifdef DEBUG
    else
    {
        log_err("acl: unsupported address family %d", mesg->other.sa.sa_family);

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
        if(mesg->ar_start != NULL)
        {
            return_code += acl_address_match_set_check_tsig(ams, mesg);
        }
        else
        {
            return_code = AMIM_REJECT;
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

static acl_check_access_filter_callback* access_filter_by_type[18]=
{
 CAF(RRI),  CAF(ARI),  CAF(4RI), 
 CAF(RAI),  CAF(AAI),  CAF(4AI), 
 CAF(R6I),  CAF(A6I),  CAF(46I), 
 CAF(RRT),  CAF(ART),  CAF(4RT), 
 CAF(RAT),  CAF(AAT),  CAF(4AT), 
 CAF(R6T),  CAF(A6T),  CAF(46T)
};

#undef CAF

acl_check_access_filter_callback *
acl_get_check_access_filter(address_match_set *set)
{
    acl_check_access_filter_callback* cb;

    u32 t = address_match_set_get_type(set);
    
    cb = access_filter_by_type[t];

    return cb;
}

/********************************************************************************************************************************/


// <editor-fold defaultstate="collapsed" desc="query access">

/**
 * This macro is a template for the hook function from the allow_query input to the generic input
 * The only hooks that are not using it are the most simple ones (returning ACCEPT or REJECT) 
 */

#define CAF_HOOK(x) static inline ya_result acl_query_access_filter_##x(message_data *mesg, void *extension) \
{ \
    access_control *ac = (access_control*)extension; \
    return acl_check_access_filter_##x(mesg, &ac->allow_query); \
}

static ya_result
acl_query_access_filter_AAI(message_data *mesg, void *extension)
{
    return AMIM_ACCEPT;
}

static ya_result
acl_query_access_filter_RRI(message_data *mesg, void *extension)
{
    return AMIM_REJECT;
}

static ya_result
acl_query_access_filter_RRT(message_data *mesg, void *extension)
{
    return AMIM_REJECT;
}

//CAF_HOOK(RRI)
CAF_HOOK(ARI)
CAF_HOOK(4RI)

CAF_HOOK(RAI)
//CAF_HOOK(AAI)
CAF_HOOK(4AI)

CAF_HOOK(R6I)
CAF_HOOK(A6I)
CAF_HOOK(46I)

//CAF_HOOK(RRT)
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

static acl_query_access_filter_callback* query_access_filter_by_type[18]=
{
 QAF(RRI),  QAF(ARI),  QAF(4RI), 
 QAF(RAI),  QAF(AAI),  QAF(4AI), 
 QAF(R6I),  QAF(A6I),  QAF(46I), 
 QAF(RRT),  QAF(ART),  QAF(4RT), 
 QAF(RAT),  QAF(AAT),  QAF(4AT), 
 QAF(R6T),  QAF(A6T),  QAF(46T)
};

#undef QAF


acl_query_access_filter_callback *
acl_get_query_access_filter(address_match_set *set)
{
    acl_query_access_filter_callback* cb;
        
    u32 t = address_match_set_get_type(set);

    cb = query_access_filter_by_type[t];

    return cb;
}

ya_result
acl_address_match_item_to_stream(output_stream *os, address_match_item *ami)
{
    ya_result return_code;
    
    if(ami == NULL)
    {
        return 0;
    }
    else if(IS_IPV4_ITEM(ami))
    {
        s8 b = ami->parameters.ipv4.maskbits;
        //s8 r = ami->parameters.ipv4.rejects;
        
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
        s16 b = ami->parameters.ipv6.maskbits;
        //s8 r = ami->parameters.ipv6.rejects;
        
        struct sockaddr_in6 ipv6;
        memcpy((u8*)&ipv6.sin6_addr, ami->parameters.ipv6.address.bytes, 16);
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
    else if(IS_TSIG_ITEM(ami))
    {
        if(IS_TSIG_ITEM_MATCH(ami))
        {
            return_code = osformat(os, "key %{dnsname}", ami->parameters.tsig.name);
        }
        else
        {
            return_code = osformat(os, "! key %{dnsname}", ami->parameters.tsig.name);
        }
    }
    else if(IS_ANY_ITEM(ami))
    {
        if(IS_ANY_ITEM_MATCH(ami))
        {/*
            return_code = osformat(os, "any");
            
            if(ISOK(return_code))
            {
                return 1;
            }*/
            
            return 1;
        }
        else
        {
            /*
            return_code = osformat(os, "none");
            
            if(ISOK(return_code))
            {
                return 2;
            }*/
            
            return 2;
        }
    }
    else
    {
        return_code = osformat(os, "?");
    }
    
    if(ISOK(return_code))
    {
        return_code = 0;
    }

    return return_code;
}

void
acl_address_match_set_to_stream(output_stream *os, address_match_set *ams)
{
    address_match_item **item;
    address_match_item **limit;
    ya_result any_none = 0;
    ya_result return_code;    
    char spc;
    
    item = ams->ipv4.items;
    limit = ams->ipv4.limit;    
    spc = ' ';
    
    while(item < limit)
    {
        output_stream_write_u8(os, (u8)spc);
        return_code = acl_address_match_item_to_stream(os, *item);
        
        if(return_code > 0)
        {
            any_none |= return_code;
            break;
        }
        
        spc = ',';
        item++;
    }

    item = ams->ipv6.items;
    limit = ams->ipv6.limit;    
    
    while(item < limit)
    {
        output_stream_write_u8(os, (u8)spc);
        
        return_code = acl_address_match_item_to_stream(os, *item);
        
        if(return_code > 0)
        {
            any_none |= return_code;
            break;
        }
        
        spc = ',';
        item++;
    }
    
    item = ams->tsig.items;
    limit = ams->tsig.limit;    
    
    while(item < limit)
    {
        output_stream_write_u8(os, (u8)spc);
        return_code = acl_address_match_item_to_stream(os, *item);
        
        if(return_code > 0)
        {
            any_none |= return_code;
            break;
        }
        
        spc = ',';
        item++;
    }
    
    if(any_none != 0)
    {
        if(any_none & 1)
        {
            osformat(os, "%cany", spc);
            spc = ',';
        }
        if(any_none & 2)
        {
            osformat(os, "%cnone", spc);
        }
    }
}

ya_result
acl_address_match_item_to_string(address_match_item *ami, char *out_txt, u32 *out_txt_lenp)
{
    ya_result return_code;
    
    u32 out_txt_len = *out_txt_lenp;
    
    if(ami == NULL)
    {
        return_code = snformat(out_txt, out_txt_len, "NULL->REJECT");
    }
    else if(IS_IPV4_ITEM(ami))
    {
        s8 b = ami->parameters.ipv4.maskbits;
        //s8 r = ami->parameters.ipv4.rejects;
        
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
        s16 b = ami->parameters.ipv6.maskbits;
        //s8 r = ami->parameters.ipv6.rejects;
        
        struct sockaddr_in6 ipv6;
        memcpy((u8*)&ipv6.sin6_addr, ami->parameters.ipv6.address.bytes, 16);
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
        *out_txt_lenp = return_code;
    }
    
    return return_code;
}

/** @} */
