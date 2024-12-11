/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

#ifndef _ACL_H
#define _ACL_H

#include <dnscore/ptr_vector.h>
#include <dnscore/dns_message.h>
#include <dnscore/host_address.h>
#include <dnscore/config_settings.h>
#include <dnscore/ptr_treemap.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define ACL_ERROR_BASE          0x80060000
#define ACL_ERROR_CODE(code_)   ((int32_t)(ACL_ERROR_BASE + (code_)))

#define ACL_TOKEN_SIZE_ERROR    ACL_ERROR_CODE(1)
#define ACL_UNEXPECTED_NEGATION ACL_ERROR_CODE(2)
#define ACL_WRONG_V4_MASK       ACL_ERROR_CODE(3)
#define ACL_WRONG_V6_MASK       ACL_ERROR_CODE(4)
#define ACL_WRONG_MASK          ACL_ERROR_CODE(5)
#define ACL_DUPLICATE_ENTRY     ACL_ERROR_CODE(6)
#define ACL_RESERVED_KEYWORD    ACL_ERROR_CODE(7)
#define ACL_TOO_MANY_TOKENS     ACL_ERROR_CODE(8)
#define ACL_UNDEFINED_TOKEN     ACL_ERROR_CODE(9)

#define ACL_UPDATE_REJECTED     ACL_ERROR_CODE(104)
#define ACL_NOTIFY_REJECTED     ACL_ERROR_CODE(105)

#define ACL_NAME_PARSE_ERROR    ACL_ERROR_CODE(201)
#define ACL_UNKNOWN_TSIG_KEY    ACL_ERROR_CODE(202)

/* acl can be identified by
 * ipv4 (accept/reject)
 * ipv6 (accept/reject)
 * TSIG (accept only)
 * => 3 distinct entry points
 * Tests will be done first on IP (if any, and by version) then on TSIG (if any)
 *
 */

struct ipv4_id_s
{
    addressv4 address;
    addressv4 mask;
    int8_t    maskbits; // needs to be signed
    int8_t    rejects;
} PACKED_STRUCTURE_ATTRIBUTE;

typedef struct ipv4_id_s ipv4_id_t;

struct ipv6_id_s
{
    addressv6 address;
    addressv6 mask;
    int16_t   maskbits; // needs to be signed
    int8_t    rejects;
} PACKED_STRUCTURE_ATTRIBUTE;

typedef struct ipv6_id_s ipv6_id_t;

#define TSIG_SECRET_SIZE_MAX 32

struct tsig_id_s
{
    uint8_t  secret_size;
    uint8_t  name_size;
    uint8_t  mac_algorithm;
    uint8_t  reserved;
    uint8_t *known;
    uint8_t *name;
};

typedef struct tsig_id_s tsig_id_t;

struct ref_id_s
{
    const char *name;
    bool        mark;
};

typedef struct ref_id_s ref_id_t;

/*
 * I've chosen these values to avoid some tests
 *
 * Basically, there are 2 tests for ACL: IP & TSIG
 *
 * First IP, then, if available in the message, TSIG
 *
 * IP will trigger a return in case of reject, but else will worth 0 or -2
 * Then TSIG, if available, will worth -2,0,+2
 * What we want is:
 *      IAIAIA
 *      RRIIAA
 * =>   RRRAAA
 *
 * With these values we can simply sum instead of doing tests
 *      0 +2  0 +2  0 +2
 *  +  -4 -4  0  0 +2 +2
 *  =  -4 -2  0 +2 +2 +4
 * then remove 1
 *  =  -3 -1 -1 +1 +1 +3
 *  =>  R  R  R  A  A  A
 *
 */

#define AMIM_ACCEPT                 2
#define AMIM_SKIP                   0
#define AMIM_REJECT                 (-4) // Reject has much more weight, and in theory -2 should be enough ( 1 IPV4/6, 1 TSIG )

#define ACL_SORT_RULES              0
#define ACL_MERGE_RULES             0
#define ACL_DEFAULT_RULE            AMIM_REJECT

#define ACL_REJECTED(__amim_code__) ((__amim_code__) < 0)
#define ACL_ACCEPTED(__amim_code__) ((__amim_code__) > 0)
#define ACL_IGNORED(__amim_code__)  ((__amim_code__) == 0)

/**
 *  Returns:
 *	    > 0 : Accept: matched and accepted
 *      < 0 : Reject: matched and rejected
 *      = 0 : Skip  : not matched
 */

struct address_match_item_s;

typedef int address_match_item_matcher(const struct address_match_item_s *, const void *);

/* Rules like the ones in the ACL named rules set */

struct address_match_item_s
{
    address_match_item_matcher *match;
    union
    {
        ipv4_id_t ipv4;
        ipv6_id_t ipv6;
        tsig_id_t tsig;
        ref_id_t  ref;
    } parameters;

    int32_t _rc;
};

typedef struct address_match_item_s address_match_item_t;

#define ADDRESS_MATCH_LIST_INITIALIZER {NULL, NULL}

struct address_match_list_s
{
    address_match_item_t **items;
    address_match_item_t **limit; /* Address limit of the items ( p = items; while(p<items) {process(p);} ) */
};

typedef struct address_match_list_s address_match_list_t;

struct acl_entry_s
{
    address_match_list_t list;
    const char          *name;
}; // +RC?

typedef struct acl_entry_s acl_entry_t;

#define ADDRESS_MATCH_SET_INITIALIZER {ADDRESS_MATCH_LIST_INITIALIZER, ADDRESS_MATCH_LIST_INITIALIZER, ADDRESS_MATCH_LIST_INITIALIZER}

struct address_match_set_s
{
    address_match_list_t ipv4;
    address_match_list_t ipv6;
    address_match_list_t tsig;
};

typedef struct address_match_set_s address_match_set_t;

struct access_control_s /* NULL if the list is empty */
{
    address_match_set_t      allow_query;
    address_match_set_t      allow_update;
    address_match_set_t      allow_update_forwarding;
    address_match_set_t      allow_transfer;
    address_match_set_t      allow_notify;
    address_match_set_t      allow_control;
    struct access_control_s *based_on;
    int                      _rc;
};

typedef struct access_control_s access_control_t;

/* Add one line into the acl */
ya_result         acl_definition_add(const char *name, const char *description);

void              acl_definitions_free();

access_control_t *acl_access_control_new_instance();

/**
 * Builds an access control using the text descriptors and the acl data.
 * Expands the access control.
 *
 */

ya_result acl_access_control_init_from_text(access_control_t *ac, const char *allow_query, const char *allow_update, const char *allow_update_forwarding, const char *allow_transfer, const char *allow_notify, const char *allow_control);

/**
 * Clears the memory used by an access control.
 */

void acl_access_control_clear(access_control_t *ac);

/**
 * Copy a match set.
 * The destination must not be initialised.
 */

void acl_address_match_set_copy(address_match_set_t *target, const address_match_set_t *ams);

/**
 * Copies an access control.
 * The destination must not be initialised.
 *
 * @param target will receive the copy
 * @param ac the original
 */

void acl_access_control_copy(access_control_t *target, const access_control_t *ac);

/**
 * Increments the reference count of the access control.
 */

void acl_access_control_acquire(access_control_t *ac);

/**
 * Decrements the reference count of the access control.
 * Destroys it if reference count reaches zero.
 */

bool acl_access_control_release(access_control_t *ac);

/**
 * Initialises an ACL match set (IPv4, IPv6, keys) from a text line.
 *
 * @param ams the ACL match set
 * @param allow_whatever the text description of the ACL match set
 *
 * @return an error code
 */

ya_result         acl_access_control_item_init_from_text(address_match_set_t *aci, const char *allow_whatever);

void              acl_merge_access_control(access_control_t *dest, access_control_t *src);

void              acl_unmerge_access_control(access_control_t *dest);

void              acl_address_match_set_clear(address_match_set_t *ams);

bool              acl_address_match_set_isempty(const address_match_set_t *ams);

typedef ya_result acl_check_access_filter_callback(const dns_message_t *mesg, const address_match_set_t *ams);

typedef ya_result acl_query_access_filter_callback(const dns_message_t *mesg, const void *extension);

/**
 * Checks if the message is accepted (> 0), rejected (< 0) or ignored (==0)
 *
 * @param mesg the message
 * @param ams the access match set to check the message against.
 *
 * @return return an amim code, use with: ACL_ACCEPTED(amim), ACL_REJECTED(amim), ACL_IGNORED(amim)
 */

ya_result acl_check_access_filter(const dns_message_t *mesg, const address_match_set_t *ams);

/*
 * Returns the filter appropriate for processing the set
 */

/**
 * Returns the check access filter callback for an addres match set
 *
 * @return the callback
 */

acl_check_access_filter_callback *acl_get_check_access_filter(const address_match_set_t *set);

/**
 * Returns the query check access filter callback for an addres match set
 *
 * @return the callback
 */

acl_query_access_filter_callback *acl_get_query_access_filter(const address_match_set_t *set);

ya_result                         acl_address_match_item_to_stream(output_stream_t *os, const address_match_item_t *ami);
ya_result                         acl_address_match_item_to_string(const address_match_item_t *ami, char *out_txt, uint32_t *out_txt_lenp);

void                              acl_address_match_set_to_stream(output_stream_t *os, const address_match_set_t *ams);

/**
 * Compares two address_match_item_t
 * @param a first item
 * @param b second item
 * @return 0: equals <0: a<b >0: a>b
 *
 */

int  acl_address_match_item_compare(const address_match_item_t *a, const address_match_item_t *b);

bool acl_address_match_item_equals(const address_match_item_t *a, const address_match_item_t *b);
bool acl_address_match_list_equals(const address_match_list_t *a, const address_match_list_t *b);
bool acl_address_match_set_equals(const address_match_set_t *a, const address_match_set_t *b);
bool acl_address_control_equals(const access_control_t *a, const access_control_t *b);

/**
 * Returns the number of registered acl entries.
 *
 * @return the count
 */

uint32_t acl_entry_count();

/**
 * Initialises an iterator on the acl entries.
 * Values are of type acl_entry_t*
 */

void      acl_entry_iterator_init(ptr_treemap_iterator_t *iter);
void      acl_match_item_print(const struct address_match_item_s *item, output_stream_t *os);
ya_result acl_match_items_print(address_match_item_t *const *address, address_match_item_t *const *limit, output_stream_t *os);

/**
 * Registers all ACL errors.
 */

void acl_register_errors();

/**
 * Returns a name associated to a matcher.  Mostly for debugging purpose.
 */

const char *acl_get_matcher_name(address_match_item_matcher *matcher);

/**
 * Returns the index of a filter callback.  Mostly for debugging purpose.
 * @return [0;17]
 */

int acl_get_check_access_filter_index(acl_check_access_filter_callback *callback);

/**
 * Returns the index of a filter callback.  Mostly for debugging purpose.
 * @return [0;17]
 */

const char *acl_get_check_access_filter_name(acl_check_access_filter_callback *callback);

#ifdef __cplusplus
}
#endif

#endif /* _ACL_H */

/** @} */
