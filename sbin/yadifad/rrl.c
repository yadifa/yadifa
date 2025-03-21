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
 * @defgroup
 * @ingroup yadifad
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "server_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>

#include <dnscore/random.h>
#include <dnscore/rfc.h>
#include <dnscore/logger.h>
#include <dnscore/format.h>
#include <dnscore/mutex.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/config_settings.h>

#include "rrl.h"
#include "confs.h"
#include <dnscore/acl.h>
#include <dnscore/acl_config.h>

#include <dnsdb/zdb_query_to_wire.h>

extern logger_handle_t *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#define EPOCH_PRECISION   6

#define ONE_SECOND_TICKS  (1 << EPOCH_PRECISION)

#define RRLITEM_TAG       0x4d4554494c5252

struct rrl_settings_s
{
    uint32_t                          responses_per_second; // 5
    uint32_t                          errors_per_second;    // 5

    uint32_t                          window; // 15
    uint32_t                          slip;   // 2

    int32_t                           max_table_size; // 10000
    int32_t                           min_table_size; // 1000
    uint32_t                          window_ticks;

    address_match_set_t               exempted;

    acl_check_access_filter_callback *exempted_filter;
    uint64_t                          ipv6_prefix_mask_high;
    uint64_t                          ipv6_prefix_mask_low;
    uint32_t                          ipv4_prefix_mask;
    int32_t                           drop_default;       // RRL_DROP except in log_only where it is RRL_PROCEED_DROP
    uint8_t                           ipv4_prefix_length; // 24
    uint8_t                           ipv6_prefix_length; //
    bool                              log_only;           // false
    bool                              enabled;
};

typedef struct rrl_settings_s rrl_settings_s;

#define CONFIG_TYPE rrl_settings_s
#include <dnscore/acl.h>
CONFIG_BEGIN(config_rrl_desc)
CONFIG_U32(responses_per_second, TOSTRING(RRL_RESPONSES_PER_SECOND_DEFAULT))
CONFIG_U32(errors_per_second, TOSTRING(RRL_ERRORS_PER_SECOND_DEFAULT))
CONFIG_U32(window, TOSTRING(RRL_WINDOW_DEFAULT))
CONFIG_U32(slip, TOSTRING(RRL_SLIP_DEFAULT))
CONFIG_U32(max_table_size, TOSTRING(RRL_QUEUE_SIZE_MAX_DEFAULT))
CONFIG_U32(min_table_size, TOSTRING(RRL_QUEUE_SIZE_MIN_DEFAULT))
CONFIG_U8(ipv4_prefix_length, TOSTRING(RRL_IPV4_PREFIX_LENGTH_DEFAULT))
CONFIG_U8(ipv6_prefix_length, TOSTRING(RRL_IPV6_PREFIX_LENGTH_DEFAULT))
CONFIG_BOOL(log_only, TOSTRING(RRL_LOG_ONLY_DEFAULT))
CONFIG_BOOL(enabled, TOSTRING(RRL_ENABLED_DEFAULT))
CONFIG_ACL_FILTER(exempted, RRL_EXEMPTED_DEFAULT)
/* alias, aliased */
CONFIG_ALIAS(exempt - clients, exempted)
CONFIG_ALIAS(enable, enabled)
CONFIG_END(config_rrl_desc)
#undef CONFIG_TYPE

static mutex_t               rrl_mtx;
static random_ctx_t          g_rrl_rnd;
static struct rrl_settings_s g_rrl_settings;
static ptr_vector_t          g_rrl_list = PTR_VECTOR_EMPTY;
static uint64_t              g_rrl_start = 0;
static uint32_t              g_rrl_slip_bucket = 0;
static int8_t                g_rrl_slip_bucket_bits = 0;

static ya_result             config_rrl_section_postprocess(struct config_section_descriptor_s *csd, config_error_t *cfgerr)
{
    (void)csd;
    (void)cfgerr;

    g_rrl_settings.window_ticks = g_rrl_settings.window * ONE_SECOND_TICKS;

    g_rrl_settings.exempted_filter = acl_get_check_access_filter(&g_rrl_settings.exempted);

    if(g_rrl_settings.ipv4_prefix_length == 0)
    {
        log_warn("ipv4-prefix-length set to 0, setting to recommended value: " TOSTRING(RRL_IPV4_PREFIX_LENGTH_DEFAULT));
        g_rrl_settings.ipv4_prefix_length = RRL_IPV4_PREFIX_LENGTH_DEFAULT;
    }

    if(g_rrl_settings.ipv4_prefix_length < 32)
    {
        uint32_t mask = U32_MAX << (32 - g_rrl_settings.ipv4_prefix_length);
        g_rrl_settings.ipv4_prefix_mask = htonl(mask);
    }
    else
    {
        log_warn("ipv4-prefix-length is wrong, setting to 32");
        g_rrl_settings.ipv4_prefix_length = 32;
        g_rrl_settings.ipv4_prefix_mask = U32_MAX;
    }

    uint64_t mask_h, mask_l;

    if(g_rrl_settings.ipv6_prefix_length == 0)
    {
        log_warn("ipv6-prefix-length set to 0, setting to recommended value: " TOSTRING(RRL_IPV6_PREFIX_LENGTH_DEFAULT));
        g_rrl_settings.ipv6_prefix_length = RRL_IPV6_PREFIX_LENGTH_DEFAULT;
    }

    if(g_rrl_settings.ipv6_prefix_length < 128) // [1;127]
    {
        if(g_rrl_settings.ipv6_prefix_length <= 64) // [1;64]
        {
            mask_h = U64_MAX << (64 - g_rrl_settings.ipv6_prefix_length); // shift [63; 0]
            mask_l = 0;
        }
        else // [65;127]
        {
            mask_h = U64_MAX;
            mask_l = U64_MAX << (128 - g_rrl_settings.ipv6_prefix_length); // shift [63; 1]
        }
    }
    else
    {
        log_warn("ipv6-prefix-length is wrong, setting to 128");

        g_rrl_settings.ipv6_prefix_length = 128;
        mask_h = U64_MAX;
        mask_l = U64_MAX;
    }

    g_rrl_settings.ipv6_prefix_mask_high = htobe64(mask_h);
    g_rrl_settings.ipv6_prefix_mask_low = htobe64(mask_l);

    if(g_rrl_settings.min_table_size < RRL_QUEUE_SIZE_MIN)
    {
        log_warn("min-table-size too low, set to %d", g_rrl_settings.min_table_size = RRL_QUEUE_SIZE_MIN);
    }
    else if(g_rrl_settings.min_table_size > RRL_QUEUE_SIZE_MAX)
    {
        log_warn("min-table-size too high, set to %d", g_rrl_settings.min_table_size = RRL_QUEUE_SIZE_MAX);
    }

    if(g_rrl_settings.max_table_size < RRL_QUEUE_SIZE_MIN)
    {
        log_warn("max-table-size too low, set to %d", g_rrl_settings.max_table_size = RRL_QUEUE_SIZE_MIN);
    }
    else if(g_rrl_settings.max_table_size > RRL_QUEUE_SIZE_MAX)
    {
        log_warn("max-table-size too high, set to %d", g_rrl_settings.max_table_size = RRL_QUEUE_SIZE_MAX);
    }

    if(g_rrl_settings.min_table_size > g_rrl_settings.max_table_size)
    {
        log_warn("min-table-size > max-table-size (%d > %d) setting min-table-size to %d instead", g_rrl_settings.min_table_size, g_rrl_settings.max_table_size, g_rrl_settings.max_table_size);
        g_rrl_settings.min_table_size = g_rrl_settings.max_table_size;
    }

    ptr_vector_resize(&g_rrl_list, g_rrl_settings.min_table_size);

    g_rrl_settings.drop_default = (g_rrl_settings.log_only) ? RRL_PROCEED_DROP : RRL_DROP;

    return SUCCESS;
}

ya_result config_register_rrl(int32_t priority)
{

    const char *section_name = "rrl";

    ya_result   return_code = config_register_struct(section_name, config_rrl_desc, &g_rrl_settings, priority);
    if(ISOK(return_code))
    {
        // hook a new finaliser before the standard one

        config_section_descriptor_t      *section_desc = config_section_get_descriptor(section_name);
        config_section_descriptor_vtbl_s *vtbl = (config_section_descriptor_vtbl_s *)section_desc->vtbl;
        vtbl->postprocess = config_rrl_section_postprocess;
    }

    return return_code;
}

/*
 * The item will be dynamic in size
 * the key being error_mask_ip_imputed_name, crafter every time for a (fast) memcmp comparison
 * The key should be a multiple of 8 bytes, padded with 0 (faster memcmp)
 *
 * The epoch should cover enough time.
 * It should have an imprecision lower than the second.
 * We can have it covering only a few minutes (8: 25.5, 16: 655.35, ...)
 * There is 32 bits available for a fast structure so I plan to simply use an epoch based on the start-time of the
 * server. The (currentTime - serverStartTime) >> 4 would give an acceptable precision (1/16 of a second) and cover
 * 3106.89 days or 8.5 years The (currentTime - serverStartTime) >> 6 would give an acceptable precision (1/64 of a
 * second) and cover 776.72 days or 2.1 years In the unlikely event the server is not restarted once before the covered
 * time, the table would be flushed out and the serverStartTime reset to the current time.
 */

struct rrl_item_s;

struct rrl_item_children
{
    struct rrl_item_s *left;
    struct rrl_item_s *right;
};

union rrl_item_children_union
{
    struct rrl_item_children lr;
    struct rrl_item_s       *child[2];
};

/*
 * error_mask_ip_imputed_name format:
 * [ 0] : E000IPSZ
 * E    : 1 = error, 0 = ok
 * IPSZ : number of bytes for the IP
 * 1 + 4 + name_length
 *
 * That was the first idea anyway ... now I settled for:
 *
 * [ 0      1 ] native endian 16 bits header
 * [ 2 ..   ? ] IP bytes
 * [ ? .. n-1 ] NAME bytes
 *
 * header: [ E??????S SSSSSSSS ]
 * E: the msb is used to tell if it's an error or not
 * S: 9 bits are used to store the total size of the key (so the two first bytes included)
 *
 */

struct rrl_item_s
{
    union rrl_item_children_union children; // 128  64                  // AVL

    uint32_t                      timestamp;     // 160  96
    uint32_t                      lasttimestamp; //

    int32_t                       hits;      //
    int8_t                        balance;   //                          // AVL
    uint8_t                       reserved0; // alignment
    uint16_t                      slip_countdown;

    uint8_t                       error_mask_ip_imputed_name[1]; // max 1 + 16 + 255 = 272
}; // max 280 bytes

#define RRL_KEY_SIZE_MAX (1 + 1 + 16 + DOMAIN_LENGTH_MAX)

typedef struct rrl_item_s rrl_item_s;

static inline uint32_t    rrl_item_key_size(const uint8_t *key)
{
    uint32_t size = GET_U16_AT(key[0]) & 0x1ff;

    return size;
}

static inline uint32_t rrl_item_size_for_key(const uint8_t *key)
{
    uint32_t size = rrl_item_key_size(key);

    size += sizeof(rrl_item_s) - 1; // -1 because the key takes originally 1 byte in the struct definition

    return size;
}

static inline uint32_t rrl_item_size(const rrl_item_s *rrl)
{
    uint32_t size = rrl_item_size_for_key(rrl->error_mask_ip_imputed_name);

    return size;
}

static inline bool rrl_key_is_error(const uint8_t *key)
{
    bool iserror = (GET_U16_AT(key[0]) & 0x8000) != 0;

    return iserror;
}

/**
 * out_key must be at least 1 + 1 + 16 + 255 bytes long
 *
 * returns the size of the key
 */

static inline uint32_t rrl_make_key(const dns_message_t *mesg, const zdb_query_to_wire_context_t *query_context, uint8_t *out_key)
{
    uint8_t       *tgt;
    const uint8_t *src;
    uint32_t       size;
    uint32_t       flags = 0;

    if(dns_message_get_sender_sa_family(mesg) == AF_INET)
    {
        size = 4;

        uint32_t ip = dns_message_get_sender_sa4(mesg)->sin_addr.s_addr;
        ip &= g_rrl_settings.ipv4_prefix_mask;
        SET_U32_AT(out_key[2], ip);

        tgt = &out_key[6];
    }
    else
    {
        size = 16;

        uint64_t iph = GET_U64_AT(((uint64_t *)&dns_message_get_sender_sa6(mesg)->sin6_addr)[0]);
        iph &= g_rrl_settings.ipv6_prefix_mask_high;
        SET_U64_AT(out_key[2], iph);

        uint64_t ipl = GET_U64_AT(((uint64_t *)&dns_message_get_sender_sa6(mesg)->sin6_addr)[1]);
        ipl &= g_rrl_settings.ipv6_prefix_mask_low;
        SET_U64_AT(out_key[10], ipl);

        tgt = &out_key[18];
        flags |= 0x2000;
    }

    // note: wildcard names are not handled (yet)

    switch(dns_message_get_status(mesg))
    {
        case FP_RCODE_NOERROR:
        {
            // take the answer
            if(!query_context->delegation)
            {
                // src = message_get_canonised_fqdn(mesg); // query name
                // src = query_context->
                src = (const uint8_t *)query_context->fqdn_label;
            }
            else
            {
                // src = authority_fqdn;
                if(query_context->ns_rrset_count > 0)
                {
                    src = (const uint8_t *)query_context->ns_rrsets[0];
                }
                else
                {
                    src = NULL;
                }
            }
            break;
        }
        case FP_RCODE_NXDOMAIN:
        {
            flags |= 0x8000; // note: if we want to have a different key for NXDOMAIN and other errors, we can use
                             // 0xc000 instead
            if(query_context->ns_rrset_count > 0)
            {
                // src = authority_fqdn;
                src = (const uint8_t *)query_context->ns_rrsets[0];
            }
            else
            {
                // src = message_get_canonised_fqdn(mesg);
                src = (const uint8_t *)query_context->fqdn_label;
            }
            break;
        }
        // case wildcard name ?
        default:
        {
            flags = 0x8000;
            // src = message_get_canonised_fqdn(mesg); // query name
            src = (const uint8_t *)query_context->fqdn_label;
            if(IS_WILD_LABEL(query_context->fqdn_label))
            {
                ++src;
            }
        }
    }

    /*
    size += dnsname_copy(tgt, src);
    size += 2;
    */
    SET_U64_AT_P(tgt, (intptr_t)src);
    size += sizeof(src);

    SET_U16_AT(out_key[0], size | flags);

    return size;
}

static inline void rrl_set_key(rrl_item_s *rrl, const uint8_t *key)
{
    uint32_t key_size = GET_U16_AT(key[0]);

    key_size &= 0x01ff;

    memcpy(rrl->error_mask_ip_imputed_name, key, key_size);
}

static rrl_item_s *rrl_alloc(const uint8_t *key)
{
    rrl_item_s *item;
    ZALLOC_ARRAY_OR_DIE(rrl_item_s *, item, rrl_item_size_for_key(key), RRLITEM_TAG);
    item->timestamp = 0;
    item->hits = 0;
    item->slip_countdown = 0;
    SET_U16_AT(item->error_mask_ip_imputed_name[0], 0);
    return item;
}

static void rrl_free(rrl_item_s *item)
{
    /*
     * This assert is wrong because this is actually the payload that has just overwritten our node
     * assert(node->rc == 0 && node->sc == 0 && node->label.owners == NULL && node->star_label.owners == NULL &
     * node->type_bit_maps == NULL);
     */
    ZFREE_ARRAY(item, rrl_item_size(item));
}

#ifdef AVL_DOES_NOT_DO_PAYLOAD_COPY_ANYMORE
static void rrl_payload_copy(rrl_item_s *a, const rrl_item_s *b)
{
    a->timestamp = b->timestamp;
    a->lasttimestamp = b->lasttimestamp;
    a->hits = b->hits;
    a->slip_countdown = b->slip_countdown;
    yassert(rrl_item_size(a) == rrl_item_size(b));
    memcpy(a->error_mask_ip_imputed_name, b->error_mask_ip_imputed_name, rrl_item_size(a));
}
#endif

/*
 * AVL definition part begins here
 */

/*
 * The maximum depth of a tree.
 * 40 is enough for storing 433494436 items (worst case)
 *
 * Depth 0 is one node.
 *
 * Worst case : N is enough for sum[n = 0,N](Fn) where Fn is Fibonacci(n+1)1
 * Best case : N is enough for (2^(N+1))-1
 */
#define AVL_DEPTH_MAX 34 // 24157816 items max (worst case)*/

/*
 * The previx that will be put in front of each function name
 */
#define AVL_PREFIX    rrl_set_

/*
 * The type that hold the node
 */
#define AVL_NODE_TYPE rrl_item_s

/*
 * The type that hold the tree (should be AVL_NODE_TYPE*)
 */
#define AVL_TREE_TYPE AVL_NODE_TYPE *

typedef AVL_TREE_TYPE rrl_set_s;

/*
 * The type that hold the tree (should be AVL_NODE_TYPE*)
 */
#define AVL_CONST_TREE_TYPE      AVL_NODE_TYPE *const

/*
 * How to find the root in the tree
 */
#define AVL_TREE_ROOT(__tree__)  (*(__tree__))

/*
 * The type used for comparing the nodes.
 */
#define AVL_REFERENCE_TYPE       uint8_t *
#define AVL_REFERENCE_IS_POINTER true
#define AVL_REFERENCE_IS_CONST   false

/*
 * The node has got a pointer to its parent
 *
 * 0   : disable
 * !=0 : enable
 */
#define AVL_HAS_PARENT_POINTER   0

#include <dnscore/avl.h.inc>

/*
 * Access to the field that points to the left child
 *
 */
#define AVL_LEFT_CHILD(node)            ((node)->children.lr.left)
/*
 * Access to the field that points to the right child
 */
#define AVL_RIGHT_CHILD(node)           ((node)->children.lr.right)
/*
 * Access to the field that points to one of the children (0: left, 1: right)
 */
#define AVL_CHILD(node, id)             ((node)->children.child[(id)])
/*
 * OPTIONAL : Access to the field that points the parent of the node.
 *
 * This field is optional but is mandatory if AVL_HAS_PARENT_POINTER is not 0
 */
// #define AVL_PARENT(node) ((node)->parent)
/*
 * Access to the field that keeps the balance (a signed byte)
 */
#define AVL_BALANCE(node)               ((node)->balance)
/*
 * The type used for comparing the nodes.
 */
#define AVL_REFERENCE_TYPE              uint8_t *
/*
 *
 */

#define AVL_REFERENCE_FORMAT_STRING     "%p"
#define AVL_REFERENCE_FORMAT(reference) reference

/*
 * A macro to initialize a node and setting the reference
 */
#define AVL_INIT_NODE(node, reference)  rrl_set_key((node), reference)
/*
 * A macro to allocate a new node
 */
#define AVL_ALLOC_NODE(node, reference) node = rrl_alloc(reference)

/*
 * A macro to free a node allocated by ALLOC_NODE
 */

#define AVL_FREE_NODE(node)             rrl_free(node)
/*
 * A macro to print the node
 */
#define AVL_DUMP_NODE(node)             format("node@%p", (node));
/*
 * A macro that returns the reference field of the node.
 * It must be of type REFERENCE_TYPE
 */
#define AVL_REFERENCE(node)             (node)->error_mask_ip_imputed_name

#define AVL_TERNARYCMP                  1

#if !AVL_TERNARYCMP
/*
 * A macro to compare two references
 * Returns true if and only if the references are equal.
 */
#define AVL_ISEQUAL(reference_a, reference_b)  (memcmp(&(reference_a)[0], &(reference_b)[0], rrl_item_key_size(reference_a)) == 0)
/*
 * A macro to compare two references
 * Returns true if and only if the first one is bigger than the second one.
 */
#define AVL_ISBIGGER(reference_a, reference_b) (memcmp(&(reference_a)[0], &(reference_b)[0], rrl_item_key_size(reference_a)) > 0)

#else

#define AVL_COMPARE(reference_a, reference_b) (memcmp(&(reference_a)[0], &(reference_b)[0], rrl_item_key_size(reference_a)))

#endif

/*
 * Copies the payload of a node
 * It MUST NOT copy the "proprietary" node fields : children, parent, balance
 *
 * NOTE: this macro is most likely not used anymore
 */
#define AVL_COPY_PAYLOAD(node_trg, node_src) rrl_payload_copy((node_trg), (node_src))
/*
 * A macro to preprocess a node before it is preprocessed for a delete (detach)
 * If there was anything to do BEFORE deleting a node, we would do it here
 * After this macro is exectuted, the node
 * _ is detached, then deleted with FREE_NODE
 * _ has got its content overwritten by the one of another node, then the other
 *   node is deleted with FREE_NODE
 */
#define AVL_NODE_DELETE_CALLBACK(node)

#include <dnscore/avl.c.inc>

static rrl_set_s           g_rrl = NULL;

static initialiser_state_t rrl_init_state = INITIALISE_STATE_INIT;

void                       rrl_init()
{
    if(initialise_state_begin(&rrl_init_state))
    {
        mutex_init(&rrl_mtx);
        rrl_set_init(&g_rrl);

        g_rrl_start = timeus();
        g_rrl_rnd = random_init_auto();
        g_rrl_slip_bucket = random_next(g_rrl_rnd);
        g_rrl_slip_bucket_bits = 32;

        /*
        uint32_t responses_per_tick = (5 * 1000000) >> (20 - EPOCH_PRECISION);
        uint32_t errors_per_tick = (5 * 1000000) >> (20 - EPOCH_PRECISION);
        uint32_t window_ticks = (15 * 1000000) >> (20 - EPOCH_PRECISION);
        */
        initialise_state_ready(&rrl_init_state);
    }
}

void rrl_cull_all();

void rrl_finalize()
{
    if(initialise_state_unready(&rrl_init_state))
    {
        rrl_cull_all();

        rrl_set_destroy(&g_rrl);
        ptr_vector_finalise(&g_rrl_list);

        mutex_destroy(&rrl_mtx);
        random_finalize(g_rrl_rnd);

        initialise_state_end(&rrl_init_state);
    }
}

/**
 *
 * Called when maybe we should slip
 *
 * @param mesg
 * @return
 */

static inline int32_t rrl_slip(dns_message_t *mesg)
{
    int32_t return_code = RRL_DROP;

    // g_rrl_slip_bucket is a global random 32 bits number
    // for every slip call, its lsb is shifted out and used to ...
    // 1 : send a truncated answer
    // 0 : drop the answer
    //
    // every 32 calls, fill the bucket again with a random number

    if((g_rrl_slip_bucket & 1) != 0)
    {
        // slip

#if DEBUG
        log_debug("rrl: %{sockaddrip} %{dnsname} %{dnstype} %{dnsclass}: slipping", dns_message_get_sender_sa(mesg), dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type_ptr(mesg), dns_message_get_query_class_ptr(mesg));
#endif

        return_code = RRL_SLIP;

        if(!g_rrl_settings.log_only)
        {
            /**
             * Give a truncated answer
             */

            dns_message_update_truncated_answer_status(mesg);
            dns_message_set_answer_count_ne(mesg, 0);
            dns_message_set_authority_additional_counts_ne(mesg, 0, 0);

            if(dns_message_has_edns0(mesg))
            {
                /* 00 00 29 SS SS rr vv 80 00 00 00 */

                dns_message_set_additional_count_ne(mesg, NETWORK_ONE_16);

                uint8_t *ednsrecord = dns_message_get_buffer_limit(mesg);

                *ednsrecord++ = 0;                 // fqdn
                SET_U16_AT(*ednsrecord, TYPE_OPT); // type
                ednsrecord += 2;
                SET_U16_AT(*ednsrecord, htons(dns_message_edns0_getmaxsize())); // udp payload size
                ednsrecord += 2;
                SET_U32_AT(*ednsrecord, dns_message_get_edns0_opt_ttl(mesg)); // edns flags
                ednsrecord += 4;
                SET_U16_AT(*ednsrecord, 0); // rdata size

                // nsid

                dns_message_increase_size(mesg, EDNS0_RECORD_SIZE);
            }
        }
    }
    else
    {
        if(g_rrl_settings.log_only)
        {
            return_code = RRL_PROCEED_DROP;
        }
    }
    if(--g_rrl_slip_bucket_bits > 0)
    {
        g_rrl_slip_bucket >>= 1;
    }
    else
    {
        g_rrl_slip_bucket_bits = 32;
        g_rrl_slip_bucket = random_next(g_rrl_rnd);
    }

    return return_code;
}

/**
 * Look at the message for RRL processing.
 * Returns an RRL code.
 * After this call, the message may be truncated.
 *
 * @param mesg the query message
 * @param ans_auth_add the answer that would be given to the client
 * @return an RRL error code
 */

/**
 * Look at the message for RRL processing.
 * Returns an RRL code.
 * After this call, the message may be truncated.
 *
 * @param mesg the query message
 * @param ans_auth_add the answer that would be given to the client
 * @return an RRL error code
 */

ya_result rrl_process(dns_message_t *mesg, zdb_query_to_wire_context_t *query_context)
{
    int32_t return_code = RRL_PROCEED;

    // if the RRL is enabled and
    // if the sender is not exempted

    if(!g_rrl_settings.enabled || (g_rrl_settings.exempted_filter(mesg, &g_rrl_settings.exempted) > 0))
    {
#if DEBUG
        log_debug(
            "rrl: %{sockaddrip} %{dnsname} %{dnstype} %{dnsclass}: disabled or exempted", dns_message_get_sender_sa(mesg), dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type_ptr(mesg), dns_message_get_query_class_ptr(mesg));
#endif /*                                                                                                                                                                                                                                      \
         zdb_query_to_wire_context_t context;                                                                                                                                                                                                  \
         zdb_query_to_wire_context_init(&context, mesg);                                                                                                                                                                                       \
         zdb_query_to_wire(g_config->database, &context);                                                                                                                                                                                      \
 */
        return return_code;
    }

    uint64_t now = timeus();
    uint8_t  key[RRL_KEY_SIZE_MAX];

    // uint32_t rrl_make_key(const dns_message_t *mesg, const uint8_t *authority_fqdn, bool is_delegation, uint8_t
    // *out_key) rrl_make_key(mesg, ans_auth_add, key);

    rrl_make_key(mesg, query_context, key);

    now -= g_rrl_start;
    // it's us so about 20 bits of (im)precision
    now >>= (20 - EPOCH_PRECISION);

    // 1 s ~ 61.035 ticks

    mutex_lock(&rrl_mtx);

    rrl_item_s *item = rrl_set_insert(&g_rrl, key);

    if(item->timestamp > 0)
    {
        int32_t hits;
        int32_t limit;

        // ensure no overflow of the 1s bucket

        if((now - item->lasttimestamp) >= ONE_SECOND_TICKS)
        {
            // nothing happened for 1 second, we cannot accumulate so ...
            // we cut at lasttimestamp, we remove (lasttimestamp - timestamp) * rps
            int32_t tsd = (now - item->timestamp) & ~(ONE_SECOND_TICKS - 1);
            item->timestamp += tsd;
            int32_t hsd = (tsd >> EPOCH_PRECISION) * g_rrl_settings.responses_per_second;

#if DEBUG
            log_debug(
                "rrl: %{sockaddrip} %{dnsname} %{dnstype} %{dnsclass}: 1s bucket overflow; delta time = %d (%ds); hits "
                "adjusted from %i to %i",
                dns_message_get_sender_sa(mesg),
                dns_message_get_canonised_fqdn(mesg),
                dns_message_get_query_type_ptr(mesg),
                dns_message_get_query_class_ptr(mesg),
                tsd,
                tsd >> EPOCH_PRECISION,
                item->hits,
                MAX(item->hits - hsd, 0));
#endif

            item->hits -= hsd;

            if(item->hits < 0)
            {
                item->hits = 0;
                item->timestamp = now - ONE_SECOND_TICKS;
            }

            // tsd
        }

        item->lasttimestamp = now;

        uint32_t ticks = (now - item->timestamp); // 1s + delta time (so we see for 1 second)

        hits = item->hits + 1;

        // ensure now overflow of the hits counter

        if(hits == U16_MAX)
        {
            // divide hits by 16
            // divide time by 16
            // adjust
            hits >>= 4;
            item->hits = hits;
            ticks >>= 4;
            item->timestamp = now - ticks;
        }

        // compute the current limit

        if(!rrl_key_is_error(key))
        {
            limit = ((g_rrl_settings.responses_per_second * ticks) >> EPOCH_PRECISION);

#if DEBUG
            log_debug(
                "rrl: %{sockaddrip} %{dnsname} %{dnstype} %{dnsclass}: %i responses with a limit of %i in %i ticks, "
                "%i/s, %is",
                dns_message_get_sender_sa(mesg),
                dns_message_get_canonised_fqdn(mesg),
                dns_message_get_query_type_ptr(mesg),
                dns_message_get_query_class_ptr(mesg),
                hits,
                limit,
                ticks,
                g_rrl_settings.responses_per_second,
                ticks >> EPOCH_PRECISION);
#endif
        }
        else
        {
            limit = ((g_rrl_settings.errors_per_second * ticks) >> EPOCH_PRECISION);

#if DEBUG
            log_debug(
                "rrl: %{sockaddrip} %{dnsname} %{dnstype} %{dnsclass}: %i errors with a limit of %i in %i ticks, %i/s, "
                "%is",
                dns_message_get_sender_sa(mesg),
                dns_message_get_canonised_fqdn(mesg),
                dns_message_get_query_type_ptr(mesg),
                dns_message_get_query_class_ptr(mesg),
                hits,
                limit,
                ticks,
                g_rrl_settings.errors_per_second,
                ticks >> EPOCH_PRECISION);
#endif
        }

        // test if we are in the allowed rate

        if(hits <= limit)
        {
            item->hits = hits;
        }
        else
        {
#if DEBUG
            log_debug(
                "rrl: %{sockaddrip} %{dnsname} %{dnstype} %{dnsclass}: rate exceeded", dns_message_get_sender_sa(mesg), dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type_ptr(mesg), dns_message_get_query_class_ptr(mesg));
#endif
            // rate exceeded, drop ... except if we slip

            return_code = g_rrl_settings.drop_default;

            if((g_rrl_settings.slip > 0) && (--item->slip_countdown == 0))
            {
#if DEBUG
                // pure debug
                log_debug(
                    "rrl: %{sockaddrip} %{dnsname} %{dnstype} %{dnsclass}: testing slip", dns_message_get_sender_sa(mesg), dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type_ptr(mesg), dns_message_get_query_class_ptr(mesg));
#endif
                item->slip_countdown = g_rrl_settings.slip;

                /*
                 * Every 'slip' counts, compute if we slip or drop
                 */

                if((return_code = rrl_slip(mesg)) == RRL_SLIP)
                {
                    // count it

                    item->hits = hits;
                }
            }
        }

        mutex_unlock(&rrl_mtx);

        if(((return_code & (RRL_SLIP | RRL_DROP)) == 0) || g_rrl_settings.log_only)
        {
#if DEBUG
            log_debug("rrl: %{sockaddrip} %{dnsname} %{dnstype} %{dnsclass}: %x | %i",
                      dns_message_get_sender_sa(mesg),
                      dns_message_get_canonised_fqdn(mesg),
                      dns_message_get_query_type_ptr(mesg),
                      dns_message_get_query_class_ptr(mesg),
                      return_code,
                      g_rrl_settings.log_only);
#endif
            zdb_query_to_wire_context_t context;
            zdb_query_to_wire_context_init(&context, mesg);
            zdb_query_to_wire(g_config->database, &context);
        }
    }
    else
    {
#if DEBUG
        // pure debug
        log_debug("rrl: %{sockaddrip} %{dnsname} %{dnstype} %{dnsclass}: new entry", dns_message_get_sender_sa(mesg), dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type_ptr(mesg), dns_message_get_query_class_ptr(mesg));
#endif
        item->timestamp = now - ONE_SECOND_TICKS;
        item->lasttimestamp = now;
        item->slip_countdown = g_rrl_settings.slip;

        if(g_rrl_list.offset + 1 < g_rrl_settings.max_table_size)
        {
            // enough room: append
            ptr_vector_append_restrict_size(&g_rrl_list, item, g_rrl_settings.max_table_size);
        }
        else
        {
            // full: replace
            int32_t victim = random_next(g_rrl_rnd) % g_rrl_settings.max_table_size;

#if DEBUG
            log_debug("rrl: table is full (%u), removing entry #%i", g_rrl_settings.max_table_size, victim);
#endif

            rrl_item_s *victim_item = (rrl_item_s *)g_rrl_list.data[victim];

            rrl_set_delete(&g_rrl, victim_item->error_mask_ip_imputed_name);

            g_rrl_list.data[victim] = item;
        }

        mutex_unlock(&rrl_mtx);

        zdb_query_to_wire_context_t context;
        zdb_query_to_wire_context_init(&context, mesg);
        zdb_query_to_wire(g_config->database, &context);
    }

    return return_code;
}

void rrl_cull()
{
    uint64_t now = timeus();
    now -= g_rrl_start;
    // it's us so about 20 bits of (im)precision
    now >>= (20 - EPOCH_PRECISION);

    mutex_lock(&rrl_mtx);

    for(int_fast32_t i = 0; i <= g_rrl_list.offset; i++)
    {
        rrl_item_s *item = (rrl_item_s *)g_rrl_list.data[i];

        if(now - item->lasttimestamp > g_rrl_settings.window_ticks)
        {
            // put the end here (i == offset is irrelevant)
            g_rrl_list.data[i] = g_rrl_list.data[g_rrl_list.offset];
            g_rrl_list.offset--;

            // remove from the tree
            rrl_set_delete(&g_rrl, item->error_mask_ip_imputed_name);
        }
    }

    mutex_unlock(&rrl_mtx);
}

void rrl_cull_all()
{
#if 0
    uint64_t now = timeus();
    now -= g_rrl_start;
    // it's us so about 20 bits of (im)precision
    now >>= (20 - EPOCH_PRECISION);
#endif
    mutex_lock(&rrl_mtx);

    for(int_fast32_t i = 0; i <= g_rrl_list.offset; i++)
    {
        rrl_item_s *item = (rrl_item_s *)g_rrl_list.data[i];
        g_rrl_list.data[i] = g_rrl_list.data[g_rrl_list.offset];

        // remove from the tree
        rrl_set_delete(&g_rrl, item->error_mask_ip_imputed_name);
    }

    g_rrl_list.offset = -1;

    mutex_unlock(&rrl_mtx);
}

bool rrl_is_logonly() { return g_rrl_settings.log_only; }

/** @} */
