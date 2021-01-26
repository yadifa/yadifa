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

/** @defgroup ### #######
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>

#include "dnscore/dnscore-config.h"
#include "dnscore/zalloc.h"
#include "dnscore/message.h" // DO NOT REMOVE ME
#include "dnscore/tsig.h"
#include "dnscore/packet_reader.h"
#include "dnscore/logger.h"

#if DNSCORE_HAS_TSIG_SUPPORT

#define TSIGNODE_TAG 0x45444f4e47495354
#define TSIGPAYL_TAG 0x4c59415047495354
#define TSIGMAC_TAG 0x43414d47495354
#define TSIGOTHR_TAG 0x5248544f47495354

#define MODULE_MSG_HANDLE g_system_logger

#define LOG_DIGEST_INPUT 2 // set up to 2 for debugging

#define TSIG_TCP_PERIOD 99

/* overrites the detected TSIG with 0xff */
#define TSIG_DESTROY_DEBUG 1

/*
 * AVL definition part begins here
 */

/*
 * The maximum depth of a tree.
 * 40 is enough for storing 433494436 items (worst case)
 *
 * Depth 0 is one node.
 *
 * Worst case : N is enough for sum[n = 0,N](Fn) where Fn is Fibonacci(n+1)
 * Best case : N is enough for (2^(N+1))-1
 */
#define AVL_MAX_DEPTH 40 // no need for more

/*
 * The previx that will be put in front of each function name
 */
#define AVL_PREFIX	    tsig_

/*
 * The type that hold the node
 */
#define AVL_NODE_TYPE   tsig_node

/*
 * The type that hold the tree (should be AVL_NODE_TYPE*)
 */
#define AVL_TREE_TYPE   AVL_NODE_TYPE*

/*
 * The type that hold the tree (should be AVL_NODE_TYPE*)
 */
#define AVL_CONST_TREE_TYPE AVL_NODE_TYPE * const

/*
 * The way to get the root from the tree
 */
#define AVL_TREE_ROOT(__tree__) (*(__tree__))

/*
 * The type used for comparing the nodes.
 */
#define AVL_REFERENCE_TYPE const u8*

#define AVL_REFERENCE_IS_CONST TRUE
#define AVL_REFERENCE_IS_POINTER TRUE

/*
 * The node has got a pointer to its parent
 *
 * 0   : disable
 * !=0 : enable
 */
#define AVL_HAS_PARENT_POINTER 0

#include "dnscore/avl.h.inc"

/*********************************************************/

/*
 * The following macros are defining relevant fields in the node
 */

/*
 * Access to the field that points to the left child
 */
#define AVL_LEFT_CHILD(node) ((node)->children.lr.left)
/*
 * Access to the field that points to the right child
 */
#define AVL_RIGHT_CHILD(node) ((node)->children.lr.right)
/*
 * Access to the field that points to one of the children (0: left, 1: right)
 */
#define AVL_CHILD(node,id) ((node)->children.child[(id)])
/*
 * Access to the field that keeps the balance (a signed byte)
 */
#define AVL_BALANCE(node) ((node)->balance)
/*
 * The type used for comparing the nodes.
 */
#define AVL_REFERENCE_TYPE const u8*

#define AVL_REFERENCE_IS_CONST TRUE

/*
 *
 */

#define AVL_REFERENCE_FORMAT_STRING "%{dnsname}"
#define AVL_REFERENCE_FORMAT(reference) reference

/*
 * A macro to initialize a node and setting the reference
 */

#define AVL_INIT_NODE(node,reference) ZEROMEMORY((node),sizeof(tsig_node));(node)->item.name = dnsname_dup(reference)

/*
 * A macro to allocate a new node
 */

#define AVL_ALLOC_NODE(node,reference) MALLOC_OR_DIE(AVL_NODE_TYPE*,node,sizeof(AVL_NODE_TYPE), TSIGNODE_TAG)

/*
 * A macro to free a node allocated by ALLOC_NODE
 */

#define AVL_FREE_NODE(node) free((u8*)(node)->item.name);free((u8*)(node)->item.mac);free(node)
/*
 * A macro to print the node
 */
#define AVL_DUMP_NODE(node) format("node@%p",(node));
/*
 * A macro that returns the reference field of the node.
 * It must be of type REFERENCE_TYPE
 */
#define AVL_REFERENCE(node) (node)->item.name

#define AVL_TERNARYCMP 1

#if !AVL_TERNARYCMP
/*
 * A macro to compare two references
 * Returns TRUE if and only if the references are equal.
 */
#define AVL_ISEQUAL(reference_a,reference_b) dnsname_equals(reference_a,reference_b)
/*
 * A macro to compare two references
 * Returns TRUE if and only if the first one is bigger than the second one.
 */
#define AVL_ISBIGGER(reference_a,reference_b) (dnsname_compare(reference_a,reference_b) > 0)
#else
#define AVL_COMPARE(reference_a,reference_b) (dnsname_compare(reference_a,reference_b))
#endif

/*
 * Copies the payload of a node
 * It MUST NOT copy the "proprietary" node fields : children, parent, balance
 */
#define AVL_COPY_PAYLOAD(node_trg,node_src) (node_trg)->item.name = dnsname_dup((node_src)->item.name);		  \
					    MALLOC_OR_DIE(const u8*,(node_trg)->item.mac,(node_src)->item.mac_size, TSIGPAYL_TAG); \
					    MEMCOPY((u8*)(node_trg)->item.mac, (node_src)->item.mac, (node_src)->item.mac_size);  \
					    (node_trg)->item.mac_size = (node_src)->item.mac_size; \
					    (node_trg)->item.mac_algorithm = (node_src)->item.mac_algorithm;
/*
 * A macro to preprocess a node before it is preprocessed for a delete (detach)
 * If there was anything to do BEFORE deleting a node, we would do it here
 * After this macro is exectuted, the node
 * _ is detached, then deleted with FREE_NODE
 * _ has got its content overwritten by the one of another node, then the other
 *   node is deleted with FREE_NODE
 */
#define AVL_NODE_DELETE_CALLBACK(node)

#include "dnscore/avl.c.inc"
#include "dnscore/message.h" // DO NOT REMOVE ME

#undef AVL_MAX_DEPTH
#undef AVL_PREFIX
#undef AVL_NODE_TYPE
#undef AVL_TREE_TYPE
#undef AVL_CONST_TREE_TYPE
#undef AVL_TREE_ROOT
#undef AVL_REFERENCE_TYPE
#undef _AVL_H_INC

/*
 *
 */

static tsig_node *tsig_tree = NULL;
static u32 tsig_tree_count = 0;
static u8 tsig_serial = 0; /// @note load serial

static const value_name_table hmac_digest_enum[]=
{
    {HMAC_MD5   , "hmac-md5"    },
    {HMAC_SHA1  , "hmac-sha1"   },
    {HMAC_SHA224, "hmac-sha224" },
    {HMAC_SHA256, "hmac-sha256" },
    {HMAC_SHA384, "hmac-sha384" },
    {HMAC_SHA512, "hmac-sha512" },
    {0, NULL}
};

ya_result
tsig_get_hmac_algorithm_from_friendly_name(const char *hmacname)
{
    ya_result ret;
    u32 integer_value;
    if(ISOK(ret = value_name_table_get_value_from_casename(hmac_digest_enum, hmacname, &integer_value)))
    {
        return (ya_result)integer_value;
    }
    else
    {
        return ret;
    }
}

/**
 * Call this before a config reload
 */

void
tsig_serial_next()
{
    tsig_serial++;
}

ya_result
tsig_register(const u8 *name, const u8 *mac, u16 mac_size, u8 mac_algorithm)
{
    ya_result return_code = SUCCESS;

    tsig_node *node = tsig_insert(&tsig_tree, name);

    if(node != NULL)
    {
        if(node->item.mac != NULL)
        {
            bool same = (node->item.mac_size == mac_size)                 &&
                        (node->item.mac_algorithm == mac_algorithm)       &&
                        (memcmp((u8*)node->item.mac, mac, mac_size) == 0);

            if(same)
            {
                // don't complain if they are an exact match
                return SUCCESS;
            }
            
            if(node->item.load_serial != tsig_serial)
            {
                node->item.load_serial = tsig_serial; // else every 256 updates will see a duplicate

                // this is an old version of the key

                free((void*)node->item.mac);
                node->item.mac = NULL;
            }
            else
            {
                // it's a dup in the config file
                
                return TSIG_DUPLICATE_REGISTRATION; /* dup */
            }
        }
        
        yassert(node->item.mac == NULL);
        
        MALLOC_OR_DIE(u8*, node->item.mac, mac_size, TSIGMAC_TAG);
        MEMCOPY((u8*)node->item.mac, mac, mac_size);

        node->item.mac_algorithm_name = tsig_get_algorithm_name(mac_algorithm);
        node->item.name_len = dnsname_len(name);
        node->item.mac_algorithm_name_len = dnsname_len(node->item.mac_algorithm_name);
        node->item.mac_size = mac_size;
        node->item.mac_algorithm = mac_algorithm;
        node->item.load_serial = tsig_serial;

        tsig_tree_count++;
    }
    else
    {
        return_code = INVALID_STATE_ERROR; /* internal error */
    }

    return return_code;
}

tsig_item*
tsig_get(const u8 *name)
{
    tsig_node *node = tsig_find(&tsig_tree, name);

    if(node != NULL)
    {
        return &node->item;
    }

    return NULL;
}

u32
tsig_get_count()
{
    return tsig_tree_count;
}

tsig_item*
tsig_get_at_index(s32 index)
{
    if(index < 0 || (u32)index >= tsig_tree_count)
    {
        return NULL;
    }
    
    tsig_iterator iter;
    tsig_iterator_init(&tsig_tree, &iter);
    
    while(tsig_iterator_hasnext(&iter))
    {
        tsig_node *node = tsig_iterator_next_node(&iter);
        
        if(index == 0)
        {
            return &node->item;
        }
        
        index--;
    }
    
    // should never be reached
    
    return NULL;
}

void tsig_finalize_algorithms();

void
tsig_finalize()
{
    tsig_destroy(&tsig_tree);
    tsig_finalize_algorithms();
}

static u8 tsig_typeclassttl[8] = {0x00, 0xfa, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00};
static u8 tsig_classttl[6] = {0x00, 0xff, 0x00, 0x00, 0x00, 0x00};
static u8 tsig_noerror_noother[4] = {0x00, 0x00, 0x00, 0x00};

static void
tsig_update_time(message_data *mesg)
{
    u64 now = time(NULL);
    mesg->_tsig.timehi = htons((u16)(now >> 32));
    mesg->_tsig.timelo = htonl((u32)now);
}

static ya_result
tsig_verify_query(message_data *mesg)
{
    u32 md_len = 0;
    u8 md[EVP_MAX_MD_SIZE];

#if LOG_DIGEST_INPUT
    log_debug("tsig_verify_query(%p = %{dnsname} %{dnstype} %{dnsclass})", mesg, message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), message_get_query_class_ptr(mesg));
#endif

    tsig_hmac_t hmac = tsig_hmac_allocate();

    if(hmac == NULL)
    {
        return INVALID_STATE_ERROR;
    }

    if(FAIL(hmac_init(hmac, message_tsig_get_key_bytes(mesg), message_tsig_get_key_size(mesg), mesg->_tsig.tsig->mac_algorithm)))
    {
        hmac_free(hmac);
        return ERROR;
    }

    /* DNS message */

    hmac_update(hmac, message_get_buffer_const(mesg), message_get_size(mesg));

    /* TSIG Variables */

    hmac_update(hmac, mesg->_tsig.tsig->name, mesg->_tsig.tsig->name_len);
    hmac_update(hmac, tsig_classttl, sizeof(tsig_classttl));
    hmac_update(hmac, mesg->_tsig.tsig->mac_algorithm_name, mesg->_tsig.tsig->mac_algorithm_name_len);
    hmac_update(hmac, (u8*) & mesg->_tsig.timehi, 2);
    hmac_update(hmac, (u8*) & mesg->_tsig.timelo, 4);
    hmac_update(hmac, (u8*) & mesg->_tsig.fudge, 2);
    hmac_update(hmac, (u8*) & mesg->_tsig.error, 2);
    hmac_update(hmac, (u8*) & mesg->_tsig.other_len, 2);

    if(mesg->_tsig.other_len != 0)
    {
        hmac_update(hmac, mesg->_tsig.other, ntohs(mesg->_tsig.other_len));
    }

    hmac_final(hmac, md, &md_len);
    
#if LOG_DIGEST_INPUT
    log_debug("tsig_verify_query: computed:");
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, md, md_len, 32);
    log_debug("tsig_verify_query: expected:", mesg);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) mesg->_tsig.mac, md_len, 32);
#endif
    
    hmac_free(hmac);

    if((md_len != mesg->_tsig.mac_size) || (memcmp(mesg->_tsig.mac, md, md_len) != 0))
    {
        log_debug("tsig_verify_query: BADSIG");
        message_set_status(mesg, FP_TSIG_ERROR);
        mesg->_tsig.error = NU16(RCODE_BADSIG);
        return TSIG_BADSIG;
    }

    return SUCCESS;
}

ya_result
tsig_verify_answer(message_data *mesg, const u8 *mac, u16 mac_size)
{
    u32 md_len = 0;
    u8 md[EVP_MAX_MD_SIZE];

    u16 mac_size_network = htons(mac_size);

#if LOG_DIGEST_INPUT
    log_debug("tsig_verify_answer(%p = %{dnsname} %{dnstype} %{dnsclass}, %p, %i)",
            mesg, message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), message_get_query_class_ptr(mesg),
            mac, mac_size
            );
#endif

    tsig_hmac_t hmac = tsig_hmac_allocate();

    if(hmac == NULL)
    {
        return INVALID_STATE_ERROR;
    }

    if(FAIL(hmac_init(hmac, message_tsig_get_key_bytes(mesg), message_tsig_get_key_size(mesg), mesg->_tsig.tsig->mac_algorithm)))
    {
        hmac_free(hmac);
        return ERROR;
    }
    
    hmac_update(hmac, (u8*) &mac_size_network, 2);
    hmac_update(hmac, mac, mac_size);

    /* DNS message */

    hmac_update(hmac, message_get_buffer_const(mesg), message_get_size(mesg));

    /* TSIG Variables */

    hmac_update(hmac, mesg->_tsig.tsig->name, mesg->_tsig.tsig->name_len);
    hmac_update(hmac, tsig_classttl, sizeof(tsig_classttl));
    hmac_update(hmac, mesg->_tsig.tsig->mac_algorithm_name, mesg->_tsig.tsig->mac_algorithm_name_len);
    hmac_update(hmac, (u8*) &mesg->_tsig.timehi, 2);
    hmac_update(hmac, (u8*) &mesg->_tsig.timelo, 4);
    hmac_update(hmac, (u8*) &mesg->_tsig.fudge, 2);
    hmac_update(hmac, (u8*) &mesg->_tsig.error, 2);
    hmac_update(hmac, (u8*) &mesg->_tsig.other_len, 2);

    if(mesg->_tsig.other_len != 0)
    {
        hmac_update(hmac, mesg->_tsig.other, ntohs(mesg->_tsig.other_len));
    }

    hmac_final(hmac, md, &md_len);
    
#if LOG_DIGEST_INPUT
    log_debug("tsig_verify_answer: computed");
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, md, md_len, 32);
    log_debug("tsig_verify_answer: expected");
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->_tsig.mac, md_len, 32);
#endif

    hmac_free(hmac);

    //if(md_len != ntohs(mesg->_tsig.mac_size))
    if(md_len != mac_size)
    {
        message_set_status(mesg, FP_TSIG_ERROR);
        return TSIG_BADSIG;
    }

    if(memcmp(mesg->_tsig.mac, md, md_len) != 0)
    {
        log_debug("tsig_verify_answer: BADSIG");
        message_set_status(mesg, FP_TSIG_ERROR);
        return TSIG_BADSIG;
    }

    return SUCCESS;
}


static ya_result
tsig_digest_query(message_data *mesg)
{
/* Request MAC */
    
#if LOG_DIGEST_INPUT
    log_debug("tsig_digest_query(%p = %{dnsname} %{dnstype} %{dnsclass})",
            mesg, message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), message_get_query_class_ptr(mesg));
#endif

    tsig_hmac_t hmac = tsig_hmac_allocate();

    if(hmac == NULL)
    {
        return INVALID_STATE_ERROR;
    }

    if(FAIL(hmac_init(hmac, message_tsig_get_key_bytes(mesg), message_tsig_get_key_size(mesg), mesg->_tsig.tsig->mac_algorithm)))
    {
        hmac_free(hmac);
        return ERROR;
    }
    
    /* DNS message */

    hmac_update(hmac, message_get_buffer_const(mesg), message_get_size(mesg));

    /* TSIG Variables */

    hmac_update(hmac, mesg->_tsig.tsig->name, mesg->_tsig.tsig->name_len);
    hmac_update(hmac, tsig_classttl, sizeof(tsig_classttl));
    hmac_update(hmac, mesg->_tsig.tsig->mac_algorithm_name, mesg->_tsig.tsig->mac_algorithm_name_len);
    hmac_update(hmac, (u8*) & mesg->_tsig.timehi, 2);
    hmac_update(hmac, (u8*) & mesg->_tsig.timelo, 4);
    hmac_update(hmac, (u8*) & mesg->_tsig.fudge, 2);
    // error is 0
    // other len is 0
    // no need to work on other data either (since other len is 0)
    hmac_update(hmac, tsig_noerror_noother, 4); // four zeros

    u32 tmp_mac_size;
    hmac_final(hmac, mesg->_tsig.mac, &tmp_mac_size);
    mesg->_tsig.mac_size = tmp_mac_size;
    
#if LOG_DIGEST_INPUT
    log_debug("tsig_digest_query: computed");
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->_tsig.mac, tmp_mac_size, 32);
#endif

    hmac_free(hmac);

    return SUCCESS;
}

static ya_result
tsig_digest_answer(message_data *mesg)
{
    tsig_hmac_t hmac = tsig_hmac_allocate();

    if(hmac == NULL)
    {
        return INVALID_STATE_ERROR;
    }

    /* Request MAC */

#if LOG_DIGEST_INPUT
    log_debug("tsig_digest_answer(%p = %{dnsname} %{dnstype} %{dnsclass})",
            mesg, message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), message_get_query_class_ptr(mesg));
#endif
    
    if(FAIL(hmac_init(hmac, message_tsig_get_key_bytes(mesg), message_tsig_get_key_size(mesg), mesg->_tsig.tsig->mac_algorithm)))
    {
        hmac_free(hmac);
        return ERROR;
    }

    u16 mac_size_network = htons(mesg->_tsig.mac_size);
    hmac_update(hmac, (u8*) & mac_size_network, 2);
    hmac_update(hmac, mesg->_tsig.mac, mesg->_tsig.mac_size);

    /* DNS message */

    hmac_update(hmac, message_get_buffer_const(mesg), message_get_size(mesg));

    /* TSIG Variables */

    hmac_update(hmac, mesg->_tsig.tsig->name, mesg->_tsig.tsig->name_len);
    hmac_update(hmac, tsig_classttl, sizeof(tsig_classttl));
    hmac_update(hmac, mesg->_tsig.tsig->mac_algorithm_name, mesg->_tsig.tsig->mac_algorithm_name_len);
    hmac_update(hmac, (u8*) & mesg->_tsig.timehi, 2);
    hmac_update(hmac, (u8*) & mesg->_tsig.timelo, 4);
    hmac_update(hmac, (u8*) & mesg->_tsig.fudge, 2);
    hmac_update(hmac, (u8*) & mesg->_tsig.error, 2);
    hmac_update(hmac, (u8*) & mesg->_tsig.other_len, 2);

    if(mesg->_tsig.other_len != 0)
    {
        hmac_update(hmac, mesg->_tsig.other, ntohs(mesg->_tsig.other_len));
    }

    u32 tmp_mac_size;
    hmac_final(hmac, mesg->_tsig.mac, &tmp_mac_size);
    mesg->_tsig.mac_size = tmp_mac_size;

#if LOG_DIGEST_INPUT
    log_debug("tsig_digest_answer: computed");
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->_tsig.mac, tmp_mac_size, 32);
#endif
    
    hmac_free(hmac);

    return SUCCESS;
}

/**
 * Extracts the TSIG from a message
 * 
 * _ checks if the CLASS & TTL are right
 * _ checks if the TSIG name is known
 * _ loads the TSIG into the TSIG structure into the message
 * 
 * Works fine for questions but for answer it needs to match a previous setup.
 * 
 * @param mesg          the message
 * @param purd          a packet reader at the position of the TSIG record
 * @param tsig_offset
 * @param tsigname
 * @param tctr
 * @return 
 */

ya_result
tsig_process(message_data *mesg, packet_unpack_reader_data *purd, u32 tsig_offset, const tsig_item *tsig, struct type_class_ttl_rdlen *tctr)
{
    u16 ar_count = message_get_additional_count(mesg);
    u8 algorithm[256];
    
    if((tctr->qclass == CLASS_ANY) && (tctr->ttl == 0))
    {
        /*
         * Check if the key is known to us
         *
         * We must know the key, else there is a few error options available.
         */

        if(tsig == NULL)
        {
            /* oops */

            /**
             * If a non-forwarding server does not recognize the key used by the
             * client, the server MUST generate an error response with RCODE 9
             * (NOTAUTH) and TSIG ERROR 17 (BADKEY).
             *
             * The server SHOULD log the error.
             *
             */

            mesg->_tsig.error = NU16(RCODE_BADKEY);
            message_set_status(mesg, FP_RCODE_NOTAUTH); // no fingerprint here, it's RFC
            message_set_rcode(mesg, RCODE_NOTAUTH);

            return TSIG_BADKEY;
        }
        
        /*
         * Got the TSIG:
         *
         *
         * Now we can remove the tsig from the AR.
         */

        ya_result return_code;

        message_set_size(mesg, tsig_offset);
        message_set_additional_count(mesg, ar_count - 1);

        /*
         * Read the algorithm name and see if it matches our TSIG key
         */

        if(FAIL(return_code = packet_reader_read_fqdn(purd, algorithm, sizeof(algorithm))))
        {
            /* oops */

            mesg->_tsig.error = NU16(RCODE_BADKEY);
            message_set_status(mesg, FP_TSIG_BROKEN);
            return TSIG_BADKEY; // format error reading the key name
        }

        u8 alg = tsig_get_algorithm(algorithm);

        if(tsig->mac_algorithm != alg)
        {
            /* oops */

            mesg->_tsig.error = NU16(RCODE_BADKEY);
            message_set_status(mesg, FP_TSIG_ERROR);
            return TSIG_BADKEY; // mismatched algorithm
        }

        /*
         * Save the TSIG.
         */
        
        mesg->_tsig.other = NULL;
        mesg->_tsig.tsig = tsig;
        mesg->_tsig.mac_algorithm = alg;
        
        if(FAIL(return_code = packet_reader_read(purd, &mesg->_tsig.timehi, 10)))
        {
            /* oops */
            message_set_status(mesg, FP_TSIG_BROKEN);
            return TSIG_FORMERR;
        }
        
        /* Check the time */

        /**
         *
         * If the server time is outside the time interval specified by the
         * request (which is: Time Signed, plus/minus Fudge), the server MUST
         * generate an error response with RCODE 9 (NOTAUTH) and TSIG ERROR 18 (BADTIME).
         *
         * I cannot use time_t because on some systems time_t is 32 bits.  I need more.
         * The next best thing is u64
         */

        u64 then = (u64)ntohs(mesg->_tsig.timehi);
        then <<= 32;
        then |= (u64)ntohl(mesg->_tsig.timelo);

        u64 now = time(NULL);

        s64 fudge = ntohs(mesg->_tsig.fudge);

        u16 mac_size = ntohs(mesg->_tsig.mac_size);  /* NETWORK => NATIVE */

        if(mac_size > sizeof(mesg->_tsig.mac))
        {
            /* oops */
            message_set_status(mesg, FP_TSIG_BROKEN);
            return TSIG_FORMERR;
        }

        mesg->_tsig.mac_size = mac_size;

        if(FAIL(return_code = packet_reader_read(purd, mesg->_tsig.mac, mac_size)))
        {
            /* oops */
            message_set_status(mesg, FP_TSIG_BROKEN);
            return TSIG_FORMERR;
        }

        if(FAIL(return_code = packet_reader_read(purd, &mesg->_tsig.original_id, 6))) // and error, and other len
        {
            /* oops */
            message_set_status(mesg, FP_TSIG_BROKEN);
            return TSIG_FORMERR;
        }

        if(mesg->_tsig.other_len != 0)
        {
            /**
             * @note This should never be run in input queries ...
             */

            u16 other_len = ntohs(mesg->_tsig.other_len);

            MALLOC_OR_DIE(u8*, mesg->_tsig.other, other_len, TSIGOTHR_TAG);

            if(FAIL(return_code = packet_reader_read(purd, mesg->_tsig.other, other_len)))
            {
                /* oops */

                free(mesg->_tsig.other);
                mesg->_tsig.other = NULL;
                message_set_status(mesg, FP_TSIG_BROKEN);
                return TSIG_FORMERR;
            }
        }
        
        if(llabs((s64)((s64)then - now)) > fudge) // cast to signed in case now > then
        {
            mesg->_tsig.error = NU16(RCODE_BADTIME);
            message_set_status(mesg, FP_TSIG_ERROR); // MUST be NOTAUTH
            return TSIG_BADTIME;
        }

        /*
         * We can now process the wire and compute the HMAC
         * Note that if message_id != original_message_id, then message_id replaces original_message_id
         */

        return SUCCESS;
    }

    /* error : tsig but wrong tsig setup */
    message_set_status(mesg, FP_TSIG_BROKEN);
    return TSIG_FORMERR;
}

ya_result
tsig_process_query(message_data *mesg, packet_unpack_reader_data *purd, u32 tsig_offset, u8 tsigname[MAX_DOMAIN_LENGTH], struct type_class_ttl_rdlen *tctr)
{
    ya_result return_value;
    
    tsig_item *tsig = tsig_get(tsigname);
    
    if(ISOK(return_value = tsig_process(mesg, purd, tsig_offset, tsig, tctr)))
    {
        if(ISOK(return_value = tsig_verify_query(mesg)))
        {
            return return_value;
        }
        
        // tsig process may have allocated tsig other
        
        free(mesg->_tsig.other);
        mesg->_tsig.other = NULL;
        mesg->_tsig.error = htons(RCODE_BADSIG);
    }
    
    switch(return_value)
    {
        case TSIG_FORMERR:
            break;
        case TSIG_BADTIME:
            tsig_append_error(mesg);
            break;
        default:
            tsig_append_unsigned_error(mesg);
            break;
    }

    return return_value;
}

/**
 * Extracts and verifies the TSIG in an (answer) message.
 * 
 * @param mesg the message
 * @param purd a packet reader set for the message
 * @param tsig_offset the position of the tsig
 * @param tsig 
 * @param tctr
 * @return 
 */

ya_result
tsig_process_answer(message_data *mesg, packet_unpack_reader_data *purd, u32 tsig_offset, struct type_class_ttl_rdlen *tctr)
{
    ya_result return_value;
    
    int mac_size = message_tsig_mac_get_size(mesg);
    u8 mac[64];

    assert(mac_size <= (int)sizeof(mac));
    
    message_tsig_mac_copy(mesg, mac);
    
    // extract the tsig
    
    if(ISOK(return_value = tsig_process(mesg, purd, tsig_offset, message_tsig_get_key(mesg), tctr)))
    {
        // verify the tsig in the answer
        
        if(FAIL(return_value = tsig_verify_answer(mesg, mac, mac_size)))
        {
            /* oops */

            free(mesg->_tsig.other);
            mesg->_tsig.other = NULL;
            mesg->_tsig.error = htons(RCODE_BADSIG);

            tsig_append_error(mesg);
        }        
    }
    
    return return_value;
}



/**
 * Extracts the TSIG from the message
 *
 * Reads all the records but the last AR one
 */

ya_result
tsig_extract_and_process(message_data *mesg)
{
    /*yassert(message_is_additional_section_ptr_set(mesg));*/

    /*
     * rfc2845
     *
     * If there is a TSIG then
     * _ It must be put aside, safely
     * _ It must be removed from the query
     * _ It must be processed
     *
     * rfc2671
     *
     * Handle OPT
     *
     */

    /*
     * Read DNS name (decompression on)
     * Read type (TSIG = 250)
     * Read class (ANY)
     * Read TTL (0)
     * Read RDLEN
     *
     */

    packet_unpack_reader_data purd;
    
    purd.packet = message_get_buffer_const(mesg);
    purd.packet_size = message_get_size(mesg);

    if(!message_is_additional_section_ptr_set(mesg))
    {
        u32 tsig_index = message_get_answer_count(mesg) +
                message_get_authority_count(mesg) +
                message_get_additional_count(mesg) - 1;
        purd.offset = DNS_HEADER_LENGTH; /* Header */
        packet_reader_skip_fqdn(&purd); /* Query DNAME */
        purd.offset += 4; /* TYPE CLASS */

        while(tsig_index-- > 0) /* Skip all AR records but the last one */
        {
            /*
             * It should be in this kind of processing that we read the EDNS0 flag
             */

            packet_reader_skip_record(&purd);
        }

        message_set_additional_section_ptr(mesg, (void*)packet_reader_get_next_u8_ptr_const(&purd));
    }
    else
    {
        packet_reader_set_position(&purd, message_get_additional_section_ptr(mesg) - message_get_buffer(mesg));
    }

    struct type_class_ttl_rdlen tctr;

    u32 record_offset = purd.offset;

    u8 tsigname[MAX_DOMAIN_LENGTH];

    if(FAIL(packet_reader_read_fqdn(&purd, tsigname, sizeof(tsigname))))
    {
        /* oops */

        return TSIG_FORMERR;
    }

    /*yassert(((u8*)&tctr.rdlen) - ((u8*)&tctr.qtype) == 8);*/

    if(ISOK(packet_reader_read(&purd, &tctr, 10))) // exact
    {
        if(tctr.qtype == TYPE_TSIG) /* && (tctr.qclass == TYPE_ANY) && (tctr.ttl == 0 )*/
        {
            /* It must be the last AR record, class = ANY and TTL = 0 */

            return tsig_process_query(mesg, &purd, record_offset, tsigname, &tctr);

        } /* if type is TSIG */

        /* AR but not a TSIG  : there is just no TSIG in this packet */

        message_tsig_clear_key(mesg);
    }

    return TSIG_FORMERR;
}

/**
 * Adds the TSIG to the message
 *
 */

ya_result
tsig_add_tsig(message_data *mesg)
{
    u16 ar_count = message_get_additional_count(mesg);

    /* Converted after network read ... so why do I do this ? */
    u16 mac_size = mesg->_tsig.mac_size;
    u16 other_len = ntohs(mesg->_tsig.other_len);

    if(message_get_buffer_size(mesg) < message_get_size(mesg) +         // valid use of message_get_buffer_size()
                                       message_tsig_get_key(mesg)->name_len + /* DNS NAME of the TSIG (name of the key) */
                                       mac_size + /* MAC */
                                       other_len + /* OTHER DATA */
                                       12) /* time + fudge + mac size + original id + error + other len = 12 bytes */
    {
        /* Cannot sign because of truncation */
        message_set_truncated_answer(mesg);

        return TSIG_SIZE_LIMIT_ERROR;
    }

    u8 *tsig_ptr = message_get_buffer_limit(mesg);

    /* record */

    memcpy(tsig_ptr, mesg->_tsig.tsig->name, mesg->_tsig.tsig->name_len);
    tsig_ptr += mesg->_tsig.tsig->name_len;

    memcpy(tsig_ptr, tsig_typeclassttl, sizeof(tsig_typeclassttl));
    tsig_ptr += sizeof(tsig_typeclassttl);
    u16 *rdata_size_ptr = (u16*)tsig_ptr;
    tsig_ptr += 2;

    /* rdata */

    memcpy(tsig_ptr, mesg->_tsig.tsig->mac_algorithm_name, mesg->_tsig.tsig->mac_algorithm_name_len);
    tsig_ptr += mesg->_tsig.tsig->mac_algorithm_name_len;

    SET_U16_AT(tsig_ptr[0], mesg->_tsig.timehi);
    SET_U32_AT(tsig_ptr[2], mesg->_tsig.timelo);
    SET_U16_AT(tsig_ptr[6], mesg->_tsig.fudge);
    SET_U16_AT(tsig_ptr[8], htons(mesg->_tsig.mac_size));

    memcpy(&tsig_ptr[10], mesg->_tsig.mac, mac_size);
    tsig_ptr += mac_size + 10;

    SET_U16_AT(tsig_ptr[0], mesg->_tsig.original_id);
    SET_U16_AT(tsig_ptr[2], mesg->_tsig.error);
    SET_U16_AT(tsig_ptr[4], mesg->_tsig.other_len);

    tsig_ptr += 6;

    if(mesg->_tsig.other_len != 0)
    {
        yassert(mesg->_tsig.other != NULL);
        memcpy(tsig_ptr, mesg->_tsig.other, other_len);
        tsig_ptr += other_len;
    }

    u16 rdata_size = (tsig_ptr - (u8*)rdata_size_ptr) - 2;

    SET_U16_AT(*rdata_size_ptr, htons(rdata_size));

    message_set_size(mesg, tsig_ptr - message_get_buffer(mesg));

    message_set_additional_count(mesg, ar_count + 1);
    
    return SUCCESS;
}

/**
 * Signs the message answer with its TSIG
 */

ya_result
tsig_sign_answer(message_data *mesg)
{
    yassert(message_is_additional_section_ptr_set(mesg));
    
    ya_result ret;

    tsig_update_time(mesg);
    
    if(ISOK(ret = tsig_digest_answer(mesg)))
    {
        ret = tsig_add_tsig(mesg);
    }
    
    return ret;
}

/**
 * Signs the message query with its TSIG
 */

ya_result
tsig_sign_query(message_data *mesg)
{
    yassert(message_is_additional_section_ptr_set(mesg));
    
    ya_result ret;
    
    tsig_update_time(mesg);
    
    if(ISOK(ret = tsig_digest_query(mesg)))
    {
        ret = tsig_add_tsig(mesg);
    }
    
    return ret;
}

/**
 * On a RECEIVED message.
 *
 *  Adds a TSIG error to the message
 *
 */

ya_result
tsig_append_unsigned_error(message_data *mesg)
{
    yassert(message_is_additional_section_ptr_set(mesg));

    u16 ar_count = message_get_additional_count(mesg);

    packet_unpack_reader_data purd;
    packet_reader_init_from_message(&purd, mesg);
    
    packet_reader_skip_fqdn(&purd);
    purd.offset += 4;
    message_set_size(mesg, purd.offset);
    
    message_set_query_answer_authority_additional_counts_ne(mesg, NU16(1), 0, 0, 0);

    if(!message_has_tsig(mesg) ||
            message_get_buffer_size(mesg) < message_get_size(mesg) + // valid use of message_get_buffer_size()
            mesg->_tsig.tsig->name_len + /* DNS NAME of the TSIG (name of the key) */
            0 + /* MAC */
            0 + /* OTHER DATA */
            12 /*DO NOT REPLACE*/) /* = time + fudge + mac size + original id + error + other len */
    {
        /* Cannot sign */

        return TSIG_UNABLE_TO_SIGN;
    }

    u8 *tsig_ptr = message_get_buffer_limit(mesg);

    /* record */

    memcpy(tsig_ptr, mesg->_tsig.tsig->name, mesg->_tsig.tsig->name_len);
    tsig_ptr += mesg->_tsig.tsig->name_len;

    memcpy(tsig_ptr, tsig_typeclassttl, sizeof(tsig_typeclassttl));
    tsig_ptr += sizeof(tsig_typeclassttl);
    u16 *rdata_size_ptr = (u16*)tsig_ptr;
    tsig_ptr += 2;

    /* rdata */

    memcpy(tsig_ptr, mesg->_tsig.tsig->mac_algorithm_name, mesg->_tsig.tsig->mac_algorithm_name_len);
    tsig_ptr += mesg->_tsig.tsig->mac_algorithm_name_len;

    SET_U16_AT(tsig_ptr[ 0], mesg->_tsig.timehi);
    SET_U32_AT(tsig_ptr[ 2], mesg->_tsig.timelo);
    SET_U16_AT(tsig_ptr[ 6], mesg->_tsig.fudge);
    SET_U16_AT(tsig_ptr[ 8], 0); /* MAC len */
    SET_U16_AT(tsig_ptr[10], mesg->_tsig.original_id);
    SET_U16_AT(tsig_ptr[12], mesg->_tsig.error);
    SET_U16_AT(tsig_ptr[14], 0); /* Error len */

    tsig_ptr += 16;

    u16 rdata_size = (tsig_ptr - (u8*)rdata_size_ptr) - 2;

    SET_U16_AT(*rdata_size_ptr, htons(rdata_size));

    message_set_size(mesg, tsig_ptr - message_get_buffer(mesg));

    message_set_additional_count(mesg, ar_count + 1);

    return SUCCESS;
}

ya_result
tsig_append_error(message_data *mesg)
{
    yassert(message_is_additional_section_ptr_set(mesg));
    
    message_update_answer_status(mesg);
    tsig_sign_answer(mesg);

    return SUCCESS;
}

ya_result
tsig_sign_tcp_first_message(struct message_data *mesg)
{
    ya_result ret = tsig_sign_answer(mesg);

    /* I must NOT clear the digest memory : it has already been done at the end of tsig_sign_answer */

    if(FAIL(ret))
    {
        return ret;
    }

    /*
     * Reset the digest
     *
     * Digest the digest (mesg->_tsig.mac, mesg->_tsig.mac_size (NETWORK ORDERED!))
     */

    yassert(mesg->_tsig.hmac == NULL); // ensure it's clean

    mesg->_tsig.hmac = tsig_hmac_allocate();

    if(mesg->_tsig.hmac == NULL)
    {
        return INVALID_STATE_ERROR;
    }

    if(FAIL(hmac_init(mesg->_tsig.hmac, message_tsig_get_key_bytes(mesg), message_tsig_get_key_size(mesg), mesg->_tsig.tsig->mac_algorithm)))
    {
        hmac_free(mesg->_tsig.hmac);
        mesg->_tsig.hmac = NULL;
        return ERROR;
    }

    u16 mac_size_ne = htons(mesg->_tsig.mac_size);
    
#if LOG_DIGEST_INPUT
    log_debug("tsig_sign_tcp_first_message(%p = %{dnsname} %{dnstype} %{dnsclass})",
            mesg, message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), message_get_query_class_ptr(mesg));
#endif
    
#if LOG_DIGEST_INPUT
    log_debug("tsig_sign_tcp_first_message: previous digest: (%p)", mesg);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) &mac_size_ne, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->_tsig.mac, mesg->_tsig.mac_size, 32);
#endif

    hmac_update(mesg->_tsig.hmac, (u8*) &mac_size_ne, 2);
    hmac_update(mesg->_tsig.hmac, mesg->_tsig.mac, mesg->_tsig.mac_size);

    mesg->_tsig.tcp_tsig_countdown = TSIG_TCP_PERIOD;

    return SUCCESS;
}

ya_result
tsig_sign_tcp_next_message(struct message_data *mesg)
{
    /*
     * Digest the message
     */

#if LOG_DIGEST_INPUT
    log_debug("tsig_sign_tcp_next_message(%p = %{dnsname} %{dnstype} %{dnsclass})",
            mesg, message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), message_get_query_class_ptr(mesg));
#endif

    hmac_update(mesg->_tsig.hmac, message_get_buffer_const(mesg), message_get_size(mesg));

    /*
     * If it's the 100th since the last TSIG, then ...
     */

    if(--mesg->_tsig.tcp_tsig_countdown == 0)
    {
        mesg->_tsig.tcp_tsig_countdown = TSIG_TCP_PERIOD;

        /*
         * Digest the time
         */
        
        tsig_update_time(mesg);

        hmac_update(mesg->_tsig.hmac, (u8*) & mesg->_tsig.timehi, 2);
        hmac_update(mesg->_tsig.hmac, (u8*) & mesg->_tsig.timelo, 4);
        hmac_update(mesg->_tsig.hmac, (u8*) & mesg->_tsig.fudge, 2);

        u32 tmp_mac_size;
        hmac_final(mesg->_tsig.hmac, mesg->_tsig.mac, &tmp_mac_size);

        /*
         * Store the TSIG
         */

        tsig_add_tsig(mesg);

        /*
         * Reset the digest
         *
         * Digest the digest
         */

        hmac_reset(mesg->_tsig.hmac);
        
        if(FAIL(hmac_init(mesg->_tsig.hmac, message_tsig_get_key_bytes(mesg), message_tsig_get_key_size(mesg), mesg->_tsig.tsig->mac_algorithm)))
        {
            return ERROR;
        }

        u16 mac_size_ne = htons(mesg->_tsig.mac_size);

#if LOG_DIGEST_INPUT
        log_debug("tsig_sign_tcp_first_message: previous digest: (%p)", mesg);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) &mac_size_ne, 2, 32);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->_tsig.mac, mesg->_tsig.mac_size, 32);
#endif

        hmac_update(mesg->_tsig.hmac, (u8*) &mac_size_ne, 2);
        hmac_update(mesg->_tsig.hmac, mesg->_tsig.mac, mesg->_tsig.mac_size);
    }

    return SUCCESS;
}

ya_result
tsig_sign_tcp_last_message(struct message_data *mesg)
{
    /*
     * Digest the message
     */

#if LOG_DIGEST_INPUT
    log_debug("tsig_sign_tcp_last_message(%p = %{dnsname} %{dnstype} %{dnsclass})",
            mesg, message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), message_get_query_class_ptr(mesg));
#endif

    hmac_update(mesg->_tsig.hmac, message_get_buffer_const(mesg), message_get_size(mesg));

    /*
     * If it's the 100th since the last TSIG, then ...
     */

    mesg->_tsig.tcp_tsig_countdown = 0;

    /*
     * Digest the time
     */
    
    tsig_update_time(mesg);

    hmac_update(mesg->_tsig.hmac, (u8*) & mesg->_tsig.timehi, 2);
    hmac_update(mesg->_tsig.hmac, (u8*) & mesg->_tsig.timelo, 4);
    hmac_update(mesg->_tsig.hmac, (u8*) & mesg->_tsig.fudge, 2);

    u32 tmp_mac_size;
    hmac_final(mesg->_tsig.hmac, mesg->_tsig.mac, &tmp_mac_size);

    /*
     * Store the TSIG
     */

    tsig_add_tsig(mesg);

    hmac_free(mesg->_tsig.hmac);
    mesg->_tsig.hmac = NULL;

    return SUCCESS;
}

/**
 * If the message has no TSIG to do, it is considered to be successful.
 */

ya_result
tsig_sign_tcp_message(struct message_data *mesg, tsig_tcp_message_position pos)
{
    ya_result return_code = SUCCESS;

    if(message_has_tsig(mesg))
    {
        switch(pos)
        {
            case TSIG_START:
            {
                return_code = tsig_sign_tcp_first_message(mesg);
                break;
            }
            case TSIG_MIDDLE:
            {
                return_code = tsig_sign_tcp_next_message(mesg);
                break;
            }
            case TSIG_END:
            {
                return_code = tsig_sign_tcp_last_message(mesg);
                break;
            }
            case TSIG_WHOLE:    /* one packet message */
            {
                return_code = tsig_sign_answer(mesg);
                break;
            }
            case TSIG_NOWHERE:
            {
                break;
            }
        }
    }

    return return_code;
}

ya_result
tsig_verify_tcp_first_message(struct message_data *mesg, const u8 *mac, u16 mac_size)
{
#if LOG_DIGEST_INPUT
    log_debug("tsig_verify_tcp_first_message: first verify: (%p)", mesg);
#endif
    
    ya_result ret = tsig_verify_answer(mesg, mac, mac_size);

    /* I must NOT clear the digest memory : it has already been done at the end of tsig_sign */

    if(FAIL(ret))
    {
        return ret;
    }

    /*
     * Reset the digest
     *
     * Digest the digest (mesg->_tsig.mac, mesg->_tsig.mac_size (NETWORK ORDERED!))
     */

    yassert(mesg->_tsig.hmac == NULL); // ensure it's clean

    mesg->_tsig.hmac = tsig_hmac_allocate();

    if(mesg->_tsig.hmac == NULL)
    {
        return INVALID_STATE_ERROR;
    }

    if(FAIL(hmac_init(mesg->_tsig.hmac, message_tsig_get_key_bytes(mesg), message_tsig_get_key_size(mesg), mesg->_tsig.tsig->mac_algorithm)))
    {
        hmac_free(mesg->_tsig.hmac);
        mesg->_tsig.hmac = NULL;
        return ERROR;
    }

    u16 mac_size_network = htons(mesg->_tsig.mac_size);

#if LOG_DIGEST_INPUT
    log_debug("tsig_verify_tcp_first_message: previous MAC: (%p)", mesg);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mac_size_network, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->_tsig.mac, mesg->_tsig.mac_size, 32);
#endif

    hmac_update(mesg->_tsig.hmac, (u8*) & mac_size_network, 2);
    hmac_update(mesg->_tsig.hmac, mesg->_tsig.mac, mesg->_tsig.mac_size);

    mesg->_tsig.tcp_tsig_countdown = TSIG_TCP_PERIOD + 2;    /* be a bit lenient */

    return SUCCESS;
}

ya_result
tsig_verify_tcp_next_message(struct message_data *mesg)
{
    /*
     * Digest the message
     */

    u8 mac[64];

#if LOG_DIGEST_INPUT
    log_debug("tsig_verify_tcp_next_message: message: (%p)", mesg);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, message_get_buffer_const(mesg), message_get_size(mesg), 32);
#endif

    if(mesg->_tsig.tcp_tsig_countdown-- < 0)
    {
        return TSIG_BADSIG;
    }

    hmac_update(mesg->_tsig.hmac, message_get_buffer_const(mesg), message_get_size(mesg));

    /*
     * If it has been signed ...
     */

    if(mesg->_tsig.tsig != NULL)
    {
        mesg->_tsig.tcp_tsig_countdown = TSIG_TCP_PERIOD + 2;    /* be a bit lenient */

        /*
         * Digest the time
         */

#if LOG_DIGEST_INPUT
        log_debug("tsig_verify_tcp_next_message: timers: (%p)", mesg);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->_tsig.timehi, 2, 32);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->_tsig.timelo, 4, 32);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->_tsig.fudge, 2, 32);
#endif

        hmac_update(mesg->_tsig.hmac, (u8*) & mesg->_tsig.timehi, 2);
        hmac_update(mesg->_tsig.hmac, (u8*) & mesg->_tsig.timelo, 4);
        hmac_update(mesg->_tsig.hmac, (u8*) & mesg->_tsig.fudge, 2);

        u32 tmp_mac_size;
        hmac_final(mesg->_tsig.hmac, mac, &tmp_mac_size);
        
#if LOG_DIGEST_INPUT
        log_debug("tsig_verify_tcp_next_message: value:", mesg);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) mac, tmp_mac_size, 32);
        log_debug("tsig_verify_tcp_next_message: expected:", mesg);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) mesg->_tsig.mac, tmp_mac_size, 32);
#endif

        if(memcmp(mesg->_tsig.mac, mac, tmp_mac_size) != 0)
        {
            log_debug("tsig_verify_tcp_next_message: BADSIG");
            hmac_free(mesg->_tsig.hmac);
            mesg->_tsig.hmac = NULL;
            return TSIG_BADSIG;
        }

        /*
         * Reset the digest
         *
         * Digest the digest
         */

        hmac_reset(mesg->_tsig.hmac);
        
        if(FAIL(hmac_init(mesg->_tsig.hmac, message_tsig_get_key_bytes(mesg), message_tsig_get_key_size(mesg), mesg->_tsig.tsig->mac_algorithm)))
        {
            return ERROR;
        }

        u16 mac_size_network = htons(mesg->_tsig.mac_size);

#if LOG_DIGEST_INPUT
        log_debug("tsig_verify_tcp_next_message: previous MAC: (%p)", mesg);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mac_size_network, 2, 32);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->_tsig.mac, mesg->_tsig.mac_size, 32);
#endif

        hmac_update(mesg->_tsig.hmac, (u8*) & mac_size_network, 2);
        hmac_update(mesg->_tsig.hmac, mesg->_tsig.mac, mesg->_tsig.mac_size);
    }
    
    return SUCCESS;
}

/**
 * This only cleans-up after the verify
 * 
 * @param mesg
 */

void 
tsig_verify_tcp_last_message(struct message_data *mesg)
{
    /*
     * Clear the digest
     */
    
#if LOG_DIGEST_INPUT
    log_debug("tsig_verify_tcp_last_message: message: (%p)", mesg);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, message_get_buffer_const(mesg), message_get_size(mesg), 32);
#endif
    message_clear_hmac(mesg);
}


/**
 * Skips the header and all the records but the last AR.
 *
 * Does NOT care about errors but the ones preventing it to find the TSIG record
 *
 * Extract the TSIG
 * Decreases AR
 * Decreases the size of the message.
 * 
 * Whole-message processing should avoid this as it does the job twice ...
 */

ya_result
tsig_message_extract(struct message_data *mesg)
{
    packet_unpack_reader_data reader;
    ya_result return_value;
    
    u16 ar_count = message_get_additional_count_ne(mesg); // will change endian after this

    if( ar_count == 0)
    {
        return 0;   /* no TSIG */
    }
    
    ar_count = ntohs(ar_count);

    u16 qd = message_get_query_count(mesg);
    u16 an = message_get_answer_count(mesg);
    u16 ns = message_get_authority_count(mesg);

    packet_reader_init(&reader, message_get_buffer_const(mesg), message_get_size(mesg));
    reader.offset = DNS_HEADER_LENGTH;
    
    while(qd > 0)
    {
        if(FAIL(return_value = packet_reader_skip_fqdn(&reader)))
        {
            return return_value;
        }
        
        if(FAIL(return_value = packet_reader_skip(&reader, 4)))
        {
            return return_value;
        }

        qd--;
    }
    
    u16 n = an + ns + ar_count - 1;

    while(n > 0)
    {
        if(FAIL(return_value = packet_reader_skip_record(&reader)))
        {
            return return_value;
        }

        n--;
    }

    /* The following record is supposed to be a TSIG */

    u32 tsig_offset = reader.offset;

    u8 fqdn[MAX_DOMAIN_LENGTH];

    if(FAIL(return_value = packet_reader_read_fqdn(&reader, fqdn, sizeof(fqdn))))
    {
        return return_value;
    }

    struct type_class_ttl_rdlen tctr;
    
    if(FAIL(return_value = packet_reader_read(&reader, &tctr, 10)))
    {
        return return_value;
    }

    if(tctr.qtype != TYPE_TSIG)
    {
        return 0;
    }
    
    if(tctr.qclass != CLASS_ANY)
    {
        return TSIG_FORMERR;
    }

    if(tctr.ttl != 0)
    {
        return TSIG_FORMERR;
    }

    tsig_item *tsig = tsig_get(fqdn);

    if(tsig == NULL)
    {
        return TSIG_BADKEY;
    }

    s32 len = ntohs(tctr.rdlen) - 16;

    if(len < 3 + 3) /* minimum for the fixed bytes + two relevant fqdn */
    {
        return TSIG_FORMERR;
    }

    if(FAIL(return_value = packet_reader_read_fqdn(&reader, fqdn, sizeof(fqdn))))
    {
        return return_value;
    }

    len -= return_value;

    packet_reader_read_u16(&reader, &mesg->_tsig.timehi);
    packet_reader_read_u32(&reader, &mesg->_tsig.timelo);    
    packet_reader_read_u16(&reader, &mesg->_tsig.fudge);
    packet_reader_read_u16(&reader, &mesg->_tsig.mac_size);

    u16 mac_size = ntohs(mesg->_tsig.mac_size);

    mesg->_tsig.mac_size = mac_size;

    if(mac_size > sizeof(mesg->_tsig.mac))
    {
        return TSIG_BADKEY; /* The key is bigger than anything supported */
    }

    if(FAIL(return_value = packet_reader_read(&reader, mesg->_tsig.mac, mac_size)))
    {
        return return_value;
    }

    len -= return_value;

    packet_reader_read_u16(&reader, &mesg->_tsig.original_id);
    packet_reader_read_u16(&reader, &mesg->_tsig.error);
    
    if(FAIL(return_value = packet_reader_read_u16(&reader, &mesg->_tsig.other_len)))
    {
        return return_value;
    }

    u16 other_len = ntohs(mesg->_tsig.other_len);

    len -= other_len;

    if(len != 0)
    {
        return TSIG_FORMERR;
    }

    mesg->_tsig.other = NULL;

    mesg->_tsig.tsig = tsig;

    mesg->_tsig.mac_algorithm = tsig->mac_algorithm;

    message_set_size(mesg, tsig_offset);

    message_set_additional_count(mesg, ar_count - 1);

    return 1;   /* got 1 signature */
}

#endif

/** @} */

