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
/** @defgroup ### #######
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#include <stdio.h>
#include <stdlib.h>

#include "dnscore-config.h"

#include "dnscore/message.h" // DO NOT REMOVE ME
#include "dnscore/tsig.h"
#include "dnscore/packet_reader.h"

#if DNSCORE_HAS_TSIG_SUPPORT

#define TSIGNODE_TAG 0x45444f4e47495354
#define TSIGPAYL_TAG 0x4c59415047495354
#define TSIGMAC_TAG 0x43414d47495354
#define TSIGOTHR_TAG 0x5248544f47495354

#define MODULE_MSG_HANDLE g_system_logger

#define LOG_DIGEST_INPUT 0

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
 * Worst case : N is enough for sum[n = 0,N](Fn) where F is Fibonacci
 * Best case : N is enough for (2^(N+1))-1
 */
#define AVL_MAX_DEPTH   32	/* worst case scenario : about 9M keys */

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

    tsig_node *node = tsig_avl_insert(&tsig_tree, name);

    if(node != NULL)
    {
        if(node->item.mac != NULL)
        {
            bool same = (node->item.mac_size == mac_size)                 &&
                        (node->item.mac_algorithm == mac_algorithm)       &&
                        (memcmp((u8*)node->item.mac, mac, mac_size) == 0);
            
            if(node->item.load_serial != tsig_serial)
            {
                if(same)
                {
                    // same key, different instances ... nothing to do
                    
                    return SUCCESS;
                }
                else
                {
                    // this is an old version of the key
                    
                    free((void*)node->item.mac);
                    node->item.mac = NULL;
                }
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

        node->item.evp_md = tsig_get_EVP_MD(mac_algorithm);
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
        return_code = ERROR; /* internal error */
    }

    return return_code;
}

tsig_item*
tsig_get(const u8 *name)
{
    tsig_node *node = tsig_avl_find(&tsig_tree, name);

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
    if(index < 0 || index >= tsig_tree_count)
    {
        return NULL;
    }
    
    tsig_avl_iterator iter;
    tsig_avl_iterator_init(&tsig_tree, &iter);
    
    while(tsig_avl_iterator_hasnext(&iter))
    {
        tsig_node *node = tsig_avl_iterator_next_node(&iter);
        
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
    tsig_avl_destroy(&tsig_tree);
    tsig_finalize_algorithms();
}

static u8 tsig_typeclassttl[8] = {0x00, 0xfa, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00};
static u8 tsig_classttl[6] = {0x00, 0xff, 0x00, 0x00, 0x00, 0x00};
static u8 tsig_noerror_noother[4] = {0x00, 0x00, 0x00, 0x00};

static ya_result
tsig_verify_query(message_data *mesg)
{
    u32 md_len = 0;
    u8 md[EVP_MAX_MD_SIZE];

#if LOG_DIGEST_INPUT >= 2
    log_debug("tsig_verify: %hx", mesg->tsig.mac_size);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.mac_size, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.tsig->mac, mesg->tsig.tsig->mac_size, 32);
    log_debug("tsig_verify: start");
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->buffer, mesg->send_length, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.tsig->name, mesg->tsig.tsig->name_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, tsig_classttl, sizeof (tsig_classttl), 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.tsig->mac_algorithm_name, mesg->tsig.tsig->mac_algorithm_name_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.timehi, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.timelo, 4, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.fudge, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.error, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.other_len, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.other, ntohs(mesg->tsig.other_len), 32);
    log_debug("tsig_verify: stop");
#endif

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

    HMAC_Init(&ctx, mesg->tsig.tsig->mac, mesg->tsig.tsig->mac_size, mesg->tsig.tsig->evp_md);

    /* DNS message */

    HMAC_Update(&ctx, mesg->buffer, mesg->received);

    /* TSIG Variables */

    HMAC_Update(&ctx, mesg->tsig.tsig->name, mesg->tsig.tsig->name_len);
    HMAC_Update(&ctx, tsig_classttl, sizeof (tsig_classttl));
    HMAC_Update(&ctx, mesg->tsig.tsig->mac_algorithm_name, mesg->tsig.tsig->mac_algorithm_name_len);
    HMAC_Update(&ctx, (u8*) & mesg->tsig.timehi, 2);
    HMAC_Update(&ctx, (u8*) & mesg->tsig.timelo, 4);
    HMAC_Update(&ctx, (u8*) & mesg->tsig.fudge, 2);
    HMAC_Update(&ctx, (u8*) & mesg->tsig.error, 2);
    HMAC_Update(&ctx, (u8*) & mesg->tsig.other_len, 2);

    if(mesg->tsig.other_len != 0)
    {
        HMAC_Update(&ctx, mesg->tsig.other, ntohs(mesg->tsig.other_len));
    }

    HMAC_Final(&ctx, md, &md_len);

    HMAC_CTX_cleanup(&ctx);

    if((md_len != mesg->tsig.mac_size) || (memcmp(mesg->tsig.mac, md, md_len) != 0))
    {
        mesg->status = FP_TSIG_ERROR;
        mesg->tsig.error = NU16(RCODE_BADSIG);
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

#if LOG_DIGEST_INPUT >= 2
    log_debug("tsig_verify_answer: %hx", mesg->tsig.mac_size);
    log_debug("tsig_verify_answer: start");
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) &mac_size_network, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mac, mac_size, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->buffer, mesg->send_length, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.tsig->name, mesg->tsig.tsig->name_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, tsig_classttl, sizeof (tsig_classttl), 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.tsig->mac_algorithm_name, mesg->tsig.tsig->mac_algorithm_name_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) &mesg->tsig.timehi, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) &mesg->tsig.timelo, 4, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) &mesg->tsig.fudge, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) &mesg->tsig.error, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) &mesg->tsig.other_len, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.other, ntohs(mesg->tsig.other_len), 32);
    log_debug("tsig_verify_answer: stop");
#endif

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

    HMAC_Init(&ctx, mesg->tsig.tsig->mac, mesg->tsig.tsig->mac_size, mesg->tsig.tsig->evp_md);
    
    HMAC_Update(&ctx, (u8*) &mac_size_network, 2);
    HMAC_Update(&ctx, mac, mac_size);

    /* DNS message */

    HMAC_Update(&ctx, mesg->buffer, mesg->received);

    /* TSIG Variables */

    HMAC_Update(&ctx, mesg->tsig.tsig->name, mesg->tsig.tsig->name_len);
    HMAC_Update(&ctx, tsig_classttl, sizeof (tsig_classttl));
    HMAC_Update(&ctx, mesg->tsig.tsig->mac_algorithm_name, mesg->tsig.tsig->mac_algorithm_name_len);
    HMAC_Update(&ctx, (u8*) &mesg->tsig.timehi, 2);
    HMAC_Update(&ctx, (u8*) &mesg->tsig.timelo, 4);
    HMAC_Update(&ctx, (u8*) &mesg->tsig.fudge, 2);
    HMAC_Update(&ctx, (u8*) &mesg->tsig.error, 2);
    HMAC_Update(&ctx, (u8*) &mesg->tsig.other_len, 2);

    if(mesg->tsig.other_len != 0)
    {
        HMAC_Update(&ctx, mesg->tsig.other, ntohs(mesg->tsig.other_len));
    }

    HMAC_Final(&ctx, md, &md_len);

    HMAC_CTX_cleanup(&ctx);

    //if(md_len != ntohs(mesg->tsig.mac_size))
    if(md_len != mac_size)
    {
        mesg->status = FP_TSIG_ERROR;
        return TSIG_BADSIG;
    }

    if(memcmp(mesg->tsig.mac, md, md_len) != 0)
    {
        mesg->status = FP_TSIG_ERROR;
        return TSIG_BADSIG;
    }

    return SUCCESS;
}


static ya_result
tsig_digest_query(message_data *mesg)
{
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

    HMAC_Init(&ctx, mesg->tsig.tsig->mac, mesg->tsig.tsig->mac_size, mesg->tsig.tsig->evp_md);

    /* Request MAC */

#if LOG_DIGEST_INPUT >= 2
    log_debug("tsig_digest_query: %hx", mesg->tsig.mac_size);

    log_debug("tsig_digest_query: start");

    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->buffer, mesg->send_length, 32);

    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.tsig->name, mesg->tsig.tsig->name_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, tsig_classttl, sizeof (tsig_classttl), 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.tsig->mac_algorithm_name, mesg->tsig.tsig->mac_algorithm_name_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.timehi, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.timelo, 4, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.fudge, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.error, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.other_len, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.other, ntohs(mesg->tsig.other_len), 32);
    log_debug("tsig_digest_query: stop");
#endif

    /* DNS message */

    HMAC_Update(&ctx, mesg->buffer, mesg->send_length);

    /* TSIG Variables */

    HMAC_Update(&ctx, mesg->tsig.tsig->name, mesg->tsig.tsig->name_len);
    HMAC_Update(&ctx, tsig_classttl, sizeof (tsig_classttl));
    HMAC_Update(&ctx, mesg->tsig.tsig->mac_algorithm_name, mesg->tsig.tsig->mac_algorithm_name_len);
    HMAC_Update(&ctx, (u8*) & mesg->tsig.timehi, 2);
    HMAC_Update(&ctx, (u8*) & mesg->tsig.timelo, 4);
    HMAC_Update(&ctx, (u8*) & mesg->tsig.fudge, 2);
    // error is 0
    // other len is 0
    // no need to work on other data either (since other len is 0)
    HMAC_Update(&ctx, tsig_noerror_noother, 4); // four zeros

    u32 tmp_mac_size;
    HMAC_Final(&ctx, mesg->tsig.mac, &tmp_mac_size);
    mesg->tsig.mac_size = tmp_mac_size;

    HMAC_CTX_cleanup(&ctx);

    return SUCCESS;
}

static ya_result
tsig_digest_answer(message_data *mesg)
{
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

    HMAC_Init(&ctx, mesg->tsig.tsig->mac, mesg->tsig.tsig->mac_size, mesg->tsig.tsig->evp_md);

    /* Request MAC */

#if LOG_DIGEST_INPUT >= 2
    log_debug("tsig_digest_answer: %hx", mesg->tsig.mac_size);

    log_debug("tsig_digest_answer: start");
    
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.tsig->mac_size, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.tsig->mac, mesg->tsig.tsig->mac_size, 32);

    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->buffer, mesg->send_length, 32);

    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.tsig->name, mesg->tsig.tsig->name_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, tsig_classttl, sizeof (tsig_classttl), 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.tsig->mac_algorithm_name, mesg->tsig.tsig->mac_algorithm_name_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.timehi, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.timelo, 4, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.fudge, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.error, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.other_len, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.other, ntohs(mesg->tsig.other_len), 32);
    log_debug("tsig_digest_answer: stop");
#endif

    u16 mac_size_network = htons(mesg->tsig.mac_size);
    HMAC_Update(&ctx, (u8*) & mac_size_network, 2);
    HMAC_Update(&ctx, mesg->tsig.mac, mesg->tsig.mac_size);

    /* DNS message */

    HMAC_Update(&ctx, mesg->buffer, mesg->send_length);

    /* TSIG Variables */

    HMAC_Update(&ctx, mesg->tsig.tsig->name, mesg->tsig.tsig->name_len);
    HMAC_Update(&ctx, tsig_classttl, sizeof (tsig_classttl));
    HMAC_Update(&ctx, mesg->tsig.tsig->mac_algorithm_name, mesg->tsig.tsig->mac_algorithm_name_len);
    HMAC_Update(&ctx, (u8*) & mesg->tsig.timehi, 2);
    HMAC_Update(&ctx, (u8*) & mesg->tsig.timelo, 4);
    HMAC_Update(&ctx, (u8*) & mesg->tsig.fudge, 2);
    HMAC_Update(&ctx, (u8*) & mesg->tsig.error, 2);
    HMAC_Update(&ctx, (u8*) & mesg->tsig.other_len, 2);

    if(mesg->tsig.other_len != 0)
    {
        HMAC_Update(&ctx, mesg->tsig.other, ntohs(mesg->tsig.other_len));
    }

    u32 tmp_mac_size;
    HMAC_Final(&ctx, mesg->tsig.mac, &tmp_mac_size);
    mesg->tsig.mac_size = tmp_mac_size;

    HMAC_CTX_cleanup(&ctx);

    return SUCCESS;
}

/**
 * Extract the TSIG from a message
 * 
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
    u16 ar_count = MESSAGE_AR(mesg->buffer);
    u8 algorithm[256];
    
    ar_count = ntohs(ar_count);

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

            mesg->tsig.error = NU16(RCODE_BADKEY);
            mesg->status = RCODE_NOTAUTH; // no fingerprint here, it's RFC
            MESSAGE_LOFLAGS(mesg->buffer) = (MESSAGE_LOFLAGS(mesg->buffer)&~RCODE_BITS) | mesg->status;

            return TSIG_BADKEY;
        }
        
        /*
         * Got the TSIG:
         *
         *
         * Now we can remove the tsig from the AR.
         */

        ya_result return_code;

        mesg->received = tsig_offset;
        mesg->send_length = tsig_offset;
        MESSAGE_SET_AR(mesg->buffer,htons(ar_count - 1));

        /*
         * Read the algorithm name and see if it matches our TSIG key
         */

        if(FAIL(return_code = packet_reader_read_fqdn(purd, algorithm, sizeof (algorithm))))
        {
            /* oops */

            mesg->tsig.error = NU16(RCODE_BADKEY);
            mesg->status = FP_TSIG_BROKEN;
            return TSIG_BADKEY;
        }

        u8 alg = tsig_get_algorithm(algorithm);

        if(tsig->mac_algorithm != alg)
        {
            /* oops */

            mesg->tsig.error = NU16(RCODE_BADKEY);
            mesg->status = FP_TSIG_ERROR;
            return TSIG_BADKEY;
        }

        /*
         * Save the TSIG.
         */
        
        mesg->tsig.other = NULL;
        mesg->tsig.tsig = tsig;
        mesg->tsig.mac_algorithm = alg;
        
        if(FAIL(return_code = packet_reader_read(purd, &mesg->tsig.timehi, 10)))
        {
            /* oops */
            mesg->status = FP_TSIG_BROKEN;
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

        u64 then = ntohs(mesg->tsig.timehi);
        then <<= 32;
        then |= ntohl(mesg->tsig.timelo);

        u64 now = time(NULL);

        u64 fudge = ntohs(mesg->tsig.fudge);

        u16 mac_size = ntohs(mesg->tsig.mac_size);  /* NETWORK => NATIVE */

        if(mac_size > sizeof(mesg->tsig.mac))
        {
            /* oops */
            mesg->status = FP_TSIG_BROKEN;
            return TSIG_FORMERR;
        }

        mesg->tsig.mac_size = mac_size;

        if(FAIL(return_code = packet_reader_read(purd, mesg->tsig.mac, mac_size)))
        {
            /* oops */
            mesg->status = FP_TSIG_BROKEN;
            return TSIG_FORMERR;
        }

        if(FAIL(return_code = packet_reader_read(purd, &mesg->tsig.original_id, 6))) // and error, and other len
        {
            /* oops */
            mesg->status = FP_TSIG_BROKEN;
            return TSIG_FORMERR;
        }

        if(mesg->tsig.other_len != 0)
        {
            /**
             * @note This should never be run in input queries ...
             */

            u16 other_len = ntohs(mesg->tsig.other_len);

            MALLOC_OR_DIE(u8*, mesg->tsig.other, other_len, TSIGOTHR_TAG);

            if(FAIL(return_code = packet_reader_read(purd, mesg->tsig.other, other_len)))
            {
                /* oops */

                free(mesg->tsig.other);
                mesg->tsig.other = NULL;
                mesg->status = FP_TSIG_BROKEN;
                return TSIG_FORMERR;
            }
        }
        
        if(llabs((s64)(then - now)) > fudge) // cast to signed in case now > then
        {
            mesg->tsig.error = htons(RCODE_BADTIME);
            mesg->status = FP_TSIG_ERROR;
            return TSIG_BADTIME;
        }

        /*
         * We can now process the wire and compute the HMAC
         * Note that if message_id != original_message_id, then message_id replaces original_message_id
         */

        return SUCCESS;
    }

    /* error : tsig but wrong tsig setup */
    mesg->status = FP_TSIG_BROKEN;
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
        
        free(mesg->tsig.other);
        mesg->tsig.other = NULL;
        mesg->tsig.error = htons(RCODE_BADSIG);
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
                    
    /* oops */

    
    
    return return_value;
}

ya_result
tsig_process_answer(message_data *mesg, packet_unpack_reader_data *purd, u32 tsig_offset, const tsig_item *tsig, struct type_class_ttl_rdlen *tctr, const u8 *mac, u16 mac_size)
{
    ya_result return_value;
    
    if(ISOK(return_value = tsig_process(mesg, purd, tsig_offset, tsig, tctr)))
    {
        if(FAIL(return_value = tsig_verify_answer(mesg, mac, mac_size)))
        {
            /* oops */

            free(mesg->tsig.other);
            mesg->tsig.other = NULL;
            mesg->tsig.error = htons(RCODE_BADSIG);

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
    /*yassert(mesg->ar_start != NULL);*/

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
    purd.packet = mesg->buffer;
    purd.packet_size = mesg->received;

    if(mesg->ar_start == NULL)
    {
        u32 tsig_index = ntohs(MESSAGE_AN(mesg->buffer)) + ntohs(MESSAGE_NS(mesg->buffer)) + ntohs(MESSAGE_AR(mesg->buffer)) - 1;

        purd.offset = 12; /* Header */
        packet_reader_skip_fqdn(&purd); /* Query DNAME */
        purd.offset += 4; /* TYPE CLASS */

        while(tsig_index-- > 0) /* Skip all AR records but the last one */
        {
            /*
             * It should be in this kind of processing that we read the EDNS0 flag
             */

            packet_reader_skip_record(&purd);
        }

        mesg->ar_start = &mesg->buffer[purd.offset];
    }
    else
    {
        purd.offset = mesg->ar_start - mesg->buffer;
    }

    struct type_class_ttl_rdlen tctr;

    u32 record_offset = purd.offset;

    u8 tsigname[MAX_DOMAIN_LENGTH];

    if(FAIL(packet_reader_read_fqdn(&purd, tsigname, sizeof (tsigname))))
    {
        /* oops */

        return TSIG_FORMERR;
    }

    /*yassert(((u8*)&tctr.rdlen) - ((u8*)&tctr.qtype) == 8);*/

    if(ISOK(packet_reader_read(&purd, &tctr, 10)))
    {
        if(tctr.qtype == TYPE_TSIG) /* && (tctr.qclass == TYPE_ANY) && (tctr.ttl == 0 )*/
        {
            /* It must be the last AR record, class = ANY and TTL = 0 */

            return tsig_process_query(mesg, &purd, record_offset, tsigname, &tctr);

        } /* if type is TSIG */

        /* AR but not a TSIG  : there is just no TSIG in this packet */

        mesg->tsig.tsig = NULL;
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
    u16 ar_count = ntohs(MESSAGE_AR(mesg->buffer));

    /* Converted after network read ... so why do I do this ? */
    //u16 mac_size = ntohs(mesg->tsig.mac_size);
    u16 mac_size = mesg->tsig.mac_size;
    u16 other_len = ntohs(mesg->tsig.other_len);

    if(mesg->size_limit < mesg->send_length +
            mesg->tsig.tsig->name_len + /* DNS NAME of the TSIG (name of the key) */
            mac_size + /* MAC */
            other_len + /* OTHER DATA */
            12) /* time + fudge + mac size + original id + error + other len */
    {
        /* Cannot sign because of truncation */

        MESSAGE_HIFLAGS(mesg->buffer) |= TC_BITS;

        return TSIG_SIZE_LIMIT_ERROR;
    }

    u8 *tsig_ptr = &mesg->buffer[mesg->send_length];

    /* record */

    memcpy(tsig_ptr, mesg->tsig.tsig->name, mesg->tsig.tsig->name_len);
    tsig_ptr += mesg->tsig.tsig->name_len;

    memcpy(tsig_ptr, tsig_typeclassttl, sizeof (tsig_typeclassttl));
    tsig_ptr += sizeof (tsig_typeclassttl);
    u16 *rdata_size_ptr = (u16*)tsig_ptr;
    tsig_ptr += 2;

    /* rdata */

    memcpy(tsig_ptr, mesg->tsig.tsig->mac_algorithm_name, mesg->tsig.tsig->mac_algorithm_name_len);
    tsig_ptr += mesg->tsig.tsig->mac_algorithm_name_len;

    SET_U16_AT(tsig_ptr[0], mesg->tsig.timehi);
    SET_U32_AT(tsig_ptr[2], mesg->tsig.timelo);
    SET_U16_AT(tsig_ptr[6], mesg->tsig.fudge);
    SET_U16_AT(tsig_ptr[8], htons(mesg->tsig.mac_size));

    memcpy(&tsig_ptr[10], mesg->tsig.mac, mac_size);
    tsig_ptr += mac_size + 10;

    SET_U16_AT(tsig_ptr[0], mesg->tsig.original_id);
    SET_U16_AT(tsig_ptr[2], mesg->tsig.error);
    SET_U16_AT(tsig_ptr[4], mesg->tsig.other_len);

    tsig_ptr += 6;

    if(mesg->tsig.other_len != 0)
    {
        memcpy(tsig_ptr, mesg->tsig.other, other_len);
        tsig_ptr += other_len;
    }

    u16 rdata_size = (tsig_ptr - (u8*)rdata_size_ptr) - 2;

    SET_U16_AT(*rdata_size_ptr, htons(rdata_size));

    mesg->send_length = (tsig_ptr - mesg->buffer);

    MESSAGE_SET_AR(mesg->buffer, htons(ar_count + 1));
    
    return SUCCESS;
}

/**¨
 * Signs the message answer with its TSIG
 */

ya_result
tsig_sign_answer(message_data *mesg)
{
    yassert(mesg->ar_start != NULL);

    tsig_digest_answer(mesg);

    return tsig_add_tsig(mesg);
}

/**¨
 * Signs the message query with its TSIG
 */

ya_result
tsig_sign_query(message_data *mesg)
{
    yassert(mesg->ar_start != NULL);

    tsig_digest_query(mesg);

    return tsig_add_tsig(mesg);
}

/**
 * On a RECEIVED message.
 *
 *  Adds a TSIG error to the message
 *
 * @todo 20140523 edf -- Change the algorithm to use tsig_add_tsig
 */

ya_result
tsig_append_unsigned_error(message_data *mesg)
{
    yassert(mesg->ar_start != NULL);

    u16 ar_count = ntohs(MESSAGE_AR(mesg->buffer));

    packet_unpack_reader_data purd;
    purd.packet = mesg->buffer;
    purd.packet_size = mesg->received;
    purd.offset = 12;
    packet_reader_skip_fqdn(&purd);
    purd.offset += 4;
    mesg->send_length = purd.offset;
    mesg->received = purd.offset;

    MESSAGE_SET_AN(mesg->buffer, 0);
    MESSAGE_SET_NS(mesg->buffer, 0);
    MESSAGE_SET_AR(mesg->buffer, 0);

    if(!MESSAGE_HAS_TSIG(*mesg) ||
            mesg->size_limit < (mesg->send_length +
            mesg->tsig.tsig->name_len + /* DNS NAME of the TSIG (name of the key) */
            0 + /* MAC */
            0 + /* OTHER DATA */
            12 /*DO NOT REPLACE*/)) /* = time + fudge + mac size + original id + error + other len */
    {
        /* Cannot sign */

        return TSIG_UNABLE_TO_SIGN;
    }

    u8 *tsig_ptr = &mesg->buffer[mesg->received];

    /* record */

    memcpy(tsig_ptr, mesg->tsig.tsig->name, mesg->tsig.tsig->name_len);
    tsig_ptr += mesg->tsig.tsig->name_len;

    memcpy(tsig_ptr, tsig_typeclassttl, sizeof (tsig_typeclassttl));
    tsig_ptr += sizeof (tsig_typeclassttl);
    u16 *rdata_size_ptr = (u16*)tsig_ptr;
    tsig_ptr += 2;

    /* rdata */

    memcpy(tsig_ptr, mesg->tsig.tsig->mac_algorithm_name, mesg->tsig.tsig->mac_algorithm_name_len);
    tsig_ptr += mesg->tsig.tsig->mac_algorithm_name_len;

    SET_U16_AT(tsig_ptr[ 0], mesg->tsig.timehi);
    SET_U32_AT(tsig_ptr[ 2], mesg->tsig.timelo);
    SET_U16_AT(tsig_ptr[ 6], mesg->tsig.fudge);
    SET_U16_AT(tsig_ptr[ 8], 0); /* MAC len */
    SET_U16_AT(tsig_ptr[10], mesg->tsig.original_id);
    SET_U16_AT(tsig_ptr[12], mesg->tsig.error);
    SET_U16_AT(tsig_ptr[14], 0); /* Error len */

    tsig_ptr += 16;

    u16 rdata_size = (tsig_ptr - (u8*)rdata_size_ptr) - 2;

    SET_U16_AT(*rdata_size_ptr, htons(rdata_size));

    mesg->send_length = (tsig_ptr - mesg->buffer);

    MESSAGE_SET_AR(mesg->buffer, htons(ar_count + 1));

    return SUCCESS;
}

ya_result
tsig_append_error(message_data *mesg)
{
    yassert(mesg->ar_start != NULL);
    
    MESSAGE_FLAGS_OR(mesg->buffer, QR_BITS, mesg->status);
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
     * Digest the digest (mesg->tsig.mac, mesg->tsig.mac_size (NETWORK ORDERED!))
     */

    HMAC_CTX_init(&mesg->tsig.ctx);
    HMAC_Init(&mesg->tsig.ctx, mesg->tsig.tsig->mac, mesg->tsig.tsig->mac_size, mesg->tsig.tsig->evp_md);

    u16 mac_size_network = htons(mesg->tsig.mac_size);

#if LOG_DIGEST_INPUT != 0
    log_debug("tsig_sign_tcp: PRIOR: (%p)", mesg);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mac_size_network, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.mac, mesg->tsig.mac_size, 32);
#endif

    HMAC_Update(&mesg->tsig.ctx, (u8*) & mac_size_network, 2);
    HMAC_Update(&mesg->tsig.ctx, mesg->tsig.mac, mesg->tsig.mac_size);

    mesg->tsig.tcp_tsig_countdown = TSIG_TCP_PERIOD;

    return SUCCESS;
}

ya_result
tsig_sign_tcp_next_message(struct message_data *mesg)
{
    /*
     * Digest the message
     */

#if LOG_DIGEST_INPUT != 0
    log_debug("tsig_sign_tcp: Message: (%p)", mesg);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->buffer, mesg->send_length, 32);
#endif

    HMAC_Update(&mesg->tsig.ctx, mesg->buffer, mesg->send_length);

    /*
     * If it's the 100th since the last TSIG, then ...
     */

    if(--mesg->tsig.tcp_tsig_countdown == 0)
    {
        mesg->tsig.tcp_tsig_countdown = TSIG_TCP_PERIOD;

        /*
         * Digest the time
         */

#if LOG_DIGEST_INPUT != 0
        log_debug("tsig_sign_tcp: Timers: (%p)", mesg);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.timehi, 2, 32);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.timelo, 4, 32);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.fudge, 2, 32);
#endif

        HMAC_Update(&mesg->tsig.ctx, (u8*) & mesg->tsig.timehi, 2);
        HMAC_Update(&mesg->tsig.ctx, (u8*) & mesg->tsig.timelo, 4);
        HMAC_Update(&mesg->tsig.ctx, (u8*) & mesg->tsig.fudge, 2);

        u32 tmp_mac_size;
        HMAC_Final(&mesg->tsig.ctx, mesg->tsig.mac, &tmp_mac_size);

        /*
         * Store the TSIG
         */

        tsig_add_tsig(mesg);

        /*
         * Reset the digest
         *
         * Digest the digest
         */

        HMAC_CTX_cleanup(&mesg->tsig.ctx);
        HMAC_CTX_init(&mesg->tsig.ctx);
        HMAC_Init(&mesg->tsig.ctx, mesg->tsig.tsig->mac, mesg->tsig.tsig->mac_size, mesg->tsig.tsig->evp_md);

        u16 mac_size_network = htons(mesg->tsig.mac_size);

#if LOG_DIGEST_INPUT != 0
        log_debug("tsig_sign_tcp: Prior: (%p)", mesg);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mac_size_network, 2, 32);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.mac, mesg->tsig.mac_size, 32);
#endif

        HMAC_Update(&mesg->tsig.ctx, (u8*) & mac_size_network, 2);
        HMAC_Update(&mesg->tsig.ctx, mesg->tsig.mac, mesg->tsig.mac_size);
    }

    return SUCCESS;
}

ya_result
tsig_sign_tcp_last_message(struct message_data *mesg)
{
    /*
     * Digest the message
     */

#if LOG_DIGEST_INPUT != 0
    log_debug("tsig_sign_tcp: MESSAGE: (%p)", mesg);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->buffer, mesg->send_length, 32);
#endif

    HMAC_Update(&mesg->tsig.ctx, mesg->buffer, mesg->send_length);

    /*
     * If it's the 100th since the last TSIG, then ...
     */

    mesg->tsig.tcp_tsig_countdown = 0;

    /*
     * Digest the time
     */

#if LOG_DIGEST_INPUT != 0
    log_debug("tsig_sign_tcp: TIMERS: (%p)", mesg);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.timehi, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.timelo, 4, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.fudge, 2, 32);
#endif

    HMAC_Update(&mesg->tsig.ctx, (u8*) & mesg->tsig.timehi, 2);
    HMAC_Update(&mesg->tsig.ctx, (u8*) & mesg->tsig.timelo, 4);
    HMAC_Update(&mesg->tsig.ctx, (u8*) & mesg->tsig.fudge, 2);

    u32 tmp_mac_size;
    HMAC_Final(&mesg->tsig.ctx, mesg->tsig.mac, &tmp_mac_size);

    /*
     * Store the TSIG
     */

    tsig_add_tsig(mesg);

    HMAC_CTX_cleanup(&mesg->tsig.ctx);

    return SUCCESS;
}

/**
 * If the message has no TSIG to do, it is considered to be successful.
 */

ya_result
tsig_sign_tcp_message(struct message_data *mesg, tsig_tcp_message_position pos)
{
    ya_result return_code = SUCCESS;

    if(MESSAGE_HAS_TSIG(*mesg))
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
#if LOG_DIGEST_INPUT != 0
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
     * Digest the digest (mesg->tsig.mac, mesg->tsig.mac_size (NETWORK ORDERED!))
     */

    HMAC_CTX_init(&mesg->tsig.ctx);
    HMAC_Init(&mesg->tsig.ctx, mesg->tsig.tsig->mac, mesg->tsig.tsig->mac_size, mesg->tsig.tsig->evp_md);

    u16 mac_size_network = htons(mesg->tsig.mac_size);

#if LOG_DIGEST_INPUT != 0
    log_debug("tsig_verify_tcp_first_message: previous MAC: (%p)", mesg);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mac_size_network, 2, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.mac, mesg->tsig.mac_size, 32);
#endif

    HMAC_Update(&mesg->tsig.ctx, (u8*) & mac_size_network, 2);
    HMAC_Update(&mesg->tsig.ctx, mesg->tsig.mac, mesg->tsig.mac_size);

    mesg->tsig.tcp_tsig_countdown = TSIG_TCP_PERIOD + 2;    /* be a bit lenient */

    return SUCCESS;
}

ya_result
tsig_verify_tcp_next_message(struct message_data *mesg)
{
    /*
     * Digest the message
     */

    u8 mac[64];

#if LOG_DIGEST_INPUT != 0
    log_debug("tsig_verify_tcp_next_message: message: (%p)", mesg);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->buffer, mesg->received, 32);
#endif

    if(mesg->tsig.tcp_tsig_countdown-- < 0)
    {
        return TSIG_BADSIG;
    }

    HMAC_Update(&mesg->tsig.ctx, mesg->buffer, mesg->received);

    /*
     * If it has been signed ...
     */

    if(mesg->tsig.tsig != NULL)
    {
        mesg->tsig.tcp_tsig_countdown = TSIG_TCP_PERIOD + 2;    /* be a bit lenient */

        /*
         * Digest the time
         */

#if LOG_DIGEST_INPUT != 0
        log_debug("tsig_verify_tcp_next_message: timers: (%p)", mesg);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.timehi, 2, 32);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.timelo, 4, 32);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mesg->tsig.fudge, 2, 32);
#endif

        HMAC_Update(&mesg->tsig.ctx, (u8*) & mesg->tsig.timehi, 2);
        HMAC_Update(&mesg->tsig.ctx, (u8*) & mesg->tsig.timelo, 4);
        HMAC_Update(&mesg->tsig.ctx, (u8*) & mesg->tsig.fudge, 2);

        u32 tmp_mac_size;
        HMAC_Final(&mesg->tsig.ctx, mac, &tmp_mac_size);

        HMAC_CTX_cleanup(&mesg->tsig.ctx);

        if(memcmp(mesg->tsig.mac, mac, tmp_mac_size) != 0)
        {
            return TSIG_BADSIG;
        }

        /*
         * Reset the digest
         *
         * Digest the digest
         */

        HMAC_CTX_init(&mesg->tsig.ctx);
        HMAC_Init(&mesg->tsig.ctx, mesg->tsig.tsig->mac, mesg->tsig.tsig->mac_size, mesg->tsig.tsig->evp_md);

        u16 mac_size_network = htons(mesg->tsig.mac_size);

#if LOG_DIGEST_INPUT != 0
        log_debug("tsig_verify_tcp_next_message: previous MAC: (%p)", mesg);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, (u8*) & mac_size_network, 2, 32);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->tsig.mac, mesg->tsig.mac_size, 32);
#endif

        HMAC_Update(&mesg->tsig.ctx, (u8*) & mac_size_network, 2);
        HMAC_Update(&mesg->tsig.ctx, mesg->tsig.mac, mesg->tsig.mac_size);
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
    
#if LOG_DIGEST_INPUT != 0
    log_debug("tsig_verify_tcp_last_message: message: (%p)", mesg);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->buffer, mesg->received, 32);
#endif


    HMAC_CTX_cleanup(&mesg->tsig.ctx);
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
    
    u16 ar = ntohs(MESSAGE_AR(mesg->buffer));

    if( ar < 1)
    {
        return 0;   /* no TSIG */
    }

    u16 qd = ntohs(MESSAGE_QD(mesg->buffer));
    u16 an = ntohs(MESSAGE_AN(mesg->buffer));
    u16 ns = ntohs(MESSAGE_NS(mesg->buffer));

    packet_reader_init(&reader, mesg->buffer, mesg->received);
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
    
    u16 n = an + ns + ar - 1;

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

    packet_reader_read_u16(&reader, &mesg->tsig.timehi);
    packet_reader_read_u32(&reader, &mesg->tsig.timelo);    
    packet_reader_read_u16(&reader, &mesg->tsig.fudge);
    packet_reader_read_u16(&reader, &mesg->tsig.mac_size);

    u16 mac_size = ntohs(mesg->tsig.mac_size);

    mesg->tsig.mac_size = mac_size;

    if(mac_size > sizeof(mesg->tsig.mac))
    {
        return TSIG_BADKEY; /* The key is bigger than anything supported */
    }

    if(FAIL(return_value = packet_reader_read(&reader, mesg->tsig.mac, mac_size)))
    {
        return return_value;
    }

    len -= return_value;

    packet_reader_read_u16(&reader, &mesg->tsig.original_id);
    packet_reader_read_u16(&reader, &mesg->tsig.error);
    
    if(FAIL(return_value = packet_reader_read_u16(&reader, &mesg->tsig.other_len)))
    {
        return return_value;
    }

    u16 other_len = ntohs(mesg->tsig.other_len);

    len -= other_len;

    if(len != 0)
    {
        return TSIG_FORMERR;
    }

    mesg->tsig.other = NULL;

    mesg->tsig.tsig = tsig;

    mesg->tsig.mac_algorithm = tsig->mac_algorithm;

    mesg->received = tsig_offset;

    MESSAGE_SET_AR(mesg->buffer, htons(ar - 1));

    return 1;   /* got 1 signature */
}

#endif

/** @} */

