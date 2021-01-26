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

#ifndef TSIG_H_
#define TSIG_H_

#include <stdio.h>
#include <stdlib.h>

#include <dnscore/dnskey.h>
#include <dnscore/hmac.h>

#if DNSCORE_HAS_TSIG_SUPPORT

#ifdef	__cplusplus
extern "C"
{
#endif

#define HMAC_UNKNOWN	  0
#define HMAC_MD5        157
#define HMAC_SHA1       161
#define HMAC_SHA224     162
#define HMAC_SHA256     163
#define HMAC_SHA384     164
#define HMAC_SHA512     165

struct packet_unpack_reader_data;

/*
 * A digest is stored prefixed with its length ([1;255])
 */

/*
 * A structure to hold both children with direct access
 */

typedef struct tsig_node tsig_node;

struct tsig_children
{
    struct tsig_node* left;
    struct tsig_node* right;
};

/*
 * An union to have access to the children with direct or indexed access
 */

typedef union tsig_children_union tsig_children_union;

union tsig_children_union
{
    struct tsig_children lr;
    struct tsig_node * child[2];
};

typedef struct tsig_item tsig_item;

struct tsig_item
{
    const u8 *name;
    const u8 *mac;
    const u8 *mac_algorithm_name;
    u16 name_len;
    u16 mac_algorithm_name_len;
    u16 mac_size;
    u8 mac_algorithm;
    
    u8 load_serial;
};

/*
 * The node structure CANNOT have a varying size on a given collection
 * This means that the digest size is a constant in the whole tree
 */

struct tsig_node
{
    union tsig_children_union children;
    tsig_item item;
    s8 balance;
};

/**
 * Call this before a config reload
 */

void tsig_serial_next();

/*
 * I recommend setting a define to identify the C part of the template
 * So it can be used to undefine what is not required anymore for every
 * C file but that one.
 *
 */

ya_result tsig_register(const u8 *name, const u8 *mac, u16 mac_size, u8 mac_algorithm);

void tsig_finalize();

tsig_item *tsig_get(const u8 *name);

u32 tsig_get_count();

tsig_item *tsig_get_at_index(s32 index);

struct message_data;

typedef enum
{
    TSIG_NOWHERE = -1,
    TSIG_START   =  0,
    TSIG_MIDDLE  =  1,
    TSIG_END     =  2,
    TSIG_WHOLE   =  3
} tsig_tcp_message_position;

/**
 * Sign the first message_data of a tcp answer
 */

ya_result tsig_sign_tcp_first_message(struct message_data *mesg);

/**
 * Sign one of the "middle" message_data of a tcp answer
 */

ya_result tsig_sign_tcp_next_message(struct message_data *mesg);

/**
 * Sign the 100*Nth last message_data of a tcp answer
 */

ya_result tsig_sign_tcp_last_message(struct message_data *mesg);

/**
 * Calls the relevant sign tcp function
 */

ya_result tsig_sign_tcp_message(struct message_data *mesg, tsig_tcp_message_position pos);

/**
 * Sign the first message_data of a tcp answer
 */

ya_result tsig_sign_tcp_first_message(struct message_data *mesg);

/**
 * Sign one of the "middle" message_data of a tcp answer
 */

ya_result tsig_sign_tcp_next_message(struct message_data *mesg);

/**
 * Sign the 100*Nth last message_data of a tcp answer
 */

ya_result tsig_sign_tcp_last_message(struct message_data *mesg);

/**
 * Calls the relevant verify tcp function
 */

ya_result tsig_verify_tcp_first_message(struct message_data *mesg, const u8 *mac, u16 mac_size);
ya_result tsig_verify_tcp_next_message(struct message_data *mesg);
void tsig_verify_tcp_last_message(struct message_data *mesg);


void tsig_register_algorithms();

ya_result tsig_get_hmac_algorithm_from_friendly_name(const char *hmacname);

u8 tsig_get_algorithm(const u8 *name);
const u8* tsig_get_algorithm_name(u8 algorithm);

/*
 * Called by tsig_extract_and_process
 * Processes the TSIG of the message, remove the TSIG from the message
 * *mesg the message
 * *purd the packet reader pointing to be start of the RDATA of the TSIG
 * tsigname the dname of the TSIG
 * tctr the TYPE-CLASS-TTL-RDATALEN of the TSIG
 */

// no verification whatsoever, use with care
ya_result tsig_process(struct message_data *mesg, struct packet_unpack_reader_data *purd, u32 tsig_offset, const tsig_item *tsig, struct type_class_ttl_rdlen *tctr);

ya_result tsig_process_query(struct message_data *mesg, struct packet_unpack_reader_data *purd, u32 tsig_offset, u8 tsigname[MAX_DOMAIN_LENGTH], struct type_class_ttl_rdlen *tctr);

ya_result tsig_process_answer(struct message_data *mesg, struct packet_unpack_reader_data *purd, u32 tsig_offset, struct type_class_ttl_rdlen *tctr);

/*
 * Search for the last
 *
 */

ya_result tsig_extract_and_process(struct message_data *mesg);

/**
 * signs the message
 * the tsig.tsig should be set
 * the tsig fields must be set
 *
 */

ya_result tsig_sign_answer(struct message_data *mesg);

/**
 * signs the message
 * the tsig.tsig should be set
 * the tsig fields should be clear
 *
 */

ya_result tsig_sign_query(struct message_data *mesg);

ya_result tsig_verify_answer(struct message_data *mesg, const u8 *mac, u16 mac_size);

ya_result tsig_append_unsigned_error(struct message_data *mesg);
ya_result tsig_append_error(struct message_data *mesg);

/**
 * Removes the TSIG if any, setups the tsig fields of the message.
 * 
 * Returns 1 if a TSIG has been processed.
 * Returns 0 if none were found.
 */

ya_result tsig_message_extract(struct message_data *mesg);

#ifdef	__cplusplus
}
#endif

#endif /* TSIG support */

#endif /* TSIG_H_ */

/** @} */
