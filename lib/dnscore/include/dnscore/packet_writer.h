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

/** @defgroup dnspacket DNS Messages
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _PACKET_WRITER_H
#define	_PACKET_WRITER_H

#include <dnscore/sys_types.h>
#include <dnscore/output_stream.h>
#include <dnscore/message.h>
#include <dnscore/dns_resource_record.h>

#define PW_MESSAGE_BUFFER_SIZE 0x10500

#ifdef	__cplusplus
extern "C"
{
#endif

typedef struct packet_dictionary_node packet_dictionary_node;


struct packet_dictionary_node // 16 / 28
{
    packet_dictionary_node* next;
    packet_dictionary_node* child;
    u8* label;
    u32 offset;
};

typedef struct packet_writer packet_writer;

struct packet_writer
{
    packet_dictionary_node* head;       //     4  8
    packet_dictionary_node* pool_head;  //     8 16
    
    u8* packet;                         //    12 24 

    u32 packet_offset;                  //    16 28
    u32 packet_limit;                   //    20 32

    packet_dictionary_node pool[4096];  // 65556 114720 or 131104 (depending on struct alignment)
};

/**
 * 
 * creates an new packet
 * 
 * @param pw
 * @param packet
 * @param limit
 */

void packet_writer_create(packet_writer *pw, u8* packet, u32 limit);

/**
 * 
 * initialises a writer based on an existing message
 * 
 * @param pw
 * @param packet a packet containing a valid message
 * @param packet_offset
 * @param size_limit
 * @return 
 */

ya_result packet_writer_init(packet_writer *pw, u8* packet, u32 packet_offset, u32 size_limit);

static inline ya_result
packet_writer_init_append_to_message(packet_writer* pw, message_data *mesg)
{ // do not use the logical max
    return packet_writer_init(pw, message_get_buffer(mesg), message_get_size(mesg), message_get_buffer_size_max(mesg));
}

/**
 *
 * initialises a writer based on an existing message
 *
 * @param pw
 * @param packet a packet containing a valid message
 * @param packet_offset
 * @param size_limit
 * @return
 */


static inline ya_result
packet_writer_init_from_message(packet_writer* pw, message_data *mesg)
{ // do not use the logical max
    return packet_writer_init(pw, message_get_buffer(mesg), message_get_size(mesg), message_get_buffer_size_max(mesg));
}

/**
 *
 * initialises a writer into an existing message, does not parse the message
 *
 * @param pw
 * @param packet a packet containing a valid message
 * @param packet_offset
 * @param size_limit
 * @return
 */

static inline void
packet_writer_init_into_message(packet_writer* pw, message_data *mesg)
{ // do not use the logical max
    packet_writer_create(pw, message_get_buffer(mesg), message_get_buffer_size_max(mesg));
}

/**
 * @note uncompressed names will not be compressed, of course *** BUT ***
 *       they will not be used in the compression dictionnary either
 */

ya_result packet_writer_add_fqdn_uncompressed(packet_writer *pw, const u8 *fqdn);
ya_result packet_writer_add_fqdn(packet_writer *pw, const u8* fqdn);
ya_result packet_writer_add_rdata(packet_writer *pw, u16 rr_type, const u8 *rdata, u16 rdata_len);

ya_result packet_writer_add_record(packet_writer *pw, const u8* fqdn, u16 rr_type, u16 rr_class, u32 ttl, const u8* rdata, u16 rdata_len);
ya_result packet_writer_add_dnsrr(packet_writer *pw, dns_resource_record* dns_rr);

static inline void packet_writer_forward(packet_writer *pw, u32 bytes)
{
    assert(pw->packet_offset + bytes <= pw->packet_limit);
    pw->packet_offset += bytes;
}

static inline void packet_writer_set_u8(packet_writer *pw, u16 value, u32 offset)
{
    assert(pw->packet_offset <= pw->packet_limit);
    pw->packet[offset] = value;
}

static inline void packet_writer_add_u8(packet_writer *pw, u16 value)
{
    assert(pw->packet_offset + 1 <= pw->packet_limit);
    pw->packet[pw->packet_offset++] = value;
}

static inline void packet_writer_set_u16(packet_writer *pw, u16 value, u32 offset)
{

    SET_U16_AT(pw->packet[offset], value);
}

static inline void packet_writer_add_u16(packet_writer *pw, u16 value)
{
    assert(pw->packet_offset + 2 <= pw->packet_limit);
    SET_U16_AT(pw->packet[pw->packet_offset], value);
    pw->packet_offset += 2;
}

static inline void packet_writer_add_u32(packet_writer *pw, u32 value)
{
    assert(pw->packet_offset + 4 <= pw->packet_limit);
    SET_U32_AT(pw->packet[pw->packet_offset], value);
    pw->packet_offset += 4;
}

static inline void packet_writer_set_u32(packet_writer *pw, u32 value, u32 offset)
{
    assert(offset + 4 <= pw->packet_limit);
    SET_U32_AT(pw->packet[offset], value);
}

static inline void packet_writer_add_bytes(packet_writer *pw, const u8 *buffer, u32 len)
{
    assert(pw->packet_offset + len <= pw->packet_limit);
    MEMCOPY(&pw->packet[pw->packet_offset], buffer, len);
    pw->packet_offset += len;
}

static inline u32 packet_writer_get_offset(const packet_writer *pw)
{
    return pw->packet_offset;
}

static inline void packet_writer_set_offset(packet_writer *pw, u32 offset)
{
    yassert(offset <= pw->packet_limit);
    pw->packet_offset = offset;
}

static inline u32 packet_writer_get_limit(const packet_writer *pw)
{
    return pw->packet_limit;
}

static inline s32 packet_writer_get_remaining_capacity(const packet_writer *pw)
{
    assert(pw->packet_offset <= pw->packet_limit);
    return (s32)pw->packet_limit - (s32)pw->packet_offset;
}


static inline u8* packet_writer_get_next_u8_ptr(const packet_writer *pw)
{
    return &pw->packet[pw->packet_offset];
}

ya_result write_tcp_packet(packet_writer *pw, output_stream *tcpos);

#ifdef	__cplusplus
}
#endif

#endif	/* _PACKET_WRITER_H */
/** @} */
