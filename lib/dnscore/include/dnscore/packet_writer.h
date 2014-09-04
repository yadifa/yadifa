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

#ifdef	__cplusplus
extern "C"
{
#endif

typedef struct packet_dictionary_node packet_dictionary_node;


struct packet_dictionary_node
{
    packet_dictionary_node* next;
    packet_dictionary_node* child;
    u8* label;
    u32 offset;
};

typedef struct packet_writer packet_writer;


struct packet_writer
{
    packet_dictionary_node* head;
    packet_dictionary_node* pool_head;
    
    u8* packet;

    u32 packet_offset;
    u32 packet_limit;

    packet_dictionary_node pool[4096];
};

/**
 * 
 * creates an new packet
 * 
 * @param pc
 * @param packet
 * @param limit
 */

void packet_writer_create(packet_writer* pc, u8* packet, u16 limit);

/**
 * 
 * initialises a writer based on an existing message
 * 
 * @param pc
 * @param packet a packet containing a valid message
 * @param packet_offset
 * @param size_limit
 * @return 
 */

ya_result packet_writer_init(packet_writer* pc, u8* packet, u32 packet_offset, u32 size_limit);

/**
 * @note uncompressed names will not be compressed, of course *** BUT ***
 *       they will not be used in the compression dictionnary either
 */

ya_result packet_writer_add_fqdn_uncompressed(packet_writer* pc, const u8* fqdn);
ya_result packet_writer_add_fqdn(packet_writer* pc, const u8* fqdn);
ya_result packet_writer_add_rdata(packet_writer* pc, u16 rr_type, const u8* rdata, u16 rdata_len);

ya_result packet_writer_add_record(packet_writer* pc, const u8* fqdn, u16 rr_type, u16 rr_class, u32 ttl, const u8* rdata, u16 rdata_len);

static inline s32 packet_writer_remaining_capacity(packet_writer* pc)
{
    return (s32)pc->packet_limit - (s32)pc->packet_offset;
}

static inline void packet_writer_set_u16(packet_writer* pc, u16 value, u32 offset)
{
    SET_U16_AT(pc->packet[offset], value);
}

static inline void packet_writer_add_u16(packet_writer* pc, u16 value)
{
    SET_U16_AT(pc->packet[pc->packet_offset], value);
    pc->packet_offset += 2;
}

static inline void packet_writer_add_u32(packet_writer* pc, u32 value)
{
    SET_U32_AT(pc->packet[pc->packet_offset], value);
    pc->packet_offset += 4;
}

static inline void packet_writer_add_bytes(packet_writer* pc, const u8* buffer, u32 len)
{
    MEMCOPY(&pc->packet[pc->packet_offset], buffer, len);
    pc->packet_offset += len;
}

ya_result write_tcp_packet(packet_writer *pw, output_stream *tcpos);

#ifdef	__cplusplus
}
#endif

#endif	/* _PACKET_WRITER_H */
/** @} */

/*----------------------------------------------------------------------------*/

