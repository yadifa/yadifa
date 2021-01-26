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
#ifndef _PACKET_READER_H
#define	_PACKET_READER_H

#include <dnscore/sys_types.h>
#include <dnscore/host_address.h>
#include <dnscore/message.h>
#include <dnscore/dns_resource_record.h>

#ifdef	__cplusplus
extern "C"
{
#endif

/* dynupdate */

/* reads and unpack */

typedef struct packet_unpack_reader_data packet_unpack_reader_data;


struct packet_unpack_reader_data
{
    const u8* packet;
    u32 packet_size;
    u32 offset;
};

static inline void packet_reader_init_at(packet_unpack_reader_data* reader, const u8* buffer, u32 buffer_size, u32 position)
{
    reader->packet = buffer;
    reader->packet_size = buffer_size;
    reader->offset = position;
}

static inline void packet_reader_init(packet_unpack_reader_data* reader, const u8* buffer, u32 buffer_size)
{
    packet_reader_init_at(reader, buffer, buffer_size, 0);
}

static inline void
packet_reader_init_from_message_at(packet_unpack_reader_data* reader, const message_data *mesg, u32 position)
{
    packet_reader_init_at(reader, message_get_buffer_const(mesg), message_get_size(mesg), position);
}

static inline void
packet_reader_init_from_message(packet_unpack_reader_data* reader, const message_data *mesg)
{
    packet_reader_init_from_message_at(reader, mesg, DNS_HEADER_LENGTH);
}

static inline ya_result packet_reader_opcode(packet_unpack_reader_data* reader)
{
    if(reader->packet_size >= DNS_HEADER_LENGTH)
    {
        return MESSAGE_OP(reader->packet) >> OPCODE_SHIFT;
    }
    else
    {
        return UNEXPECTED_EOF;
    }
}

/* fqdn + type + class */
ya_result packet_reader_read_zone_record(packet_unpack_reader_data* reader, u8* output_buffer, u32 len);
ya_result packet_reader_skip_zone_record(packet_unpack_reader_data* reader);

ya_result packet_reader_skip_query_section(packet_unpack_reader_data* reader);
ya_result packet_reader_skip_section(packet_unpack_reader_data* reader, int section);

/* fqdn + type + class + ttl + size + rdata */
ya_result packet_reader_read_record(packet_unpack_reader_data* reader, u8 *output_buffer, u32 len);

ya_result packet_reader_read_dns_resource_record(packet_unpack_reader_data* reader, dns_resource_record *rr);

/**
 * Note that the last parameter is the buffer size and the data size to be read is right after the type.
 */

ya_result packet_reader_read_rdata(packet_unpack_reader_data* reader, u16 type, u32 rdata_size, u8 *buffer, u32 buffer_size);

ya_result packet_reader_read_fqdn(packet_unpack_reader_data* reader, u8 *output_buffer, u32 len);

ya_result packet_reader_read(packet_unpack_reader_data* reader, void *output_buffer, u32 len);

static inline void packet_reader_read_unchecked(packet_unpack_reader_data* reader, void *output_buffer, u32 len)
{
    MEMCOPY(output_buffer, &reader->packet[reader->offset], len);
    reader->offset += len;
}

static inline const void *packet_reader_get_current_ptr_const(const packet_unpack_reader_data* reader, u16 size)
{
    if(reader->offset + size <= reader->packet_size)
    {
        return &reader->packet[reader->offset];
    }
    else
    {
        return NULL;
    }
}

ya_result packet_reader_read_u16(packet_unpack_reader_data* reader, u16 *val);

ya_result packet_reader_read_dnstype(packet_unpack_reader_data* reader);
ya_result packet_reader_read_dnsclass(packet_unpack_reader_data* reader);
ya_result packet_reader_skip_query(packet_unpack_reader_data* reader, const u8 *domain, u16 dnstype, u16 dnsclass);

ya_result packet_reader_read_u32(packet_unpack_reader_data* reader, u32 *val);

static inline void packet_reader_read_u16_unchecked(packet_unpack_reader_data* reader, u16 *val)
{
    *val = GET_U16_AT(reader->packet[reader->offset]);
    reader->offset += 2;
}

static inline void packet_reader_read_u32_unchecked(packet_unpack_reader_data* reader, u32 *val)
{
    *val = GET_U32_AT(reader->packet[reader->offset]);
    reader->offset += 4;
}

static inline ya_result packet_reader_read_s32(packet_unpack_reader_data* reader, s32 *val)
{
    return packet_reader_read_u32(reader, (u32*)val);
}

static inline void packet_reader_read_s32_unchecked(packet_unpack_reader_data* reader, s32 *val)
{
    packet_reader_read_u32_unchecked(reader, (u32*)val);
}

static inline ya_result packet_reader_skip(packet_unpack_reader_data* reader, u32 len)
{
    if((reader->offset += len) > reader->packet_size)
    {
        reader->offset = reader->packet_size;
	
        return UNEXPECTED_EOF;	/* unexpected EOF */
    }

    return len;
}

static inline void packet_reader_skip_unchecked(packet_unpack_reader_data* reader, u32 len)
{
    reader->offset += len;
}

static inline size_t packet_reader_available(packet_unpack_reader_data* reader)
{
    return reader->packet_size - reader->offset;
}

void packet_reader_rewind(packet_unpack_reader_data* reader);

ya_result packet_reader_skip_fqdn(packet_unpack_reader_data* reader);
ya_result packet_reader_skip_record(packet_unpack_reader_data* reader);

/* two tools functions for the controller */

ya_result packet_reader_read_utf8(packet_unpack_reader_data *reader, u16 rdatasize, u16 rclass, char **txt, bool dryrun);

ya_result packet_reader_read_remote_server(packet_unpack_reader_data *reader, u16 rdatasize, u16 rclass, host_address **ha, bool dryrun);
/*
static inline u8* packet_reader_get_next_u8_ptr(packet_unpack_reader_data *reader)
{
    return &reader->packet[reader->offset];
}
*/
static inline const u8* packet_reader_get_next_u8_ptr_const(const packet_unpack_reader_data *reader)
{
    return &reader->packet[reader->offset];
}

static inline void packet_reader_set_position(packet_unpack_reader_data *reader, u32 position)
{
    reader->offset = position;
}

#ifdef	__cplusplus
}
#endif

#endif	/* _PACKET_READER_H */

/** @} */
