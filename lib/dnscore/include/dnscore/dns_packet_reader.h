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
 * @defgroup dnspacket DNS Messages
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _PACKET_READER_H
#define _PACKET_READER_H

#include <dnscore/sys_types.h>
#include <dnscore/host_address.h>
#include <dnscore/dns_message.h>
#include <dnscore/dns_resource_record.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* dynupdate */

/* reads and unpack */

struct dns_packet_reader_s
{
    const uint8_t *packet;
    uint32_t       packet_size;
    uint32_t       packet_offset;
};

typedef struct dns_packet_reader_s dns_packet_reader_t;

static inline void                 dns_packet_reader_init_at(dns_packet_reader_t *reader, const uint8_t *buffer, uint32_t buffer_size, uint32_t position)
{
    reader->packet = buffer;
    reader->packet_size = buffer_size;
    reader->packet_offset = position;
}

static inline void dns_packet_reader_init(dns_packet_reader_t *reader, const uint8_t *buffer, uint32_t buffer_size) { dns_packet_reader_init_at(reader, buffer, buffer_size, 0); }

static inline void dns_packet_reader_init_from_message_at(dns_packet_reader_t *reader, const dns_message_t *mesg, uint32_t position)
{
    dns_packet_reader_init_at(reader, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), position);
}

static inline void      dns_packet_reader_init_from_message(dns_packet_reader_t *reader, const dns_message_t *mesg) { dns_packet_reader_init_from_message_at(reader, mesg, DNS_HEADER_LENGTH); }

static inline ya_result dns_packet_reader_opcode(dns_packet_reader_t *reader)
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

static inline bool dns_packet_reader_eof(dns_packet_reader_t *reader) { return reader->packet_offset >= reader->packet_size; }

/* fqdn + type + class */
ya_result dns_packet_reader_read_zone_record(dns_packet_reader_t *reader, uint8_t *output_buffer, uint32_t len);
ya_result dns_packet_reader_skip_zone_record(dns_packet_reader_t *reader);

ya_result dns_packet_reader_skip_query_section(dns_packet_reader_t *reader);
ya_result dns_packet_reader_skip_section(dns_packet_reader_t *reader, int section);

/* fqdn + type + class + ttl + size + rdata */
ya_result dns_packet_reader_read_record(dns_packet_reader_t *reader, uint8_t *output_buffer, uint32_t len);

ya_result dns_packet_reader_read_dns_resource_record(dns_packet_reader_t *reader, dns_resource_record_t *rr);

/**
 * Note that the last parameter is the buffer size and the data size to be read is right after the type.
 */

ya_result          dns_packet_reader_read_rdata(dns_packet_reader_t *reader, uint16_t type, int32_t rdata_size, uint8_t *buffer, int32_t buffer_size);

ya_result          dns_packet_reader_read_fqdn(dns_packet_reader_t *reader, uint8_t *output_buffer, uint32_t len);

ya_result          dns_packet_reader_read(dns_packet_reader_t *reader, void *output_buffer, uint32_t len);

static inline void dns_packet_reader_read_unchecked(dns_packet_reader_t *reader, void *output_buffer, uint32_t len)
{
    MEMCOPY(output_buffer, &reader->packet[reader->packet_offset], len);
    reader->packet_offset += len;
}

static inline const void *dns_packet_reader_get_current_ptr_const(const dns_packet_reader_t *reader, uint16_t size)
{
    if(reader->packet_offset + size <= reader->packet_size)
    {
        return &reader->packet[reader->packet_offset];
    }
    else
    {
        return NULL;
    }
}

ya_result          dns_packet_reader_read_u16(dns_packet_reader_t *reader, uint16_t *val);
ya_result          dns_packet_reader_read_dnstype(dns_packet_reader_t *reader);
ya_result          dns_packet_reader_read_dnsclass(dns_packet_reader_t *reader);
ya_result          dns_packet_reader_skip_query(dns_packet_reader_t *reader, const uint8_t *domain, uint16_t dnstype, uint16_t dnsclass);
ya_result          dns_packet_reader_skip_bytes(dns_packet_reader_t *reader, uint16_t count);
ya_result          dns_packet_reader_read_u32(dns_packet_reader_t *reader, uint32_t *val);

static inline void dns_packet_reader_read_u16_unchecked(dns_packet_reader_t *reader, uint16_t *val)
{
    *val = GET_U16_AT(reader->packet[reader->packet_offset]);
    reader->packet_offset += 2;
}

static inline void dns_packet_reader_read_u32_unchecked(dns_packet_reader_t *reader, uint32_t *val)
{
    *val = GET_U32_AT(reader->packet[reader->packet_offset]);
    reader->packet_offset += 4;
}

static inline ya_result dns_packet_reader_read_s32(dns_packet_reader_t *reader, int32_t *val) { return dns_packet_reader_read_u32(reader, (uint32_t *)val); }

static inline void      dns_packet_reader_read_s32_unchecked(dns_packet_reader_t *reader, int32_t *val)
{
    dns_packet_reader_read_u32_unchecked(reader, (uint32_t *)val); // wrapped
}

static inline ya_result dns_packet_reader_skip(dns_packet_reader_t *reader, uint32_t len)
{
    if((reader->packet_offset += len) > reader->packet_size)
    {
        reader->packet_offset = reader->packet_size;
        return UNEXPECTED_EOF; /* unexpected EOF */
    }

    return len;
}

static inline void    dns_packet_reader_skip_unchecked(dns_packet_reader_t *reader, uint32_t len) { reader->packet_offset += len; }

static inline int32_t dns_packet_reader_available(dns_packet_reader_t *reader) { return (int32_t)reader->packet_size - (int32_t)reader->packet_offset; }

void                  dns_packet_reader_rewind(dns_packet_reader_t *reader);

ya_result             dns_packet_reader_skip_fqdn(dns_packet_reader_t *reader);
ya_result             dns_packet_reader_skip_record(dns_packet_reader_t *reader);

/* two tools functions for the controller */

ya_result                    dns_packet_reader_read_utf8(dns_packet_reader_t *reader, uint16_t rdatasize, uint16_t rclass, char **txt, bool dryrun);

ya_result                    dns_packet_reader_read_remote_server(dns_packet_reader_t *reader, uint16_t rdatasize, uint16_t rclass, host_address_t **ha, bool dryrun);

static inline const uint8_t *dns_packet_reader_get_next_u8_ptr_const(const dns_packet_reader_t *reader) { return &reader->packet[reader->packet_offset]; }

static inline void           dns_packet_reader_set_position(dns_packet_reader_t *reader, uint32_t position) { reader->packet_offset = position; }

static inline uint32_t       dns_packet_reader_position(dns_packet_reader_t *reader) { return reader->packet_offset; }

#ifdef __cplusplus
}
#endif

#endif /* _PACKET_READER_H */

/** @} */
