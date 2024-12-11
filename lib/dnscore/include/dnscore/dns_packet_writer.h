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
 * @defgroup dnspacket DNS Messages
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _PACKET_WRITER_H
#define _PACKET_WRITER_H

#include <dnscore/sys_types.h>
#include <dnscore/output_stream.h>
#include <dnscore/dns_message.h>
#include <dnscore/dns_resource_record.h>

#define PW_MESSAGE_BUFFER_SIZE 0x10500

#ifdef __cplusplus
extern "C"
{
#endif

struct dns_packet_dictionary_node_s // 16 / 28
{
    struct dns_packet_dictionary_node_s *next;
    struct dns_packet_dictionary_node_s *child;
    uint8_t                             *label;
    uint32_t                             offset;
};

typedef struct dns_packet_dictionary_node_s dns_packet_dictionary_node_t;

struct dns_packet_writer_s
{
    dns_packet_dictionary_node_t *head;      //     4  8
    dns_packet_dictionary_node_t *pool_head; //     8 16

    uint8_t                      *packet; //    12 24

    uint32_t                      packet_offset; //    16 28
    uint32_t                      packet_limit;  //    20 32

    dns_packet_dictionary_node_t  pool[4096]; // 65556 114720 or 131104 (depending on struct alignment)
};

typedef struct dns_packet_writer_s dns_packet_writer_t;

/**
 *
 * creates an new packet
 *
 * @param pw
 * @param packet
 * @param limit
 */

void dns_packet_writer_create(dns_packet_writer_t *pw, uint8_t *packet, uint32_t limit);

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

ya_result               dns_packet_writer_init(dns_packet_writer_t *pw, uint8_t *packet, uint32_t packet_offset, uint32_t size_limit);

static inline ya_result dns_packet_writer_init_append_to_message(dns_packet_writer_t *pw, dns_message_t *mesg)
{ // do not use the logical max
    return dns_packet_writer_init(pw, dns_message_get_buffer(mesg), dns_message_get_size(mesg), dns_message_get_buffer_size_max(mesg));
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

static inline ya_result dns_packet_writer_init_from_message(dns_packet_writer_t *pw, dns_message_t *mesg)
{ // do not use the logical max
    return dns_packet_writer_init(pw, dns_message_get_buffer(mesg), dns_message_get_size(mesg), dns_message_get_buffer_size_max(mesg));
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

static inline void dns_packet_writer_init_into_message(dns_packet_writer_t *pw, dns_message_t *mesg)
{ // do not use the logical max
    dns_packet_writer_create(pw, dns_message_get_buffer(mesg), dns_message_get_buffer_size_max(mesg));
}

/**
 * @note uncompressed names will not be compressed, of course *** BUT ***
 *       they will not be used in the compression dictionnary either
 */

ya_result dns_packet_writer_add_fqdn_uncompressed(dns_packet_writer_t *pw, const uint8_t *fqdn);
ya_result dns_packet_writer_add_fqdn(dns_packet_writer_t *pw, const uint8_t *fqdn);

/**
 * Writes the RDATA size + RDATA bytes, compressed if appropriate.
 *
 * @param pc the packet writer
 * @param rr_type the record type
 * @param rdata the rdata to write
 * @param rdata_size the (compressed) rdata size
 *
 * @return the offset in the packet
 */

ya_result          dns_packet_writer_add_rdata(dns_packet_writer_t *pw, uint16_t rr_type, const uint8_t *rdata, uint16_t rdata_len);
ya_result          dns_packet_writer_encode_base32hex_digest(dns_packet_writer_t *pw, const uint8_t *digest);

ya_result          dns_packet_writer_add_record(dns_packet_writer_t *pw, const uint8_t *fqdn, uint16_t rr_type, uint16_t rr_class, uint32_t ttl, const uint8_t *rdata, uint16_t rdata_len);
ya_result          dns_packet_writer_add_dnsrr(dns_packet_writer_t *pw, const dns_resource_record_t *dns_rr);

static inline void dns_packet_writer_set_truncated(dns_packet_writer_t *pw) { MESSAGE_HIFLAGS(pw->packet) |= TC_BITS | QR_BITS; }

static inline void dns_packet_writer_forward(dns_packet_writer_t *pw, uint32_t bytes)
{
    assert(pw->packet_offset + bytes <= pw->packet_limit);
    pw->packet_offset += bytes;
}

static inline void dns_packet_writer_set_u8(dns_packet_writer_t *pw, uint16_t value, uint32_t offset)
{
    assert(pw->packet_offset <= pw->packet_limit);
    pw->packet[offset] = value;
}

static inline void dns_packet_writer_add_u8(dns_packet_writer_t *pw, uint16_t value)
{
    assert(pw->packet_offset + 1 <= pw->packet_limit);
    pw->packet[pw->packet_offset++] = value;
}

static inline void dns_packet_writer_set_u16(dns_packet_writer_t *pw, uint16_t value, uint32_t offset) { SET_U16_AT(pw->packet[offset], value); }

static inline void dns_packet_writer_add_u16(dns_packet_writer_t *pw, uint16_t value)
{
    assert(pw->packet_offset + 2 <= pw->packet_limit);
    SET_U16_AT(pw->packet[pw->packet_offset], value);
    pw->packet_offset += 2;
}

static inline void dns_packet_writer_add_u32(dns_packet_writer_t *pw, uint32_t value)
{
    assert(pw->packet_offset + 4 <= pw->packet_limit);
    SET_U32_AT(pw->packet[pw->packet_offset], value);
    pw->packet_offset += 4;
}

static inline void dns_packet_writer_set_u32(dns_packet_writer_t *pw, uint32_t value, uint32_t offset)
{
    assert(offset + 4 <= pw->packet_limit);
    SET_U32_AT(pw->packet[offset], value);
}

static inline void dns_packet_writer_add_bytes(dns_packet_writer_t *pw, const uint8_t *buffer, uint32_t len)
{
    assert(pw->packet_offset + len <= pw->packet_limit);
    MEMCOPY(&pw->packet[pw->packet_offset], buffer, len);
    pw->packet_offset += len;
}

static inline uint32_t dns_packet_writer_get_offset(const dns_packet_writer_t *pw) { return pw->packet_offset; }

static inline void     dns_packet_writer_set_offset(dns_packet_writer_t *pw, uint32_t offset)
{
    assert(offset <= pw->packet_limit);
    pw->packet_offset = offset;
}

static inline uint32_t dns_packet_writer_get_limit(const dns_packet_writer_t *pw) { return pw->packet_limit; }

static inline int32_t  dns_packet_writer_get_remaining_capacity(const dns_packet_writer_t *pw)
{
    assert(pw->packet_offset <= pw->packet_limit);
    return (int32_t)pw->packet_limit - (int32_t)pw->packet_offset;
}

static inline uint8_t *dns_packet_writer_get_next_u8_ptr(const dns_packet_writer_t *pw) { return &pw->packet[pw->packet_offset]; }

ya_result              dns_packet_write_tcp(dns_packet_writer_t *pw, output_stream_t *tcpos);

#ifdef __cplusplus
}
#endif

#endif /* _PACKET_WRITER_H */
/** @} */
