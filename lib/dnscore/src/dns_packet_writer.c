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
#include "dnscore/dnscore_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <dnscore/base32hex.h>

#include <dnscore/dns_packet_writer.h>
#include "dnscore/dnsname.h"
#include "dnscore/logger.h"
#include "dnscore/dns_message.h"
#include "dnscore/rfc.h"
#include "dnscore/dns_resource_record.h"

extern logger_handle_t *g_system_logger;
#define MODULE_MSG_HANDLE        g_system_logger

#define PACKET_COMPRESSION_DEBUG 0

/*
 *
 */

ya_result dns_packet_writer_init(dns_packet_writer_t *pw, uint8_t *packet, uint32_t packet_offset, uint32_t size_limit)
{
    pw->pool_head = pw->pool;
    pw->head = NULL;

    dns_packet_dictionary_node_t *child_node = NULL;

    uint32_t                      offset = DNS_HEADER_LENGTH;
    if(GET_U64_AT_P(packet + 4) != 0)
    {
        uint8_t *fqdn = &packet[offset];

        while(*fqdn != 0)
        {
            dns_packet_dictionary_node_t *node = pw->pool_head++;

            node->next = NULL;
            node->child = child_node;
            node->label = fqdn;
            node->offset = offset;

            uint8_t len = fqdn[0] + 1;

            fqdn += len;
            offset += len;

            child_node = node;
        }

#if DEBUG
        fqdn += 1 + 2 + 2;

        if(packet_offset < (uint32_t)(fqdn - packet))
        {
            log_err("dns_packet_writer_init expected %u = %u", packet_offset, fqdn - packet);
        }
#endif

        pw->head = child_node;
        pw->packet = packet;
        pw->packet_offset = packet_offset;
        pw->packet_limit = size_limit;
        return SUCCESS;
    }
    else
    {
        pw->packet = packet;
        pw->packet_offset = packet_offset;
        pw->packet_limit = size_limit;
        return SUCCESS;
    }
}

void dns_packet_writer_create(dns_packet_writer_t *pw, uint8_t *packet, uint32_t limit)
{
    pw->pool_head = pw->pool;

    pw->head = NULL;
    pw->packet = packet;
    pw->packet_offset = DNS_HEADER_LENGTH;
    pw->packet_limit = limit;
}

ya_result dns_packet_writer_add_fqdn_uncompressed(dns_packet_writer_t *pc, const uint8_t *fqdn)
{
    pc->packet_offset += dnsname_copy(&pc->packet[pc->packet_offset], fqdn);

    return pc->packet_offset;
}

#if PACKET_COMPRESSION_DEBUG

static char dns_packet_writer_dictionary_node_log_spaces[129] = {'>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>',
                                                                 ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ',
                                                                 ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ',
                                                                 ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', '>', ' ', ' ', ' ', 0};

static void dns_packet_writer_dictionary_node_log(packet_dictionary_node *node, int spaces, dnsname_stack *fqdnp)
{
    while(node != NULL)
    {
        dnsname_stack_push_label(fqdnp, node->label);

        log_debug2("%p [%4i] %04x %s %{dnslabel} : %{dnsnamestack}", node, spaces, node->offset, &dns_packet_writer_dictionary_node_log_spaces[sizeof(dns_packet_writer_dictionary_node_log_spaces) - 1 - 4 * spaces], node->label, fqdnp);

        packet_dictionary_node *child = node->child;
        if(child != NULL)
        {
            do
            {
                dns_packet_writer_dictionary_node_log(child, spaces + 1, fqdnp);
                child = child->child;
            } while(child != NULL);
        }

        dnsname_stack_pop_label(fqdnp);

        node = node->next;
    }
}

static void dns_packet_writer_dictionary_log(dns_packet_writer *pc)
{
    dnsname_stack fqdn;
    fqdn.size = -1;

    packet_dictionary_node *node = pc->head;
    log_debug2("packet_writer_dictionary_log(%p)", pc);
    dns_packet_writer_dictionary_node_log(node, 0, &fqdn);
}

#endif // PACKET_COMPRESSION_DEBUG

ya_result dns_packet_writer_add_fqdn(dns_packet_writer_t *pc, const uint8_t *fqdn)
{
#if PACKET_COMPRESSION_DEBUG
    log_debug2("packet_writer_add_fqdn(%p, %{dnsname} @ %04x)", pc, fqdn, pc->packet_offset);
#endif

    dnslabel_vector_t             name;
    int32_t                       top = dnsname_to_dnslabel_vector(fqdn, name);
    int32_t                       best_top = top + 1;
    dns_packet_dictionary_node_t *best = NULL;
    dns_packet_dictionary_node_t *node = pc->head;
    uint8_t                      *packet_base = pc->packet;
    uint32_t                      offset = pc->packet_offset;
    uint32_t                      limit = pc->packet_limit;

    /* Look for the name in the compression dictionary */

    if((node != NULL) && (top >= 0))
    {
        for(;;)
        {
            if(dnslabel_equals_ignorecase_left(name[top], node->label))
            {
                /* we got a match on this level */

                best = node;
                best_top = top;

                node = node->child;

                if(node == NULL)
                {
                    break;
                }

                if(--top < 0)
                {
                    break;
                }
            }
            else if((node = node->next) == NULL)
            {
                break;
            }
        }
    }

    /* Every label in the interval [0;best_top is new */
    /* Create a compression dictionary entry for each of them
     * along with their writing.
     */

    dns_packet_dictionary_node_t *child_node = NULL;

    uint8_t                      *packet = &packet_base[offset];

    if(best_top > 0)
    {
        top = 0;

        if(offset < 0x3ffe)
        {
            do
            {
                uint8_t len = name[top][0] + 1;

                if(offset + len >= limit)
                {
                    return BUFFER_WOULD_OVERFLOW;
                }

                MEMCOPY(packet, name[top], len);

                node = pc->pool_head++;
                node->next = NULL;
                node->child = child_node;
                node->label = packet;
                node->offset = offset;

                child_node = node;

                packet += len;
                offset += len;
            } while(++top < best_top);

            if(offset >= 0x4000)
            {
                child_node = NULL;
            }
        }
        else
        {
            do
            {
                uint8_t len = name[top][0] + 1;

                if(offset + len >= limit)
                {
                    return BUFFER_WOULD_OVERFLOW;
                }

                MEMCOPY(packet, name[top], len);

                packet += len;
                offset += len;
            } while(++top < best_top);
        }
    }

    if(best != NULL)
    {
        /* found a (partial) match */
        /* Add the new chain to the parent */

        if(offset + 2 >= limit)
        {
            return BUFFER_WOULD_OVERFLOW;
        }

        if(child_node != NULL)
        {
            child_node->next = best->child;
            best->child = child_node;
        }

        *packet++ = (best->offset >> 8) | 0xc0;
        *packet = (best->offset & 0xff);

        offset += 2;
    }
    else
    {
        /* create a new entry */

        /* child_node can be null if we tried to write something beyond the
         * 16KB limit
         *
         */

        if(offset + 1 >= limit)
        {
            return BUFFER_WOULD_OVERFLOW;
        }

        if(child_node != NULL)
        {
            child_node->next = pc->head;
            pc->head = child_node;
        }

        *packet = 0;

        offset++;
    }

    pc->packet_offset = offset;

#if PACKET_COMPRESSION_DEBUG
    dns_packet_writer_dictionary_log(pc);
    log_debug2("packet_writer_add_fqdn(%p, %{dnsname}) = %i", pc, fqdn, offset);
#endif

    return offset;
}

/**
 * Writes the RDATA size + RDATA bytes, compressed if appropriate.
 *
 * @param pw the packet writer
 * @param rr_type the record type
 * @param rdata the rdata to write
 * @param rdata_len the (compressed) rdata size
 *
 * @return the offset in the packet
 */

ya_result dns_packet_writer_add_rdata(dns_packet_writer_t *pw, uint16_t rr_type, const uint8_t *rdata, uint16_t rdata_len)
{
    yassert(pw->packet_offset + rdata_len < pw->packet_limit);

    uint32_t offset = pw->packet_offset;
    pw->packet_offset += 2;

    switch(rr_type)
    {
        case TYPE_MX:

            dns_packet_writer_add_bytes(pw, rdata, 2);
            rdata += 2;

            /* Fallthrough */

        case TYPE_NS:
        case TYPE_CNAME:
        case TYPE_DNAME:
        case TYPE_PTR:
        case TYPE_MB:
        case TYPE_MD:
        case TYPE_MF:
        case TYPE_MG:
        case TYPE_MR:
            /* ONE NAME record */
            {
                dns_packet_writer_add_fqdn(pw, rdata);

                dns_packet_writer_set_u16(pw, htons(pw->packet_offset - offset - 2), offset);

                break;
            }
        case TYPE_SOA:
        {
            uint32_t len1 = dnsname_len(rdata);
            dns_packet_writer_add_fqdn(pw, rdata);
            rdata += len1;

            uint32_t len2 = dnsname_len(rdata);
            dns_packet_writer_add_fqdn(pw, rdata);
            rdata += len2;

            dns_packet_writer_add_bytes(pw, rdata, 20);

            dns_packet_writer_set_u16(pw, htons(pw->packet_offset - offset - 2), offset);

            break;
        }
        default:
        {
            dns_packet_writer_set_u16(pw, htons(rdata_len), offset);
            dns_packet_writer_add_bytes(pw, rdata, rdata_len);
            break;
        }
    } /* switch(type) */

    return pw->packet_offset;
}

ya_result dns_packet_writer_encode_base32hex_digest(dns_packet_writer_t *pw, const uint8_t *digest)
{
    pw->packet[pw->packet_offset++] = BASE32HEX_ENCODED_LEN(SHA_DIGEST_LENGTH);
    /*uint32_t b32_len =*/base32hex_encode_lc(digest, SHA_DIGEST_LENGTH, (char *)&pw->packet[pw->packet_offset]);
    pw->packet_offset += BASE32HEX_ENCODED_LEN(SHA_DIGEST_LENGTH);
    return BASE32HEX_ENCODED_LEN(SHA_DIGEST_LENGTH) + 1;
}

/**
 * Writes the content of the buffer of a packet writer to a TCP output stream,
 * that is: first the size of the buffer in network endiant 16 bits followed
 * by the actual content of the buffer
 *
 * @param pw the packet writer whose content needs to be written
 * @param tcpos the TCP output stream
 *
 * @return an error code or the size of the buffer
 */

ya_result dns_packet_write_tcp(dns_packet_writer_t *pw, output_stream_t *tcpos)
{
    int n;

    if(FAIL(n = output_stream_write_nu16(tcpos, pw->packet_offset)))
    {
        return n;
    }

    if(FAIL(n = output_stream_write(tcpos, pw->packet, pw->packet_offset)))
    {
        return n;
    }

    return n;
}

ya_result dns_packet_writer_add_record(dns_packet_writer_t *pw, const uint8_t *fqdn, uint16_t rr_type, uint16_t rr_class, uint32_t ttl, const uint8_t *rdata, uint16_t rdata_len)
{
    ya_result return_code;

    uint32_t  offset = pw->packet_offset;

    if(ISOK(return_code = dns_packet_writer_add_fqdn(pw, fqdn)))
    {
        if(pw->packet_limit - pw->packet_offset >= 10)
        {
            dns_packet_writer_add_u16(pw, rr_type);
            dns_packet_writer_add_u16(pw, rr_class);
            dns_packet_writer_add_u32(pw, ttl);

            if(ISOK(return_code = dns_packet_writer_add_rdata(pw, rr_type, rdata, rdata_len)))
            {
                return pw->packet_offset;
            }
        }
    }

    pw->packet_offset = offset;

    return return_code;
}

ya_result dns_packet_writer_add_dnsrr(dns_packet_writer_t *pw, const dns_resource_record_t *dns_rr)
{
    ya_result return_code;

    uint32_t  offset = pw->packet_offset;

    if(ISOK(return_code = dns_packet_writer_add_fqdn(pw, dns_rr->name)))
    {
        if(pw->packet_limit - pw->packet_offset >= 10)
        {
            dns_packet_writer_add_u16(pw, dns_rr->tctr.rtype);
            dns_packet_writer_add_u16(pw, dns_rr->tctr.rclass);
            dns_packet_writer_add_u32(pw, dns_rr->tctr.ttl);

            if(ISOK(return_code = dns_packet_writer_add_rdata(pw, dns_rr->tctr.rtype, dns_rr->rdata, dns_rr->rdata_size)))
            {
                return pw->packet_offset;
            }
        }
    }

    pw->packet_offset = offset;

    return return_code;
}

/** @} */
