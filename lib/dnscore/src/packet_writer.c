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
#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>

#include "dnscore/packet_writer.h"
#include "dnscore/dnsname.h"
#include "dnscore/logger.h"
#include "dnscore/message.h"
#include "dnscore/rfc.h"
#include "dnscore/dns_resource_record.h"

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#define PACKET_COMPRESSION_DEBUG 0

/*
 *
 */

ya_result
packet_writer_init(packet_writer* pc, u8* packet, u32 packet_offset, u32 size_limit)
{
    pc->pool_head = pc->pool;
    pc->head = NULL;

    packet_dictionary_node* child_node = NULL;

    u32 offset = DNS_HEADER_LENGTH;
    u8* fqdn = &packet[offset];

    while(*fqdn != 0)
    {
        packet_dictionary_node* node = pc->pool_head++;

        node->next = NULL;
        node->child = child_node;
        node->label = fqdn;
        node->offset = offset;

        u8 len = fqdn[0] + 1;

        fqdn += len;
        offset += len;

        child_node = node;
    }
    
#if DEBUG
    fqdn += 1 + 2 + 2;
    
    if(packet_offset < fqdn - packet)
    {
        log_err("packet_writer_init expected %u = %u", packet_offset, fqdn - packet);
    }
#endif

    pc->head = child_node;
    pc->packet = packet;
    pc->packet_offset = packet_offset;
    pc->packet_limit = size_limit;

    return SUCCESS;
}

void
packet_writer_create(packet_writer* pc, u8* packet, u32 limit)
{
    pc->pool_head = pc->pool;
    
    pc->head = NULL;
    pc->packet = packet;
    pc->packet_offset = DNS_HEADER_LENGTH;
    pc->packet_limit = limit;
}

ya_result
packet_writer_add_fqdn_uncompressed(packet_writer* pc, const u8* fqdn)
{
    pc->packet_offset += dnsname_copy(&pc->packet[pc->packet_offset], fqdn);

    return pc->packet_offset;
}

#if PACKET_COMPRESSION_DEBUG

static char packet_writer_dictionary_node_log_spaces[129] =
{
    '>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ',
    '>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ',
    '>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ',
    '>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ',
    '>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ',
    '>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ',
    '>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ',
    '>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ','>',' ',' ',' ',
    0
};

static void packet_writer_dictionary_node_log(packet_dictionary_node* node, int spaces, dnsname_stack *fqdnp)
{
    while(node != NULL)
    {
        dnsname_stack_push_label(fqdnp, node->label);

        log_debug2("%p [%4i] %04x %s %{dnslabel} : %{dnsnamestack}", node, spaces, node->offset, &packet_writer_dictionary_node_log_spaces[sizeof(packet_writer_dictionary_node_log_spaces) - 1 - 4 * spaces], node->label, fqdnp);

        packet_dictionary_node* child = node->child;
        if(child != NULL)
        {
            do
            {
                packet_writer_dictionary_node_log(child, spaces + 1, fqdnp);
                child = child->child;
            }
            while(child != NULL);
        }

        dnsname_stack_pop_label(fqdnp);

        node = node->next;
    }
}

static void packet_writer_dictionary_log(packet_writer* pc)
{
    dnsname_stack fqdn;
    fqdn.size = -1;

    packet_dictionary_node* node = pc->head;
    log_debug2("packet_writer_dictionary_log(%p)", pc);
    packet_writer_dictionary_node_log(node, 0, &fqdn);
}

#endif // PACKET_COMPRESSION_DEBUG

ya_result
packet_writer_add_fqdn(packet_writer* pc, const u8* fqdn)
{
#if PACKET_COMPRESSION_DEBUG
    log_debug2("packet_writer_add_fqdn(%p, %{dnsname} @ %04x)", pc, fqdn, pc->packet_offset);
#endif

    dnslabel_vector name;
    s32 top = dnsname_to_dnslabel_vector(fqdn, name);
    s32 best_top = top + 1;
    packet_dictionary_node* best = NULL;
    packet_dictionary_node* node = pc->head;
    u8 *packet_base = pc->packet;
    u32 offset = pc->packet_offset;
    u32 limit = pc->packet_limit;

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

    packet_dictionary_node* child_node = NULL;

    u8* packet = &packet_base[offset];

    if(best_top > 0)
    {
        top = 0;

        if(offset < 0x3ffe)
        {
            do
            {
                u8 len = name[top][0] + 1;

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
            }
            while(++top < best_top);

            if(offset >= 0x4000)
            {
                child_node = NULL;
            }
        }
        else
        {
            do
            {
                u8 len = name[top][0] + 1;

                if(offset + len >= limit)
                {
                    return BUFFER_WOULD_OVERFLOW;
                }

                MEMCOPY(packet, name[top], len);

                packet += len;
                offset += len;
            }
            while(++top < best_top);
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
    packet_writer_dictionary_log(pc);
    log_debug2("packet_writer_add_fqdn(%p, %{dnsname}) = %i", pc, fqdn, offset);
#endif

    return offset;
}

ya_result
packet_writer_add_rdata(packet_writer* pc, u16 rr_type, const u8* rdata, u16 rdata_size)
{
    yassert(pc->packet_offset + rdata_size < pc->packet_limit);
    
    u32 offset = pc->packet_offset;
    pc->packet_offset += 2;

    switch(rr_type)
    {
        case TYPE_MX:

            packet_writer_add_bytes(pc, rdata, 2);
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
            packet_writer_add_fqdn(pc, rdata);

            packet_writer_set_u16(pc, htons(pc->packet_offset - offset - 2), offset);

            break;
        }
        case TYPE_SOA:
        {
            u32 len1 = dnsname_len(rdata);
            packet_writer_add_fqdn(pc, rdata);
            rdata += len1;

            u32 len2 = dnsname_len(rdata);
            packet_writer_add_fqdn(pc, rdata);
            rdata += len2;

            packet_writer_add_bytes(pc, rdata, 20);

            packet_writer_set_u16(pc, htons(pc->packet_offset - offset - 2), offset);

            break;
        }
        default:
        {
            packet_writer_set_u16(pc, htons(rdata_size), offset);
            packet_writer_add_bytes(pc, rdata, rdata_size);
            break;
        }
    } /* switch(type) */

    return pc->packet_offset;
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

ya_result
write_tcp_packet(packet_writer *pw, output_stream *tcpos)
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

ya_result
packet_writer_add_record(packet_writer* pw, const u8* fqdn, u16 rr_type, u16 rr_class, u32 rr_ttl, const u8* rdata, u16 rdata_size)
{
    ya_result return_code;
    
    u32 offset = pw->packet_offset;
    
    if(ISOK(return_code = packet_writer_add_fqdn(pw, fqdn)))
    {
        if(pw->packet_limit - pw->packet_offset >= 10)
        {
            packet_writer_add_u16(pw, rr_type);
            packet_writer_add_u16(pw, rr_class);
            packet_writer_add_u32(pw, rr_ttl);

            if(ISOK(return_code = packet_writer_add_rdata(pw, rr_type, rdata, rdata_size)))
            {
                return pw->packet_offset;
            }
        }
    }

    pw->packet_offset = offset;

    return return_code;
}

ya_result
packet_writer_add_dnsrr(packet_writer *pw, dns_resource_record* dns_rr)
{
    ya_result return_code;
    
    u32 offset = pw->packet_offset;
    
    if(ISOK(return_code = packet_writer_add_fqdn(pw, dns_rr->name)))
    {
        if(pw->packet_limit - pw->packet_offset >= 10)
        {
            packet_writer_add_u16(pw, dns_rr->tctr.qtype);
            packet_writer_add_u16(pw, dns_rr->tctr.qclass);
            packet_writer_add_u32(pw, dns_rr->tctr.ttl);

            if(ISOK(return_code = packet_writer_add_rdata(pw, dns_rr->tctr.qtype, dns_rr->rdata, dns_rr->rdata_size)))
            {
                return pw->packet_offset;
            }
        }
    }

    pw->packet_offset = offset;

    return return_code;
}

/** @} */
