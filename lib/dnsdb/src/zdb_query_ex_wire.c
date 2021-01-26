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

/** @defgroup query_ex Database top-level query function
 *  @ingroup dnsdb
 *  @brief Database top-level query function
 *
 *  Database top-level query function
 *
 * @{
 */

#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "dnsdb/dnsdb-config.h"

#include "dnsdb/zdb_types.h"

#include <dnscore/format.h>
#include <dnscore/message.h>
#include <dnscore/packet_writer.h>

#include <dnscore/logger.h>

#include "dnsdb/htable.h"
#include "dnscore/hash.h"
#include "dnsdb/dnsdb-config.h"

#if ZDB_HAS_NSID_SUPPORT
#include <dnscore/nsid.h>
#endif

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define ANSWER_DO_COMPRESSION 1

#if BYTE_ORDER==BIG_ENDIAN
#define ENCODE_OFFSET(offset) (offset|0xc000)
#else
#define ENCODE_OFFSET(offset) ((offset>>8)|(offset<<8)|0x00c0)
#endif

extern process_flags_t zdb_query_process_flags;

/**
 * @note I could also have tables by label depth.
 *       But I'll need more time to experiment this.
 * 
 * @note Only used in zdb_query_message_update
 */

static bool
zdb_query_message_update_write_label(const zdb_resourcerecord* rr, u32* countp, packet_writer* pc, u32 max_size)
{
    u32 count = 0;
    bool fully_written = TRUE;

    while(rr != NULL)
    {
        /* Store the name */
        const u8* name = rr->name;

        u16 rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(rr->ttl_rdata);

        u32 offset_backup = pc->packet_offset;

        /* copy the name */

#if !ANSWER_DO_COMPRESSION
        packet_writer_add_fqdn_uncompressed(pc, name);
#else
        if(FAIL(packet_writer_add_fqdn(pc, name)))
        {
            pc->packet_offset = offset_backup;
            return FALSE;
        }
#endif
        /* copy the TYPE + CLASS + RDATA SIZE */

        /* Here we do compression (or not) */

#if !ANSWER_DO_COMPRESSION

        if(pc->packet_offset + 2 + 2 + 4 + 2 + rdata_size >= pc->packet_limit)
        {
            pc->packet_offset = offset_backup;
            return FALSE;
        }

        packet_writer_add_u16(pc, (rr->rtype)); /** @note: NATIVETYPE */
        packet_writer_add_u16(pc, (rr->zclass)); /** @note: NATIVECLASS */

        packet_writer_add_u32(pc, htonl(rr->ttl));

        /* Store the RDATA len (16 bits) */

        u8* rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(rr->ttl_rdata);

        packet_writer_add_u16(pc, htons(rdata_size));

        /* copy the RDATA */

        packet_writer_add_bytes(pc, rdata, rdata_size);

#else
        if(pc->packet_offset + 2 + 2 + 4 + 2 >= pc->packet_limit)
        {
            pc->packet_offset = offset_backup;
            return FALSE;
        }

        packet_writer_add_u16(pc, (rr->rtype)); /** @note: NATIVETYPE */
        packet_writer_add_u16(pc, (rr->zclass)); /** @note: NATIVECLASS */
        packet_writer_add_u32(pc, htonl(rr->ttl));

        u32 offset = pc->packet_offset;
        u8* rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(rr->ttl_rdata);
        pc->packet_offset += 2;

        switch(rr->rtype)
        {
            case TYPE_MX:

                if(pc->packet_offset + 2 >= pc->packet_limit)
                {
                    pc->packet_offset = offset_backup;
                    return FALSE;
                }

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
                if(FAIL(packet_writer_add_fqdn(pc, rdata)))
                {
                    pc->packet_offset = offset_backup;
                    return FALSE;
                }

                packet_writer_set_u16(pc, htons(pc->packet_offset - offset - 2), offset);

                break;
            }
            case TYPE_SOA:
            {
                u32 len1 = dnsname_len(rdata);
                if(FAIL(packet_writer_add_fqdn(pc, rdata)))
                {
                    pc->packet_offset = offset_backup;
                    return FALSE;
                }
                rdata += len1;

                u32 len2 = dnsname_len(rdata);
                if(FAIL(packet_writer_add_fqdn(pc, rdata)))
                {
                    pc->packet_offset = offset_backup;
                    return FALSE;
                }
                rdata += len2;

                if(pc->packet_offset + 20 >= pc->packet_limit)
                {
                    pc->packet_offset = offset_backup;
                    return FALSE;
                }

                packet_writer_add_bytes(pc, rdata, 20);

                packet_writer_set_u16(pc, htons(pc->packet_offset - offset - 2), offset);

                break;
            }
            default:
            {
                if(pc->packet_offset + rdata_size >= pc->packet_limit)
                {
                    pc->packet_offset = offset_backup;
                    return FALSE;
                }

                packet_writer_set_u16(pc, htons(rdata_size), offset);
                packet_writer_add_bytes(pc, rdata, rdata_size);
                break;
            }
        } /* switch(type) */
#endif

        /*
         * If we are beyond the limit, we restore the offset and stop here.
         */

        if(pc->packet_offset > max_size)
        {
            pc->packet_offset = offset_backup;

            fully_written = FALSE;
            break;
        }

        count++;

        rr = rr->next;
    }

    *countp = count; /* stores the count */

    return fully_written; /* returns the offset of the next writable byte */
}

extern u16 edns0_maxsize;

void
zdb_query_message_update(message_data* mesg, const zdb_query_ex_answer* answer_set)
{
    /*
     *
     * OPCODE       (16 bits)
     * QUERY            "
     * ANSWER           "
     * AUTHORITY        "
     * ADDITIONAL       "
     *
     */

    /* Insert the query */
    message_header* header = message_get_header(mesg);
    
    message_set_referral(mesg, answer_set->delegation);

    u32 count;

    bool fully_written;

    /* Initialize the compression dictionnary with the query */

    packet_writer pw;

#if DEBUG
    count = ~0;
    memset(&pw, 0xff, sizeof(pw));
#endif

    if(message_is_edns0(mesg))
    {
#if ZDB_HAS_NSID_SUPPORT
        message_reserve_buffer_size(mesg, edns0_record_size); /* edns0 opt record */
#else
        message_reserve_buffer_size(mesg, EDNS0_RECORD_SIZE); /* edns0 opt record */
#endif
    }

    packet_writer_init_append_to_message(&pw, mesg);

    // write_label handles truncation
    
    u32 max_size = message_get_buffer_size(mesg);       // valid use of message_get_buffer_size()
    
    fully_written = zdb_query_message_update_write_label(answer_set->answer, &count, &pw, max_size);
    header->ancount = htons(count);
    header->nscount = 0;
    header->arcount = 0;
    
    if(fully_written)
    {
        if((zdb_query_process_flags & PROCESS_FL_AUTHORITY_AUTH) != 0)
        {
            fully_written = zdb_query_message_update_write_label(answer_set->authority, &count, &pw, max_size);
            header->nscount = htons(count);
        }

        if(fully_written && ((zdb_query_process_flags & PROCESS_FL_ADDITIONAL_AUTH) != 0))
        {
            /* fully_written = */ zdb_query_message_update_write_label(answer_set->additional, &count, &pw, max_size);
            header->arcount = htons(count);
        }
    }
    
    if(message_is_edns0(mesg))
    {
        /* 00 00 29 SS SS rr vv 80 00 00 00 */
        /* 00 00 29 SS SS rr vv 80 00 |opt| 00 03 |nsid| nsid */

#if ZDB_HAS_NSID_SUPPORT
        if(!message_has_nsid(mesg))
        {
            message_increase_buffer_size(mesg, EDNS0_RECORD_SIZE); /* edns0 opt record */

            memset(&pw.packet[pw.packet_offset], 0, EDNS0_RECORD_SIZE);
            pw.packet_offset += 2;
            pw.packet[pw.packet_offset++] = 0x29;
            packet_writer_add_u16(&pw, htons(edns0_maxsize));
            packet_writer_add_u32(&pw, message_get_rcode_ext(mesg));
            pw.packet_offset += 2; // rdata size already set to 0, skip it
        }
        else
        {
            message_increase_buffer_size(mesg, edns0_record_size); /* edns0 opt record */

            packet_writer_add_u16(&pw, 0);          // fqdn + 1st half of type
            pw.packet[pw.packet_offset++] = 0x29;   // 2nd half of type

            packet_writer_add_u16(&pw, htons(edns0_maxsize));
            packet_writer_add_u32(&pw, message_get_rcode_ext(mesg));

            memcpy(&pw.packet[pw.packet_offset], edns0_rdatasize_nsid_option_wire, edns0_rdatasize_nsid_option_wire_size);
            pw.packet_offset += edns0_rdatasize_nsid_option_wire_size;
        }
#else
        message_increase_buffer_size(mesg, EDNS0_RECORD_SIZE); /* edns0 opt record */
        
        pw.packet_limit += EDNS0_RECORD_SIZE;
        memset(&pw.packet[pw.packet_offset], 0, EDNS0_RECORD_SIZE);
        pw.packet_offset += 2;
        pw.packet[pw.packet_offset++] = 0x29;
        packet_writer_add_u16(&pw, htons(edns0_maxsize));
        packet_writer_add_u32(&pw, message_get_rcode_ext(mesg));
        pw.packet_offset += 2; // rdata size already set to 0, skip it
#endif

        header->arcount = htons(ntohs(header->arcount) + 1);
    }

    if(fully_written)
    {
         message_update_answer_status(mesg);
    }
    else
    {
        /* TC ! */

        message_update_truncated_answer_status(mesg);
    }

    message_set_size(mesg, pw.packet_offset);
}

/** @} */
