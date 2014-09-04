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
/** @defgroup query_ex Database top-level query function
 *  @ingroup dnsdb
 *  @brief Database top-level query function
 *
 *  Database top-level query function
 *
 * @{
 */

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "dnsdb-config.h"

#include "dnsdb/zdb_types.h"

#include <dnscore/format.h>
#include <dnscore/message.h>
#include <dnscore/packet_writer.h>

#include <dnscore/logger.h>

#include "dnsdb/htable.h"
#include "dnsdb/hash.h"
#include "dnsdb/dnsdb-config.h"

#if HAS_NSID_SUPPORT
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

/**
 * @note I could also have tables by label depth.
 *       But I'll need more time to experiment this.
 */

static bool
write_label(zdb_resourcerecord* rr, u32* countp, packet_writer* pc)
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

#if ANSWER_DO_COMPRESSION == 0
        packet_writer_add_fqdn_uncompressed(pc, name);
#else
        packet_writer_add_fqdn(pc, name);
#endif
        /* copy the TYPE + CLASS + RDATA SIZE */

        packet_writer_add_u16(pc, (rr->rtype)); /** @note: NATIVETYPE */
        packet_writer_add_u16(pc, (rr->zclass)); /** @note: NATIVECLASS */
        
        packet_writer_add_u32(pc, htonl(rr->ttl));

        /* Here we do compression (or not) */

#if ANSWER_DO_COMPRESSION == 0
        /* Store the RDATA len (16 bits) */

        u8* rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(rr->ttl_rdata);

        packet_writer_add_u16(pc, htons(rdata_size));

        /* copy the RDATA */

        packet_writer_add_bytes(pc, rdata, rdata_size);

#else
        u32 offset = pc->packet_offset;
        u8* rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(rr->ttl_rdata);
        pc->packet_offset += 2;

        switch(rr->rtype)
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
#endif

        /*
         * If we are beyond the limit, we restore the offset and stop here.
         */

        if(pc->packet_offset > pc->packet_limit)
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

ya_result
zdb_query_message_update(message_data* message, zdb_query_ex_answer* answer_set)
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
    message_header* header = (message_header*)message->buffer;

    u32 count;

    bool fully_written;

    /* Initialize the compression dictionnary with the query */

    packet_writer pc;

#ifdef DEBUG
    count = ~0;
    memset(&pc, 0xff, sizeof (pc));
#endif

    if(message->edns)
    {
#if HAS_NSID_SUPPORT
        message->size_limit -= edns0_record_size;  /* edns0 opt record */
#else
        message->size_limit -= EDNS0_RECORD_SIZE;  /* edns0 opt record */
#endif
    }

    packet_writer_init(&pc, message->buffer, message->received, message->size_limit);

    // write_label handles truncation
    
    fully_written = write_label(answer_set->answer, &count, &pc);
    header->ancount = htons(count);
    header->nscount = 0;
    header->arcount = 0;

    if(fully_written)
    {
        if((message->process_flags & PROCESS_FL_AUTHORITY_AUTH) != 0)
        {
            fully_written = write_label(answer_set->authority, &count, &pc);
            header->nscount = htons(count);
        }

        if(fully_written && ((message->process_flags & PROCESS_FL_ADDITIONAL_AUTH) != 0))
        {
            /* fully_written = */ write_label(answer_set->additional, &count, &pc);
            header->arcount = htons(count);
        }
    }
    
    if(message->edns)
    {
        /* 00 00 29 SS SS rr vv 80 00 00 00 */
        /* 00 00 29 SS SS rr vv 80 00 |opt| 00 03 |nsid| nsid */

#if HAS_NSID_SUPPORT
        if(!message->nsid)
        {
            message->size_limit += EDNS0_RECORD_SIZE;  /* edns0 opt record */
            pc.packet_limit += EDNS0_RECORD_SIZE;

            memset(&pc.packet[pc.packet_offset], 0, EDNS0_RECORD_SIZE);
            pc.packet_offset += 2;
            pc.packet[pc.packet_offset++] = 0x29;
            packet_writer_add_u16(&pc, htons(edns0_maxsize));
            packet_writer_add_u32(&pc, message->rcode_ext);
            pc.packet_offset += 2; // rdata size already set to 0, skip it
        }
        else
        {
            message->size_limit += edns0_record_size;  /* edns0 opt record */
            pc.packet_limit += edns0_record_size;

            packet_writer_add_u16(&pc, 0);          // fqdn + 1st half of type
            pc.packet[pc.packet_offset++] = 0x29;   // 2nd half of type

            packet_writer_add_u16(&pc, htons(edns0_maxsize));
            packet_writer_add_u32(&pc, message->rcode_ext);

            memcpy(&pc.packet[pc.packet_offset], edns0_rdatasize_nsid_option_wire, edns0_rdatasize_nsid_option_wire_size);
            pc.packet_offset += edns0_rdatasize_nsid_option_wire_size;
        }
#else
        message->size_limit += EDNS0_RECORD_SIZE;  /* edns0 opt record */
        pc.packet_limit += EDNS0_RECORD_SIZE;
        
        memset(&pc.packet[pc.packet_offset], 0, EDNS0_RECORD_SIZE);
        pc.packet_offset += 2;
        pc.packet[pc.packet_offset++] = 0x29;
        packet_writer_add_u16(&pc, htons(edns0_maxsize));
        packet_writer_add_u32(&pc, message->rcode_ext);
        pc.packet_offset += 2; // rdata size already set to 0, skip it
#endif

        header->arcount = htons(ntohs(header->arcount) + 1);
    }

    u16 hi;

    if(fully_written)
    {
         hi = QR_BITS;
    }
    else
    {
        /* TC ! */

        hi = QR_BITS|TC_BITS;
    }

    MESSAGE_FLAGS_OR(message->buffer, hi, message->status);

    return pc.packet_offset;
}

/** @} */
