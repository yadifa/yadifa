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

/** @defgroup dnsdbupdate Dynamic update functions
 *  @ingroup dnsdb
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>

#include "dnsdb/dynupdate-message.h"

#define DMSGPCKT_TAG 0x544b435047534d44

// Disable detailled diff log even in debug builds

#define DYNUPDATE_DIFF_DETAILLED_LOG 0

#ifndef DYNUPDATE_DIFF_DETAILLED_LOG
#if DEBUG
#define DYNUPDATE_DIFF_DETAILLED_LOG 1
#else
#define DYNUPDATE_DIFF_DETAILLED_LOG 0
#endif
#endif

///////////////////////////////////////////////////////////////////////////////

/**
 * Initialises a simple update buffer
 * 
 * @param dmsg
 */

void
dynupdate_message_init(dynupdate_message *dmsg, const u8 *origin, u16 rclass)
{
    dmsg->size = MAX_U16;
    MALLOC_OR_DIE(u8*, dmsg->packet, dmsg->size, DMSGPCKT_TAG);
    // packet_writer_init is for valid messages.  For writing a new message use:
    packet_writer_create(&dmsg->pw, dmsg->packet, dmsg->size);
    dmsg->rclass = rclass;
    message_header *hdr = (message_header*)dmsg->packet;
#if DEBUG
    memset(dmsg->packet, 0xcc, dmsg->size);
#endif
    ZEROMEMORY(hdr, DNS_HEADER_LENGTH);
    hdr->opcode = OPCODE_UPDATE;
    packet_writer_add_fqdn(&dmsg->pw, origin);
    packet_writer_add_u16(&dmsg->pw, TYPE_SOA);
    packet_writer_add_u16(&dmsg->pw, rclass);
    hdr->qdcount = NU16(1);
}

void
dynupdate_message_reset(dynupdate_message *dmsg, const u8 *origin, u16 rclass)
{
    // packet_writer_init is for valid messages.  For writing a new message use:
    packet_writer_create(&dmsg->pw, dmsg->packet, dmsg->size);
    dmsg->rclass = rclass;
    message_header *hdr = (message_header*)dmsg->packet;
#if DEBUG
    memset(dmsg->packet, 0xcc, dmsg->size);
#endif
    ZEROMEMORY(hdr, DNS_HEADER_LENGTH);
    hdr->opcode = OPCODE_UPDATE;
    packet_writer_add_fqdn(&dmsg->pw, origin);
    packet_writer_add_u16(&dmsg->pw, TYPE_SOA);
    packet_writer_add_u16(&dmsg->pw, rclass);
    hdr->qdcount = NU16(1);
}

/**
 * Releases resources.
 * 
 * @param dmsg
 */

void
dynupdate_message_finalize(dynupdate_message *dmsg)
{
    //packet_writer_finalize(&dmsg->pw);
    free(dmsg->packet);
}

/**
 * Sets a reader up for the buffer.
 * 
 * @param dmsg
 * @param purd
 */

void
dynupdate_message_set_reader(dynupdate_message *dmsg, packet_unpack_reader_data *purd)
{
    yassert(dmsg->pw.packet_offset >= DNS_HEADER_LENGTH);
    
    packet_reader_init(purd, dmsg->packet, dmsg->pw.packet_offset);
}

/**
 * Return the number of update records.
 * 
 * @param dmsg
 * @return 
 */

u16
dynupdate_message_get_count(dynupdate_message *dmsg)
{
    message_header *hdr = (message_header*)dmsg->packet;
    u16 count = ntohs(hdr->nscount);
    return count;
}

/**
 * Adds a dnskey record to the buffer
 * 
 * @param dmsg
 * @param ttl
 * @param key
 * @return 
 */

ya_result
dynupdate_message_add_dnskey(dynupdate_message *dmsg, s32 ttl, const dnssec_key *key)
{
    u32 rdata_size = key->vtbl->dnssec_key_rdatasize(key);
    u32 remaining = packet_writer_get_remaining_capacity(&dmsg->pw);
    
    ya_result ret = BUFFER_WOULD_OVERFLOW;
    
    // the first 2 is assuming compression will take place
    // which is as it should be since the messages are initialised with the fqdn of the zone
        
    if(remaining >= 2 + 2 + 2 + 4 + 2 + rdata_size)
    {
        if(ISOK(ret = packet_writer_add_fqdn(&dmsg->pw, &dmsg->packet[DNS_HEADER_LENGTH])))
        {
            packet_writer_add_u16(&dmsg->pw, TYPE_DNSKEY);
            packet_writer_add_u16(&dmsg->pw, dmsg->rclass);
            packet_writer_add_u32(&dmsg->pw, htonl(ttl));
            packet_writer_add_u16(&dmsg->pw, htons(rdata_size));
            key->vtbl->dnssec_key_writerdata(key, packet_writer_get_next_u8_ptr(&dmsg->pw), rdata_size);
            packet_writer_forward(&dmsg->pw, rdata_size);
            message_header *hdr = (message_header*)dmsg->packet;
            hdr->nscount = htons(ntohs(hdr->nscount) + 1);
        }
    }
    
    return ret;
}

/**
 * Deletes a dnskey record to the buffer
 * 
 * @param dmsg
 * @param ttl
 * @param key
 * @return 
 */

ya_result
dynupdate_message_del_dnskey(dynupdate_message *dmsg, const dnssec_key *key)
{
    u32 rdata_size = key->vtbl->dnssec_key_rdatasize(key);
    u32 remaining = packet_writer_get_remaining_capacity(&dmsg->pw);
    
    ya_result ret = BUFFER_WOULD_OVERFLOW;
        
    if(remaining >= 2 + 2 + 2 + 4 + 2 + rdata_size)
    {
        if(ISOK(ret = packet_writer_add_fqdn(&dmsg->pw, &dmsg->packet[DNS_HEADER_LENGTH])))
        {
            packet_writer_add_u16(&dmsg->pw, TYPE_DNSKEY);
            packet_writer_add_u16(&dmsg->pw, CLASS_NONE);
            packet_writer_add_u32(&dmsg->pw, 0);
            packet_writer_add_u16(&dmsg->pw, htons(rdata_size));
            key->vtbl->dnssec_key_writerdata(key, packet_writer_get_next_u8_ptr(&dmsg->pw), rdata_size);
            packet_writer_forward(&dmsg->pw, rdata_size);
            message_header *hdr = (message_header*)dmsg->packet;
            hdr->nscount = htons(ntohs(hdr->nscount) + 1);
        }
    }
    
    return ret;
}

/**
 * Appends a "add RR" command to the buffer.
 * 
 * @param dmsg
 * @param fqdn
 * @param rtype
 * @param ttl
 * @param rdata_size
 * @param rdata
 * @return 
 */

ya_result
dynupdate_message_add_record(dynupdate_message *dmsg, const u8 *fqdn, u16 rtype, s32 ttl, u16 rdata_size, void *rdata)
{
    ya_result ret;
    if(ISOK(ret = packet_writer_add_record(&dmsg->pw, fqdn, rtype, dmsg->rclass, ttl, rdata, rdata_size)))
    {
        message_header *hdr = (message_header*)dmsg->packet;
        hdr->nscount = htons(ntohs(hdr->nscount) + 1);
    }
    return ret;
}

/**
 * Appends a "delete RR" command to the buffer.
 * 
 * @param dmsg
 * @param fqdn
 * @param rtype
 * @param ttl
 * @param rdata_size
 * @param rdata
 * @return 
 */

ya_result
dynupdate_message_del_record(dynupdate_message *dmsg, const u8 *fqdn, u16 rtype, s32 ttl, u16 rdata_size, void *rdata)
{
    ya_result ret;
    if(ISOK(ret = packet_writer_add_record(&dmsg->pw, fqdn, rtype, TYPE_NONE, ttl, rdata, rdata_size)))
    {
        message_header *hdr = (message_header*)dmsg->packet;
        hdr->nscount = htons(ntohs(hdr->nscount) + 1);
    }
    return ret;
}

/**
 * 
 * Appends a "delete RRSET" command to the buffer.
 * 
 * @param dmsg
 * @param fqdn
 * @param rtype
 * @return 
 */

ya_result
dynupdate_message_del_record_set(dynupdate_message *dmsg, const u8 *fqdn, u16 rtype)
{
    ya_result ret;
    if(ISOK(ret = packet_writer_add_record(&dmsg->pw, fqdn, rtype, TYPE_ANY, 0, NULL, 0)))
    {
        message_header *hdr = (message_header*)dmsg->packet;
        hdr->nscount = htons(ntohs(hdr->nscount) + 1);
    }
    return ret;
}

/**
 * Appends a "delete fqdn" command to the buffer.
 * 
 * @param dmsg
 * @param fqdn
 * @return 
 */

ya_result
dynupdate_message_del_fqdn(dynupdate_message *dmsg, const u8 *fqdn)
{
    ya_result ret;
    if(ISOK(ret = packet_writer_add_record(&dmsg->pw, fqdn, TYPE_ANY, TYPE_ANY, 0, NULL, 0)))
    {
        message_header *hdr = (message_header*)dmsg->packet;
        hdr->nscount = htons(ntohs(hdr->nscount) + 1);
    }
    return ret;
}

