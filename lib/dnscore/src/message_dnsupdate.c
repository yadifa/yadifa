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

/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

//#include "dnscore/message_dnsupdate.h"
#include "dnscore/dnscore-config.h"
#include "dnscore/message.h"
#include "dnscore/format.h"
#include "dnscore/packet_writer.h"
#include "dnscore/dns_resource_record.h"
#include "dnscore/logger.h"

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

/*
 * RFC 2136 :
 * 
   CLASS    TYPE     RDATA    Meaning
   ---------------------------------------------------------
   ANY      ANY      empty    Delete all RRsets from a name
   ANY      rrset    empty    Delete an RRset
   NONE     rrset    rr       Delete an RR from an RRset
   zone     rrset    rr       Add to an RRset
 * 
*/

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/** @brief Function ...
 *
 *  ...
 *
 *  @param ...
 *
 *  @retval OK
 *  @retval NOK
 */

void 
message_make_dnsupdate_init(message_data *mesg, u16 id, const u8 *origin, u16 zclass, u32 max_size, packet_writer *uninitialised_pw)
{
    assert(uninitialised_pw != NULL);


    /* 1. INITIALIZE PACKET */

#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->_buffer[0], 0x0000280000010000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#else
    SET_U64_AT(mesg->_buffer[0], 0x0000010000280000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#endif
    message_set_id(mesg, id);

    mesg->_ar_start   = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
    mesg->_tsig.tsig  = NULL;
#endif
    message_set_buffer_size(mesg, max_size);
    mesg->_rcode_ext  = 0;
    
    if(max_size > message_get_buffer_size_max(mesg))
    {
        message_set_edns0(mesg, TRUE);
    }
    
    message_set_canonised_fqdn(mesg, origin);
    message_set_query_type(mesg, TYPE_SOA);
    message_set_query_class(mesg, zclass);
    
    packet_writer_create(uninitialised_pw, message_get_buffer(mesg), message_get_buffer_size(mesg)); // valid use of message_get_buffer_size()
    /* 2. DO ZONE SECTION */
    packet_writer_add_fqdn(uninitialised_pw, origin);

    /* type in Zone Section must be SOA */
    packet_writer_add_u16(uninitialised_pw, TYPE_SOA);
    packet_writer_add_u16(uninitialised_pw, zclass);

    message_set_size(mesg, uninitialised_pw->packet_offset);

    message_set_status(mesg, FP_MESG_OK);
}

ya_result 
message_make_dnsupdate_delete_all_rrsets(message_data *mesg, packet_writer *pw, const u8 *fqdn)
{
    ya_result return_code;
    
    s32 offset = pw->packet_offset;
    
    if(ISOK(return_code = packet_writer_add_fqdn(pw, fqdn)))
    {
        if(packet_writer_get_remaining_capacity(pw) >= 10)
        {
            packet_writer_add_u16(pw, TYPE_ANY);  // type
            packet_writer_add_u16(pw, CLASS_ANY); // class
            packet_writer_add_u32(pw, 0);         // ttl = 0
            packet_writer_add_u16(pw, 0);         // empty rdata
            
            message_add_update_count(mesg, 1);

            return SUCCESS;
        }
        
        return_code = BUFFER_WOULD_OVERFLOW;
    }
    
    pw->packet_offset = offset;
    
    return return_code;
}

ya_result 
message_make_dnsupdate_delete_rrset(message_data *mesg, packet_writer *pw, const u8 *fqdn, u16 rtype)
{
    ya_result return_code;
    
    s32 offset = pw->packet_offset;
    
    if(ISOK(return_code = packet_writer_add_fqdn(pw, fqdn)))
    {
        if(packet_writer_get_remaining_capacity(pw) >= 10)
        {
            packet_writer_add_u16(pw, rtype);  // type
            packet_writer_add_u16(pw, CLASS_ANY); // class
            packet_writer_add_u32(pw, 0);         // ttl = 0
            packet_writer_add_u16(pw, 0);         // empty rdata
            
            message_add_update_count(mesg, 1);            

            return SUCCESS;
        }
        
        return_code = BUFFER_WOULD_OVERFLOW;
    }
    
    pw->packet_offset = offset;
    
    return return_code;
}

ya_result 
message_make_dnsupdate_delete_record(message_data *mesg, packet_writer *pw, const u8 *fqdn, u16 rtype, u16 rdata_size, const u8 *rdata)
{
    ya_result return_code;
    
    s32 offset = pw->packet_offset;
    
    if(ISOK(return_code = packet_writer_add_fqdn(pw, fqdn)))
    {
        if(packet_writer_get_remaining_capacity(pw) >= 10 + rdata_size)
        {
            packet_writer_add_u16(pw, rtype);  // type
            packet_writer_add_u16(pw, CLASS_NONE); // class
            packet_writer_add_u32(pw, 0);         // ttl = 0
            //packet_writer_add_u16(pw, htons(rdata_size));         // empty rdata
            
            if(ISOK(return_code = packet_writer_add_rdata(pw, rtype, rdata, rdata_size)))  // empty rdata
            {
                message_add_update_count(mesg, 1);

                return SUCCESS;
            }                        
        }
        
        return_code = BUFFER_WOULD_OVERFLOW;
    }
    
    pw->packet_offset = offset;
    
    return return_code;
}

ya_result 
message_make_dnsupdate_delete_dns_resource_record(message_data *mesg, packet_writer *pw, const dns_resource_record *rr)
{
    ya_result ret;
    ret = message_make_dnsupdate_delete_record(mesg, pw, rr->name, rr->tctr.qtype, rr->rdata_size, rr->rdata);
    return ret;
}

ya_result 
message_make_dnsupdate_add_record(message_data *mesg, packet_writer *pw, const u8 *fqdn, u16 rtype, u16 rclass, s32 rttl, u16 rdata_size, const u8 *rdata)
{
#if DEBUG
    if(rttl > 86400 * 31)
    {
        log_warn("message_make_dnsupdate_add_record: sending an invalid TTL of %u (%x)", rttl, rttl);
    }
#endif
    
    yassert(rttl >= 0);
    
    /* 3. DO PREREQUISITE SECTION */

    /* 4. DO UPDATE SECTION */

    ya_result return_code;
    
    s32 offset = pw->packet_offset;
    
    if(ISOK(return_code = packet_writer_add_fqdn(pw, fqdn)))
    {
        if(packet_writer_get_remaining_capacity(pw) >= 10 + rdata_size)
        {
            packet_writer_add_u16(pw, rtype);  // type
            packet_writer_add_u16(pw, rclass); // class
            packet_writer_add_u32(pw, htonl(rttl));   // rttl
            //packet_writer_add_u16(pw, htons(rdata_size));         // empty rdata
            
            if(ISOK(return_code = packet_writer_add_rdata(pw, rtype, rdata, rdata_size)))  // empty rdata
            {
                message_add_update_count(mesg, 1);

                return SUCCESS;
            }                        
        }
        
        return_code = BUFFER_WOULD_OVERFLOW;
    }
    
    pw->packet_offset = offset;
    
    return return_code;
}

ya_result 
message_make_dnsupdate_add_dns_resource_record(message_data *mesg, packet_writer *pw, const dns_resource_record *rr)
{
    ya_result ret;
    ret = message_make_dnsupdate_add_record(mesg, pw, rr->name, rr->tctr.qtype, rr->tctr.qclass, ntohl(rr->tctr.ttl), rr->rdata_size, rr->rdata);
    return ret;
}

ya_result
message_make_dnsupdate_add_dnskey(message_data *mesg, packet_writer *pw, dnssec_key *key, s32 ttl)
{
    ya_result ret;
    u8 buffer[8192];
    ret = key->vtbl->dnssec_key_writerdata(key, buffer, sizeof(buffer));
    ret = message_make_dnsupdate_add_record(mesg, pw, dnskey_get_domain(key), TYPE_DNSKEY, CLASS_IN, ttl, ret, buffer);
    return ret;
}


ya_result
message_make_dnsupdate_delete_dnskey(message_data *mesg, packet_writer *pw, dnssec_key *key)
{
    ya_result ret;
    u8 buffer[8192];
    ret = key->vtbl->dnssec_key_writerdata(key, buffer, sizeof(buffer));
    ret = message_make_dnsupdate_delete_record(mesg, pw, dnskey_get_domain(key), TYPE_DNSKEY, ret, buffer);
    return ret;
}

ya_result
message_make_dnsupdate_finalize(message_data *mesg, packet_writer *pw)
{
    message_set_size(mesg, pw->packet_offset);
    
    // handle EDNS0
    
    if(message_is_edns0(mesg))
    {
        if(packet_writer_get_remaining_capacity(pw) >= 11)
        {            
            /* #AR = 1 */
            // faster:
            // message_set_additional_count(mesg, NETWORK_U16_ONE);
            mesg->_buffer[DNS_HEADER_LENGTH - 1] = 1;    /* AR count was 0, now it is 1 */

            /* append opt *//* */
            u8 *buffer = message_get_buffer_limit(mesg);

            buffer[ 0] = 0;
            buffer[ 1] = 0;
            buffer[ 2] = 0x29;        
            buffer[ 3] = message_get_buffer_size(mesg) >> 8;    // valid use of message_get_buffer_size()
            buffer[ 4] = message_get_buffer_size(mesg);         // valid use of message_get_buffer_size()
            buffer[ 5] = message_get_status(mesg) >> 4;
            buffer[ 6] = mesg->_rcode_ext >> 16;
            buffer[ 7] = mesg->_rcode_ext >> 8;
            buffer[ 8] = mesg->_rcode_ext;
            buffer[ 9] = 0;
            buffer[10] = 0;
            
            // no NSID support here

            message_increase_size(mesg, 11);
        }
        else
        {
            return MESSAGE_CONTENT_OVERFLOW;
        }
    }
    
    return SUCCESS;
}

/** @} */

