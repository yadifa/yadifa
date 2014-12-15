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
/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

//#include "dnscore/message_dnsupdate.h"
#include "dnscore/message.h"
#include "dnscore/format.h"


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
message_make_dnsupdate_init(message_data *mesg, u16 id, const u8 *zzone, u16 zclass, u16 max_size, packet_writer *uninitialised_pw)
{
    assert(uninitialised_pw != NULL);


    /* 1. INITIALIZE PACKET */

#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->buffer[0], 0x0000280000010000LL);
    SET_U32_AT(mesg->buffer[8], 0);
#else
    SET_U64_AT(mesg->buffer[0], 0x0000010000280000LL);
    SET_U32_AT(mesg->buffer[8], 0);
#endif
    MESSAGE_SET_ID(mesg->buffer, id);

    mesg->ar_start   = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
    mesg->tsig.tsig  = NULL;
#endif
    mesg->size_limit = max_size;
    mesg->rcode_ext  = 0;
    
    if(max_size > UDPPACKET_MAX_LENGTH)
    {
        mesg->edns = TRUE;
    }
    
    packet_writer_create(uninitialised_pw, mesg->buffer, mesg->size_limit);

    /* 2. DO ZONE SECTION */
    packet_writer_add_fqdn(uninitialised_pw, zzone);

    /* type in Zone Section must be SOA */
    packet_writer_add_u16(uninitialised_pw, TYPE_SOA);
    packet_writer_add_u16(uninitialised_pw, zclass);

    mesg->send_length = uninitialised_pw->packet_offset;

    mesg->status = FP_MESG_OK;
}

ya_result 
message_make_dnsupdate_delete_all_rrsets(message_data *mesg, packet_writer *pw, const u8 *fqdn)
{
    ya_result return_code;
    
    s32 offset = pw->packet_offset;
    
    if(ISOK(return_code = packet_writer_add_fqdn(pw, fqdn)))
    {
        if(packet_writer_remaining_capacity(pw) >= 10)
        {
            packet_writer_add_u16(pw, TYPE_ANY);  // type
            packet_writer_add_u16(pw, CLASS_ANY); // class
            packet_writer_add_u32(pw, 0);         // ttl = 0
            packet_writer_add_u16(pw, 0);         // empty rdata
            MESSAGE_SET_UP(mesg->buffer,  ntohs(htons(MESSAGE_UP(mesg->buffer)) + 1));

            return SUCCESS;
        }
        
        return_code = ERROR;
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
        if(packet_writer_remaining_capacity(pw) >= 10)
        {
            packet_writer_add_u16(pw, rtype);  // type
            packet_writer_add_u16(pw, CLASS_ANY); // class
            packet_writer_add_u32(pw, 0);         // ttl = 0
            packet_writer_add_u16(pw, 0);         // empty rdata
            MESSAGE_SET_UP(mesg->buffer,  ntohs(htons(MESSAGE_UP(mesg->buffer)) + 1));

            return SUCCESS;
        }
        
        return_code = ERROR;
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
        if(packet_writer_remaining_capacity(pw) >= 10 + rdata_size)
        {
            packet_writer_add_u16(pw, rtype);  // type
            packet_writer_add_u16(pw, CLASS_NONE); // class
            packet_writer_add_u32(pw, 0);         // ttl = 0
            //packet_writer_add_u16(pw, htons(rdata_size));         // empty rdata
            
            if(ISOK(return_code = packet_writer_add_rdata(pw, rtype, rdata, rdata_size)))  // empty rdata
            {
                MESSAGE_SET_UP(mesg->buffer,  ntohs(htons(MESSAGE_UP(mesg->buffer)) + 1));

                return SUCCESS;
            }                        
        }
        
        return_code = ERROR;
    }
    
    pw->packet_offset = offset;
    
    return return_code;
}

ya_result 
message_make_dnsupdate_add_record(message_data *mesg, packet_writer *pw, const u8 *fqdn, u16 rtype, u16 rclass, u32 rttl, u16 rdata_size, const u8 *rdata)
{
#ifdef DEBUG
    if(rttl > 86400 * 31)
    {
        log_warn("message_make_dnsupdate_add_record: sending an insane TTL of %u (%x)", rttl, rttl);
    }
#endif
    /* 3. DO PREREQUISITE SECTION */



    /* 4. DO UPDATE SECTION */

    ya_result return_code;
    
    s32 offset = pw->packet_offset;
    
    if(ISOK(return_code = packet_writer_add_fqdn(pw, fqdn)))
    {
        if(packet_writer_remaining_capacity(pw) >= 10 + rdata_size)
        {
            packet_writer_add_u16(pw, rtype);  // type
            packet_writer_add_u16(pw, rclass); // class
            packet_writer_add_u32(pw, htonl(rttl));   // rttl
            //packet_writer_add_u16(pw, htons(rdata_size));         // empty rdata
            
            if(ISOK(return_code = packet_writer_add_rdata(pw, rtype, rdata, rdata_size)))  // empty rdata
            {
                MESSAGE_SET_UP(mesg->buffer,  ntohs(htons(MESSAGE_UP(mesg->buffer)) + 1));

                return SUCCESS;
            }                        
        }
        
        return_code = ERROR;
    }
    
    pw->packet_offset = offset;
    
    return return_code;
}

ya_result
message_make_dnsupdate_finalize(message_data *mesg, packet_writer *pw)
{
    mesg->send_length = pw->packet_offset;
    
    // handle EDNS0
    
    if(mesg->edns)
    {
        if(packet_writer_remaining_capacity(pw) >= 11)
        {            
            /* #AR = 1 */
            mesg->buffer[DNS_HEADER_LENGTH - 1] = 1;    /* AR count was 0, now it is 1 */

            /* append opt *//* */
            u8 *buffer = &mesg->buffer[mesg->send_length];

            buffer[ 0] = 0;
            buffer[ 1] = 0;
            buffer[ 2] = 0x29;        
            buffer[ 3] = mesg->size_limit >> 8;
            buffer[ 4] = mesg->size_limit;
            buffer[ 5] = (mesg->status >> 4);
            //buffer[ 6] = mesg->rcode_ext >> 24;
            buffer[ 6] = mesg->rcode_ext >> 16;
            buffer[ 7] = mesg->rcode_ext >> 8;
            buffer[ 8] = mesg->rcode_ext;
            buffer[ 9] = 0;
            buffer[10] = 0;
            
            // no NSID support here

            mesg->send_length += 11;
        }
        else
        {
            return MESSAGE_CONTENT_OVERFLOW;
        }
    }
    
    return SUCCESS;
}


void
message_dnsupdate_data_show(message_dnsupdate_data *entry)
{
    u16 count = 0;

    while (entry != NULL)
    {
        count++;
        format("COUNT        : %d\n", count);
        format("ENTRY TTL    : %d\n", (entry->zttl));
        format("ENTRY CLASS  : %d\n", ntohs(entry->zclass));
        format("ENTRY TYPE   : %d\n", ntohs(entry->ztype));
        format("ENTRY NAME   : %{dnsname}\n", entry->zname);
//        format("ENTRY POINTER: %p :: %p :::\n", entry, entry->next);
        format("\n");

        entry = entry->next;
    }
}

void
message_dnsupdate_data_init(message_dnsupdate_data* new_entry)
{
#ifdef DEBUG
    memset(new_entry, 0xff, sizeof(message_dnsupdate_data));
#endif

    new_entry->next    = NULL;
    new_entry->zttl     = 0;
    new_entry->ztype    = 0;
    new_entry->zclass   = 0;

#ifdef DEBUG
    memset(new_entry->zname,  0xff, sizeof(new_entry->zname));
    memset(new_entry->zrdata, 0xff, sizeof(new_entry->zrdata));
#endif

    new_entry->zname[0] = 0;
    new_entry->zname[1] = 0;
}

void
message_dnsupdate_data_create(message_dnsupdate_data* entry,  u32 zttl, u16 ztype, u16 zclass, const u8 *zname, u16 zrdata_len, char *zrdata)
{
    entry->zttl       = zttl;
    entry->ztype      = ztype;
    entry->zclass     = zclass;
    entry->zrdata_len = zrdata_len;

    dnsname_copy(entry->zname, zname);
    strncpy(entry->zrdata, zrdata, zrdata_len);
}

void
message_dnsupdate_data_append_message_dnsupdate_data(message_dnsupdate_data *entry, message_dnsupdate_data *new_entry)
{
    for(;;)
    {
        if(entry->next == NULL)
        {
            break;
        }

        entry = entry->next;
    }

    entry->next = new_entry;

//    MALLOC_OR_DIE(message_dnsupdate_data *, new_entry, sizeof(message_dnsupdate_data), MESSAGE_DNSUPDATE_DATA_TAG);
}




    /*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/

