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
 * @defgroup
 * @ingroup
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
//#include "dnscore/message_dnsupdate.h"
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore_config.h"
#include "dnscore/dns_message.h"
#include "dnscore/format.h"
#include <dnscore/dns_packet_writer.h>
#include "dnscore/dns_resource_record.h"
#include "dnscore/logger.h"

extern logger_handle_t *g_system_logger;
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

ya_result dns_message_update_init(dns_message_t *mesg, uint16_t id, const uint8_t *zzone, uint16_t zclass, uint32_t max_size, dns_packet_writer_t *uninitialised_pw)
{
    assert(uninitialised_pw != NULL);

    if(max_size > dns_message_get_buffer_size_max(mesg))
    {
        max_size = dns_message_get_buffer_size_max(mesg);
    }

    if(max_size < DNS_HEADER_LENGTH + dnsname_len(zzone) + 4)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    /* 1. INITIALIZE PACKET */

#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->_buffer[0], 0x0000280000010000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#else
    SET_U64_AT(mesg->_buffer[0], 0x0000010000280000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#endif
    dns_message_set_id(mesg, id);

    mesg->_ar_start = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
    mesg->_tsig.tsig = NULL;
#endif

    dns_message_set_buffer_size(mesg, max_size);
    mesg->_edns0_opt_ttl.as_u32 = 0;

    if(max_size > EDNS0_LENGTH_MIN)
    {
        dns_message_set_edns0(mesg, true);
    }

    dns_message_set_canonised_fqdn(mesg, zzone);
    dns_message_set_query_type(mesg, TYPE_SOA);
    dns_message_set_query_class(mesg, zclass);

    dns_packet_writer_create(uninitialised_pw, dns_message_get_buffer(mesg),
                             dns_message_get_buffer_size(mesg)); // valid use of message_get_buffer_size()
    /* 2. DO ZONE SECTION */
    dns_packet_writer_add_fqdn(uninitialised_pw, zzone);

    /* type in Zone Section must be SOA */
    dns_packet_writer_add_u16(uninitialised_pw, TYPE_SOA);
    dns_packet_writer_add_u16(uninitialised_pw, zclass);

    dns_message_set_size(mesg, uninitialised_pw->packet_offset);

    dns_message_set_status(mesg, FP_MESG_OK);

    return uninitialised_pw->packet_offset;
}

ya_result dns_message_update_delete_all_rrsets(dns_message_t *mesg, dns_packet_writer_t *pw, const uint8_t *fqdn)
{
    ya_result return_code;

    int32_t   offset = pw->packet_offset;

    if(ISOK(return_code = dns_packet_writer_add_fqdn(pw, fqdn)))
    {
        if(dns_packet_writer_get_remaining_capacity(pw) >= 10)
        {
            dns_packet_writer_add_u16(pw, TYPE_ANY);  // type
            dns_packet_writer_add_u16(pw, CLASS_ANY); // class
            dns_packet_writer_add_u32(pw, 0);         // ttl = 0
            dns_packet_writer_add_u16(pw, 0);         // empty rdata

            dns_message_add_update_count(mesg, 1);

            return SUCCESS;
        }

        return_code = BUFFER_WOULD_OVERFLOW;
    }

    pw->packet_offset = offset;

    return return_code;
}

ya_result dns_message_update_delete_rrset(dns_message_t *mesg, dns_packet_writer_t *pw, const uint8_t *fqdn, uint16_t rtype)
{
    ya_result return_code;

    int32_t   offset = pw->packet_offset;

    if(ISOK(return_code = dns_packet_writer_add_fqdn(pw, fqdn)))
    {
        if(dns_packet_writer_get_remaining_capacity(pw) >= 10)
        {
            dns_packet_writer_add_u16(pw, rtype);     // type
            dns_packet_writer_add_u16(pw, CLASS_ANY); // class
            dns_packet_writer_add_u32(pw, 0);         // ttl = 0
            dns_packet_writer_add_u16(pw, 0);         // empty rdata

            dns_message_add_update_count(mesg, 1);

            return SUCCESS;
        }

        return_code = BUFFER_WOULD_OVERFLOW;
    }

    pw->packet_offset = offset;

    return return_code;
}

ya_result dns_message_update_delete_record(dns_message_t *mesg, dns_packet_writer_t *pw, const uint8_t *fqdn, uint16_t rtype, uint16_t rdata_size, const uint8_t *rdata)
{
    ya_result return_code;

    int32_t   offset = pw->packet_offset;

    if(ISOK(return_code = dns_packet_writer_add_fqdn(pw, fqdn)))
    {
        if(dns_packet_writer_get_remaining_capacity(pw) >= 10 + rdata_size)
        {
            dns_packet_writer_add_u16(pw, rtype);      // type
            dns_packet_writer_add_u16(pw, CLASS_NONE); // class
            dns_packet_writer_add_u32(pw, 0);          // ttl = 0
            // dns_packet_writer_add_u16(pw, htons(rdata_size));         // empty rdata

            if(ISOK(return_code = dns_packet_writer_add_rdata(pw, rtype, rdata, rdata_size))) // empty rdata
            {
                dns_message_add_update_count(mesg, 1);

                return SUCCESS;
            }
        }

        return_code = BUFFER_WOULD_OVERFLOW;
    }

    pw->packet_offset = offset;

    return return_code;
}

ya_result dns_message_update_delete_dns_resource_record(dns_message_t *mesg, dns_packet_writer_t *pw, const dns_resource_record_t *rr)
{
    ya_result ret;
    ret = dns_message_update_delete_record(mesg, pw, rr->name, rr->tctr.rtype, rr->rdata_size, rr->rdata);
    return ret;
}

ya_result dns_message_update_add_record(dns_message_t *mesg, dns_packet_writer_t *pw, const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t rttl, uint16_t rdata_size, const uint8_t *rdata)
{
#if DEBUG
    if(rttl > 86400 * 31)
    {
        log_warn("dns_message_update_add_record: sending an invalid TTL of %u (%x)", rttl, rttl);
    }
#endif

    yassert(rttl >= 0);

    /* 3. DO PREREQUISITE SECTION */

    /* 4. DO UPDATE SECTION */

    ya_result return_code;

    int32_t   offset = pw->packet_offset;

    if(ISOK(return_code = dns_packet_writer_add_fqdn(pw, fqdn)))
    {
        if(dns_packet_writer_get_remaining_capacity(pw) >= 10 + rdata_size)
        {
            dns_packet_writer_add_u16(pw, rtype);       // type
            dns_packet_writer_add_u16(pw, rclass);      // class
            dns_packet_writer_add_u32(pw, htonl(rttl)); // rttl
            // dns_packet_writer_add_u16(pw, htons(rdata_size));         // empty rdata

            if(ISOK(return_code = dns_packet_writer_add_rdata(pw, rtype, rdata, rdata_size))) // empty rdata
            {
                dns_message_add_update_count(mesg, 1);

                return SUCCESS;
            }
        }

        return_code = BUFFER_WOULD_OVERFLOW;
    }

    pw->packet_offset = offset;

    return return_code;
}

ya_result dns_message_update_add_dns_resource_record(dns_message_t *mesg, dns_packet_writer_t *pw, const dns_resource_record_t *rr)
{
    ya_result ret;
    ret = dns_message_update_add_record(mesg, pw, rr->name, rr->tctr.rtype, rr->tctr.rclass, ntohl(rr->tctr.ttl), rr->rdata_size, rr->rdata);
    return ret;
}

ya_result dns_message_update_add_dnskey(dns_message_t *mesg, dns_packet_writer_t *pw, dnskey_t *key, int32_t ttl)
{
    ya_result ret;
    uint8_t   buffer[8192];
    ret = key->vtbl->dnskey_writerdata(key, buffer, sizeof(buffer));
    ret = dns_message_update_add_record(mesg, pw, dnskey_get_domain(key), TYPE_DNSKEY, CLASS_IN, ttl, ret, buffer);
    return ret;
}

ya_result dns_message_update_delete_dnskey(dns_message_t *mesg, dns_packet_writer_t *pw, dnskey_t *key)
{
    ya_result ret;
    uint8_t   buffer[8192];
    ret = key->vtbl->dnskey_writerdata(key, buffer, sizeof(buffer));
    ret = dns_message_update_delete_record(mesg, pw, dnskey_get_domain(key), TYPE_DNSKEY, ret, buffer);
    return ret;
}

ya_result dns_message_update_finalize(dns_message_t *mesg, dns_packet_writer_t *pw)
{
    dns_message_set_size(mesg, pw->packet_offset);

    // handle EDNS0

    if(dns_message_has_edns0(mesg))
    {
        if(dns_packet_writer_get_remaining_capacity(pw) >= 11)
        {
            /* #AR = 1 */
            // faster:
            // message_set_additional_count(mesg, NETWORK_U16_ONE);
            mesg->_buffer[DNS_HEADER_LENGTH - 1] = 1; /* AR count was 0, now it is 1 */

            /* append opt */ /* */
            uint8_t *buffer = dns_message_get_buffer_limit(mesg);

            buffer[0] = 0;
            buffer[1] = 0;
            buffer[2] = 0x29; // don't use the function from message_opt.h
#if DNSCORE_HAS_LITTLE_ENDIAN
            /*
                        buffer[ 3] = dns_message_get_buffer_size(mesg) >> 8;    // valid use of
               message_get_buffer_size() buffer[ 4] = dns_message_get_buffer_size(mesg);         // valid use of
               message_get_buffer_size()
            */
            SET_U16_AT(buffer[3], htons(dns_message_get_buffer_size(mesg)));
#else
            SET_U16_AT(buffer[3], dns_message_get_buffer_size(mesg));
#endif
            SET_U32_AT(buffer[5], mesg->_edns0_opt_ttl.as_u32);

            buffer[9] = 0;
            buffer[10] = 0;

            // no NSID support here

            dns_message_increase_size(mesg, 11);
        }
        else
        {
            return BUFFER_WOULD_OVERFLOW;
        }
    }

    return SUCCESS;
}

/** @} */
