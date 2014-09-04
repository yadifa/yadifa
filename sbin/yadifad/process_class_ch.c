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
/** @defgroup server
 *  @ingroup yadifad
 *  @brief server
 *
 *  Handles queries made in the CH class (ie: version.*)
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#include "config.h"

#include <poll.h>

#include <dnscore/logger.h>
#include <dnscore/format.h>
#include <dnscore/thread_pool.h>
#include <dnscore/fdtools.h>

#include <dnscore/rfc.h>

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "process_class_ch.h"
#include "confs.h"

extern logger_handle* g_server_logger;

/*
 * The TXT CH record wire.  Only the first 10 bytes will be taken.
 */

static u8 version_txt[3*8 + 3] = {
    0xc0, 0x0c, 0x00, 0x10, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    /* |RDATA| */
    0x00, 0x0f, 0x0e, 0x6e, 0x6f, 0x74, 0x20, 0x61, 0x64, 0x76,
    0x65, 0x72, 0x74, 0x69, 0x73, 0x65, 0x64 };

/*
 * The SOA CH record wire.
 */

static u8 version_soa[5*8 + 7] = {
    0xc0, 0x0c, 0x00, 0x06, 0x00, 0x03, 0x00, 0x01, 0x51, 0x80,
    0x00, 0x23, 0xc0, 0x0c, 0x0a, 0x68, 0x6f, 0x73, 0x74, 0x6d,
    0x61, 0x73, 0x74, 0x65, 0x72, 0xc0, 0x0c, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x70, 0x80, 0x00, 0x00, 0x1c, 0x20, 0x00,
    0x09, 0x3a, 0x80, 0x00, 0x01, 0x51, 0x80 };

/*
 * The NS CH record wire.
 */

static u8 version_ns[1*8 + 6] = {
    0xc0, 0x0c, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0xc0, 0x0c };

void
process_class_ch(message_data *mesg)
{
    ya_result return_value;

    u16 t = mesg->qtype;
    u16 an = 0;
    u16 au = 0;
    
    u8 qname[MAX_DOMAIN_LENGTH];
    
#if HAS_ACL_SUPPORT
    if(ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac.allow_query)))
    {
        mesg->status = FP_ACCESS_REJECTED;
        message_transform_to_error(mesg);
        
        return;
    }
#endif

    packet_unpack_reader_data purd;
    purd.packet = mesg->buffer;
    purd.packet_size = mesg->received;
    purd.offset = DNS_HEADER_LENGTH;

    if(FAIL(return_value = packet_reader_read_fqdn(&purd, qname, sizeof (qname))))
    {
        /* oops */

        log_err("chaos: error reading query: %r", return_value);

        return;
    }

    /* version */

    if(dnslabel_equals_ignorecase_left((const u8*)"\007version", qname))
    {
        /* set the flags */

        MESSAGE_FLAGS_OR(mesg->buffer, QR_BITS|AA_BITS, 0);
        MESSAGE_FLAGS_AND(mesg->buffer, QR_BITS|AA_BITS|RD_BITS, 0);

        u8 *p = &mesg->buffer[mesg->received];

        if(t == TYPE_TXT || t == TYPE_ANY)
        {
            memcpy(p, version_txt, 10); /* take the start only */
            p += 10;

            char * version_chaos = g_config->version_chaos;

            int len = strlen(version_chaos);

            SET_U16_AT(*p, htons(len + 1));
            p += 2;
            *p++ = (u8)len;
            memcpy(p, version_chaos, len);
            p += len;

            an++;
        }
        if(t == TYPE_SOA || t == TYPE_ANY)
        {
            memcpy(p, version_soa, sizeof(version_soa));
            p += sizeof(version_soa);

            MESSAGE_SET_AN(mesg->buffer, NETWORK_ONE_16);

            an++;
        }
        
        memcpy(p, version_ns, sizeof(version_ns));
        p += sizeof(version_ns);

        if(t == TYPE_ANY || t == TYPE_NS)
        {
            an++;
        }
        else
        {
            au++;
        }
        
        MESSAGE_SET_AN(mesg->buffer, htons(an));
        MESSAGE_SET_NS(mesg->buffer, htons(au));
        
        if(mesg->edns)
        {
            u16 edns0_maxsize = g_config->edns0_max_size;
            u32 rcode_ext = mesg->rcode_ext;
            p[ 0] = 0;
            p[ 1] = 0;
            p[ 2] = 0x29;        
            p[ 3] = edns0_maxsize>>8;
            p[ 4] = edns0_maxsize;
            p[ 5] = (mesg->status >> 4);
            //p[ 6] = rcode_ext >> 24;
            p[ 6] = rcode_ext >> 16;
            p[ 7] = rcode_ext >> 8;
            p[ 8] = rcode_ext;
            p[ 9] = 0;
            p[10] = 0;
            
            // nsid
            
            p += 11;
         
            MESSAGE_SET_AR(mesg->buffer, NETWORK_ONE_16);
        }

        mesg->send_length = p - mesg->buffer;
    }
    else
    {
        /* REFUSED */

        mesg->status = FP_NOZONE_FOUND;
        message_transform_to_error(mesg);
    }
}

/** @} */
