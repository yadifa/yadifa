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
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <dnscore/dnscore_config_features.h>

#include <dnscore/dns_message.h>
#include <dnscore/nsid.h>
#include <dnscore/dns_packet_writer.h>

/**
 * Appends a REPLY OPT record to a message.
 *
 * mesg The message
 * pw a packet writer initialised with the message and pointing at the end of it
 */

static inline void dns_message_edns0_append_ex(dns_message_t *mesg, dns_packet_writer_t *pw)
{
    if(dns_message_has_edns0(mesg))
    {
        uint16_t edns0_maxsize = dns_message_edns0_getmaxsize();
#if DNSCORE_HAS_NSID_SUPPORT
        switch(dns_message_opt_get(mesg))
        {
            case MESSAGE_OPT_EDNS0:
            {
                if(dns_packet_writer_get_remaining_capacity(pw) >= EDNS0_RECORD_SIZE)
                {
                    memset(&pw->packet[pw->packet_offset], 0, EDNS0_RECORD_SIZE);
                    pw->packet_offset += 2;
                    pw->packet[pw->packet_offset++] = 0x29;
                    dns_packet_writer_add_u16(pw, htons(edns0_maxsize));
                    dns_packet_writer_add_u32(pw, dns_message_get_edns0_opt_ttl(mesg));
                    pw->packet_offset += 2; // rdata size already set to 0 with the memset above, skip it
                    dns_message_add_additional_count(mesg, 1);
                }
                break;
            }
            case MESSAGE_OPT_EDNS0 | MESSAGE_OPT_NSID:
            {
                if(dns_packet_writer_get_remaining_capacity(pw) >= (int32_t)(EDNS0_RECORD_SIZE - 2 + edns0_rdatasize_nsid_option_wire_size))
                {
                    dns_packet_writer_add_u16(pw, 0);       // fqdn + 1st half of type : 00 0029
                    pw->packet[pw->packet_offset++] = 0x29; // 2nd half of type

                    dns_packet_writer_add_u16(pw, htons(edns0_maxsize));                // e.g. 1000
                    dns_packet_writer_add_u32(pw, dns_message_get_edns0_opt_ttl(mesg)); // rcode (32 bits)

                    dns_packet_writer_add_bytes(pw, edns0_rdatasize_nsid_option_wire, edns0_rdatasize_nsid_option_wire_size); // full NSID rdata
                    dns_message_add_additional_count(mesg, 1);
                }
                break;
            }
            case MESSAGE_OPT_EDNS0 | MESSAGE_OPT_NSID | MESSAGE_OPT_COOKIE:
            {
                if(dns_packet_writer_get_remaining_capacity(pw) >= (int32_t)(EDNS0_RECORD_SIZE - 2 + edns0_rdatasize_nsid_option_wire_size + 20))
                {
                    dns_packet_writer_add_u16(pw, 0);       // fqdn + 1st half of type : 00 0029
                    pw->packet[pw->packet_offset++] = 0x29; // 2nd half of type

                    dns_packet_writer_add_u16(pw, htons(edns0_maxsize));                // e.g. 1000
                    dns_packet_writer_add_u32(pw, dns_message_get_edns0_opt_ttl(mesg)); // rcode (32 bits)

                    dns_packet_writer_add_bytes(pw, edns0_rdatasize_nsid_cookie_option_wire,
                                                edns0_rdatasize_nsid_option_wire_size); // full NSID rdata
                    dns_packet_writer_add_u32(pw, NU32(0x000a0010));
                    yassert(mesg->_cookie.size == 16);
                    dns_packet_writer_add_bytes(pw, mesg->_cookie.bytes, mesg->_cookie.size);
                    dns_message_add_additional_count(mesg, 1);
                }
                break;
            }
            case MESSAGE_OPT_EDNS0 | MESSAGE_OPT_COOKIE:
            {
                if(dns_packet_writer_get_remaining_capacity(pw) >= EDNS0_RECORD_SIZE - 2 + 22)
                {
                    dns_packet_writer_add_u16(pw, 0);       // fqdn + 1st half of type : 00 0029
                    pw->packet[pw->packet_offset++] = 0x29; // 2nd half of type

                    dns_packet_writer_add_u16(pw, htons(edns0_maxsize));                // e.g. 1000
                    dns_packet_writer_add_u32(pw, dns_message_get_edns0_opt_ttl(mesg)); // rcode (32 bits)

                    dns_packet_writer_add_u32(pw, NU32(0x0014000a)); // size of the message + 4, then the code and the
                                                                     // length (the reason of the +4) and the message
                    dns_packet_writer_add_u16(pw, NU16(0x0010));
                    yassert(mesg->_cookie.size == 16);
                    dns_packet_writer_add_bytes(pw, mesg->_cookie.bytes, mesg->_cookie.size);
                    dns_message_add_additional_count(mesg, 1);
                }
                break;
            }
                // there is no other possible value
        }

#else
        dns_message_increase_buffer_size(mesg, EDNS0_RECORD_SIZE); /* edns0 opt record */
        if(dns_packet_writer_get_remaining_capacity(pw) >= EDNS0_RECORD_SIZE)
        {
            pw->packet_limit += EDNS0_RECORD_SIZE;
            memset(&pw->packet[pw->packet_offset], 0, EDNS0_RECORD_SIZE);
            pw->packet_offset += 2;
            pw->packet[pw->packet_offset++] = 0x29;
            dns_packet_writer_add_u16(pw, htons(edns0_maxsize));
            dns_packet_writer_add_u32(pw, dns_message_get_edns0_opt_ttl(mesg));
            pw->packet_offset += 2; // rdata size already set to 0 with the memset above, skip it

            dns_message_add_additional_count(mesg, 1);
        }
#endif
        dns_message_set_size(mesg, pw->packet_offset);
    }
}

/**
 * Appends a REPLY OPT record to a message.
 *
 * mesg The message
 */

static inline void dns_message_edns0_append(dns_message_t *mesg)
{
    dns_packet_writer_t pw;
    dns_packet_writer_init_append_to_message(&pw, mesg);
    dns_message_edns0_append_ex(mesg, &pw);
}

#ifdef __cplusplus
}
#endif

/** @} */
