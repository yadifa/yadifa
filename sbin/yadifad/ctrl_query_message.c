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
 * @defgroup server
 * @ingroup yadifad
 * @brief server
 *
 *  Handles queries made in the CH class (ie: version.*)
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "server_config.h"

#include <dnscore/file_output_stream.h>
#include <dnscore/logger.h>
#include <dnscore/rfc.h>
#include <dnscore/ctrl_rfc.h>
#include <dnscore/threaded_queue.h>

#include <dnsdb/zdb_zone.h>
#include <dnscore/format.h>
#include <dnscore/dns_packet_writer.h>

extern logger_handle_t *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "confs.h"
#include "signals.h"
#include <dnscore/acl.h>

#include "database_service.h"

#include "ctrl_query_message.h"

#define TMP00001_TAG 0x3130303030504d54

#ifdef HAS_EXPERIMENTAL

extern logger_handle_t *g_server_logger;

// CH fqdn TXT command
// freeze zone
// unfreeze zone
// reload zone
// load zone
// drop zone

/**
 * The q&d model used types for control.
 *
 * Do we want a script model ? A loop could make sense but I don't see a real practical use yet.
 *
 * for $z in (a,b,c,d){load $z}
 * if(whatever) {notify hostname}
 *
 * Do we want optional encryption ? (This may be interesting).
 *
 * ie: one may want to send a command with a TSIG through an unsafe network.
 *
 * If we use TXT we can simply have:
 *
 * script. TXT load this;foreach(a,b,c,d){drop $};if(whateverstatus){reload whatever}
 * key. TXT mycbckeyname
 *
 *
 */

/* helper functions to fill the answer to the controller */

/**
 *
 * @param pw
 * @param name
 * @param value
 * @return
 */

ya_result ctrl_query_message_add_soa(dns_packet_writer_t *pw, zone_desc_s *zone_desc)
{
    int32_t from = dns_packet_writer_get_offset(pw);

    dns_packet_writer_add_fqdn(pw, zone_origin(zone_desc));
    dns_packet_writer_add_u16(pw, TYPE_SOA);
    dns_packet_writer_add_u16(pw, CLASS_CTRL);
    dns_packet_writer_add_u32(pw, 0);        /* TTL */
    dns_packet_writer_add_u16(pw, NU16(22)); /* RDATA size ( 1 + 1 + 5 * 4 ) */
    dns_packet_writer_add_u16(pw, 0);        /* covers mname and rname */
    dns_packet_writer_add_u32(pw, htonl(zone_desc->dynamic_provisioning.timestamp));
    dns_packet_writer_add_u32(pw, htonl(zone_desc->dynamic_provisioning.refresh));
    dns_packet_writer_add_u32(pw, htonl(zone_desc->dynamic_provisioning.retry));
    dns_packet_writer_add_u32(pw, htonl(zone_desc->dynamic_provisioning.expire));
    dns_packet_writer_add_u32(pw, 0);

    return dns_packet_writer_get_offset(pw) - from;
}

ya_result ctrl_query_message_add_u32_txt(dns_packet_writer_t *pw, const char *name, uint32_t value)
{
    uint8_t dnsname[DOMAIN_LENGTH_MAX];
    uint8_t line[255];

    cstr_to_dnsname(dnsname, name);
    line[0] = snformat((char *)&line[1], sizeof(line) - 1, "%u", value);

    return dns_packet_writer_add_record(pw, dnsname, TYPE_TXT, CLASS_IN, 0, line, line[0] + 1);
}

ya_result ctrl_query_message_add_type_txt(dns_packet_writer_t *pw, const char *name, uint16_t value)
{
    uint8_t dnsname[DOMAIN_LENGTH_MAX];
    uint8_t line[255];

    cstr_to_dnsname(dnsname, name);
    line[0] = snformat((char *)&line[1], sizeof(line) - 1, "%{dnstype}", &value);
    return dns_packet_writer_add_record(pw, dnsname, TYPE_TXT, CLASS_IN, 0, line, line[0] + 1);
}

ya_result ctrl_query_message_add_class_txt(dns_packet_writer_t *pw, const char *name, uint16_t value)
{
    uint8_t dnsname[DOMAIN_LENGTH_MAX];
    uint8_t line[255];

    cstr_to_dnsname(dnsname, name);
    line[0] = snformat((char *)&line[1], sizeof(line) - 1, "%{dnsclass}", &value);
    return dns_packet_writer_add_record(pw, dnsname, TYPE_TXT, CLASS_IN, 0, line, line[0] + 1);
}

ya_result ctrl_query_message_add_hosts_txt(dns_packet_writer_t *pw, const char *name, host_address_t *hosts)
{
    uint8_t  *line_buffer;
    int32_t   size;
    int32_t   offs;
    ya_result return_value = SUCCESS;
    uint8_t   dnsname[DOMAIN_LENGTH_MAX];
    uint8_t   buffer[4096]; /* must remain a power of two less or equal than 0x10000 */

    line_buffer = buffer;
    size = sizeof(buffer);
    offs = 0;

    cstr_to_dnsname(dnsname, name);

    while(hosts != NULL)
    {
        if((size - offs < DOMAIN_LENGTH_MAX + 1 + 5 + 1 + DOMAIN_LENGTH_MAX) && (size < 0x10000))
        {
            uint8_t *tmp;
            MALLOC_OR_DIE(uint8_t *, tmp, size * 2, TMP00001_TAG);
            memcpy(tmp, line_buffer, size);
            if(line_buffer != buffer)
            {
                free(line_buffer);
            }
            line_buffer = tmp;
        }

        uint8_t *line = &line_buffer[offs];
        uint32_t remaining = size - offs;

        if(FAIL(return_value = snformat((char *)&line[1], remaining - 1, "%{hostaddr}", hosts)))
        {
            break;
        }

        offs += return_value;

        if(hosts->tsig != NULL)
        {
            line += offs;

            if(FAIL(return_value = snformat((char *)&line[1], remaining - 1, "+%{dnsname}", hosts->tsig->name)))
            {
                break;
            }

            offs += return_value;
        }

        hosts = hosts->next;
    }

    if(ISOK(return_value))
    {
        return_value = dns_packet_writer_add_record(pw, dnsname, TYPE_TXT, CLASS_IN, 0, line_buffer, size);
    }

    if(line_buffer != buffer)
    {
        free(line_buffer);
    }

    return return_value;
}

ya_result ctrl_query_message_add_time_txt(dns_packet_writer_t *pw, const char *name, uint32_t value)
{
    uint8_t   dnsname[DOMAIN_LENGTH_MAX];
    uint8_t   line[255];

    struct tm tm;
    time_t    t = value;
    gmtime_r(&t, &tm);

    cstr_to_dnsname(dnsname, name);
    line[0] = snformat((char *)&line[1], sizeof(line) - 1, "%04u-%02u-%02u.%02u-%02u-%02u.%s", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_zone);

    return dns_packet_writer_add_record(pw, dnsname, TYPE_TXT, CLASS_IN, 0, line, line[0] + 1);
}

ya_result ctrl_query_message_add_text_txt(dns_packet_writer_t *pw, const char *name, const char *value)
{
    uint8_t dnsname[DOMAIN_LENGTH_MAX];
    uint8_t line[255];

    cstr_to_dnsname(dnsname, name);

    line[0] = snformat((char *)&line[1], sizeof(line) - 1, "%s", value);

    return dns_packet_writer_add_record(pw, dnsname, TYPE_TXT, CLASS_IN, 0, line, line[0] + 1);
}

ya_result ctrl_query_message_add_aml_txt(dns_packet_writer_t *pw, const char *name, const address_match_list *aml)
{
    uint8_t   dnsname[DOMAIN_LENGTH_MAX];
    uint8_t   line[255];
    uint32_t  offset = 1;

    ya_result return_value = 0;

    cstr_to_dnsname(dnsname, name);

    address_match_item       **amip = aml->items;
    address_match_item **const limitp = aml->limit;

    if(amip < limitp)
    {
        do
        {
            address_match_item *ami = *amip;

            uint32_t            used = sizeof(line) - 1 - offset;

            if(FAIL(return_value = acl_address_match_item_to_string(ami, (char *)&line[offset], &used)))
            {
                break;
            }

            offset += used;

            amip++;
        } while(amip < limitp);
    }
    else
    {
        line[1] = '[';
        line[2] = '-';
        line[3] = '-';
        line[4] = '-';
        line[5] = ']';
        offset = 6;
    }

    if(ISOK(return_value))
    {
        line[0] = offset - 1;
    }
    else
    {
        line[0] = snformat((char *)&line[1], sizeof(line), "%r", return_value);
    }

    return dns_packet_writer_add_record(pw, dnsname, TYPE_TXT, CLASS_IN, 0, line, line[0] + 1);
}

ya_result ctrl_query_message_add_ams_txt(dns_packet_writer_t *pw, const char *name, const address_match_set *ams)
{
    ya_result return_value;

    char      tmpname[128];

    snformat(tmpname, sizeof(tmpname), "allow-%s-ipv4", name);

    if(FAIL(return_value = ctrl_query_message_add_aml_txt(pw, tmpname, &ams->ipv4)))
    {
        return return_value;
    }

    snformat(tmpname, sizeof(tmpname), "allow-%s-ipv6", name);
    if(FAIL(return_value = ctrl_query_message_add_aml_txt(pw, tmpname, &ams->ipv6)))
    {
        return return_value;
    }

    snformat(tmpname, sizeof(tmpname), "allow-%s-tsig", name);
    return_value = ctrl_query_message_add_aml_txt(pw, tmpname, &ams->tsig);

    return return_value;
}

ya_result ctrl_query_message_add_u8(dns_packet_writer_t *pw, const uint8_t *fqdn, uint16_t rtype, uint8_t value) { return dns_packet_writer_add_record(pw, fqdn, rtype, CLASS_CTRL, 0, &value, 1); }

ya_result ctrl_query_message_add_u32(dns_packet_writer_t *pw, const uint8_t *fqdn, uint16_t rtype, uint32_t value)
{
    uint32_t nvalue = htonl(value);
    return dns_packet_writer_add_record(pw, fqdn, rtype, CLASS_CTRL, 0, (uint8_t *)&nvalue, 4);
}

ya_result ctrl_query_message_add_utf8(dns_packet_writer_t *pw, const uint8_t *fqdn, uint16_t rtype, const char *value) { return dns_packet_writer_add_record(pw, fqdn, rtype, CLASS_CTRL, 0, (const uint8_t *)value, strlen(value)); }

ya_result ctrl_query_message_add_hosts(dns_packet_writer_t *pw, const uint8_t *fqdn, uint16_t rtype, const host_address_t *value)
{
    ya_result count = 0;

    while(value != NULL)
    {
        ya_result return_value = 0;
        uint16_t  len = 1;
        uint8_t   flags = 0;

        switch(value->version)
        {
            case HOST_ADDRESS_IPV4:
            {
                len += 4;
                flags = 0x04;
                break;
            }
            case HOST_ADDRESS_IPV6:
            {
                len += 16;
                flags = 0x06;
                break;
            }
            default:
            {
                return INVALID_ARGUMENT_ERROR;
            }
        }

        if(value->port != NU16(DNS_DEFAULT_PORT))
        {
            len += 2;
            flags |= 0x10;
        }

        if(value->tsig != NULL)
        {
            len += value->tsig->name_len;
            flags |= 0x20;
        }

        if(ISOK(return_value = dns_packet_writer_add_fqdn(pw, fqdn)))
        {
            if(dns_packet_writer_get_remaining_capacity(pw) >= 10 + len)
            {
                dns_packet_writer_add_u16(pw, rtype);
                dns_packet_writer_add_u16(pw, CLASS_CTRL);
                dns_packet_writer_add_u32(pw, 0);

                uint32_t rdata_size_offset = dns_packet_writer_get_offset(pw);

                dns_packet_writer_add_u16(pw, 0xffff); // place holder
                dns_packet_writer_add_bytes(pw, &flags, 1);

                if(value->version == HOST_ADDRESS_IPV4)
                {
                    dns_packet_writer_add_bytes(pw, value->ip.v4.bytes, 4);
                }
                else
                {
                    dns_packet_writer_add_bytes(pw, value->ip.v6.bytes, 16);
                }

                if(value->port != NU16(DNS_DEFAULT_PORT))
                {
                    dns_packet_writer_add_u16(pw, value->port);
                }

                if(value->tsig != NULL)
                {
                    if(FAIL(return_value = dns_packet_writer_add_fqdn(pw, value->tsig->name)))
                    {
                        return return_value;
                    }
                }

                SET_U16_AT(pw->packet[rdata_size_offset], htons(dns_packet_writer_get_offset(pw) - rdata_size_offset - 2));
            }
            else
            {
                return BUFFER_WOULD_OVERFLOW;
            }
        }
        else
        {
            return return_value;
        }

        count++;
        value = value->next;
    }

    return count;
}

#endif // HAS_CTRL

/** @} */
