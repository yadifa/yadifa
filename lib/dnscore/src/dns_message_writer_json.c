/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

#include "dnscore/dnscore_config.h"
#include <stddef.h>
#include <unistd.h>

#include "dnscore/format.h"
#include "dnscore/logger.h"
#include "dnscore/dns_message.h"
#include "dnscore/dns_message_writer.h"
#include "dnscore/rfc.h"
#include <dnscore/dns_packet_reader.h>

static char *message_section_names[4] = {"questions", "answers", "authorities", "additionals"};

static char *message_section_update_names[4] = {"zone", "prerequisites", "update records", "additional records"};

ya_result    dns_message_writer_json(const dns_message_writer_t *dmw, const dns_message_writer_message_t *msg)
{
    const uint8_t      *buffer = msg->buffer;
    output_stream_t    *os = dmw->os;
    uint32_t            length = msg->length;
    uint32_t            flags = dmw->flags;
    ya_result           return_value;

    dns_packet_reader_t purd;

    uint8_t             record_wire[DOMAIN_LENGTH_MAX + 10 + 65535];

    /*    ------------------------------------------------------------    */

    /* Init packet reader with buffer. length and offset in the buffer */
    purd.packet = buffer;
    purd.packet_size = length;
    purd.packet_offset = DNS_HEADER_LENGTH;

    /* 1. GET ID */
    uint16_t id = MESSAGE_ID(buffer);

    /* 2. GET OPCODE AND RCODE */
    uint8_t opcode = MESSAGE_OP(buffer);
    opcode >>= OPCODE_SHIFT;

    uint8_t     rcode = MESSAGE_RCODE(buffer);

    const char *opcode_txt = dns_message_opcode_get_name(opcode);
    const char *status_txt = dns_message_rcode_get_name(rcode);

    /* 3. GET VALUES OF THE SECTIONS */
    uint16_t count[4];
    count[0] = ntohs(MESSAGE_QD(buffer));
    count[1] = ntohs(MESSAGE_AN(buffer));
    count[2] = ntohs(MESSAGE_NS(buffer));
    count[3] = ntohs(MESSAGE_AR(buffer));

    /* 3. GET THE NAMES FOR THE PRESENTATOIN */
    char **section_name = (opcode != OPCODE_UPDATE) ? message_section_names : message_section_update_names;

    /* 5. FILL THE STREAM */

    output_stream_write_u8(os, '{');

    /* fill the information of the header of a DNS packet */
    osprint(os, "\"header\":");
    output_stream_write_u8(os, '{');

    osformat(os, "\"id\":\"%hd\",", id);
    osformat(os, "\"rcode\":\"%s\",", status_txt);
    osformat(os, "\"opcode\":\"%s\",", opcode_txt);

    /* seperator */
    const uint8_t *sep = (const uint8_t *)",";
    uint8_t        sep_length = 0; // used to write the comma or not

    /* print flags */
    osprint(os, "\"flags\":\"[");

    if(MESSAGE_QR(buffer) != 0)
    {
        output_stream_write(os, sep, sep_length);
        sep_length = 1;

        osprint(os, "\"qr\"");
    }
    if(MESSAGE_AA(buffer) != 0)
    {
        output_stream_write(os, sep, sep_length);
        sep_length = 1;

        osprint(os, "\"aa\"");
    }
    if(MESSAGE_TC(buffer) != 0)
    {
        output_stream_write(os, sep, sep_length);
        sep_length = 1;

        osprint(os, "\"tc\"");
    }
    if(MESSAGE_RD(buffer) != 0)
    {
        output_stream_write(os, sep, sep_length);
        sep_length = 1;

        osprint(os, "\"rd\"");
    }
    if(MESSAGE_RA(buffer) != 0)
    {
        output_stream_write(os, sep, sep_length);
        sep_length = 1;

        osprint(os, "\"ra\"");
    }
    if(MESSAGE_ZF(buffer) != 0)
    {
        output_stream_write(os, sep, sep_length);
        sep_length = 1;

        osprint(os, "\"zf\"");
    }
    if(MESSAGE_AD(buffer) != 0)
    {
        output_stream_write(os, sep, sep_length);
        sep_length = 1;

        osprint(os, "\"ad\"");
    }
    if(MESSAGE_CD(buffer) != 0)
    {
        output_stream_write(os, sep, sep_length);
        // sep_length = 1; // no further use

        osprint(os, "\"CD\"");
    }

    osprint(os, "],");

    /* print counters */
    osformat(os, "\"qdcount\":%hd,", count[0]);
    osformat(os, "\"ancount\":%hd,", count[1]);
    osformat(os, "\"nscount\":%hd,", count[2]);
    osformat(os, "\"arcount\":%hd,", count[3]);
    osprint(os, "},");

    /* QUESTION SECTION */
    {
        uint32_t section_idx = 0;

        /* print SECTION name */
        if(message_viewer_requires_section(section_idx, flags))
        {
            osformat(os, "\"%s\":[", section_name[section_idx]);
        }

        for(uint_fast16_t n = count[section_idx]; n > 0; n--)
        {
            /* 1. GET EVERYTHING FROM THE BUFFER FOR QUESTION + OFFSET packet reader */

            /* retrieve QNAME from packet reader */
            if(FAIL(return_value = dns_packet_reader_read_fqdn(&purd, record_wire, sizeof(record_wire))))
            {
                return return_value;
            }

            /* retrieve QTYPE from packet reader */
            uint16_t rtype;
            if(FAIL(return_value = dns_packet_reader_read_u16(&purd, &rtype)))
            {
                return return_value;
            }

            /* retrieve QCLASS from packet reader */
            uint16_t rclass;
            if(FAIL(return_value = dns_packet_reader_read_u16(&purd, &rclass)))
            {
                return return_value;
            }

            /* print everything from QUESTION SECTION */
            if(message_viewer_requires_section(section_idx, flags))
            {
                output_stream_write_u8(os, '{');

                /* name */
                osformat(os, "\"name\":\"%{dnsname}\",", record_wire);
                /* class */
                osformat(os, "\"class\":\"%{dnsclass}\",", &rclass);
                /* type */
                osformat(os, "\"type\":\"%{dnstype}\",", &rtype);

                osprint(os, "},");
            }
        }

        /* closing SECTION */
        if(message_viewer_requires_section(section_idx, flags))
        {
            osprint(os, "],");
        }
    }

    for(uint_fast32_t section_idx = 1; section_idx < 4; section_idx++)
    {
        /* print SECTION name */
        if(message_viewer_requires_section(section_idx, flags))
        {
            osformat(os, "\"%s\":[", section_name[section_idx]);
        }

        for(uint_fast16_t n = count[section_idx]; n > 0; n--)
        {
            /* Get next record and put the packet reader offset on the next record */
            if(FAIL(return_value = dns_packet_reader_read_record(&purd, record_wire, sizeof(record_wire))))
            {
                return return_value;
            }

            /* initialize the values needed for printing */
            uint8_t *rname = record_wire;
            uint8_t *rdata = rname + dnsname_len(rname);
            uint16_t rtype = GET_U16_AT(rdata[0]);
            uint16_t rclass = GET_U16_AT(rdata[2]);
            uint16_t rttl = ntohl(GET_U32_AT(rdata[4]));
            uint16_t rdata_size = ntohs(GET_U16_AT(rdata[8]));

            /** @todo 20130530 gve -- test that rdata_size matches the record size */

            rdata += 10;

            /* Starting printing */
            if(message_viewer_requires_section(section_idx, flags))
            {
                output_stream_write_u8(os, '{');

                /* name */
                osformat(os, "\"name\":\"%{dnsname}\",", rname);
                /* class */
                osformat(os, "\"class\":\"%{dnsclass}\",", &rclass);
                /* type */
                osformat(os, "\"type\":\"%{dnstype}\",", &rtype);
                /* ttl */
                osformat(os, "\"ttl\":%7d,", rttl);
                /* rdata */
                osprint(os, "\"rdata\":\", \"");
                osprint_rdata(os, rtype, rdata, rdata_size);

                osprint(os, "\"},");
            }
        }

        /* closing SECTION */
        if(message_viewer_requires_section(section_idx, flags))
        {
            osprint(os, "],");
        }
    }

    if(dmw->flags & DNS_MESSAGE_WRITER_WITH_DURATION)
    {
        osformat(os, "\"query_time\":{\"unit\":\"msec\",\"duration\":\"%ld\"},", msg->time_duration_ms);
    }

    if(dmw->flags & DNS_MESSAGE_WRITER_WITH_SERVER)
    {
        /// @todo 20240923 gve -- implement the server formatting and protocol correctly
        // osformat(os, ";; SERVER: %{hostaddr}(%{hostaddr})\n", config->server, config->server);
    }

    if(dmw->flags & DNS_MESSAGE_WRITER_WITH_TIME)
    {
        osformat(os, "\"when\":\"%s\",", ctime(&msg->when));
    }
    osformat(os, "\"msg_size\":{\"kind\":\"received\",\"bytes\":%ld}", length);

    output_stream_write_u8(os, '}');

    return 0;
}

ya_result dns_message_print_format_json(output_stream_t *os, const uint8_t *buffer, uint32_t length, uint32_t view_mode_with, int32_t time_duration_ms)
{
    dns_message_writer_t dmw;
    dns_message_writer_init(&dmw, os, dns_message_writer_json, view_mode_with);
    dns_message_writer_message_t msg;
    msg.buffer = buffer;
    msg.length = length;
    msg.time_duration_ms = time_duration_ms;
    msg.when = time(NULL);
    msg.server = NULL;
    msg.protocol = 0;
    ya_result ret = dns_message_writer_write(&dmw, &msg);
    return ret;
}

ya_result dns_message_print_format_json_buffer(output_stream_t *os_, const uint8_t *buffer, uint32_t length, uint32_t view_mode_with)
{
    ya_result ret = dns_message_print_format_json(os_, buffer, length, view_mode_with & ~DNS_MESSAGE_WRITER_WITH_DURATION, 0);
    return ret;
}
