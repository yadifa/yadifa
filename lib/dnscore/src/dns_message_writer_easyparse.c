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

#include "dnscore/dnscore_config.h"
#include <stddef.h>
#include <unistd.h>

#include "dnscore/counter_output_stream.h"
#include "dnscore/format.h"
#include "dnscore/logger.h"
#include "dnscore/dns_message.h"
#include "dnscore/dns_message_writer.h"
#include "dnscore/rfc.h"
#include <dnscore/dns_packet_reader.h>

static char *message_section_names[4] = {"SECTION QUESTION", "SECTION ANSWER", "SECTION AUTHORITY", "SECTION ADDITIONAL"};

static char *message_section_update_names[4] = {"SECTION ZONE", "SECTION PREREQUISITES", "SECTION UPDATE RECORDS", "SECTION ADDITIONAL RECORDS"};

static char *message_count_names[4] = {"COUNT QUERY", "COUNT ANSWER", "COUNT AUTHORITY", "COUNT ADDITIONAL"};

static char *message_count_update_names[4] = {"COUNT ZONE", "COUNT PREREQUISITES", "COUNT UPDATE", "COUNT ADDITIONAL"};

ya_result    dns_message_writer_easyparse(const dns_message_writer_t *dmw, const dns_message_writer_message_t *msg)
{
    const uint8_t *buffer = msg->buffer;
    uint32_t       length = msg->length;
    uint32_t       view_mode_with = dmw->flags;
    ya_result      return_value;

    /*
     * There is no padding support for formats on complex types (padding is ignored)
     * Doing it would be relatively expensive for it's best doing it manually when needed (afaik: only here)
     */

    counter_output_stream_context_t counters;
    output_stream_t                 cos;
    counter_output_stream_init(dmw->os, &cos, &counters);

    output_stream_t    *os = &cos;

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

    /* 4. GET THE NAMES FOR THE PRESENTATION */
    char **count_name = (opcode != OPCODE_UPDATE) ? message_count_names : message_count_update_names;
    char **section_name = (opcode != OPCODE_UPDATE) ? message_section_names : message_section_update_names;

    /* 5. FILL THE STREAM */

    /* fill the information of the header of a DNS packet */

    osformat(os, "%18s : %s\n", "HEADER STATUS", status_txt);
    osformat(os, "%18s : %hd\n", "HEADER ID", id);
    osformat(os, "%18s : %s\n", "HEADER OPCODE", opcode_txt);

    if(MESSAGE_QR(buffer) != 0)
    {
        osformat(os, "%18s : %s\n", "HEADER FLAG", "QR");
    }
    if(MESSAGE_AA(buffer) != 0)
    {
        osformat(os, "%18s : %s\n", "HEADER FLAG", "AA");
    }
    if(MESSAGE_TC(buffer) != 0)
    {
        osformat(os, "%18s : %s\n", "HEADER FLAG", "TC");
    }
    if(MESSAGE_RD(buffer) != 0)
    {
        osformat(os, "%18s : %s\n", "HEADER FLAG", "RD");
    }
    if(MESSAGE_RA(buffer) != 0)
    {
        osformat(os, "%18s : %s\n", "HEADER FLAG", "RA");
    }
    if(MESSAGE_ZF(buffer) != 0)
    {
        osformat(os, "%18s : %s\n", "HEADER FLAG", "ZF");
    }
    if(MESSAGE_AD(buffer) != 0)
    {
        osformat(os, "%18s : %s\n", "HEADER FLAG", "AD");
    }
    if(MESSAGE_CD(buffer) != 0)
    {
        osformat(os, "%18s : %s\n", "HEADER FLAG", "CD");
    }

    osformat(os, "%18s : %hd\n", count_name[0], count[0]);
    osformat(os, "%18s : %hd\n", count_name[1], count[1]);
    osformat(os, "%18s : %hd\n", count_name[2], count[2]);
    osformat(os, "%18s : %hd\n", count_name[3], count[3]);
    osprintln(os, "");

    {
        uint32_t section_idx = 0;

        /* Print SECTION name */
#if 0
        if(message_viewer_requires_section(section_idx, view_mode_with))
        {
            osformat(os, "\n;; %s:\n", section_name[section_idx]);
        }
#endif

        for(uint_fast16_t n = count[section_idx]; n > 0; n--)
        {
            /* 1. GET EVERYTHING FROM THE BUFFER FOR QUESTION + OFFSET packet reader */

            /* Retrieve QNAME from packet reader */
            if(FAIL(return_value = dns_packet_reader_read_fqdn(&purd, record_wire, sizeof(record_wire))))
            {
                return return_value;
            }

            /* Retrieve QTYPE from packet reader */
            uint16_t rtype;
            if(FAIL(return_value = dns_packet_reader_read_u16(&purd, &rtype)))
            {
                return return_value;
            }

            /* Retrieve QCLASS from packet reader */
            uint16_t rclass;
            if(FAIL(return_value = dns_packet_reader_read_u16(&purd, &rclass)))
            {
                return return_value;
            }

            /* Print everything from QUESTION SECTION */

            if(message_viewer_requires_section(section_idx, view_mode_with))
            {
                uint64_t next = counters.write_count + 24 + 8;

                /* write NAME + alignment for next item */
                osformat(os, "%18s : %{dnsname}", section_name[section_idx], record_wire, ' ');
                while(counters.write_count < next)
                {
                    output_stream_write_u8(os, (uint8_t)' ');
                }
                output_stream_write_u8(os, (uint8_t)' ');

                next = counters.write_count + 7;

                /* write CLASS + alignment for next item */
                osformat(os, "%7{dnsclass}", &rclass);
                while(counters.write_count < next)
                {
                    output_stream_write_u8(os, (uint8_t)' ');
                }
                output_stream_write_u8(os, (uint8_t)' ');

                /* write TYPE */
                osformat(os, "%7{dnstype}", &rtype);

                osprintln(os, "");
            }
        }
        osprintln(os, "");
    }

    for(uint_fast32_t section_idx = 1; section_idx < 4; section_idx++)
    {
#if 0
        if(message_viewer_requires_section(section_idx, view_mode_with))
        {
            osformat(os, ";; %s:\n", section_name[section_idx]);
        }
#endif

        for(uint_fast16_t n = count[section_idx]; n > 0; n--)
        {
            /* Get next record and put the packet reader offset on the next record */
            if(FAIL(return_value = dns_packet_reader_read_record(&purd, record_wire, sizeof(record_wire))))
            {
                return return_value;
            }

            /* Initialize the values needed for printing */
            // uint8_t *limit      = &record_wire[return_value];

            uint8_t *rname = record_wire;
            uint8_t *rdata = rname + dnsname_len(rname);
            uint16_t rtype = GET_U16_AT(rdata[0]);
            uint16_t rclass = GET_U16_AT(rdata[2]);
            uint16_t rttl = ntohl(GET_U32_AT(rdata[4]));
            uint16_t rdata_size = ntohs(GET_U16_AT(rdata[8]));

            /** @todo 20130530 gve -- test that rdata_size matches the record size */

            rdata += 10;

            uint64_t next = counters.write_count + 24;

            /* Starting printing */
            if(message_viewer_requires_section(section_idx, view_mode_with))
            {
                /* write NAME + alignment for next item */
                osformat(os, "%18s : %{dnsname}", section_name[section_idx], rname);
                while(counters.write_count < next)
                {
                    output_stream_write_u8(os, (uint8_t)' ');
                }
                output_stream_write_u8(os, (uint8_t)' ');

                /* write TTL + alignment for next item */
                osformat(os, "%7d", rttl);
                output_stream_write_u8(os, (uint8_t)' ');

                next = counters.write_count + 7;

                /* write CLASS + alignment for next item */
                osformat(os, "%7{dnsclass}", &rclass);
                while(counters.write_count < next)
                {
                    output_stream_write_u8(os, (uint8_t)' ');
                }
                output_stream_write_u8(os, (uint8_t)' ');

                next = counters.write_count + 7;

                /* write TYPE + alignment for next item */
                osformat(os, "%7{dnstype} ", &rtype);
                while(counters.write_count < next)
                {
                    output_stream_write_u8(os, (uint8_t)' ');
                }

                output_stream_write_u8(os, (uint8_t)' ');

                /* write RDATA */
                osprint_rdata(os, rtype, rdata, rdata_size);

                osprintln(os, "");
            }
        }
        if(message_viewer_requires_section(section_idx, view_mode_with))
        {
            osprintln(os, "");
        }
    }

    osformat(os, "SYS %14s : %ld\n", "MSG SIZE rcvd", length);

    if(dmw->flags & DNS_MESSAGE_WRITER_WITH_DURATION)
    {
        osformat(os, "SYS %14s : %ld msec\n", "QUERY TIME", msg->time_duration_ms);
    }

    if(dmw->flags & DNS_MESSAGE_WRITER_WITH_SERVER)
    {
        /// @todo 20240923 gve -- implement the server formatting and protocol correctly
        // osformat(os, ";; SERVER: %{hostaddr}(%{hostaddr})\n", config->server, config->server);
    }

    if(dmw->flags & DNS_MESSAGE_WRITER_WITH_TIME)
    {
        osformat(os, "SYS %14s : %s", "WHEN", ctime(&msg->when));
    }

    osformat(os, "SYS %14s : %ld\n", "MSG SIZE rcvd", length);

    return 0;
}

ya_result dns_message_print_format_easyparse(output_stream_t *os, const uint8_t *buffer, uint32_t length, uint32_t view_mode_with, int32_t time_duration_ms)
{
    dns_message_writer_t dmw;
    dns_message_writer_init(&dmw, os, dns_message_writer_easyparse, view_mode_with);
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

ya_result dns_message_print_format_easyparse_buffer(output_stream_t *os_, const uint8_t *buffer, uint32_t length, uint16_t view_mode_with)
{
    ya_result ret = dns_message_print_format_easyparse(os_, buffer, length, view_mode_with & ~DNS_MESSAGE_WRITER_WITH_DURATION, 0);
    return ret;
}
