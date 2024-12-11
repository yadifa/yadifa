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

/**-----------------------------------------------------------------------------
 * @defgroup dnscore System core functions
 * @brief System core functions
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include <stddef.h>
#include <dnscore/dns_message_writer.h>

#include "dnscore/counter_output_stream.h"
#include "dnscore/format.h"
#include "dnscore/dns_message.h"
#include <dnscore/dns_packet_reader.h>

static char *message_section_names[4] = {"QUESTION SECTION", "ANSWER SECTION", "AUTHORITY SECTION", "ADDITIONAL SECTION"};

static char *message_section_update_names[4] = {"ZONE", "PREREQUISITES", "UPDATE RECORDS", "ADDITIONAL RECORDS"};

static char *message_count_names[4] = {"QUERY", "ANSWER", "AUTHORITY", "ADDITIONAL"};

static char *message_count_update_names[4] = {"ZONE", "PREREQUISITES", "UPDATE", "ADDITIONAL"};

ya_result    dns_message_writer_dig(const dns_message_writer_t *dmw, const dns_message_writer_message_t *msg)
{
    ya_result      return_value;
    const uint8_t *buffer = msg->buffer;

    /*
     * There is no padding support for formats on complex types (padding is ignored)
     * Doing it would be relatively expensive for it's best doing it manually when needed (afaik: only here)
     */

    counter_output_stream_context_t counters;
    output_stream_t                 cos;
    counter_output_stream_init(&cos, dmw->os, &counters);

    output_stream_t    *os = &cos;

    dns_packet_reader_t purd;

    uint8_t             record_wire[DOMAIN_LENGTH_MAX + 10 + 65535];

    /*    ------------------------------------------------------------    */

    /* Init packet reader with buffer. length and offset in the buffer */

    dns_packet_reader_init_at(&purd, buffer, msg->length, DNS_HEADER_LENGTH);

    /* 1. GET ID */
    uint16_t id = MESSAGE_ID(buffer);

    /* 2. GET OPCODE AND RCODE */
    uint8_t     opcode_shifted = MESSAGE_OP(buffer);
    uint8_t     opcode = opcode_shifted >> OPCODE_SHIFT;

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
    char **count_name = (opcode_shifted != OPCODE_UPDATE) ? message_count_names : message_count_update_names;
    char **section_name = (opcode_shifted != OPCODE_UPDATE) ? message_section_names : message_section_update_names;

    /* 5. FILL THE STREAM */

    if(dmw->flags & DNS_MESSAGE_WRITER_WITH_SERVER_COUNT)
    {
        uint32_t host_count = host_address_count(msg->server);

        if(host_count == 1)
        {
            osformatln(os, "; (1 server found)");
        }
        else
        {
            osformatln(os, "; (%u servers found)", host_count);
        }
    }

    /*
     // @todo 20240923 edf -- add this here or with an alternate writer
    static const char global_options_got_answer[] =
        ";; global options:\n"
        ";; Got answer:\n";
    output_stream_write_fully(os, global_options_got_answer, sizeof(global_options_got_answer) - 1);
    */

    /* fill the information with the header of a DNS packet */
    osformat(os, ";; ->>HEADER<<- opcode: %s, status: %s, id: %hd\n", opcode_txt, status_txt, ntohs(id));
    osformat(os, ";; flags: ");

    if(MESSAGE_QR(buffer) != 0)
    {
        osprint(os, "qr ");
    }
    if(MESSAGE_AA(buffer) != 0)
    {
        osprint(os, "aa ");
    }
    if(MESSAGE_TC(buffer) != 0)
    {
        osprint(os, "tc ");
    }
    if(MESSAGE_RD(buffer) != 0)
    {
        osprint(os, "rd ");
    }
    if(MESSAGE_RA(buffer) != 0)
    {
        osprint(os, "ra ");
    }
    if(MESSAGE_ZF(buffer) != 0)
    {
        osprint(os, "zf ");
    }
    if(MESSAGE_AD(buffer) != 0)
    {
        osprint(os, "ad ");
    }
    if(MESSAGE_CD(buffer) != 0)
    {
        osprint(os, "cd ");
    }

    osformat(os, "%s: %hd, %s: %hd, %s: %hd, %s: %hd\n", count_name[0], count[0], count_name[1], count[1], count_name[2], count[2], count_name[3], count[3]);

    {
        uint32_t section_idx = 0;

        /* Print SECTION name */

        if(message_viewer_requires_section(section_idx, dmw->flags))
        {
            osformat(os, "\n;; %s:\n", section_name[section_idx]);
        }

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

            if(message_viewer_requires_section(section_idx, dmw->flags))
            {
                uint64_t next = counters.write_count + 24 + 8;

                /* write NAME + alignment for next item */
                osformat(os, ";%{dnsname}", record_wire);
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

                //                next = counters.write_count + 7;

                /* write TYPE */
                osformatln(os, "%7{dnstype}", &rtype);
            }
        }
        osprintln(os, "");
    }

    for(uint_fast32_t section_idx = 1; section_idx < 4; section_idx++)
    {
        if(message_viewer_requires_section(section_idx, dmw->flags))
        {
            osformat(os, ";; %s:\n", section_name[section_idx]);
        }

        for(uint_fast16_t n = count[section_idx]; n > 0; n--)
        {
            /* Get next record and put the packet reader offset on the next record */
            if(FAIL(return_value = dns_packet_reader_read_record(&purd, record_wire, sizeof(record_wire))))
            {
                return return_value;
            }

            /* Initialize the values needed for printing */
            uint8_t *rname = record_wire;
            uint8_t *rdata = rname + dnsname_len(rname); // points to {type class ttl rdata_size}
            uint16_t rtype = GET_U16_AT(rdata[0]);

            if(section_idx == 3)
            {
                if(rtype == TYPE_OPT)
                {
                    rdata += 2;
                    uint16_t rclass = GET_U16_AT_P(rdata);
                    rdata += 2;
                    uint32_t ttl = GET_U32_AT_P(rdata);
                    rdata += 4;
                    osformatln(os, ";; OPT: UDP payload size: %i", rclass);
                    osformat(os, ";; OPT: extended RCODE and flags: %08x", ttl);
                    osprintln(os, "");
                    uint16_t rdata_size = ntohs(GET_U16_AT_P(rdata));
                    rdata += 2;
                    while(rdata_size > 0)
                    {
                        if(rdata_size < 4)
                        {
                            osformatln(os, ";; OPT: corrupted entry");
                            break;
                        }
                        uint16_t code = GET_U16_AT_P(rdata);
                        rdata += 2;
                        uint16_t len = ntohs(GET_U16_AT_P(rdata));
                        rdata += 2;
                        rdata_size -= 4;
                        if(rdata_size < len)
                        {
                            osformatln(os, ";; OPT: corrupted entry data");
                            break;
                        }
                        switch(code)
                        {
                            case OPT_NSID:
                            {
                                osformat(os, ";; OPT: NSID:");
                                for(int i = 0; i < len; ++i)
                                {
                                    osformat(os, " %02x", rdata[i]);
                                }
                                osprintln(os, "");
                                break;
                            }
                            case OPT_COOKIE:
                            {
                                osformat(os, ";; OPT: COOKIE: ");
                                for(int i = 0; i < len; ++i)
                                {
                                    osformat(os, " %02x", rdata[i]);
                                }
                                osprintln(os, "");
                                break;
                            }
                            default:
                            {
                                osformat(os, ";; OPT: OPT_%i: ", ntohs(code));
                                for(int i = 0; i < len; ++i)
                                {
                                    osformat(os, " %02x", rdata[i]);
                                }
                                osprintln(os, "");
                                break;
                            }
                        }
                        rdata += len;
                        rdata_size -= len;
                    }
                    continue;
                }
                else if(rtype == TYPE_TSIG)
                {
                    if((dmw->flags & DNS_MESSAGE_WRITER_WITH_TSIG) != 0)
                    {
                        rdata += 8; // type class ttl
                        uint16_t rdata_size = ntohs(GET_U16_AT_P(rdata));
                        rdata += 2;
                        uint8_t *record_wire_limit = &rdata[rdata_size];
                        if(record_wire_limit <= &record_wire[sizeof(record_wire)])
                        {
                            uint8_t *algorithm_name = rdata;
                            uint8_t *timep = algorithm_name + dnsname_len(algorithm_name);
                            uint8_t *fudgep = timep + 6;
                            uint8_t *macsizep = fudgep + 2;
                            uint8_t *macp = macsizep + 2;
                            if(macp <= record_wire_limit)
                            {
                                uint16_t macsize = ntohs(GET_U16_AT_P(macsizep));
                                uint8_t *originalidp = macp + macsize;
                                uint8_t *errorp = originalidp + 2;
                                uint8_t *otherlenp = errorp + 2;
                                uint8_t *otherp = otherlenp + 2;
                                if(otherp <= record_wire_limit)
                                {
                                    uint16_t otherlen = ntohs(GET_U16_AT_P(otherlenp));

                                    int64_t  timelo = ntohl(GET_U32_AT_P(timep + 2));
                                    int64_t  timehi = ntohs(GET_U16_AT_P(timep));
                                    int64_t  time_signed = (timehi << 32) + timelo;
                                    uint16_t fudge = ntohs(GET_U16_AT_P(fudgep));
                                    uint16_t originalid = ntohs(GET_U16_AT_P(originalidp));
                                    uint16_t error = ntohs(GET_U16_AT_P(errorp));

                                    osformat(os, "\n;; SIGNATURE SECTION:\n%{dnsname} %{dnstype} %{dnsname} %T +- %hu ", rname, &rtype, algorithm_name, time_signed, fudge);
                                    osprint_base64(os, macp, macsize);
                                    osformatln(os, " %hx [%hu]", originalid, error, otherlen);
                                    continue;
                                }
                            }
                        }

                        return DNS_ERROR_CODE(RCODE_FORMERR);
                    }
                    else
                    {
                        continue;
                    }
                }
            }

            uint16_t rclass = GET_U16_AT(rdata[2]);
            uint32_t rttl = ntohl(GET_U32_AT(rdata[4]));
            uint16_t rdata_size = ntohs(GET_U16_AT(rdata[8]));

            rdata += 10; // skip the type class ttl rdata_len

            // test that rdata_size matches the record size

            if(&rdata[rdata_size] != &record_wire[return_value])
            {
                // rdata_size doesn't exactly match the returned size
                osformatln(os, ";; error reading the message");
                return MAKE_RCODE_ERROR(RCODE_FORMERR);
            }

            uint64_t next = counters.write_count + 24;

            /* Starting printing */
            if(message_viewer_requires_section(section_idx, dmw->flags))
            {
                /* write NAME + alignment for next item */
                osformat(os, "%{dnsname}", rname);
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
        if(message_viewer_requires_section(section_idx, dmw->flags))
        {
            osprintln(os, "");
        }
    }

    if(dmw->flags & DNS_MESSAGE_WRITER_WITH_DURATION)
    {
        osformat(os, ";; Query time: %i msec\n", msg->time_duration_ms);
    }

    if(dmw->flags & DNS_MESSAGE_WRITER_WITH_SERVER)
    {
        /// @todo 20240923 gve -- implement the server formatting and protocol correctly
        // osformat(os, ";; SERVER: %{hostaddr}(%{hostaddr})\n", config->server, config->server);
    }

    if(dmw->flags & DNS_MESSAGE_WRITER_WITH_TIME)
    {
        osformat(os, ";; WHEN: %s\n", ctime(&msg->when));
        osformat(os, ";; MSG SIZE rcvd: %ld\n", msg->length);
    }
    else
    {
        osformat(os, ";; MSG SIZE: %ld\n", msg->length);
    }

    output_stream_write_u8(os, '\n');

    return 0;
}

ya_result dns_message_print_format_dig(output_stream_t *os, const uint8_t *buffer, uint32_t length, uint32_t view_mode_with, int32_t time_duration_ms)
{
    dns_message_writer_t dmw;
    dns_message_writer_init(&dmw, os, dns_message_writer_dig, view_mode_with);
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

ya_result dns_message_print_format_dig_buffer(output_stream_t *os_, const uint8_t *buffer, uint32_t length, uint32_t view_mode_with)
{
    ya_result ret = dns_message_print_format_dig(os_, buffer, length, view_mode_with & ~DNS_MESSAGE_WRITER_WITH_DURATION, 0);
    return ret;
}
