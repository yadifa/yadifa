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

/** @defgroup dnscore System core functions
 *  @brief System core functions
 *
 * @{ */

#include "dnscore/dnscore-config.h"
#include <stddef.h>
#include <unistd.h>
#include <dnscore/message-viewer.h>

#include "dnscore/counter_output_stream.h"
#include "dnscore/format.h"
#include "dnscore/message.h"
#include "dnscore/packet_reader.h"

static char* message_section_names[4] =
{
    "QUESTION SECTION", "ANSWER SECTION", "AUTHORITY SECTION", "ADDITIONAL SECTION"
};

static char* message_section_update_names[4] =
{
    "ZONE", "PREREQUISITES", "UPDATE RECORDS", "ADDITIONAL RECORDS"
};

static char* message_count_names[4] =
{
    "QUERY", "ANSWER", "AUTHORITY", "ADDITIONAL"
};

static char* message_count_update_names[4] =
{
    "ZONE", "PREREQUISITES", "UPDATE", "ADDITIONAL"
};


ya_result
message_print_format_dig_buffer(output_stream *os_, const u8 *buffer, u32 length, u16 view_mode_with)
{
    ya_result                                                  return_value;
    
    /*
     * There is no padding support for formats on complex types (padding is ignored)
     * Doing it would be relatively expensive for it's best doing it manually when needed (afaik: only here)
     */
    
    counter_output_stream_data                                     counters;
    output_stream                                                       cos;
    counter_output_stream_init(os_, &cos, &counters);

    output_stream                                                *os = &cos;    

    packet_unpack_reader_data                                          purd;

    u8                          record_wire[MAX_DOMAIN_LENGTH + 10 + 65535];

    /*    ------------------------------------------------------------    */    

    /* Init packet reader with buffer. length and offset in the buffer */

    packet_reader_init_at(&purd, buffer, length, DNS_HEADER_LENGTH);

    /* 1. GET ID */
    u16 id           = MESSAGE_ID(buffer);


    /* 2. GET OPCODE AND RCODE */
    u8 opcode_shifted= MESSAGE_OP(buffer);
    u8 opcode        = opcode_shifted >> OPCODE_SHIFT;

    u8 rcode         = MESSAGE_RCODE(buffer);

    const char *opcode_txt = dns_message_opcode_get_name(opcode);
    const char *status_txt = dns_message_rcode_get_name(rcode);


    /* 3. GET VALUES OF THE SECTIONS */
    u16 count[4];
    count[0] = ntohs(MESSAGE_QD(buffer));
    count[1] = ntohs(MESSAGE_AN(buffer));
    count[2] = ntohs(MESSAGE_NS(buffer));
    count[3] = ntohs(MESSAGE_AR(buffer));
    

    /* 4. GET THE NAMES FOR THE PRESENTATION */
    char **count_name   = (opcode_shifted != OPCODE_UPDATE)? message_count_names   : message_count_update_names;
    char **section_name = (opcode_shifted != OPCODE_UPDATE)? message_section_names : message_section_update_names;


    /* 5. FILL THE STREAM */

    /* fill the information of the header of a DNS packet */
    osformat(os, ";; ->>HEADER<<- opcode: %s, status: %s, id: %hd\n", opcode_txt, status_txt, ntohs(id));
    osformat(os, ";; flags: ");
    
    if(MESSAGE_QR(buffer) != 0) osprint(os, "qr ");
    if(MESSAGE_AA(buffer) != 0) osprint(os, "aa ");
    if(MESSAGE_TC(buffer) != 0) osprint(os, "tc ");
    if(MESSAGE_RD(buffer) != 0) osprint(os, "rd ");
    if(MESSAGE_RA(buffer) != 0) osprint(os, "ra ");
    if(MESSAGE_ZF(buffer) != 0) osprint(os, "zf ");
    if(MESSAGE_AD(buffer) != 0) osprint(os, "ad ");
    if(MESSAGE_CD(buffer) != 0) osprint(os, "cd ");
    
    osformat(os, "%s: %hd, %s: %hd, %s: %hd, %s: %hd\n",
             count_name[0], count[0],
             count_name[1], count[1],
             count_name[2], count[2],
             count_name[3], count[3]
             );
    
    {
        u32 section_idx = 0;
      
        /* Print SECTION name */

        if(message_viewer_requires_section(section_idx, view_mode_with))
        {
            osformat(os, "\n;; %s:\n", section_name[section_idx]);
        }
        
        for(u16 n = count[section_idx]; n > 0; n--)
        {
            /* 1. GET EVERYTHING FROM THE BUFFER FOR QUESTION + OFFSET packet reader */

            /* Retrieve QNAME from packet reader */
            if(FAIL(return_value = packet_reader_read_fqdn(&purd, record_wire, sizeof(record_wire))))
            {
                return return_value;
            }

            /* Retrieve QTYPE from packet reader */
            u16 rtype;
            if(FAIL(return_value = packet_reader_read_u16(&purd, &rtype)))
            {
                return return_value;
            }

            /* Retrieve QCLASS from packet reader */
            u16 rclass;
            if(FAIL(return_value = packet_reader_read_u16(&purd, &rclass)))
            {
                return return_value;
            }

            /* Print everything from QUESTION SECTION */


            if(message_viewer_requires_section(section_idx, view_mode_with))
            {
                u64 next = counters.write_count + 24 + 8;

                /* write NAME + alignment for next item */
                osformat(os, ";%{dnsname}", record_wire, ' ' );
                while(counters.write_count < next)
                {
                    output_stream_write_u8(os, (u8)' ');
                }
                output_stream_write_u8(os, (u8)' ');

                next = counters.write_count + 7;

                /* write CLASS + alignment for next item */
                osformat(os, "%7{dnsclass}", &rclass);
                while(counters.write_count < next)
                {
                    output_stream_write_u8(os, (u8)' ');
                }
                output_stream_write_u8(os, (u8)' ');

//                next = counters.write_count + 7;

                /* write TYPE */
                osformatln(os, "%7{dnstype}", &rtype);
            }
        }
        osprintln(os, "");
    }

    
    for(u32 section_idx = 1; section_idx < 4; section_idx++)
    {
        if(message_viewer_requires_section(section_idx, view_mode_with))
        {
            osformat(os, ";; %s:\n", section_name[section_idx]);
        }
        
        for(u16 n = count[section_idx]; n > 0; n--)
        {
            /* Get next record and put the packet reader offset on the next record */
            if(FAIL(return_value = packet_reader_read_record(&purd, record_wire, sizeof(record_wire))))
            {
                return return_value;
            }

            /* Initialize the values needed for printing */
            u8 *rname      = record_wire;
            u8 *rdata      = rname + dnsname_len(rname);
            u16 rtype      = GET_U16_AT(rdata[0]);
            u16 rclass     = GET_U16_AT(rdata[2]);
            u32 rttl       = ntohl(GET_U32_AT(rdata[4]));
            u16 rdata_size = ntohs(GET_U16_AT(rdata[8]));

            if(section_idx == 3)
            {
                if(rtype == TYPE_OPT)
                {
                    continue;
                }
                else if(rtype == TYPE_OPT)
                {
                    continue;
                }
            }

            /** @todo 20130530 gve -- test that rdata_size matches the record size */
            
            rdata         += 10;

            u64 next       = counters.write_count + 24;

            /* Starting printing */
            if(message_viewer_requires_section(section_idx, view_mode_with))
            {
                /* write NAME + alignment for next item */
                osformat(os, "%{dnsname}", rname);
                while(counters.write_count < next)
                {
                    output_stream_write_u8(os, (u8)' ');
                }
                output_stream_write_u8(os, (u8)' ');

                /* write TTL + alignment for next item */
                osformat(os, "%7d", rttl);
                output_stream_write_u8(os, (u8)' ');

                next = counters.write_count + 7;

                /* write CLASS + alignment for next item */
                osformat(os, "%7{dnsclass}", &rclass);
                while(counters.write_count < next)
                {
                    output_stream_write_u8(os, (u8)' ');
                }
                output_stream_write_u8(os, (u8)' ');

                next = counters.write_count + 7;

                /* write TYPE + alignment for next item */
                osformat(os, "%7{dnstype} ", &rtype);
                while(counters.write_count < next)
                {
                    output_stream_write_u8(os, (u8)' ');
                }
                output_stream_write_u8(os, (u8)' ');

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
             
    return 0;
}


ya_result
message_print_format_dig(output_stream *os, const u8 *buffer, u32 length, u16 view_mode_with, long time_duration)
{
    ya_result                                                  return_value;

    time_t                                                            timep;

    /*    ------------------------------------------------------------    */ 

    osformat(os, ";; global options: \n");
    osformat(os, ";; Got answer:\n");

    if(FAIL(return_value = message_print_format_dig_buffer(os, buffer, length, view_mode_with)))
    {
        return return_value;
    }

    time(&timep);

    if(time_duration >= 0)
    {
        osformat(os, ";; Query time: %ld msec\n", time_duration);
    }

    /** @todo 20130530 gve -- still need to implemented the server viewable line */
//    osformat(os, ";; SERVER: %{hostaddr}(%{hostaddr})\n", config->server, config->server);

    osformat(os, ";; WHEN: %s", ctime(&timep));
    if(time_duration >= 0)
    {
        osformat(os, ";; MSG SIZE rcvd: %ld\n", length);
    }
    else
    {
        osformat(os, ";; MSG SIZE: %ld\n", length);
    }
    osformat(os, "\n");

    return OK;
}
