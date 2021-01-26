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

#include "client-config.h"

#include <dnscore/output_stream.h>
#include <dnscore/counter_output_stream.h>
#include <dnscore/format.h>
#include <dnscore/message.h>
#include <dnscore/message-viewer.h>

//#include message-viewer-parse.h"

static char* message_count_names[4] =
{
    "QUERY", "ANSWER", "AUTHORITY", "ADDITIONAL"
};

static char* message_count_update_names[4] =
{
    "ZONE", "PREREQUISITES", "UPDATE", "ADDITIONAL"
};

static char* message_section_names[4] =
{
    "QUESTION SECTION", "ANSWER SECTION", "AUTHORITY SECTION", "ADDITIONAL SECTION"
};

static char* message_section_update_names[4] =
{
    "ZONE", "PREREQUISITES", "UPDATE RECORDS", "ADDITIONAL RECORDS"
};


static void
message_viewer_parse_start(message_viewer *mv)
{
    output_stream                                             *os  = mv->os;

    /*    ------------------------------------------------------------    */

    osformatln(os, "; ( server found)");         /// @todo 20150709 gve -- still need to find a way to show amount of servers
    osformatln(os, ";; global options: ");       /// @todo 20150709 gve -- no global options given output_stream                                         *os  = mv->os;
}


static void
message_viewer_parse_end(message_viewer *mv, long time_duration)
{
    output_stream                                              *os = mv->os;
    time_t                                                            timep;

    time(&timep);

    osformat(os, ";; Query time: %ld msec\n", time_duration);

    /** @todo 20150716 gve -- still need to implemented the server viewable line */
//    osformat(os, ";; SERVER: %{hostaddr}(%{hostaddr})\n", config->server, config->server);

    osformat(os,   ";; WHEN: %s", ctime(&timep));

    if(mv->view_mode_with & MESSAGE_VIEWER_WITH_XFR)
    {
        osformatln(os, ";; XFR size: %lu records (messages %lu, bytes %lu)", mv->resource_records_total[1], mv->messages, mv->bytes);
    }
    else
    {
        osformatln(os, ";; MSG SIZE rcvd: %ld", mv->bytes);
    }
    osformat(os, "\n");
}


static void
message_viewer_parse_header(message_viewer *mv, const u8 *buffer)
{
    /* 1. get the output stream */
    output_stream *os      = mv->os;


    /* 2. get values of the different sections: QUESTION, ANSWER, AUTHORITY and ADDITIONAL */
    u16 count[4];
    count[0]               = ntohs(MESSAGE_QD(buffer));
    count[1]               = ntohs(MESSAGE_AN(buffer));
    count[2]               = ntohs(MESSAGE_NS(buffer));
    count[3]               = ntohs(MESSAGE_AR(buffer));


    /* 3. add the amount of section resource records into a total */
    message_viewer_resource_record_total_update(mv, count);


    /* 4. get message id */
    u16 id                 = MESSAGE_ID(buffer);


    /* 5. get opcode and rcode.
     *    opcode is needed for for knowing the difference between a regular message and a update message
     */
    u8 opcode              = MESSAGE_OP(buffer);
    opcode               >>= OPCODE_SHIFT;

    u8 rcode               = MESSAGE_RCODE(buffer);

    const char *opcode_txt = dns_message_opcode_get_name(opcode);
    const char *status_txt = dns_message_rcode_get_name(rcode);

    mv->section_name       = (opcode != OPCODE_UPDATE)? message_section_names : message_section_update_names;


    /* if no view with header then inmediately return,
     * parse axfr has no header information so --> return
     */
    if(mv->view_mode_with & MESSAGE_VIEWER_WITH_XFR)
    {
        return;
    }


    /* 6. we have all the information, fill the stream */
    osformat(os, ";; Got answer:\n");
    osformat(os, ";; ->>HEADER<<- opcode: %s, status: %s, id: %hd\n", opcode_txt, status_txt, id);
    osformat(os, ";; flags: ");

    if(MESSAGE_QR(buffer) != 0) osprint(os, "qr ");
    if(MESSAGE_AA(buffer) != 0) osprint(os, "aa ");
    if(MESSAGE_TC(buffer) != 0) osprint(os, "tc ");
    if(MESSAGE_RD(buffer) != 0) osprint(os, "rd ");
    if(MESSAGE_RA(buffer) != 0) osprint(os, "ra ");
    if(MESSAGE_ZF(buffer) != 0) osprint(os, "zf ");
    if(MESSAGE_AD(buffer) != 0) osprint(os, "ad ");
    if(MESSAGE_CD(buffer) != 0) osprint(os, "cd ");

    /* 3. get the names for the presentation */
    char  **count_name;
    count_name             = (opcode != OPCODE_UPDATE)? message_count_names   : message_count_update_names;

    osformat(os, "%s: %hd, %s: %hd, %s: %hd, %s: %hd\n",
             count_name[0], count[0],
             count_name[1], count[1],
             count_name[2], count[2],
             count_name[3], count[3]
    );
}


static void
message_viewer_parse_section_header(message_viewer *mv, u32 section_idx, u16 count)
{
    if(mv->view_mode_with & MESSAGE_VIEWER_WITH_XFR)
    {
        return;
    }

//    u16 view_mode_with = mv->view_mode_with;
    output_stream *os  = mv->os;

    const char *section_name   = mv->section_name[section_idx];


//    if(message_viewer_requires_section(section_idx, view_mode_with) && count)
    {
        osformat(os, ";; %s:\n", section_name);
    }
}


static void
message_viewer_parse_section_footer(message_viewer *mv, u32 section_idx, u16 count)
{
    if(mv->view_mode_with & MESSAGE_VIEWER_WITH_XFR)
    {
        return;
    }

//    u16 view_mode_with = mv->view_mode_with;
    output_stream *os  = mv->os;

//    const char *section_name   = mv->section_name[section_idx];

//    if(message_viewer_requires_section(section_idx, view_mode_with))
    {
        osprintln(os, "");
    }
}


static void
message_viewer_parse_question_record(message_viewer *mv, u8 *record_wire, u16 rclass, u16 rtype)
{
    if(mv->view_mode_with & MESSAGE_VIEWER_WITH_XFR)
    {
        return;
    }

    output_stream *os_ = mv->os;


    /*
     * There is no padding support for formats on complex types (padding is ignored)
     * Doing it would be relatively expensive for it's best doing it manually when needed (afaik: only here)
     */

    counter_output_stream_data                                     counters;
    output_stream                                                       cos;
    counter_output_stream_init(os_, &cos, &counters);

    output_stream                                                *os = &cos;


    u64 next = counters.write_count + 24 + 8;

    /* write NAME + alignment for next item */
    osformat(os, ";%{dnsname}", record_wire, ' ');
    while(counters.write_count < next)
    {
        output_stream_write_u8(os, (u8) ' ');
    }
    output_stream_write_u8(os, (u8) ' ');

    next = counters.write_count + 7;

    /* write CLASS + alignment for next item */
    osformat(os, "%7{dnsclass}", &rclass);
    while(counters.write_count < next)
    {
        output_stream_write_u8(os, (u8) ' ');
    }
    output_stream_write_u8(os, (u8) ' ');

    //                next = counters.write_count + 7;

    /* write TYPE */
    osformatln(os, "%7{dnstype}", &rtype);
}


static void
message_viewer_parse_section_record(message_viewer *mv, u8 *record_wire, u8 section_idx)
{
    (void)section_idx;

    /*
     * there is no padding support for formats on complex types (padding is ignored)
     * doing it would be relatively expensive for it's best doing it manually when needed (afaik: only here)
     */

    counter_output_stream_data                                     counters;
    output_stream                                                       cos;
    output_stream *os_                                             = mv->os;
    counter_output_stream_init(os_, &cos, &counters);

    output_stream                                                *os = &cos; /* final output stream */

    /*    ------------------------------------------------------------    */


    /* 1. get the needed parameters: FQDN, TYPE, CLASS, TTL, RDATA size */
    u8 *rname      = record_wire;
    u8 *rdata      = rname + dnsname_len(rname);
    u16 rtype      = GET_U16_AT(rdata[0]);
    u16 rclass     = GET_U16_AT(rdata[2]);
    u32 rttl       = ntohl(GET_U32_AT(rdata[4]));
    u16 rdata_size = ntohs(GET_U16_AT(rdata[8]));

    /** @todo 20150716 gve -- test that rdata_size matches the record size */

    /* move pointer to RDATA information in the record_wire */
    rdata         += 10;


    /* 2. write the retrieved info into the stream:
     *    FQDN                     TTL     CLASS   TYPE    RDATA
     *
     *    e.g.
     *    somedomain.eu.           86400   IN      NS      ns1.somedomain.eu.
     */

    /* A. write FQDN + alignment for next item */
    u64 next       = counters.write_count + 24;

    osformat(os, "%{dnsname}", rname);
    while(counters.write_count < next)
    {
        output_stream_write_u8(os, (u8)' ');
    }
    output_stream_write_u8(os, (u8)' ');

    /* B. write TTL + alignment for next item */
    osformat(os, "%7d", rttl);
    output_stream_write_u8(os, (u8)' ');


    /* C. write CLASS + alignment for next item */
    next = counters.write_count + 7;

    osformat(os, "%7{dnsclass}", &rclass);
    while(counters.write_count < next)
    {
        output_stream_write_u8(os, (u8) ' ');
    }
    output_stream_write_u8(os, (u8)' ');


    /* D. write TYPE + alignment for next item */
    next = counters.write_count + 7;

    osformat(os, "%7{dnstype} ", &rtype);
    while(counters.write_count < next)
    {
        output_stream_write_u8(os, (u8)' ');
    }
    output_stream_write_u8(os, (u8)' ');


    /* E. write RDATA */
    osprint_rdata(os, rtype, rdata, rdata_size);


    osprintln(os, "");
    flushout();
}


static const message_viewer_vtbl parse_viewer_vtbl = {
       message_viewer_parse_header,
       message_viewer_parse_start,
       message_viewer_parse_end,
       message_viewer_parse_section_header,
       message_viewer_parse_section_footer,
       message_viewer_parse_question_record,
       message_viewer_parse_section_record,
       "message_viewer_parse",
};


void
message_viewer_parse_set(message_viewer *mv)
{
    mv->vtbl = &parse_viewer_vtbl;
}


void
message_viewer_parse_init(message_viewer *mv, output_stream *os, u16 view_mode_with)
{
    message_viewer_init(mv);

    mv->vtbl                      = &parse_viewer_vtbl;
    mv->os                        = os;
    mv->view_mode_with            = view_mode_with;


}

