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

/** @defgroup yadifa
 *  @ingroup ###
 *  @brief
 */
#include "client-config.h"

#include <dnscore/output_stream.h>
#include <dnscore/counter_output_stream.h>
#include <dnscore/format.h>
#include <dnscore/message.h>
#include <dnscore/message-viewer.h>

//#include message-viewer-xml.h"



static char *message_record_names[4] =
        {
                "question", "answer", "authority", "additional"
        };

static char *message_section_names[4] =
        {
                "questions", "answers", "authorities", "additionals"
        };

static char *message_section_update_names[4] =
        {
                "ZONE", "PREREQUISITES", "UPDATE RECORDS", "ADDITIONAL RECORDS"
        };

static char *record_name;


#define PRETTY_PRINT_WORD "|    "
#define PRETTY_PRINT_CR   '\n'

static char pretty_print_tab[32];
static char pretty_print_cr[2];

/*----------------------------------------------------------------------------*/
#pragma mark STATIC PROTOTYPES

static void level_up(message_viewer *mv)
{
    strcat(pretty_print_tab, PRETTY_PRINT_WORD);
}

static void level_down(message_viewer *mv)
{
    size_t l = strlen(PRETTY_PRINT_WORD);
    size_t length = strlen(pretty_print_tab);

    pretty_print_tab[length -l] = '\0';
}

static void level_finalize(message_viewer *mv)
{
    pretty_print_cr[0] = '\0';
    pretty_print_tab[0] = '\0';
}

static void level_init(message_viewer *mv)
{
    pretty_print_cr[0] = PRETTY_PRINT_CR;
    pretty_print_tab[0] = '\0';
}

static void
message_viewer_xml_start(message_viewer *mv)
{
    output_stream *os = mv->os;

    /* init if pretty print outpu */
    level_init(mv);

    /*    ------------------------------------------------------------    */

    osformatln(os,
               "; ( server found)");         /// @todo 20150709 gve -- still need to find a way to show amount of servers
    osformatln(os,
               ";; global options: ");       /// @todo 20150709 gve -- no global options given output_stream                                         *os  = mv->os;


    /*
     * print xml encoding and start of the response container
     *
     * <?xml version="1.0" encoding="UTF-8"?>
     * <response>
     */

    osformat(os,"<?xml version=\"1.0\" encoding=\"UTF-8\"?>%s", pretty_print_cr);
    osformat(os, "<response>%s", pretty_print_cr);

    /* pretty print output level of tabs +1 */
    level_up(mv);
}


static void
message_viewer_xml_end(message_viewer *mv, long time_duration)
{
    output_stream *os = mv->os;
    time_t timep;

    time(&timep);

    level_down(mv);
    osformat(os, "</response>%s", pretty_print_cr);

    osformat(os, "%s<meta-data>%s", pretty_print_tab, pretty_print_cr);
    level_up(mv);
    osformat(os, "%s<query-time unit=\"msec\">%ld<query-time>%s", pretty_print_tab, time_duration, pretty_print_cr);

    /** @todo 20150716 gve -- still need to implemented the server viewable line */
//    osformat(os, ";; SERVER: %{hostaddr}(%{hostaddr})\n", config->server, config->server);


    /// @todo 20150716 gve -- remove carriage return in timep

    osformat(os, "%s<date>%s</date>%s", pretty_print_tab, ctime(&timep), pretty_print_cr);
    // osformat(os, "<when>%s</when>", date_stamp);

    if(mv->view_mode_with & MESSAGE_VIEWER_WITH_XFR)
    {
        osformat(os, "%s<records>%lu</records>%s", pretty_print_tab, mv->resource_records_total[1], pretty_print_cr);
        osformat(os, "%s<messages>%lu</messages>%s", pretty_print_tab, mv->messages, pretty_print_cr);
        osformat(os, "%s<bytes>%lu</bytes>%s", pretty_print_tab, mv->bytes, pretty_print_cr);
    }
    else
    {
        osformatln(os, "%s<msg-size kind=\"rcvd\">%ld<msg-size>%s", pretty_print_tab, mv->bytes, pretty_print_tab);
    }


    /* pretty print output level of tabs -1 */
    level_down(mv);
    osformat(os, "%s</meta-data>%s", pretty_print_tab, pretty_print_cr);

    /* clear pretty print output */
    level_finalize(mv);
}


static void
message_viewer_xml_header(message_viewer *mv, const u8 *buffer)
{
    /* 1. get the output stream */
    output_stream *os = mv->os;


    /* 2. get values of the different sections: QUESTION, ANSWER, AUTHORITY and ADDITIONAL */
    u16 count[4];
    count[0] = ntohs(MESSAGE_QD(buffer));
    count[1] = ntohs(MESSAGE_AN(buffer));
    count[2] = ntohs(MESSAGE_NS(buffer));
    count[3] = ntohs(MESSAGE_AR(buffer));


    /* 3. add the amount of section resource records into a total */
    message_viewer_resource_record_total_update(mv, count);


    /* 4. get message id */
    u16 id = MESSAGE_ID(buffer);


    /* 5. get opcode and rcode.
     *    opcode is needed for for knowing the difference between a regular message and a update message
     */
    u8 opcode = MESSAGE_OP(buffer);
    opcode >>= OPCODE_SHIFT;

    u8 rcode = MESSAGE_RCODE(buffer);

    const char *opcode_txt = dns_message_opcode_get_name(opcode);
    const char *status_txt = dns_message_rcode_get_name(rcode);

    mv->section_name = (opcode != OPCODE_UPDATE) ? message_section_names : message_section_update_names;


    /* if no view with header then inmediately return,
     * xml axfr has no header information so --> return
     */
    if(mv->view_mode_with & MESSAGE_VIEWER_WITH_XFR)
    {
        return;
    }


    /* 6. we have all the information, fill the stream */
    osformat(os, "%s<opcode>%s</opcode>%s", pretty_print_tab, opcode_txt, pretty_print_cr);
    osformat(os, "%s<status>%s</status>%s", pretty_print_tab, status_txt, pretty_print_cr);
    osformat(os, "%s<id format=\"dec\">%hd</id>%s", pretty_print_tab, id, pretty_print_cr);

    osformat(os, "%s<flags>%s", pretty_print_tab, pretty_print_cr);

    /* pretty print output level of tabs +1 */
    level_up(mv);

    if(MESSAGE_QR(buffer) != 0) osformat(os, "%s<flag>qr</flag>%s", pretty_print_tab, pretty_print_cr);
    if(MESSAGE_AA(buffer) != 0) osformat(os, "%s<flag>aa</flag>%s", pretty_print_tab, pretty_print_cr);
    if(MESSAGE_TC(buffer) != 0) osformat(os, "%s<flag>tc</flag>%s", pretty_print_tab, pretty_print_cr);
    if(MESSAGE_RD(buffer) != 0) osformat(os, "%s<flag>rd</flag>%s", pretty_print_tab, pretty_print_cr);
    if(MESSAGE_RA(buffer) != 0) osformat(os, "%s<flag>ra</flag>%s", pretty_print_tab, pretty_print_cr);
    if(MESSAGE_ZF(buffer) != 0) osformat(os, "%s<flag>zf</flag>%s", pretty_print_tab, pretty_print_cr);
    if(MESSAGE_AD(buffer) != 0) osformat(os, "%s<flag>ad</flag>%s", pretty_print_tab, pretty_print_cr);
    if(MESSAGE_CD(buffer) != 0) osformat(os, "%s<flag>cd</flag>%s", pretty_print_tab, pretty_print_cr);

    /* pretty print output level of tabs -1 */
    level_down(mv);

    osformat(os, "%s</flags>%s", pretty_print_tab, pretty_print_cr);
}


static void
message_viewer_xml_section_header(message_viewer *mv, u32 section_idx, u16 count)
{
    if(mv->view_mode_with & MESSAGE_VIEWER_WITH_XFR)
    {
        return;
    }

//    u16 view_mode_with = mv->view_mode_with;
    output_stream *os = mv->os;

    const char *section_name = mv->section_name[section_idx];

    record_name = message_record_names[section_idx];

//    if(message_viewer_requires_section(section_idx, view_mode_with) && count)
    {
        osformat(os, "%s<%s amount=\"%d\">%s", pretty_print_tab, section_name , count, pretty_print_cr);
    }


    /* pretty print output level of tabs +1 */
    level_up(mv);
}


static void
message_viewer_xml_section_footer(message_viewer *mv, u32 section_idx, u16 count)
{
    if(mv->view_mode_with & MESSAGE_VIEWER_WITH_XFR)
    {
        return;
    }

//    u16 view_mode_with = mv->view_mode_with;
    output_stream *os = mv->os;

    const char *section_name = mv->section_name[section_idx];

    /* pretty print output level of tabs -1 */
    level_down(mv);

//    if(message_viewer_requires_section(section_idx, view_mode_with))
    {
        osformat(os, "%s</%s>%s", pretty_print_tab, section_name, pretty_print_cr);
    }
}


static void
message_viewer_xml_question_record(message_viewer *mv, u8 *record_wire, u16 rclass, u16 rtype)
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

    counter_output_stream_data counters;
    output_stream cos;
    counter_output_stream_init(os_, &cos, &counters);

    output_stream *os = &cos;

    /* A. print container begin */
    osformat(os, "%s<%s>%s", pretty_print_tab, record_name, pretty_print_cr);

    /* pretty print output level of tabs +1 */
    level_up(mv);


    /* B. write resource record: FQDN + attribute 'ClASS' and 'TYPE' */
    osformat(os, "%s<name class=\"%{dnsclass}\" type=\"%{dnstype}\">%{dnsname}</name>%s",
             pretty_print_tab, &rclass, &rtype, record_wire, pretty_print_cr);


    /* C. print container end */

    /* pretty print output level of tabs -1 */
    level_down(mv);

    osformat(os, "%s</%s>%s", pretty_print_tab, record_name, pretty_print_cr);


    flushout();
}


static void
message_viewer_xml_section_record(message_viewer *mv, u8 *record_wire, u8 section_idx)
{
    (void)section_idx;

    /*
     * there is no padding support for formats on complex types (padding is ignored)
     * doing it would be relatively expensive for it's best doing it manually when needed (afaik: only here)
     */

    counter_output_stream_data counters;
    output_stream cos;
    output_stream *os_ = mv->os;
    counter_output_stream_init(os_, &cos, &counters);

    output_stream *os = &cos; /* final output stream */

    /*    ------------------------------------------------------------    */


    /* 1. get the needed parameters: FQDN, TYPE, CLASS, TTL, RDATA size */
    u8 *rname = record_wire;
    u8 *rdata = rname + dnsname_len(rname);
    u16 rtype = GET_U16_AT(rdata[0]);
    u16 rclass = GET_U16_AT(rdata[2]);
    u32 rttl = ntohl(GET_U32_AT(rdata[4]));
    u16 rdata_size = ntohs(GET_U16_AT(rdata[8]));

    /** @todo 20150716 gve -- test that rdata_size matches the record size */

    /* move pointer to RDATA information in the record_wire */
    rdata += 10;


    /* 2. write the retrieved info into the stream:
     *    e.g.
     *
     *  <answer>
     *      <name class="IN" type="NS" ttl"86400">somedomain.eu</name>
     *      <rdata length="19">ns1.somedomain.eu.</rdata>
     *  </answer>
     */

    /* A. print container begin */
    osformat(os, "%s<%s>%s", pretty_print_tab, record_name, pretty_print_cr);

    /* pretty print output level of tabs +1 */
    level_up(mv);


    /* B. write resource record: FQDN + attribute 'ClASS', 'TYPE' and 'TTL' */
    osformat(os, "%s<name class=\"%{dnsclass}\" type=\"%{dnstype}\" ttl\"%d\">%{dnsname}</name>%s", pretty_print_tab, &rclass, &rtype, rttl, rname, pretty_print_cr);


    /* C. write RDATA with attribute rdata size */
    //osformat(os, "%s<rdata size=\"%d\">", pretty_print_tab, rdata_size);
    osformat(os, "%s<rdata>", pretty_print_tab);
    osprint_rdata(os, rtype, rdata, rdata_size);
    osformat(os, "</rdata>%s", pretty_print_cr);


    /* D. print container end */

    /* pretty print output level of tabs -1 */
    level_down(mv);

    osformat(os, "%s</%s>%s", pretty_print_tab, record_name, pretty_print_cr);


    flushout();
}


static const message_viewer_vtbl xml_viewer_vtbl = {
        message_viewer_xml_header,
        message_viewer_xml_start,
        message_viewer_xml_end,
        message_viewer_xml_section_header,
        message_viewer_xml_section_footer,
        message_viewer_xml_question_record,
        message_viewer_xml_section_record,
        "message_viewer_xml",
};


/*----------------------------------------------------------------------------*/
#pragma mark FUNCTIONS

void
message_viewer_xml_set(message_viewer *mv)
{
    mv->vtbl = &xml_viewer_vtbl;
}


void
message_viewer_xml_init(message_viewer *mv, output_stream *os, u16 view_mode_with)
{
    message_viewer_init(mv);

    mv->vtbl = &xml_viewer_vtbl;
    mv->os = os;
    mv->view_mode_with = view_mode_with;
}
