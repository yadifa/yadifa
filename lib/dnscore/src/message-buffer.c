/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2023, EURid vzw. All rights reserved.
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

#include "dnscore/dnscore-config.h"
#include "dnscore/packet_reader.h"
#include "dnscore/message.h"
#include "dnscore/message-viewer.h"

ya_result
message_buffer_processor(message_viewer *mv, const u8 *buffer, u16 length)
{
    ya_result                                                  return_value;
    packet_unpack_reader_data                                          purd;
    u8                          record_wire[MAX_DOMAIN_LENGTH + 10 + 65535];
    u16                                                            count[4];

    /*    ------------------------------------------------------------    */

    /* 1. get values of the sections and added them with the totols */
    count[0]           = ntohs(MESSAGE_QD(buffer));
    count[1]           = ntohs(MESSAGE_AN(buffer));
    count[2]           = ntohs(MESSAGE_NS(buffer));
    count[3]           = ntohs(MESSAGE_AR(buffer));

    if(mv->view_mode_with & MESSAGE_VIEWER_WITH_HEADER)
    {
        /* 2. go thru the buffer and do what is needed for output or calculations */
        message_viewer_header(mv, buffer);
    }

    // ;; WARNING: recursion requested but not available

    const u8 *opt_record = NULL;
    const u8 *tsig_record = NULL;

    packet_reader_init_at(&purd, buffer, length, DNS_HEADER_LENGTH);

    for(u32 n = count[0]; n > 0; --n)
    {
        if(FAIL(return_value = packet_reader_skip_zone_record(&purd)))
        {
            return return_value;
        }
    }

    for(u32 section_idx = 1; section_idx < 4; section_idx++)
    {
        for(u16 n = count[section_idx]; n > 0; n--)
        {
            // Get next record and put the packet reader offset on the next record

            // note: packet_reader_read_record unpacks the name

            if(FAIL(return_value = packet_reader_read_record(&purd, record_wire, sizeof(record_wire))))
            {
                return return_value;
            }

            if(section_idx == 3)
            {
                s32 len = dnsname_len_checked_with_size(record_wire, sizeof(record_wire));

                if(FAIL(len))
                {
                    return len;
                }

                if(return_value - len < 10) // type class ttl rdata_size
                {
                    return MAKE_RCODE_ERROR(FP_RCODE_FORMERR);
                }

                const u8 *p = record_wire + len;

                u16 record_type = GET_U16_AT_P(p);
                if(record_type == TYPE_OPT)
                {
                    opt_record = record_wire;
                    --count[3];
                    message_viewer_pseudosection_record(mv, record_wire);
                }
                else if(record_type == TYPE_TSIG)
                {
                    tsig_record = record_wire;
                    --count[3];
                }
            }
        }
    }

    /* SECTION QUESTION */
    u32 section_idx    = 0;

    bool show_question_section = message_viewer_requires_section(0, mv->view_mode_with);

    if(show_question_section)
    {
        /* Print SECTION name */
        message_viewer_section_header(mv, section_idx, count[section_idx]);
    }

    /* init packet reader with buffer. length and offset in the buffer */

    packet_reader_init_at(&purd, buffer, length, DNS_HEADER_LENGTH);

    for(u16 n = count[section_idx]; n > 0; n--)
    {
        /* 1. GET EVERYTHING FROM THE BUFFER FOR QUESTION + OFFSET packet reader */

        if(FAIL(return_value = packet_reader_read_zone_record(&purd, record_wire, sizeof(record_wire))))
        {
            return return_value;
        }

        s32 len = dnsname_len_checked_with_size(record_wire, sizeof(record_wire));

        if(FAIL(len))
        {
            return len;
        }

        if(return_value - len != 4)
        {
            return MAKE_RCODE_ERROR(FP_RCODE_FORMERR);
        }

        const u8 *p = record_wire + len;

        /* Retrieve QTYPE from packet reader */
        u16 rtype = GET_U16_AT_P(p);
        p += 2;
        /* Retrieve QCLASS from packet reader */
        u16 rclass = GET_U16_AT_P(p);;
        //p += 2;

        if(show_question_section)
        {
            /* Print everything from QUESTION SECTION */
            message_viewer_question_record(mv, record_wire, rclass, rtype);
        }
    }

    if(show_question_section)
    {
        message_viewer_section_footer(mv, section_idx, count[section_idx]);
    }

    /* SECTIONS WITHOUT QUESTION */
    for(u32 section_idx = 1; section_idx < 4; section_idx++)
    {
        bool show_section = message_viewer_requires_section(section_idx, mv->view_mode_with) && (count[section_idx] > 0);
        bool print_footer = show_section;

        if(show_section)
        {
            message_viewer_section_header(mv, section_idx, count[section_idx]);
        }

        for(u16 n = count[section_idx]; n > 0; n--)
        {
            // Get next record and put the packet reader offset on the next record

            // note: packet_reader_read_record unpacks the name

            if(FAIL(return_value = packet_reader_read_record(&purd, record_wire, sizeof(record_wire))))
            {
                return return_value;
            }

            if(show_section)
            {
                /* Initialize the values needed for printing */
                message_viewer_section_record(mv, record_wire, section_idx);
            }
        }

        if(print_footer)
        {
            message_viewer_section_footer(mv, section_idx, count[section_idx]);
        }
    }

    if(opt_record)
    {
        --count[3];
        if(FAIL(return_value = packet_reader_read_record(&purd, record_wire, sizeof(record_wire))))
        {
            return return_value;
        }
    }

    if(tsig_record)
    {
        --count[3];
        if(FAIL(return_value = packet_reader_read_record(&purd, record_wire, sizeof(record_wire))))
        {
            return return_value;
        }
        message_viewer_pseudosection_record(mv, record_wire);
    }

    // here handle extraneous bytes

    return 0;
}

