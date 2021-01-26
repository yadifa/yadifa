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

    /* SECTION QUESTION */
    u32 section_idx    = 0;

    if(message_viewer_requires_section(section_idx, mv->view_mode_with))
    {
        /* Print SECTION name */
        message_viewer_section_header(mv, section_idx, count[section_idx]);
    }

    /* init packet reader with buffer. length and offset in the buffer */
    purd.packet        = buffer;
    purd.packet_size   = length;
    purd.offset        = DNS_HEADER_LENGTH;

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

        if(message_viewer_requires_section(section_idx, mv->view_mode_with))
        {
            /* Print everything from QUESTION SECTION */
            message_viewer_question_record(mv, record_wire, rclass, rtype);
        }
    }

    if(message_viewer_requires_section(section_idx, mv->view_mode_with))
    {
        message_viewer_section_footer(mv, section_idx, count[section_idx]);
    }


    /* SECTIONS WITHOUT QUESTION */
    for(u32 section_idx = 1; section_idx < 4; section_idx++)
    {
        if(message_viewer_requires_section(section_idx, mv->view_mode_with))
        {
            message_viewer_section_header (mv, section_idx, count[section_idx]);
        }

        for(u16 n = count[section_idx]; n > 0; n--)
        {
            /* Get next record and put the packet reader offset on the next record */
            if(FAIL(return_value = packet_reader_read_record(&purd, record_wire, sizeof(record_wire))))
            {
                return return_value;
            }

            if(message_viewer_requires_section(section_idx, mv->view_mode_with))
            {
                /* Initialize the values needed for printing */
                message_viewer_section_record(mv, record_wire, section_idx);
            }
        }

        if(message_viewer_requires_section(section_idx, mv->view_mode_with))
        {
            message_viewer_section_footer(mv, section_idx, count[section_idx]);
        }
    }

    return 0;
}

