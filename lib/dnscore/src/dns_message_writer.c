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
#include <dnscore/dns_message_writer.h>

static uint8_t message_viewer_requires_section_with_view_with_mode[4] = {DNS_MESSAGE_WRITER_WITH_QUESTION, DNS_MESSAGE_WRITER_WITH_ANSWER, DNS_MESSAGE_WRITER_WITH_AUTHORITY, DNS_MESSAGE_WRITER_WITH_ADDITIONAL};

bool           message_viewer_requires_section(int section, int view_with_mode)
{
    if((section >= 0) && (section <= 3))
    {
        return (message_viewer_requires_section_with_view_with_mode[section] & view_with_mode) != 0;
    }

    return false;
}
#if 0
static void
message_viewer_default_three(message_viewer *view, const uint8_t *buffer)
{
    printf("three!\n");
}

static void
message_viewer_default_four(message_viewer *view)
{
    printf("four!\n");
}


static void
message_viewer_default_five(message_viewer *viewer, long time_duration)
{
    printf("five!\n");
}


static void
message_viewer_default_six(message_viewer *viewer, uint32_t section_idx, uint16_t count)
{
    printf("six!\n");
}


static void
message_viewer_default_seven(message_viewer *viewer, uint32_t section_idx, uint16_t count)
{
    printf("seven!\n");
}


static void
message_viewer_default_eight(message_viewer *viewer, const uint8_t *record_wire, uint16_t rclass, uint16_t rtype)
{
    printf("eight!\n");
}


static void
message_viewer_default_nine(message_viewer *viewer, const uint8_t *record_wire, uint8_t view_mode_with)
{
    printf("nine!\n");
}

static ya_result message_viewer_default_pseudosection_record(message_viewer *mv, const uint8_t *record_wire)
{
    (void)mv;
    (void)record_wire;
    return 0;
}

static const message_viewer_vtbl default_viewer_vtbl = {
       message_viewer_default_three,
       message_viewer_default_four,
       message_viewer_default_five,
       message_viewer_default_six,
       message_viewer_default_seven,
       message_viewer_default_eight,
       message_viewer_default_nine,
       message_viewer_default_pseudosection_record,
       "message_viewer_default",
};

void
message_viewer_set_default(message_viewer *view)
{
    view->data = NULL;
    view->vtbl = &default_viewer_vtbl;
}

void
message_viewer_init(message_viewer *view)
{

    view->bytes                     = 0;
    view->data                      = NULL;
    view->messages                  = 0;
    view->os                        = NULL;
    view->resource_records_total[0] = 0;
    view->resource_records_total[1] = 0;
    view->resource_records_total[2] = 0;
    view->resource_records_total[3] = 0;
    view->view_mode_with            = 0;
    view->host = NULL;

    view->vtbl                      = &default_viewer_vtbl;
}
#endif
