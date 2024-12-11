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

#pragma once

#include <dnscore/sys_types.h>
#include <dnscore/output_stream.h>
#include <dnscore/host_address.h>
#include "dns_message.h"

#define DNS_MESSAGE_WRITER_WITH_QUESTION     0x0001
#define DNS_MESSAGE_WRITER_WITH_ANSWER       0x0002
#define DNS_MESSAGE_WRITER_WITH_AUTHORITY    0x0004
#define DNS_MESSAGE_WRITER_WITH_ADDITIONAL   0x0008
#define DNS_MESSAGE_WRITER_WITH_HEADER       0x0010
#define DNS_MESSAGE_WRITER_WITH_XFR          0x0020
#define DNS_MESSAGE_WRITER_WITH_TSIG         0x0040
#define DNS_MESSAGE_WRITER_WITH_OPT          0x0080
#define DNS_MESSAGE_WRITER_WITH_TIME         0x0100
#define DNS_MESSAGE_WRITER_WITH_DURATION     0x0200
#define DNS_MESSAGE_WRITER_WITH_SERVER       0x0400
#define DNS_MESSAGE_WRITER_WITH_SERVER_COUNT 0x0800

#define DNS_MESSAGE_WRITER_PROTOCOL_UDP      0
#define DNS_MESSAGE_WRITER_PROTOCOL_TCP      1

#define DNS_MESSAGE_WRITER_SIMPLE_QUERY      (DNS_MESSAGE_WRITER_WITH_HEADER | DNS_MESSAGE_WRITER_WITH_QUESTION | DNS_MESSAGE_WRITER_WITH_ANSWER | DNS_MESSAGE_WRITER_WITH_AUTHORITY | DNS_MESSAGE_WRITER_WITH_ADDITIONAL)
#define DNS_MESSAGE_WRITER_XFR_QUERY         (DNS_MESSAGE_WRITER_WITH_HEADER | DNS_MESSAGE_WRITER_WITH_QUESTION | DNS_MESSAGE_WRITER_WITH_ANSWER | DNS_MESSAGE_WRITER_WITH_XFR)

bool message_viewer_requires_section(int section, int view_with_mode);

#if 0
typedef struct message_viewer message_viewer;

typedef void message_viewer_header_method(message_viewer *mv, const uint8_t *buffer);
typedef void message_viewer_start_method(message_viewer *mv);
typedef void message_viewer_end_method(message_viewer *mv, long time_duration);

typedef void message_viewer_section_header_method(message_viewer *mv, uint32_t section_idx, uint16_t count);
typedef void message_viewer_section_footer_method(message_viewer *mv, uint32_t section_idx, uint16_t count);

typedef void message_viewer_question_record_method(message_viewer *mv, const uint8_t *record_wire, uint16_t rclass, uint16_t rtype);
typedef void message_viewer_section_record_method(message_viewer *mv, const uint8_t *record_wire, uint8_t sectionidx);

typedef ya_result message_viewer_pseudosection_record_method(message_viewer *mv, const uint8_t *record_wire);

typedef struct message_viewer_vtbl message_viewer_vtbl;

struct message_viewer_vtbl
{
    message_viewer_header_method           *three;
    message_viewer_start_method             *four;
    message_viewer_end_method               *five;
    message_viewer_section_header_method     *six;
    message_viewer_section_footer_method   *seven;
    message_viewer_question_record_method  *eight;
    message_viewer_section_record_method    *nine;

    message_viewer_pseudosection_record_method *print_pseudosection_record;

    const char    *__class__;           /* MUST BE A UNIQUE POINTER, ie: One defined in the class's .c file
                                           The name should be unique in order to avoid compiler tricks
                                         */

    /* Add your inheritable methods here */
};

struct message_viewer
{
    uint64_t                             bytes;
    uint32_t                          messages;
    uint32_t         resource_records_total[4];

    void                            *data;
    output_stream_t                     *os;
    const message_viewer_vtbl       *vtbl;

    char                   **section_name;
    const host_address_t              *host; // if set, will be used to count the servers found and in some messages. (default is NULL)

    uint16_t                    view_mode_with;
};
#endif

struct dns_message_writer_s;

struct dns_message_writer_message_s
{
    const void           *buffer;
    uint32_t              length;
    int32_t               time_duration_ms;
    time_t                when;
    const host_address_t *server;
    uint8_t               protocol;
};

typedef struct dns_message_writer_message_s dns_message_writer_message_t;

typedef ya_result                           dns_message_writer_method(const struct dns_message_writer_s *dmw, const dns_message_writer_message_t *);

struct dns_message_writer_s
{
    output_stream_t           *os;
    dns_message_writer_method *writer;
    uint32_t                   flags; // DNS_MESSAGE_WRITER_WITH_*
};

typedef struct dns_message_writer_s dns_message_writer_t;

static inline void                  dns_message_writer_message_init_with_dns_message(dns_message_writer_message_t *msg, dns_message_t *mesg)
{
    msg->buffer = dns_message_get_buffer_const(mesg);
    msg->length = dns_message_get_size(mesg);
    msg->time_duration_ms = 0;
    msg->when = time(NULL);
    msg->server = NULL;
    msg->protocol = 0;
}

ya_result          dns_message_writer_dig(const dns_message_writer_t *dmw, const dns_message_writer_message_t *msg);
ya_result          dns_message_writer_json(const dns_message_writer_t *dmw, const dns_message_writer_message_t *msg);
ya_result          dns_message_writer_easyparse(const dns_message_writer_t *dmw, const dns_message_writer_message_t *msg);

static inline void dns_message_writer_init(dns_message_writer_t *dmw, output_stream_t *os, dns_message_writer_method *method, uint32_t flags)
{
    dmw->os = os;
    dmw->writer = method;
    dmw->flags = flags;
}

static inline ya_result dns_message_writer_write(const dns_message_writer_t *dmw, const dns_message_writer_message_t *writer_message)
{
    ya_result ret = dmw->writer(dmw, writer_message);
    return ret;
}

/**
 * Wrapper of dns_message_writer for the old API
 */
ya_result dns_message_print_format_dig(output_stream_t *os, const uint8_t *buffer, uint32_t length, uint32_t flags, int32_t time_duration_ms);
ya_result dns_message_print_format_json(output_stream_t *os, const uint8_t *buffer, uint32_t length, uint32_t flags, int32_t time_duration_ms);
ya_result dns_message_print_format_easyparse(output_stream_t *os, const uint8_t *buffer, uint32_t length, uint32_t flags, int32_t time_duration_ms);

#if 0
#define message_viewer_class(mv_)                                          ((mv_)->vtbl)
#define message_viewer_class_name(mv_)                                     ((mv_)->vtbl->__class__)

#define message_viewer_header(mv_, buffer_)                                (mv_)->vtbl->three((mv_), (const uint8_t *)(buffer_))
#define message_viewer_start(mv_)                                          (mv_)->vtbl->four(mv_)
#define message_viewer_end(mv_, time_duration_)                            (mv_)->vtbl->five((mv_), (time_duration_))

#define message_viewer_section_header(mv_, section_idx_, count_)           (mv_)->vtbl->six((mv_), (section_idx_), (count_))
#define message_viewer_section_footer(mv_, section_idx_, count_)           (mv_)->vtbl->seven((mv_), (section_idx_), (count_))

#define message_viewer_question_record(mv_, record_wire_, rclass_, rtype_) (mv_)->vtbl->eight((mv_), (record_wire_), (rclass_), (rtype_))
#define message_viewer_section_record(mv_, record_wire_, sectionidx_)      (mv_)->vtbl->nine((mv_), (record_wire_), (sectionidx_))

#define message_viewer_pseudosection_record(mv_, record_wire_)             (mv_)->vtbl->print_pseudosection_record((mv_), (record_wire_))

#define message_viewer_bytes_and_message_update(mv_, bytes_, messages_)                                                                                                                                                                        \
    {                                                                                                                                                                                                                                          \
        (mv_)->bytes += (bytes_);                                                                                                                                                                                                              \
        (mv_)->messages += (messages_);                                                                                                                                                                                                        \
    };

#define message_viewer_resource_record_total_update(mv_, count_)                                                                                                                                                                               \
    {                                                                                                                                                                                                                                          \
        mv->resource_records_total[0] += count_[0];                                                                                                                                                                                            \
        mv->resource_records_total[1] += count_[1];                                                                                                                                                                                            \
        mv->resource_records_total[2] += count_[2];                                                                                                                                                                                            \
        mv->resource_records_total[3] += count_[3];                                                                                                                                                                                            \
    };

bool message_viewer_requires_section(int section, int view_with_mode);
void message_viewer_set_default(message_viewer *mv);
void message_viewer_init(message_viewer *mv);
#endif
