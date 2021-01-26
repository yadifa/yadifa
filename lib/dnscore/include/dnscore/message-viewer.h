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

#pragma once

#include <dnscore/sys_types.h>
#include <dnscore/output_stream.h>
#include <dnscore/host_address.h>

#define     MESSAGE_VIEWER_WITH_QUESTION                    0x01
#define     MESSAGE_VIEWER_WITH_ANSWER                      0x02
#define     MESSAGE_VIEWER_WITH_AUTHORITY                   0x04
#define     MESSAGE_VIEWER_WITH_ADDITIONAL                  0x08
#define     MESSAGE_VIEWER_WITH_HEADER                      0x10
#define     MESSAGE_VIEWER_WITH_XFR                         0x20

#define     MESSAGE_VIEWER_SIMPLE_QUERY (MESSAGE_VIEWER_WITH_HEADER|MESSAGE_VIEWER_WITH_QUESTION|MESSAGE_VIEWER_WITH_ANSWER|MESSAGE_VIEWER_WITH_AUTHORITY|MESSAGE_VIEWER_WITH_ADDITIONAL)
#define     MESSAGE_VIEWER_XFR_QUERY (MESSAGE_VIEWER_WITH_HEADER|MESSAGE_VIEWER_WITH_QUESTION|MESSAGE_VIEWER_WITH_ANSWER|MESSAGE_VIEWER_WITH_XFR)

typedef struct message_viewer message_viewer;

typedef void message_viewer_header_method(message_viewer *mv, const u8 *buffer);
typedef void message_viewer_start_method(message_viewer *mv);
typedef void message_viewer_end_method(message_viewer *mv, long time_duration);

typedef void message_viewer_section_header_method(message_viewer *mv, u32 section_idx, u16 count);
typedef void message_viewer_section_footer_method(message_viewer *mv, u32 section_idx, u16 count);

typedef void message_viewer_question_record_method(message_viewer *mv, u8 *record_wire, u16 rclass, u16 rtype);
typedef void message_viewer_section_record_method(message_viewer *mv, u8 *record_wire, u8 sectionidx);

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

    const char    *__class__;           /* MUST BE A UNIQUE POINTER, ie: One defined in the class's .c file
                                           The name should be unique in order to avoid compiler tricks
                                         */

    /* Add your inheritable methods here */
};


struct message_viewer
{
    u64                             bytes;
    u32                          messages;
    u32         resource_records_total[4];

    void                            *data;
    output_stream                     *os;
    const message_viewer_vtbl       *vtbl;

    char                   **section_name;
    host_address                    *host; // if set, will be used to count the servers found and in some messages. (default is NULL)

    u16                    view_mode_with;
};


#define message_viewer_class(mv_) ((mv_)->vtbl)
#define message_viewer_class_name(mv_) ((mv_)->vtbl->__class__)

#define message_viewer_header(mv_,buffer_) (mv_)->vtbl->three((mv_),(const u8*)(buffer_))
#define message_viewer_start(mv_) (mv_)->vtbl->four(mv_)
#define message_viewer_end(mv_,time_duration_) (mv_)->vtbl->five((mv_),(time_duration_))

#define message_viewer_section_header(mv_,section_idx_,count_) (mv_)->vtbl->six((mv_),(section_idx_),(count_))
#define message_viewer_section_footer(mv_,section_idx_,count_) (mv_)->vtbl->seven((mv_),(section_idx_),(count_))

#define message_viewer_question_record(mv_,record_wire_,rclass_,rtype_) (mv_)->vtbl->eight((mv_),(record_wire_),(rclass_),(rtype_))
#define message_viewer_section_record(mv_,record_wire_,sectionidx_) (mv_)->vtbl->nine((mv_),(record_wire_),(sectionidx_))

#define message_viewer_bytes_and_message_update(mv_,bytes_, messages_) {(mv_)->bytes+=(bytes_);(mv_)->messages+=(messages_);};
#define message_viewer_resource_record_total_update(mv_,count_) {     \
                          mv->resource_records_total[0]+=count_[0];   \
                          mv->resource_records_total[1]+=count_[1];   \
                          mv->resource_records_total[2]+=count_[2];   \
                          mv->resource_records_total[3]+=count_[3];};

bool message_viewer_requires_section(int section, int view_with_mode);
void message_viewer_set_default(message_viewer *mv);
void message_viewer_init(message_viewer *mv);
