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

#include <dnsdb/journal-cjf-common.h>

/**
 * Prepares a stream for the next chunk (-SOA ... +SOA ...)
 * 
 * @note before being closed, this stream MUST be either 'next'ed or 'cancel'ed
 */

void journal_cjf_page_output_stream_next(output_stream *stream);

/**
 * Cancels a stream's currentchunk (-SOA ... +SOA ...)
 * 
 * @note before being closed, this stream MUST be either 'next'ed or 'cancel'ed
 */

void journal_cjf_page_output_stream_cancel(output_stream *stream);

void journal_cjf_page_output_stream_set_serial_from(output_stream *stream, u32 serial);
void journal_cjf_page_output_stream_set_serial_to(output_stream *stream, u32 serial);
void journal_cjf_page_output_stream_set_soa_to_offset(output_stream *stream, u32 offset);
ya_result journal_cfj_page_output_stream_write_resource_record(output_stream *stream, dns_resource_record *rr);
/**
 * 
 * stream MUST be initalised with output_stream_set_void(stream) before first call
 * 
 * @param stream
 * @param jnl
 * @return 
 */
u32 journal_cjf_page_output_stream_reopen(output_stream *stream, journal_cjf *jnl);

u32 journal_cfj_page_output_stream_get_size(output_stream *stream);

u32 journal_cfj_page_output_stream_get_start_offset(output_stream *stream);

u32 journal_cfj_page_output_stream_get_current_offset(output_stream *stream);
