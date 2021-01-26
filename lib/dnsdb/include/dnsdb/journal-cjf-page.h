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
 * Search from the offset of the stream for a serial, looking in an PAGE referenced by index
 * 
 * @param jnl
 * @param idx
 * @param serial
 * @param out_offset
 * @return 
 */

ya_result journal_cjf_page_get_stream_offset_from_serial(journal_cjf *jnl, int idx, u32 serial, u32 *out_offset);


/**
 * 
 * Returns true iff the current PAGE table is full
 * 
 * @param jnl
 * @return 
 */

bool journal_cjf_page_is_full(journal_cjf *jnl);

/**
 * 
 * Returns the file offset value at index in the current PAGE
 * 
 * @param jnl
 * @param index
 * @return 
 */

u32 journal_cjf_page_get_file_offset(journal_cjf *jnl);

u32 journal_cjf_page_get_stream_file_offset(journal_cjf *jnl);

/**
 * 
 * Returns the last serial number value at index in the PAGE
 * 
 * @param jnl
 * @param index
 * @return 
 */

u32 journal_cjf_page_get_last_serial(journal_cjf *jnl, s16 index);


bool journal_cjf_page_is_full(journal_cjf *jnl);

bool journal_cjf_page_line_count(journal_cjf *jnl);

/**
 * 
 * Returns the file offset value at index in the current PAGE
 * 
 * @param jnl
 * @param index
 * @return 
 */

u32 journal_cjf_page_get_file_offset(journal_cjf *jnl);


/**
 * 
 * Returns the last serial number value at index in the PAGE
 * 
 * @param jnl
 * @param index
 * @return 
 */

u32 journal_cjf_page_get_last_serial(journal_cjf *jnl, s16 index);

/**
 * Returns true if it's technically possible to overwrite the last page from our position
 * 
 * @param jnl
 * @return 
 */

static inline bool journal_cjf_page_current_output_stream_may_overwrite(journal_cjf *jnl)
{
    return (jnl->first_page_offset > jnl->last_page.file_offset);
}
