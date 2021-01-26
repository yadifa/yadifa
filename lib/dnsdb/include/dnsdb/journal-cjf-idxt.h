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

#include <dnsdb/journal-cjf-page.h>

void journal_cjf_idxt_flush(journal_cjf *jnl);

const journal_cjf_idxt_tbl_item *journal_cjf_idxt_get_entry(const journal_cjf *jnl, s16 index);

/**
 * 
 * Returns the last serial number value at index in the IDXT
 * 
 * @param jnl
 * @param index
 * @return 
 */

u32 journal_cjf_idxt_get_last_serial(const journal_cjf *jnl, s16 index);

/**
 * 
 * Returns the file offset value at index in the current IDXT
 * 
 * @param jnl
 * @param index
 * @return 
 */

u32 journal_cjf_idxt_get_file_offset(const journal_cjf *jnl, s16 index);

/**
 * Appends an PAGE after this one
 * 
 * @param jnl
 */

void journal_cjf_idxt_append_page(journal_cjf *jnl);

/**
 * Updates the value of the last serial at current position in the PAGE
 * 
 * @param jnl
 * @param last_serial
 */

void journal_cjf_idxt_update_last_serial(journal_cjf *jnl, u32 last_serial);

/**
 * 
 * Flushes the IDXT to disk if needed, then destroys the structure content.
 * 
 * @param jnl
 */

void journal_cjf_idxt_destroy(journal_cjf *jnl);

/**
 * Creates an empty table of indexes (IDXT) for the journal, with a minimum number of entries.
 * Nothing is written to disk.
 * 
 * @param jnl
 * @param entries
 */

void journal_cjf_idxt_create(journal_cjf *jnl, s16 entries);

/**
 * Loads (or rebuilds) the table of indexes (IDXT)
 * 
 * @param jnl
 */

void journal_cjf_idxt_load(journal_cjf *jnl);

u32 journal_cjf_idxt_get_last_file_offset(const journal_cjf *jnl);

u32 journal_cjf_idxt_get_page_serial_from_index(const journal_cjf *jnl, int idx);

ya_result journal_cjf_idxt_get_page_offset_from_serial(const journal_cjf *jnl, u32 serial, u32 *file_offset);

ya_result journal_cjf_idxt_get_page_index_from_serial(const journal_cjf *jnl, u32 serial);

ya_result journal_cjf_idxt_get_page_serial_to(const journal_cjf *jnl, int idx);

u32 journal_cjf_idxt_get_page_offset(const journal_cjf *jnl, int idx);

static inline u32 journal_cjf_idxt_get_page_count(journal_cjf *jnl)
{
    return jnl->idxt.count;
}
