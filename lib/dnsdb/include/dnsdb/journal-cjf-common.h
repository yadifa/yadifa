/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2016, EURid. All rights reserved.
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

#define ZDB_JOURNAL_CODE 1
#define JOURNAL_CJF 1

#include <dnscore/output_stream.h>
#include "dnsdb/journal.h"

#ifdef CJF_HEADER_SIZE
#error "CJF_HEADER_SIZE already defined"
#endif

#define CJF_HEADER_SIZE 30

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

struct jnl_page
{
    u32 file_offset;    // position in the file
    u32 count;          // number of updates
    u32 size;           // size is fixed to CJF_SECTION_INDEX_SLOT_COUNT
    u32 serial_start;   // first serial in this section. Could probably be lost if not for debugging
    u32 serial_end;     // last serial in this section
    u32 records_limit;    // starts at file_offset (position of the PAGE in the file) + 4KB
    u32 file_offset_limit;   // if the section is about to break this limit, something has to be done. ie:
                        // _ resynchronise serials in the file
                        // _ write the zone to disk
};

typedef struct jnl_page jnl_page;

struct journal_cjf;

struct journal_cjf_idxt_tbl_header
{
    u32 magic;
    u16 size;
};

typedef struct journal_cjf_idxt_tbl_header journal_cjf_idxt_tbl_header;


struct journal_cjf_idxt_tbl_item
{
    u32 last_serial;    // last serial for this item
    u32 file_offset;    // position of the item
};

typedef struct journal_cjf_idxt_tbl_item journal_cjf_idxt_tbl_item;

struct journal_cjf_idxt
{
    s16 count;
    s16 first;
    s16 size;
    bool dirty;
    bool marked;
    journal_cjf_idxt_tbl_item *entries;
};

typedef struct journal_cjf_idxt journal_cjf_idxt;

#define CJF_IDXT_MAGIC MAGIC4('I','D','X','T')

#define JOURNAL_CFJ_FLAGS_OTHER_ENDIAN  0x8000
#define JOURNAL_CFJ_FLAGS_MY_ENDIAN     0x0080
#define JOURNAL_CFJ_FLAGS_NOT_EMPTY     0x0001
#define JOURNAL_CFJ_FLAGS_DIRTY         0x0002

struct journal_cjf
{
    /* common points with journal base */
    volatile struct journal_vtbl *vtbl;
    volatile zdb_zone            *zone;    
    volatile struct journal      *next;
    volatile struct journal      *prev;
    volatile bool                  mru;
    
    /* ******************************* */

    journal_cjf_idxt              idxt;
    jnl_page                 last_page;
    
    u32                   serial_begin;
    u32                     serial_end;
    
    u32              first_page_offset;
    u32         page_table_file_offset;
    
    u32                last_soa_offset;
    u32              file_maximum_size;
    
    int                             fd;
    
    shared_group_mutex_t           mtx;
    
    u16                          flags;
        
    char            *journal_file_name;
};

typedef struct journal_cjf journal_cjf;

void log_debug_jnl(journal_cjf *jnl, const char *prefix);
void jnl_header_flush(journal_cjf *jnl);
void journal_cjf_remove_first_page(journal_cjf *jnl);

static inline u32 journal_cjf_get_last_page_offset_limit(journal_cjf *jnl)
{
    return jnl->last_page.file_offset_limit;
}

static inline u32 journal_cjf_get_last_page_first_available_byte_offset(journal_cjf *jnl)
{
    return jnl->last_page.records_limit;
}

static inline u32 journal_cjf_get_last_page_has_room_left(journal_cjf *jnl)
{
    return jnl->last_page.file_offset_limit >= jnl->last_page.records_limit;
}

static inline s64 journal_cjf_get_last_page_available_space_left(journal_cjf *jnl)
{
    s64 to = (s64)jnl->last_page.file_offset_limit;
    s64 from = (s64)jnl->last_page.records_limit;
    s64 ret = MAX(to - from, 0);
    return ret;
}

bool jnl_ensure_file_opened(journal_cjf *jnl, bool create);

static inline u32 journal_cjf_maximum_size(journal_cjf *jnl)
{
    return jnl->file_maximum_size;
}

static inline bool journal_cjf_has_flag(journal_cjf *jnl, u16 bits)
{
    return (jnl->flags & bits) == bits;
}

static inline void journal_cjf_set_flag(journal_cjf *jnl, u16 bits)
{
    jnl->flags |= bits;
}

static inline void journal_cjf_clear_flag(journal_cjf *jnl, u16 bits)
{
    jnl->flags &= ~bits;
}

static inline void journal_cjf_set_dirty(journal_cjf *jnl)
{
    journal_cjf_set_flag(jnl, JOURNAL_CFJ_FLAGS_DIRTY);
}

static inline bool journal_cjf_is_dirty(journal_cjf *jnl)
{
    bool ret = journal_cjf_has_flag(jnl, JOURNAL_CFJ_FLAGS_DIRTY);
    return ret;
}

static inline void journal_cjf_clear_dirty(journal_cjf *jnl)
{
    journal_cjf_clear_flag(jnl, JOURNAL_CFJ_FLAGS_DIRTY);
}

static inline void journal_cjf_set_empty(journal_cjf *jnl)
{
    journal_cjf_clear_flag(jnl, JOURNAL_CFJ_FLAGS_NOT_EMPTY);
}

static inline void journal_cjf_clear_empty(journal_cjf *jnl)
{
    journal_cjf_set_flag(jnl, JOURNAL_CFJ_FLAGS_NOT_EMPTY);
}

static inline bool journal_cjf_is_empty(journal_cjf *jnl)
{
    bool ret = !journal_cjf_has_flag(jnl, JOURNAL_CFJ_FLAGS_NOT_EMPTY);
    return ret;
}

static inline bool journal_cjf_is_my_endian(journal_cjf *jnl)
{
    bool ret = journal_cjf_has_flag(jnl, JOURNAL_CFJ_FLAGS_MY_ENDIAN);
    return ret;
}

