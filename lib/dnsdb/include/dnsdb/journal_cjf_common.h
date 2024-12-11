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

#define ZDB_JOURNAL_CODE 1
#define JOURNAL_CJF      1

#include <dnscore/output_stream.h>
#include <dnscore/serial.h>
#include <dnscore/logger.h>
#include <dnsdb/journal.h>
#include <dnsdb/zdb_zone_path_provider.h>

#ifdef CJF_HEADER_SIZE
#error "CJF_HEADER_SIZE already defined"
#endif

#include <dnscore/file_pool.h>

/*
 *  MAGIC 'JCS' 0
 *  offset to next (0 until the section is closed and followed by a new one)
 *  list of last-serial + file_offset
 */

#define CJF_IDXT_MAGIC                  MAGIC4('I', 'D', 'X', 'T')

#define JOURNAL_CFJ_FLAGS_OTHER_ENDIAN  0x8000 // journal endian is different
#define JOURNAL_CFJ_FLAGS_MY_ENDIAN     0x0080 // journal endian is the same
#define JOURNAL_CFJ_FLAGS_NOT_EMPTY     0x0001 // journal contains pages
#define JOURNAL_CFJ_FLAGS_DIRTY         0x0002 // journal needs flushing
#define JOURNAL_CFJ_FLAGS_UNINITIALISED 0x0004

struct cjf_header // Cyclic Journal File
{
    uint32_t magic_plus_version;
    uint32_t serial_begin;
    uint32_t serial_end;
    uint32_t first_index_offset; // PAGE
    uint32_t table_index_offset; // IDXT
    //
    uint32_t last_soa_offset;       // record
    uint32_t last_page_offset_next; // the byte after the last PAGE on the chain ends
    uint16_t flags;
    uint8_t  __end_of_struct__;
};

typedef struct cjf_header cjf_header;

#define CJF_HEADER_REAL_SIZE offsetof(cjf_header, __end_of_struct__)
/*
#if CJF_HEADER_SIZE != CJF_HEADER_REAL_SIZE
#error "CJF_HEADER_SIZE != CJF_HEADER_REAL_SIZE"
#endif
*/

/*
 * PAGE
 *
 * Serial Number Stream Offset
 *
 * The table of serials streams (IXFR) and their offset
 * The value stored is of the serial ending the IXFR
 */

#define CJF_CJF0_MAGIC       MAGIC4('C', 'J', 'F', 0x20) // ver 2.0

#define CJF_HEADER_SIZE      30

#ifndef MODULE_MSG_HANDLE
extern logger_handle_t *g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger
#endif

struct jnl_page
{
    uint32_t file_offset;       // position in the file
    uint32_t count;             // number of updates
    uint32_t size;              // size is fixed to CJF_SECTION_INDEX_SLOT_COUNT
    uint32_t serial_start;      // first serial in this section. Could probably be lost if not for debugging
    uint32_t serial_end;        // last serial in this section
    uint32_t records_limit;     // starts at file_offset (position of the PAGE in the file) + CJF_SECTION_INDEX_SLOT_COUNT *
                                // 8 (4KB)
    uint32_t file_offset_limit; // if the section is about to break this limit, something has to be done. ie:
                                // _ resynchronise serials in the file
                                // _ write the zone to disk
};

typedef struct jnl_page jnl_page;

struct journal_cjf;

struct journal_cjf_idxt_tbl_header
{
    uint32_t magic;
    uint16_t size;
};

typedef struct journal_cjf_idxt_tbl_header journal_cjf_idxt_tbl_header;

#define JCJFITI_TAG 0x495449464a434a

struct journal_cjf_idxt_tbl_item
{
    uint32_t last_serial;
    uint32_t file_offset;
};

typedef struct journal_cjf_idxt_tbl_item journal_cjf_idxt_tbl_item;

struct journal_cjf_idxt
{
    int16_t                    count;
    int16_t                    first;
    int16_t                    size;
    bool                       dirty;
    bool                       marked;
    journal_cjf_idxt_tbl_item *entries;
};

typedef struct journal_cjf_idxt journal_cjf_idxt;

struct journal_cjf
{
    /* common points with journal base */
    volatile struct journal_vtbl *vtbl;
    volatile list_dl_node_t       mru_node;
    atomic_int                    rc;
    volatile unsigned int         _forget : 1, _mru : 1;

    /* ******************************* */

    journal_cjf_idxt     idxt;
    jnl_page             last_page; // current page

    uint32_t             serial_begin;
    uint32_t             serial_end;

    uint32_t             first_page_offset;
    uint32_t             page_table_file_offset;

    uint32_t             last_soa_offset;
    uint32_t             file_maximum_size;

    file_pool_file_t     file;

    shared_group_mutex_t mtx;

    uint16_t             flags;
    uint8_t             *origin; // to not rely on zone
    char                *journal_file_name;
};

typedef struct journal_cjf journal_cjf;

void                       log_debug_jnl(journal_cjf *jnl, const char *prefix);
void                       journal_cjf_header_flush(journal_cjf *jnl);
void                       journal_cjf_remove_first_page(journal_cjf *jnl);

static inline uint32_t     journal_cjf_get_last_page_offset_limit(journal_cjf *jnl) { return jnl->last_page.file_offset_limit; }

static inline uint32_t     journal_cjf_get_last_page_first_available_byte_offset(journal_cjf *jnl) { return jnl->last_page.records_limit; }

static inline uint32_t     journal_cjf_get_last_page_has_room_left(journal_cjf *jnl) { return jnl->last_page.file_offset_limit >= jnl->last_page.records_limit; }

static inline int64_t      journal_cjf_get_last_page_available_space_left(journal_cjf *jnl)
{
    int64_t to = (int64_t)jnl->last_page.file_offset_limit;
    int64_t from = (int64_t)jnl->last_page.records_limit;
    int64_t ret = MAX(to - from, 0);
    return ret;
}

static inline uint32_t journal_cjf_maximum_size(journal_cjf *jnl) { return jnl->file_maximum_size; }

static inline bool     journal_cjf_has_flag(journal_cjf *jnl, uint16_t bits) { return (jnl->flags & bits) == bits; }

static inline void     journal_cjf_set_flag(journal_cjf *jnl, uint16_t bits) { jnl->flags |= bits; }

static inline void     journal_cjf_clear_flag(journal_cjf *jnl, uint16_t bits) { jnl->flags &= ~bits; }

static inline void     journal_cjf_set_dirty(journal_cjf *jnl) { journal_cjf_set_flag(jnl, JOURNAL_CFJ_FLAGS_DIRTY); }

static inline bool     journal_cjf_is_dirty(journal_cjf *jnl)
{
    bool ret = journal_cjf_has_flag(jnl, JOURNAL_CFJ_FLAGS_DIRTY);
    return ret;
}

static inline void journal_cjf_clear_dirty(journal_cjf *jnl) { journal_cjf_clear_flag(jnl, JOURNAL_CFJ_FLAGS_DIRTY); }

static inline void journal_cjf_set_empty(journal_cjf *jnl) { journal_cjf_clear_flag(jnl, JOURNAL_CFJ_FLAGS_NOT_EMPTY); }

static inline void journal_cjf_clear_empty(journal_cjf *jnl) { journal_cjf_set_flag(jnl, JOURNAL_CFJ_FLAGS_NOT_EMPTY); }

static inline bool journal_cjf_isempty(journal_cjf *jnl)
{
    bool ret = !journal_cjf_has_flag(jnl, JOURNAL_CFJ_FLAGS_NOT_EMPTY);
    return ret;
}

static inline bool journal_cjf_is_my_endian(journal_cjf *jnl)
{
    bool ret = journal_cjf_has_flag(jnl, JOURNAL_CFJ_FLAGS_MY_ENDIAN);
    return ret;
}
