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

/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/** @brief Function ...
 *
 *  ...
 *
 *  @param ...
 *
 *  @retval OK
 *  @retval NOK
 */

#if !JOURNAL_CJF_ENABLED

#include "dnsdb/dnsdb-config.h"

#define ZDB_JOURNAL_CODE 1

#include "dnsdb/journal.h"

#if !JOURNAL_CJF_ENABLED

#define JOURNAL_CJF_BASE 1

#include "dnsdb/journal-cjf-page.h"
#include "dnsdb/journal-cjf-page-cache.h"
#include "dnsdb/journal-cjf-page-output-stream.h"
#include "dnsdb/journal-cjf-idxt.h"
#include "dnsdb/journal-cjf-common.h"
#include "dnsdb/journal-cjf.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/empty-input-stream.h>
#include <dnscore/mutex.h>
#include <dnscore/serial.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/format.h>

#include <dnscore/ptr_set.h>
#include <dnscore/fdtools.h>

#include <dnscore/u32_set.h>
#include <dnscore/list-dl.h>

#include <dnscore/ctrl-rfc.h>

#include <dnscore/bytearray_output_stream.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/zalloc.h>

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/journal.h"
#include "dnsdb/zdb_types.h"
#include "dnsdb/xfr_copy.h"
#include "dnsdb/zdb-zone-path-provider.h"
#include "dnsdb/zdb_zone.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define DEBUG_JOURNAL 0
#if !DEBUG
#undef DEBUG_JOURNAL
#define DEBUG_JOURNAL 0
#endif

#define JOURNAL_FORMAT_NAME "cyclic"
#define VERSION_HI 0
#define VERSION_LO 1
#define JOURNAL_CLASS_NAME "journal_cjf"

#define LOCK_NONE   0
#define LOCK_READ   1
#define LOCK_WRITE  2

#define CJF_EXT "cjf"
#define CJF_EXT_STRLEN 3

#define CJF_IDXT_SLOT_SIZE 8

#define SOA_RDATA_SIZE_MAX 532

#define DO_SYNC 1

#define JRNLCJF_TAG 0x58494c4e524a

/**
 * Two steps means that the journal is written in two passes.
 * Pass 1 gathers a full page from input and validates it.
 * Pass 2 stores it to the journal file.
 */

#define CJF_USE_TWO_STEPS 1

/*
 * Contains the journal (almost: not the matching start and end SOA)
 */

#define CJF_WIRE_FILE_FORMAT "%s/%{dnsname}." CJF_EXT
#define FIRST_FROM_END  (CJF_EXT_STRLEN + (1 + 8 + 1 + 8))
#define LAST_FROM_END   (CJF_EXT_STRLEN + (1 + 8))

#define CJF_SECTION_INDEX_SLOT_HEAD  16
#define CJF_SECTION_INDEX_SLOT_SIZE  8
#define CJF_SECTION_INDEX_SLOT_COUNT 510
#define CJF_SECTION_INDEX_SIZE       (CJF_SECTION_INDEX_SLOT_HEAD + CJF_SECTION_INDEX_SLOT_SIZE * CJF_SECTION_INDEX_SLOT_COUNT) // 4KB

#define CJF_PAGE_SIZE_IN_BYTE        (CJF_SECTION_INDEX_SLOT_HEAD + (CJF_SECTION_INDEX_SLOT_COUNT * CJF_SECTION_INDEX_SLOT_SIZE))
#define CJF_PAGE_ARBITRARY_UPDATE_SIZE      512

#define CJF_SECTION_INDEX_SLOT_HEAD_SLOT (CJF_SECTION_INDEX_SLOT_HEAD / CJF_SECTION_INDEX_SLOT_SIZE)


/*******************************************************************************
 *
 *  JNL (HEADER) ---> IDXT
 *   |                 |
 *   +------+------+---+
 *   |      |      |
 *   v      v      v
 *  PAGE -> PAGE -> PAGE
 *   |      |      |
 *   v      v      v
 *  IXFRs  IXFRs  IXFRs
 * 
 ******************************************************************************/

/*
 * MAGIC 'JNL' + Version 0
 * Serial begin
 * Serial end
 * Begin Index Offset
 * Table Index Offset
 */


/**
 * There is a need of lockable 4K pages in an MRU that points back to their user
 * That's where the PAGE will be stored
 * I'm not sure of what the ratio between allowed FDs and allowed PAGE pages should be.
 */

static shared_group_shared_mutex_t journal_shared_mtx;
static bool journal_initialized = FALSE;

static file_pool_t journal_file_pool = 0;

void
log_debug_jnl(journal_cjf *jnl, const char *text)
{
    log_debug4("cjf-ro: %s,%p: %s: header SN=[%08x; %08x] F=%08x L=%08x dirty=%i empty=%i",
                jnl->journal_file_name, jnl->file, text,
                jnl->serial_begin, jnl->serial_end,
                jnl->first_page_offset, jnl->page_table_file_offset,
                journal_cjf_is_dirty(jnl),
                journal_cjf_isempty(jnl));
    
    s16 n = jnl->idxt.count;
    
    if(jnl->last_page.count == 0)
    {
        n--;
    }
    
    log_debug4("cjf-ro: %s,%p: %s: idxt %3hi/%3hi [%3hi] dirty=%i marked=%i", 
        jnl->journal_file_name, jnl->file, text,
        jnl->idxt.count, jnl->idxt.size, jnl->idxt.first, (jnl->idxt.dirty)?1:0, (jnl->idxt.marked)?1:0);
    
    log_debug4("cjf-ro: %s,%p: %s: page: SN=[%08x; %08x] count=%3u size=%3u at=%08x next=%08x ... limit=%08x",
               jnl->journal_file_name, jnl->file, text,
               jnl->last_page.serial_start, jnl->last_page.serial_end,
               jnl->last_page.count,jnl->last_page.size,
               jnl->last_page.file_offset, jnl->last_page.records_limit,
               jnl->last_page.file_offset_limit);
        
    for(s16 idx = 0; idx < n; idx++)
    {
        journal_cjf_idxt_tbl_item *item = &jnl->idxt.entries[(jnl->idxt.first + idx) % jnl->idxt.size];
        
        log_debug4("cjf-ro: %s,%p: %s: idxt[%3i] = %08x %08x", jnl->journal_file_name, jnl->file, text, idx, item->last_serial, item->file_offset);
    }
    
    if(jnl->last_page.count == 0)
    {
        journal_cjf_idxt_tbl_item *item = &jnl->idxt.entries[(jnl->idxt.first + n) % jnl->idxt.size];
        
        log_debug4("cjf-ro: %s,%p: %s: idxt[%3i] =  [empty] %08x", jnl->journal_file_name, jnl->file, text, n, item->file_offset);
    }    
}

static void
journal_cjf_ro_readlock(journal_cjf *jnl)
{
#if DEBUG
    log_debug4("cjf-ro: %s,%p: read lock", jnl->journal_file_name, jnl->file);
#endif
    shared_group_mutex_lock(&jnl->mtx, GROUP_MUTEX_READ);
}

static void
journal_cjf_ro_readunlock(journal_cjf *jnl)
{
#if DEBUG
    log_debug4("cjf-ro: %s,%p: read unlock", jnl->journal_file_name, jnl->file);
#endif
    shared_group_mutex_unlock(&jnl->mtx, GROUP_MUTEX_READ);
}

bool
journal_cjf_ro_isreadlocked(journal_cjf *jnl)
{
    bool ret = shared_group_mutex_islocked_by(&jnl->mtx, GROUP_MUTEX_READ);
    return ret;
}

bool
journal_cjf_ro_iswritelocked(journal_cjf *jnl)
{
    bool ret = shared_group_mutex_islocked_by(&jnl->mtx, GROUP_MUTEX_WRITE);
    return ret;
}

void
journal_cjf_ro_release(journal_cjf *jnl)
{
    journal_release((journal*)jnl);
}

static journal_cjf* journal_cjf_ro_alloc_default(const u8 *origin, const char *filename);

static const journal_cjf_idxt_tbl_item*
journal_cjf_ro_idxt_get_entry(const journal_cjf *jnl, s16 index)
{
    yassert(index >= 0);yassert(jnl->idxt.first >= 0);

    journal_cjf_idxt_tbl_item *entry;
    entry = &jnl->idxt.entries[(jnl->idxt.first + index) % jnl->idxt.size];
    return entry;
}

static u32
journal_cjf_ro_idxt_get_file_offset(const journal_cjf *jnl, s16 index)
{
    u32 file_offset = journal_cjf_ro_idxt_get_entry(jnl, index)->file_offset;
    return file_offset;
}

static void
journal_cjf_ro_page_cache_read_header(file_pool_file_t file, u64 file_offset,  journal_cjf_page_tbl_header *value)
{
    yassert(file_offset >= CJF_HEADER_SIZE);
    size_t current_position;
    file_pool_tell(file, &current_position);
    file_pool_seek(file, file_offset, SEEK_SET);
    file_pool_readfully(file, value, offsetof(journal_cjf_page_tbl_header, __end_of_struct__));
    file_pool_seek(file, current_position, SEEK_SET);

    log_debug("cjf: %s: %lli=%llx read header {%08x,%3d,%3d,%08x}", file_pool_filename(file), file_offset, file_offset, value->next_page_offset, value->count, value->size, value->stream_end_offset);
}

static u32
journal_cjf_ro_idxt_get_page_offset(const journal_cjf *jnl, int idx)
{
    journal_cjf_idxt_tbl_item *entry;
    entry = &jnl->idxt.entries[(jnl->idxt.first + idx) % jnl->idxt.size];
    return entry->file_offset;
}


static u32
journal_cjf_ro_idxt_get_page_serial_from_index(const journal_cjf *jnl, int idx)
{
    if(idx > 0)
    {
        journal_cjf_idxt_tbl_item *prev_entry;
        prev_entry = &jnl->idxt.entries[(jnl->idxt.first + idx - 1) % jnl->idxt.size];
        return prev_entry->last_serial;
    }
    else
    {
        return jnl->serial_begin;
    }
}

ya_result
journal_cjf_ro_idxt_get_page_offset_from_serial(const journal_cjf *jnl, u32 serial, u32 *file_offset)
{
    u32 prev_serial = jnl->serial_begin;

    // ensure the journal starts at least from the serial we are looking for

    if(serial_lt(serial, prev_serial))
    {
        return ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE;
    }

    s16 n = jnl->idxt.count;
    for(s16 i = 0; i < n; i++)
    {
        journal_cjf_idxt_tbl_item *entry;
        entry = &jnl->idxt.entries[(jnl->idxt.first + i) % jnl->idxt.size];

        // entry->last_serial is the last_serial TO, so the start of the next page

        if(serial_lt(serial, entry->last_serial))
        {
            log_debug1("journal_cjf_idxt_get_page_index_from_serial(%s, %d) returning %i (%i -> %i)",
                       jnl->journal_file_name, serial, i, prev_serial, entry->last_serial);
            if(file_offset != NULL)
            {
                *file_offset = entry->file_offset;
            }
            return i;
        }

        prev_serial = entry->last_serial;
    }

    // too far ...

    return ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE;
}


/*
 scans all the PAGE entries from the IDXT and get the one that contains the serial
 */

static ya_result
journal_cjf_ro_idxt_get_page_index_from_serial(const journal_cjf *jnl, u32 serial)
{
    u32 prev = jnl->serial_begin;

    if(serial_lt(serial, prev))
    {
        return ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE;
    }

    u32 prev_serial = jnl->serial_begin;

    s16 n = jnl->idxt.count;
    for(s16 i = 0; i < n; i++)
    {
        journal_cjf_idxt_tbl_item *entry;
        entry = &jnl->idxt.entries[(jnl->idxt.first + i) % jnl->idxt.size];
        // the last serial of an entry is the one of the last SOA added on it
        // we want to start after that one
        if(serial_lt(serial, entry->last_serial))
        {
            log_debug1("journal_cjf_idxt_get_page_index_from_serial(%s, %d) returning %i (%i -> %i)", jnl->journal_file_name, serial, i, prev_serial, entry->last_serial);
            return i;
        }
        prev_serial = entry->last_serial;
    }

    return ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE;
}

/**
 * 
 * Does NOT set the fd field in jnl
 * MUST return -1 in case of error
 * 
 * @param jnl
 * @param create
 * @return the file descriptor or an error code
 */

static int
journal_cjf_ro_init_from_file(journal_cjf **jnlp, const u8 *origin, const char *filename, bool create)
{
    (void)create;

    log_debug3("cjf-ro: %{dnsname}: opening%s %s", origin, filename);
    
    int flags = O_RDWR|O_CLOEXEC;
#ifdef O_NOATIME
    flags |= O_NOATIME;
#endif
    file_pool_file_t file;
    ya_result ret;
    bool bad_journal = FALSE;
    cjf_header hdr;

    file = file_pool_open_ex(journal_file_pool, filename, flags, 0660);

    if(file == NULL)
    {
        ret = ERRNO_ERROR;
        log_debug3("cjf-ro: %{dnsname}: failed to open %s: %r", origin, filename, ret);

        return ret;
    }
    
    s64 size = filesize(filename);
    if(size < CJF_HEADER_SIZE)
    {
        bad_journal = TRUE;
    }
    
    // look if the journal makes sense

    if(FAIL(ret = file_pool_readfully(file, &hdr, sizeof(hdr))))
    {
        ret = ERRNO_ERROR;
        log_err("cjf-ro: %{dnsname}: could not read header on %s: %r", origin, filename, ret);
        bad_journal = TRUE;
    }
    else if((hdr.magic_plus_version != CJF_CJF0_MAGIC) || ((hdr.flags & JOURNAL_CFJ_FLAGS_MY_ENDIAN) == 0) )
    {
        if(hdr.magic_plus_version != CJF_CJF0_MAGIC)
        {
            log_err("cjf-ro: %{dnsname}: wrong magic on %s", origin, filename);
        }
        else
        {
            log_err("cjf-ro: %{dnsname}: wrong endian on %s", origin, filename);
        }

        bad_journal = TRUE;
    }
    else if(hdr.first_index_offset == 0)
    {
        bad_journal = TRUE;
    }

    if(!bad_journal)
    {
        // it does makes sense
        
        // note: DO NOT jnl->file = fd;
        
        journal_cjf *jnl = journal_cjf_ro_alloc_default(origin, filename);

        jnl->flags = hdr.flags;

        jnl->serial_begin = hdr.serial_begin;
        jnl->serial_end = hdr.serial_end;
        jnl->first_page_offset = hdr.first_index_offset;
        jnl->page_table_file_offset = hdr.table_index_offset;
        jnl->last_soa_offset = hdr.last_soa_offset;

        jnl->last_page.serial_end = jnl->serial_end;    
        jnl->last_page.records_limit = hdr.last_page_offset_next;
        
        jnl->file = file;

        log_debug("cjf-ro: %{dnsname}: journal expected to cover serials from %i to %i", jnl->origin, hdr.serial_begin, hdr.serial_end);
        log_debug("cjf-ro: %{dnsname}: journal table index located at %x%s", jnl->origin, hdr.table_index_offset,
            (hdr.table_index_offset!=0)?"":", which means it has not been closed properly");
        
        *jnlp = jnl;

        return SUCCESS;
    }
    else
    {
        // the journal content is unexpected
        
        file_pool_close(file);
        file = NULL;

        char broken_file_path[PATH_MAX];

        if(ISOK(ret = snformat(broken_file_path, sizeof(broken_file_path),"%s.bad-journal", filename)))
        {
            // remove previous bad-journal if any
            if(unlink(broken_file_path) < 0)
            {
                ret = ERRNO_ERROR;
                if(ret == MAKE_ERRNO_ERROR(ENOENT))
                {
                    ret = SUCCESS;
                }
                else
                {
                    log_err("cjf-ro: %{dnsname}: unable to delete previous bad journal %s: %r", origin, broken_file_path, ret);
                }
            }
            
            // successfully handled the previous .bad-journal
            
            if(ISOK(ret))
            {
                // rename the journal into bad-journal
                if(rename(filename, broken_file_path) < 0)
                {
                    ret = ERRNO_ERROR;
                    log_err("cjf-ro: %{dnsname}: unable to rename %s into %s: %r", origin, filename, broken_file_path, ret);

                    if(unlink(filename) < 0)
                    {
                        ret = ERRNO_ERROR;
                        log_err("cjf-ro: %{dnsname}: unable to delete %s: %r", origin, filename, ret);
                    }
                }
                
                ret = ZDB_ERROR_ICMTL_NOTFOUND;
            }
        }
        else
        {
            log_err("cjf-ro: %{dnsname}: %s is a bad journal, please remove it.", origin, filename);
        }
    }
    
    return ret;
}

/*******************************************************************************
 * 
 * Index table handling functions
 *
 ******************************************************************************/

/*****************************************************************************/

static void journal_cjf_ro_readlock(journal_cjf *jnl);
static void journal_cjf_ro_readunlock(journal_cjf *jnl);

static const char *
journal_cjf_ro_get_format_name()
{
    return JOURNAL_FORMAT_NAME;
}

static u32
journal_cjf_ro_get_format_version()
{
    return VERSION_U32(VERSION_HI,VERSION_LO);
}

static ya_result
journal_cjf_ro_read_soa_record(dns_resource_record *rr, input_stream *ixfr_wire_is)
{
    ya_result return_value;
    
    if((return_value = dns_resource_record_read(rr, ixfr_wire_is)) <= 0)
    {
        /* FAIL or EOF */
        return return_value;
    }
    
#if DEBUG
    rdata_desc rdatadesc = {rr->tctr.qtype, rr->rdata_size, rr->rdata};
    log_debug("cjf-ro: %{dnsname} %{typerdatadesc}", rr->name, &rdatadesc);
#endif
    
    if((rr->tctr.qtype != TYPE_SOA) || (rr->rdata_size > SOA_RDATA_SIZE_MAX))
    {    
        log_err("cjf-ro: expected SOA record but got %{dnstype} instead", &rr->tctr.qtype);
        
        return ZDB_JOURNAL_SOA_RECORD_EXPECTED;
    }
    
    return return_value;
}

struct journal_cjf_ro_read_ixfr_s
{
    input_stream *ixfr_wire_is;
    output_stream baos;
    dns_resource_record rr;
    u32 serial_from;
    u32 serial_to;
    u32 size;
    bool eof;
};

typedef struct journal_cjf_ro_read_ixfr_s journal_cjf_ro_read_ixfr_s;

ya_result
journal_cjf_ro_read_ixfr_init(journal_cjf_ro_read_ixfr_s *ixfrinc, input_stream *ixfr_wire_is)
{
    ya_result ret;
    ixfrinc->ixfr_wire_is = ixfr_wire_is;
    bytearray_output_stream_init_ex(&ixfrinc->baos, NULL, 65536, BYTEARRAY_DYNAMIC);
    dns_resource_record_init(&ixfrinc->rr);
    ixfrinc->serial_from = 0;
    ixfrinc->serial_to = 0;
    ixfrinc->size = 0;
    ixfrinc->eof = FALSE;
    
    ret = journal_cjf_ro_read_soa_record(&ixfrinc->rr, ixfr_wire_is);
    
#if DEBUG
    if(ISOK(ret))
    {
        log_debug2("cjf-ro: ---: started with %{dnsrr}", &ixfrinc->rr); 
    }
#endif
    
    return ret;
}

void
journal_cjf_ro_read_ixfr_finalize(journal_cjf_ro_read_ixfr_s *ixfrinc)
{
    ixfrinc->ixfr_wire_is = NULL;
    
    dns_resource_record_clear(&ixfrinc->rr);
    output_stream_close(&ixfrinc->baos);
    
    ixfrinc->serial_from = 0;
    ixfrinc->serial_to = 0;
    ixfrinc->size = 0;
}

static ya_result
journal_cjf_ro_append_ixfr_stream(journal *jh, input_stream *ixfr_wire_is)
{
    (void)jh;
    (void)ixfr_wire_is;
    return CIRCULAR_FILE_FULL;
}

/******************************************************************************
 *
 * Journal Input Stream
 * This one returns and IXFR stream
 *  
 ******************************************************************************/

#define JCJFISDT_TAG 0x54445349464a434a

struct journal_cjf_ro_input_stream_data
{
    journal_cjf *jnl;
    
    file_pool_file_t file;
    u32 available;
    
    u32 serial_from;
    u32 page_next;      // DEBUG
    
    u16 idxt_index;
    u16 idxt_size;
    
    u16 todo_soa_record_size;
    bool first_stream;
    
    u8* todo_soa_record;
};

typedef struct journal_cjf_ro_input_stream_data journal_cjf_ro_input_stream_data;

static void
journal_cjf_ro_page_cache_read(file_pool_file_t file, u64 file_offset, s16 offset, void *value, u32 value_len)
{
    yassert(file_offset >= CJF_HEADER_SIZE);
    size_t current_position;
    file_pool_tell(file, &current_position);
    file_pool_seek(file, file_offset + CJF_SECTION_INDEX_SLOT_SIZE * offset , SEEK_SET);
    file_pool_readfully(file, value, value_len);
    file_pool_seek(file, current_position, SEEK_SET);

    log_debug("cjf: %s: %lli=%llx read {%08x,%9lld,%4d, %p,%08x}", file_pool_filename(file), file_offset, file_offset, offset, value, value_len);
}

static void
journal_cjf_ro_page_cache_read_item(file_pool_file_t file, u64 file_offset, s16 offset, journal_cjf_page_tbl_item *value)
{
    yassert(file_offset >= CJF_HEADER_SIZE);
    journal_cjf_ro_page_cache_read(file, file_offset, offset + CJF_SECTION_INDEX_SLOT_HEAD_SLOT, value, sizeof(journal_cjf_page_tbl_item));
}

/**
 * Search from the offset of the stream for a serial, looking in an PAGE referenced by index
 *
 * @param jnl
 * @param idx
 * @param serial
 * @param out_offset
 * @return
 */

static ya_result
journal_cjf_ro_page_get_stream_offset_from_serial(journal_cjf *jnl, int idx, u32 serial, u32 *out_offset)
{
    u32 file_offset = journal_cjf_ro_idxt_get_page_offset(jnl, idx);
    journal_cjf_page_tbl_item value;

    if(journal_cjf_ro_idxt_get_page_serial_from_index(jnl, idx) == serial)
    {
        // the first one

        journal_cjf_ro_page_cache_read_item(jnl->file, file_offset, 0, &value);
        *out_offset = value.stream_file_offset;

        return SUCCESS;
    }

    // read how much items are in the PAGE

    journal_cjf_page_tbl_header hdr;
    journal_cjf_ro_page_cache_read_header(jnl->file, file_offset, &hdr);

    if(hdr.magic == CJF_PAGE_MAGIC)
    {
        //for(int i = 1; i <= CJF_SECTION_INDEX_SLOT_COUNT - 1; i++)
        for(int i = 0; i < hdr.count - 1; i++)
        {
            journal_cjf_ro_page_cache_read_item(jnl->file, file_offset, i, &value);

            if(value.ends_with_serial == serial)
            {
                // we found the item that ends with the requested serial,
                // the next item is the one that starts from the requested serial

                journal_cjf_ro_page_cache_read_item(jnl->file, file_offset, i + 1, &value);
                *out_offset = value.stream_file_offset;

                return SUCCESS;
            }
        }

        //this is the wrong idx
#endif
    }
    else
    {
        // invalid
    }

    return ERROR;
}


static ya_result
journal_cjf_ro_input_stream_read(input_stream* stream, void *buffer_, u32 len)
{
    journal_cjf_ro_input_stream_data *data = (journal_cjf_ro_input_stream_data*)stream->data;
    u8 *buffer = (u8*)buffer_;
    const u8 *base = buffer;
    const u8 *limit = &buffer[len];
    intptr n;
    ya_result ret = 0;
    
    journal_cjf *jnl = data->jnl;
    
    log_debug("cjf-ro: %s,%p: input: reading %u/%u bytes, pos is %lli", jnl->journal_file_name, jnl->file,
            len, data->available, file_pool_seek(data->file, 0, SEEK_CUR));

    // while there is still room in the output buffer
    
    while((n = limit - buffer) > 0)
    {
        // if there is no data ready on input, fetch some more
        
        if(data->available == 0)
        {
            // get the next one
            
            if(data->idxt_index == data->idxt_size)
            {
                // EOF : we were at the last index in the IDXT
                break;
            }
            
            // get the offset of the current PAGE table

            u32 page_offset = journal_cjf_ro_idxt_get_file_offset(data->jnl, data->idxt_index);
            u32 stream_offset;
            u32 stream_limit_offset;
            
            // look for the first SOA requested
            
            if(!data->first_stream)
            {
                // we are already streaming, the XFR stream starts at the end of the PAGE (4096 bytes until next version of the journal)
                
                stream_offset = page_offset + CJF_PAGE_SIZE_IN_BYTE;
            }
            else
            {
                // the starting stream offset is obtained through a bit more work
                
                if(FAIL(ret = journal_cjf_ro_page_get_stream_offset_from_serial(data->jnl, data->idxt_index, data->serial_from, &stream_offset)))
                {
                    return ret;
                }
                
                data->first_stream = FALSE;
            }
            
            journal_cjf_page_tbl_header page_header;
            journal_cjf_ro_page_cache_read_header(data->jnl->file, page_offset, &page_header);
            
            if(page_header.count == 0)
            {
                // empty page, proably not flushed
                break;
            }
            
            stream_limit_offset = page_header.stream_end_offset;
                        
            // we know where to start ...
                        
            data->idxt_index++;
            
            (void)stream_limit_offset;
            
#if DEBUG
            if(stream_limit_offset == 0)
            {
                log_err("impossible limit value read from the journal");
                journal_cjf_ro_page_cache_read_header(data->jnl->file, page_offset, &page_header);
            }
#endif

            yassert(stream_limit_offset != 0);
            yassert(stream_limit_offset > page_offset);
 
            data->available = page_header.stream_end_offset - stream_offset;
            data->page_next = page_header.next_page_offset;
            
            if(file_pool_seek(data->file, stream_offset, SEEK_SET) < 0)
            {
                return ERRNO_ERROR;
            }
        }
        
        n = MIN(n, data->available);
        
        if(FAIL(ret = file_pool_readfully(data->file, buffer, n)))
        {
            return ret;
        }
        
        data->available -= n;
        buffer += n;
    }
        
    return buffer - base;
}

static ya_result
journal_cjf_ro_input_stream_skip(input_stream* is, u32 len)
{
    u8 tmp[512];
    
    journal_cjf_ro_input_stream_data *data = (journal_cjf_ro_input_stream_data*)is->data;
    journal_cjf *jnl = data->jnl;
    log_debug("cjf-ro: %s,%p: input: skipping %u bytes", jnl->journal_file_name, jnl->file, len);
    
    while(len > 0)
    {
        ya_result ret;
        u32 n = MIN(len, sizeof(tmp));
        if(FAIL(ret = journal_cjf_ro_input_stream_read(is, tmp, n)))
        {
            return ret;
        }
        
        len -= n;
    }

    return len;
}

static void
journal_cjf_ro_input_stream_close(input_stream* is)
{
    journal_cjf_ro_input_stream_data *data = (journal_cjf_ro_input_stream_data*)is->data;
    
    log_debug("cjf-ro: %s,%p: input: close (%p)", data->jnl->journal_file_name, data->jnl->file, data->file);
    journal_cjf_ro_readunlock(data->jnl);
    data->jnl->_forget = TRUE;
    journal_cjf_ro_release(data->jnl);
    file_pool_close(data->file);
    ZFREE_OBJECT(data);
    
    input_stream_set_void(is);    
}

static const input_stream_vtbl journal_cjf_ro_input_stream_vtbl =
{
    journal_cjf_ro_input_stream_read,
    journal_cjf_ro_input_stream_skip,
    journal_cjf_ro_input_stream_close,
    "journal_cjf_ro_input_stream"
};

/*
 * the last_soa_rr is used for IXFR transfers (it has to be a prefix & suffix to the returned stream)
 */

static ya_result
journal_cjf_ro_get_ixfr_stream_at_serial(journal *jh, u32 serial_from, input_stream *out_input_stream, dns_resource_record *out_last_soa_rr)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    
    log_debug("cjf-ro: %s,%p: get IXFR stream at serial %i", jnl->journal_file_name, jnl->file, serial_from);

    journal_cjf_ro_readlock(jnl);
    
    if(serial_lt(serial_from, jnl->serial_begin) || serial_ge(serial_from, jnl->serial_end))
    {
        if(serial_from == jnl->serial_end)
        {
            log_debug("cjf-ro: %s,%p: the journal ends at %i, returning empty stream", jnl->journal_file_name, jnl->file, serial_from);
            journal_cjf_ro_readunlock(jnl);
            empty_input_stream_init(out_input_stream);
            return SUCCESS; // 0
        }
        else
        {
            log_debug("cjf-ro: %s,%p: the journal ends at %i, returning empty stream", jnl->journal_file_name, jnl->file, serial_from);
            journal_cjf_ro_readunlock(jnl);
#if DEBUG
            logger_flush();
#endif
            return ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE;
        }
    }
    
    ya_result ret;    
    dns_resource_record rr;
    
    dns_resource_record_init(&rr);
    
    // increment the reference count of the journal
    // lock the range in the file so it cannot be overwritten
    // create a stream that know where to start, where to end
    // it has to first send the last SOA
    // then to send the start
    // then to send the last SOA again
    
    if(FAIL(ret = journal_cjf_ro_idxt_get_page_index_from_serial(jnl, serial_from)))
    {
        journal_cjf_ro_readunlock(jnl);
        
        return ret;
    }
    
    yassert(ret < MAX_U16);
    
    u16 idxt_index = (u16)ret;
        
    journal_cjf_ro_input_stream_data *data;
    ZALLOC_OBJECT_OR_DIE(data, journal_cjf_ro_input_stream_data, JCJFISDT_TAG);
    journal_acquire((journal*)jnl);
    data->jnl = jnl;
    
    data->file = file_pool_open_ex(journal_file_pool, jnl->journal_file_name, O_RDONLY|O_CLOEXEC, 0660);
    
    if(data->file == NULL)
    {
        // the journal doess not exist (anymore ?)
        ZFREE_OBJECT(data);
        
        journal_cjf_ro_readunlock(jnl);
        journal_cjf_ro_release(jnl);
        
        return MAKE_ERRNO_ERROR(ENOENT);
    }
    
    data->serial_from = serial_from;
    
    if(out_last_soa_rr != NULL)
    {
        yassert(jnl->last_soa_offset != 0);
        // read the last SOA
        
        size_t from = ~0;
        
        file_pool_tell(data->file, &from);
        
        file_pool_seek(data->file, jnl->last_soa_offset, SEEK_SET);
        
        input_stream tmp;
        file_pool_file_input_stream_init(&tmp, data->file);
        ret = dns_resource_record_read(out_last_soa_rr, &tmp);
        file_pool_file_input_stream_detach(&tmp);
        
        file_pool_seek(data->file, from, SEEK_SET);
        
        if(FAIL(ret))
        {
            journal_cjf_ro_readunlock(jnl);
            journal_cjf_ro_release(jnl);
            
            log_err("cjf-ro: %s,%p: unable to read the SOA for serial %u at position %u: %r", jnl->journal_file_name, jnl->file, serial_from, jnl->last_soa_offset, ret);
            ZFREE_OBJECT(data);
            return ret;
        }
    }
    
    data->idxt_index = idxt_index;
    data->idxt_size = jnl->idxt.count;
    data->available = 0;
    
    data->first_stream = TRUE;
        
    out_input_stream->data = data;
    out_input_stream->vtbl = &journal_cjf_ro_input_stream_vtbl;
        
    return ret;
    
    /*
     * In page_begin.file_offset, we get the first PAGE table
     * 
     * That table may chain to a next PAGE, and so on and so forth
     * While this is happening, every stream between offsets:
     * 
     * page_begin.file_offset + CJF_SECTION_INDEX_SIZE
     * 
     * and
     * 
     * @(page_begin.file_offset + 4)
     * 
     * is to be sent by the stream
     * 
     * When @(page_begin.file_offset + 4) is 0, it is the last PAGE
     * 
     * Note that @(page_begin.file_offset + 4) is cached in the IDXT entries
     * 
     * Every PAGE table but the last one has exactly CJF_SECTION_INDEX_SLOT_COUNT items
     * 
     * jnl->page.count contains the count of items of the current (not full) PAGE
     * jnl->page.offset_next contains the supremum of input after the last PAGE
     * 
     * This means a journal has to be fully initialised before being read (it was not the case for an IX file)
     * 
     * The content of the PAGE itself is not required.  Only the DNS part matters.
     * 
     * All this also means a journal has to be flushed for its DNS on disk (since the file has to be opened separately because a cloned fd shares the file pointer)
     * 
     * A range-locking mechanism is clearly needed. It should only be capable of locking up to two ranges (covers all cases).
     * 
     * So here, in summary, return a stream that is linked to the journal
     * 
     * It will start at offset:
     * 
     * idxt[ret].file_offset + CJF_SECTION_INDEX_SIZE
     * 
     * until:
     * 
     * idxt[ret + 1].file_offset or page.offset_next
     * 
     * and continue that way for every ret < idxt.count
     * 
     */
}

static ya_result
journal_cjf_ro_get_first_serial(journal *jh, u32 *serial)
{
    ya_result ret = UNEXPECTED_NULL_ARGUMENT_ERROR;
    journal_cjf *jnl = (journal_cjf*)jh;
    
    journal_cjf_ro_readlock(jnl);
    
    u32 value = jnl->serial_begin;
    
    if(serial != NULL)
    {
        *serial = value;
        ret = SUCCESS;
    }
    
    journal_cjf_ro_readunlock(jnl);
    
    log_debug("cjf-ro: %s,%p: get first serial: %i", jnl->journal_file_name, jnl->file, value);
    
    return ret;
}

static ya_result
journal_cjf_ro_get_last_serial(journal *jh, u32 *serial)
{
    ya_result ret = UNEXPECTED_NULL_ARGUMENT_ERROR;
    journal_cjf *jnl = (journal_cjf*)jh;
    
    journal_cjf_ro_readlock(jnl);
    
    u32 value = jnl->serial_end;
    
    if(serial != NULL)
    {
        *serial = value;
        ret = SUCCESS;
    }
    
    log_debug("cjf-ro: %s,%p: get last serial: %i", jnl->journal_file_name, jnl->file, value);

    journal_cjf_ro_readunlock(jnl);
    
    return ret;
}

static ya_result
journal_cjf_ro_get_serial_range(journal *jh, u32 *serial_start, u32 *serial_end)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    
    journal_cjf_ro_readlock(jnl);
    
    if(serial_start != NULL)
    {
        *serial_start = jnl->serial_begin;
    }
    if(serial_end != NULL)
    {
        *serial_end = jnl->serial_end;
    }
    
    journal_cjf_ro_readunlock(jnl);
    
    return SUCCESS;
}

static ya_result
journal_cjf_ro_truncate_to_size(journal *jh, u32 size_)
{
    journal_cjf *jnl = (journal_cjf*)jh;

    if(size_ == 0)
    {
        // destroy and close

        return SUCCESS;
    }
    else
    {    
        log_err("cjf-ro: %s,%p: truncate to size != 0 not implemented", jnl->journal_file_name, jnl->file);
        
        return ZDB_JOURNAL_FEATURE_NOT_SUPPORTED;
    }
}

static ya_result
journal_cjf_ro_truncate_to_serial(journal *jh, u32 serial_)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    (void)serial_;
    journal_cjf_ro_readlock(jnl);
    log_err("cjf-ro: %s,%p: truncate to serial not implemented", jnl->journal_file_name, jnl->file);
    journal_cjf_ro_readunlock(jnl);
    
    return ZDB_JOURNAL_FEATURE_NOT_SUPPORTED;
}

/**
 * 
 * @param jnl
 * @return 
 */

static ya_result
journal_cjf_ro_reopen(journal *jh)
{
    (void)jh;
    return SUCCESS;
}

static void
journal_cjf_ro_flush(journal *jh)
{
    journal_cjf *jnl = (journal_cjf*)jh;

    log_debug("cjf-ro: %s,%p: flush (nop)", jnl->journal_file_name, jnl->file);
}

static ya_result
journal_cjf_ro_close(journal *jh)
{
    journal_cjf *jnl = (journal_cjf*)jh;

    log_debug("cjf-ro: %s,%p: close", jnl->journal_file_name, jnl->file);
    
#if ZDB_ZONE_HAS_JNL_REFERENCE
    zdb_zone *zone;
    if((zone = (zdb_zone*)jnl->zone) != NULL)
    {
        yassert(zone->journal == jh);
        zone->journal = NULL;
    }
#endif
    
    log_debug3("cjf-ro: %s,%p: closing file", jnl->journal_file_name, jnl->file);
    
    if(jnl->file != NULL)
    {

        log_debug3("cjf-ro: %s,%p: closing file", jnl->journal_file_name, jnl->file, jnl->journal_file_name);

        log_info("zone: %{dnsname}: closing journal file '%s'", jnl->origin, jnl->journal_file_name);

        file_pool_close(jnl->file);
        jnl->file = NULL;
    }
    
    return SUCCESS;
}

static void
journal_cjf_ro_log_dump(journal *jh)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    journal_cjf_ro_readlock(jnl);
    log_debug("cjf-ro: %s,%p: [%u; %u] '%s' (%i) lck=%i rc=%i", jnl->journal_file_name, jnl->file, jnl->serial_begin, jnl->serial_end, jnl->journal_file_name, jnl->file, jnl->mtx.owner, jnl->mtx.count);
    journal_cjf_ro_readunlock(jnl);
}

static ya_result
journal_cjf_ro_get_domain(journal *jh, u8 *out_domain)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    
    // don't: journal_cjf_ro_readlock(jnl); as the field is constant until the destruction of the journal

    dnsname_copy(out_domain, jnl->origin);
    return SUCCESS;
}

static void
journal_cjf_ro_destroy(journal *jh)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    
    yassert(jnl->rc == 0);
    
    log_debug("cjf-ro: %s,%p: destroy", jnl->journal_file_name, jnl->file);

    shared_group_mutex_destroy(&jnl->mtx);
    free(jnl->origin);
    free(jnl->journal_file_name);
    
#if DEBUG    
    memset(jnl, 0xfe, sizeof(journal_cjf));
    jnl->_mru = FALSE;
#endif
    
    ZFREE_OBJECT(jnl);
}

static const u8 *
journal_cjf_ro_get_domain_const(const journal *jh)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    return jnl->origin;
}

static void
journal_cjf_ro_minimum_serial_update(journal *jh, u32 stored_serial)
{
    (void)jh;
    (void)stored_serial;
}

static void
journal_cjf_ro_maximum_size_update_method(journal *jh, u32 maximum_size)
{
    (void)jh;
    (void)maximum_size;
}

static void
journal_cjf_ro_limit_size_update_method(journal *jh, u32 maximum_size)
{
    (void)jh;
    (void)maximum_size;
}

/*******************************************************************************
 * 
 * vtbl handling functions
 *
 ******************************************************************************/

struct journal_vtbl journal_cjf_ro_vtbl =
{
    journal_cjf_ro_get_format_name,             // ok
    journal_cjf_ro_get_format_version,          // ok
    journal_cjf_ro_reopen,
    journal_cjf_ro_flush,                       // ok
    journal_cjf_ro_close,
    journal_cjf_ro_append_ixfr_stream,          // ok (for now)
    journal_cjf_ro_get_ixfr_stream_at_serial,
    journal_cjf_ro_get_first_serial,            // ok
    journal_cjf_ro_get_last_serial,             // ok
    journal_cjf_ro_get_serial_range,            // ok
    journal_cjf_ro_truncate_to_size,
    journal_cjf_ro_truncate_to_serial,
    journal_cjf_ro_log_dump,
    journal_cjf_ro_get_domain,                  // ok
    journal_cjf_ro_destroy,
    journal_cjf_ro_get_domain_const,            // ok
    journal_cjf_ro_minimum_serial_update,       // ok
    journal_cjf_ro_maximum_size_update_method,  // ok
    journal_cjf_ro_limit_size_update_method,    // ok
    JOURNAL_CLASS_NAME
};



static journal_cjf*
journal_cjf_ro_alloc_default(const u8 *origin, const char *filename)
{
    journal_cjf *jnl;
    ZALLOC_OBJECT_OR_DIE(jnl, journal_cjf, JRNLCJF_TAG);
    ZEROMEMORY(jnl, sizeof(journal_cjf));
    jnl->vtbl = &journal_cjf_ro_vtbl;
    jnl->mru_node.data = jnl;
    jnl->file = NULL;
    jnl->file_maximum_size = MAX_U32;
    jnl->first_page_offset = CJF_HEADER_SIZE;
    jnl->origin = dnsname_dup(origin);
    jnl->journal_file_name = strdup(filename);                
    jnl->last_page.file_offset = CJF_HEADER_SIZE;
    jnl->last_page.size = CJF_SECTION_INDEX_SLOT_COUNT;
    jnl->last_page.records_limit = CJF_HEADER_SIZE + CJF_SECTION_INDEX_SIZE;
    jnl->last_page.file_offset_limit = jnl->file_maximum_size;
    jnl->flags = JOURNAL_CFJ_FLAGS_MY_ENDIAN|JOURNAL_CFJ_FLAGS_UNINITIALISED;
    shared_group_mutex_init(&jnl->mtx, &journal_shared_mtx, "journal-cjf");
    return jnl;
}

static u32
journal_cjf_ro_idxt_get_last_file_offset(const journal_cjf *jnl)
{
    if(jnl->idxt.count > 0)
    {
        u32 n = journal_cjf_ro_idxt_get_file_offset(jnl, jnl->idxt.count - 1);
        return n;
    }
    else
    {
        return 0;
    }
}

static u32
journal_cjf_ro_idxt_get_last_serial(const journal_cjf *jnl, s16 index)
{
    u32 last_serial = journal_cjf_ro_idxt_get_entry(jnl, index)->last_serial;
    return last_serial;
}

static void
journal_cjf_ro_idxt_create(journal_cjf *jnl, s16 entries)
{
    yassert(jnl->idxt.size == 0);
    yassert(entries >= 0);

    jnl->idxt.count = 1;
    jnl->idxt.first = 0;
    jnl->idxt.size = entries + 1;
    jnl->idxt.dirty = TRUE;
    jnl->idxt.marked = 0;

    MALLOC_OR_DIE(journal_cjf_idxt_tbl_item*, jnl->idxt.entries, sizeof(journal_cjf_idxt_tbl_item) * jnl->idxt.size, JCJFITI_TAG);
    ZEROMEMORY(jnl->idxt.entries, sizeof(journal_cjf_idxt_tbl_item) * jnl->idxt.size);

    jnl->idxt.entries[0].last_serial = jnl->serial_begin;
    jnl->idxt.entries[0].file_offset = jnl->last_page.file_offset;
    jnl->first_page_offset = jnl->last_page.file_offset;
}

static s16
journal_cjf_idxt_size(const journal_cjf *jnl)
{
    return jnl->idxt.count;
}

static ya_result
journal_cjf_ro_idxt_verify(journal_cjf *jnl)
{
    // check the values of the pages
    // serials have to be ordered in serial arithmetics
    // pages are supposed to start after each other except a looping ones that goes after the header

    // if the verify fails, a scan may be needed (other procedure)

    journal_cjf_page_tbl_header page_hdr;
    u32 previous_page_offset;
    u32 stream_end_offset;
    u32 next_page_offset; // uninitialised false positive: either size is <= 0, skipping for & if, either it's >= 0 and page_hrd is set and initialises next_page_offset
    u32 prev_serial = jnl->serial_begin;
    int loops = 0;
    bool error = FALSE;
    bool has_page_after_header = FALSE;

    s16 size = journal_cjf_idxt_size(jnl);

    for(int page = 0; page < size; ++page)
    {
        const journal_cjf_idxt_tbl_item* entry = journal_cjf_ro_idxt_get_entry(jnl, page);

        has_page_after_header |= entry->file_offset == CJF_HEADER_SIZE;

        if(page > 0)
        {
            if(entry->file_offset != next_page_offset) // gcc false positive: next_page_offset is initialised when page == 0
            {
                // page do not start at the expected position
                log_err("cjf: %{dnsname}: page[%i] starts at an unexpected position (%u != expected %u)", jnl->origin, page, entry->file_offset, next_page_offset);
                error = TRUE;
            }

            if(entry->file_offset == previous_page_offset)
            {
                // broken chain
                log_err("cjf: %{dnsname}: page[%i] is a duplicate at position %u", jnl->origin, page, entry->file_offset);
                error = TRUE;
            }

            if(entry->file_offset > previous_page_offset)
            {
                if(entry->file_offset != stream_end_offset)
                {
                    // suspicious hole in the file
                    log_err("cjf: %{dnsname}: page[%i] is %u bytes after the expected position", jnl->origin, page, entry->file_offset - stream_end_offset);
                    error = TRUE;
                }
            }
            else
            {
                // just looped ...

                if(loops == 0)
                {
                    if(entry->file_offset > CJF_HEADER_SIZE)
                    {
                        // looped at an unexpected position
                        log_err("cjf: %{dnsname}: page[%i] looped at an unexpected position (%u != expected %u)", jnl->origin, page, entry->file_offset, CJF_HEADER_SIZE);
                        error = TRUE;
                    }
                    else if(entry->file_offset > CJF_HEADER_SIZE)
                    {
                        // looped at an unexpected position
                        log_err("cjf: %{dnsname}: page[%i] looped into the header position (%u < %u)", jnl->origin, page, entry->file_offset, CJF_HEADER_SIZE);
                        error = TRUE;
                    }

                    loops = 1;
                }
                else
                {
                    // should only have looped once
                    log_err("cjf: %{dnsname}: page[%i] looped for a second time", jnl->origin, page);
                    error = TRUE;
                }
            }

            if(error)
            {
                // got at least one error
                return ERROR;
            }
        }

        ssize_t pos = file_pool_seek(jnl->file, entry->file_offset, SEEK_SET);

        if(pos < 0)
        {
            // invalid position (as EBADF should not happen)
            ya_result ret = ERRNO_ERROR;

            log_err("cjf: %{dnsname}: page[%i] seek at %u returned %r", jnl->origin, page, ret);

            return ret;
        }

        int len = file_pool_readfully(jnl->file, &page_hdr, CJF_SECTION_INDEX_SLOT_HEAD);

        if(len != CJF_SECTION_INDEX_SLOT_HEAD)
        {
            if(len >= 0)
            {
                log_err("cjf: %{dnsname}: page[%i] short count reading the header (%u < %u)", jnl->origin, page, len, CJF_SECTION_INDEX_SLOT_HEAD);
                return ERROR; // short
            }
            else
            {
                log_err("cjf: %{dnsname}: page[%i] error reading the header: %r", jnl->origin, page, len);
                return len; // other error
            }
        }

        if(page_hdr.magic != CJF_PAGE_MAGIC)
        {
            // page is corrupted
            log_err("cjf: %{dnsname}: page[%i] corrupted magic", jnl->origin, page);
            return ERROR;
        }
        if(page_hdr.count > page_hdr.size)
        {
            // page is corrupted
            log_err("cjf: %{dnsname}: page[%i] says to contain more than allowed", jnl->origin, page, page_hdr.count, page_hdr.size);
            return ERROR;
        }

        if(page_hdr.count == 0)
        {
            // empty page (warning)
            log_warn("cjf: %{dnsname}: page[%i] is empty", jnl->origin, page);
        }

        if(serial_gt(prev_serial, entry->last_serial))
        {
            // suspicious serial backward jump
            log_err("cjf: %{dnsname}: page[%i] serial jumped back from %u to %u", jnl->origin, page, prev_serial, entry->last_serial);
        }
        else if(serial_eq(prev_serial, entry->last_serial))
        {
            // suspicious serial standstill
            log_err("cjf: %{dnsname}: page[%i] serial didn't changed from %u", jnl->origin, page, prev_serial);
        }

        previous_page_offset = entry->file_offset;
        next_page_offset = page_hdr.next_page_offset; // next page, 0 for the last one
        stream_end_offset = page_hdr.stream_end_offset; // start of next page, start of page table, or 0 for the last in the chain
    }

    if(size > 0)
    {
        if(next_page_offset != 0) // gcc false positive: size > 0 => next_page_offset has been set to page_hdr.next_page_offset (read from the disk)
        {
            // chain end was not marked
            log_err("cjf: %{dnsname}: page[%i] is last but points to a next at %u", jnl->origin, size - 1, next_page_offset);
            return ERROR;
        }
        if(!has_page_after_header)
        {
            // no page at an obvious position
            log_err("cjf: %{dnsname}: page table has no page at position %u", jnl->origin, CJF_HEADER_SIZE);
            return ERROR;
        }
    }
    else
    {
        // table is empty
        log_err("cjf: %{dnsname}: page table is empty", jnl->origin);
        return ERROR;
    }

    return SUCCESS;
}


static void
journal_cjf_ro_idxt_load(journal_cjf *jnl)
{
    if(jnl->idxt.entries != NULL)
    {
        // already loaded ...
        return;
    }

    // the file is opened

    if(jnl->page_table_file_offset != 0)
    {
        log_debug1("journal_cjf_ro_idxt_load: loading stored IDXT from '%s'", jnl->journal_file_name);

        // load
        file_pool_seek(jnl->file, jnl->page_table_file_offset, SEEK_SET);

        input_stream fis;
        input_stream bis;
        file_pool_file_input_stream_init(&fis, jnl->file);

        buffer_input_stream_init(&bis, &fis, 512);
        u8 magic[4];
        input_stream_read(&bis, magic, 4);
        u32 *magic_u32p = (u32*)&magic[0];
        if(*magic_u32p == CJF_IDXT_MAGIC)
        {
            s16 count;
            input_stream_read(&bis, (u8*)&count , 2);

            journal_cjf_ro_idxt_create(jnl, count + 1);

            input_stream_read(&bis, (u8*)&jnl->idxt.entries[0], count * CJF_IDXT_SLOT_SIZE);

            file_pool_file_input_stream_detach(buffer_input_stream_get_filtered(&bis));
            input_stream_close(&bis);

            jnl->idxt.count = count;

            u32 first_page_offset = journal_cjf_ro_idxt_get_file_offset(jnl, 0);

            if(jnl->first_page_offset != first_page_offset)
            {
                // discrepancy : check the IDXT is valid

                if(ISOK(journal_cjf_ro_idxt_verify(jnl)))
                {
                    // the header is wrong, update it

                    jnl->first_page_offset = first_page_offset;
                }
            }

            return;
        }

        file_pool_file_input_stream_detach(buffer_input_stream_get_filtered(&bis));
        input_stream_close(&bis);

        // ERROR, need to rebuild
    }

    log_debug1("journal_cjf_ro_idxt_load: rebuilding IDXT from '%s', following the PAGE", jnl->journal_file_name);

    // rebuild

    journal_cjf_page_tbl_item *tbl;
    s16 size = 512;
    journal_cjf_page_tbl_item tmp_tbl[512];
    tbl = tmp_tbl;

    if(jnl->first_page_offset < JOURNAL_CJF_PAGE_HEADER_SIZE)
    {
        // the PAGE chain has been lost : start from HEAD and follow the chain
        // then after the 0, scan from the furthest known byte for PAGE+offset
        // and follow until the chain points back to offset sizeof(head)
    }

    // read the PAGE chain from the file (no caching)

    u32 index_offset = jnl->first_page_offset;
    //u32 current_serial = jnl->serial_begin;
    journal_cjf_page_tbl_header page_header;
    journal_cjf_page_tbl_item page_last_item;
    s16 idx = 0;
    u32 page_serial = 0;
    bool page_read = FALSE;

    do
    {
        // move to the page offset and read the header

        log_debug2("journal_cjf_ro_idxt_load: reading '%s' PAGE header at %x", jnl->journal_file_name, index_offset);

        file_pool_seek(jnl->file, index_offset, SEEK_SET);
        if(file_pool_readfully(jnl->file, &page_header, JOURNAL_CJF_PAGE_HEADER_SIZE) != JOURNAL_CJF_PAGE_HEADER_SIZE) // next offset
        {
            log_err("journal_cjf_ro_idxt_load: '%s' is too corrupt to go on further reading PAGE header at %x", jnl->journal_file_name, index_offset);
            break;
        }
        /*
        if(page_header.magic != CJF_PAGE_MAGIC)
        {
            // corrupt
        }
        */
        if(page_header.count > 0)
        {
            u32 tail_offset = (page_header.count - 1) * CJF_SECTION_INDEX_SLOT_SIZE;

            log_debug2("journal_cjf_ro_idxt_load: reading '%s' PAGE tail at %x", jnl->journal_file_name, index_offset + tail_offset);

            // the last serial is on the last slot

            file_pool_seek(jnl->file, tail_offset, SEEK_CUR);
            if(file_pool_readfully(jnl->file, &page_last_item, JOURNAL_CJF_PAGE_ITEM_SIZE) != JOURNAL_CJF_PAGE_ITEM_SIZE)
            {
                log_err("journal_cjf_ro_idxt_load: '%s' is too corrupt to go on further reading PAGE tail at %x", jnl->journal_file_name, index_offset + CJF_SECTION_INDEX_SIZE - CJF_SECTION_INDEX_SLOT_HEAD - CJF_SECTION_INDEX_SLOT_SIZE);
                break;
            }

            // if there is a next page ...

            if(idx == size)
            {
                log_debug2("journal_cjf_ro_idxt_load: growing IDXT table from %i to %i", size, size * 2);

                journal_cjf_page_tbl_item *tmp;
                MALLOC_OR_DIE(journal_cjf_page_tbl_item*, tmp, JOURNAL_CJF_PAGE_ITEM_SIZE * size * 2, JCJFTI_TAG);
                memcpy(tmp, tbl, JOURNAL_CJF_PAGE_ITEM_SIZE * size);
                if(tbl != tmp_tbl)
                {
                    free(tbl);
                }
                tbl = tmp;
                size *= 2;
            }

            tbl[idx].stream_file_offset = index_offset;
            tbl[idx].ends_with_serial = page_last_item.ends_with_serial;

            log_debug2("journal_cjf_ro_idxt_load: IDXT[%3i] = {%8x, %u}", idx, index_offset, page_last_item.ends_with_serial);

            page_serial = page_last_item.ends_with_serial;
            page_read = TRUE;

            ++idx;

            index_offset = page_header.next_page_offset;
        }
        else
        {
            // an empty page should not exist

            if(page_read)
            {
                if(serial_eq(page_serial, jnl->serial_end))
                {
                    log_info("journal_cjf_ro_idxt_load: got up to expected serial %i", page_serial);
                }
                else if(serial_lt(page_serial, jnl->serial_end))
                {
                    log_err("journal_cjf_ro_idxt_load: got up to serial %i, before the expected %i", page_serial, jnl->serial_end);
                }
                else if(serial_gt(page_serial, jnl->serial_end))
                {
                    log_err("journal_cjf_ro_idxt_load: got up to serial %i, after the expected %i", page_serial, jnl->serial_end);
                }
            }
            else
            {
                log_err("journal_cjf_ro_idxt_load: could not read the content of the journal");
            }

            break;
        }
    }
    while(index_offset != 0);

    log_debug1("journal_cjf_ro_idxt_load: IDXT table has size %i", idx + 1);

    // scan for an SOA record

    journal_cjf_ro_idxt_create(jnl, idx + 1);
    memcpy(jnl->idxt.entries, tbl, JOURNAL_CJF_PAGE_ITEM_SIZE * idx); // False positive from VS Code Analysis jnl->idxt.entries cannot be NULL at this point
    jnl->idxt.count = idx;
}

static void
journal_cjf_ro_idxt_destroy(journal_cjf *jnl)
{
    yassert(!jnl->idxt.dirty);

    free(jnl->idxt.entries);
    jnl->idxt.entries = NULL;

    jnl->idxt.size = 0;
    jnl->idxt.first = 0;
    jnl->idxt.count = 0;
}

static void
journal_cjf_ro_load_idxt(journal_cjf *jnl)
{
    if(jnl->idxt.entries != NULL)
    {
        return;
    }

    journal_cjf_ro_idxt_load(jnl);

    if(jnl->idxt.count > 0)
    {
        jnl->last_page.file_offset = journal_cjf_ro_idxt_get_last_file_offset(jnl);
        journal_cjf_page_tbl_header current_page_header;
        journal_cjf_ro_page_cache_read_header(jnl->file, jnl->last_page.file_offset, &current_page_header);
        jnl->last_page.count = current_page_header.count;
        jnl->last_page.size = current_page_header.size;

        if(jnl->last_page.file_offset < jnl->first_page_offset)
        {
            jnl->last_page.file_offset_limit = jnl->first_page_offset;
        }
        else
        {
            jnl->last_page.file_offset_limit = jnl->file_maximum_size;
        }

        if(jnl->idxt.count > 1)
        {
            jnl->last_page.serial_start = journal_cjf_ro_idxt_get_last_serial(jnl, jnl->idxt.count - 2);
        }
        else
        {
            jnl->last_page.serial_start = jnl->serial_begin;
        }
    }
    else
    {
        jnl->idxt.dirty = FALSE;
        jnl->flags |= JOURNAL_CFJ_FLAGS_DIRTY;

        journal_cjf_ro_idxt_destroy(jnl);

        jnl->serial_begin = 0;
        jnl->serial_end = 0;

        jnl->mtx.owner = LOCK_NONE;
        jnl->mtx.count = 0;
        jnl->first_page_offset = CJF_HEADER_SIZE;
        jnl->page_table_file_offset = 0;
        jnl->last_soa_offset = 0;
        jnl->file_maximum_size = MAX_S32;

        jnl->last_page.file_offset = CJF_HEADER_SIZE;
        jnl->last_page.count = 0;
        jnl->last_page.size = CJF_SECTION_INDEX_SLOT_COUNT;
        jnl->last_page.serial_start = 0;
        jnl->last_page.serial_end = 0;
        jnl->last_page.records_limit = jnl->last_page.file_offset + CJF_SECTION_INDEX_SIZE;
        jnl->last_page.file_offset_limit = jnl->file_maximum_size;

#if _BSD_SOURCE || _XOPEN_SOURCE >= 500 || _XOPEN_SOURCE && _XOPEN_SOURCE_EXTENDED || /* Since glibc 2.3.5: */ _POSIX_C_SOURCE >= 200112L
        file_pool_resize(jnl->file, CJF_HEADER_SIZE);
#endif
    }
}

/**
 * The caller guarantees not to call this on an already opened journal
 * 
 * Should not be called directly (only by journal_* functions.
 * 
 * Opens or create a journal handling structure.
 * If the journal did not exist, the structure is returned without a file opened
 * 
 * @param jh
 * @param origin
 * @param workingdir
 * @param create
 * 
 * @return 
 */

ya_result
journal_cjf_ro_open_file(journal **jhp, const char *filename, const u8* origin, bool create)
{
    // CFJ_PAGE_CACHE ->
    if(!journal_initialized)
    {
        shared_group_shared_mutex_init(&journal_shared_mtx);
        
        journal_file_pool = file_pool_init("journal-file-pool", 256);
        
        journal_initialized = TRUE;
    }
    
    journal_cjf *jnl = NULL;
    ya_result ret;
    
    if(file_exists(filename) || create)
    {
        // instantiate and open the journal
        
        ret = journal_cjf_ro_init_from_file(&jnl, origin, filename, create);

        if(ISOK(ret))
        {
            yassert(jnl != NULL); // to help scan-build

            if(!((jnl->serial_begin == 0) && (jnl->serial_begin == jnl->serial_end))) // scan-build false-positive : if ISOK(ret) => jnl != NULL
            {
                journal_cjf_ro_load_idxt(jnl);
            }
        }
        else
        {
            if(create)
            {
                log_err("cjf-ro: %{dnsname}: failed to open %s: %r", origin, filename, ret);
            }
            else
            {
                log_debug("cjf-ro: %{dnsname}: failed to open %s: %r", origin, filename, ret);
            }

            if(jnl != NULL)
            {
                journal_cjf_ro_destroy((journal*)jnl);
#if DEBUG
                log_debug("cjf-ro: %{dnsname}: journal file cannot be opened/created", origin);
#endif
            }
            
            return ZDB_ERROR_ICMTL_NOTFOUND;
        }
        
#if DEBUG
        log_debug("cjf-ro: %{dnsname}: journal opened", origin);
#endif
        *jhp = (journal*)jnl;
        
        return SUCCESS;
    }
    else
    {
#if DEBUG
        log_debug("cjf-ro: %{dnsname}: journal file not found", origin);
#endif
        return ZDB_ERROR_ICMTL_NOTFOUND;
    }
}

/**
 * The caller guarantees not to call this on an already opened journal
 * 
 * Should not be called directly (only by journal_* functions.
 * 
 * Opens or create a journal handling structure.
 * If the journal did not exist, the structure is returned without a file opened
 * 
 * @param jh
 * @param origin
 * @param workingdir
 * @param create
 * 
 * @return 
 */

ya_result
journal_cjf_ro_open(journal **jhp, const u8* origin, const char *workingdir, bool create)
{
    // CFJ_PAGE_CACHE <-
    
    ya_result ret;
    
    *jhp = NULL;
    
    // generate the file name
    
    char filename[PATH_MAX];
    
    if((jhp == NULL) || (origin == NULL) || (workingdir == NULL))
    {
        return ZDB_JOURNAL_WRONG_PARAMETERS;
    }

#if DEBUG
    log_debug("cjf-ro: trying to open journal for %{dnsname} in '%s'", origin, workingdir);
#endif
    
    /* get the soa of the loaded zone */
        
    if(FAIL(ret = snformat(filename, sizeof(filename), CJF_WIRE_FILE_FORMAT, workingdir, origin)))
    {
#if DEBUG
        log_debug("cjf-ro: %{dnsname}: journal file name is too long", origin);
#endif
        return ret;
    }
    
    ret = journal_cjf_ro_open_file(jhp, filename, origin, create);
    
    return ret;
}

void
journal_cjf_ro_finalize()
{
    file_pool_finalize(journal_file_pool);
}

#else

char journal_cjf_ro[] = "placeholder";

#endif

/** @} */
