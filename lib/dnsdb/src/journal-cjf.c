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


#include "dnsdb/dnsdb-config.h"

#define ZDB_JOURNAL_CODE 1

#include "dnsdb/journal.h"

#if JOURNAL_CJF_ENABLED

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

#define DEBUG_JOURNAL 1
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
    log_debug4("cjf: %s,%p: %s: header SN=[%08x; %08x] F=%08x L=%08x dirty=%i empty=%i",
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
    
    log_debug4("cjf: %s,%p: %s: idxt %3hi/%3hi [%3hi] dirty=%i marked=%i", 
        jnl->journal_file_name, jnl->file, text,
        jnl->idxt.count, jnl->idxt.size, jnl->idxt.first, (jnl->idxt.dirty)?1:0, (jnl->idxt.marked)?1:0);
    
    log_debug4("cjf: %s,%p: %s: page: SN=[%08x; %08x] count=%3u size=%3u at=%08x next=%08x ... limit=%08x",
               jnl->journal_file_name, jnl->file, text,
               jnl->last_page.serial_start, jnl->last_page.serial_end,
               jnl->last_page.count,jnl->last_page.size,
               jnl->last_page.file_offset, jnl->last_page.records_limit,
               jnl->last_page.file_offset_limit);
        
    for(s16 idx = 0; idx < n; idx++)
    {
        journal_cjf_idxt_tbl_item *item = &jnl->idxt.entries[(jnl->idxt.first + idx) % jnl->idxt.size];
        
        log_debug4("cjf: %s,%p: %s: idxt[%3i] = %08x %08x", jnl->journal_file_name, jnl->file, text, idx, item->last_serial, item->file_offset);
    }
    
    if(jnl->last_page.count == 0)
    {
        journal_cjf_idxt_tbl_item *item = &jnl->idxt.entries[(jnl->idxt.first + n) % jnl->idxt.size];
        
        log_debug4("cjf: %s,%p: %s: idxt[%3i] =  [empty] %08x", jnl->journal_file_name, jnl->file, text, n, item->file_offset);
    }    
}

static void
journal_cjf_writelock(journal_cjf *jnl)
{
#if DEBUG
    log_debug4("cjf: %s,%p: write lock", jnl->journal_file_name, jnl->file);
#endif
    shared_group_mutex_lock(&jnl->mtx, GROUP_MUTEX_WRITE);
}

static void
journal_cjf_writeunlock(journal_cjf *jnl)
{
#if DEBUG
    log_debug4("cjf: %s,%p: write unlock", jnl->journal_file_name, jnl->file);
#endif
    shared_group_mutex_unlock(&jnl->mtx, GROUP_MUTEX_WRITE);
}

static void
journal_cjf_readlock(journal_cjf *jnl)
{
#if DEBUG
    log_debug4("cjf: %s,%p: read lock", jnl->journal_file_name, jnl->file);
#endif
    shared_group_mutex_lock(&jnl->mtx, GROUP_MUTEX_READ);
}

static void
journal_cjf_readunlock(journal_cjf *jnl)
{
#if DEBUG
    log_debug4("cjf: %s,%p: read unlock", jnl->journal_file_name, jnl->file);
#endif
    shared_group_mutex_unlock(&jnl->mtx, GROUP_MUTEX_READ);
}

bool
journal_cjf_isreadlocked(journal_cjf *jnl)
{
    bool ret = shared_group_mutex_islocked_by(&jnl->mtx, GROUP_MUTEX_READ);
    return ret;
}

bool
journal_cjf_iswritelocked(journal_cjf *jnl)
{
    bool ret = shared_group_mutex_islocked_by(&jnl->mtx, GROUP_MUTEX_WRITE);
    return ret;
}

void
journal_cjf_release(journal_cjf *jnl)
{
    journal_release((journal*)jnl);
}

static journal_cjf* journal_cjf_alloc_default(const u8 *origin, const char *filename);

static void
journal_cjf_load_idxt(journal_cjf *jnl)
{
    if(jnl->idxt.entries != NULL)
    {
        return;
    }
    
    journal_cjf_idxt_load(jnl);

    if(jnl->idxt.count > 0)
    {
        jnl->last_page.file_offset = journal_cjf_idxt_get_last_file_offset(jnl);
        journal_cjf_page_tbl_header current_page_header;
        journal_cjf_page_cache_read_header(jnl->file, jnl->last_page.file_offset, &current_page_header);
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
            jnl->last_page.serial_start = journal_cjf_idxt_get_last_serial(jnl, jnl->idxt.count - 2);
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

        journal_cjf_page_cache_flush(jnl->file);

        journal_cjf_idxt_destroy(jnl);

        jnl->serial_begin = 0;
        jnl->serial_end = 0;

        jnl->mtx.owner = LOCK_NONE;
        jnl->mtx.count = 0;
        jnl->first_page_offset = CJF_HEADER_SIZE;
        jnl->page_table_file_offset = 0;
        jnl->last_soa_offset = 0;
        jnl->file_maximum_size = MAX_U32;

        if(jnl->zone != NULL)
        {
            jnl->file_maximum_size = jnl->zone->wire_size >> 1;
            zdb_zone_info_get_zone_max_journal_size(jnl->origin, &jnl->file_maximum_size);
        }

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

static int
journal_cjf_create_file(journal_cjf **jnlp, const u8 *origin, const char *filename)
{
    log_debug3("cjf: %{dnsname}: creating %s", origin, filename);
    
    int flags = O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC;
#ifdef O_NOATIME
    flags |= O_NOATIME;
#endif
    file_pool_file_t file;
    ya_result ret;
    cjf_header hdr;

    file = file_pool_open_ex(journal_file_pool, filename, flags, 0644);

    if(file != NULL)
    {
        journal_cjf *jnl = journal_cjf_alloc_default(origin, filename);
        
        hdr.magic_plus_version = CJF_CJF0_MAGIC;
        hdr.serial_begin = 0;
        hdr.serial_end = 0;
        hdr.first_index_offset = 0;
        hdr.table_index_offset = 0;
        hdr.last_soa_offset = 0,
        hdr.last_page_offset_next = 0;
        //hdr.last_page_item_count = 0;
        hdr.flags = JOURNAL_CFJ_FLAGS_MY_ENDIAN; // not dirty

        ssize_t n = file_pool_writefully(file, &hdr, CJF_HEADER_SIZE);
        if(n < 0)
        {
            ret = ERRNO_ERROR;
            return ret;
        }
        
        jnl->file = file;
        
        *jnlp = jnl;

        return SUCCESS;
    }
    else
    {
        ret = ERRNO_ERROR;
        log_err("cjf: %s: failed to create %s: %r", origin, filename, ret);
        
        *jnlp = NULL;
        
        return ret;
    }
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
journal_cjf_init_from_file(journal_cjf **jnlp, const u8 *origin, const char *filename, bool create)
{
    log_debug3("cjf: %{dnsname}: opening%s %s", origin, (create)?"/creating":"", filename);
    
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
        log_debug3("cjf: %{dnsname}: failed to open %s: %r", origin, filename, ret);
        
        if(create)
        {
            ret = journal_cjf_create_file(jnlp, origin, filename);
        }
        
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
        log_err("cjf: %{dnsname}: could not read header on %s: %r", origin, filename, ret);
        bad_journal = TRUE;
    }
    else if((hdr.magic_plus_version != CJF_CJF0_MAGIC) || ((hdr.flags & JOURNAL_CFJ_FLAGS_MY_ENDIAN) == 0) )
    {
        if(hdr.magic_plus_version != CJF_CJF0_MAGIC)
        {
            log_err("cjf: %{dnsname}: wrong magic on %s", origin, filename);
        }
        else
        {
            log_err("cjf: %{dnsname}: wrong endian on %s", origin, filename);
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
        
        journal_cjf *jnl = journal_cjf_alloc_default(origin, filename);

        jnl->flags = hdr.flags;

        jnl->serial_begin = hdr.serial_begin;
        jnl->serial_end = hdr.serial_end;
        jnl->first_page_offset = hdr.first_index_offset;
        jnl->page_table_file_offset = hdr.table_index_offset;
        jnl->last_soa_offset = hdr.last_soa_offset;

        jnl->last_page.serial_end = jnl->serial_end;    
        jnl->last_page.records_limit = hdr.last_page_offset_next;
        
        jnl->file = file;

        log_debug("cjf: %{dnsname}: journal expected to cover serials from %i to %i", jnl->origin, hdr.serial_begin, hdr.serial_end);
        log_debug("cjf: %{dnsname}: journal table index located at %x%s", jnl->origin, hdr.table_index_offset,
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
            bool try_again = create;

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
                    log_err("cjf: %{dnsname}: unable to delete previous bad journal %s: %r", origin, broken_file_path, ret);
                    try_again = FALSE;
                }
            }
            
            // successfully handled the previous .bad-journal
            
            if(ISOK(ret))
            {
                // rename the journal into bad-journal
                if(rename(filename, broken_file_path) < 0)
                {
                    ret = ERRNO_ERROR;
                    log_err("cjf: %{dnsname}: unable to rename %s into %s: %r", origin, filename, broken_file_path, ret);

                    if(unlink(filename) < 0)
                    {
                        ret = ERRNO_ERROR;
                        log_err("cjf: %{dnsname}: unable to delete %s: %r", origin, filename, ret);
                        try_again = FALSE;
                    }
                }
                
                ret = ZDB_ERROR_ICMTL_NOTFOUND;
            }

            if(try_again) // we are allowed to create and got no counter-indication
            {
                int ret = journal_cjf_create_file(jnlp, origin, filename); // we are in a branch where "create = TRUE"

                return ret;
            }
        }
        else
        {
            log_err("cjf: %{dnsname}: %s is a bad journal, please remove it.", origin, filename);
        }
    }
    
    return ret;
}

void
journal_cjf_header_flush(journal_cjf *jnl)
{
    if(journal_cjf_is_dirty(jnl))
    {
        yassert(jnl->file != NULL);
        
        log_debug("cjf: %s,%p: flushing header SN=[%08x; %08x] F=%08x T=%08x", jnl->journal_file_name, jnl->file,
                jnl->serial_begin, jnl->serial_end, jnl->first_page_offset, jnl->page_table_file_offset);
        
        off_t pos;
        
        if((pos = file_pool_seek(jnl->file, 4, SEEK_SET)) != 4)
        {
            log_err("cjf: %s,%p: failed to set file position: %lli instead of %i (%r)", jnl->journal_file_name, jnl->file, pos, 4, ERRNO_ERROR);
            logger_flush();
            abort();
        }

        cjf_header hdr;
        //hdr.magic_plus_version = 0;
        hdr.serial_begin = jnl->serial_begin;
        hdr.serial_end = jnl->serial_end;
        hdr.first_index_offset = jnl->first_page_offset;
        hdr.table_index_offset = jnl->page_table_file_offset;
        hdr.last_soa_offset = jnl->last_soa_offset;
        hdr.last_page_offset_next = jnl->last_page.records_limit;
        //hdr.last_page_item_count = jnl->page.count;
        hdr.flags = jnl->flags;

        file_pool_writefully(jnl->file, &hdr.serial_begin, CJF_HEADER_SIZE - 4);
        
        journal_cjf_clear_dirty(jnl);
    }
}

/**
 * 
 * Removes the first PAGE from the journal.
 * Adjust the current PAGE limit;
 * 
 * @param jnl
 */

void
journal_cjf_remove_first_page(journal_cjf *jnl)
{
    log_debug_jnl(jnl, "journal_cjf_remove_first_page: BEFORE");
    
    u32 stored_serial = jnl->serial_begin + 1; // (ensure an error would trigger a flush)
    
    u8 zt = 0;
    if(ISOK(zdb_zone_info_get_zone_type(jnl->origin, &zt)))
    {
        if(zt == ZT_MASTER)
        {
            zdb_zone_info_get_stored_serial(jnl->origin, &stored_serial); // for master only
    
            if(serial_le(stored_serial, jnl->serial_begin))
            {
                log_debug("cjf: %s,%p: journal page %u will be lost, flushing zone first", jnl->journal_file_name, jnl->file, jnl->journal_file_name, jnl->serial_begin);
                zdb_zone_info_background_store_zone(jnl->origin);
            }
        }
    }
    
    journal_cjf_page_tbl_header first_page_hdr;    
    journal_cjf_page_cache_read_header(jnl->file, jnl->first_page_offset,  &first_page_hdr);
    if(first_page_hdr.next_page_offset < jnl->first_page_offset)
    {
        // this is the last page, of the file, physically
        jnl->page_table_file_offset = jnl->last_page.records_limit;
        jnl->idxt.dirty = TRUE;
    }
        
    journal_cjf_page_cache_clear(jnl->file, jnl->first_page_offset);
    
    jnl->serial_begin = journal_cjf_idxt_get_last_serial(jnl, 0);
    jnl->first_page_offset = journal_cjf_idxt_get_file_offset(jnl, 1);
    
    ++jnl->idxt.first;
    --jnl->idxt.count;
    
    journal_cjf_set_dirty(jnl);
    
    if(jnl->last_page.file_offset < jnl->first_page_offset)
    {
        jnl->last_page.file_offset_limit = jnl->first_page_offset;
    }
    else // at or after
    {
        jnl->last_page.file_offset_limit = jnl->file_maximum_size;
    }
    
    log_debug_jnl(jnl, "journal_cjf_remove_first_page: AFTER");

    log_debug("cjf: %s,%p: first PAGE now at %u (%08x), journal starts with serial %u (%08x", jnl->journal_file_name, jnl->file,
                jnl->first_page_offset, jnl->first_page_offset, jnl->serial_begin, jnl->serial_begin);
}

/*******************************************************************************
 * 
 * Index table handling functions
 *
 ******************************************************************************/

/*****************************************************************************/

static void journal_cjf_writelock(journal_cjf *jnl);
static void journal_cjf_writeunlock(journal_cjf *jnl);

static void journal_cjf_readlock(journal_cjf *jnl);
static void journal_cjf_readunlock(journal_cjf *jnl);

static const char *
journal_cjf_get_format_name()
{
    return JOURNAL_FORMAT_NAME;
}

static u32
journal_cjf_get_format_version()
{
    return VERSION_U32(VERSION_HI,VERSION_LO);
}

static ya_result
journal_cjf_read_soa_record(dns_resource_record *rr, input_stream *ixfr_wire_is)
{
    ya_result return_value;
    
    if((return_value = dns_resource_record_read(rr, ixfr_wire_is)) <= 0)
    {
        /* FAIL or EOF */
        return return_value;
    }
    
#if DEBUG
    rdata_desc rdatadesc = {rr->tctr.qtype, rr->rdata_size, rr->rdata};
    log_debug("cjf: %{dnsname} %{typerdatadesc}", rr->name, &rdatadesc);
#endif
    
    if((rr->tctr.qtype != TYPE_SOA) || (rr->rdata_size > SOA_RDATA_SIZE_MAX))
    {    
        log_err("cjf: expected SOA record but got %{dnstype} instead", &rr->tctr.qtype);
        
        return ZDB_JOURNAL_SOA_RECORD_EXPECTED;
    }
    
    return return_value;
}

struct journal_cjf_read_ixfr_s
{
    input_stream *ixfr_wire_is;
    output_stream baos;
    dns_resource_record rr;
    u32 serial_from;
    u32 serial_to;
    u32 size;
    bool eof;
};

typedef struct journal_cjf_read_ixfr_s journal_cjf_read_ixfr_s;

ya_result
journal_cjf_read_ixfr_init(journal_cjf_read_ixfr_s *ixfrinc, input_stream *ixfr_wire_is)
{
    ya_result ret;
    ixfrinc->ixfr_wire_is = ixfr_wire_is;
    bytearray_output_stream_init_ex(&ixfrinc->baos, NULL, 65536, BYTEARRAY_DYNAMIC);
    dns_resource_record_init(&ixfrinc->rr);
    ixfrinc->serial_from = 0;
    ixfrinc->serial_to = 0;
    ixfrinc->size = 0;
    ixfrinc->eof = FALSE;
    
    ret = journal_cjf_read_soa_record(&ixfrinc->rr, ixfr_wire_is);
    
#if DEBUG
    if(ISOK(ret))
    {
        log_debug2("cjf: ---: started with %{dnsrr}", &ixfrinc->rr); 
    }
#endif
    
    return ret;
}

void
journal_cjf_read_ixfr_finalize(journal_cjf_read_ixfr_s *ixfrinc)
{
    ixfrinc->ixfr_wire_is = NULL;
    
    dns_resource_record_clear(&ixfrinc->rr);
    output_stream_close(&ixfrinc->baos);
    
    ixfrinc->serial_from = 0;
    ixfrinc->serial_to = 0;
    ixfrinc->size = 0;
}

/**
 * 
 * Reads a single page of incremental changes (-SOA ... +SOA ...)
 * 
 * @param ixfrinc
 * @return the size of the page (0 if there is nothing to be read), or an error code
 */

static ya_result
journal_cjf_read_ixfr_read(journal_cjf_read_ixfr_s *ixfrinc)
{
    if(ixfrinc->eof)
    {
        ixfrinc->size = 0;
        return 0;
    }
    
    input_stream *ixfr_wire_is = ixfrinc->ixfr_wire_is;
    output_stream *baos = &ixfrinc->baos;
    dns_resource_record *rr = &ixfrinc->rr;
        
    ya_result ret;
    bool need_another_soa = TRUE;
    
    bytearray_output_stream_reset(baos);
    
    // must start by an SOA
        
    if(rr->tctr.qtype == TYPE_SOA)
    {
        ret = rr_soa_get_serial(rr->rdata, rr->rdata_size, &ixfrinc->serial_from);
    }
    else
    {
        ret = ZDB_JOURNAL_SOA_RECORD_EXPECTED;
    }
    
    ixfrinc->size = 0;
    
    if(ISOK(ret))
    {
        for(int idx = 0;; ++idx)
        {
#if DEBUG
            log_debug2("cjf: ---: %4i: %{dnsrr}", idx, rr); 
#endif
            dns_resource_record_write(rr, baos);

            if((ret = dns_resource_record_read(rr, ixfr_wire_is)) <= 0)
            {
                if(ret == 0)
                {
                    if(!need_another_soa)
                    {
                        ixfrinc->size = bytearray_output_stream_size(baos);
#if DEBUG
                        log_debug2("cjf: ===: IXFR incremental change size: %i", ixfrinc->size);
#endif
                        ret = ixfrinc->size;
                    }
                    else
                    {
#if DEBUG
                        log_debug2("cjf: ===: still expected an SOA");
#endif
                        // SOA expected
                        ret = ZDB_JOURNAL_SOA_RECORD_EXPECTED;
                    }
                    
                    ixfrinc->eof = TRUE;
                }
                else
                {
#if DEBUG
                    log_debug2("cjf: ===: failed to read the next record: %r", ret);
#endif
                }
                
                break;
            }
            
            if(rr->tctr.qtype == TYPE_SOA)
            {
                if(need_another_soa)
                {
                    if(FAIL(ret = rr_soa_get_serial(rr->rdata, rr->rdata_size, &ixfrinc->serial_to)))
                    {
#if DEBUG
                        log_debug2("cjf: ===: failed parse serial from record: %r", ret);
#endif
                        break;
                    }
                    
                    need_another_soa = FALSE;
                }
                else
                {
                    // another page starts here
                    // this record will written for the next page
                    
                    ixfrinc->size = bytearray_output_stream_size(baos);
#if DEBUG
                    log_debug2("cjf: ===: IXFR incremental change size: %i (followed ...)", ixfrinc->size);
#endif
                    ret = ixfrinc->size;
                    break;
                }
            }
        }
    }
    
    return ret;
}

/**
 * The caller will take action that will end up removing the first page.
 * Either explicitly, either overwriting it (ie: looping).
 * 
 * This function ensures that it's OK to do so.
 * 
 * Returns:
 * 
 * 0 if it's OK to do so, and no actions were taken,
 * 1 if it's OK to do so, but the zone needed to be stored
 * or an error code.
 * 
 * @param jnl
 * 
 * @return the state of the operation
 * 
 */

static ya_result
journal_cjf_append_ixfr_stream_first_page_removal(journal_cjf *jnl)
{
    // the caller will remove first page to make room, prepare for it
    
    ya_result ret;
    u32 zone_stored_serial;
    
    // get the serial of the stored zone

    if(FAIL(ret = zdb_zone_info_get_stored_serial(jnl->origin, &zone_stored_serial)))
    {
        log_warn("cjf: %{dnsname}: could not get the serial of the stored zone: %r", jnl->origin, ret);
        return ret;
    }
    
    u8 zt = 0;
    if(ISOK(zdb_zone_info_get_zone_type(jnl->origin, &zt)))
    {
        if(zt == ZT_SLAVE)
        {
            u32 ts = jnl->zone->axfr_timestamp;
            u32 sr = jnl->zone->axfr_serial;
            if(ts > 1)
            {
                if(serial_gt(sr, zone_stored_serial))
                {
                    zone_stored_serial = sr;
                }
            }
        }
    }
    
    // get the page of the serial

    if(FAIL(ret = journal_cjf_idxt_get_page_offset_from_serial(jnl, zone_stored_serial, NULL)))
    {
        if(serial_le(jnl->serial_end, zone_stored_serial))
        {
            log_debug("cjf: %{dnsname}: no need to store the zone again as it's already %i steps further", jnl->origin, zone_stored_serial - jnl->serial_end);
            return 0;
        }
        else
        {
            log_warn("cjf: %{dnsname}: could not get page of serial %u: %r", jnl->origin, zone_stored_serial, ret);
            return ret;
        }
    }

    // ret is the index of the page, if it is 0 we may need to save the current zone

    bool need_to_store_before_removing_first_page = (ret == 0);
    
    log_debug("cjf: %{dnsname}: zone currently stored up to serial %i, located on page %i of the journal", jnl->origin, zone_stored_serial, ret);
    
    if(need_to_store_before_removing_first_page)
    {
        // we are about to destroy the page of the currently stored serial AND
        // there are steps remaining to be safe

        log_warn("cjf: %{dnsname}: need to store the zone right now, consider increasing the journal size", jnl->origin);

        zdb_zone *zone = (zdb_zone*)jnl->zone;

        // the zone at this point is supposed to be locked
        // either simply with a simple reader
        // either doubly with something and a simple reader
        // if simply : do nothing
        // if doubly : with the simple reader : exchange them
        //             with anything else : it cannot ever work

        u8 owner = zone->lock_owner;
        u8 reserved_owner = zone->lock_reserved_owner;
        if(owner == ZDB_ZONE_MUTEX_SIMPLEREADER)
        {
            zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
            ret = zdb_zone_info_store_locked_zone(jnl->origin);
            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
        }
        else if(owner == ZDB_ZONE_MUTEX_NOBODY)
        {
            zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
            ret = zdb_zone_info_store_locked_zone(jnl->origin);
            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
        }
        else if(reserved_owner == ZDB_ZONE_MUTEX_SIMPLEREADER)
        {   
            zdb_zone_exchange_locks(zone, owner, ZDB_ZONE_MUTEX_SIMPLEREADER);
            ret = zdb_zone_info_store_locked_zone(jnl->origin);
            zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, owner);
        }
        else
        {
            ret = ERROR; // obsolete
        }

        if(FAIL(ret))
        {
            log_warn("cjf: %{dnsname}: cannot store the zone: %r", jnl->origin, ret);
            return ret;
        }

        return 1; // try again
    }
    else
    {
        return 0; // continue
    }
}

static s64 journal_cjf_get_space_left_until_need_storage_page(journal_cjf *jnl)
{
    ya_result ret;
    u32 zone_stored_serial;
    
    if(FAIL(ret = zdb_zone_info_get_stored_serial(jnl->origin, &zone_stored_serial)))
    {
        log_warn("cjf: %{dnsname}: could not get teh serial of the stored zone: %r", jnl->origin, ret);
        
        // save asap
        
        return 0;
    }
    
    u8 zt = 0;
    if(ISOK(zdb_zone_info_get_zone_type(jnl->origin, &zt)))
    {
        if(zt == ZT_SLAVE)
        {
            u32 ts = jnl->zone->axfr_timestamp;
            u32 sr = jnl->zone->axfr_serial;
            if(ts > 1)
            {
                if(serial_gt(sr, zone_stored_serial))
                {
                    zone_stored_serial = sr;
                }
            }
        }
    }
    
    // get the page of the serial

    if(FAIL(ret = journal_cjf_idxt_get_page_offset_from_serial(jnl, zone_stored_serial, NULL)))
    {
        if(serial_le(jnl->serial_end, zone_stored_serial))
        {
            log_debug("cjf: %{dnsname}: no need to store the zone again as it's already %i steps further", jnl->origin, zone_stored_serial - jnl->serial_end);
            
            // the journal is only there for the slaves, it could be completely replaced
            
            return jnl->file_maximum_size;
        }
        else
        {
            log_warn("cjf: %{dnsname}: could not get page of serial %u: %r", jnl->origin, zone_stored_serial, ret);
            
            // save asap
            
            return 0;
        }
    }
    
    const journal_cjf_idxt_tbl_item* need_storage = journal_cjf_idxt_get_entry(jnl, ret);
    
    if(jnl->last_page.file_offset == need_storage->file_offset)
    {
        // we are on the page : we basically have the size of our page minus the file size
        
        return MAX((s32)(jnl->file_maximum_size - (jnl->last_page.records_limit - jnl->last_page.file_offset)), 0);
    }
    else if(jnl->last_page.file_offset < need_storage->file_offset)
    {
        // we have everything until that page
        
        return MAX((s32)(need_storage->file_offset - jnl->last_page.records_limit), 0);
    }
    else // if(jnl->last_page.file_offset > need_storage->file_offset)
    {
        // we have the remaining space until the end of the file plus the offset of the page (minus the header)
        
        return MAX((s32)(jnl->file_maximum_size - jnl->last_page.records_limit), 0) + need_storage->file_offset;
    }    
}

static ya_result
journal_cjf_append_ixfr_stream_per_page(journal *jh, input_stream *ixfr_wire_is, bool is_slave)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    ya_result ret;
    
    log_debug("cjf: %s,%p: append IXFR (master)", jnl->journal_file_name, jnl->file);
    
    // ensure the zone locks are usable : locked by the reader, by nobody, or the reader is a reserved owner
    if(jnl->zone != NULL)
    {
        zdb_zone *zone = (zdb_zone*)jnl->zone;
        u8 owner = zone->lock_owner;
        u8 reserved_owner = zone->lock_reserved_owner;
        if(
                !(
                (owner == ZDB_ZONE_MUTEX_SIMPLEREADER) ||
                (owner == ZDB_ZONE_MUTEX_NOBODY) ||
                (reserved_owner == ZDB_ZONE_MUTEX_SIMPLEREADER)
                )
            )
        {
            log_err("cjf: %s,%p: append IXFR (master) cannot happen because the zone locks are not set properly", jnl->journal_file_name, jnl->file);
            return ERROR;
        }
    }
    
    int written_pages = 0;
    
    dns_resource_record rr;    
    dns_resource_record_init(&rr);
    
    output_stream os;
    output_stream_set_void(&os); // very important
    
    journal_cjf_read_ixfr_s ixfrinc;
    journal_cjf_read_ixfr_init(&ixfrinc, ixfr_wire_is);
    
    journal_cjf_writelock(jnl);

    for(;;)
    {
        ret = journal_cjf_read_ixfr_read(&ixfrinc);
        
        if(ret <= 0)
        {
            journal_cjf_page_output_stream_cancel(&os);
            
            if(ret == 0)
            {
                log_info("cjf: %{dnsname}: no incremental changes remaining", jnl->origin);
            }
            else
            {
                log_err("cjf: %{dnsname}: failed to read changes: %r", jnl->origin, ret);
            }
            break;
        }
        
        // else records have been read
        
        yassert((ixfrinc.serial_from == ixfrinc.serial_to) || (ixfrinc.size != 0));
        
        log_info("cjf: %{dnsname}: incremental changes read from %u to %u (%u bytes)", jnl->origin, ixfrinc.serial_from, ixfrinc.serial_to, ixfrinc.size);
        
        bool journal_is_empty = journal_cjf_isempty(jnl);
        
        if(!journal_is_empty)
        {
            // if the journal is not empty, ensure the page follows the last journal page
            
            if(serial_lt(ixfrinc.serial_from, jnl->serial_end))
            {
                log_info("cjf: %{dnsname}: ignoring changes before serial %u", jnl->origin, jnl->serial_end);
                
                continue;   // read next page
            }
            else if(serial_gt(ixfrinc.serial_from, jnl->serial_end))
            {
                log_warn("cjf: %{dnsname}: missing changes between serials %u and %u", jnl->origin, jnl->serial_end, ixfrinc.serial_from);
                
                break;      // full stop
            }
        }
        else
        {
            // create a journal with one entry
            
            journal_cjf_idxt_create(jnl, 1);
        }
        
        /***/
        
        // reserve the known size of this single page with the serial range
        // write the page
        
        /***/
        
journal_cjf_append_ixfr_stream_master_accum_tryagain:
        
        journal_cjf_page_output_stream_reopen(&os, jnl);
        
        // the file is cycling, so we also need to see if we are writing at
        // a position before the first page's and thus risking to overwrite it
        
        s64 available = 0;
        
        while(journal_cjf_page_current_output_stream_may_overwrite(jnl))
        {
            // if total available is smaller than half the file, the division will be >= 2
            
            s64 total_available = journal_cjf_get_space_left_until_need_storage_page(jnl);
            
            // should not store in background. Handle it first-hand (maybe postpone the update) ... (obsolete)
            
            if( ((total_available > 0) && ((jnl->file_maximum_size / total_available) >= 2)) || (total_available == 0))
            {
                // if not writing already, then write
                // 0 = not saving, 1 = saving, <0 = error
                if(zdb_zone_info_background_store_in_progress(jnl->origin) != 1)
                {
                    zdb_zone_info_background_store_zone(jnl->origin);
                }
            }
            
            available = jnl->first_page_offset - jnl->last_page.records_limit;

            if(available >= ixfrinc.size)
            {
                log_debug("cjf: %{dnsname}: %lli >= %i storage available before overwriting the first page", jnl->origin, available, ixfrinc.size);
                break;
            }
            
            if(FAIL(ret = journal_cjf_append_ixfr_stream_first_page_removal(jnl)))
            {
                break;
            }
            
            if(ret == 1)
            {
                continue;
            }

            journal_cjf_remove_first_page(jnl);
        } // while may overwrite
        
        if(FAIL(ret))
        {
            journal_cjf_page_output_stream_cancel(&os);
            break;
        }
        
        // available space between the first available byte to write records and
        // the file size limit
        
        if(!journal_cjf_page_current_output_stream_may_overwrite(jnl))
        {
            s64 total_available = journal_cjf_get_space_left_until_need_storage_page(jnl);
            
            if( ((total_available > 0) && ((jnl->file_maximum_size / total_available) >= 2)) || (total_available == 0))
            {
                // if not writing already, then write
                // 0 = not saving, 1 = saving, <0 = error
                if(zdb_zone_info_background_store_in_progress(jnl->origin) != 1)
                {
                    zdb_zone_info_background_store_zone(jnl->origin);
                }
            }
            
            // space available until the current limit of the page (file size or first page offset)
            available = journal_cjf_get_last_page_available_space_left(jnl);
            
            if(available >= ixfrinc.size)
            {
                log_debug("cjf: %{dnsname}: %lli >= %i storage available in this page", jnl->origin, available, ixfrinc.size);
            }
            else
            {
                // not enough room, but can we handle it ?
                //
                // if there is only one NON-EMPTY page in the journal,
                //    cut it and create a new one
                // if there are at least two NON-EMPTY pages and the available space between them is big enough,
                //    cut the last page
                //    remove the first 
                // else just complain about the journal size and continue
                
                int page_count = journal_cjf_idxt_get_page_count(jnl);
                bool last_page_empty = journal_cjf_page_line_count(jnl) == 0;
                
                yassert(page_count > 0);
                
                if(page_count == 1)
                {
                    if(!last_page_empty)
                    {
                        log_debug("cjf: %{dnsname}: one page: append another page", jnl->origin);
                        
                        // cut and proceed, as we will probably want to roll on the next update
                        
                        journal_cjf_page_output_stream_cancel(&os);
                        journal_cjf_idxt_append_page(jnl);
                        output_stream_close(&os);
                        output_stream_set_void(&os); // very important
                        
                        //journal_cjf_page_output_stream_reopen(&os, jnl);
                        
                        // and loop
                        
                        ret = SUCCESS;
                        
                        goto journal_cjf_append_ixfr_stream_master_accum_tryagain;
                    }
                    else
                    {
                        log_debug("cjf: %{dnsname}: one empty page: write on it", jnl->origin);
                        // just proceed
                    }
                }
                else
                {
                    if(!last_page_empty)
                    {
                        u32 available_from_beginning = jnl->last_page.file_offset - CJF_PAGE_SIZE_IN_BYTE - CJF_HEADER_SIZE;
                        
                        if(ixfrinc.size <= available_from_beginning)
                        {
                            // for a slave only, ensure the journal has been read before going further.
                            
                            if(is_slave)
                            {
                                // page_count > 1
                                
                                u32 page_1_serial_from = journal_cjf_idxt_get_page_serial_from_index(jnl, 1);
                                u32 starting_zone_serial = page_1_serial_from - 1;
                                zdb_zone_lock((zdb_zone*)jnl->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                                /*ret = */zdb_zone_getserial((zdb_zone*)jnl->zone, &starting_zone_serial); // zone is locked
                                zdb_zone_unlock((zdb_zone*)jnl->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                                // compare with start serial of second page
                                if(serial_lt(starting_zone_serial, page_1_serial_from))
                                {
                                    // cutting the first page will break continuity :stop reading IXFR now, apply the journal and try later.
                                    journal_cjf_page_output_stream_cancel(&os);
                                    goto journal_cjf_append_ixfr_stream_master_accum_exit;
                                }
                            }
                            
                            log_debug("cjf: %{dnsname}: %u of %u bytes available on a loop: loop", jnl->origin, available_from_beginning, ixfrinc.size);
                            
                            // cutting now will allow to loop
                            
                            if(FAIL(ret = journal_cjf_append_ixfr_stream_first_page_removal(jnl)))
                            {
                                // could not remove first page
                                break;
                            }
                            
                            journal_cjf_page_output_stream_cancel(&os);
                            u32 tmp = jnl->file_maximum_size;
                            jnl->file_maximum_size = 0; // force the loop (thus removing the first page)
                            journal_cjf_idxt_append_page(jnl);
                            jnl->file_maximum_size = tmp;
                            output_stream_close(&os);
                            output_stream_set_void(&os); // very important
                            journal_cjf_page_output_stream_reopen(&os, jnl);
                        }
                        else
                        {
                            log_debug("cjf: %{dnsname}: %u/%u bytes available on a loop: continue", jnl->origin, available_from_beginning, ixfrinc.size);
                                    
                            // do a cut to allow to loop soon

                            journal_cjf_page_output_stream_cancel(&os);
                            u32 tmp = jnl->file_maximum_size;
                            jnl->file_maximum_size = MAX_U32;
                            journal_cjf_idxt_append_page(jnl);
                            jnl->file_maximum_size = tmp;
                            output_stream_close(&os);
                            output_stream_set_void(&os); // very important
                            journal_cjf_page_output_stream_reopen(&os, jnl);
                        }
                    }
                    else
                    {
                        // just proceed
                        log_debug("cjf: %{dnsname}: last page is empty: write on it", jnl->origin);
                    }
                }
            }
        }
        
        // write the ixfr increment in the page
        
        input_stream bais;
        bytearray_input_stream_init_const(&bais, bytearray_output_stream_buffer(&ixfrinc.baos), bytearray_output_stream_size(&ixfrinc.baos));
        for(;;)
        {
            if((ret = dns_resource_record_read(&rr, &bais)) <= 0)
            {
                if(ret != 0)
                {
                    log_err("cjf: %{dnsname}: error re-reading record: %r", jnl->origin, ret);
                }
                break;
            }
            
#if DEBUG
            log_debug("cjf: %{dnsname}: writing %{dnsrr}", jnl->origin, &rr);
#endif
            
            if(FAIL(ret = journal_cfj_page_output_stream_write_resource_record(&os, &rr)))
            {
                log_err("cjf: %{dnsname}: could not store record: %r", jnl->origin, ret);
                break;
            }
        }
        input_stream_close(&bais);
        
        if(ISOK(ret))
        {
            if(journal_is_empty)
            {
                jnl->serial_begin = ixfrinc.serial_from;
                journal_cjf_clear_empty(jnl);
            }
            
            jnl->serial_end = ixfrinc.serial_to;
            journal_cjf_set_dirty(jnl);
            
            ++written_pages;
            journal_cjf_page_output_stream_next(&os);
            
            // if we wrote records after the expected position for the IDXT, move the IDXT position
            
            if(jnl->last_page.records_limit > jnl->page_table_file_offset)
            {
                jnl->page_table_file_offset = jnl->last_page.records_limit;
                jnl->idxt.dirty = TRUE;
                journal_cjf_set_dirty(jnl);
            }
        }
        else
        {
            journal_cjf_page_output_stream_cancel(&os);
            break;
        }
    }

journal_cjf_append_ixfr_stream_master_accum_exit:
    if(os.data != NULL)
    {
        output_stream_close(&os);
    }
    
    journal_cjf_read_ixfr_finalize(&ixfrinc);
    dns_resource_record_clear(&rr);
    
    if(written_pages > 0)
    {
        journal_cjf_page_cache_flush(jnl->file);
        journal_cjf_header_flush(jnl);
    }
        
    journal_cjf_writeunlock(jnl);
    
    if(ISOK(ret))
    {
        log_info("cjf: %{dnsname}: added %i incremental changes to the journal", jnl->origin, written_pages);
        ret = TYPE_IXFR;
    }
    else
    {
        log_err("cjf: %{dnsname}: append IXFR (master) failed with: %r", jnl->origin, ret);
    }
    
    return ret;
}

static ya_result
journal_cjf_append_ixfr_stream(journal *jh, input_stream *ixfr_wire_is)
{
    u8 zt;
    journal_cjf *jnl = (journal_cjf*)jh;
    ya_result ret = zdb_zone_info_get_zone_type(jnl->origin, &zt);
    if(ISOK(ret))
    {
        switch(zt)
        {
            case ZT_MASTER:
                ret = journal_cjf_append_ixfr_stream_per_page(jh, ixfr_wire_is, FALSE);
                break;
            case ZT_SLAVE:
                ret = journal_cjf_append_ixfr_stream_per_page(jh, ixfr_wire_is, TRUE);
                break;
            default:
                ret = ERROR; // obsolete
                break;
        }
    }
    return ret;
}

/******************************************************************************
 *
 * Journal Input Stream
 * This one returns and IXFR stream
 *  
 ******************************************************************************/

#define JCJFISDT_TAG 0x54445349464a434a

struct journal_cjf_input_stream_data
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

typedef struct journal_cjf_input_stream_data journal_cjf_input_stream_data;

static ya_result
journal_cjf_input_stream_read(input_stream* stream, void *buffer_, u32 len)
{
    journal_cjf_input_stream_data *data = (journal_cjf_input_stream_data*)stream->data;
    u8 *buffer = (u8*)buffer_;
    const u8 *base = buffer;
    const u8 *limit = &buffer[len];
    intptr n;
    ya_result ret = 0;
    
    journal_cjf *jnl = data->jnl;
    
    log_debug("cjf: %s,%p: input: reading %u/%u bytes, pos is %lli", jnl->journal_file_name, jnl->file,
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

            u32 page_offset = journal_cjf_idxt_get_file_offset(data->jnl, data->idxt_index);
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
                
                if(FAIL(ret = journal_cjf_page_get_stream_offset_from_serial(data->jnl, data->idxt_index, data->serial_from, &stream_offset)))
                {
                    return ret;
                }
                
                data->first_stream = FALSE;
            }
            
            journal_cjf_page_tbl_header page_header;
            journal_cjf_page_cache_read_header(data->jnl->file, page_offset, &page_header);
            
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
                journal_cjf_page_cache_read_header(data->jnl->file, page_offset, &page_header);
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
journal_cjf_input_stream_skip(input_stream* is, u32 len)
{
    u8 tmp[512];
    
    journal_cjf_input_stream_data *data = (journal_cjf_input_stream_data*)is->data;
    journal_cjf *jnl = data->jnl;
    log_debug("cjf: %s,%p: input: skipping %u bytes", jnl->journal_file_name, jnl->file, len);
    
    while(len > 0)
    {
        ya_result ret;
        u32 n = MIN(len, sizeof(tmp));
        if(FAIL(ret = journal_cjf_input_stream_read(is, tmp, n)))
        {
            return ret;
        }
        
        len -= n;
    }

    return len;
}

static void
journal_cjf_input_stream_close(input_stream* is)
{
    journal_cjf_input_stream_data *data = (journal_cjf_input_stream_data*)is->data;
    
    log_debug("cjf: %s,%p: input: close (%p)", data->jnl->journal_file_name, data->jnl->file, data->file);
    journal_cjf_readunlock(data->jnl);
    journal_cjf_release(data->jnl);
    file_pool_close(data->file);
    ZFREE_OBJECT(data);
    
    input_stream_set_void(is);    
}

static const input_stream_vtbl journal_cjf_input_stream_vtbl =
{
    journal_cjf_input_stream_read,
    journal_cjf_input_stream_skip,
    journal_cjf_input_stream_close,
    "journal_cjf_input_stream"
};

/*
 * the last_soa_rr is used for IXFR transfers (it has to be a prefix & suffix to the returned stream)
 */

static ya_result
journal_cjf_get_ixfr_stream_at_serial(journal *jh, u32 serial_from, input_stream *out_input_stream, dns_resource_record *out_last_soa_rr)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    
    log_debug("cjf: %s,%p: get IXFR stream at serial %i", jnl->journal_file_name, jnl->file, serial_from);

    journal_cjf_readlock(jnl);
    
    if(serial_lt(serial_from, jnl->serial_begin) || serial_ge(serial_from, jnl->serial_end))
    {
        if(serial_from == jnl->serial_end)
        {
            log_debug("cjf: %s,%p: the journal ends at %i, returning empty stream", jnl->journal_file_name, jnl->file, serial_from);
            journal_cjf_readunlock(jnl);
            empty_input_stream_init(out_input_stream);
            return SUCCESS; // 0
        }
        else
        {
            log_debug("cjf: %s,%p: the journal ends at %i, returning empty stream", jnl->journal_file_name, jnl->file, serial_from);
            journal_cjf_readunlock(jnl);
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
    
    if(FAIL(ret = journal_cjf_idxt_get_page_index_from_serial(jnl, serial_from)))
    {
        journal_cjf_readunlock(jnl);
        
        return ret;
    }
    
    yassert(ret < MAX_U16);
    
    u16 idxt_index = (u16)ret;
        
    journal_cjf_input_stream_data *data;
    ZALLOC_OBJECT_OR_DIE(data, journal_cjf_input_stream_data, JCJFISDT_TAG);
    journal_acquire((journal*)jnl);
    data->jnl = jnl;
    
    data->file = file_pool_open_ex(journal_file_pool, jnl->journal_file_name, O_RDONLY|O_CLOEXEC, 0660);
    
    if(data->file == NULL)
    {
        // the journal doess not exist (anymore ?)
        ZFREE_OBJECT(data);
        
        journal_cjf_readunlock(jnl);
        journal_cjf_release(jnl);
        
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
            journal_cjf_readunlock(jnl);
            journal_cjf_release(jnl);
            
            log_err("cjf: %s,%p: unable to read the SOA for serial %u at position %u: %r", jnl->journal_file_name, jnl->file, serial_from, jnl->last_soa_offset, ret);
            ZFREE_OBJECT(data);
            return ret;
        }
    }
    
    data->idxt_index = idxt_index;
    data->idxt_size = jnl->idxt.count;
    data->available = 0;
    
    data->first_stream = TRUE;
        
    out_input_stream->data = data;
    out_input_stream->vtbl = &journal_cjf_input_stream_vtbl;
        
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
journal_cjf_get_first_serial(journal *jh, u32 *serial)
{
    ya_result ret = BUFFER_WOULD_OVERFLOW;
    journal_cjf *jnl = (journal_cjf*)jh;
    
    journal_cjf_readlock(jnl);
    
    u32 value = jnl->serial_begin;
    
    if(serial != NULL)
    {
        *serial = value;
        ret = SUCCESS;
    }
    
    journal_cjf_readunlock(jnl);
    
    log_debug("cjf: %s,%p: get first serial: %i", jnl->journal_file_name, jnl->file, value);
    
    return ret;
}

static ya_result
journal_cjf_get_last_serial(journal *jh, u32 *serial)
{
    ya_result ret = BUFFER_WOULD_OVERFLOW;
    journal_cjf *jnl = (journal_cjf*)jh;
    
    journal_cjf_readlock(jnl);
    
    u32 value = jnl->serial_end;
    
    if(serial != NULL)
    {
        *serial = value;
        ret = SUCCESS;
    }
    
    log_debug("cjf: %s,%p: get last serial: %i", jnl->journal_file_name, jnl->file, value);

    journal_cjf_readunlock(jnl);
    
    return ret;
}

static ya_result
journal_cjf_get_serial_range(journal *jh, u32 *serial_start, u32 *serial_end)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    
    journal_cjf_readlock(jnl);
    
    if(serial_start != NULL)
    {
        *serial_start = jnl->serial_begin;
    }
    if(serial_end != NULL)
    {
        *serial_end = jnl->serial_end;
    }
    
    journal_cjf_readunlock(jnl);
    
    return SUCCESS;
}

static ya_result
journal_cjf_truncate_to_size(journal *jh, u32 size_)
{
    journal_cjf *jnl = (journal_cjf*)jh;

    if(size_ == 0)
    {
        journal_cjf_writelock(jnl);
        
        log_debug("cjf: %s,%p: truncate to size 0", jnl->journal_file_name, jnl->file);
       
        if(jnl->file == NULL)
        {
            journal_cjf_page_cache_close(jnl->file);
            file_pool_close(jnl->file);
            jnl->file = NULL;
        }
        file_pool_unlink_from_pool_and_filename(journal_file_pool, jnl->journal_file_name);

        jnl->idxt.dirty = FALSE;
        journal_cjf_idxt_destroy(jnl);

        jnl->file_maximum_size = MAX_U32;
        if(jnl->zone != NULL)
        {
            jnl->file_maximum_size = jnl->zone->wire_size >> 1;
            zdb_zone_info_get_zone_max_journal_size(jnl->origin, &jnl->file_maximum_size);
        }
        
        jnl->file = NULL;
            
        jnl->last_page.file_offset = CJF_HEADER_SIZE;
        jnl->last_page.count = 0;
        jnl->last_page.size = CJF_SECTION_INDEX_SLOT_COUNT;
        jnl->last_page.serial_start = 0;
        jnl->last_page.serial_end = 0;
        jnl->last_page.records_limit = CJF_HEADER_SIZE + CJF_SECTION_INDEX_SIZE;
        jnl->last_page.file_offset_limit = jnl->file_maximum_size;

        jnl->serial_begin = 0;
        jnl->serial_end = 0;            
        jnl->first_page_offset = CJF_HEADER_SIZE;
        jnl->page_table_file_offset = 0;
        jnl->last_soa_offset = 0;
        //jnl->file_maximum_size = MAX_U32;

        //jnl->mtx.owner = LOCK_NONE;
        //jnl->mtx.count = 0;

        jnl->flags = JOURNAL_CFJ_FLAGS_MY_ENDIAN;

        jnl->last_page.records_limit = jnl->last_page.file_offset + CJF_SECTION_INDEX_SIZE;
        jnl->last_page.file_offset_limit = jnl->file_maximum_size;

        //jnl->journal_file_name = strdup(filename);
        
        journal_cjf_writeunlock(jnl);

        return SUCCESS;
    }
    else
    {    
        log_err("cjf: %s,%p: truncate to size != 0 not implemented", jnl->journal_file_name, jnl->file);
        
        return ZDB_JOURNAL_FEATURE_NOT_SUPPORTED;
    }
}

static ya_result
journal_cjf_truncate_to_serial(journal *jh, u32 serial_)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    (void)serial_;
    journal_cjf_readlock(jnl);
    log_err("cjf: %s,%p: truncate to serial not implemented", jnl->journal_file_name, jnl->file);
    journal_cjf_readunlock(jnl);
    
    return ZDB_JOURNAL_FEATURE_NOT_SUPPORTED;
}

/**
 * 
 * @param jnl
 * @return 
 */

static ya_result
journal_cjf_reopen(journal *jh)
{
#if 0 /* fix */
#else
    return SUCCESS;
#endif
}

static void
journal_cjf_flush(journal *jh)
{
    journal_cjf *jnl = (journal_cjf*)jh;

    log_debug("cjf: %s,%p: flush", jnl->journal_file_name, jnl->file);
    
    journal_cjf_writelock(jnl);
    
#if ZDB_ZONE_HAS_JNL_REFERENCE
    zdb_zone *zone;
    if((zone = (zdb_zone*)jnl->zone) != NULL)
    {
        yassert(zone->journal == jh);
        zone->journal = NULL;
    }
#endif
    
    log_debug3("cjf: %s,%p: flushing to file", jnl->journal_file_name, jnl->file);
    
    log_debug3("cjf: %s,%p: flushing to file: flushing PAGE cache", jnl->journal_file_name, jnl->file, jnl->journal_file_name);
    journal_cjf_page_cache_flush(jnl->file);
    log_debug3("cjf: %s,%p: flushing to file: flushing IDXT", jnl->journal_file_name, jnl->file, jnl->journal_file_name);
    journal_cjf_idxt_flush(jnl);
    log_debug3("cjf: %s,%p: flushing to file: flushing header", jnl->journal_file_name, jnl->file, jnl->journal_file_name);
    journal_cjf_header_flush(jnl);
    
    journal_cjf_writeunlock(jnl);
}

static ya_result
journal_cjf_close(journal *jh)
{
    journal_cjf *jnl = (journal_cjf*)jh;

    log_debug("cjf: %s,%p: close", jnl->journal_file_name, jnl->file);
    
    journal_cjf_writelock(jnl);
    
#if ZDB_ZONE_HAS_JNL_REFERENCE
    zdb_zone *zone;
    if((zone = (zdb_zone*)jnl->zone) != NULL)
    {
        yassert(zone->journal == jh);
        zone->journal = NULL;
    }
#endif
    
    log_debug3("cjf: %s,%p: closing file", jnl->journal_file_name, jnl->file);
    
    if(jnl->file != NULL)
    {
        log_debug3("cjf: %s,%p: closing file: closing PAGE cache", jnl->journal_file_name, jnl->file, jnl->journal_file_name);
        journal_cjf_page_cache_close(jnl->file);
        log_debug3("cjf: %s,%p: closing file: flushing IDXT", jnl->journal_file_name, jnl->file, jnl->journal_file_name);
        journal_cjf_idxt_flush(jnl);
        log_debug3("cjf: %s,%p: closing file: flushing header", jnl->journal_file_name, jnl->file, jnl->journal_file_name);
        journal_cjf_header_flush(jnl);
        log_debug3("cjf: %s,%p: closing file: closing file", jnl->journal_file_name, jnl->file, jnl->journal_file_name);
        
        journal_cjf_idxt_destroy(jnl);
        
        if(jnl->zone != NULL)
        {
            log_info("zone: %{dnsname}: closing journal file '%s'", jnl->origin, jnl->journal_file_name);
        }
        else
        {
            log_info("zone: <notset>: closing journal file '%s'", jnl->journal_file_name);
        }
        
        file_pool_close(jnl->file);
        jnl->file = NULL;
    }
    
    journal_cjf_writeunlock(jnl);

    return SUCCESS;
}

static void
journal_cjf_log_dump(journal *jh)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    journal_cjf_readlock(jnl);
    log_debug("cjf: %s,%p: [%u; %u] '%s' (%i) lck=%i rc=%i", jnl->journal_file_name, jnl->file, jnl->serial_begin, jnl->serial_end, jnl->journal_file_name, jnl->file, jnl->mtx.owner, jnl->mtx.count);
    journal_cjf_readunlock(jnl);
}

static ya_result
journal_cjf_get_domain(journal *jh, u8 *out_domain)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    
    // don't: journal_cjf_readlock(jnl); as the field is constant until the destruction of the journal

    dnsname_copy(out_domain, jnl->origin);
    return SUCCESS;
}

/**
 * Links a zdb_zone and a journal
 * 
 * @param jh
 * @param zone
 */

static void
journal_cjf_link_zone(journal *jh, zdb_zone *zone)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    
    journal_cjf_writelock(jnl);
        
    if(jnl->zone != zone)
    {
        jnl->file_maximum_size = MAX_U32;
        
#if !ZDB_ZONE_HAS_JNL_REFERENCE
        if(jnl->zone != NULL)
        {
            log_debug("cjf: %s,%p: unlinking zone %{dnsname},%p", jnl->journal_file_name, jnl->file, jnl->zone->origin, jnl->zone);
            
            zdb_zone_release((zdb_zone*)jnl->zone); //jnl->zone = NULL;
        }
        
        if(zone != NULL)
        {
            zdb_zone_acquire(zone);
            
            log_debug("cjf: %s,%p: linking to zone %{dnsname},%p", jnl->journal_file_name, jnl->file, zone->origin, zone);
            
            jnl->file_maximum_size = zone->wire_size >> 1;
        }
#endif
        jnl->zone = zone;
        
        zdb_zone_info_get_zone_max_journal_size(jnl->origin, &jnl->file_maximum_size);
    
        jnl->last_page.file_offset_limit = jnl->file_maximum_size;
    }
    
    journal_cjf_writeunlock(jnl);
}

static void
journal_cjf_destroy(journal *jh)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    
    yassert(jnl->rc == 0);
    
    log_debug("cjf: %s,%p: destroy", jnl->journal_file_name, jnl->file);
    
    journal_cjf_link_zone(jh, NULL);
    
    shared_group_mutex_destroy(&jnl->mtx);
    free(jnl->origin);
    free(jnl->journal_file_name);
    
#if DEBUG    
    memset(jnl, 0xfe, sizeof(journal_cjf));
    jnl->mru = FALSE;
#endif
    
    ZFREE_OBJECT(jnl);
}

static const u8 *
journal_cjf_get_domain_const(journal *jh)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    return jnl->origin;
}

/*******************************************************************************
 * 
 * vtbl handling functions
 *
 ******************************************************************************/

struct journal_vtbl journal_cjf_vtbl =
{
    journal_cjf_get_format_name,
    journal_cjf_get_format_version,
    journal_cjf_reopen,
    journal_cjf_flush,
    journal_cjf_close,
    journal_cjf_append_ixfr_stream,
    journal_cjf_get_ixfr_stream_at_serial,
    journal_cjf_get_first_serial,
    journal_cjf_get_last_serial,
    journal_cjf_get_serial_range,
    journal_cjf_truncate_to_size,
    journal_cjf_truncate_to_serial,
    journal_cjf_log_dump,
    journal_cjf_get_domain,
    journal_cjf_destroy,
    journal_cjf_link_zone,
    journal_cjf_get_domain_const,
    JOURNAL_CLASS_NAME
};

ya_result
journal_cjf_load_index_table(journal *jh)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    
    // check if the index table (referencing all indexes)
    
    if(jnl->page_table_file_offset == 0)
    {
        // the table does not exist or is corrupted
        // it has to be read again
        // from first_index_offset the index list has to be followed to recreate it
        // if such table only contains one entry, it could probably be ignored in most cases
    }
    else
    {
        // seek and load the table
    }
    
    return -1;
}

static journal_cjf*
journal_cjf_alloc_default(const u8 *origin, const char *filename)
{
    journal_cjf *jnl;
    ZALLOC_OBJECT_OR_DIE(jnl, journal_cjf, JRNLCJF_TAG);
    ZEROMEMORY(jnl, sizeof(journal_cjf));
    jnl->vtbl = &journal_cjf_vtbl;
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
journal_cjf_open_file(journal **jhp, const char *filename, const u8* origin, bool create)
{
    // CFJ_PAGE_CACHE ->
    if(!journal_initialized)
    {
        journal_cjf_page_cache_init();
        
        shared_group_shared_mutex_init(&journal_shared_mtx);
        
        journal_file_pool = file_pool_init("journal-file-pool", 256);
        
        journal_initialized = TRUE;
    }
    
    journal_cjf *jnl = NULL;
    ya_result ret;
    
    if(file_exists(filename) || create)
    {
        // instantiate and open the journal
        
        ret = journal_cjf_init_from_file(&jnl, origin, filename, create);

        if(ISOK(ret))
        {
            yassert(jnl != NULL); // to help scan-build

            if(!((jnl->serial_begin == 0) && (jnl->serial_begin == jnl->serial_end))) // scan-build false-positive : if ISOK(ret) => jnl != NULL
            {
                journal_cjf_load_idxt(jnl);
            }
        }
        else
        {
            if(create)
            {
                log_err("cjf: %{dnsname}: failed to open %s: %r", origin, filename, ret);
            }
            else
            {
                log_debug("cjf: %{dnsname}: failed to open %s: %r", origin, filename, ret);
            }

            if(jnl != NULL)
            {
                journal_cjf_destroy((journal*)jnl);
#if DEBUG
                log_debug("cjf: %{dnsname}: journal file cannot be opened/created", origin);
#endif
            }
            
            return ZDB_ERROR_ICMTL_NOTFOUND;
        }
        
#if DEBUG
        log_debug("cjf: %{dnsname}: journal opened", origin);
#endif
        *jhp = (journal*)jnl;
        
        return SUCCESS;
    }
    else
    {
#if DEBUG
        log_debug("cjf: %{dnsname}: journal file not found", origin);
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
journal_cjf_open(journal **jhp, const u8* origin, const char *workingdir, bool create)
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
    log_debug("cjf: trying to open journal for %{dnsname} in '%s'", origin, workingdir);
#endif
    
    /* get the soa of the loaded zone */
        
    if(FAIL(ret = snformat(filename, sizeof(filename), CJF_WIRE_FILE_FORMAT, workingdir, origin)))
    {
#if DEBUG
        log_debug("cjf: %{dnsname}: journal file name is too long", origin);
#endif
        return ret;
    }
    
    ret = journal_cjf_open_file(jhp, filename, origin, create);
    
    return ret;
}

void
journal_cjf_finalize()
{
    journal_cjf_page_cache_finalize();
    file_pool_finalize(journal_file_pool);
}

#endif

/** @} */
