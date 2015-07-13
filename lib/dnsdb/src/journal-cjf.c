/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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

#define ZDB_JOURNAL_CODE 1

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

#include <dnscore/buffer_input_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/limited_input_stream.h>
#include <dnscore/empty-input-stream.h>
#include <dnscore/mutex.h>
#include <dnscore/serial.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/format.h>

#include <dnscore/ptr_set.h>
#include <dnscore/fdtools.h>

#include <dnscore/u32_set.h>
#include <dnscore/u64_set.h>
#include <dnscore/list-dl.h>

#include <dnscore/ctrl-rfc.h>

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/journal.h"
#include "dnsdb/zdb_types.h"
#include "dnsdb/xfr_copy.h"
#include "dnsdb/zdb-zone-path-provider.h"
#include "dnsdb/zdb_zone.h"


#define DEBUG_JOURNAL 1
#ifndef DEBUG
#undef DEBUG_JOURNAL
#define DEBUG_JOURNAL 0
#endif

#define CJF_CYCLING_ENABLED 1

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

/*
 *  MAGIC 'JCS' 0
 *  offset to next (0 until the section is closed and followed by a new one)
 *  list of last-serial + file_offset
 */


struct cjf_header // Cyclic Journal File
{
    u32 magic_plus_version;
    u32 serial_begin;
    u32 serial_end;
    u32 first_index_offset;
    u32 table_index_offset;
    //
    u32 last_soa_offset;
    u32 last_page_offset_next; // the byte after the last PAGE on the chain ends
    u16 flags;
    u8 __end_of_struct__;
};

typedef struct cjf_header cjf_header;

#define CJF_HEADER_REAL_SIZE offsetof(cjf_header,__end_of_struct__)
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

#define CJF_CJF0_MAGIC MAGIC4('C','J','F', 0x20) // ver 2.0

/**
 * There is a need of lockable 4K pages in an MRU that points back to their user
 * That's where the PAGE will be stored
 * I'm not sure of what the ratio between allowed FDs and allowed PAGE pages should be.
 */



static ptr_set journal_cjf_set = PTR_SET_ASCIIZ_EMPTY;
static mutex_t journal_cjf_set_mtx = MUTEX_INITIALIZER;

static shared_group_shared_mutex_t journal_shared_mtx;
static bool journal_shared_mtx_initialized = FALSE;

void
log_debug_jnl(journal_cjf *jnl, const char *text)
{
    log_debug4("cjf: %s,%i: %s: header SN=[%08x; %08x] F=%08x L=%08x dirty=%i empty=%i",
                jnl->journal_file_name, jnl->fd, text,
                jnl->serial_begin, jnl->serial_end,
                jnl->first_page_offset, jnl->page_table_file_offset,
                journal_cjf_is_dirty(jnl),
                journal_cjf_is_empty(jnl));
    
    s16 n = jnl->idxt.count;
    
    if(jnl->last_page.count == 0)
    {
        n--;
    }
    
    log_debug4("cjf: %s,%i: %s: idxt %3hi/%3hi [%3hi] dirty=%i marked=%i", 
        jnl->journal_file_name, jnl->fd, text,
        jnl->idxt.count, jnl->idxt.size, jnl->idxt.first, (jnl->idxt.dirty)?1:0, (jnl->idxt.marked)?1:0);
    
    log_debug4("cjf: %s,%i: %s: page: SN=[%08x; %08x] count=%3u size=%3u at=%08x next=%08x ... limit=%08x",
               jnl->journal_file_name, jnl->fd, text,
               jnl->last_page.serial_start, jnl->last_page.serial_end,
               jnl->last_page.count,jnl->last_page.size,
               jnl->last_page.file_offset, jnl->last_page.records_limit,
               jnl->last_page.file_offset_limit);
        
    for(s16 idx = 0; idx < n; idx++)
    {
        journal_cjf_idxt_tbl_item *item = &jnl->idxt.entries[(jnl->idxt.first + idx) % jnl->idxt.size];
        
        log_debug4("cjf: %s,%i: %s: idxt[%3i] = %08x %08x", jnl->journal_file_name, jnl->fd, text, idx, item->last_serial, item->file_offset);
    }
    
    if(jnl->last_page.count == 0)
    {
        journal_cjf_idxt_tbl_item *item = &jnl->idxt.entries[(jnl->idxt.first + n) % jnl->idxt.size];
        
        log_debug4("cjf: %s,%i: %s: idxt[%3i] =  [empty] %08x", jnl->journal_file_name, jnl->fd, text, n, item->file_offset);
    }    
}

static void
journal_cjf_writelock(journal_cjf *jnl)
{
    shared_group_mutex_lock(&jnl->mtx, GROUP_MUTEX_WRITE);
}

static void
journal_cjf_writeunlock(journal_cjf *jnl)
{
    shared_group_mutex_unlock(&jnl->mtx, GROUP_MUTEX_WRITE);
}

static void
journal_cjf_readlock(journal_cjf *jnl)
{
    shared_group_mutex_lock(&jnl->mtx, GROUP_MUTEX_READ);
}

static void
journal_cjf_readunlock(journal_cjf *jnl)
{
    shared_group_mutex_unlock(&jnl->mtx, GROUP_MUTEX_READ);
}

/**
 * 
 * Does NOT set the fd field in jnl
 * MUST return -1 in case of error
 * 
 * @param jnl
 * @param create
 * @return 
 */

static int
jnl_open_file(journal_cjf *jnl, bool create)
{
    const u8* origin = (jnl->zone)?jnl->zone->origin:(const u8*)"\004NULL"; // VALID
    log_debug3("cjf: %{dnsname},%i: opening%s %s", origin, jnl->fd, (create)?"/creating":"", jnl->journal_file_name);
    
    int flags = O_RDWR;
#ifdef O_NOATIME
    flags |= O_NOATIME;
#endif
    int fd;

    cjf_header hdr;

    if(create)
    {
        flags |= O_CREAT;

        fd = open_create_ex(jnl->journal_file_name, flags, 0644);

        if(fd >= 0)
        {
            hdr.magic_plus_version = CJF_CJF0_MAGIC;
            hdr.serial_begin = 0;
            hdr.serial_end = 0;
            hdr.first_index_offset = 0;
            hdr.table_index_offset = 0;
            hdr.last_soa_offset = 0,
            hdr.last_page_offset_next = 0;
            //hdr.last_page_item_count = 0;
            hdr.flags = JOURNAL_CFJ_FLAGS_MY_ENDIAN;

            writefully(fd, &hdr, CJF_HEADER_SIZE);
        }
        else
        {
            log_err("cjf: %s,%i: failed to create %s: %r", origin, jnl->fd, jnl->journal_file_name, ERRNO_ERROR);
        }
    }        
    else
    {
        fd = open_ex(jnl->journal_file_name, flags);
        
        if(fd < 0)
        {
            log_debug3("cjf: %s,%i: failed to open %s: %r", origin, jnl->fd, jnl->journal_file_name, ERRNO_ERROR);
        }
    }
    
    return fd;
}

bool
jnl_ensure_file_opened(journal_cjf *jnl, bool create)
{
    if(jnl->fd < 0)
    {
        journal_cjf_writelock(jnl);
        jnl->fd = jnl_open_file(jnl, create);
        int err = ERRNO_ERROR;
        journal_cjf_writeunlock(jnl);
        if(jnl->fd < 0)
        {
            if(create)
            {
                log_err("cjf: %s,%i: failed to open %s: %r", jnl->journal_file_name, jnl->fd, jnl->journal_file_name, err);
            }
            else
            {
                log_debug("cjf: %s,%i: failed to open %s: %r", jnl->journal_file_name, jnl->fd, jnl->journal_file_name, err);
            }
        }
    }
        
    return jnl->fd >= 0;
}


void
jnl_header_flush(journal_cjf *jnl)
{
    yassert(jnl->fd >= 0);
    
    if(journal_cjf_is_dirty(jnl))
    {
        log_debug("cjf: %s,%i: flushing header SN=[%08x; %08x] F=%08x T=%08x", jnl->journal_file_name, jnl->fd,
                jnl->serial_begin, jnl->serial_end, jnl->first_page_offset, jnl->page_table_file_offset);
        
        off_t pos;
        
        if((pos = lseek(jnl->fd, 4, SEEK_SET)) != 4)
        {
            log_err("cjf: %s,%i: failed to set file position: %lli instead of %i (%r)", jnl->journal_file_name, jnl->fd, pos, 4, ERRNO_ERROR);
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

        writefully(jnl->fd, &hdr.serial_begin, CJF_HEADER_SIZE - 4);
        
        journal_cjf_clear_dirty(jnl);
    }
}

static void
jnl_close_file(journal_cjf *jnl)
{
    log_debug3("cjf: %s,%i: closing file", jnl->journal_file_name, jnl->fd, jnl->journal_file_name);
    
    if(jnl->fd >= 0)
    {
        log_debug3("cjf: %s,%i: closing file: closing PAGE cache", jnl->journal_file_name, jnl->fd, jnl->journal_file_name);
        journal_cjf_page_cache_close(jnl->fd);
        log_debug3("cjf: %s,%i: closing file: flushing IDXT", jnl->journal_file_name, jnl->fd, jnl->journal_file_name);
        journal_cjf_idxt_flush(jnl);
        log_debug3("cjf: %s,%i: closing file: flushing header", jnl->journal_file_name, jnl->fd, jnl->journal_file_name);
        jnl_header_flush(jnl);
        log_debug3("cjf: %s,%i: closing file: closing file", jnl->journal_file_name, jnl->fd, jnl->journal_file_name);
        close_ex(jnl->fd);
        jnl->fd = -1;
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
    if(ISOK(zdb_zone_info_get_zone_type(jnl->zone->origin, &zt)))
    {
        if(zt == ZT_MASTER)
        {
            zdb_zone_info_get_stored_serial(jnl->zone->origin, &stored_serial);
    
            if(serial_le(stored_serial, jnl->serial_begin))
            {
                log_debug("cjf: %s,%i: journal page %u will be lost, flushing zone first", jnl->journal_file_name, jnl->fd, jnl->journal_file_name, jnl->serial_begin);
                zdb_zone_info_store_zone(jnl->zone->origin);
            }
        }
    }
    
    journal_cjf_page_cache_clear(jnl->fd, jnl->first_page_offset);
    
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

    log_debug("cjf: %s,%i: first PAGE now at %u (%08x), journal starts with serial %u (%08x", jnl->journal_file_name, jnl->fd,
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
    
#ifdef DEBUG
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

/**
 * Appends the uncompressed IXFR stream (SOA RR ... RR SOA RR ... RR) to the journal
 * Only checks that the first SOA serial is the current last serial
 * Should also check that the stream is complete before adding it.
 * 
 * _ get the current written serial (AXFR/TXT), there must be a bridge between that serial an the journal
 * _ get how much room is available after that serial
 * _ if the available room is less or equal to half the maximum size of the journal,
 *   trigger a write to disk and proceed
 * 
 */

static ya_result
journal_cjf_append_ixfr_stream_master(journal *jh, input_stream *ixfr_wire_is)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    
    log_debug("cjf: %s,%i: append IXFR (master)", jnl->journal_file_name, jnl->fd);
    
    if(!jnl_ensure_file_opened(jnl, TRUE))
    {
        return ERRNO_ERROR;
    }
    
    ya_result ret;
    ya_result record_size;
    u32 stream_serial_del;
    
#ifdef DEBUG
    stream_serial_del = ~0;
#endif
    

    // current record
#if SLAVE_ONLY    
    u32 starting_zone_serial;
#endif    
    u32 previous_journal_serial;
    
#if SLAVE_ONLY
    zdb_zone *zone = (zdb_zone*)jnl->zone;
    zdb_zone_acquire(zone);
    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    ret = zdb_zone_getserial((zdb_zone*)jnl->zone, &starting_zone_serial);
    zdb_zone_release_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    
    if(FAIL(ret))
    {
        log_err("cjf: %s,%i: failed to get the serial from the zone: %r", jnl->journal_file_name, jnl->fd, ret);
        return ret;
    }
    
    // remember the offset in the page when we started    
    u32 starting_page_file_offset = CJF_HEADER_SIZE;
#endif
    
    bool journal_was_empty;
    
    if(!journal_cjf_is_empty(jnl))
    {
#if SLAVE_ONLY

        if(FAIL(journal_cjf_idxt_get_page_offset_from_serial(jnl, starting_zone_serial, &starting_page_file_offset)))
        {
            log_err("cjf: %s,%i: failed to get the serial from the zone: %r", jnl->journal_file_name, jnl->fd, ret);
            return ret;
        }
#endif        
        previous_journal_serial = jnl->serial_end;
        journal_was_empty = FALSE;
    }
    else
    {
        // create the IDXT
        journal_cjf_idxt_create(jnl, 1);
        journal_was_empty = TRUE;
    }
    
    dns_resource_record rr;    
    dns_resource_record_init(&rr);
    
    // read the SOA record (start serial)
            
    if(FAIL(record_size = journal_cjf_read_soa_record(&rr, ixfr_wire_is)))
    {
        log_err("cjf: %s,%i: expected valid SOA record: %r", jnl->journal_file_name, jnl->fd, record_size);

        dns_resource_record_clear(&rr);

        return record_size;
    }

#ifdef DEBUG
    log_debug1("cjf: %s,%i: SOA: %{dnsrr}", jnl->journal_file_name, jnl->fd, &rr);
#endif
    // this is the SOA we are about to delete from, get its serial

    if(FAIL(ret = rr_soa_get_serial(rr.rdata, rr.rdata_size, &stream_serial_del)))
    {
        log_err("cjf: %s,%i: could not get serial from SOA record: %r", jnl->journal_file_name, jnl->fd, ret);

        dns_resource_record_clear(&rr);

        return ret;
    }
    
    // the journal can only be used by the writer
    
    journal_cjf_writelock(jnl);
    
    ////////////////////////////////////////////////////////////////////////////

    // we didn't got the SOA yet
    u8 soa_count;
       
    output_stream os;
    output_stream_set_void(&os); // very important
    
    do
    {
        // open a new output stream where to write the records
        // if the stream is already set in a non-void state, use it from its position
        // this may open a new page
        
        journal_cjf_page_output_stream_reopen(&os, jnl);
        
        // compute the amount of space available on the journal from the current writing position
        // this takes into account both the maximum size of the journal and the possible overwrite
        s64 available = journal_cjf_get_last_page_available_space_left(jnl);
        
        // are we in a situation were it is possible to overwrite the first page ?
        bool overwrite_risk = journal_cjf_page_current_output_stream_may_overwrite(jnl);
        
        u32 zone_stored_serial;
        u32 zone_stored_serial_page_offset;
        
        // if the journal is empty ...
        if(journal_was_empty)
        {
            // the serial of the SOA is our starting point
            previous_journal_serial = stream_serial_del;
            zone_stored_serial = 0;
            zone_stored_serial_page_offset = 0;
        }
        else
        {        
            // if the serial we are about to delete from is not the last serial, AND if we are not in a starting state (empty journal)
            if(stream_serial_del != previous_journal_serial) // false positive: previous_journal_serial is initialised (!journal_was_empty)
            {
                // complain about it

                if(serial_lt(stream_serial_del, previous_journal_serial))
                {
                    log_err("cjf: %s,%i: serial of stream (%i) is inside the journal range [%i; %i]", jnl->journal_file_name, jnl->fd, stream_serial_del, jnl->serial_begin, jnl->serial_end);
                }
                else
                {
                    log_err("cjf: %s,%i: serial of stream (%i) is outside the journal range [%i; %i]", jnl->journal_file_name, jnl->fd, stream_serial_del, jnl->serial_begin, jnl->serial_end);
                }

#ifdef DEBUG
                logger_flush();
#endif
                ret = ZDB_JOURNAL_IXFR_SERIAL_OUT_OF_KNOWN_RANGE;
                break;
            }
        
            // BEGIN SERVER FLUSH CONDITION AND TRIGGER
            
            zone_stored_serial = jnl->serial_begin;
            zone_stored_serial_page_offset = 0;

            // get the serial number of the persistent image of the zone file
            
            if(ISOK(ret = zdb_zone_info_get_stored_serial(jnl->zone->origin, &zone_stored_serial)))
            {
                // get the offset of the PAGE that works from that serial
                if(ISOK(ret = journal_cjf_idxt_get_page_offset_from_serial(jnl, zone_stored_serial, &zone_stored_serial_page_offset)))
                {
                    // that offset is the limit of no return, if we overwrite it will not be
                    // able to replay the journal from the zone

                    // if the remaining space between the current writing position and the
                    // above limit is half the maximum journal size, we ask to dump the zone
                    // on disk.  It will hopefully be done by the time we reach the limit
                    // (else we will have to wait)

                    bool cut_current_page = FALSE;

                    if(zone_stored_serial_page_offset <= jnl->last_page.records_limit)
                    {
                        // we are after the limit, we can easily get the used space
                        u32 used_space = MAX(jnl->last_page.records_limit - zone_stored_serial_page_offset, 1);
                        if((jnl->file_maximum_size / used_space) <= 1)
                        {
                            cut_current_page = TRUE;
                        }
                    }
                    else
                    {
                        u32 remaining_space = MAX(zone_stored_serial_page_offset - jnl->last_page.file_offset, 1);
                        if((jnl->file_maximum_size / remaining_space) >= 1)
                        {
                            cut_current_page = TRUE;
                        }
                    }

                    if(cut_current_page)
                    {
                        log_debug("cjf: %s,%i: half the space has been reached, requesting zone write and forcing page change", jnl->journal_file_name, jnl->fd);

                        zdb_zone_info_store_zone(jnl->zone->origin);

                        jnl->last_page.file_offset_limit = jnl->last_page.records_limit; // this will tell the PAGE is full
                        jnl->last_page.size = jnl->last_page.count;
                        journal_cjf_page_output_stream_cancel(&os);
                        journal_cjf_idxt_append_page(jnl);
                        output_stream_set_void(&os); // very important
                        journal_cjf_page_output_stream_reopen(&os, jnl);

                        overwrite_risk = journal_cjf_page_current_output_stream_may_overwrite(jnl);

                        if(jnl->last_page.file_offset_limit >= jnl->last_page.records_limit)
                        {
                            available = jnl->last_page.file_offset_limit - jnl->last_page.records_limit;
                        }
                        else
                        {
                            // we are already at the limit
                            available = 0;
                        }
                    }
                }
                else
                {
                    log_err("cjf: %s,%i: could not find the serial %u in the journal: %r", jnl->journal_file_name, jnl->fd, zone_stored_serial, ret);
                }
            }
            else
            {
                log_warn("cjf: %s,%i: could not get information on the stored zone: %r", jnl->journal_file_name, jnl->fd, ret);
            }

            // END SERVER FLUSH CONDITION AND TRIGGER
        }
        
        soa_count = 0;
        
        for(;;)
        {
            // if the record is an SOA, we may be at the end of the current stream

            if(rr.tctr.qtype == TYPE_SOA)
            {
                if(++soa_count == 3)
                {
                    // we had a +SOA already:
                    //   mark that we have a -SOA ready in rr
#ifdef DEBUG
                    log_debug1("cjf: %s,%i: SOA: %{dnsrr}", jnl->journal_file_name, jnl->fd, &rr);
#endif
                    break;
                }
                
                // this is the +SOA of the chunk
                // for now it is also the last SOA found in the file
            }
            
            yassert((soa_count > 0) && (soa_count < 3));
            
#ifdef DEBUG
            if(soa_count == 2)
            {
                log_debug1("cjf: %s,%i: +++: %{dnsrr}", jnl->journal_file_name, jnl->fd, &rr);
            }
            else
            {
                log_debug1("cjf: %s,%i: ---: %{dnsrr}", jnl->journal_file_name, jnl->fd, &rr);
            }
#endif
            
            // if there is a risk overwriting a page, and not enough room is available, then update the journal structure

            if(!journal_was_empty)
            {
                // BEGIN CUT CONDITION TEST
                
                for(;;)
                {
                    // if writing the next record (SOA) makes us go beyond the limit, we need to start a new page
                    bool should_add_page = (record_size > available);

                    if(!should_add_page)
                    {
                        break;
                    }

                    // if we have started to write, as a master, we MUST continue
                    bool can_stop_writing_without_breaking = journal_cfj_page_output_stream_get_size(&os) == 0;

                    // as a slave, we cannot lose the page that contains our starting point for the next update
                    bool cannot_remove_first_page = (jnl->first_page_offset == zone_stored_serial_page_offset); // implies we need at least 2 pages

                    // if writing the next record (SOA) makes us go beyond the limit and that limit is a page, we need to make room
                    bool must_remove_first_page = (overwrite_risk && should_add_page);

                    // if the journal is full, we should remove a page
                    bool journal_full = journal_cfj_page_output_stream_get_current_offset(&os) >= journal_cjf_maximum_size(jnl);

                    bool not_enough_pages_to_loop = (journal_cjf_idxt_get_page_count(jnl) <= 1);

                    // impossible conundrum
                    if(cannot_remove_first_page && must_remove_first_page)
                    {
                        log_warn("cjf: %s,%i: journal size is too small compared to the rate of updates", jnl->journal_file_name, jnl->fd);

                        if(ISOK(ret = zdb_zone_info_store_zone_and_wait_for_serial(jnl->zone->origin, previous_journal_serial)))
                        {
                            // and recompute ...

                            if(ISOK(ret = zdb_zone_info_get_stored_serial(jnl->zone->origin, &zone_stored_serial)))
                            {
                                // get the offset of the PAGE that works from that serial
                                if(ISOK(ret = journal_cjf_idxt_get_page_offset_from_serial(jnl, zone_stored_serial, &zone_stored_serial_page_offset)))
                                {
                                    log_debug("cjf: %s,%i: zone stored with serial %i, journal page offset %i", jnl->journal_file_name, jnl->fd, zone_stored_serial, zone_stored_serial_page_offset);
                                }
                                else
                                {
                                    log_err("cjf: %s,%i: could not find the serial in the journal: %r", jnl->journal_file_name, jnl->fd, ret);
                                }
                            }
                            else
                            {
                                log_warn("cjf: %s,%i: could not get information on the stored zone: %r", jnl->journal_file_name, jnl->fd, ret);
                            }
                        }
                        else
                        {
                            log_err("cjf: %s,%i: could not trigger the zone write: %r", jnl->journal_file_name, jnl->fd, ret);
                        }

                        continue;
                    }

                    // remember the current limit for the page
                    u32 old_page_file_offset_limit = jnl->last_page.file_offset_limit;

                    if(must_remove_first_page)
                    {
#ifdef DEBUG
                        log_debug1("cjf: %s,%i: must remove first page before overwrite", jnl->journal_file_name, jnl->fd);
#endif
                        // remove the first page (which is our current limit)
                        journal_cjf_remove_first_page(jnl);

                        // add the difference of limits
                        available += jnl->last_page.file_offset_limit - old_page_file_offset_limit;
                        // update the overwrite risk
                        overwrite_risk = journal_cjf_page_current_output_stream_may_overwrite(jnl);

                        // just continue writing
                        break;
                    }

                    // if we must finish the steam, we cannot break it, obviously
                    if(can_stop_writing_without_breaking)
                    {
                        if(not_enough_pages_to_loop)
                        {   
#ifdef DEBUG
                            log_debug1("cjf: %s,%i: journal is full with one page, adding one", jnl->journal_file_name, jnl->fd);
#endif

                            journal_cjf_page_output_stream_cancel(&os);
                            journal_cjf_idxt_append_page(jnl);
                            output_stream_set_void(&os); // very important
                            journal_cjf_page_output_stream_reopen(&os, jnl);

                            // compute the amount of space available on the journal from the current writing position
                            // this takes into account both the maximum size of the journal and the possible overwrite
                            available = journal_cjf_get_last_page_available_space_left(jnl);

                            // are we in a situation were it is possible to overwrite the first page ?
                            overwrite_risk = journal_cjf_page_current_output_stream_may_overwrite(jnl);

                            // just continue writing
                            break;
                        }
                        else // there are enough pages to loop
                        {
                            if(journal_cjf_page_line_count(jnl) > 0)
                            {
                                // we have at least one line in the page

                                if(journal_full)
                                {
#ifdef DEBUG
                                    log_debug1("cjf: %s,%i: journal is full and the first page can be removed", jnl->journal_file_name, jnl->fd);
#endif

                                    journal_cjf_page_output_stream_cancel(&os);
                                    //journal_cjf_remove_first_page(jnl);
                                    journal_cjf_idxt_append_page(jnl);
                                    output_stream_set_void(&os); // very important
                                    journal_cjf_page_output_stream_reopen(&os, jnl);

                                    // compute the amount of space available on the journal from the current writing position
                                    // this takes into account both the maximum size of the journal and the possible overwrite
                                    available = journal_cjf_get_last_page_available_space_left(jnl);

                                    // are we in a situation were it is possible to overwrite the first page ?
                                    overwrite_risk = journal_cjf_page_current_output_stream_may_overwrite(jnl);

                                    // just continue writing
                                    break;
                                }

#ifdef DEBUG
                                log_debug1("cjf: %s,%i: journal is full but the first page cannot be removed", jnl->journal_file_name, jnl->fd);
#endif

                                // give up

                                //goto journal_cjf_append_ixfr_stream_slave_exit;
                            }

#ifdef DEBUG
                            log_debug1("cjf: %s,%i: last page has not even one line yet", jnl->journal_file_name, jnl->fd);
#endif

                            // empty page : just continue writing
                            break;
                        }
                    }
                    else
                    {
                        // just continue writing
                        break;
                    }

                    // add the difference of limits
                    available += jnl->last_page.file_offset_limit - old_page_file_offset_limit;
                    // update the overwrite risk
                    overwrite_risk = journal_cjf_page_current_output_stream_may_overwrite(jnl);
                }
            
               // END CUT CONDITION TEST
            }
            
            if(FAIL(ret = journal_cfj_page_output_stream_write_resource_record(&os, &rr)))
            {
                log_err("cjf: %s,%i: failed to write record %{dnsrr}: %r", jnl->journal_file_name, jnl->fd, &rr, ret);
                break;
            }
            
            yassert(ret == record_size);
            yassert(!overwrite_risk || (available >= record_size));
            available -= record_size;
            
            if((record_size = dns_resource_record_read(&rr, ixfr_wire_is)) <= 0)
            {
                /* FAIL or EOF */                
#ifdef DEBUG
                log_debug1("journal: %s,%i: EOF: no more resource records from input", jnl->journal_file_name, jnl->fd);
#endif
                break;
            }
        }

        if((soa_count >= 2) && ISOK(ret))
        {
            // only close the output stream if ALL the PAGE of a page have been written OR if we are about to exit the loop

            journal_cjf_page_output_stream_next(&os);
        }
        else
        {
            // cancel the stream
            journal_cjf_page_output_stream_cancel(&os);
            break;
        }
    }
    while(soa_count > 2);


// It's for a goto and it's ugly ...
    
//journal_cjf_append_ixfr_stream_master_exit:
            
    //journal_cjf_page_output_stream_close(jnl);
    output_stream_close(&os);

    dns_resource_record_clear(&rr);

    // ...

    // update the next append position

    // update the header (?)

    // journal_cjf_page_flush(); // =>  journal_cjf_idxt_flush() => jnl_header_flush();

    // if the last SOA read is not the last serial, loop
    
    if(ISOK(ret))
    {
        journal_cjf_page_cache_flush(jnl->fd);
        jnl_header_flush(jnl);
        
        journal_cjf_writeunlock(jnl);
        
        log_debug("cjf: %s,%i: append IXFR (master) done", jnl->journal_file_name, jnl->fd);

        return TYPE_IXFR;       /* that's what the caller expects to handle the new journal pages */
    }
    else
    {   
        journal_cjf_writeunlock(jnl);
        
        // in case of error, forget the last stream addition (more or less no operation)
        
        log_err("cjf: %s,%i: append IXFR (master) failed with: %r", jnl->journal_file_name, jnl->fd, ret);

        return ret;
    }
}

static ya_result
journal_cjf_append_ixfr_stream_slave(journal *jh, input_stream *ixfr_wire_is)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    
    if(!jnl_ensure_file_opened(jnl, TRUE))
    {
        log_err("cjf: %{dnsname}: failed to open/create the file", jnl->zone);
        return ERRNO_ERROR;
    }
    
    ya_result ret;
    ya_result record_size;
    u32 stream_serial_del;
    
#ifdef DEBUG
    stream_serial_del = ~0;
#endif
    
    // current record
    
    u32 starting_zone_serial;
    u32 previous_journal_serial;
    
    zdb_zone *zone = (zdb_zone*)jnl->zone;
    zdb_zone_acquire(zone);
    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    ret = zdb_zone_getserial((zdb_zone*)jnl->zone, &starting_zone_serial);
    zdb_zone_release_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    
    if(FAIL(ret))
    {
        log_err("cjf: %s,%i: failed to get the serial from the zone: %r", jnl->journal_file_name, jnl->fd, ret);
        return ret;
    }
    
    // remember the offset in the page when we started    
    u32 starting_page_file_offset = CJF_HEADER_SIZE;
    
    if(!journal_cjf_is_empty(jnl))
    {
        if(FAIL(journal_cjf_idxt_get_page_offset_from_serial(jnl, starting_zone_serial, &starting_page_file_offset)))
        {
            log_err("cjf: %s,%i: failed to get the serial from the zone: %r", jnl->journal_file_name, jnl->fd, ret);
            return ret;
        }
        
        previous_journal_serial = jnl->serial_end;
    }
    else
    {
        // create the IDXT
        journal_cjf_idxt_create(jnl, 1);
    }
    
    dns_resource_record rr;    
    dns_resource_record_init(&rr);
    
    // read the SOA record (start serial)
            
    if(FAIL(record_size = journal_cjf_read_soa_record(&rr, ixfr_wire_is)))
    {
        log_err("cjf: %s,%i: expected valid SOA record: %r", jnl->journal_file_name, jnl->fd, record_size);

        dns_resource_record_clear(&rr);

        return record_size;
    }

#ifdef DEBUG
    log_debug1("cjf: %s,%i: SOA: %{dnsrr}", jnl->journal_file_name, jnl->fd, &rr);
#endif
    // this is the SOA we are about to delete from, get its serial

    if(FAIL(ret = rr_soa_get_serial(rr.rdata, rr.rdata_size, &stream_serial_del)))
    {
        log_err("cjf: %s,%i: could not get serial from SOA record: %r", jnl->journal_file_name, jnl->fd, ret);

        dns_resource_record_clear(&rr);

        return ret;
    }
    
    // the journal can only be used by the writer
    
    journal_cjf_writelock(jnl);
    
    ////////////////////////////////////////////////////////////////////////////

    // we didn't got the SOA yet
    u8 soa_count;
       
    output_stream os;
    output_stream_set_void(&os); // very important
    
    do
    {
        // open a new output stream where to write the records
        // if the stream is already set in a non-void state, use it from its position
        // this may open a new page
        
        journal_cjf_page_output_stream_reopen(&os, jnl);
        
        // compute the amount of space available on the journal from the current writing position
        // this takes into account both the maximum size of the journal and the possible overwrite
        s64 available = journal_cjf_get_last_page_available_space_left(jnl);
        
        // are we in a situation were it is possible to overwrite the first page ?
        bool overwrite_risk = journal_cjf_page_current_output_stream_may_overwrite(jnl);
                      
        // if the journal is empty ...
        if(journal_cjf_is_empty(jnl))
        {
            // the serial of the SOA is our starting point
            previous_journal_serial = stream_serial_del;
        }
        else
        {
            // if the serial we are about to delete from is not the last serial, AND if we are not in a starting state (empty journal)
            if(stream_serial_del != previous_journal_serial) // false positive: previous_journal_serial is initialised (!journal_was_empty)
            {
                // complain about it

                if(serial_lt(stream_serial_del, previous_journal_serial))
                {
                    log_info("cjf: %s,%i: serial of stream (%i) is inside the journal range [%i; %i]", jnl->journal_file_name, jnl->fd, stream_serial_del, jnl->serial_begin, jnl->serial_end);
                    
                    // SKIP ? the SOA has already been read
                    // read until next SOA
                    // then read again until next SOA and evaluate again if we are at the right point.
                    // at some point we may find the right starting point, or finally give up
                                        
                    for(int soa_found = 0;;)
                    {
                        // read next redcord
                        
                        if((record_size = dns_resource_record_read(&rr, ixfr_wire_is)) <= 0)
                        {
                            /* FAIL or EOF */                
#ifdef DEBUG
                            log_debug1("journal: %s,%i: skipping old changes: EOF: no more resource records from input", jnl->journal_file_name, jnl->fd);
#endif
                            ret = record_size;
                            break; // breaks the for
                        }
                        
                        if(rr.tctr.qtype == TYPE_SOA)
                        {
                            // we got another SOA
                            
                            if(++soa_found == 2)
                            {
                                // we are at the third one
                                
                                if(FAIL(ret = rr_soa_get_serial(rr.rdata, rr.rdata_size, &stream_serial_del)))
                                {
                                    log_err("cjf: %s,%i: skipping old changes: could not get serial from SOA record: %r", jnl->journal_file_name, jnl->fd, ret);
                                    break; // breaks the for
                                }
                                
                                // if the serial is still below : skip further
                                
                                if(serial_lt(stream_serial_del, previous_journal_serial))
                                {
                                    log_info("cjf: %s,%i: skipping old changes: serial of stream (%i) is inside the journal range [%i; %i]", jnl->journal_file_name, jnl->fd, stream_serial_del, jnl->serial_begin, jnl->serial_end);
                                    soa_found = 0;
                                    continue;
                                }
                                
                                // if it is equal, we can proceed reading the stream into the journal
                                
                                if(stream_serial_del == previous_journal_serial)
                                {
                                    ret = SUCCESS;
                                }
                                else // else it's broken
                                {
                                    log_err("cjf: %s,%i: serial of stream (%i) is outside the journal range [%i; %i]", jnl->journal_file_name, jnl->fd, stream_serial_del, jnl->serial_begin, jnl->serial_end);
                                    ret = ZDB_JOURNAL_IXFR_SERIAL_OUT_OF_KNOWN_RANGE;
                                }
                                
                                break; // breaks the for
                            }
                            // else we have found the second SOA and still need to find the end or the next SOA to try to recover from this
                        }
                        // else we don't care
                    } // end for soa_found
                }
                else
                {
                    log_err("cjf: %s,%i: serial of stream (%i) is outside the journal range [%i; %i]", jnl->journal_file_name, jnl->fd, stream_serial_del, jnl->serial_begin, jnl->serial_end);
                    ret = ZDB_JOURNAL_IXFR_SERIAL_OUT_OF_KNOWN_RANGE;
                }

                // at this point, we either have
                // _ a success value in ret with record_size > 0 (and then we continue)
                // _ a success value in ret with record_size <= 0 (and then we are at the end of the stream)
                // _ an error value in ret with record_size > 0 (and the stream is not usable)
                
                if(FAIL(ret) || (record_size <= 0))
                {
#ifdef DEBUG
                    logger_flush();
#endif
                    journal_cjf_page_output_stream_cancel(&os);
                    
                    break; // breaks the do{}while();
                }
                
                // rr contains the current (next) SOA
                // record_size contains the size of that SOA
            }
        }
        
        soa_count = 0;
        
        for(;;)
        {
            // if the record is an SOA, we may be at the end of the current stream

            if(rr.tctr.qtype == TYPE_SOA)
            {
                if(++soa_count == 3)
                {
                    // we had a +SOA already:
                    //   mark that we have a -SOA ready in rr
#ifdef DEBUG
                    log_debug1("cjf: %s,%i: SOA: %{dnsrr}", jnl->journal_file_name, jnl->fd, &rr);
#endif
                    break;
                }
                
                // this is the +SOA of the chunk
                // for now it is also the last SOA found in the file
            }
            
            yassert((soa_count > 0) && (soa_count < 3));
            
#ifdef DEBUG
            if(soa_count == 2)
            {
                log_debug1("cjf: %s,%i: +++: %{dnsrr}", jnl->journal_file_name, jnl->fd, &rr);
            }
            else
            {
                log_debug1("cjf: %s,%i: ---: %{dnsrr}", jnl->journal_file_name, jnl->fd, &rr);
            }
#endif
            
            // if there is a risk overwriting a page, and not enough room is available, then update the journal structure

            // BEGIN CUT CONDITION TEST
            
            for(;;)
            {
                // if writing the next record (SOA) makes us go beyond the limit, we need to start a new page
                bool should_add_page = (record_size > available);

                if(!should_add_page)
                {
                    break;
                }
                
                // if we have started to write, as a slave, we should continue
                bool can_stop_writing_without_breaking = journal_cfj_page_output_stream_get_size(&os) == 0;
                
                // as a slave, we cannot lose the page that contains our starting point for the next update
                bool cannot_remove_first_page = (jnl->first_page_offset == starting_page_file_offset); // implies we need at least 2 pages

                // if writing the next record (SOA) makes us go beyond the limit and that limit is a page, we need to make room
                bool must_remove_first_page = (overwrite_risk && should_add_page);
                
                // if the journal is full, we should remove a page
                bool journal_full = journal_cfj_page_output_stream_get_current_offset(&os) >= journal_cjf_maximum_size(jnl);
                
                bool not_enough_pages_to_loop = (journal_cjf_idxt_get_page_count(jnl) <= 1);

                // impossible conundrum
                if(cannot_remove_first_page && must_remove_first_page)
                {
                    log_err("cjf: %s,%i: journal size is too small compared to what the master is sending", jnl->journal_file_name, jnl->fd);

                    // we are about to destroy what we still need to read
                    // no can do : we must stop here.
                    journal_cjf_page_output_stream_cancel(&os);
                    soa_count = 0;
                    goto journal_cjf_append_ixfr_stream_slave_exit;
                }

                // remember the current limit for the page
                u32 old_page_file_offset_limit = jnl->last_page.file_offset_limit;

                if(must_remove_first_page)
                {
#ifdef DEBUG
                    log_debug1("cjf: %s,%i: must remove first page before overwrite", jnl->journal_file_name, jnl->fd);
#endif
                    // remove the first page (which is our current limit)
                    journal_cjf_remove_first_page(jnl);
                    
                    // add the difference of limits
                    available += jnl->last_page.file_offset_limit - old_page_file_offset_limit;
                    // update the overwrite risk
                    overwrite_risk = journal_cjf_page_current_output_stream_may_overwrite(jnl);
                    
                    // just continue writing
                    break;
                }
                
                // if we must finish the steam, we cannot break it, obviously
                if(can_stop_writing_without_breaking)
                {
                    if(not_enough_pages_to_loop)
                    {   
#ifdef DEBUG
                        log_debug1("cjf: %s,%i: journal is full with one page, adding one", jnl->journal_file_name, jnl->fd);
#endif
                        
                        journal_cjf_page_output_stream_cancel(&os);
                        journal_cjf_idxt_append_page(jnl);
                        output_stream_set_void(&os); // very important
                        journal_cjf_page_output_stream_reopen(&os, jnl);
                        
                        // compute the amount of space available on the journal from the current writing position
                        // this takes into account both the maximum size of the journal and the possible overwrite
                        available = journal_cjf_get_last_page_available_space_left(jnl);

                        // are we in a situation were it is possible to overwrite the first page ?
                        overwrite_risk = journal_cjf_page_current_output_stream_may_overwrite(jnl);
                        
                        // just continue writing
                        break;
                    }
                    else
                    {
                        if(journal_cjf_page_line_count(jnl) > 0)
                        {
                            // we have at least one line in the page
                            
                            if(journal_full && !cannot_remove_first_page)
                            {
#ifdef DEBUG
                                log_debug1("cjf: %s,%i: journal is full and the first page can be removed", jnl->journal_file_name, jnl->fd);
#endif
                                
                                journal_cjf_page_output_stream_cancel(&os);
                                //journal_cjf_remove_first_page(jnl);
                                journal_cjf_idxt_append_page(jnl);
                                output_stream_set_void(&os); // very important
                                journal_cjf_page_output_stream_reopen(&os, jnl);
                                
                                // compute the amount of space available on the journal from the current writing position
                                // this takes into account both the maximum size of the journal and the possible overwrite
                                available = journal_cjf_get_last_page_available_space_left(jnl);

                                // are we in a situation were it is possible to overwrite the first page ?
                                overwrite_risk = journal_cjf_page_current_output_stream_may_overwrite(jnl);

                                // just continue writing
                                break;
                            }
                            
#ifdef DEBUG
                            log_debug1("cjf: %s,%i: journal is full but the first page cannot be removed", jnl->journal_file_name, jnl->fd);
#endif
                            
                            // give up
                            
                            goto journal_cjf_append_ixfr_stream_slave_exit;
                        }
                        
#ifdef DEBUG
                        log_debug1("cjf: %s,%i: last page has not even one line yet", jnl->journal_file_name, jnl->fd);
#endif
                        
                        // empty page : just continue writing
                        break;
                    }
                }
                else
                {
                    // just continue writing
                    break;
                }

                // add the difference of limits
                available += jnl->last_page.file_offset_limit - old_page_file_offset_limit;
                // update the overwrite risk
                overwrite_risk = journal_cjf_page_current_output_stream_may_overwrite(jnl);
            }
            
            // END CUT CONDITION TEST
            
            if(FAIL(ret = journal_cfj_page_output_stream_write_resource_record(&os, &rr)))
            {
                log_err("cjf: %s,%i: failed to write record %{dnsrr}: %r", jnl->journal_file_name, jnl->fd, &rr, ret);
                break;
            }
            
            yassert(ret == record_size);
            yassert(!overwrite_risk || (available >= record_size));
            available -= record_size;
            
            if((record_size = dns_resource_record_read(&rr, ixfr_wire_is)) <= 0)
            {
                /* FAIL or EOF */                
#ifdef DEBUG
                log_debug1("journal: %s,%i: EOF: no more resource records from input", jnl->journal_file_name, jnl->fd);
#endif
                break;
            }
        } // end for

        if((soa_count >= 2) && ISOK(ret))
        {
            // only close the output stream if ALL the PAGE of a page have been written OR if we are about to exit the loop

            journal_cjf_page_output_stream_next(&os);
        }
        else
        {
            // cancel the stream
            journal_cjf_page_output_stream_cancel(&os);
            break;
        }
    }
    while(soa_count > 2);


// It's for a goto and it's ugly ...
    
journal_cjf_append_ixfr_stream_slave_exit:
            
    //journal_cjf_page_output_stream_close(jnl);
    output_stream_close(&os);

    dns_resource_record_clear(&rr);

    // ...

    // update the next append position

    // update the header (?)

    // journal_cjf_page_flush(); // =>  journal_cjf_idxt_flush() => jnl_header_flush();

    // if the last SOA read is not the last serial, loop
    
    if(ISOK(ret))
    {
        journal_cjf_page_cache_flush(jnl->fd);
        jnl_header_flush(jnl);
        journal_cjf_writeunlock(jnl);
        
        log_debug("cjf: %s,%i: append IXFR (slave) done", jnl->journal_file_name, jnl->fd);

        return TYPE_IXFR;       /* that's what the caller expects to handle the new journal pages */
    }
    else
    {   
        journal_cjf_writeunlock(jnl);
        
        log_err("cjf: %s,%i: append IXFR (slave) failed with: %r", jnl->journal_file_name, jnl->fd, ret);
        
        // in case of error, forget the last stream addition (more or less no operation)

        return ret;
    }
}


static ya_result
journal_cjf_append_ixfr_stream(journal *jh, input_stream *ixfr_wire_is)
{
    u8 zt;
    ya_result ret = zdb_zone_info_get_zone_type(jh->zone->origin, &zt);
    if(ISOK(ret))
    {
        switch(zt)
        {
            case ZT_MASTER:
                ret = journal_cjf_append_ixfr_stream_master(jh, ixfr_wire_is);
                break;
            case ZT_SLAVE:
                ret = journal_cjf_append_ixfr_stream_slave(jh, ixfr_wire_is);
                break;
            default:
                ret = ERROR;
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

struct journal_cjf_input_stream_data
{
    journal_cjf *jnl;
    
    int fd;
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
journal_cjf_input_stream_read(input_stream* stream, u8 *buffer, u32 len)
{
    journal_cjf_input_stream_data *data = (journal_cjf_input_stream_data*)stream->data;
    const u8 *base = buffer;
    const u8 *limit = &buffer[len];
    intptr n;
    ya_result ret = 0;
    
    journal_cjf *jnl = data->jnl;
    
    log_debug("cjf: %s,%i: input: reading %u/%u bytes, pos is %lli", jnl->journal_file_name, jnl->fd,
            len, data->available, lseek(data->fd, 0, SEEK_CUR));

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
            journal_cjf_page_cache_read_header(data->jnl->fd, page_offset, &page_header);
            stream_limit_offset = page_header.stream_end_offset;
                        
            // we know where to start ...
                        
            data->idxt_index++;
            
            (void)stream_limit_offset;
            
            yassert(stream_limit_offset != 0);
            yassert(stream_limit_offset > page_offset);
 
            data->available = page_header.stream_end_offset - stream_offset;
            data->page_next = page_header.next_page_offset;
            
            if(lseek(data->fd, stream_offset, SEEK_SET) < 0)
            {
                return ERRNO_ERROR;
            }
        }
        
        n = MIN(n, data->available);
        
        if(FAIL(ret = readfully(data->fd, buffer, n)))
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
    log_debug("cjf: %s,%i: input: skipping %u bytes", jnl->journal_file_name, jnl->fd, len);
    
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
    
    log_debug("cjf: %s,%i: input: close (%i)", data->jnl->journal_file_name, data->jnl->fd, data->fd);
    journal_cjf_readunlock(data->jnl);
    
    close_ex(data->fd);
    ZFREE(data, journal_cjf_input_stream_data);
    
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
    
    log_debug("cjf: %s,%i: get IXFR stream at serial %i", jnl->journal_file_name, jnl->fd, serial_from);
    
    if(!jnl_ensure_file_opened(jnl, TRUE))
    {
        return ERRNO_ERROR;
    }
    
    journal_cjf_readlock(jnl);
    
    if(serial_lt(serial_from, jnl->serial_begin) || serial_ge(serial_from, jnl->serial_end))
    {
        if(serial_from == jnl->serial_end)
        {
            journal_cjf_readunlock(jnl);
            empty_input_stream_init(out_input_stream);
            return SUCCESS; // 0
        }
        else
        {
            journal_cjf_readunlock(jnl);
#ifdef DEBUG
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
    ZALLOC_OR_DIE(journal_cjf_input_stream_data*, data, journal_cjf_input_stream_data, GENERIC_TAG);
    data->jnl = jnl;
    data->fd = jnl_open_file(jnl, FALSE);
    
    data->serial_from = serial_from;
    
    if(out_last_soa_rr != NULL)
    {
        yassert(jnl->last_soa_offset != 0);
        // read the last SOA
        
        off_t from = lseek(data->fd, 0, SEEK_CUR);
                
        lseek(data->fd, jnl->last_soa_offset, SEEK_SET);
        input_stream tmp;
        fd_input_stream_attach(&tmp, data->fd);
        ret = dns_resource_record_read(out_last_soa_rr, &tmp);
        fd_input_stream_detach(&tmp);
        
        lseek(data->fd, from, SEEK_SET);
        
        if(FAIL(ret))
        {
            journal_cjf_readunlock(jnl);
            
            log_err("cjf: %s,%i: unable to read the SOA at position %u: %r", jnl->journal_file_name, jnl->fd, jnl->last_soa_offset, ret);
            ZFREE(data, journal_cjf_input_stream_data);
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
    ya_result ret = ERROR;
    journal_cjf *jnl = (journal_cjf*)jh;
    
    journal_cjf_readlock(jnl);
    
    u32 value = jnl->serial_begin;
    
    if(serial != NULL)
    {
        *serial = value;
        ret = SUCCESS;
    }
    
    journal_cjf_readunlock(jnl);
    
    log_debug("cjf: %s,%i: get first serial: %i", jnl->journal_file_name, jnl->fd, value);
    
    return ret;
}

static ya_result
journal_cjf_get_last_serial(journal *jh, u32 *serial)
{
    ya_result ret = ERROR;
    journal_cjf *jnl = (journal_cjf*)jh;
    
    journal_cjf_readlock(jnl);
    
    u32 value = jnl->serial_end;
    
    if(serial != NULL)
    {
        *serial = value;
        ret = SUCCESS;
    }
    
    journal_cjf_readunlock(jnl);
    
    log_debug("cjf: %s,%i: get last serial: %i", jnl->journal_file_name, jnl->fd, value);
    
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
    yassert(!shared_group_mutex_islocked(&jnl->mtx));

    if(size_ == 0)
    {
        log_debug("cjf: %s,%i: truncate to size 0", jnl->journal_file_name, jnl->fd);

        if(jnl->fd >= 0)
        {
            journal_cjf_page_cache_close(jnl->fd);
            close_ex(jnl->fd);
            jnl->fd = -1;
        }
        unlink(jnl->journal_file_name);

        jnl->idxt.dirty = FALSE;
        journal_cjf_idxt_destroy(jnl);

        jnl->file_maximum_size = MAX_U32;
        if(jnl->zone != NULL)
        {
            jnl->file_maximum_size = jnl->zone->wire_size >> 1;
            zdb_zone_info_get_zone_max_journal_size(jnl->zone->origin, &jnl->file_maximum_size);
        }

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

        jnl->mtx.owner = LOCK_NONE;
        jnl->mtx.count = 0;

        jnl->flags = JOURNAL_CFJ_FLAGS_MY_ENDIAN;

        jnl->last_page.records_limit = jnl->last_page.file_offset + CJF_SECTION_INDEX_SIZE;
        jnl->last_page.file_offset_limit = jnl->file_maximum_size;

        //jnl->journal_file_name = strdup(filename);

        return SUCCESS;
    }
    else
    {    
        log_err("cjf: %s,%i: truncate to size != 0 not implemented", jnl->journal_file_name, jnl->fd);
        
        return ZDB_JOURNAL_FEATURE_NOT_SUPPORTED;
    }
}

static ya_result
journal_cjf_truncate_to_serial(journal *jh, u32 serial_)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    log_err("cjf: %s,%i: truncate to serial not implemented", jnl->journal_file_name, jnl->fd);
    
    return ZDB_JOURNAL_FEATURE_NOT_SUPPORTED;
}

static ya_result
journal_cjf_close(journal *jh)
{
    journal_cjf *jnl = (journal_cjf*)jh;

    log_debug("cjf: %s,%i: close", jnl->journal_file_name, jnl->fd);
    
    shared_group_mutex_lock(&jnl->mtx, 0x83);
    
    zdb_zone *zone;
    if((zone = (zdb_zone*)jnl->zone) != NULL)
    {
        //zdb_zone_lock(zone, ZDB_ZONE_MUTEX_LOAD);
        yassert(zone->journal == jh);
        zone->journal = NULL;
        //zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_LOAD);
    }
    
    shared_group_mutex_unlock(&jnl->mtx, 0x83);
    
    yassert(!shared_group_mutex_islocked(&jnl->mtx));
    
    mutex_lock(&journal_cjf_set_mtx);
    ptr_set_avl_delete(&journal_cjf_set, jnl->journal_file_name);
    mutex_unlock(&journal_cjf_set_mtx);
    
    journal_cjf_writelock(jnl);
    
    jnl_close_file(jnl);
    
    jnl->vtbl = NULL;
    
    journal_cjf_writeunlock(jnl);
    
    shared_group_mutex_destroy(&jnl->mtx);
    free(jnl->journal_file_name);
    memset(jnl, 0xfe, sizeof(journal_cjf));
    free(jnl);
        
    return SUCCESS;
}

static void
journal_cjf_log_dump(journal *jh)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    log_debug("cjf: %s,%i: [%u; %u] '%s' (%i) lck=%i rc=%i", jnl->journal_file_name, jnl->fd, jnl->serial_begin, jnl->serial_end, jnl->journal_file_name, jnl->fd, jnl->mtx.owner, jnl->mtx.count);
}

static ya_result
journal_cjf_get_domain(journal *jh, u8 *out_domain)
{
    if(jh->zone != NULL)
    {   
        dnsname_copy(out_domain, jh->zone->origin);
        return SUCCESS;
    }
    
    return ERROR;
}

static void
journal_cjf_destroy(journal *jh)
{
    journal_cjf *jnl = (journal_cjf*)jh;
    log_debug("cjf: %s,%i: destroy", jnl->journal_file_name, jnl->fd);
    shared_group_mutex_destroy(&jnl->mtx);
    free(jnl->journal_file_name);
    free(jnl);
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
    yassert(zone != NULL);
    
    journal_cjf *jnl = (journal_cjf*)jh;
    
    if(jh->zone != NULL)
    {
        if(jh->zone->journal == jh)
        {
            log_debug("cjf: %s,%i: updating maximum journal size", jnl->journal_file_name, jnl->fd);
            jnl->file_maximum_size = jnl->zone->wire_size >> 1;
            zdb_zone_info_get_zone_max_journal_size(jnl->zone->origin, &jnl->file_maximum_size);
            return;
        }
        else
        {
            log_err("cjf: %s,%i: journal (%p) is already linked to a zone (%p) and that zone links to another journal (%p)", jnl->journal_file_name, jnl->fd, jh, jh->zone, jh->zone->journal);
            logger_flush();
            abort();
        }
    } //jh->zone may be null
    
    if(zone->journal != NULL)
    {
        if(zone->journal == jh)
        {
            log_debug("cjf: %s,%i: updating incomplete link", jnl->journal_file_name, jnl->fd);
            jh->zone = zone;
            jnl->file_maximum_size = jnl->zone->wire_size >> 1;
            zdb_zone_info_get_zone_max_journal_size(jnl->zone->origin, &jnl->file_maximum_size);
            return;
        }
        else
        {
            log_err("cjf: %s,%i: zone already points to another journal (%p instead of to %p)", jnl->journal_file_name, jnl->fd, zone->journal, jh);
            logger_flush();
            abort();
        }
    }
    
    log_debug("cjf: %s,%i: linking to zone %{dnsname},%p", jnl->journal_file_name, jnl->fd, zone->origin, zone);
    
    jnl->zone = zone;
    zone->journal = jh;
    jnl->file_maximum_size = jnl->zone->wire_size >> 1;
    zdb_zone_info_get_zone_max_journal_size(jnl->zone->origin, &jnl->file_maximum_size);
    

    {
        jnl->last_page.file_offset_limit = jnl->file_maximum_size;
    }
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
journal_cjf_alloc_default(const char *filename)
{
    journal_cjf *jnl;
    MALLOC_OR_DIE(journal_cjf*, jnl, sizeof(journal_cjf), JRNLCJF_TAG);
    ZEROMEMORY(jnl, sizeof(journal_cjf));
    jnl->vtbl = &journal_cjf_vtbl;
    jnl->fd = -1;
    jnl->file_maximum_size = MAX_U32;                
    jnl->first_page_offset = CJF_HEADER_SIZE;
    jnl->journal_file_name = strdup(filename);                
    jnl->last_page.file_offset = CJF_HEADER_SIZE;
    jnl->last_page.size = CJF_SECTION_INDEX_SLOT_COUNT;
    jnl->last_page.records_limit = CJF_HEADER_SIZE + CJF_SECTION_INDEX_SIZE;
    jnl->last_page.file_offset_limit = jnl->file_maximum_size;
    jnl->flags = JOURNAL_CFJ_FLAGS_MY_ENDIAN;
    shared_group_mutex_init(&jnl->mtx, &journal_shared_mtx, "journal-cjf");
    return jnl;
}
/**
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
journal_cjf_open(journal **jh, const u8* origin, const char *workingdir, bool create)
{
    /*
     * try to open the journal file
     * if it exists, create the structure for the handle
     */
        
    // CFJ_PAGE_CACHE ->
    journal_cjf_page_cache_init();
    if(!journal_shared_mtx_initialized)
    {
        shared_group_shared_mutex_init(&journal_shared_mtx);
        journal_shared_mtx_initialized = TRUE;
    }
    // CFJ_PAGE_CACHE <-
    
    journal_cjf *jnl;
    ya_result return_value;
    char   filename[PATH_MAX];
    
    if((jh == NULL) || (origin == NULL) || (workingdir == NULL))
    {
        return ZDB_JOURNAL_WRONG_PARAMETERS;
    }
    
#ifdef DEBUG
    log_debug("cjf: open(%p, '%{dnsname}', \"%s\", %d)", jh, origin, workingdir, (create)?1:0);
#endif
        
#ifdef DEBUG
    log_debug("cjf: trying to open journal for %{dnsname} in '%s'", origin, workingdir);
#endif
    
    /* get the soa of the loaded zone */
    
    *jh = NULL;
    
    if(FAIL(return_value = snformat(filename, sizeof(filename), CJF_WIRE_FILE_FORMAT, workingdir, origin)))
    {
        return return_value;
    }
    
    mutex_lock(&journal_cjf_set_mtx);
    ptr_node *node = ptr_set_avl_find(&journal_cjf_set, filename);
    if(node != NULL)
    {
        journal_cjf *current_jnl = (journal_cjf*)node->value;
        if(journal_cjf_is_empty(current_jnl))
        {
            mutex_unlock(&journal_cjf_set_mtx);
            
            if(!jnl_ensure_file_opened(current_jnl, create))
            {
                return ZDB_ERROR_ICMTL_NOTFOUND;
            }
            
            *jh = (journal*)current_jnl;
            return SUCCESS;
        }
        log_debug("cjf: %{dnsname} has already got an opened journal at %p, fd=%i", origin, current_jnl, current_jnl->fd);
#if DEBUG
        logger_flush();
#endif
        *jh = (journal*)current_jnl;
        mutex_unlock(&journal_cjf_set_mtx);
        return 1;
    }
    
    mutex_unlock(&journal_cjf_set_mtx);
    
    int fd = open_ex(filename, O_RDWR);

    if(fd < 0)
    {
        // not found (?)
        int err = errno;
        
        if(err == ENOENT)
        {
            if(create)
            {
                jnl = journal_cjf_alloc_default(filename);

                *jh = (journal*)jnl;
                
                mutex_lock(&journal_cjf_set_mtx);
                ptr_node *node = ptr_set_avl_insert(&journal_cjf_set, jnl->journal_file_name);
                yassert(node->value == NULL);
                node->value = jnl;
                mutex_unlock(&journal_cjf_set_mtx);
                                
                return SUCCESS;
            }
            else
            {
                return ZDB_ERROR_ICMTL_NOTFOUND;
            }
        }

        return MAKE_ERRNO_ERROR(err);
    }
    else // the file exists, is opened, an its file descriptor is in fd
    {
        /*
         * Got a journal file, initialise the handling structure
         */

        struct cjf_header header;

        if(FAIL(return_value = readfully(fd, &header, sizeof(header))))
        {
            close_ex(fd);
            return return_value;
        }

        if((header.magic_plus_version != CJF_CJF0_MAGIC) || ((header.flags & JOURNAL_CFJ_FLAGS_MY_ENDIAN) == 0) )
        {
            if(header.magic_plus_version != CJF_CJF0_MAGIC)
            {
                log_err("cjf: wrong magic on %s", filename);
            }
            else
            {
                log_err("cjf: wrong endian on %s", filename);
            }

            close_ex(fd);

            if(create)
            {
                // try to fix it
                // rename
                
                char broken_file_path[PATH_MAX];

                if(ISOK(snformat(broken_file_path, sizeof(broken_file_path),"%s.bad-journal", filename)))
                {
                    bool try_again = TRUE;
                    
                    // remove previous bad-journal if any
                    unlink(broken_file_path);

                    // rename the journal into bad-journal
                    if(rename(filename, broken_file_path) < 0)
                    {
                        log_err("cjf: unable to rename %s into %s: %r", filename, broken_file_path, ERRNO_ERROR);

                        if(unlink(filename) < 0)
                        {
                            log_err("cjf: unable to delete %s: %r", filename, ERRNO_ERROR);
                            try_again = FALSE;
                        }
                    }

                    if(try_again)
                    {
                        return_value = journal_cjf_open(jh, origin, workingdir, TRUE); // we are in a branch where "create = TRUE"

                        return return_value;
                    }
                }
                else
                {
                    log_err("cjf: %s is a bad journal, please remove it.", filename);
                }
            }

            return ZDB_JOURNAL_ERROR_READING_JOURNAL;
        }

        log_debug("cjf: journal for %{dnsname} expected to cover serials from %i to %i", origin, header.serial_begin, header.serial_end);
        log_debug("cjf: journal for %{dnsname} table index located at %x%s", origin, header.table_index_offset,
            (header.table_index_offset!=0)?"":", which means it has not been closed properly");

        jnl = journal_cjf_alloc_default(filename);
        
        jnl->fd = fd; // file opened
        
        // if the file is empty, the header can be ignored (or reconstructed)
        
        if((header.flags & JOURNAL_CFJ_FLAGS_NOT_EMPTY) != 0)
        {        
            jnl->flags = header.flags;

            jnl->serial_begin = header.serial_begin;
            jnl->serial_end = header.serial_end;
            jnl->first_page_offset = header.first_index_offset;
            jnl->page_table_file_offset = header.table_index_offset;
            jnl->last_soa_offset = header.last_soa_offset;

            jnl->last_page.serial_end = jnl->serial_end;    
            jnl->last_page.records_limit = header.last_page_offset_next;

            jnl->journal_file_name = strdup(filename);

            journal_cjf_idxt_load(jnl);
            
            if(jnl->idxt.count > 0)
            {
                jnl->last_page.file_offset = journal_cjf_idxt_get_last_file_offset(jnl);
                journal_cjf_page_tbl_header current_page_header;
                journal_cjf_page_cache_read_header(jnl->fd, jnl->last_page.file_offset, &current_page_header);
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
                jnl->flags = JOURNAL_CFJ_FLAGS_MY_ENDIAN|JOURNAL_CFJ_FLAGS_DIRTY;

                journal_cjf_page_cache_flush(jnl->fd);

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
                    zdb_zone_info_get_zone_max_journal_size(jnl->zone->origin, &jnl->file_maximum_size);
                }

                jnl->last_page.file_offset = CJF_HEADER_SIZE;
                jnl->last_page.count = 0;
                jnl->last_page.size = CJF_SECTION_INDEX_SLOT_COUNT;
                jnl->last_page.serial_start = 0;
                jnl->last_page.serial_end = 0;
                jnl->last_page.records_limit = jnl->last_page.file_offset + CJF_SECTION_INDEX_SIZE;
                jnl->last_page.file_offset_limit = jnl->file_maximum_size;

                jnl_header_flush(jnl);
    
#if _BSD_SOURCE || _XOPEN_SOURCE >= 500 || _XOPEN_SOURCE && _XOPEN_SOURCE_EXTENDED || /* Since glibc 2.3.5: */ _POSIX_C_SOURCE >= 200112L        
                ftruncate(jnl->fd, CJF_HEADER_SIZE);
#endif
            }
        }
        
        // got the header loaded
        // now we know the basics about this journal
        // remaining work has to be done on a as-needed basis

        *jh = (journal*)jnl;

        mutex_lock(&journal_cjf_set_mtx);
        ptr_node *journal_cjf_node = ptr_set_avl_insert(&journal_cjf_set, jnl->journal_file_name);
        journal_cjf_node->value = jnl;
        mutex_unlock(&journal_cjf_set_mtx);

#ifdef DEBUG
        log_debug("cjf: returning %r", return_value);
#endif

        return return_value;
    }
}

/** @} */

