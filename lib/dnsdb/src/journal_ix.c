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
#include <dnscore/mutex.h>
#include <dnscore/serial.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/format.h>
#include <dnscore/xfr_copy.h>
#include <dnscore/fdtools.h>

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/journal.h"

#define JOURNAL_FORMAT_NAME "ix"
#define VERSION_HI 0
#define VERSION_LO 1
#define JOURNAL_CLASS_NAME "journal_ix"

#define LOCK_NONE   0
#define LOCK_READ   1
#define LOCK_WRITE  2

#define IX_EXT "ix"
#define IX_EXT_STRLEN 2

#define DEBUG_JOURNAL 1
#ifndef DEBUG
#undef DEBUG_JOURNAL
#define DEBUG_JOURNAL 0
#endif

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define JRNLIX_TAG 0x58494c4e524a

/*
 * Contains the removed records
 */
#define IX_REMOVE_FILE_FORMAT "%s/%{dnsname}%08x-%08x.ir"
/*
 * Contains the added records
 */
#define IX_ADD_FILE_FORMAT "%s/%{dnsname}%08x-%08x.ia"
/*
 * Contains the summary (SOA from / SOA to)
 */
#define IX_SUMMARY_FILE_FORMAT "%s/%{dnsname}%08x-%08x.is"

/*
 * Contains the wire IX (almost: not the matching start and end SOA)
 */

#define IX_WIRE_FILE_FORMAT "%s/%{dnsname}%08x-%08x." IX_EXT

#define FIRST_FROM_END  (IX_EXT_STRLEN + (1 + 8 + 1 + 8))
#define LAST_FROM_END   (IX_EXT_STRLEN + (1 + 8))

/*****************************************************************************/

/**
 * reads the stream for pairs of SOA and return the last odd SOA offset from the
 * initial position of the stream.
 */

static s64
journal_ix_find_last_soa_record(input_stream *is)
{
    dns_resource_record rr;
    dns_resource_record_init(&rr);
    ya_result record_len;
    s64 offset = 0;
    s64 last_page_offset = 0;
    s64 valid_page_offset = -1;
    bool good_one = FALSE;
    
    while((record_len = dns_resource_record_read(&rr, is)) > 0 )
    {
        if(rr.tctr.qtype == TYPE_SOA)
        {
            if(good_one)
            {
                valid_page_offset = last_page_offset;
            }
            else
            {
                last_page_offset = offset;
            }
            good_one = !good_one;
        }
        
        offset += record_len;
    }
    
    if(valid_page_offset != last_page_offset)
    {
        log_err("journal: ix: end of journal seems corrupted. A page started at %lld, after %lld", last_page_offset, valid_page_offset);
    }
    
    if(FAIL(record_len))
    {
        log_err("journal: ix: trouble finding the end of the journal : %r", record_len);
        valid_page_offset = record_len;
    }
    else if(valid_page_offset < 0)
    {
        valid_page_offset = (s32)ZDB_JOURNAL_READING_DID_NOT_FOUND_SOA;
    }

    dns_resource_record_clear(&rr);
    
    return valid_page_offset;
}

/*****************************************************************************/


typedef struct journal_ix journal_ix;

struct journal_ix
{
    /* common points with journal base */
    volatile struct journal_vtbl *vtbl;
    volatile zdb_zone            *zone;    
    volatile struct journal      *next;
    volatile struct journal      *prev;
    
    volatile u32                    rc;
    volatile bool                  mru;
    
    /* ******************************* */

    volatile u32  read_lock_count;
    volatile u8   flags;
    u8            reserved_1;
    u16           journal_name_len;
        
    u32           first_serial;
    u32           last_serial;    
    
    s64           last_page_offset;
    
    char         *journal_name;
    
    int           fd;
};

static void journal_ix_writelock(journal_ix *jix);
static void journal_ix_writeunlock(journal_ix *jix);

static void journal_ix_readlock(journal_ix *jix);
static void journal_ix_readunlock(journal_ix *jix);

static ya_result journal_ix_ensure_opened(journal_ix *jix)
{
    return SUCCESS;
}

static const char *
journal_ix_get_format_name()
{
    return JOURNAL_FORMAT_NAME;
}

static u32
journal_ix_get_format_version()
{
    return VERSION_U32(VERSION_HI,VERSION_LO);
}

/**
 * Appends the uncompressed IXFR stream (SOA RR RR SOA RR RR) to the journal
 * Only checks that the first SOA serial is the current last serial
 * Should also check that the stream is complete before adding it
 */

static ya_result
journal_ix_append_ixfr_stream(journal *jh, input_stream *ixfr_wire_is)
{
    journal_ix *jix = (journal_ix*)jh;
    
    journal_ix_writelock(jix);
    
    /*
     * Move at the end of the file
     * Check that the wire starts with the last soa/serial
     * Append the wire
     * update the last serial
     */
    
    // read the record
    
    ya_result return_value;    
    dns_resource_record rr;
    
    dns_resource_record_init(&rr);
    
    if((return_value = dns_resource_record_read(&rr, ixfr_wire_is)) <= 0)
    {
        /* FAIL or EOF */
        
        dns_resource_record_clear(&rr);
        journal_ix_writeunlock(jix);
        
        log_err("journal: ix: unable to read record: %r", return_value);
        
        return return_value;
    }
    
    /*
     * The first record is an SOA and our starting point (to be deleted)
     */
    
#ifdef DEBUG
    rdata_desc rdatadesc = {rr.tctr.qtype, rr.rdata_size, rr.rdata};
    log_debug("journal: ix: DEL %{dnsname} %{typerdatadesc}", rr.name, &rdatadesc);
#endif
        
    if(rr.tctr.qtype != TYPE_SOA)
    {
        u16 rtype = rr.tctr.qtype;
        dns_resource_record_clear(&rr);
        journal_ix_writeunlock(jix);
        
        log_err("journal: ix: expected SOA record but got %{dnstype} instead", &rtype);
        
        return ZDB_JOURNAL_SOA_RECORD_EXPECTED;
    }
    
    /*
     * check the journal file exists/is defined
     * do it now if not
     * proceed
     */
    
    if(((jix->first_serial == 0) && (jix->last_serial == 0)) || (jix->fd == -1))
    {
        /* the file does not exists yet */
        
        if(FAIL(return_value = rr_soa_get_serial(rr.rdata, rr.rdata_size, &jix->first_serial)))
        {
            dns_resource_record_clear(&rr);
            journal_ix_writeunlock(jix);
            
            log_err("journal: ix: unable to read record: %r", return_value);

            return return_value;
        }
        
        int fd = open_create_ex(jix->journal_name, O_RDWR|O_CREAT, 0644);

        if(fd < 0)
        {
            return_value = ERRNO_ERROR;
            dns_resource_record_clear(&rr);
            journal_ix_writeunlock(jix);
            
            log_err("journal: ix: unable to open journal file '%s': %r", jix->journal_name, return_value);
            
            return return_value;
        }
        
        log_info("journal: ix: journal file created '%s'", jix->journal_name);
        
        jix->fd = fd;
    }
    
    if(FAIL(return_value = journal_ix_ensure_opened(jix)))
    {
        return return_value;
    }
    
    u64 valid_offset = lseek(jix->fd, 0, SEEK_END);
    u64 current_offset = valid_offset;
    
    u32 valid_serial = jix->last_serial;
    u32 potential_serial = valid_serial;
    
    s64 valid_page_offset = jix->last_page_offset;
    s64 potential_page_offset = current_offset;
    
#ifdef DEBUG
    log_debug("journal: ix: ready to append to journal after serial %08x (%d) at offset %lld", valid_serial, valid_serial, valid_offset);
#endif
    
    u8 mode = 0; /* 0: del, 1: add */
    
    output_stream fos;    
    fd_output_stream_attach(jix->fd, &fos);
    output_stream bos;
    buffer_output_stream_init(&fos, &bos, 512);
    
    for(;;)
    {
        /* write the first */

        if(FAIL(return_value = dns_resource_record_write(&rr, &bos)))
        {
            /* this is VERY bad */
            
            log_err("journal: ix: error writing a record to the journal: %r", return_value);

            break;
        }
        
        /* update the current offset */
        
        current_offset += return_value;        
        
        if((return_value = dns_resource_record_read(&rr, ixfr_wire_is)) <= 0) /* no bytes read OR error, there is no macro for this */
        {
            /* error or end of stream */
            
            if(return_value == 0)           /* end of stream */
            {
                if(mode != 0)               /* on add mode so everything should be fine */
                {
                    valid_offset = current_offset;
                    valid_serial = potential_serial;
                    valid_page_offset = potential_page_offset;
                }
                else                        /* but on delete mode instead of add mode */
                {
                    log_err("journal: ix: ixfr stream unexpected eof");

                    return_value = UNEXPECTED_EOF;  /* we have an error */
                }
            }

            break;
        }
        
        if(rr.tctr.qtype == TYPE_SOA)
        {
            mode ^= 1;
            
#ifdef DEBUG
            rdata_desc rdatadesc = {rr.tctr.qtype, rr.rdata_size, rr.rdata};
            log_debug("journal: ix: %s %{dnsname} %{typerdatadesc}", (mode!=0)?"add":"del", rr.name, &rdatadesc);
#endif
            
            if(mode == 0)
            {
                /* 
                 * new SOA to delete
                 * 
                 * it's a new "page" (delete -> add)
                 * 
                 * the offset before we write this record is the highest valid one in the file
                 * so the error correcting truncation will be made at that offset
                 */
                
                valid_offset = current_offset;
                
                /*
                 * the serial number that has been added with the previous page
                 */
                
                valid_serial = potential_serial;
                
                /*
                 * the offset of the previous page
                 */
                
                valid_page_offset = potential_page_offset;
                
                /*
                 * the new page starts here : update
                 */
                
                potential_page_offset = current_offset;
            }
            else
            {
                /*
                 * new SOA add
                 * 
                 * this is the second half of the page, we know what serial it is about
                 */
                
                if(FAIL(return_value = rr_soa_get_serial(rr.rdata, rr.rdata_size, &potential_serial)))
                {
                    break;
                }
            }
        }
#ifdef DEBUG
        else
        {
            rdata_desc rdatadesc = {rr.tctr.qtype, rr.rdata_size, rr.rdata};
            log_debug("journal: ix: %s %{dnsname} %{typerdatadesc}", (mode!=0)?"add":"del", rr.name, &rdatadesc);
        }
#endif
    }

    if(FAIL(return_value))
    {
        /*
         * The journal is only valid up to valid_offset with serial ...
         */
        
        log_err("journal: ix: rewinding journal up to last valid point (%lld)", valid_offset);
        
        ftruncate(jix->fd, valid_offset);
    }
    
#ifdef DEBUG
    log_debug("journal: ix: page offset got from %d to %d", jix->last_page_offset, valid_page_offset);
    log_debug("journal: ix: serial got from %d to %d", jix->last_serial, valid_serial);
#endif
    
    jix->last_page_offset = valid_page_offset;    
    jix->last_serial = valid_serial;
    
    /*
     * rename the file
     */
    
    if(ISOK(return_value))
    {
        char new_name[PATH_MAX];
        memcpy(new_name, jix->journal_name, jix->journal_name_len);
        snformat(&new_name[jix->journal_name_len - FIRST_FROM_END], 8 + 1 + 8 + 1 + IX_EXT_STRLEN + 1,
                "%08x-%08x." IX_EXT , jix->first_serial, jix->last_serial);
        if(rename(jix->journal_name, new_name) >= 0)
        {
            memcpy(jix->journal_name, new_name, jix->journal_name_len);
        }
    }
    
    /*
     */

#ifdef DEBUG
    log_debug("journal: ix: fd=%i from=%08x to=%08x soa@%lld file=%s",
            jix->fd, jix->first_serial, jix->last_serial, jix->last_page_offset, (jix->journal_name!=NULL)?jix->journal_name:"NONE-YET");
#endif
    
    output_stream_flush(&bos);
    fd_output_stream_detach(buffer_output_stream_get_filtered(&bos));
    output_stream_close(&bos);
    
    dns_resource_record_clear(&rr);
    
    journal_ix_writeunlock(jix);
    
    if(ISOK(return_value))
    {
#ifdef DEBUG
        log_debug("journal: ix: page added (fd=%i from=%08x to=%08x soa@%lld file=%s): %r",
                jix->fd, jix->first_serial, jix->last_serial, jix->last_page_offset, (jix->journal_name!=NULL)?jix->journal_name:"NONE-YET",
                return_value);
#endif
        return TYPE_IXFR;       /* that's what the caller expects to handle the new journal pages */
    }
    else
    {    
        log_err("journal: ix: failed to add page");
        return return_value;
    }
}

/*
 * the last_soa_rr is used for IXFR transfers (it has to be a prefix & suffix to the returned stream)
 */

static ya_result
journal_ix_get_ixfr_stream_at_serial(journal *jh, u32 serial_from, input_stream *out_input_stream, dns_resource_record *last_soa_rr)
{
    journal_ix *jix = (journal_ix*)jh;
    ya_result return_value = SUCCESS;
    
    journal_ix_readlock(jix);
    
    /*
     * check that serial_from in in the journal range
     * set the file descriptor to the position
     * create a stream that'll stop at the current end of the stream
     */
    
    if(serial_lt(serial_from, jix->first_serial) || serial_ge(serial_from, jix->last_serial) || ((jix->first_serial == 0) && (jix->last_serial == 0)))
    {
        /* out of known range */
        
        journal_ix_readunlock(jix);
        
        if(serial_from == jix->last_serial)
        {
            return SUCCESS;
        }
        else
        {        
            return ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE;
        }
    }
    
    /*
     * On success, dup() returns a new file descriptor that has the following in common with the original:
     * 
     *  _ Same open file (or pipe)
     *  _ Same file pointer (both file descriptors share one file pointer) <= THIS is a problem
     *  _ Same access mode (read, write, or read/write)
     * 
     * So this is wrong:
     * 
     * cloned_fd = dup(jix->fd);
     */    
    
    int cloned_fd;
    
    while((cloned_fd = open_ex(jix->journal_name, O_RDONLY)) < 0)
    {
        int err = errno;

        if(err == EINTR)
        {
            continue;
        }

        return_value = MAKE_ERRNO_ERROR(err);

#ifdef DEBUG
        log_debug("journal: ix: unable to clone the file descriptor: %r", return_value);
#endif
        journal_ix_readunlock(jix);

        return return_value;
    }
    
    /* 
     * given that I use a clone of the fd and
     * given that only appends are done in the file and
     * given that the limit of the file has already been processed (should be at this point)
     * 
     * THEN
     * 
     * there is no point keeping the lock for reading (on unix systems)
     */
    
    struct stat journal_stat;
    
    s64 last_page_offset = jix->last_page_offset;
    
    if(fstat(cloned_fd, &journal_stat) < 0)
    {
        return_value = ERRNO_ERROR;
        
        log_err("journal: ix: unable to get journal file status", return_value);
        
        close_ex(cloned_fd);

        return return_value;
    }
    
    s64 file_size = journal_stat.st_size;
    
    
#if DEBUG_JOURNAL != 0
    log_debug("journal: ix: the last page starts at position %lld", last_page_offset);
#endif

    journal_ix_readunlock(jix);
    jix = NULL;  
    
    input_stream fis;
    fd_input_stream_attach(cloned_fd, &fis);
    
    if(last_soa_rr != NULL)
    {
        /* seek and store the last SOA print*/
        
        last_soa_rr->tctr.qtype = 0; // clear type
        
        if(lseek(cloned_fd, last_page_offset, SEEK_SET) >= 0)
        {
            /* deleted SOA */
            if((return_value = dns_resource_record_read(last_soa_rr, &fis)) > 0 ) // Not FAIL nor EOF
            {
                if(last_soa_rr->tctr.qtype == TYPE_SOA)
                {
                    /* DEL records */
                    last_soa_rr->tctr.qtype = 0; // clear type
            
                    /* scan until added SOA found */
                    while((return_value = dns_resource_record_read(last_soa_rr, &fis)) > 0 ) // Not FAIL nor EOF
                    {
                        if(last_soa_rr->tctr.qtype == TYPE_SOA)
                        {
                            break;
                        }
                    }
                }
            }
            
            // if the SOA has not been found, it's an error (EOF has been reached is covered by this)
            
            
            if(ISOK(return_value))
            {
                if(last_soa_rr->tctr.qtype != TYPE_SOA)
                {
                    return_value = ZDB_JOURNAL_SOA_RECORD_EXPECTED;
                }
            }
        }
        else
        {
            return_value = ERRNO_ERROR;
        }
        
        if(FAIL(return_value))
        {
            input_stream_close(&fis);
            
            return return_value;
        }
    }
    
    /*
     * this format has no indexing so we scan for a page that STARTS with a DELETE of the SOA with serial = serial_from
     */
    
    if(lseek(cloned_fd, 0, SEEK_SET) != 0)  /* the resulting offset MUST be zero */
    {
        return_value = ERRNO_ERROR;
        
        if(ISOK(return_value))
        {
            return_value = ERROR;
        }
        
        input_stream_close(&fis);
            
        return return_value;
    }
    
    input_stream bis;
    dns_resource_record rr;
    dns_resource_record_init(&rr);
    buffer_input_stream_init(&fis, &bis, 512);
    
    s64 offset = 0;

    /* skip until the right serial is found */

    u32 soa_count = 0;

#ifdef DEBUG_JOURNAL
    u32 rr_count = 0;
#endif
    
    for(;;)
    {
        if( (return_value = dns_resource_record_read(&rr, &bis)) <= 0 ) // FAIL or nothing to 
        {
            return_value = ZDB_JOURNAL_ERROR_READING_JOURNAL; /* is the journal file broken ? */
            
            break;
        }

#ifdef DEBUG_JOURNAL
        rr_count++;
#endif
        
        u32 record_size = return_value;
        
        if(rr.tctr.qtype == TYPE_SOA)
        {
            // ((0+1)&1) != 0 => Y N Y N 
            
            if((++soa_count & 1) != 0) // 1 2 3 4
            {
                u8 *p = rr.rdata;

                if(FAIL(return_value = dnsname_len(p)))
                {
                    break;
                }

                p += return_value;

                if(FAIL(return_value = dnsname_len(p)))
                {
                    break;
                }

                p += return_value;

                u32 serial = ntohl(GET_U32_AT(*p));

                if(serial_ge(serial, serial_from))
                {
                    if(serial == serial_from)
                    {
                        /* setup the serial to be from 'offset' up to the current length of the stream */

                        return_value = SUCCESS;
                    }
                    else
                    {
                        /* the serial does not exist in the range */

                        return_value = ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE;
                    }

                    break;
                }
            }
        }
        
        offset += record_size;
    }
    
#if DEBUG_JOURNAL != 0
    log_debug("journal: ix: serial %08x (%d) is at offset %lld. %d records parsed", serial_from, serial_from, offset, rr_count);
#endif
    
    dns_resource_record_clear(&rr);
    
    /* 
     * detach the file descriptor from the file stream in the buffer stream
     * I do it like this because the streams are not needed anymore but the
     * file descriptor still is (if no error occurred)
     */
    
    fd_input_stream_detach(buffer_input_stream_get_filtered(&bis));
    input_stream_close(&bis);

    if(ISOK(return_value))
    {
        // offset is the start of the page we are looking for
        if(lseek(cloned_fd, offset, SEEK_SET) >= 0)
        {
            fd_input_stream_attach(cloned_fd, &fis);
            limited_input_stream_init(&fis, out_input_stream, file_size - offset);
        }
        else
        {
            return_value = ERRNO_ERROR;
            
            close_ex(cloned_fd);
        }
    }
    else
    {
        close_ex(cloned_fd);
    }
        
    return return_value;
}

static ya_result
journal_ix_get_first_serial(journal *jh, u32 *serial)
{
    journal_ix *jix = (journal_ix*)jh;
    
    journal_ix_readlock(jix);
    
    if(serial != NULL)
    {
        *serial = jix->first_serial;
    }
    
    journal_ix_readunlock(jix);
    
    return SUCCESS;
}

static ya_result
journal_ix_get_last_serial(journal *jh, u32 *serial)
{
    journal_ix *jix = (journal_ix*)jh;
    
    journal_ix_readlock(jix);
    
    if(serial != NULL)
    {
        *serial = jix->last_serial;
    }
    
    journal_ix_readunlock(jix);
    
    return SUCCESS;
}

static ya_result
journal_ix_get_serial_range(journal *jh, u32 *serial_start, u32 *serial_end)
{
    journal_ix *jix = (journal_ix*)jh;
    
    journal_ix_readlock(jix);
    
    if(serial_start != NULL)
    {
        *serial_start = jix->first_serial;
    }
    if(serial_end != NULL)
    {
        *serial_end = jix->last_serial;
    }
    
    journal_ix_readunlock(jix);
    
    return SUCCESS;
}

static ya_result
journal_ix_truncate_to_size(journal *jh, u32 size_)
{
    /*
     * lock for a reader (block any new append)
     * create a new file to have roughly the right size
     * open the new file and use it
     * close the old file
     */
    journal_ix *jix = (journal_ix*)jh;

    if(size_ == 0)
    {
        log_debug("journal: ix: truncate to size 0 = delete", size_);

        if(jix->journal_name != NULL)
        {
            unlink(jix->journal_name);
            free(jix->journal_name);
            jix->journal_name = NULL;
            if(jix->fd >= 0)
            {
                close_ex(jix->fd);
                jix->fd = -1;
            }
        }

        return SUCCESS;
    }
    else
    {
        log_debug("journal: ix: truncate to size != 0 not implemented");
        
        return ZDB_JOURNAL_FEATURE_NOT_SUPPORTED;
    }
}

static ya_result
journal_ix_truncate_to_serial(journal *jh, u32 serial_)
{
    /*
     * lock for a reader (block any new append)
     * create a new file to start at the serial
     * open the new file and use it
     * close the old file
     */
    
    log_debug("journal: ix: truncate to serial not implemented (serial=%u)", serial_);
    
    return ZDB_JOURNAL_FEATURE_NOT_SUPPORTED;
}

static ya_result
journal_ix_close(journal *jh)
{
    journal_ix *jix = (journal_ix*)jh;
    
    journal_ix_writelock(jix);
    
    free(jix->journal_name);
    close_ex(jix->fd);
    jix->fd = -1;
    // don't do it "properly"
    //journal_ix_writeunlock(jix);
    // instead keep the write owner (preventing further use)
    assert(jix->flags == LOCK_WRITE);
    
    jix->vtbl = NULL;
    
    // and finally free it
    free(jix);
        
    return SUCCESS;
}

static void
journal_ix_log_dump_method(journal *jh)
{
    journal_ix *jix = (journal_ix*)jh;

    const u8 *origin;
    if(jh->zone != NULL)
    {
        origin = FQDNNULL(jix->zone->origin);
    }
    else
    {
        origin = (const u8*)"\012NOT-LINKED";
    }

    log_debug("domain='%{dnsname}' rc=%i mru=%i file='%s' fd=%i range=%u:%u lpo=%llu",
                origin,
                jix->rc,
                (jix->mru)?1:0,
                STRNULL(jix->journal_name),
                jix->fd,
                jix->first_serial,
                jix->last_serial,
                jix->last_page_offset);
}

struct journal_vtbl journal_ix_vtbl =
{
    journal_ix_get_format_name,
    journal_ix_get_format_version,
    journal_ix_close,
    journal_ix_append_ixfr_stream,
    journal_ix_get_ixfr_stream_at_serial,
    journal_ix_get_first_serial,
    journal_ix_get_last_serial,
    journal_ix_get_serial_range,
    journal_ix_truncate_to_size,
    journal_ix_truncate_to_serial,
    journal_ix_log_dump_method,
    
    JOURNAL_CLASS_NAME
};



static void
journal_ix_writelock(journal_ix *jix)
{
#if DEBUG_JOURNAL != 0
    log_debug("journal_ix_writelock: locking");
#endif

    for(;;)
    {
        journal_lock();

        u8 f = jix->flags;
        
        if(f == LOCK_NONE)              // nobody has the lock
        {
            jix->flags = LOCK_WRITE;    // so one writer can
            /*
            assert(jix->rc == 0);            
            jix->rc = 1;
            */
            journal_unlock();
            break;
        }

        journal_unlock();

        usleep(1000);
    }
    
#if DEBUG_JOURNAL != 0
    log_debug("journal_ix_writelock: locked");
#endif

}

static void
journal_ix_writeunlock(journal_ix *jix)
{
#if DEBUG_JOURNAL != 0
    log_debug("journal_ix_writeunlock: unlocking");
#endif

    journal_lock();
    
    if(jix->flags == LOCK_WRITE)    // the writer has the lock (hopefully this one)
    {
        jix->flags = LOCK_NONE;     // so we can unlock
        
        journal_unlock();
    
#if DEBUG_JOURNAL != 0
        log_debug("journal_ix_writeunlock: unlocked");
#endif
    }
    else // else there is something really wrong happening
    {
        // bug
        log_err("journal: ix: write-unlock non-writer");
        
        journal_unlock();
        return;
    }
}

static void
journal_ix_readlock(journal_ix *jix)
{
    /*
    jix->rc++;
    */
    for(;;)
    {
        journal_lock();

        u8 f = jix->flags;

        if(f != LOCK_WRITE)             // either nobody or the reader has the lock 
        {
            jix->flags = LOCK_READ;
            jix->read_lock_count++;     // count the readers
            journal_unlock();
            break;
        }

        journal_unlock();

        usleep(1000);
    }
}

static void
journal_ix_readunlock(journal_ix *jix)
{
    journal_lock();
    
    if(jix->flags == LOCK_READ)     // a reader has the lock
    {
        if((--jix->read_lock_count) == 0) // count the readers
        {
            jix->flags = LOCK_NONE; // if there are no readers anymore, nobody has the lock
        }
        
        journal_unlock();
    }
    else   
    {
        journal_unlock();
        
        // bug
        log_err("journal: ix: read-unlock non-reader");
    }

    /*
    jix->rc--;
    */
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
journal_ix_open(journal **jh, const u8* origin, const char *workingdir, bool create)
{
    /*
     * try to open the journal file
     * if it exists, create the structure for the handle
     */
    
#ifdef DEBUG
    log_debug("journal: ix: open(%p, '%{dnsname}', \"%s\", %d)", jh, origin, workingdir, (create)?1:0);
#endif
    
    struct dirent entry;
    struct dirent *result;
    DIR    *dir;
    u32    from;
    u32    to;
    char   fqdn[MAX_DOMAIN_LENGTH + 1];
    char   filename[PATH_MAX];
    
    if((jh == NULL) || (origin == NULL) || (workingdir == NULL))
    {
        return ZDB_JOURNAL_WRONG_PARAMETERS;
    }
    
#ifdef DEBUG
    log_debug("journal: ix: trying to open journal for %{dnsname} in '%s'", origin, workingdir);
#endif
    
    /* get the soa of the loaded zone */
    
    *jh = NULL;
    
    // open the working directory
    
    dir = opendir(workingdir);
    
    if(dir == NULL)
    {
#ifdef DEBUG
        log_debug("journal: ix: trying to open directory for %{dnsname} in '%s' failed: %r", origin, workingdir, ERRNO_ERROR);
#endif
        return ZDB_ERROR_ICMTL_NOTFOUND;
    }
    
    u32 fqdn_len = dnsname_to_cstr(fqdn, origin);    
    result = NULL;
    
    // scan for the journal file
    
    ya_result return_value = SUCCESS;
    
    do
    {
        readdir_r(dir, &entry, &result);
        
        if(result == NULL)
        {
            return_value = ZDB_ERROR_ICMTL_NOTFOUND;
            
            break;
        }
        
        u8 d_type = dirent_get_file_type(workingdir, result);

        if(d_type != DT_REG )
        {
            /* not a regular file */
            
            continue;
        }
        
        if(memcmp(result->d_name, fqdn, fqdn_len) != 0)
        {
            continue;
        }
        
        const char *serials = &result->d_name[fqdn_len];
        
        if(strlen(serials) != 8 + 1 + 8 + 1 + IX_EXT_STRLEN)
        {
            continue;
        }
        
        int converted = sscanf(serials, "%08x-%08x", &from, &to);
        
        if(converted != 2)
        {
            continue;
        }
        
        snprintf(filename, sizeof(filename), "%s/%s", workingdir, result->d_name);
        
        /* got a valid one :
            * open the file
            */

        int fd = open_ex(filename, O_RDWR);

        if(fd >= 0)
        {
            return_value = SUCCESS;

            /*
             * Got a journal file, initialise the handling structure
             */

            journal_ix *jix;

            MALLOC_OR_DIE(journal_ix*, jix, sizeof(journal_ix), JRNLIX_TAG);
            ZEROMEMORY(jix, sizeof(journal_ix));
            jix->vtbl = &journal_ix_vtbl;
            jix->flags = LOCK_NONE;
            jix->first_serial = from;
            jix->last_serial = to;
            jix->journal_name = strdup(filename);
            jix->journal_name_len = strlen(filename);
            jix->fd = fd; // file opened
            
            // get the information from the file
            
#ifdef DEBUG
            log_debug("journal: ix: got a journal file");
#endif
            input_stream fis;
            input_stream bis;
            
            if(ISOK(return_value = fd_input_stream_attach(jix->fd, &fis)))
            {
                buffer_input_stream_init(&fis, &bis, BUFFER_INPUT_STREAM_DEFAULT_BUFFER_SIZE);
                s64 soa_offset = journal_ix_find_last_soa_record(&bis);
                if(soa_offset >= 0)
                {
                    jix->last_page_offset = soa_offset;
                }
                else
                {
                    return_value = (s32)soa_offset; // an error occurred
                }
                fd_input_stream_detach(buffer_input_stream_get_filtered(&bis));
                input_stream_close(&bis);
            }

            if(FAIL(return_value)) // mostly: unable to open the file or unable to find the SOA in the file
            {
                /* parsing for SOA failed */
                journal_ix_close((journal*)jix);
                jix = NULL;
            }
            
            *jh = (journal*)jix;
        }
        else
        {
            /* something is wrong with this one */

            log_err("journal: ix: an error occurred opening journal file '%s': %r", filename, ERRNO_ERROR);
        }
    }
    while(*jh == NULL);
    
    closedir(dir);
    
    // if the journal was not found and we can create it
    
    if((*jh == NULL) && create)
    {
        // create the structure
        
#ifdef DEBUG
        log_debug("journal: ix: no file found, creating an empty structure");
#endif
        journal_ix *jix;
        char journal_name[PATH_MAX];
                
        MALLOC_OR_DIE(journal_ix*, jix, sizeof(journal_ix), JRNLIX_TAG);
        ZEROMEMORY(jix, sizeof(journal_ix));
        jix->vtbl = &journal_ix_vtbl;
        jix->flags = LOCK_NONE;
        jix->first_serial = 0;
        jix->last_serial = 0;
        jix->journal_name = NULL;
        jix->fd = -1;   // no file opened
        
        jix->journal_name_len = snformat(journal_name, sizeof(journal_name), IX_WIRE_FILE_FORMAT, workingdir, origin, 0, 0);
        jix->journal_name = strdup(journal_name);
        
        *jh = (journal*)jix;
        
        return_value = SUCCESS; /* newly created journal structure */
    }
    
#ifdef DEBUG
    log_debug("journal: ix: returning %r", return_value);
#endif
    
    return return_value;
}

/** @} */

/*----------------------------------------------------------------------------*/
