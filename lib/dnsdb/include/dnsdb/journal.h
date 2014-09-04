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
 *  @ingroup dnsdb
 *  @brief
 *
 * Journal API
 *
 *
 * @{
 */

#ifndef JOURNAL_H
#define	JOURNAL_H

#include <dnscore/input_stream.h>
#include <dnscore/dns_resource_record.h>
#include <dnsdb/zdb_types.h>

#ifdef	__cplusplus
extern "C" {
#endif
    
/*
 * We should handle multiple formats.  So the journal can improve and the older formats still be loaded
 * At some point we could also register journal formats but it does not seems important for now.
 */
    
typedef struct journal journal;

ya_result journal_init(u32 mru_size);

void journal_finalise();

void journal_set_xfr_path(const char *path);
const char* journal_get_xfr_path();

/**
 * Opens (or create) the journal for the zone
 * 
 * @param jh            pointer will be set to the journal handling structure
 * @param origin        origin of the zone
 * @param create        create an empty journal if none has been found
 * 
 * @return an error code
 */

typedef ya_result journal_open_method(journal **jh, u8* origin, bool create);

typedef const char *journal_get_format_name_method();
typedef u32         journal_get_format_version_method();

/*
 * The stream is : SOA- RR- RR- RR- SOA+ RR+ RR+ RR+ <EOS>
 */

typedef ya_result journal_append_ixfr_stream_method(journal *jh, input_stream *ixfr_wire_is);

/**
 * rr can be NULL
 */

typedef ya_result journal_get_ixfr_stream_at_serial_method(journal *jh, u32 serial_from, input_stream *out_input_stream, dns_resource_record* rr);

typedef ya_result journal_get_first_serial_method(journal *jh, u32 *serial);
typedef ya_result journal_get_last_serial_method(journal *jh, u32 *serial);
typedef ya_result journal_get_serial_range_method(journal *jh, u32 *serial_start, u32 *serial_end);

typedef ya_result journal_truncate_to_size_method(journal *jh, u32 size_);
typedef ya_result journal_truncate_to_serial_method(journal *jh, u32 serial_);
typedef ya_result journal_close_method(journal *jh);
typedef void journal_log_dump_method(journal *jh);

struct journal_vtbl
{
    journal_get_format_name_method           *get_format_name;
    journal_get_format_version_method        *get_format_version;
    journal_close_method                     *close;
    journal_append_ixfr_stream_method        *append_ixfr_stream;
    journal_get_ixfr_stream_at_serial_method *get_ixfr_stream_at_serial;
    journal_get_first_serial_method          *get_first_serial;
    journal_get_last_serial_method           *get_last_serial;
    journal_get_serial_range_method          *get_serial_range;
    journal_truncate_to_size_method          *truncate_to_size;
    journal_truncate_to_serial_method        *truncate_to_serial;
    journal_log_dump_method                  *log_dump;
    
    const  char* __class__;
};

struct journal
{
    volatile struct journal_vtbl *vtbl;
    volatile zdb_zone            *zone;
    volatile struct journal      *next;
    volatile struct journal      *prev;
    volatile s32                    rc;
    volatile bool                  mru;
    /* The journal is not like a stream, it's a full standalone entity always returned as a pointer.
     * So the handler can do whatever it wants after "vtbl"
     */
};

#define journal_get_format_name(j_)                                            (j_)->vtbl->get_format_name()
#define journal_get_format_version(j_)                                         (j_)->vtbl->get_format_version()
//#define journal_close(j_)                                                      (j_)->vtbl->close(j_)
#define journal_append_ixfr_stream(j_, ixfr_wire_is_)                          (j_)->vtbl->append_ixfr_stream((j_), (ixfr_wire_is_))
#define journal_get_ixfr_stream_at_serial(j_, serial_form_, out_input_stream_, \
                                          dns_rr_)                             (j_)->vtbl->get_ixfr_stream_at_serial((j_), (serial_form_), (out_input_stream_), (dns_rr_))
#define journal_get_first_serial(j_, serial_)                                  (j_)->vtbl->get_first_serial((j_),(serial_))
#define journal_get_last_serial(j_, serial_)                                   (j_)->vtbl->get_last_serial((j_),(serial_))
#define journal_get_serial_range(j_, serial_start_, serial_end_)               (j_)->vtbl->get_serial_range((j_),(serial_start_),(serial_end_))
#define journal_truncate_to_size(j_, size_)                                    (j_)->vtbl->truncate_to_size((j_), (size_))
#define journal_truncate_to_serial(j_, serial_)                                (j_)->vtbl->truncate_to_serial((j_), (serial_))

/**
 * 
 * Returns the journal for a loaded zone.
 * 
 * DO NOT USE THE JOURNAL WITHOUT OPENING IT.
 * ie: TAKING IT DIRECTLY FROM THE ZONE NODE IN THE DATABASE.
 * IT ***WILL*** RACE-FAIL !!!
 * 
 * @param jhp
 * @param zone
 * @param workingdir
 * @param create
 * @return 
 */

ya_result journal_open(journal **jhp, zdb_zone *zone, const char *workingdir, bool create);

/**
 * 
 * Closes a journal (decrement the reference count and delete if zero)
 * If no reference exists, remove the journal
 * 
 * @param jh
 * @return 
 */

void journal_close(journal *jh);

/**
 * Returns the last serial of a journal for a zone.
 * Does this by opening the journal.
 * This function should NOT be used for a loaded zone.
 */

ya_result journal_last_serial(const u8 *origin, const char *workingdir, u32 *serialp);

/*
 * Empties/deletes a journal
 * Does this by opening the journal and calling a truncate to size 0
 * This function should NOT be used for a loaded zone.
 */

ya_result journal_truncate(const u8 *origin, const char *workingdir);

/**
 * 
 * @param origin
 * @param workingdir
 * @param last_soa_rdata
 * @param last_soa_rdata_size
 * @return 
 */

ya_result journal_last_soa(const u8 *origin, const char *workingdir, u32 *serial, u32 *ttl, u8 *last_soa_rdata, u16 *last_soa_rdata_size);

void journal_lock();
void journal_unlock();

/**
 * Logs the current status of the journaling system
 */

void journal_log_status();

#ifdef	__cplusplus
}
#endif

#endif	/* JOURNAL_H */

/* @} */

