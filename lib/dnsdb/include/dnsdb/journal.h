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

#if !ZDB_JOURNAL_CODE

/*
 * Direct usage of journal is risky.  So now all allowed code (c files only) have :
 * #define ZDB_JOURNAL_CODE 1 before the includes.
 */

#error "Please do not include dnsdb/journal.h directly."
#endif

#define JOURNAL_IX_ENABLED 0
#define JOURNAL_CJF_ENABLED 0
#define JOURNAL_JNL_ENABLED 1

#include <dnscore/input_stream.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/list-dl.h>

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

void journal_finalize();

/**
 * 
 * The default part for XFR'ing
 * 
 * @param path
 */

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
 * The stream is : [SOA- RR- RR- RR- SOA+ RR+ RR+ RR+]+ <EOS>
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
typedef ya_result journal_reopen_method(journal *jh);
typedef void journal_flush_method(journal *jh);
typedef ya_result journal_close_method(journal *jh);
typedef ya_result journal_get_domain_method(journal *jh, u8 *out_domain);
typedef const u8 *journal_get_domain_const_method(const journal *jh);
typedef void journal_destroy_method(journal *jh);
typedef void journal_log_dump_method(journal *jh);
typedef void journal_minimum_serial_update_method(journal *jh, u32 stored_serial);
typedef void journal_maximum_size_update_method(journal *jh, u32 maximum_size);
typedef void journal_limit_size_update_method(journal *jh, u32 maximum_size);

//typedef void journal_link_zone_method(journal *jh, zdb_zone *zone);

struct journal_vtbl
{
    journal_get_format_name_method           *get_format_name;          // returns a const char*
    journal_get_format_version_method        *get_format_version;       // returns the version
    journal_reopen_method                    *reopen;                   // opens the file, if it has temporarily been closed
    journal_flush_method                     *flush;                    // flushes to storage
    journal_close_method                     *close;                    // closes the file
    journal_append_ixfr_stream_method        *append_ixfr_stream;       // appends IXFR (without the first/last SOA) to the journal
    journal_get_ixfr_stream_at_serial_method *get_ixfr_stream_at_serial;// returns a stream starting at serial SN    
    journal_get_first_serial_method          *get_first_serial;         // returns the first serial in the journal
    journal_get_last_serial_method           *get_last_serial;          // returns the last serial in the journal
    journal_get_serial_range_method          *get_serial_range;         // returns both the first and last serials in the journal
    journal_truncate_to_size_method          *truncate_to_size;         // truncates the journal size (probably never used)
    journal_truncate_to_serial_method        *truncate_to_serial;       // truncates the journal to a serial (probably never used)
    journal_log_dump_method                  *log_dump;                 // dumps the status of the journal on the database logger
    journal_get_domain_method                *get_domain;               // copies the domain to the output buffer
    journal_destroy_method                   *destroy;                  // destroys the journal at the first opportunity
    journal_get_domain_const_method          *get_domain_const;         // copies the domain to the output buffer
    journal_minimum_serial_update_method     *minimum_serial_update;    // stores the minimum serial the zone must contain (continuity from the zone)
    journal_maximum_size_update_method       *maximum_size_update;      // updates the maximum size of the journal, applied at the earliest convenience
    journal_limit_size_update_method         *limit_size_update;        // updates the limit size of the journal, applied at the earliest convenience
    const  char* __class__;
};

struct journal
{
    volatile struct journal_vtbl *vtbl;
    volatile list_dl_node_s   mru_node; // to list the journals by most to least recently used
    volatile int                    rc;
    volatile unsigned int _forget:1,_mru:1;
    
    /* The journal is not like a stream, it's a full standalone entity always returned as a pointer.
     * So the handler can do whatever it wants after "mru"
     */
};

#define journal_get_format_name(j_)                                             (j_)->vtbl->get_format_name()
#define journal_get_format_version(j_)                                          (j_)->vtbl->get_format_version()
//#define journal_close(j_)                                                       (j_)->vtbl->close(j_)
#define journal_append_ixfr_stream(j_, ixfr_wire_is_)                           (j_)->vtbl->append_ixfr_stream((j_), (ixfr_wire_is_))
#define journal_get_ixfr_stream_at_serial(j_, serial_form_, out_input_stream_, \
                                          dns_rr_)                              (j_)->vtbl->get_ixfr_stream_at_serial((j_), (serial_form_), (out_input_stream_), (dns_rr_))
#define journal_get_first_serial(j_, serial_)                                   (j_)->vtbl->get_first_serial((j_),(serial_))
#define journal_get_last_serial(j_, serial_)                                    (j_)->vtbl->get_last_serial((j_),(serial_))
#define journal_get_serial_range(j_, serial_start_, serial_end_)                (j_)->vtbl->get_serial_range((j_),(serial_start_),(serial_end_))
#define journal_truncate_to_size(j_, size_)                                     (j_)->vtbl->truncate_to_size((j_), (size_))
#define journal_truncate_to_serial(j_, serial_)                                 (j_)->vtbl->truncate_to_serial((j_), (serial_))
//#define journal_link_zone(j_, zone_)                                            (j_)->vtbl->link_zone((j_), (zone_))
#define journal_get_domain_const(j_)                                            (j_)->vtbl->get_domain_const((j_))

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

ya_result journal_acquire_from_fqdn_ex(journal **jhp, const u8 *origin, bool create);
ya_result journal_acquire_from_fqdn(journal **jhp, const u8 *origin);
ya_result journal_acquire_from_zone_ex(journal **jhp, zdb_zone *zone, bool create);
ya_result journal_acquire_from_zone(journal **jhp, zdb_zone *zone);
void journal_acquire(journal *jh);

/**
 * 
 * Decrement the reference count and potentially closes it if it reaches 0
 * 
 * @param jh
 * @return 
 */

void journal_release(journal *jh);

/**
 * Returns the last available serial of a journal for a zone.
 * Does this by opening the journal.
 * This function should NOT be used for a loaded zone.
 */

ya_result journal_last_serial(const u8 *origin, u32 *serialp);

ya_result journal_serial_range(const u8 *origin, u32 *serialfromp, u32 *serialtop);

/*
 * Empties/deletes a journal
 * Does this by opening the journal and calling a truncate to size 0
 * This function should NOT be used for a loaded zone.
 */

ya_result journal_truncate(const u8 *origin);

/**
 * Returns the last SOA TTL + RDATA
 *
 * @param jh the journal
 * @param rr an initialised resource record
 *
 * @return an error code
 */

ya_result journal_get_last_soa(journal *jh, dns_resource_record *rr);

/**
 * Flushes, closes and destroys all currently unused journals (from memory)
 */

void journal_close_unused();


/**
 * Logs the current status of the journaling system
 */

void journal_log_status();

#ifdef	__cplusplus
}
#endif

#endif	/* JOURNAL_H */

/* @} */

