/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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

/**-----------------------------------------------------------------------------
 * @defgroup types The types used in the database
 * @ingroup dnsdb
 * @brief The types used in the database
 *
 * The types used in the database
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnscore/dnscore_config_features.h>
#include <dnsdb/zdb_config_features.h>
#include "dnscore/sys_types.h"

#if DNSCORE_HAVE_STDATOMIC_H
#include <stdatomic.h>
#elif __windows__
#include <stdatomic.h>
#else
#include <dnscore/thirdparty/stdatomic.h>
#endif

#include <dnscore/dnsname.h>
#include <dnscore/rfc.h>
#include <dnscore/dns_message.h>
#include <dnscore/alarm.h>
#include <dnscore/mutex.h>
#include <dnscore/acl.h>

#include <dnsdb/zdb_config.h>
#include <dnsdb/zdb_zone_resource_record_sets.h>
#include <dnsdb/dictionary.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct journal;

#define ROOT_LABEL                 ((uint8_t *)"")

#define ZDB_ZONE_LOCK_HAS_OWNER_ID 0 // debug

#if ZDB_ZONE_LOCK_HAS_OWNER_ID
#pragma message("***********************************************************")
#pragma message("***********************************************************")
#pragma message("ZDB_ZONE_LOCK_HAS_OWNER_ID 1")
#pragma message("***********************************************************")
#pragma message("***********************************************************")
#endif

/* zdb_zone */

struct zdb_zone_s;
typedef struct zdb_zone_s zdb_zone_t;

#define LABEL_HAS_RECORDS(label_) (!zdb_resource_record_sets_set_isempty(&(label_)->resource_record_set))

/* zdb_rr_label */

typedef dictionary_t zdb_rr_label_map_t;

struct zdb_rr_label_s;
typedef struct zdb_rr_label_s zdb_rr_label_t;

#if ZDB_HAS_DNSSEC_SUPPORT

#if ZDB_HAS_NSEC_SUPPORT

typedef struct nsec_label_extension_s nsec_label_extension_t;

struct nsec_node_s;
typedef struct nsec_node_s nsec_zone_t;

#endif

#if ZDB_HAS_NSEC3_SUPPORT
struct nsec3_zone_s;
typedef struct nsec3_zone_s nsec3_zone_t;
#endif

typedef struct dnssec_zone_extension_s dnssec_zone_extension_t;

struct dnssec_zone_extension_s
{
#if ZDB_HAS_NSEC_SUPPORT
    /*
     * A pointer to an array of nsec_label (nsec_label buffer[])
     * The size is the same as the dictionnary
     */
    nsec_zone_t *nsec;
#endif

#if ZDB_HAS_NSEC3_SUPPORT
    nsec3_zone_t *nsec3;
#endif
};

typedef union nsec_label_union nsec_label_union;

struct nsec_label_extension_s
{
    struct nsec_node_s *node;
};

union nsec_label_union
{
    /* NSEC */
#if ZDB_HAS_NSEC_SUPPORT
    nsec_label_extension_t nsec;
#endif

    /* NSEC3 */
#if ZDB_HAS_NSEC3_SUPPORT
    struct nsec3_label_extension_s *nsec3;
#endif

    /* Placeholder */
    void *dnssec;
};

#endif

/*
 * RR_LABEL flags
 */

/*
 * For the apex, marks a label as being the apex
 */

#define ZDB_RR_LABEL_APEX            0x0001

/*
 * For any label but the apex : marks it as being a delegation (contains an NS record)
 */

#define ZDB_RR_LABEL_DELEGATION      0x0002

/*
 * For any label, means there is a delegation (somewhere) above
 */

#define ZDB_RR_LABEL_UNDERDELEGATION 0x0004

/*
 * For any label : marks that one owns a '*' label
 */

#define ZDB_RR_LABEL_GOT_WILD        0x0008

/*
 * Explicitly mark a label as owner of a (single) CNAME
 */

#define ZDB_RR_LABEL_HASCNAME        0x0010

/*
 * Explicitly mark a label as owner of a something that is not a CNAME nor RRSIG nor NSEC
 */

#define ZDB_RR_LABEL_DROPCNAME       0x0020

#define ZDB_RR_LABEL_N3COVERED       0x0040 // expected coverage
#define ZDB_RR_LABEL_N3OCOVERED      0x0080 // expected coverage

#if ZDB_HAS_DNSSEC_SUPPORT
/*
 * This flag means that the label has a valid NSEC structure
 *
 * IT IS NOT VALID TO CHECK THIS TO SEE IF A ZONE IS NSEC
 */
#define ZDB_RR_LABEL_NSEC         0x0100

/*
 * This flag means that the label has a valid NSEC3 structure
 *
 * IT IS NOT VALID TO CHECK THIS TO SEE IF A ZONE IS NSEC3
 */
#define ZDB_RR_LABEL_NSEC3        0x0200 // structure

/*
 * The zone is (NSEC3) + OPTOUT (NSEC3 should also be set)
 *
 * IT IS NOT VALID TO CHECK THIS TO SEE IF A ZONE IS NSEC3
 */

#define ZDB_RR_LABEL_NSEC3_OPTOUT 0x0400 // structure

#define ZDB_RR_LABEL_DNSSEC_MASK  0x0700
#define ZDB_RR_LABEL_DNSSEC_SHIFT 8

/*
 * Marks a label so it cannot be deleted.
 * Used for incremental changes when it is known that an empty terminal will have records added.
 * (Avoiding to delete then re-create several structures)
 */
#define ZDB_RR_LABEL_KEEP         0x0800

#endif

#define ZDB_RR_LABEL_HAS_NS                  0x1000 // quick check of the presence of an NS record
#define ZDB_RR_LABEL_HAS_DS                  0x2000 // quick check of the presence of an DS record

#define ZDB_LABEL_UNDERDELEGATION(__l__)     ((((__l__)->_flags) & ZDB_RR_LABEL_UNDERDELEGATION) != 0)
#define ZDB_LABEL_ATDELEGATION(__l__)        ((((__l__)->_flags) & ZDB_RR_LABEL_DELEGATION) != 0)
#define ZDB_LABEL_ATORUNDERDELEGATION(__l__) ((((__l__)->_flags) & (ZDB_RR_LABEL_DELEGATION | ZDB_RR_LABEL_UNDERDELEGATION)) != 0)

struct zdb_rr_label_s
{
    zdb_rr_label_t                *next; /* dictionnary_node* next */          /*  4  8 */
    zdb_rr_label_map_t             sub; /* dictionnary of N children labels */ /* 16 24 */

    zdb_resource_record_sets_set_t resource_record_set; /* resource records for the ²label (a btree)*/ /*  4  4 */

#if ZDB_HAS_DNSSEC_SUPPORT
    nsec_label_union nsec;
#endif

    uint16_t _flags; /* NSEC, NSEC3, and 6 for future usage ... */

    uint8_t  name[1]; /* label */ /*  4  8 */
    /* No zone ptr */
}; /* 28 44 => 32 48 */

static inline void     zdb_rr_label_flag_or(zdb_rr_label_t *rr_label, uint16_t or_mask) { rr_label->_flags |= or_mask; }

static inline void     zdb_rr_label_flag_and(zdb_rr_label_t *rr_label, uint16_t and_mask) { rr_label->_flags &= and_mask; }

static inline void     zdb_rr_label_flag_or_and(zdb_rr_label_t *rr_label, uint16_t or_mask, uint16_t and_mask) { rr_label->_flags = (rr_label->_flags | or_mask) & and_mask; }

static inline bool     zdb_rr_label_flag_isset(const zdb_rr_label_t *rr_label, uint16_t and_mask) { return (rr_label->_flags & and_mask) != 0; }

static inline bool     zdb_rr_label_flag_matches(const zdb_rr_label_t *rr_label, uint16_t and_mask) { return (rr_label->_flags & and_mask) == and_mask; }

static inline bool     zdb_rr_label_flag_isclear(const zdb_rr_label_t *rr_label, uint16_t and_mask) { return (rr_label->_flags & and_mask) == 0; }

static inline uint16_t zdb_rr_label_flag_get(const zdb_rr_label_t *rr_label) { return rr_label->_flags; }

static inline bool     zdb_rr_label_is_apex(const zdb_rr_label_t *rr_label) { return zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_APEX); }

static inline bool     zdb_rr_label_is_not_apex(const zdb_rr_label_t *rr_label) { return zdb_rr_label_flag_isclear(rr_label, ZDB_RR_LABEL_APEX); }

#define ZDB_ZONE_MUTEX_EXCLUSIVE_FLAG 0x80
#define ZDB_ZONE_MUTEX_LOCKMASK_FLAG  0x7f

#if ZDB_HAS_EXPERIMENTAL_EXCLUSIVE_OVER_SHARED
#define ZDB_ZONE_MUTEX_TRANSFER_FLAG   0x40
#define ZDB_ZONE_MUTEX_UNLOCKMASK_FLAG 0x3f
#else
#define ZDB_ZONE_MUTEX_UNLOCKMASK_FLAG 0x7f
#endif

#define ZDB_ZONE_MUTEX_NOBODY        GROUP_MUTEX_NOBODY
#define ZDB_ZONE_MUTEX_SIMPLEREADER  0x01 /* non-conflicting */
#define ZDB_ZONE_MUTEX_RRSIG_UPDATER 0x82 /* conflicting */
#define ZDB_ZONE_MUTEX_XFR           0x84 /* conflicting, cannot by nature be launched more than once in parallel.  new ones have to be discarded */
#define ZDB_ZONE_MUTEX_REFRESH       0x85 /* conflicting, can never be launched more than once.  new ones have to be discarded */
#define ZDB_ZONE_MUTEX_DYNUPDATE     0x86 /* conflicting */
#define ZDB_ZONE_MUTEX_UNFREEZE      0x87 /* conflicting, needs to be sure nobody else (ie: the freeze) is acting at the same time */
#define ZDB_ZONE_MUTEX_INVALIDATE    0x88 /* conflicting */
#define ZDB_ZONE_MUTEX_REPLACE       0x89 /* conflicting */
#define ZDB_ZONE_MUTEX_LOAD          0x8a /* conflicting but this case is impossible */
#define ZDB_ZONE_MUTEX_NSEC3         0x8b /* conflicting, marks an hard operation to be done */
#define ZDB_ZONE_MUTEX_DESTROY       0xff /* conflicting, can never be launched more than once.  The zone will be destroyed before unlock. */

typedef ya_result zdb_zone_access_filter(const dns_message_t * /*mesg*/, const void * /*zone_extension*/);

#define ALARM_KEY_ZONE_SIGNATURE_UPDATE                1
#define ALARM_KEY_ZONE_AXFR_QUERY                      2
#define ALARM_KEY_ZONE_REFRESH                         3

#define ALARM_KEY_ZONE_DNSKEY_PUBLISH                  4
#define ALARM_KEY_ZONE_DNSKEY_UNPUBLISH                5
#define ALARM_KEY_ZONE_DNSKEY_ACTIVATE                 6
#define ALARM_KEY_ZONE_DNSKEY_DEACTIVATE               7
#define ALARM_KEY_ZONE_NEXT_AVAILABLE_ID               7

#define ALARM_KEY_ZONE_NOTIFY_SECONDARIES              8

#define ZDB_ZONE_KEEP_RAW_SIZE                         1

#define ZDB_ZONE_STATUS_NEED_REFRESH                   1
#define ZDB_ZONE_STATUS_DUMPING_AXFR                   2
#define ZDB_ZONE_STATUS_WILL_NOTIFY                    4 // in the queue
#define ZDB_ZONE_STATUS_MODIFIED                       8 // content has been changed since last time (typically, a replay has been done)
#define ZDB_ZONE_STATUS_WILL_NOTIFY_AGAIN              16
#define ZDB_ZONE_STATUS_SAVE_CLEAR_JOURNAL_AFTER_MOUNT 32 // if a corrupted chain has been

#define ZDB_ZONE_ERROR_STATUS_DIFF_FAILEDNOUSABLE_KEYS 1

/*
 * The zone has expired or is a stub (while the real zone is being loaded)
 */

#define ZDB_ZONE_STATUS_INVALID                        64

/*
 * Forbid updates of the zone
 */
#define ZDB_ZONE_STATUS_FROZEN                         128

#define ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF              256
#define ZDB_ZONE_STATUS_GENERATE_CHAIN                 512

// #define ZDB_ZONE_STATUS_KEEP_TEXT_UNUSED      16   // when storing an image, always keep it as text (slower, bigger)

#define ZDB_ZONE_HAS_OPTOUT_COVERAGE                   1 // assumed true, until something else is found
#define ZDB_ZONE_MAINTAIN_NOSEC                        0
#define ZDB_ZONE_MAINTAIN_NSEC                         2
#define ZDB_ZONE_MAINTAIN_NSEC3                        4
#define ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT                 5
#define ZDB_ZONE_MAINTAIN_MASK                         7
#define ZDB_ZONE_RRSIG_PUSH_ALLOWED                    8 // feature requested internally

#define ZDB_ZONE_MAINTENANCE_ON_MOUNT                  16 // means the sanity decided the zone should probably be maintained ASAP
#define ZDB_ZONE_MAINTAIN_QUEUED                       32
#define ZDB_ZONE_MAINTAINED                            64
#define ZDB_ZONE_MAINTENANCE_PAUSED                    128

struct dnskey_keyring;

#define ZDB_ZONE_HAS_JNL_REFERENCE 0

struct zdb_zone_update_signatures_ctx_s
{
    uint8_t *current_fqdn;
    int32_t  earliest_signature_expiration;
    uint16_t labels_at_once;
    int8_t   chain_index;
};

typedef struct zdb_zone_update_signatures_ctx_s zdb_zone_update_signatures_ctx_t;

struct zdb_s;

typedef ya_result zdb_zone_resolve(zdb_zone_t *zone, dns_message_t *data, struct zdb_s *db);

/**
 * A zone can be loaded from disk
 * A zone can be stored to disk
 * A zone image can be downloaded from a primary
 *
 * A primary loads an image from a text oh hierarchical image.
 * If the hierarchical image is allowed as a source (meaning no text image anymore), no AXFR image should ever be
 * stored. If only the text image is allowed, then the AXFR image should be stored as hierarchical.
 *
 * A secondary downloads an AXFR image, then incremental changes, and stores the image on disk when the journal requests
 * it. This last storage step can be done as an AXFR image, a hierarchical image, or even a text image (but that one
 * should not exist on a secondary). It means the only time an AXFR image should (partially) exist on the disk from the
 * time its being downloaded from a primary to the time it's stored again in a (better) form.
 *
 */

struct zdb_zone_s
{
    uint8_t        *origin; /* dnsname, origin */
    zdb_rr_label_t *apex;   /* pointer to the zone cut, 1 name for : SOA, NS, ... */

#if ZDB_HAS_DNSSEC_SUPPORT
    dnssec_zone_extension_t nsec;
#endif

    zdb_zone_access_filter *query_access_filter;
    access_control_t       *acl; /**
                                  * This pointer is meant to be used by the server so it can associate data with the zone
                                  * without having to do the match on its side too.
                                  *
                                  */

#if ZDB_HAS_DNSSEC_SUPPORT
    zdb_zone_update_signatures_ctx_t progressive_signature_update;
#endif

    int32_t min_ttl; /* a copy of the min-ttl from the SOA */
    int32_t min_ttl_soa;

    /*
     * AXFR handling.
     *
     * In order to be nicer with the resources of the machine and more reactive we are adding a pace mechanism.
     * PRIMARY:
     * init: ts=1, serial = real serial - 1
     * axfr(1): ts=0, serial = real serial, writing on disk, streaming to client until axfr_timestamp>1 OR axfr_serial
     * has changed (both meaning the file has fully been written on disk) axfr(2): ts=0, serial = real serial, reading
     * from the file being written axfr(3): ts=T, serial = real serial, reading from the written file axfr(4): now - ts
     * > too_much, do axfr(1) SECONDARY: : ts=last time the axfr has been fully done, serial = serial in the axfr on
     * file
     *
     */

    volatile uint32_t axfr_timestamp; // The last time when an AXFR has ENDED to be written on disk, if 0, an AXFR is
                                      // being written right now
    volatile uint32_t axfr_serial;    // The serial number of the AXFR (being written) on disk
    volatile uint32_t text_serial;    // The serial number of the TEXT on disk
#if ZDB_HAS_DNSSEC_SUPPORT
    int32_t  sig_validity_interval_seconds;
    int32_t  sig_validity_regeneration_seconds;
    int32_t  sig_validity_jitter_seconds;
    uint32_t sig_quota; // starts at 100, updated so a batch does not takes more than a fraction of a second
#endif

    alarm_t              alarm_handle;        // 32 bits
    atomic_int           rc;                  // reference counter when it reaches 0, the zone and its content should be destroyed asap
    atomic_int           lock_count;          // the number of owners with the current lock ID
    volatile uint8_t     lock_owner;          // the ID of who can manipulate the zone
    volatile uint8_t     lock_reserved_owner; // to the next-owner mechanism (reserve an ownership change)
    volatile uint8_t     _flags;              // extended flags (optout coverage)
    volatile uint8_t     _error_status;       // various error status used to avoid repetition
    atomic_uint_fast32_t _status;             // extended status flags for background tasks not part of the normal operations
#if ZDB_RECORDS_CLASS_MAX
    uint16_t zclass;
#endif

    mutex_t lock_mutex;
    cond_t  lock_cond;
#if ZDB_ZONE_LOCK_HAS_OWNER_ID
    thread_t lock_last_owner_id;
    thread_t lock_last_reserved_owner_id;
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    stacktrace lock_trace;
    thread_t   lock_id;
    int64_t    lock_timestamp;
#endif

#if ZDB_ZONE_KEEP_RAW_SIZE
    volatile int64_t  wire_size;          // approximation of the size of a zone. updated on load and store of the zone on disk
    volatile uint64_t write_time_elapsed; // the time that was spent writing the zone in a file (ie: axfr)
#endif

#if ZDB_ZONE_HAS_JNL_REFERENCE
    /** journal is only to be accessed trough the journal_* functions */
    struct journal *_journal;
#endif

    dnsname_vector_t origin_vector; // note: the origin vector is truncated to it's used length (sparing quite a lot of memory)

}; /* 18 34 => 20 40 */

/* zdb_zone_label */

typedef dictionary_t zdb_zone_label_set;

struct zdb_zone_label_s;
typedef struct zdb_zone_label_s zdb_zone_label_t;

struct zdb_zone_label_s
{
    zdb_zone_label_t  *next; /* used to link labels with the same hash into a SLL */
    zdb_zone_label_set sub;  /* labels of the sub-level                           */
    uint8_t           *name; /* label name                                        */
#if ZDB_HAS_RRCACHE_ENABLED
    /* global resource record (used by the cache) */
    zdb_resource_record_sets_set global_resource_record_set;
#endif
    zdb_zone_t *zone; /* zone cut starting at this level                   */
}; /* 32 56 */

typedef zdb_zone_label_t *zdb_zone_label_pointer_array[DNSNAME_SECTIONS_MAX];

/* zdb */

#define ZDB_MUTEX_NOBODY GROUP_MUTEX_NOBODY
#define ZDB_MUTEX_READER 0x01
#define ZDB_MUTEX_WRITER 0x82 // only one allowed at once

#define ZDBCLASS_TAG     0x5353414c4342445a

struct zdb_s
{
    zdb_zone_label_t *root;
    alarm_t           alarm_handle;
    group_mutex_t     mutex;
    uint16_t          zclass;
};

typedef struct zdb_s zdb_t;

/**
 * Iterator through the (rr) labels in a zone
 */

struct zdb_zone_label_iterator_s;
typedef struct zdb_zone_label_iterator_s zdb_zone_label_iterator_t;

#define ZDB_ZONE_LABEL_ITERATOR_CAN_SKIP_CHILDREN 0

struct zdb_zone_label_iterator_s /// 47136 bytes on a 64 bits architecture
{
    const zdb_zone_t *zone;
    zdb_rr_label_t   *current_label;
    int32_t           top;
    int32_t           current_top; /* "top" of the label pointer by current_label  */
#if ZDB_ZONE_LABEL_ITERATOR_CAN_SKIP_CHILDREN
    int32_t prev_top; /* "top" of the label returned with "_next"     */
    int32_t __reserved__;
#endif
    dnslabel_stack_t      dnslabels;
    dictionary_iterator_t stack[DNSNAME_SECTIONS_MAX];
};

struct zdb_soa_rdata_s
{
    const uint8_t *mname;
    const uint8_t *rname;
    uint32_t       serial;
    uint32_t       refresh;
    uint32_t       retry;
    uint32_t       expire;
    uint32_t       minimum; /* TTL / NTTL */
};

typedef struct zdb_soa_rdata_s zdb_soa_rdata_t;

#define RRL_PROCEED 0
#define RRL_SLIP    1
#define RRL_DROP    2

// typedef ya_result rrl_process_callback(dns_message_t *mesg, zdb_query_ex_answer *ans_auth_add);

uint32_t zdb_zone_get_status(zdb_zone_t *zone);
uint32_t zdb_zone_set_status(zdb_zone_t *zone, uint32_t status);
uint32_t zdb_zone_clear_status(zdb_zone_t *zone, uint32_t status);

bool     zdb_zone_error_status_getnot_set(zdb_zone_t *zone, uint8_t error_status);
void     zdb_zone_error_status_clear(zdb_zone_t *zone, uint8_t error_status);

/*
uint8_t zdb_zone_get_flags(zdb_zone *zone);
uint8_t zdb_zone_set_flags(zdb_zone *zone, uint8_t flags);
uint8_t zdb_zone_clear_flags(zdb_zone *zone, uint8_t flags);
*/
static inline bool zdb_zone_invalid(zdb_zone_t *zone) { return (zdb_zone_get_status(zone) & ZDB_ZONE_STATUS_INVALID) != 0; }

static inline bool zdb_zone_valid(zdb_zone_t *zone) { return (zdb_zone_get_status(zone) & ZDB_ZONE_STATUS_INVALID) == 0; }

static inline void zdb_zone_set_dumping_axfr(zdb_zone_t *zone) { zdb_zone_set_status(zone, ZDB_ZONE_STATUS_DUMPING_AXFR); }

static inline bool zdb_zone_get_set_dumping_axfr(zdb_zone_t *zone)
{
    uint8_t status = zdb_zone_set_status(zone, ZDB_ZONE_STATUS_DUMPING_AXFR);
    return (status & ZDB_ZONE_STATUS_DUMPING_AXFR) != 0;
}

static inline void zdb_zone_clear_dumping_axfr(zdb_zone_t *zone) { zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_DUMPING_AXFR); }

static inline bool zdb_zone_is_dumping_axfr(zdb_zone_t *zone) { return (zdb_zone_get_status(zone) & ZDB_ZONE_STATUS_DUMPING_AXFR) != 0; }

static inline void zdb_zone_set_store_clear_journal_after_mount(zdb_zone_t *zone) { zdb_zone_set_status(zone, ZDB_ZONE_STATUS_SAVE_CLEAR_JOURNAL_AFTER_MOUNT); }

static inline void zdb_zone_clear_store_clear_journal_after_mount(zdb_zone_t *zone) { zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_SAVE_CLEAR_JOURNAL_AFTER_MOUNT); }

static inline bool zdb_zone_is_store_clear_journal_after_mount(zdb_zone_t *zone) { return (zdb_zone_get_status(zone) & ZDB_ZONE_STATUS_SAVE_CLEAR_JOURNAL_AFTER_MOUNT) != 0; }

static inline void zdb_zone_set_invalid(zdb_zone_t *zone) { zdb_zone_set_status(zone, ZDB_ZONE_STATUS_INVALID); }

static inline void zdb_zone_clear_invalid(zdb_zone_t *zone) { zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_INVALID); }

static inline bool zdb_zone_is_invalid(zdb_zone_t *zone) { return (zdb_zone_get_status(zone) & ZDB_ZONE_STATUS_INVALID) != 0; }

static inline void zdb_zone_set_frozen(zdb_zone_t *zone) { zdb_zone_set_status(zone, ZDB_ZONE_STATUS_FROZEN); }

static inline void zdb_zone_clear_frozen(zdb_zone_t *zone) { zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_FROZEN); }

static inline bool zdb_zone_is_frozen(zdb_zone_t *zone) { return (zdb_zone_get_status(zone) & ZDB_ZONE_STATUS_FROZEN) != 0; }

#ifdef __cplusplus
}
#endif

/** @} */
