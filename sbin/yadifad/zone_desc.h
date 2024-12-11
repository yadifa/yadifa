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

/**-----------------------------------------------------------------------------
 * @defgroup ### #######
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#ifndef ZONE_DESC_H
#define ZONE_DESC_H

#include <dnscore/host_address.h>
#include <dnscore/mutex.h>
#include <dnscore/list_sl.h>
#include <dnscore/basic_priority_queue.h>

#include <dnsdb/zdb_types.h>

#include <dnscore/acl.h>
#include <dnscore/ptr_treemap.h>
#include <dnscore/ctrl_rfc.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define ZONE_LOCK_HAS_OWNER_ID   0 // debug

#define ZDB_ZONE_DESC_IS_TRACKED 0

#if ZONE_LOCK_HAS_OWNER_ID
#pragma message("***********************************************************")
#pragma message("***********************************************************")
#pragma message("ZONE_LOCK_HAS_OWNER_ID 1")
#pragma message("***********************************************************")
#pragma message("***********************************************************")
#endif

#define ZONE_DNSSEC_FL_NOSEC          0
#define ZONE_DNSSEC_FL_NSEC           1
#define ZONE_DNSSEC_FL_NSEC3          2
#define ZONE_DNSSEC_FL_NSEC3_OPTOUT   3

#define ZONE_DNSSEC_FL_MASK           7

#define ZONE_CTRL_FLAG_CLONE          1  /* has a parent in the config */
#define ZONE_CTRL_FLAG_EDITED         2  /* has been edited dynamically (it's a dynamic provisioning zone) */
#define ZONE_CTRL_FLAG_READ_FROM_CONF 4  /* has been read from the configuration file */
#define ZONE_CTRL_FLAG_READ_FROM_DIFF 8  /* has been read from the configuration updates file */
#define ZONE_CTRL_FLAG_SAVED_TO_DIFF  16 /* has been saved to the configuration updates file */
#define ZONE_CTRL_FLAG_DYNAMIC        32 //
#define ZONE_CTRL_FLAG_GENERATE_ZONE  128

// behavioural flags

#define ZONE_FLAG_NOTIFY_AUTO         0x00000001
#define ZONE_FLAG_DROP_BEFORE_LOAD    0x00000002 // drops the old instance of a zone before loading it again (spare memory)
#define ZONE_FLAG_NO_PRIMARY_UPDATES                                                                                                                                                                                                           \
    0x00000004 /* so a secondary will not ask for updates                                                                                                                                                                                      \
                * edf: I added this so I would not hammer                                                                                                                                                                                      \
                *      the root servers when doing tests                                                                                                                                                                                       \
                */
#if HAS_PRIMARY_SUPPORT
#define ZONE_FLAG_MAINTAIN_DNSSEC 0x00000008
#endif
#define ZONE_FLAG_TRUE_MULTIPRIMARY         0x00000010 // drops a zone whenever changing the primary
#define ZONE_FLAG_DROP_CURRENT_ZONE_ON_LOAD 0x00000020 // only triggered while changing the true primary: the current zone will be dropped
#if HAS_PRIMARY_SUPPORT
#define ZONE_FLAG_RRSIG_NSUPDATE_ALLOWED 0x00000040 // allows to push a signature with an update
// #define     ZONE_FLAG_MAINTAIN_ZONE_BEFORE_MOUNT 0x00000100        // must finishing applying policies and signature
// before mounting the zone
#endif
#define ZONE_FLAG_PRIORITISE_LOCAL_SOURCE   0x00000100 // If a zone exists locally : do not probe the primary, just load it.  Probe later.
#define ZONE_FLAG_FULL_ZONE_TRANSFER_ONLY   0x00000200

// status flags
// iIclLMUdDzZaAsSeERxX#---T---ur/!
// #define     ZONE_STATUS_IDLE                    0x00000000      /* i nothing happening at ALL */

#define ZONE_STATUS_STARTING_UP             0x00000001 /* I before we even tried to load it */

#define ZONE_STATUS_LOAD                    0x00000004 /* l loading of the zone queried */
#define ZONE_STATUS_LOADING                 0x00000008 /* L in the process of loading the zone */
#define ZONE_STATUS_MOUNTING                0x00000010 /* M loading of the zone queried */
#define ZONE_STATUS_UNMOUNTING              0x00000020 /* U in the process of loading the zone */
#define ZONE_STATUS_DROP                    0x00000040 /* d unloading of the zone queried */
#define ZONE_STATUS_DROPPING                0x00000080 /* D in the process of unloading the zone */
#define ZONE_STATUS_SAVETO_ZONE_FILE        0x00000100 /* z dumping to ... queried */
#define ZONE_STATUS_SAVING_ZONE_FILE        0x00000200 /* Z dumping to ... at this moment */
#define ZONE_STATUS_SAVETO_AXFR_FILE        0x00000400 /* a dumping to ... queried */
#define ZONE_STATUS_SAVING_AXFR_FILE        0x00000800 /* A dumping to ... at this moment */
#define ZONE_STATUS_SIGNATURES_UPDATE       0x00001000 /* s needs to update the signatures (?) */
#define ZONE_STATUS_SIGNATURES_UPDATING     0x00002000 /* S updating signatures */
#define ZONE_STATUS_DYNAMIC_UPDATE          0x00004000 /* e needs to update the database (?) */
#define ZONE_STATUS_DYNAMIC_UPDATING        0x00008000 /* E updating the database */
#define ZONE_STATUS_READONLY_______NOT_USED 0x00010000 /* R database updates not allowed */
#define ZONE_STATUS_DOWNLOAD_XFR_FILE       0x00020000 /* x */
#define ZONE_STATUS_DOWNLOADING_XFR_FILE    0x00040000 /* X */
#define ZONE_STATUS_DROP_AFTER_RELOAD                                                                                                                                                                                                          \
    0x00080000                                        /* # when a config reload occurrs, this flag is set to all zones                                                                                                                         \
                                                       *   when the zone has its config reloaded, it is cleared                                                                                                                                \
                                                       *   all zones with this bit set after the reload are dropped                                                                                                                            \
                                                       */
#define ZONE_STATUS_FROZEN                 0x00100000 /* f zone is read only <-> READONLY ? */
#define ZONE_STATUS_TEMPLATE_SOURCE_FILE   0x00200000
#define ZONE_STATUS_MUST_CLEAR_JOURNAL     0x00400000
#define ZONE_STATUS_NOTIFIED               0x00800000
#define ZONE_STATUS_DOWNLOADED             0x01000000 /* T the file is on disk, soon to be loaded */
#define ZONE_STATUS_AXFR_NEEDS_LOADING     0x02000000
#define ZONE_STATUS_LOAD_AFTER_DROP        0x04000000
#define ZONE_STATUS_RESERVED1              0x08000000
#define ZONE_STATUS_UNREGISTERING          0x10000000 /* u */
#define ZONE_STATUS_REGISTERED             0x20000000 /* r this instance of the zone is registered */
#define ZONE_STATUS_MARKED_FOR_DESTRUCTION 0x40000000 /* / a "destroy" command has been put in the queue */
#define ZONE_STATUS_PROCESSING             0x80000000 /* ! */

#define ZONE_STATUS_BUSY                                                                                                                                                                                                                       \
    (ZONE_STATUS_LOAD | ZONE_STATUS_LOADING | ZONE_STATUS_MOUNTING | ZONE_STATUS_UNMOUNTING | ZONE_STATUS_DROP | ZONE_STATUS_DROPPING | ZONE_STATUS_SAVETO_ZONE_FILE | ZONE_STATUS_SAVING_ZONE_FILE | ZONE_STATUS_SAVETO_AXFR_FILE |           \
     ZONE_STATUS_SAVING_AXFR_FILE | ZONE_STATUS_SIGNATURES_UPDATE | ZONE_STATUS_SIGNATURES_UPDATING | ZONE_STATUS_DYNAMIC_UPDATE | ZONE_STATUS_DYNAMIC_UPDATING | ZONE_STATUS_DOWNLOAD_XFR_FILE | ZONE_STATUS_DOWNLOADING_XFR_FILE |           \
     ZONE_STATUS_PROCESSING | 0)

// locks owners

#define ZONE_LOCK_NOBODY        0x00
#define ZONE_LOCK_READONLY      0x01
#define ZONE_LOCK_LOAD          0x82
#define ZONE_LOCK_UNLOAD        0x83
#define ZONE_LOCK_LOAD_DESC     0x84
#define ZONE_LOCK_DESC_UNLOAD   0x85
#define ZONE_LOCK_REPLACE_DESC  0x86
#define ZONE_LOCK_DOWNLOAD_DESC 0x87
#define ZONE_LOCK_MOUNT         0x88
#define ZONE_LOCK_UNMOUNT       0x89
#define ZONE_LOCK_SERVICE       0x8a
#define ZONE_LOCK_SIGNATURE     0x8b
#define ZONE_LOCK_FREEZE        0x8c
#define ZONE_LOCK_UNFREEZE      0x8d
#define ZONE_LOCK_SAVE          0x8e
#define ZONE_LOCK_DYNUPDATE     0x8f

enum zone_type
{
    HINT = ZT_HINT,
    PRIMARY = ZT_PRIMARY,
    SECONDARY = ZT_SECONDARY,
    STUB = ZT_STUB,
    UNKNOWN = ZT_UNKNOWN,
    INVALID = INT32_MAX /* ensures the enum is 32 bits (at least) */
};

typedef enum zone_type zone_type;

/**
 *
 * About secondary refresh:
 *
 * REFRESH  A 32 bit time interval before the zone should be
 *          refreshed.
 * RETRY    A 32 bit time interval that should elapse before a
 *          failed refresh should be retried.
 * EXPIRE   A 32 bit time value that specifies the upper limit on
 *          the time interval that can elapse before the zone is no
 *          longer authoritative.
 */

typedef struct zone_refresh_s zone_refresh_s;
struct zone_refresh_s
{
    // last successful refresh time
    uint32_t refreshed_time;
    // last time we retried
    uint32_t retried_time;
    // for the sole use of retry.c (updated and used by it)
    uint32_t zone_update_next_time;
    /*
    // last advertised serial (notification)
    uint32_t advertised_serial;
    // queued to handle notification
    bool notification_handling;
    */
};

typedef struct zone_notify_s zone_notify_s;
struct zone_notify_s
{
    /* retry count */
    uint32_t retry_count;
    /* period in minutes */
    uint32_t retry_period;
    /* increase of the period (in minutes) after each retry */
    uint32_t retry_period_increase;
};

#if DNSCORE_HAS_RRSIG_MANAGEMENT_SUPPORT && DNSCORE_HAS_DNSSEC_SUPPORT

#define ZONE_SIGNATURE_INVALID_FIRST_ASSUME_BROKEN 0

typedef struct zone_signature_s zone_signature_s;

struct zone_signature_s
{
    // The newly generated signatures will be valid for that amount of days
    uint32_t sig_validity_interval;
    // The amount of time before expiration to update a signature
    uint32_t sig_validity_regeneration;
    // The validity of newly generated signature will be off by at most this
    uint32_t sig_validity_jitter;
    // The earliest epoch at which a signature in the zone is expired.
    uint32_t sig_invalid_first;
    // The first epoch when a signature will be updated
    uint32_t scheduled_sig_invalid_first;
};

#endif

/// @note HAS_DYNAMIC_PROVISIONING
typedef struct dynamic_provisioning_s dynamic_provisioning_s;

struct dynamic_provisioning_s
{
    uint8_t  version;
    uint8_t  padding;
    uint16_t flags;
    uint32_t timestamp;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t timestamp_lo; /* 0 for now */
    uint32_t checksum;     /* MUST BE LAST FIELD */
};
///

#define ZONE_DESC_MATCH_ORIGIN         0x00000001
#define ZONE_DESC_MATCH_DOMAIN         0x00000002
#define ZONE_DESC_MATCH_FILE_NAME      0x00000004
#define ZONE_DESC_MATCH_PRIMARIES      0x00000008
#define ZONE_DESC_MATCH_NOTIFIES       0x00000010
#define ZONE_DESC_MATCH_TRANSFERSOURCE 0x00000020
#if HAS_DYNAMIC_PROVISIONING
#define ZONE_DESC_MATCH_DYNAMIC 0x00000040
#endif
#define ZONE_DESC_MATCH_SECONDARIES     0x00000080
#define ZONE_DESC_MATCH_REFRESH         0x00000100
#define ZONE_DESC_MATCH_NOTIFY          0x00000200
#define ZONE_DESC_MATCH_DNSSEC_MODE     0x00000400
#define ZONE_DESC_MATCH_TYPE            0x00000800
#define ZONE_DESC_MATCH_ACL             0x00001000
#define ZONE_DESC_MATCH_DNSSEC_POLICIES 0x00002000

struct dnssec_policy;

struct zone_desc_s
{
    // fqdn
    uint8_t *_origin; // cannot change
    // ascii domain name
    char *domain; // cannot change
    // name of the file on disk
    char *file_name; // may change
    // path where to find the keys
    char *keys_path; // can be NULL
    // The list of the primaries (for a secondary)
    host_address_t *primaries; // may change
    // If primary which are the servers to notify for updates IXFR or AXFR
    host_address_t *notifies; // may change
#if ZDB_HAS_ACL_SUPPORT
    // Restrited list of ip address allowed to query */
    access_control_t ac; // may change (content is made of pointers)
#endif
    // zone notify settings
    zone_notify_s notify; // may change (3 * 32 bits)
#if DNSCORE_HAS_DNSSEC_SUPPORT

#if HAS_RRSIG_MANAGEMENT_SUPPORT

#if HAS_PRIMARY_SUPPORT
    struct dnssec_policy *dnssec_policy;
    ptr_treemap_t         dnssec_policy_processed_key_suites;
#endif

    // zone signature settings
    zone_signature_s signature; // may change (5 * 32 bits)
#endif

    uint32_t dnssec_mode; // needs to be uint32_t (config descriptor requirement)
#endif
    // zone refresh status
    zone_refresh_s    refresh;                // internal (3 * 32 bits)
    volatile uint32_t _status_flags;          // internal
    volatile uint32_t last_processor;         // internal, diagnostic
    uint32_t          flags;                  // may change ? (notify auto, drop before load, ...)
    uint32_t          journal_size_kb;        // may change, expressed in kb, 0 "choose", 2^32-1 "
    uint32_t          stored_serial;          // serial of the last stored full zone image
    uint32_t          download_failure_count; // axfr or ixfr downloads that failed since the last one that succeeded
    zone_type         type;                   // type of zone file (primary, secondary, stub, unknown)
    uint16_t          qclass;                 // cannot change, most likely CLASS_IN
    uint8_t           multiprimary_retries;   // config : how many failures before changing primary
    uint8_t           multiprimary_failures;  // the number of error on the current primary primary (reset on success)

    // instead of having a priority queue with two levels, two queues will do
    // the job
    bpqueue_t commands; // queue of commands
#if HAS_DYNAMIC_PROVISIONING
    /// @note HAS_DYNAMIC_PROVISIONING
    dynamic_provisioning_s dynamic_provisioning; // proprietary
#endif
    host_address_t *secondaries; // proprietary
    host_address_t *transfer_source;

    zdb_zone_t     *loaded_zone; // internal, keeps an RC, has to be increased by users grabbing it (mutex required)
    ///
    /* marks */
    mutex_t          lock;
    cond_t           lock_cond;

    uint32_t         commands_bits;

    volatile int32_t rc;
    volatile int32_t lock_wait_count;
    volatile int32_t lock_owner_count;
    volatile uint8_t lock_owner;

#if ZONE_LOCK_HAS_OWNER_ID
    volatile thread_t lock_last_owner_tid;
#endif

#if ZDB_ZONE_DESC_IS_TRACKED
    uint64_t instance_time_us;
    uint64_t instance_id;
#endif
};

typedef struct zone_desc_s zone_desc_t;

#ifdef __cplusplus
}
#endif

#endif /* ZONE_DESC_H */

/** @} */
