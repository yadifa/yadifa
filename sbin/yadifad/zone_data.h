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
/** @defgroup ### #######
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#ifndef ZONE_DATA_H
#define ZONE_DATA_H

#include <dnscore/host_address.h>
#include <dnscore/mutex.h>

#include "list.h"
#include "acl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define     ZT_HINT         0       /**< zone file: hint */
#define     ZT_MASTER       1       /**< zone file: master */
#define     ZT_SLAVE        2       /**< zone file: slave */
#define     ZT_STUB         3       /**< zone file: stub */
#define     ZT_UNKNOWN      4       /**< zone file: unknown */

#define     ZT_STRING_HINT      "hint"
#define     ZT_STRING_MASTER    "master"
#define     ZT_STRING_SLAVE     "slave"
#define     ZT_STRING_STUB      "stub"
#define     ZT_STRING_UNKNOWN   "unknown"
    
    
#define     ZONE_DNSSEC_FL_NOSEC            0
#define     ZONE_DNSSEC_FL_NSEC             1
#define     ZONE_DNSSEC_FL_NSEC3            2
#define     ZONE_DNSSEC_FL_NSEC3_OPTOUT     3
    
#define     ZONE_DNSSEC_FL_MASK             7
    
#define     ZONE_CTRL_FLAG_CLONE            1   /* has a parent in the config */
#define     ZONE_CTRL_FLAG_EDITED           2   /* has been edited dynamically (it's a dynamic provisioning zone) */
#define     ZONE_CTRL_FLAG_READ_FROM_CONF   4   /* has been read from the configuration file */
#define     ZONE_CTRL_FLAG_READ_FROM_DIFF   8   /* has been read from the configuration updates file */
#define     ZONE_CTRL_FLAG_SAVED_TO_DIFF   16   /* has been saved to the configuration updates file */
#define     ZONE_CTRL_FLAG_DYNAMIC         32   /* not used anymore */
#define     ZONE_CTRL_FLAG_GENERATE_ZONE  128

#define     ZONE_STATUS_STARTING_UP          128 /* before we even tried to load it */
#define     ZONE_STATUS_IDLE                   0 /* nothing happening */
#define     ZONE_STATUS_LOADING                2 /* in the process of loading the zone */
#define     ZONE_STATUS_MODIFIED               1 /* has been updated since last write on/load from disk */

#define     ZONE_STATUS_SAVETO_ZONE_FILE       4 /* dumping to ... required */
#define     ZONE_STATUS_SAVETO_AXFR_FILE       8
#define     ZONE_STATUS_SAVING_ZONE_FILE      16 /* dumping to ... at this moment */
#define     ZONE_STATUS_SAVING_AXFR_FILE      32
    
#define     ZONE_STATUS_SIGNATURES_UPDATE    256 /* needs to update the signatures (?) */
#define     ZONE_STATUS_SIGNATURES_UPDATING  512 /* updating signatures */
    
#define     ZONE_STATUS_DYNAMIC_UPDATE      1024 /* needs to update the database (?) */
#define     ZONE_STATUS_DYNAMIC_UPDATING    2048 /* updating the database */

// locks owners
    
#define     ZONE_LOCK_NOBODY                0
#define     ZONE_LOCK_LOAD                  1
#define     ZONE_LOCK_UNLOAD                2
#define     ZONE_LOCK_LOAD_DESC             3
#define     ZONE_LOCK_UNLOAD_DESC           4
#define     ZONE_LOCK_REPLACE_DESC          5
#define     ZONE_LOCK_UNREGISTER         0xff
    
#define     ZONE_NOTIFY_AUTO                1   /* do not automatically notifies servers in the zone */
    
enum zone_type
{
    UNKNOWN = ZT_UNKNOWN,
    HINT = ZT_HINT,
    MASTER = ZT_MASTER,
    SLAVE = ZT_SLAVE,
    STUB = ZT_STUB,
    INVALID = MAX_S32       /* ensures the enum is 32 bits (at least) */
};

typedef enum zone_type zone_type;

    /**
     *
     * About slave refresh:
     *
     * REFRESH  A 32 bit time interval before the zone should be
     *          refreshed.
     * RETRY    A 32 bit time interval that should elapse before a
     *          failed refresh should be retried.
     * EXPIRE   A 32 bit time value that specifies the upper limit on
     *          the time interval that can elapse before the zone is no
     *          longer authoritative.
     */

typedef struct zone_data_refresh zone_data_refresh;
struct zone_data_refresh
{
    /* last successful refresh time */
    u32 refreshed_time;
    /* last time we retried */
    u32 retried_time;
    /* for the sole use of retry.c (updated and used by it) */
    u32 zone_update_next_time;
};

typedef struct zone_data_notify zone_data_notify;
struct zone_data_notify
{
    /* retry count */
    u32 retry_count;        
    /* period in minutes */
    u32 retry_period;
    /* increase of the period (in minutes) after each retry */
    u32 retry_period_increase;
};


/// @note HAS_DYNAMIC_PROVISIONING
typedef struct dynamic_provisioning_s dynamic_provisioning_s;

struct dynamic_provisioning_s
{
    u8  version;
    u8  padding;
    u16 flags;
    u32 timestamp;
    u32 refresh;
    u32 retry;
    u32 expire;
    u32 timestamp_lo;   /* 0 for now */
    u32 checksum;       /* MUST BE LAST FIELD */
};
///

#define ZONE_DESC_MATCH_ORIGIN          0x00000001
#define ZONE_DESC_MATCH_DOMAIN          0x00000002
#define ZONE_DESC_MATCH_FILE_NAME       0x00000004
#define ZONE_DESC_MATCH_MASTERS         0x00000008
#define ZONE_DESC_MATCH_NOTIFIES        0x00000010
#define ZONE_DESC_MATCH_DYNAMIC         0x00000020
#define ZONE_DESC_MATCH_SLAVES          0x00000040
#define ZONE_DESC_MATCH_REFRESH         0x00000080
#define ZONE_DESC_MATCH_NOTIFY          0x00000100
#define ZONE_DESC_MATCH_DNSSEC_MODE     0x00000200
#define ZONE_DESC_MATCH_TYPE            0x00000400

typedef struct zone_data zone_data;
struct zone_data
{
    /* fqdn */
    u8 *origin;                 // cannot change

    /* ascii domain name */
    char *domain;               // cannot change

    /* name of the file on disk */
    char *file_name;            // may change

    /* The list of the masters (for a slave) */
    host_address *masters;      // may change

    /* If master which are the servers to notify for updates
     * IXFR or AXFR
     */
    host_address *notifies;     // may change

    /* Restrited list of ip address allowed to query */

    access_control ac;          // may change
    
    /* zone refresh settings */
    
    zone_data_refresh refresh;  // may change
    
    /* zone notify settings */
    
    zone_data_notify notify;    // may change

#if HAS_DNSSEC_SUPPORT != 0
    /*
        * The newly generated signatures will be valid for that amount of days
        */
    u32                                             sig_validity_interval;
    /*
        * I forgot what it was supposed to be used for
        */
    u32                                         sig_validity_regeneration;
    /*
        * The validity of newly generated signature will be off by at most this
        */
    u32                                               sig_validity_jitter;
    /*
        * The first epoch when a signature will be marked as invalid.
        */
    u32                                       scheduled_sig_invalid_first;

#endif


#if HAS_DNSSEC_SUPPORT != 0
    u32                                                       dnssec_mode;  /* needs to be u32 */
#endif
    u16 qclass;                 // cannot change
    
    /// @note HAS_DYNAMIC_PROVISIONING
    dynamic_provisioning_s dynamic_provisioning;
    host_address *slaves;
    ///

    smp_int is_saving_as_text;

    /* Type of zone file (master, slave, stub, unknown) */
    zone_type type;
    
    volatile u8 status_flag;
    
    volatile u8 notify_flags;
    
    /* marks */
    
    mutex_t                                                         lock;
    volatile u8                                               lock_owner;
    volatile u8                                           obsolete_owner;
};

#ifdef __cplusplus
}
#endif

#endif /* ZONE_DATA_H */

/*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/

