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
 * @defgroup ### #######
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "server_config.h"

#include <dnscore/dnsname.h>
#include <dnscore/rfc.h>
#include <dnscore/mutex.h>
#include <dnscore/ptr_treemap.h>
#include <dnscore/logger.h>

#define MAINTAIN_ONLY_AT_DIFF_AND_REPLAY 0

typedef struct zone_data_set zone_data_set;

struct zone_data_set
{
    ptr_treemap_t set;
    group_mutex_t lock;
    uint32_t      set_count;
};

#if HAS_CTRL
#include "ctrl.h"
#endif
#include "zone_desc.h"

/*    ------------------------------------------------------------
 *
 *      VALUES
 */

#define BRACKET_CLOSED 0x00U
#define BRACKET_OPEN   0x01U
/**  flag settings for printing the zone file
 * \param 0 means not printing of the resource records
 * \param 1 means printing of the resource records
 */
#define WITHOUT_RR     0
#define WITH_RR        1

#define ZONE_NAME      0x01U
#define ZONE_TYPE      0x02U
#define ZONE_ACL       0x04U
#define ZONE_GLOBAL_RR 0x08U
#define ZONE_RR        0x10U
#define ZONE_ALL       (ZONE_NAME | ZONE_TYPE | ZONE_ACL | ZONE_GLOBAL_RR | ZONE_RR)

#define ZONECMD_TAG    0x444d43454e4f5a

struct zone_command_s
{
    union
    {
        uint8_t    *origin;
        zdb_zone_t *zone;
        void       *ptr;
    } parm;

    uint32_t id;
};

typedef struct zone_command_s zone_command_s;

typedef bool                  zone_data_matching_callback(zone_desc_t *);

bool                          zone_data_is_clone(zone_desc_t *desc);

int32_t                       zone_desc_match(const zone_desc_t *a, const zone_desc_t *b);

void                          zone_init(zone_data_set *set);

/** @brief Initializing zone_data variable
 *
 *  Allocates and clears a new zone data (fully empty)
 *
 *  @retval clean new zone_data
 */
zone_desc_t *zone_alloc();

zone_desc_t *zone_clone(zone_desc_t *zone_setup);

/** \brief
 *  Frees a zone data
 *
 *  @param[in] src is a * to the zone data
 */

void zone_acquire(zone_desc_t *zone_desc);

void zone_release(zone_desc_t *zone_desc);

#define zone_free(zd__) zone_release(zd__)

#if ZDB_ZONE_DESC_IS_TRACKED

void zone_dump_allocated();

#endif

/**
 *
 */

void zone_remove_all_matching(zone_data_set *dset, zone_data_matching_callback *matchcallback);

/** \brief Frees all elements of the collection
 *
 *  @param[in] src the collection
 *
 *  @return NONE
 */

void      zone_free_all(zone_data_set *set);

ya_result zone_complete_settings(zone_desc_t *zone_desc);

/**
 *
 * Adds the zone in the collection (if it's not there already)
 *
 * @param set
 * @param zone
 * @return
 */

ya_result zone_register(zone_data_set *set, zone_desc_t *zone);

/**
 * Removes the zone with the given origin from the collection.
 * Returns a pointer to the zone. (The caller may destroy it if
 * he wants)
 */

zone_desc_t *zone_unregister(zone_data_set *set, const uint8_t *origin);

/**
 * returns the zone_data from the zone config that's just after the name
 * in lexicographic order
 *
 * @param name
 * @return
 */

zone_desc_t *zone_getafterdnsname(const uint8_t *name);

/**
 * returns the zone_data from the zone config for the name
 *
 * @param name
 * @return
 */

zone_desc_t *zone_acquirebydnsname(const uint8_t *name);

/*
 * functions used for removing a zone_desc
 */

void                         zone_setloading(zone_desc_t *zone_desc, bool v);
void                         zone_setmustsavefile(zone_desc_t *zone_desc, bool v);
void                         zone_setmustsaveaxfr(zone_desc_t *zone_desc, bool v);
void                         zone_setsavingfile(zone_desc_t *zone_desc, bool v);
void                         zone_setsavingaxfr(zone_desc_t *zone_desc, bool v);
void                         zone_setstartingup(zone_desc_t *zone_desc, bool v);
void                         zone_setdynamicupdating(zone_desc_t *zone_desc, bool v);

bool                         zone_isidle(zone_desc_t *zone_desc);
bool                         zone_isfrozen(zone_desc_t *zone_desc);

bool                         zone_isloading(zone_desc_t *zone_desc);
bool                         zone_mustsavefile(zone_desc_t *zone_desc);
bool                         zone_mustsaveaxfr(zone_desc_t *zone_desc);
bool                         zone_issavingfile(zone_desc_t *zone_desc);
bool                         zone_issavingaxfr(zone_desc_t *zone_desc);
bool                         zone_isdynamicupdating(zone_desc_t *zone_desc);
bool                         zone_canbeedited(zone_desc_t *zone_desc);

static inline const uint8_t *zone_origin(const zone_desc_t *zone_desc) { return zone_desc->_origin; }

static inline const char    *zone_domain(const zone_desc_t *zone_desc) { return zone_desc->domain; }

static inline bool           zone_is_primary(const zone_desc_t *zone_desc) { return zone_desc->type == ZT_PRIMARY; }

zdb_zone_t                  *zone_get_loaded_zone(zone_desc_t *zone_desc);
zdb_zone_t                  *zone_set_loaded_zone(zone_desc_t *zone_desc, zdb_zone_t *zone);
bool                         zone_has_loaded_zone(zone_desc_t *zone_desc);
/*
 * This will mark a zone as being obsolete.
 * It means that we are about to delete it.
 * It also means that nobody can lock it anymore, but the destoyer) (lock will return an error for anybody else)
 */

ya_result zone_wait_unlocked(zone_desc_t *zone_desc);

void      zone_set_lock(zone_data_set *dset);
void      zone_set_unlock(zone_data_set *dset);
bool      zone_islocked(zone_desc_t *zone_desc);

/*
 * returns true if a zone is obsolete
 */

bool zone_is_obsolete(zone_desc_t *zone_desc);

/*
 * returns true if the zone hasn't even tried to load its zone
 */

bool zone_isstartingup(zone_desc_t *zone_desc);

/*
 * returns the owner, or error if the zone_desc is obsolete
 */

ya_result zone_try_lock(zone_desc_t *zone_desc, uint8_t owner_mark);

/*
 * wait for lock (and return the owner) or return an error if the zone_desc becomes obsolete
 */

ya_result zone_lock(zone_desc_t *zone_desc, uint8_t owner_mark);

/*
 * wait a while for lock (and return the owner) or return an error if the zone_desc becomes obsolete
 */

ya_result zone_try_lock_wait(zone_desc_t *zone_desc, uint64_t usec, uint8_t owner_id);

/*
 * unlocks if locked by the owner, else return an error
 */

void        zone_unlock(zone_desc_t *zone_desc, uint8_t owner_mark);

const char *zone_type_to_name(zone_type t);
const char *zone_dnssec_to_name(uint32_t dnssec_flags);

void        zone_setdefaults(zone_desc_t *zone_desc);

// 0 : no merge, 1 : merge, < 0 : error
ya_result zone_setwithzone(zone_desc_t *zone_desc, zone_desc_t *src);

/**
 * Returns true iff the zone has DNSSEC maintenance on.
 *
 * @return true iff zone has ZONE_FLAG_MAINTAIN_DNSSEC.
 */

#if HAS_PRIMARY_SUPPORT
static inline bool zone_maintains_dnssec(zone_desc_t *zone_desc) { return (zone_desc->flags & ZONE_FLAG_MAINTAIN_DNSSEC) != 0; }
#endif

#if HAS_PRIMARY_SUPPORT
static inline void zone_maintains_dnssec_set(zone_desc_t *zone_desc, bool enable)
{
    if(enable)
    {
        zone_desc->flags |= ZONE_FLAG_MAINTAIN_DNSSEC;
    }
    else
    {
        zone_desc->flags &= ~ZONE_FLAG_MAINTAIN_DNSSEC;
    }
}
#endif

static inline bool zone_is_auto_notify(zone_desc_t *zone_desc) { return (zone_desc->flags & ZONE_FLAG_NOTIFY_AUTO) != 0; }

static inline void zone_auto_notify_set(zone_desc_t *zone_desc, bool enable)
{
    if(enable)
    {
        zone_desc->flags |= ZONE_FLAG_NOTIFY_AUTO;
    }
    else
    {
        zone_desc->flags &= ~ZONE_FLAG_NOTIFY_AUTO;
    }
}

static inline bool zone_is_drop_before_load(zone_desc_t *zone_desc) { return (zone_desc->flags & ZONE_FLAG_DROP_BEFORE_LOAD) != 0; }

#if HAS_PRIMARY_SUPPORT
static inline bool zone_rrsig_nsupdate_allowed(zone_desc_t *zone_desc) { return (zone_desc->flags & ZONE_FLAG_RRSIG_NSUPDATE_ALLOWED) != 0; }
#endif

void            zone_enqueue_command(zone_desc_t *zone_desc, uint32_t id, void *parm, bool has_priority);
zone_command_s *zone_dequeue_command(zone_desc_t *zone_desc);
void            zone_command_free(zone_command_s *cmd);
/**
 *
 * Functions to log a zone desc
 *
 * @param zone_desc
 * @param text
 */

void                           zone_desc_log(logger_handle_t *handle, uint32_t level, const zone_desc_t *zone_desc, const char *text);
void                           zone_desc_log_all(logger_handle_t *handle, uint32_t level, zone_data_set *dset, const char *text);

typedef ptr_treemap_iterator_t zone_set_iterator_t;

/**
 * Initialises an iterator on all the configured zones.
 *
 * Locks the set.
 */

void zone_set_iterator_init(zone_set_iterator_t *iter);

/**
 * Returns true iff there are still zones in the iterator
 */

bool zone_set_iterator_hasnext(zone_set_iterator_t *iter);

/**
 * Returns the next zone_desc from the set.
 *
 * Does NOT acquire the zone_desc
 */

zone_desc_t *zone_set_iterator_next(zone_set_iterator_t *iter);

/**
 * Mandatory call to end any operation started by  a zone_set_iterator_init.
 * Unlocks the set.
 */

void zone_set_iterator_finalise(zone_set_iterator_t *iter);

/**
 * Callback for zone_desc_for_all
 */

typedef ya_result zone_desc_for_all_callback(zone_desc_t *zone_desc, void *args);

/**
 *
 * Calls the callback for all zone_desc.
 * If the callback returns an error, the process stops.
 *
 * @param cb
 * @param args
 * @return SUCCESS or the error code returned by the callback
 */

ya_result zone_desc_for_all(zone_desc_for_all_callback *cb, void *args);

/**
 * return the number of configured zones
 */

uint32_t zone_count();

/**
 */

void               zone_desc_status_flags_long_format(const void *value, output_stream_t *os, int32_t padding, char pad_char, bool left_justified, void *reserved_for_method_parameters);

static inline bool zone_is_multiprimary(const zone_desc_t *zone_desc) { return (zone_desc->primaries != NULL) && (zone_desc->primaries->next != NULL); }

static inline bool zone_is_true_multiprimary(const zone_desc_t *zone_desc) { return zone_is_multiprimary(zone_desc) && ((zone_desc->flags & ZONE_FLAG_TRUE_MULTIPRIMARY) != 0); }

void               zone_set_status(zone_desc_t *zone_desc, uint32_t flags);
uint32_t           zone_get_set_status(zone_desc_t *zone_desc, uint32_t flags);
void               zone_clear_status(zone_desc_t *zone_desc, uint32_t flags);
uint32_t           zone_get_status(const zone_desc_t *zone_desc);

host_address_t    *zone_transfer_source_copy(const uint8_t *domain);
ya_result          zone_transfer_source_tcp_connect(const host_address_t *server, host_address_t **current_transfer_sourcep, input_stream_t *is, output_stream_t *os, int to_sec);

void               zone_dnssec_status_update(zdb_zone_t *zone);

uint8_t            zone_policy_guess_dnssec_type(zdb_zone_t *zone);

uint32_t           zone_policy_get_earliest_queued_key_generation(zone_desc_t *zone_desc);
uint32_t           zone_policy_set_earliest_queued_key_generation(zone_desc_t *zone_desc, uint32_t epoch);
uint32_t           zone_policy_clear_earliest_queued_key_generation(zone_desc_t *zone_desc, uint32_t epoch);

struct dnssec_policy_key_suite;

bool zone_policy_key_suite_is_marked_processed(zone_desc_t *zone_desc, const struct dnssec_policy_key_suite *kr);
bool zone_policy_key_suite_mark_processed(zone_desc_t *zone_desc, const struct dnssec_policy_key_suite *kr);
void zone_policy_key_suite_unmark_processed(zone_desc_t *zone_desc, const struct dnssec_policy_key_suite *kr);

/** @} */
