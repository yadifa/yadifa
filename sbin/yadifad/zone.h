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

#ifndef ZONE_H_
#define ZONE_H_
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include	"config.h"

#include <dnscore/dnsname.h>
#include <dnscore/rfc.h>
#include <dnscore/mutex.h>
#include <dnscore/treeset.h>

typedef struct zone_data_set zone_data_set;

struct zone_data_set
{
    treeset_tree set;
    mutex_t lock;
};

#include "zone_desc.h"

/*    ------------------------------------------------------------
 *
 *      VALUES
 */

#define BRACKET_CLOSED          0x00U
#define BRACKET_OPEN            0x01U
/**  flag settings for printing the zone file
 * \param 0 means not printing of the resource records
 * \param 1 means printing of the resource records
 */
#define WITHOUT_RR		0
#define WITH_RR                 1

#define ZONE_NAME              0x01U
#define ZONE_TYPE              0x02U
#define ZONE_ACL               0x04U
#define ZONE_GLOBAL_RR         0x08U
#define ZONE_RR                0x10U
#define ZONE_ALL               (ZONE_NAME | ZONE_TYPE | ZONE_ACL | ZONE_GLOBAL_RR | ZONE_RR)

struct zone_command_s
{
    union
    {
        u8       *origin;
        zdb_zone *zone;
        void     *ptr;
    } parm;
    
    u32 id;
};

typedef struct zone_command_s zone_command_s;


typedef bool zone_data_matching_callback(zone_desc_s*);

bool zone_data_is_clone(zone_desc_s *desc);

s32 zone_desc_match(const zone_desc_s *a, const zone_desc_s *b);

void zone_init(zone_data_set *set);

/** @brief Initializing zone_data variable
 *
 *  Allocates and clears a new zone data (fully empty)
 *
 *  @retval clean new zone_data
 */
zone_desc_s *zone_alloc();

zone_desc_s *zone_clone(zone_desc_s *zone_setup);

/** \brief
 *  Frees a zone data
 *
 *  @param[in] src is a * to the zone data
 */

void zone_acquire(zone_desc_s *zone_desc);

void zone_free(zone_desc_s *zone_setup);

#define zone_release(zd__) zone_free(zd__)

void zone_dump_allocated();

/**
 * 
 */

void zone_remove_all_matching(zone_data_set *dset, zone_data_matching_callback *matchcallback);



#if 1 // NOT USED

/** \brief Frees all elements of the collection
 *
 *  @param[in] src the collection
 *
 *  @return NONE
 */

void zone_free_all(zone_data_set *set);

#endif

ya_result zone_complete_settings(zone_desc_s *zone_desc);

/**
 * 
 * Adds the zone in the collection (if it's not there already)
 * 
 * @param set
 * @param zone
 * @return 
 */

ya_result zone_register(zone_data_set *set, zone_desc_s *zone);

/**
 * Removes the zone with the given origin from the collection.
 * Returns a pointer to the zone. (The caller may destroy it if
 * he wants)
 */

zone_desc_s *zone_unregister(zone_data_set *set, const u8 *origin);

/**
 * returns the zone_data from the zone config that's just after the name
 * in lexicographic order
 * 
 * @param name
 * @return 
 */

zone_desc_s *zone_getafterdnsname(const u8 *name);

/**
 * returns the zone_data from the zone config for the name
 * 
 * @param name
 * @return 
 */

zone_desc_s *zone_acquirebydnsname(const u8 *name);


/*
 * functions used for removing a zone_desc
 */

void zone_setmodified(zone_desc_s *zone_desc, bool v);
void zone_setloading(zone_desc_s *zone_desc, bool v);
void zone_setmustsavefile(zone_desc_s *zone_desc, bool v);
void zone_setmustsaveaxfr(zone_desc_s *zone_desc, bool v);
void zone_setsavingfile(zone_desc_s *zone_desc, bool v);
void zone_setsavingaxfr(zone_desc_s *zone_desc, bool v);
void zone_setstartingup(zone_desc_s *zone_desc, bool v);
void zone_setdynamicupdating(zone_desc_s *zone_desc, bool v);

bool zone_isidle(zone_desc_s *zone_desc);
bool zone_isfrozen(zone_desc_s *zone_desc);
bool zone_ismodified(zone_desc_s *zone_desc);
bool zone_isloading(zone_desc_s *zone_desc);
bool zone_mustsavefile(zone_desc_s *zone_desc);
bool zone_mustsaveaxfr(zone_desc_s *zone_desc);
bool zone_issavingfile(zone_desc_s *zone_desc);
bool zone_issavingaxfr(zone_desc_s *zone_desc);
bool zone_isdynamicupdating(zone_desc_s *zone_desc);
bool zone_canbeedited(zone_desc_s *zone_desc);
/*
 * This will mark a zone as being obsolete.
 * It means that we are about to delete it.
 * It also means that nobody can lock it anymore, but the destoyer) (lock will return an error for anybody else)
 */

ya_result zone_wait_unlocked(zone_desc_s *zone_desc);

void zone_set_lock(zone_data_set *dset);
void zone_set_unlock(zone_data_set *dset);

/*
 * returns true if a zone is obsolete
 */

bool zone_is_obsolete(zone_desc_s *zone_desc);

/*
 * returns true if the zone hasn't even tried to load its zone
 */

bool zone_isstartingup(zone_desc_s *zone_desc);

/*
 * returns the owner, or error if the zone_desc is obsolete
 */

ya_result zone_try_lock(zone_desc_s *zone_desc, u8 owner_mark);

/*
 * wait for lock (and return the owner) or return an error if the zone_desc becomes obsolete
 */

ya_result zone_lock(zone_desc_s *zone_desc, u8 owner_mark);

/*
 * unlocks if locked by the owner, else return an error
 */

void zone_unlock(zone_desc_s *zone_desc, u8 owner_mark);

const char *zone_type_to_name(zone_type t);
const char* zone_dnssec_to_name(u32 dnssec_flags);

void zone_setdefaults(zone_desc_s *zone_desc);

// 0 : no merge, 1 : merge, < 0 : error
ya_result zone_setwithzone(zone_desc_s *zone_desc, zone_desc_s *src);

static inline bool
zone_is_auto_notify(zone_desc_s *zone_desc)
{
    return (zone_desc->flags & ZONE_FLAG_NOTIFY_AUTO) != 0;
}

static inline void
zone_auto_notify_set(zone_desc_s *zone_desc, bool enable)
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

static inline bool
zone_is_drop_before_load(zone_desc_s *zone_desc)
{
    return (zone_desc->flags & ZONE_FLAG_DROP_BEFORE_LOAD) != 0;
}

void zone_enqueue_command(zone_desc_s *zone_desc, u32 id, void* parm, bool has_priority);
zone_command_s* zone_dequeue_command(zone_desc_s *zone_desc);
void zone_command_free(zone_command_s *cmd);
/**
 * 
 * Functions to log a zone desc
 * 
 * @param zone_desc
 * @param text
 */

void zone_desc_log(logger_handle* handle, u32 level, const zone_desc_s *zone_desc, const char *text);
void zone_desc_log_all(logger_handle* handle, u32 level, zone_data_set *dset, const char *text);

#endif

/*    ------------------------------------------------------------    */

/** @} */
