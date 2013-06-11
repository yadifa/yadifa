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
* DOCUMENTATION */
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

#include	"check.h"
#include	"parser.h"
#include    "zone_data.h"

/*    ------------------------------------------------------------
 *
 *      VALUES
 */
/** \def ttl value used for the zone file if none provided */
#define		DEFAULT_TTL             86400
#define		DOT_DOMAIN              "."

#define		BRACKET_CLOSED          0x00U
#define		BRACKET_OPEN            0x01U
/**  flag settings for printing the zone file
 * \param 0 means not printing of the resource records
 * \param 1 means printing of the resource records
 */
#define		WITHOUT_RR		0
#define		WITH_RR                 1

/*    ------------------------------------------------------------
 *
 *      VALUES
 */

/*    ------------------------------------------------------------
 *
 *      ENUM
 */


/*    ------------------------------------------------------------
 *
 *      STRUCTS
 */

/*    ------------------------------------------------------------
 *
 *      PROTOTYPES
 */



#define         ZONE_NAME              0x01U
#define         ZONE_TYPE              0x02U
#define         ZONE_ACL               0x04U
#define         ZONE_GLOBAL_RR         0x08U
#define         ZONE_RR                0x10U
#define         ZONE_ALL               (ZONE_NAME | ZONE_TYPE | ZONE_ACL | ZONE_GLOBAL_RR | ZONE_RR)

void zone_init(zone_data_set *set);

/** @brief Initializing zone_data variable
 *
 *  Allocates and clears a new zone data (fully empty)
 *
 *  @retval clean new zone_data
 */
zone_data *zone_alloc();

zone_data *zone_clone(zone_data *zone_setup);

/** \brief
 *  Frees a zone data
 *
 *  @param[in] src is a * to the zone data
 */

void zone_free(zone_data *zone_setup);

/** \brief Frees all elements of the collection
 *
 *  @param[in] src the collection
 *
 *  @return NONE
 */

void zone_free_all(zone_data_set *set);

/**
 * Adds the zone in the collection (if it's not there already)
 */

ya_result zone_register(zone_data_set *set, zone_data *zone);

/**
 * Removes the zone with the given origin from the collection.
 * Returns a pointer to the zone. (The caller may destroy it if
 * he wants)
 */

zone_data *zone_unregister(zone_data_set *set, u8 *origin);

/**
 * returns the zone_data from the zone config for the name
 * 
 * @param name
 * @return 
 */

zone_data *zone_getbydnsname(const u8 *name);

/**
 * returns the zone_data from the dynamic zone config for the name
 * 
 * @param name
 * @return 
 */

zone_data *zone_getdynamicbydnsname(const u8 *name);

/*
 * functions used for removing a zone_desc
 */

void zone_setmodified(zone_data *zone_desc, bool v);
void zone_setloading(zone_data *zone_desc, bool v);
void zone_setmustsavefile(zone_data *zone_desc, bool v);
void zone_setmustsaveaxfr(zone_data *zone_desc, bool v);
void zone_setsavingfile(zone_data *zone_desc, bool v);
void zone_setsavingaxfr(zone_data *zone_desc, bool v);
void zone_setstartingup(zone_data *zone_desc, bool v);
void zone_setdynamicupdating(zone_data *zone_desc, bool v);

bool zone_isidle(zone_data *zone_desc);
bool zone_ismodified(zone_data *zone_desc);
bool zone_isloading(zone_data *zone_desc);
bool zone_mustsavefile(zone_data *zone_desc);
bool zone_mustsaveaxfr(zone_data *zone_desc);
bool zone_issavingfile(zone_data *zone_desc);
bool zone_issavingaxfr(zone_data *zone_desc);
bool zone_isdynamicupdating(zone_data *zone_desc);
bool zone_canbeedited(zone_data *zone_desc);
/*
 * This will mark a zone as being obsolete.
 * It means that we are about to delete it.
 * It also means that nobody can lock it anymore, but the destoyer) (lock will return an error for anybody else)
 */

ya_result zone_set_obsolete(zone_data *zone, u8 destroyer_mark);

void zone_set_lock(zone_data_set *dset);
void zone_set_unlock(zone_data_set *dset);

/*
 * returns true if a zone is obsolete
 */

bool zone_is_obsolete(zone_data *zone);

/*
 * returns true if the zone hasn't even tried to load its zone
 */

bool zone_isstartingup(zone_data *zone_desc);

/*
 * returns the owner, or error if the zone_desc is obsolete
 */

ya_result zone_try_lock(zone_data *zone, u8 owner_mark);

/*
 * wait for lock (and return the owner) or return an error if the zone_desc becomes obsolete
 */

ya_result zone_lock(zone_data *zone, u8 owner_mark);

/*
 * unlocks if locked by the owner, else return an error
 */

ya_result zone_unlock(zone_data *zone, u8 owner_mark);

const char *zone_type_to_name(zone_type t);

void zone_setdefaults(zone_data *zone);

/*
 * functions used to print a zone desc
 */

void zone_print(const zone_data *, const char *text, u8 flag, output_stream*);
void zone_print_all(zone_data_set *dset, const char *text, u8 flag, output_stream*);

#endif

/*    ------------------------------------------------------------    */

/** @} */
