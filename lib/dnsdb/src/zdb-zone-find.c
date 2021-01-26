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

/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 */

#include "dnsdb/dnsdb-config.h"
#include <unistd.h>
#include <arpa/inet.h>

#include <dnscore/mutex.h>

#include <dnscore/dnscore.h>

#include <dnscore/logger.h>

#include "dnsdb/zdb.h"

#include "dnsdb/zdb-zone-find.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_error.h"

#include "dnsdb/dnsrdata.h"

#if ZDB_HAS_NSEC_SUPPORT
#include "dnsdb/nsec.h"
#endif
#if ZDB_HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3.h"
#endif

#if DEBUG
#define ZONE_MUTEX_LOG 0    // set this to 0 to disable in DEBUG
#else
#define ZONE_MUTEX_LOG 0
#endif

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

/**
 * @brief Get the zone with the given name
 *
 * Get the zone with the given name
 * 
 * No reference counting is done.  This is ultimately used to find existence.
 *
 * @param[in] db a pointer to the database
 * @param[in] exact_match_origin the name of the zone
 *
 * @return a pointer to zone or NULL if the zone is not in the database
 *
 */

static inline zdb_zone*
zdb_zone_find(zdb *db, dnsname_vector *exact_match_origin) // INTERNAL mutex checked
{
    /* Find label */

    yassert(group_mutex_islocked(&db->mutex));
    
    zdb_zone_label *zone_label = zdb_zone_label_find(db, exact_match_origin); // zdb_zone_find

    if(zone_label != NULL)
    {
        return zone_label->zone;
    }
    else
    {
        return NULL;
    }
}

bool zdb_zone_exists(zdb *db, dnsname_vector* exact_match_origin)
{
    zdb_lock(db, ZDB_MUTEX_READER);
    bool does_exist = (zdb_zone_find(db, exact_match_origin) != NULL); // INTERNAL
    zdb_unlock(db, ZDB_MUTEX_READER);
    return does_exist;
}

/**
 * @brief Get the zone with the given name
 *
 * Get the zone with the given name
 * 
 * No reference counting is done.  This is ultimately used to find existence.
 *
 * @param[in] db a pointer to the database
 * @param[in] name the name of the zone (dotted c-string)
 *
 * @return a pointer to zone or NULL if the zone is not in the database
 *
 */

static inline zdb_zone *
zdb_zone_find_from_name(zdb* db, const char* name) // INTERNAL mutex checked
{
    dnsname_vector origin;

    u8 dns_name[MAX_DOMAIN_LENGTH];

    if(ISOK(cstr_to_dnsname(dns_name, name)))
    {
        dnsname_to_dnsname_vector(dns_name, &origin);

        zdb_zone *zone = zdb_zone_find(db, &origin); // INTERNAL
        
        return zone;
    }

    return NULL;
}

bool zdb_zone_exists_from_name(zdb *db, const char* name)
{
    zdb_lock(db, ZDB_MUTEX_READER);
    bool does_exist = (zdb_zone_find_from_name(db, name) != NULL); // INTERNAL
    zdb_unlock(db, ZDB_MUTEX_READER);
    return does_exist;
}

/**
 * @brief Get the zone with the given dns name
 *
 * Get the zone with the given dns name
 * 
 * No reference counting is done.  This is ultimately used to find existence.
 *
 * @param[in] db a pointer to the database
 * @param[in] name the name of the zone (dns name)
 *
 * @return a pointer to zone or NULL if the zone is not in the database
 *
 */

static inline zdb_zone *
zdb_zone_find_from_dnsname(zdb* db, const u8 *dns_name) // INTERNAL mutex checked
{
    dnsname_vector origin;
    
    yassert(group_mutex_islocked(&db->mutex));

    dnsname_to_dnsname_vector(dns_name, &origin);

    zdb_zone *zone = zdb_zone_find(db, &origin); // INTERNAL
    
    return zone;
}

bool
zdb_zone_exists_from_dnsname(zdb *db, const u8* dns_name)
{
    zdb_lock(db, ZDB_MUTEX_READER);
    bool does_exist = (zdb_zone_find_from_dnsname(db, dns_name) != NULL); // KEEP
    zdb_unlock(db, ZDB_MUTEX_READER);
    return does_exist;
}

/** @} */
