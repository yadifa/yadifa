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

#ifndef DATABASE_H_
#define DATABASE_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "server_config.h"

#include <dnscore/dns_message.h>
#include <dnscore/fingerprint.h>

#include <dnscore/ptr_treemap.h>

#include <dnsdb/zdb_types.h>
#include <dnsdb/zdb.h>
#include <dnsdb/zdb_query_to_wire.h>

#include "zone.h"
#if HAS_RRL_SUPPORT
#include "rrl.h"
#endif
#if ZDB_HAS_QUERY_US_DEBUG
#include <dnscore/dns_message.h>
#endif

/* List of database type in string form */

#define DB_STRING_NO                  "no database"

#define DATABASE_JOURNAL_MINIMUM_SIZE 65536

void      database_init();
void      database_finalize();

ya_result database_clear_zones(zdb_t *database, zone_data_set *dset);
ya_result database_startup(zdb_t **);

/** \brief Get dns answer from database
 *
 *  @param database
 *  @param mesg
 */

static inline void database_query(zdb_t *database, dns_message_t *mesg)
{
#if DNSCORE_HAS_QUERY_US_DEBUG
    int64_t ts_start = timeus();
#endif
    zdb_query_to_wire_context_t context;
    zdb_query_to_wire_context_init(&context, mesg, database);
    zdb_query_to_wire(&context);
    zdb_query_to_wire_finalize(&context);
#if DNSCORE_HAS_QUERY_US_DEBUG
    int64_t ts_stop = timeus();
    dns_message_log_query_us(mesg, ts_start, ts_stop);
#endif
}

#if HAS_RRL_SUPPORT

/** \brief Get DNS answer from database
 *
 *  Get DNS answer from database
 *
 *  @param mesg
 *
 *  @return RRL code
 */

static inline ya_result database_query_with_rrl(zdb_t *db, dns_message_t *mesg)
{
#if DNSCORE_HAS_QUERY_US_DEBUG
    int64_t ts_start = timeus();
#endif
    zdb_query_to_wire_context_t context;
    zdb_query_to_wire_context_init(&context, mesg, db);
    zdb_query_to_wire(&context);
    ya_result ret = rrl_process(mesg, &context);
    zdb_query_to_wire_finalize(&context);
#if DNSCORE_HAS_QUERY_US_DEBUG
    int64_t ts_stop = timeus();
    dns_message_log_query_us(mesg, ts_start, ts_stop);
#endif
    return ret;
}
#endif

ya_result database_apply_nsec3paramqueued(zdb_zone_t *zone, zdb_resource_record_set_t *rrset, uint8_t lock_owner);

/**
 * Applied the update in the message to the database.
 * Updates the message with the result of the update.
 * In case of TSIG, the answer message is signed by the call.
 *
 * @param database the zone database
 * @param mesg the update message
 * @return an error code
 */

ya_result database_update(zdb_t *database, dns_message_t *mesg);

/**
 * Logs the update result in case of error.
 *
 * @param mesg the update message
 * @param ret  the database_update return value
 */

void      database_update_log(dns_message_t *mesg, ya_result ret);
ya_result database_print_zones(zone_desc_t *, char *);
ya_result database_shutdown(zdb_t *);

/* Slave only */
ya_result database_zone_refresh_maintenance_wih_zone(zdb_zone_t *zone, uint32_t next_alarm_epoch);
ya_result database_zone_refresh_maintenance(zdb_t *database, const uint8_t *origin, uint32_t next_alarm_epoch);

bool      database_are_all_zones_stored_to_disk();
void      database_wait_all_zones_stored_to_disk();
void      database_disable_all_zone_store_to_disk();
ya_result database_store_all_zones_to_disk();

#ifdef __cplusplus
}
#endif

#endif /* DATABASE_H_ */

/** @} */
