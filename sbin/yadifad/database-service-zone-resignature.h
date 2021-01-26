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

/** @defgroup ### #######
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */
#pragma once


#include "server-config.h"

#include <dnsdb/zdb_types.h>

#if HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_DNSSEC_SUPPORT

/**
 * If zone_desc_owner is 0, does not lock the zone_desc
 */

ya_result database_service_zone_dnssec_maintenance_lock_for(zone_desc_s *zone_desc, u8 zone_desc_owner);

ya_result database_service_zone_dnssec_maintenance(zone_desc_s *zone_desc); // one thread for all the program

void database_service_zone_dnskey_set_alarms_for_key(zdb_zone *zone, dnssec_key *key);

/**
 * 
 * Fetches all (smart signing) events of all the keys of a zone and arms them.
 * 
 * @param zone
 */

void database_service_zone_dnskey_set_alarms(zdb_zone *zone);

/**
 * 
 * Fetches all (smart signing) events of all the keys of all the zones and arms them.
 * 
 * @return 
 */

void database_service_zone_dnskey_set_alarms_on_all_zones();

ya_result database_service_zone_resignature_init();

ya_result database_service_zone_resignature_finalize();

#else
#error "no RRSIG management support: database-service-zone-resignature.h should not be included"
#endif

/** @} */
