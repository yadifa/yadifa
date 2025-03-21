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

#pragma once

#include <dnsdb/zdb_config_features.h>

#if ZDB_HAS_LOCK_DEBUG_SUPPORT

#include <dnsdb/zdb_zone.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct zdb_zone_lock_monitor_s;

struct zdb_zone_lock_monitor_s *zdb_zone_lock_monitor_new(const zdb_zone_t *zone, uint8_t owner, uint8_t secondary);
struct zdb_zone_lock_monitor_s *zdb_zone_lock_monitor_get(const zdb_zone_t *zone);
bool                            zdb_zone_lock_monitor_release(struct zdb_zone_lock_monitor_s *holder);
void                            zdb_zone_lock_monitor_waits(struct zdb_zone_lock_monitor_s *holder);
void                            zdb_zone_lock_monitor_resumes(struct zdb_zone_lock_monitor_s *holder);
void                            zdb_zone_lock_monitor_exchanges(struct zdb_zone_lock_monitor_s *holder);
void                            zdb_zone_lock_monitor_locks(struct zdb_zone_lock_monitor_s *holder);
void                            zdb_zone_lock_monitor_cancels(struct zdb_zone_lock_monitor_s *holder);
void                            zdb_zone_lock_monitor_unlocks(struct zdb_zone_lock_monitor_s *holder);

void                            zdb_zone_lock_monitor_log();

#ifdef __cplusplus
}
#endif

#endif
