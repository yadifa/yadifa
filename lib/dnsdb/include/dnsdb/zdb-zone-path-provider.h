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

#pragma once

#include <dnscore/sys_types.h>

/**
 * For backward compatibility
 * 
 * @param path
 */

void journal_set_xfr_path(const char *path);

/**
 * For backward compatibility
 * 
 * @return 
 */

const char* journal_get_xfr_path();

/**
 * The database does not know zone types. The only one that does is the server.
 * So it makes sense to provide it a way to chose where the DB will store journals.
 * This is especially important with the new master/slave journal separation
 * 
 * The default provider returns something based on the XFR path (journal_set_xfr_path)
 * 
 */

#define ZDB_ZONE_PATH_PROVIDER_ZONE_PATH 1   // want the full path of the directory for the zone
#define ZDB_ZONE_PATH_PROVIDER_ZONE_FILE 2   // want the full path of the file for the zone
#define ZDB_ZONE_PATH_PROVIDER_AXFR_PATH 3   // want the full path of the directory for the image of the zone (AXFR)
#define ZDB_ZONE_PATH_PROVIDER_AXFR_FILE 4   // want the full path of the directory for the image of the zone (AXFR)
#define ZDB_ZONE_PATH_PROVIDER_IXFR_PATH 5   // want the full path of the file for the incremental of the zone (IXFR/journal)
#define ZDB_ZONE_PATH_PROVIDER_IXFR_FILE 6   // want the full path of the file for the incremental of the zone (IXFR/journal)
#define ZDB_ZONE_PATH_PROVIDER_DNSKEY_PATH 7 // want the full path containing the DNSKEY keypairs for the zone (smart signing, key management)
#define ZDB_ZONE_PATH_PROVIDER_RNDSUFFIX 64  // appends a suffix to the file name (.SUFFIX), useful for temporary files/files being build
#define ZDB_ZONE_PATH_PROVIDER_MKDIR     128 // create the path before returning

typedef ya_result zdb_zone_path_provider_callback(const u8* domain_fqdn, char *path_buffer, u32 path_buffer_size, u32 flags);

/**
 * Sets the provider.
 *
 * Note that the provider should return the length of the strings it returns.
 * 
 * @param provider the provider or NULL to reset to the default one.
 */

void zdb_zone_path_set_provider(zdb_zone_path_provider_callback *provider);
zdb_zone_path_provider_callback *zdb_zone_path_get_provider();

struct zdb_zone_path_provider_buffer
{
    void *ptr;
    u32 size;
};

typedef struct zdb_zone_path_provider_buffer zdb_zone_path_provider_buffer;

union zdb_zone_info_provider_data
{
    bool _bool;
    u8 _u8;
    u16 _u16;
    u32 _u32;
    u64 _u64;
    ya_result _result;
    void *_ptr;
    zdb_zone_path_provider_buffer _buffer;
};

typedef union zdb_zone_info_provider_data zdb_zone_info_provider_data;

/**
 * Zone info should be renamed into zone ctrl (not to be mixed with the server ctrl)
 * The zone ctrl may become a superset of the path provider
 * The zdb_zone_path_provider_data could become a generic high-level type
 */

typedef ya_result zdb_zone_info_provider_callback(const u8 *origin, zdb_zone_info_provider_data *data, u32 flags);

#define ZDB_ZONE_INFO_PROVIDER_STORED_SERIAL       0x100 // u32
#define ZDB_ZONE_INFO_PROVIDER_MAX_JOURNAL_SIZE    0x101 // u32
#define ZDB_ZONE_INFO_PROVIDER_ZONE_TYPE           0x102 // u8 (ZT_MASTER, ZT_SLAVE, ...)

#define ZDB_ZONE_INFO_PROVIDER_STORE_TRIGGER       0x10000 // NULL, enqueues the storage of the zone
#define ZDB_ZONE_INFO_PROVIDER_STORE_NOW           0x10001 // ?, stores the zone now, in this thread
#define ZDB_ZONE_INFO_PROVIDER_STORE_IN_PROGRESS   0x10002 // ?, stores the zone now, in this thread


void zdb_zone_info_set_provider(zdb_zone_info_provider_callback *data);
zdb_zone_info_provider_callback *zdb_zone_info_get_provider();

ya_result zdb_zone_info_get_stored_serial(const u8 *origin, u32 *serial);

ya_result zdb_zone_info_get_zone_max_journal_size(const u8 *origin, u32 *size);

ya_result zdb_zone_info_get_zone_type(const u8 *origin, u8 *zt);

ya_result zdb_zone_info_store_locked_zone(const u8 *origin);

ya_result zdb_zone_info_background_store_zone(const u8 *origin);

/**
 * 
 * Should not be used anymore.
 * 
 * @param origin
 * @param minimum_serial
 * @return 
 */

ya_result zdb_zone_info_background_store_zone_and_wait_for_serial(const u8 *origin, u32 minimum_serial);

ya_result zdb_zone_info_background_store_in_progress(const u8 *origin);


/** @} */
