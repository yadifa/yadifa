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

/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include "dnsdb/dnsdb-config.h"
#include <ctype.h>
#include <dnscore/format.h>
#include <dnscore/fdtools.h>
#include <dnscore/serial.h>
#include <dnscore/timems.h>
#include "dnsdb/zdb-zone-path-provider.h"

static ya_result
zdb_zone_path_provider_default(const u8* domain_fqdn, char *path_buffer, u32 path_buffer_size, u32 flags);

static zdb_zone_path_provider_callback *zdb_zone_path_provider = zdb_zone_path_provider_default;
static char *xfr_path = LOCALSTATEDIR "/zones/xfr";
static bool xfr_path_free = FALSE;

/**
 * The hash function that gives a number from an ASCIIZ string
 * 
 * @param p ASCIIZ string
 * 
 * @return the hash
 */

static u32
zdb_zone_path_provider_copy_hash(const u8 *p)
{
    u32 h = 0;
    u32 c;
    u8 s = 0;
    do
    {
        c = toupper(*p++);
        c &= 0x3f;
        h += c << (s & 15);
        h += 97;
        s += 13;
    }
    while(c != 0);
    
    return h;
}

/**
 * 
 * Returns the hashed folder path for a zone.
 * 
 * @param data_path             the target buffer for the data path
 * @param data_path_size        the target buffer size
 * @param base_data_path        the base folder
 * @param origin                the origin of the zone
 * 
 * @return 
 */

static ya_result
zdb_zone_path_provider_get_data_path(char *data_path, u32 data_path_size, const char *base_data_path, const u8 *origin)
{
    u32 h = zdb_zone_path_provider_copy_hash(origin);
    
    return snformat(data_path, data_path_size, "%s/%02x/%02x", base_data_path, h & 0xff, (h >> 8) & 0xff);
}

/**
 * For backward compatibility
 * 
 * @param path
 */

void
journal_set_xfr_path(const char *path)
{
    if(xfr_path_free)
    {
        free((char*)xfr_path);
    }
    
    if(path == NULL)
    {        
        xfr_path = LOCALSTATEDIR "/xfr";
        xfr_path_free = FALSE;
    }
    else
    {
        xfr_path = strdup(path);
        xfr_path_free = TRUE;
    }
}

/**
 * For backward compatibility
 */

const char*
journal_get_xfr_path()
{
    return xfr_path;
}

static ya_result
zdb_zone_path_provider_default(const u8* domain_fqdn, char *path_buffer, u32 path_buffer_size, u32 flags)
{
    ya_result ret;
    char *suffix = "";
    char dir_path[PATH_MAX];
    
    if((flags & ZDB_ZONE_PATH_PROVIDER_RNDSUFFIX) != 0)
    {
        flags &= ~ZDB_ZONE_PATH_PROVIDER_RNDSUFFIX;
        suffix = ".part";
    }
      
    if(FAIL(ret = zdb_zone_path_provider_get_data_path(dir_path, sizeof(dir_path), xfr_path, domain_fqdn))) // default path provider
    {
        return ret;
    }
    
    if((flags & ZDB_ZONE_PATH_PROVIDER_MKDIR) != 0)
    {
        flags &= ~ZDB_ZONE_PATH_PROVIDER_MKDIR;
        
        if(FAIL(ret = mkdir_ex(dir_path, 0755, 0)))
        {
            return ret;
        }
    }
    
    switch(flags)
    {
        case ZDB_ZONE_PATH_PROVIDER_ZONE_FILE:
        {
            ret = snformat(path_buffer, path_buffer_size, "%s/%{dnsname}%s", dir_path, domain_fqdn, suffix);
            break;
        }
        case ZDB_ZONE_PATH_PROVIDER_ZONE_PATH:
        {
            ret = snformat(path_buffer, path_buffer_size, "%s", dir_path);
            break;
        }
        case ZDB_ZONE_PATH_PROVIDER_DNSKEY_PATH:
        {
            ret = snformat(path_buffer, path_buffer_size, "%s/keys", dir_path);
            break;
        }
        default:
        {
            ret = INVALID_ARGUMENT_ERROR;    // no handled flags have been used
        }
    }
        
    return ret;
}

/**
 * Sets the provider.
 * Note that the provider should return the length of the strings it returns.
 * 
 * @param provider the provider or NULL to reset to the default one.
 */

void
zdb_zone_path_set_provider(zdb_zone_path_provider_callback *provider)
{
    if(provider == NULL)
    {
        provider = zdb_zone_path_provider_default;
    }
    
    zdb_zone_path_provider = provider;
}

/**
 * 
 * @return 
 */

static ya_result zdb_zone_info_provider_data_default(const u8 *origin, zdb_zone_info_provider_data *data, u32 flags);

static zdb_zone_info_provider_callback *zdb_zone_info_provider = zdb_zone_info_provider_data_default;

static ya_result zdb_zone_info_provider_data_default(const u8 *origin, zdb_zone_info_provider_data *data, u32 flags)
{
    (void)origin;
    (void)data;
    (void)flags;

    return FEATURE_NOT_IMPLEMENTED_ERROR;
}

zdb_zone_path_provider_callback *
zdb_zone_path_get_provider()
{
    return zdb_zone_path_provider;
}

void
zdb_zone_info_set_provider(zdb_zone_info_provider_callback *data)
{
    if(data == NULL)
    {
        data = zdb_zone_info_provider_data_default;
    }
    
    zdb_zone_info_provider = data;
}

zdb_zone_info_provider_callback *
zdb_zone_info_get_provider()
{
    return zdb_zone_info_provider;
}

ya_result
zdb_zone_info_get_stored_serial(const u8 *origin, u32 *serial)
{
    yassert(origin != NULL);
    yassert(serial != NULL);
    zdb_zone_info_provider_data data;
    ya_result ret;
    if(ISOK(ret = zdb_zone_info_get_provider()(origin, &data, ZDB_ZONE_INFO_PROVIDER_STORED_SERIAL)))
    {
        *serial = data._u32; // VS false positive: reaching this point, data is initialized (by contract)
    }
    return ret;    
}

ya_result
zdb_zone_info_get_zone_max_journal_size(const u8 *origin, u32 *size)
{
    yassert(origin != NULL);
    yassert(size != NULL);
    zdb_zone_info_provider_data data;
    data._u64 = *size;      // known wire size / 2
    ya_result ret;
    if(ISOK(ret = zdb_zone_info_get_provider()(origin, &data, ZDB_ZONE_INFO_PROVIDER_MAX_JOURNAL_SIZE)))
    {
        if(data._u64 > MAX_U32)
        {
            data._u64 = MAX_U32;
        }
        
        /// @note THX: here, if data._u64 is < 256*1024, then set to 256*1024 .
        
        *size = data._u64;
    }
    return ret;    
}

ya_result
zdb_zone_info_get_zone_type(const u8 *origin, u8 *zt)
{
    yassert(origin != NULL);
    yassert(zt != NULL);
    zdb_zone_info_provider_data data;
    ya_result ret;
    if(ISOK(ret = zdb_zone_info_get_provider()(origin, &data, ZDB_ZONE_INFO_PROVIDER_ZONE_TYPE)))
    {
        *zt = data._u8; // VS false positive: reaching this point, data is initialized (by contract)
    }
    return ret;    
}

ya_result
zdb_zone_info_background_store_zone(const u8 *origin)
{
    yassert(origin != NULL);
    ya_result ret;
    
    ret = zdb_zone_info_get_provider()(origin, NULL, ZDB_ZONE_INFO_PROVIDER_STORE_TRIGGER);
    
    return ret;    
}

ya_result
zdb_zone_info_store_locked_zone(const u8 *origin)
{
    yassert(origin != NULL);
    ya_result ret;
    
    zdb_zone_info_provider_data already_locked_by;
    already_locked_by._u8 = 0;
    ret = zdb_zone_info_get_provider()(origin, &already_locked_by, ZDB_ZONE_INFO_PROVIDER_STORE_NOW);
    
    return ret;    
}

/**
 * 
 * Should not be used anymore.
 * 
 * @param origin
 * @param minimum_serial
 * @return 
 */

ya_result
zdb_zone_info_background_store_zone_and_wait_for_serial(const u8 *origin, u32 minimum_serial)
{
    // This mechanism should be improved : the zone should be unlocked, frozen, saved, unfrozen, re-locked
    
    yassert(origin != NULL);
    ya_result ret;
    
    ret = zdb_zone_info_get_provider()(origin, NULL, ZDB_ZONE_INFO_PROVIDER_STORE_TRIGGER);
    
    if(ISOK(ret))
    {
        u64 start = timeus();
        
        for(;;)
        {
            u32 serial;
            if(FAIL(ret = zdb_zone_info_get_stored_serial(origin, &serial)))
            {
                return ret;
            }
            if(serial_ge(serial, minimum_serial))
            {
                return SUCCESS;
            }
            
            u64 now = timeus();
            
            if(now < start)
            {
                start = now; //clock modified
            }
            
            if(now - start > ONE_SECOND_US)
            {
                zdb_zone_info_provider_data already_locked_by;
                
                already_locked_by._u8 = 0;
                        
                if(FAIL(ret = zdb_zone_info_get_provider()(origin, &already_locked_by, ZDB_ZONE_INFO_PROVIDER_STORE_TRIGGER)))
                {
                    return ret;
                }
            }
            
            usleep(500000);
        }
    }
    
    return ret;    
}

ya_result
zdb_zone_info_background_store_in_progress(const u8 *origin)
{
    // This mechanism should be improved : the zone should be unlocked, frozen, saved, unfrozen, re-locked
    
    yassert(origin != NULL);
    ya_result ret;
    
    ret = zdb_zone_info_get_provider()(origin, NULL, ZDB_ZONE_INFO_PROVIDER_STORE_IN_PROGRESS);
    
    return ret;
}

/** @} */
