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

/** @defgroup dnsdbdnssec DNSSEC functions
 *  @ingroup dnsdb
 *  @brief 
 *
 * @{
 */

#include "dnsdb/dnsdb-config.h"
#include <sys/stat.h>

#include <dnscore/fdtools.h>
#include <dnscore/string_set.h>
#include <dnscore/logger.h>

#include "dnsdb/zdb-zone-dnssec.h"
#include "dnsdb/zdb-zone-path-provider.h"
#include "dnsdb/zdb_types.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

static ya_result
zdb_zone_dnssec_keys_getpath(zdb_zone *zone, char *buffer, u32 len)
{
    ya_result ret;
    
    if(FAIL(ret = zdb_zone_path_get_provider()(zone->origin, buffer, len, ZDB_ZONE_PATH_PROVIDER_DNSKEY_PATH)))
    {
        log_err("unable to retrieve zone keys for %{dnsname}", zone->origin);
    }
    
    return ret;
}

struct zdb_zone_dnssec_callback_s
{
    zdb_zone *zone;
    
};

typedef struct zdb_zone_dnssec_callback_s zdb_zone_dnssec_callback_s;

static ya_result
zdb_zone_dnssec_readdir(const char *basedir, const char* file, u8 filetype, void *args_)
{
    (void)basedir;
    (void)filetype;
    (void)args_;

    //zdb_zone_dnssec_callback_s *args = (zdb_zone_dnssec_callback_s*)args_;
    int alg;
    int tag;
    char name[256];
    
    // Korigin.+alg+tag.private
    
    if(file[0] == 'K')
    {
        size_t len = strlen(file);
        if(len >= 9)
        {
            if(memcmp(&file[len - 8], ".private", 8) == 0)
            {
                if(sscanf(file, "K%255[^+]+%03d+%05d.private", name, &alg, &tag) == 3)
                {
                    // this file contains a key for that zone
                    // put the key in the keyring
                    /*
                    struct stat st;
                    if(lstat(file, &st) >= 0)
                    {
                        st.st_mtim;
                    }
                    */
                    
                    // open the file
                }
            }
        }
    }
    
    return 0;
}

void
zdb_zone_dnssec_keys_path_init(string_set *set)
{
    *set = STRING_SET_EMPTY;
}

void
zdb_zone_dnssec_keys_path_add(string_set *set, const char *keys_path)
{
    string_node *node = string_set_insert(set, keys_path); // assumes new value set to 0
    if(node->value == 0)
    {
        node->key = strdup(keys_path);
        node->value = 1;
    }
}

void
zdb_zone_dnssec_keys_path_update(string_set *set)
{
    string_set_iterator iter;
    string_set_iterator_init(set, &iter);
    
    zdb_zone_dnssec_callback_s cb;
    
    while(string_set_iterator_hasnext(&iter))
    {
        string_node* node = string_set_iterator_next_node(&iter);
        
        /*ya_result ret =*/ readdir_forall(node->key, zdb_zone_dnssec_readdir, &cb);
    }
    
    string_set_destroy(set);
}

void
zdb_zone_dnssec_keys_path_finalize(string_set *set)
{
    string_set_iterator iter;
    string_set_iterator_init(set, &iter);
    
    while(string_set_iterator_hasnext(&iter))
    {
        string_node* node = string_set_iterator_next_node(&iter);
        free((void*)node->key);
    }
    
    string_set_destroy(set);
}

void
zdb_zone_dnssec_keys_refresh()
{

}

void
zdb_zone_dnssec_keys_publish(zdb_zone *zone)
{
    //time_t now = time(NULL);
    
//    dnskey_get_publish_epoch
    
    char keys_path[PATH_MAX];

    if(FAIL(zdb_zone_dnssec_keys_getpath(zone, keys_path, sizeof(keys_path))))
    {
        return;
    }
}

void
zdb_zone_dnssec_keys_activate(zdb_zone *zone)
{
    char keys_path[PATH_MAX];

    if(FAIL(zdb_zone_dnssec_keys_getpath(zone, keys_path, sizeof(keys_path))))
    {
        return;
    }
}

void
zdb_zone_dnssec_keys_deactivate(zdb_zone *zone)
{
    char keys_path[PATH_MAX];

    if(FAIL(zdb_zone_dnssec_keys_getpath(zone, keys_path, sizeof(keys_path))))
    {
        return;
    }
}

void
zdb_zone_dnssec_keys_unpublish(zdb_zone *zone)
{
    char keys_path[PATH_MAX];

    if(FAIL(zdb_zone_dnssec_keys_getpath(zone, keys_path, sizeof(keys_path))))
    {
        return;
    }
}

/**
 * @}
 */
