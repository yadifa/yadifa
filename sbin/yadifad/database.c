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

/** @defgroup server
 *  @ingroup yadifad
 *  @brief database functions
 *
 *  Implementation of routines for the database
 *   - add zone file(s)
 *   - clear zone file(s)
 *   - print zone files(s)
 *   - load db
 *   - unload db
 *   - lookup database result of a message
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include "server-config.h"

#include <dnscore/packet_reader.h>

#include <dnscore/dnsname.h>
#include <dnscore/format.h>
#include <dnscore/logger.h>
#include <dnscore/alarm.h>
#include <dnscore/chroot.h>
#include <dnscore/timeformat.h>
#include <dnscore/fdtools.h>

#include <dnsdb/zdb.h>
#if ZDB_HAS_DNSSEC_SUPPORT
#include <dnsdb/dnssec.h>
#endif

#include <dnsdb/zdb.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb-zone-arc.h>
#include <dnsdb/zdb_icmtl.h>
#if HAS_DYNUPDATE_SUPPORT
#include <dnsdb/dynupdate.h>
#endif
#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb_zone_load.h>

#include <dnsdb/xfr_copy.h>
#include <dnsdb/zdb-zone-path-provider.h>
#include <dnsdb/dnssec-keystore.h>

#include <dnscore/zone_reader_text.h>
#include <dnscore/zone_reader_axfr.h>


#include "server.h"
#include "database.h"
#include "database-service.h"
#if HAS_RRSIG_MANAGEMENT_SUPPORT && HAS_DNSSEC_SUPPORT
#include "database-service-zone-resignature.h"
#endif

#include "server_error.h"
#include "config_error.h"

#include "notify.h"

#include "zone.h"
#include "zone_desc.h"

#if HAS_RRL_SUPPORT
#include "rrl.h"
#endif

#include "dnsdb/dynupdate-diff.h"

#ifndef HAS_DYNUPDATE_DIFF_ENABLED
#error "HAS_DYNUPDATE_DIFF_ENABLED not defined"
#endif

#define DBSCHEDP_TAG 0x5044454843534244
#define DBREFALP_TAG 0x504c414645524244

#define DNSSEC_KEY_PARAMETERS_TAG 0x4d5059454b534e44

#define MODULE_MSG_HANDLE g_server_logger

typedef struct database_zone_refresh_alarm_args database_zone_refresh_alarm_args;

struct database_zone_refresh_alarm_args
{
    const u8 *origin;
};

/* Zone file variables */
extern zone_data_set database_zone_desc;

/*------------------------------------------------------------------------------
 * FUNCTIONS */

static zdb_zone_path_provider_callback *database_zone_path_next_provider = NULL;
static zdb_zone_info_provider_callback *database_info_next_provider = NULL;

/**
 * The hash function that gives a number from an ASCIIZ string
 * 
 * @param p ASCIIZ string
 * 
 * @return the hash
 */

static u32
database_zone_path_provider_name_hash(const u8 *p)
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
database_zone_path_provider_get_hashed_name(char *data_path, u32 data_path_size, const char *base_data_path, const u8 *origin)
{
    u32 h = database_zone_path_provider_name_hash(origin);
    
    return snformat(data_path, data_path_size, "%s/%02x/%02x", base_data_path, h & 0xff, (h >> 8) & 0xff);
}


static ya_result
database_zone_path_provider(const u8* domain_fqdn, char *path_buffer, u32 path_buffer_size, u32 flags)
{
    ya_result ret = ZDB_ERROR_ZONE_NOT_IN_DATABASE;
    
#if DEBUG
    char *original_path_buffer = path_buffer;
    u32 original_flags = flags;
    original_path_buffer[0] = '\0';
#endif
    char *suffix = "";
    if((flags & ZDB_ZONE_PATH_PROVIDER_RNDSUFFIX) != 0)
    {
        flags &= ~ZDB_ZONE_PATH_PROVIDER_RNDSUFFIX;
        suffix = ".part";
    }
    
    zone_desc_s *zone_desc = zone_acquirebydnsname(domain_fqdn);
    if(zone_desc != NULL)
    {
        if((zone_desc->file_name == NULL) || (g_config->data_path == NULL))
        {
            zone_release(zone_desc);
            log_err("database: path provider: zone file name or data path not set");
            return INVALID_STATE_ERROR;
        }

        const char *base_data_path = (zone_desc->file_name[0] != '/')?g_config->data_path:"";

        switch(flags & ~ZDB_ZONE_PATH_PROVIDER_MKDIR)
        {
            case ZDB_ZONE_PATH_PROVIDER_ZONE_PATH:
            {
                if(ISOK(ret = snformat(path_buffer, path_buffer_size, "%s%s", base_data_path, zone_desc->file_name)))
                {
                    int n = ret;
                    while(n > 0)
                    {
                        if(path_buffer[n] == '/')
                        {
                            path_buffer[n] = '\0';
                            break;
                        }

                        n--;
                    }
                    
                    if((flags & ZDB_ZONE_PATH_PROVIDER_MKDIR) != 0)
                    {
                        ya_result err = mkdir_ex(path_buffer, 0750, 0);
                        if(FAIL(err) && (err != MAKE_ERRNO_ERROR(EEXIST)))
                        {
                            log_err("database: zone path mkdir: could not create '%s': %r", path_buffer, err);
                        }
                        //flags &= ~ZDB_ZONE_PATH_PROVIDER_MKDIR;
                    }
                }
                break;
            }
            case ZDB_ZONE_PATH_PROVIDER_ZONE_FILE:
            {
                if(ISOK(ret = snformat(path_buffer, path_buffer_size, "%s%s%s", base_data_path, zone_desc->file_name, suffix)))
                {
                    if((flags & ZDB_ZONE_PATH_PROVIDER_MKDIR) != 0)
                    {
                        ya_result err = mkdir_ex(path_buffer, 0750, MKDIR_EX_PATH_TO_FILE);
                        if(FAIL(err) && (err != MAKE_ERRNO_ERROR(EEXIST)))
                        {
                            log_err("database: zone file mkdir: could not create '%s': %r", path_buffer, err);
                        }
                        //flags &= ~ZDB_ZONE_PATH_PROVIDER_MKDIR;
                    }
                }
                
                break;
            }
            case ZDB_ZONE_PATH_PROVIDER_AXFR_PATH:
            {
                if(g_config->xfr_path != NULL)
                {
                    if(ISOK(ret = database_zone_path_provider_get_hashed_name(path_buffer, path_buffer_size, g_config->xfr_path, domain_fqdn)))
                    {
                        if((flags & ZDB_ZONE_PATH_PROVIDER_MKDIR) != 0)
                        {
                            ya_result err = mkdir_ex(path_buffer, 0750, 0);
                            if(FAIL(err) && (err != MAKE_ERRNO_ERROR(EEXIST)))
                            {
                                log_err("database: axfr path mkdir: could not create '%s': %r", path_buffer, err);
                            }
                            //flags &= ~ZDB_ZONE_PATH_PROVIDER_MKDIR;
                        }
                    }
                }
                else
                {
                    log_err("database: path provider: transfer base path not set");
                    ret = INVALID_STATE_ERROR;
                }
                
                break;
            }
            case ZDB_ZONE_PATH_PROVIDER_AXFR_FILE:
            {
                if(ISOK(ret = database_zone_path_provider_get_hashed_name(path_buffer, path_buffer_size, g_config->xfr_path, domain_fqdn)))
                {
                    if((flags & ZDB_ZONE_PATH_PROVIDER_MKDIR) != 0)
                    {
                        ya_result err = mkdir_ex(path_buffer, 0750, 0);
                        if(FAIL(err) && (err != MAKE_ERRNO_ERROR(EEXIST)))
                        {
                            log_err("database: axfr file mkdir: could not create '%s': %r", path_buffer, err);
                        }
                        //flags &= ~ZDB_ZONE_PATH_PROVIDER_MKDIR;
                    }
                    
                    s32 path_size = ret;
                    
                    path_buffer += ret;
                    path_buffer_size -= ret;
                    
                    if(ISOK(ret = snformat(path_buffer, path_buffer_size, "/%{dnsname}.axfr%s", domain_fqdn, suffix)))
                    {
                        ret += path_size;
                    }
                }
                
                break;
            }
            case ZDB_ZONE_PATH_PROVIDER_DNSKEY_PATH:
            {
                if(zone_desc->keys_path != NULL)
                {
                    if(zone_desc->keys_path[0] != '/')
                    {
                        ret = snformat(path_buffer, path_buffer_size, "%s/%s", g_config->data_path, zone_desc->keys_path);
                    }
                    else
                    {
                        ret = snformat(path_buffer, path_buffer_size, "%s", zone_desc->keys_path);
                    }
                }
                else
                {
                    ret = snformat(path_buffer, path_buffer_size, "%s/", g_config->keys_path);
                }
                break;
            }
            default:
            {
                ret = database_zone_path_next_provider(domain_fqdn, path_buffer, path_buffer_size, flags);
                break;
            }
        }
        
        zone_release(zone_desc);
    }
    
#if DEBUG
    log_debug("path-provider: %{dnsname}: %02x: path='%s': %r", domain_fqdn, original_flags, original_path_buffer, ret);
#endif
    
    return ret;
}

static ya_result
database_info_provider(const u8 *origin, zdb_zone_info_provider_data *data, u32 flags)
{
    ya_result ret = ZONE_NOT_DEFINED;
    switch(flags)
    {
        case ZDB_ZONE_INFO_PROVIDER_STORED_SERIAL:
        {
            // get the zone desc and check
            
            zone_desc_s *zone_desc = zone_acquirebydnsname(origin);
            if(zone_desc != NULL)
            {
                data->_u32 = zone_desc->stored_serial;
                zone_release(zone_desc);
                ret = SUCCESS;
            }
            break;
        }
        case ZDB_ZONE_INFO_PROVIDER_MAX_JOURNAL_SIZE:
        {
            // get the zone desc and check
            
            zone_desc_s *zone_desc = zone_acquirebydnsname(origin);
            if(zone_desc != NULL)
            {
                yassert(zone_desc->journal_size_kb <= 8388608);
                u64 max_size = zone_desc->journal_size_kb;

                if(max_size > 0)
                {
                    // the size has been set by the admin
                    
                    max_size *= 1024;
                }
                else if(data->_u64 != 0)
                {
                    // the caller gave the half the wire size of the zone
                    
                    max_size = data->_u64;
                }
                else
                {
                    // nothing has been set, we have to look for the current mounted zone for its wire size
                    
                    zone_lock(zone_desc, ZONE_LOCK_LOAD);
                    zdb_zone *zone = zone_get_loaded_zone(zone_desc);
                    zone_unlock(zone_desc, ZONE_LOCK_LOAD);
                    if(zone != NULL)
                    {
                        max_size = zone->wire_size >> 1;
                        zdb_zone_release(zone);
                    }
                    else
                    {
                        // no zone found, return the default size
                        max_size = DATABASE_JOURNAL_MINIMUM_SIZE;
                    }
                }
                
                zone_release(zone_desc);
                
                if(max_size < DATABASE_JOURNAL_MINIMUM_SIZE)
                {
                    max_size = DATABASE_JOURNAL_MINIMUM_SIZE;
                }
                
                if(max_size > MAX_U32) // current limitation
                {
                    max_size = MAX_U32;
                }
                
                log_debug("database: %{dnsname} journal size set to %uKB", origin, max_size >> 10);
                
                data->_u64 = max_size;
                ret = SUCCESS;
            }
            
            break;
        }
        case ZDB_ZONE_INFO_PROVIDER_ZONE_TYPE:
        {
            // get the zone desc and check
            
            zone_desc_s *zone_desc = zone_acquirebydnsname(origin);
            if(zone_desc != NULL)
            {
                data->_u8 = (u8)zone_desc->type;
                zone_release(zone_desc);
                ret = SUCCESS;
            }
            
            break;
        }
        case ZDB_ZONE_INFO_PROVIDER_STORE_TRIGGER:
        {
            database_zone_store(origin);
            ret = SUCCESS;
            break;
        }
        case ZDB_ZONE_INFO_PROVIDER_STORE_NOW:
        {
            zone_desc_s *zone_desc = zone_acquirebydnsname(origin);
            if(zone_desc != NULL)
            {
                ret = database_service_zone_store_ex(zone_desc, 0, data->_u8, DATABASE_SERVICE_ZONE_SAVE_IGNORE_SHUTDOWN);
            }
            else
            {
                ret = ZONE_NOT_DEFINED;
            }
            break;
        }
        case ZDB_ZONE_INFO_PROVIDER_STORE_IN_PROGRESS:
        {
            zone_desc_s *zone_desc = zone_acquirebydnsname(origin);
            if(zone_desc != NULL)
            {
                bool saving = (zone_get_status(zone_desc) & (ZONE_STATUS_SAVETO_ZONE_FILE|ZONE_STATUS_SAVING_ZONE_FILE)) != 0;
                
                zone_release(zone_desc);
                ret = saving?1:0;
            }
            else
            {
                ret = ZONE_NOT_DEFINED;
            }
            break;
        }
        default:
        {
            ret = database_info_next_provider(origin, data, flags);
            break;
        }
    }
    
    return ret;
}

/**
 * Initialises the database.
 * Ensures the libraries features are matched.
 * 
 */

void
database_init()
{
    zdb_init();
    dnscore_reset_timer();
    
    database_zone_path_next_provider = zdb_zone_path_get_provider();
    zdb_zone_path_set_provider(database_zone_path_provider);
    
    database_info_next_provider = zdb_zone_info_get_provider();
    zdb_zone_info_set_provider(database_info_provider);
}

void
database_finalize()
{
    zdb_zone_path_set_provider(NULL);
    zdb_zone_info_set_provider(NULL);
    zdb_finalize();
}

/** @brief Remove the zones from the database,
 *  but do not remove the database file
 *
 *  @param[in] database
 *  @param[in] zone
 *
 *  @retval OK
 */
ya_result
database_clear_zones(zdb *database, zone_data_set *dset)
{
    dnsname_vector fqdn_vector;
    
    zone_set_lock(dset); // unlock checked

    ptr_set_iterator iter;
    ptr_set_iterator_init(&dset->set, &iter);

    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s*)zone_node->value;

        dnsname_to_dnsname_vector(zone_origin(zone_desc), &fqdn_vector);
        
        zdb_zone *myzone = zdb_remove_zone(database, &fqdn_vector);

        if(myzone != NULL)
        {
            zdb_zone_release(myzone);
        }
    }
    
    zone_set_unlock(dset);

    return OK;
}

/** @brief Creates the (IN) database
 * 
 *  Starts to load the content.
 *
 *  @param[out] database pointer to a pointer to the database 
 * 
 *  @return an error code
 */

/**
 * @NOTE THIS IS SUPPOSED TO BE RUN BEFORE THE SERVER STARTS !
 */

ya_result
database_startup(zdb **database)
{
    ya_result return_code;
    zdb* db;

    /*    ------------------------------------------------------------    */

    if(g_config->data_path == NULL)
    {
        return CONFIG_ZONE_ERR;
    }

    *database = NULL;
    
    database_init(); /* Inits the db, starts the threads of the pool, resets the timer */

    MALLOC_OBJECT_OR_DIE(db, zdb, ZDBCLASS_TAG);
    zdb_create(db);
    
    // add all the registered zones as invalid
    
    *database = db;
    
    database_service_create_invalid_zones();
    
#if ZDB_HAS_DNSSEC_SUPPORT
    dnssec_keystore_reload();
#endif
    
    if(ISOK(return_code = database_service_start()))
    {
        database_load_all_zones();
    }
    
    return return_code;
}

#if HAS_DYNUPDATE_SUPPORT

#if ZDB_HAS_DNSSEC_SUPPORT

struct dnssec_key_parameters_s
{
    const u8 *fqdn;
    u16 tag;
    u16 flags;
    u8 algorithm;
};

typedef struct dnssec_key_parameters_s dnssec_key_parameters_t;

/**
 * Adds key parameters from keys in the zone to a vector
 */

void
database_add_key_parameters_from_zone(zdb_zone *zone, ptr_vector *keys)
{
    const zdb_packed_ttlrdata *dnskey_rrset = zdb_zone_get_dnskey_rrset(zone); // zone is locked

    if(dnskey_rrset != NULL)
    {
        do
        {
            dnssec_key_parameters_t *parameters;
            ZALLOC_OBJECT_OR_DIE(parameters, dnssec_key_parameters_t, DNSSEC_KEY_PARAMETERS_TAG);
            parameters->fqdn = zone->origin;
            parameters->tag = DNSKEY_TAG(*dnskey_rrset);
            parameters->flags = DNSKEY_FLAGS(*dnskey_rrset);
            parameters->algorithm = DNSKEY_ALGORITHM(*dnskey_rrset);

            ptr_vector_append(keys, parameters);

            dnskey_rrset = dnskey_rrset->next;
        }
        while(dnskey_rrset != NULL);
    }
}

/**
 * Adds key parameters from keys added by the message to a vector.
 * Adds key parameters from keys removed by the message to a vector, removes said keys from the "added" vector.
 */

void
database_add_key_parameters_from_message(zdb_zone *zone, message_data *mesg, ptr_vector *keys, ptr_vector *removed_keys)
{
    packet_unpack_reader_data pr;
    ya_result ret = SUCCESS;

    packet_reader_init_from_message(&pr, mesg);
    packet_reader_skip_section(&pr, 0);
    packet_reader_skip_section(&pr, 1);

    // scan for added DNSKEY

    for(u16 records = message_get_authority_count(mesg); records > 0; --records)
    {
        struct type_class_ttl_rdlen tctr;
        u8 fqdn[MAX_DOMAIN_LENGTH];

        if(FAIL(ret = packet_reader_read_fqdn(&pr ,fqdn, sizeof(fqdn))))
        {
            break;
        }
        if(FAIL(ret = packet_reader_read(&pr, &tctr, 10))) // exact
        {
            break;
        }
        tctr.rdlen = ntohs(tctr.rdlen);

        if(tctr.qclass == CLASS_IN)
        {
            // load it

            if(tctr.qtype == TYPE_DNSKEY)
            {
                const void *rdata = packet_reader_get_current_ptr_const(&pr, tctr.rdlen);
                if(rdata != NULL)
                {
                    dnssec_key_parameters_t *parameters;
                    ZALLOC_OBJECT_OR_DIE(parameters, dnssec_key_parameters_t, DNSSEC_KEY_PARAMETERS_TAG);
                    parameters->fqdn = zone->origin;
                    parameters->tag = dnskey_get_tag_from_rdata(rdata, tctr.rdlen);
                    parameters->flags = dnskey_get_flags_from_rdata(rdata);
                    parameters->algorithm = dnskey_get_algorithm_from_rdata(rdata);

                    ptr_vector_append(keys, parameters);
                }
                else
                {
                    // short read:
                    // ret = UNEXPECTED_EOF;
                    break;
                }
            }
        }
        else if(tctr.qclass == CLASS_NONE)
        {
            if(tctr.qtype == TYPE_DNSKEY)
            {
                const void *rdata = packet_reader_get_current_ptr_const(&pr, tctr.rdlen);
                if(rdata != NULL)
                {
                    for(int i = 0; i <= ptr_vector_last_index(keys); ++i)
                    {
                        dnssec_key_parameters_t parameters;
                        parameters.fqdn = zone->origin; // useless
                        parameters.tag = dnskey_get_tag_from_rdata(rdata, tctr.rdlen);
                        parameters.flags = dnskey_get_flags_from_rdata(rdata);
                        parameters.algorithm = dnskey_get_algorithm_from_rdata(rdata);
                        dnssec_key_parameters_t *key_i = (dnssec_key_parameters_t*)ptr_vector_get(keys, i);
                        if((key_i->fqdn == parameters.fqdn) && (key_i->tag == parameters.tag) && (key_i->flags == parameters.flags) && (key_i->algorithm == parameters.algorithm))
                        {
                            // found a match
                            ptr_vector_remove_at(keys, i);
                            ptr_vector_append(removed_keys, key_i);
                        }
                    }
                }
            }
        }
        else if(tctr.qclass == CLASS_ANY)
        {
            if(tctr.qtype == TYPE_DNSKEY)
            {
                ptr_vector_append_vector(keys, removed_keys);
                ptr_vector_clear(keys);
            }
        }


        if(FAIL(ret = packet_reader_skip(&pr, tctr.rdlen)))
        {
            break;
        }
    }
}

/**
 * Loads the private keys (and public keys, of course) whose parameters are listed in the vector.
 */

ya_result
database_ensure_private_keys_from_key_parameters_vector(zdb_zone *zone, ptr_vector *keys)
{
    ya_result ret;

    int ksk_count = 0;
    int zsk_count = 0;
    int new_count = 0;

    for(int i = 0; i <= ptr_vector_last_index(keys); ++i)
    {
        dnssec_key_parameters_t *key_i = (dnssec_key_parameters_t*)ptr_vector_get(keys, i);
        dnssec_key *key = NULL;

        if(ISOK(ret = dnssec_keystore_load_private_key_from_parameters(key_i->algorithm, key_i->tag, key_i->flags, key_i->fqdn, &key))) // key properly released
        {
            new_count += ret;

            if(key_i->flags == DNSKEY_FLAGS_KSK)
            {
                ++ksk_count;
            }
            else if(key_i->flags == DNSKEY_FLAGS_ZSK)
            {
                ++zsk_count;
            }
            else
            {
                // the key is of no use
            }

            dnskey_release(key);
        }
        else
        {
            // only complain if KSKs RRSIGs are not meant to be pushed

            if( !( (key_i->flags == DNSKEY_FLAGS_KSK) && zdb_zone_get_rrsig_push_allowed(zone) ) )
            {
                log_warn("database: update: unable to load the private key 'K%{dnsname}+%03d+%05hd': %r", zone->origin, key_i->algorithm, key_i->tag, ret);
            }
        }
    }

    ret = new_count;

    if(zsk_count == 0)
    {
        log_err("database: update: unable to load any of the ZSK private keys of zone %{dnsname}", zone->origin);
        ret = DNSSEC_ERROR_RRSIG_NOUSABLEKEYS;
    }

    if(ksk_count == 0)
    {
        if(!zdb_zone_get_rrsig_push_allowed(zone))
        {
            log_warn("database: update: unable to load any of the KSK private keys of zone %{dnsname}", zone->origin);
        }
        else
        {
            log_debug("database: update: unable to load any of the KSK private keys of zone %{dnsname}", zone->origin);
        }
    }

    return ret;
}

void
dnssec_key_parameters_vector_destroy(ptr_vector *keys)
{
    for(int i = 0; i <= ptr_vector_last_index(keys); ++i)
    {
        dnssec_key_parameters_t *key_i = (dnssec_key_parameters_t*)ptr_vector_get(keys, i);
        ZFREE_OBJECT(key_i);
    }
    ptr_vector_destroy(keys);
}

/**
 * Loads private keys for the zone.
 * Returns the number of keys loaded or an error code.
 */

ya_result
database_zone_ensure_private_keys(zdb_zone *zone)
{                     
    ya_result return_code;
    
    /*
     * Fetch all private keys
     */

    log_debug("database: update: checking DNSKEY availability");

    const zdb_packed_ttlrdata *dnskey_rrset = zdb_zone_get_dnskey_rrset(zone); // zone is locked

    int ksk_count = 0;
    int zsk_count = 0;
    int new_count = 0;

    if(dnskey_rrset != NULL)
    {
        do
        {
            u16 flags = DNSKEY_FLAGS(*dnskey_rrset);
            //u8  protocol = DNSKEY_PROTOCOL(*dnskey_rrset);
            u8  algorithm = DNSKEY_ALGORITHM(*dnskey_rrset);
            u16 tag = DNSKEY_TAG(*dnskey_rrset);                  // note: expensive
            dnssec_key *key = NULL;

            if(ISOK(return_code = dnssec_keystore_load_private_key_from_parameters(algorithm, tag, flags, zone->origin, &key))) // key properly released
            {
                // if return_code is 0, nothing new was loaded

                new_count += return_code;

                if(flags == DNSKEY_FLAGS_KSK)
                {
                    ++ksk_count;
                }
                else if(flags == DNSKEY_FLAGS_ZSK)
                {
                    ++zsk_count;
                }
                else
                {
                    // the key is of no use
                }

                dnskey_release(key);
            }
            else
            {
                // only complain if KSKs RRSIGs are not meant to be pushed

                if( !( (flags == DNSKEY_FLAGS_KSK) && zdb_zone_get_rrsig_push_allowed(zone) ) )
                {
                    log_warn("database: update: unable to load the private key 'K%{dnsname}+%03d+%05hd': %r", zone->origin, algorithm, tag, return_code);
                }
            }

            dnskey_rrset = dnskey_rrset->next;
        }
        while(dnskey_rrset != NULL);

        return_code = new_count;

        if(zsk_count == 0)
        {
            log_err("database: update: unable to load any of the ZSK private keys of zone %{dnsname}", zone->origin);
            return_code = DNSSEC_ERROR_RRSIG_NOUSABLEKEYS;
        }

        if(ksk_count == 0)
        {
            if(!zdb_zone_get_rrsig_push_allowed(zone))
            {
                log_warn("database: update: unable to load any of the KSK private keys of zone %{dnsname}", zone->origin);
            }
            else
            {
                log_debug("database: update: unable to load any of the KSK private keys of zone %{dnsname}", zone->origin);
            }
        }
    }
    else
    {
        log_err("database: update: there are no private keys in the zone %{dnsname}", zone->origin);

        return_code = DNSSEC_ERROR_RRSIG_NOZONEKEYS;
    }

    return return_code;
}

/**
 * Scans added DNSKEYs from the message, load their private keys.
 * Returns the number of keys added or an error code.
 */

ya_result
database_zone_ensure_private_keys_from_message(message_data *mesg)
{
    packet_unpack_reader_data pr;
    dnssec_key *key;
    ya_result ret = SUCCESS;
    s32 new_key_added = 0;

    bool all_keys_removed = FALSE;

    packet_reader_init_from_message(&pr, mesg);
    packet_reader_skip_section(&pr, 0);
    packet_reader_skip_section(&pr, 1);

    // scan for added DNSKEY

    for(u16 records = message_get_authority_count(mesg); records > 0; --records)
    {
        struct type_class_ttl_rdlen tctr;
        u8 fqdn[MAX_DOMAIN_LENGTH];

        if(FAIL(ret = packet_reader_read_fqdn(&pr ,fqdn, sizeof(fqdn))))
        {
            break;
        }
        if(FAIL(ret = packet_reader_read(&pr, &tctr, 10))) // exact
        {
            break;
        }
        tctr.rdlen = ntohs(tctr.rdlen);

        if(tctr.qclass == CLASS_IN)
        {
            // load it

            if(tctr.qtype == TYPE_DNSKEY)
            {
                const void *rdata = packet_reader_get_current_ptr_const(&pr, tctr.rdlen);
                if(rdata != NULL)
                {
                    if(ISOK(ret = dnssec_keystore_load_private_key_from_rdata(rdata, tctr.rdlen, fqdn, &key)))
                    {
                        log_info("database: update: update will be adding 'K%{dnsname}+%03d+%05hd': %r", fqdn, ntohs(dnskey_get_flags(key)), dnskey_get_tag_const(key), ret);

                        new_key_added += ret;

                        dnskey_release(key);
                    }
                }
                else
                {
                    // short read:
                    ret = UNEXPECTED_EOF;
                    break;
                }
            }
        }
        else if(tctr.qclass == CLASS_ANY)
        {
            if(tctr.qtype == TYPE_DNSKEY)
            {
                all_keys_removed = TRUE;
            }
        }

        if(FAIL(ret = packet_reader_skip(&pr, tctr.rdlen)))
        {
            break;
        }
    }

    // if at least one key was added, return the count, else if there is an error, return it, else return 0
    return (new_key_added > 0)?new_key_added:(all_keys_removed)?0x40000000:FAIL(ret)?ret:0;
}

#endif

ya_result
database_update(zdb *database, message_data *mesg)
{
    ya_result ret;

    u16 count;
    /*    u16    qdcount; */
    packet_unpack_reader_data pr;
    dnsname_vector name;
    zdb_zone *zone;
    
    u8 wire[MAX_DOMAIN_LENGTH + 10 + 65535];

    ret = FP_NOZONE_FOUND;
    
    zone_desc_s *zone_desc = zone_acquirebydnsname(message_get_canonised_fqdn(mesg));

    if(zone_desc != NULL)
    {
        bool need_to_notify_slaves = FALSE;
#if ZDB_HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT
        bool database_service_zone_dnssec_maintenance_start = FALSE;
#endif

        zone_lock(zone_desc, ZONE_LOCK_DYNUPDATE);
        switch(zone_desc->type)
        {
            case MASTER:
            {
#if ZDB_HAS_MASTER_SUPPORT
                message_set_answer(mesg);

                /*
                 * Unpack the query
                 */
                packet_reader_init_from_message(&pr, mesg);

                /*    qdcount = message_get_query_count(mesg); */

                dnsname_to_dnsname_vector(message_get_canonised_fqdn(mesg), &name);

                zone = zdb_acquire_zone_read_double_lock(database, &name, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);

                if(zone != NULL && !zdb_zone_invalid(zone))
                {
                    /*
                     * If the zone is marked as:
                     * _ frozen
                     * _ updating
                     * _ signing
                     * _ dumping
                     * => don't do it
                     */
                    if(!zdb_zone_is_frozen(zone))
                    {
#if HAS_ACL_SUPPORT
                        if(ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_update)))
                        {
                            /* notauth */

                            zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
                            
                            zone_unlock(zone_desc, ZONE_LOCK_DYNUPDATE);
                            
                            zone_release(zone_desc);
                            
                            log_info("database: update: %{dnsname} not authorised", zone->origin);
                            
                            message_set_status(mesg, FP_ACCESS_REJECTED);
                            message_update_answer_status(mesg);
#if DNSCORE_HAS_TSIG_SUPPORT
                            if(message_has_tsig(mesg))  /* NOTE: the TSIG information is in mesg */
                            {
                                tsig_sign_answer(mesg);
                            }
#endif                      
                            return ACL_UPDATE_REJECTED;
                        }
#endif // HAS_ACL_SUPPORT
                        
                        /*
                         * If the zone is DNSSEC and we don't have all the keys or don't know how to use them : SERVFAIL
                         */
                        
                        ret = SUCCESS;
                        
#if ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT

                        ya_result message_dnskey_load_code = 0;
                        ya_result zone_dnskey_load_code = 0;
                        ya_result ks_dnskey_load_code = 0;

                        if(zdb_zone_is_maintained(zone) || zdb_zone_is_maintenance_paused(zone))
                        {
                            if(zone_maintains_dnssec(zone_desc))
                            {
                                // load all the private part of the keys in the zone

#if !MAINTAIN_ONLY_AT_DIFF_AND_REPLAY
                                bool needs_a_maintenance = FALSE;
#endif
                                // the early cull optimisation is integrated in all log_* calls,
                                // message_log doesn't automatically benefit from it
                                LOGGER_EARLY_CULL_PREFIX(MSG_DEBUG) message_log(MODULE_MSG_HANDLE, MSG_DEBUG, mesg);
#if 1 // new way
                                ptr_vector required_key_parameters;
                                ptr_vector deleted_key_parameters;

                                ptr_vector_init(&required_key_parameters);
                                ptr_vector_init(&deleted_key_parameters);

                                log_debug("database: update: %{dnsname}: looking for key(s) from the zone", zone->origin);

                                database_add_key_parameters_from_zone(zone, &required_key_parameters);
#if DEBUG
                                for(int i = 0; i <= ptr_vector_last_index(&required_key_parameters); ++i)
                                {
                                    dnssec_key_parameters_t *key_i = (dnssec_key_parameters_t*)ptr_vector_get(&required_key_parameters, i);
                                    log_info("database: update: %{dnsname}: <= K%{dnsname}+%03d+%05hd (%i)", zone->origin, key_i->fqdn, key_i->algorithm, key_i->tag, ntohs(key_i->flags));
                                }
#endif
                                log_debug("database: update: %{dnsname}: looking for key(s) updates from the update", zone->origin);

                                database_add_key_parameters_from_message(zone, mesg, &required_key_parameters, &deleted_key_parameters);
#if DEBUG
                                for(int i = 0; i <= ptr_vector_last_index(&required_key_parameters); ++i)
                                {
                                    dnssec_key_parameters_t *key_i = (dnssec_key_parameters_t*)ptr_vector_get(&required_key_parameters, i);
                                    log_info("database: update: %{dnsname}: => K%{dnsname}+%03d+%05hd (%i)", zone->origin, key_i->fqdn, key_i->algorithm, key_i->tag, ntohs(key_i->flags));
                                }

                                for(int i = 0; i <= ptr_vector_last_index(&deleted_key_parameters); ++i)
                                {
                                    dnssec_key_parameters_t *key_i = (dnssec_key_parameters_t*)ptr_vector_get(&deleted_key_parameters, i);
                                    log_info("database: update: %{dnsname}: -> K%{dnsname}+%03d+%05hd (%i)", zone->origin, key_i->fqdn, key_i->algorithm, key_i->tag, ntohs(key_i->flags));
                                }
#endif
                                ret = database_ensure_private_keys_from_key_parameters_vector(zone, &required_key_parameters);

#if !MAINTAIN_ONLY_AT_DIFF_AND_REPLAY
                                if(!ptr_vector_isempty(&deleted_key_parameters) || (ret > 0))
                                {
                                    needs_a_maintenance = TRUE;
                                }
#endif
                                dnssec_key_parameters_vector_destroy(&deleted_key_parameters);
                                dnssec_key_parameters_vector_destroy(&required_key_parameters);
#else // old way
                                log_debug("database: update: %{dnsname}: looking for new key(s) from the update", zone->origin);

                                if((message_dnskey_load_code = database_zone_ensure_private_keys_from_message(mesg)) >/*=*/ 0)
                                {
                                    if(message_dnskey_load_code > 0)
                                    {
                                        log_info("database: update: %{dnsname}: new key(s) from the update", zone->origin);
                                    }

#if !MAINTAIN_ONLY_AT_DIFF_AND_REPLAY
                                    needs_a_maintenance = TRUE;
#endif
                                }
                                else
                                {
                                    log_debug("database: update: %{dnsname}: looking for new key(s) from the zone", zone->origin);

                                    if((zone_dnskey_load_code = database_zone_ensure_private_keys(zone)) > 0) //  is locked
                                    {
                                        log_info("database: update: %{dnsname}: new key(s) from the zone", zone->origin);
#if !MAINTAIN_ONLY_AT_DIFF_AND_REPLAY
                                        needs_a_maintenance = TRUE;
#endif
                                    }
                                    else if(zone_dnskey_load_code <= 0)
                                    {
                                        // scan directories to find new keys

                                        log_debug("database: update: %{dnsname}: new key(s) from keystore (which will not happen anymore)", zone->origin);

                                        if((ks_dnskey_load_code = dnssec_keystore_reload_domain(zone->origin)) > 0)
                                        {
                                            log_info("database: update: %{dnsname}: new key(s) from keystore", zone->origin);
#if !MAINTAIN_ONLY_AT_DIFF_AND_REPLAY
                                            needs_a_maintenance = TRUE;
#endif
                                        }
                                    }
                                }
#endif // old way

#if !MAINTAIN_ONLY_AT_DIFF_AND_REPLAY
                                if(needs_a_maintenance) // if something was loaded on the first try, and no error occurred
                                {
                                    log_info("database: update: %{dnsname}: updating events over key timings", zone->origin);

                                    if(zdb_zone_is_maintenance_paused(zone))
                                    {
                                        log_info("database: update: %{dnsname}: maintenance resumed", zone->origin);

                                        zdb_zone_set_maintenance_paused(zone, FALSE);
                                    }

                                    // SMART SIGNING
                                    zdb_zone_update_keystore_keys_from_zone(zone, ZDB_ZONE_MUTEX_DYNUPDATE);
                                    database_service_zone_dnskey_set_alarms(zone); // we are in a ZT_MASTER case
                                }
                                else
                                {
                                    if(ISOK(message_dnskey_load_code) && ISOK(zone_dnskey_load_code) && ISOK(ks_dnskey_load_code))
                                    {
                                        log_debug("database: update: %{dnsname}: no new private key loaded", zone->origin);
                                    }
                                    else
                                    {
                                        if(FAIL(message_dnskey_load_code))
                                        {
                                            log_warn("database: update: %{dnsname}: could not find private key file(s) for DNSKEY record(s) added by the update message: %r", zone->origin, message_dnskey_load_code);
                                        }
                                        if(FAIL(zone_dnskey_load_code))
                                        {
                                            log_warn("database: update: %{dnsname}: could not find private key file(s) for DNSKEY records(s) already in the zone: %r", zone->origin, zone_dnskey_load_code);
                                        }
                                        if(FAIL(ks_dnskey_load_code))
                                        {
                                            log_warn("database: update: %{dnsname}: could not find private key file(s) for keys in the keyring: %r", zone->origin, ks_dnskey_load_code);
                                        }

                                        // log_err("database: update: %{dnsname}: could not find any usable key", zone->origin);
                                    }
                                }
#endif // MAINTAIN_ONLY_AT_DIFF_AND_REPLAY
                            }
                            else
                            {
                                log_warn("database: update: cannot update %{dnsname} because DNSSEC maintenance has been disabled on the zone", zone->origin);

                                ret = RCODE_ERROR_CODE(RCODE_SERVFAIL);
                                
                                message_set_status(mesg, FP_RCODE_SERVFAIL);
                            }
                        }
#endif // ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT
                        if(ISOK(ret))
                        {
                            // The reader is positioned after the header : read the QR section

                            u16 query_count = message_get_query_count(mesg);

                            if(query_count > 0)
                            {
                                do
                                {
                                    if(FAIL(ret = packet_reader_read_zone_record(&pr, wire, sizeof(wire))))
                                    {
                                        break;
                                    }
                                }
                                while(--query_count > 0);
                            }
                            else
                            {
                                ret = SUCCESS;
                            }
                            
                            if(ISOK(ret))
                            {
                                // The zone is known with the previous record.
                                // Since I'm just testing the update per se, I'll ignore this.

                                count = message_get_prerequisite_count(mesg);
                                
                                // The reader is positioned after the QR section, read AN section

                                // from this point, the zone is single-locked

                                log_debug("database: update: %{dnsname}: processing %d prerequisites", zone_origin(zone_desc), count);

                                if(ISOK(ret = dynupdate_check_prerequisites(zone, &pr, count)))
                                {
                                    count = message_get_update_count(mesg);

#if ZDB_HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT
                                    /*
                                     * Dry run the update for the section
                                     * (so the DB will not be broken if the query is bogus)
                                     */
                                    u8 zone_maintain_mode_prev = zone_get_maintain_mode(zone);

                                    if((zone_maintain_mode_prev == ZDB_ZONE_MAINTAIN_NOSEC) && ((message_dnskey_load_code > 0) || (zone_dnskey_load_code > 0) || (ks_dnskey_load_code > 0)))
                                    {
                                        zone->sig_validity_regeneration_seconds = zone_desc->signature.sig_validity_regeneration * SIGNATURE_VALIDITY_REGENERATION_S;
                                        zone->sig_validity_interval_seconds = zone_desc->signature.sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S;
                                        zone->sig_validity_jitter_seconds = zone_desc->signature.sig_validity_jitter * SIGNATURE_VALIDITY_JITTER_S;
                                    }
#endif
                                    if(ISOK(ret = dynupdate_diff(zone, &pr, count, ZDB_ZONE_MUTEX_DYNUPDATE, DYNUPDATE_DIFF_RUN)))
                                    {
#if ZDB_HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT
                                        u8 zone_maintain_mode_now = zone_get_maintain_mode(zone);
#if DEBUG
                                        log_info("database: update: %{dnsname}: DEBUG: code = %08x, mmp=%i, mmn=%i, m=%i, p=%i",
                                                zone_origin(zone_desc), ret,
                                                (int)zone_maintain_mode_prev,
                                                (int)zone_maintain_mode_now,
                                                (int)zdb_zone_is_maintained(zone),
                                                (int)zdb_zone_is_maintenance_paused(zone));
#endif
                                        // if there was no maintenance and now there is, ...
                                        if((zone_maintain_mode_prev == 0) && (zone_maintain_mode_now != 0))
                                        {
					                        log_info("database: update: %{dnsname}: DEBUG: maintenance mode enabled", zone_origin(zone_desc));

					                        // if the zone was not maintained and the zone maintenance is not paused, then the maintenance needs to be activated

                                            if(!zdb_zone_is_maintained(zone) && !zdb_zone_is_maintenance_paused(zone))
                                            {
					                            log_info("database: update: %{dnsname}: DEBUG: not maintained and not maintenance paused => maintenance will start", zone_origin(zone_desc));

                                                log_debug("database: update: %{dnsname}: zone had no maintenance mode but is now %u and is not maintained: activating maintenance", zone_origin(zone_desc), zone_maintain_mode_now);

                                                zdb_zone_set_maintained(zone, TRUE);

                                                database_service_zone_dnssec_maintenance_start = TRUE;
                                            }
                                        }
                                        else if((ret & (DYNUPDATE_DIFF_RETURN_DNSKEY_UPDATED|DYNUPDATE_DIFF_RETURN_DNSKEY_ADDED)) == (DYNUPDATE_DIFF_RETURN_DNSKEY_UPDATED|DYNUPDATE_DIFF_RETURN_DNSKEY_ADDED))
                                        {
                                            zdb_zone_set_maintained(zone, TRUE);
                                            zdb_zone_set_maintenance_paused(zone, FALSE);

                                            database_service_zone_dnskey_set_alarms(zone); // we are in a ZT_MASTER case

					                        log_info("database: update: %{dnsname}: DEBUG: key updated and added => maintenance will start", zone_origin(zone_desc));
                                            database_service_zone_dnssec_maintenance_start = zdb_zone_is_maintained(zone);
                                        }

                                        else if((ret & (DYNUPDATE_DIFF_RETURN_DNSKEY_UPDATED|DYNUPDATE_DIFF_RETURN_DNSKEY_REMOVED)) == (DYNUPDATE_DIFF_RETURN_DNSKEY_UPDATED|DYNUPDATE_DIFF_RETURN_DNSKEY_REMOVED))
                                        {
                                            zdb_zone_set_maintained(zone, TRUE);
                                            zdb_zone_set_maintenance_paused(zone, FALSE);

                                            log_info("database: update: %{dnsname}: DEBUG: key updated and removed => maintenance will start", zone_origin(zone_desc));
                                            database_service_zone_dnssec_maintenance_start = zdb_zone_is_maintained(zone);
                                        }
#endif
                                        need_to_notify_slaves = TRUE;
                                    }
                                    else
                                    {
                                        if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                                        {
                                            // trigger a background store of the zone
                                            
                                            zdb_zone_info_background_store_zone(zone->origin);
                                        }

                                        message_set_error_status_from_result(mesg, ret);
                                    }
                                }
                                else
                                {
                                    /*
                                     * ZONE CANNOT BE UPDATED (prerequisites not met)
                                     */

                                    log_warn("database: update: %{dnsname}: prerequisites not met", message_get_canonised_fqdn(mesg));

                                    message_set_error_status_from_result(mesg, ret);
                                }

                                zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);

                                zdb_zone_release(zone);
                            }
                            else
                            {
                                message_set_status(mesg, FP_RCODE_FORMERR);
                                
                                zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
                            }
                        }
                        else
                        {
                            /*
                             * ZONE CANNOT BE UPDATED (missing private keys)                             
                             */
                            
                            message_set_status(mesg, FP_CANNOT_DYNUPDATE);
                            
                            zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
                        }
                    }
                    else
                    {
                        /*
                         * ZONE CANNOT BE UPDATED (frozen)
                         */

                        message_set_status(mesg, FP_CANNOT_DYNUPDATE);
                        
                        zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
                    }
                }
                else
                {
                    // zone is null or invalid
                    // if not null, it is double-locked for ZDB_ZONE_MUTEX_SIMPLEREADER and ZDB_ZONE_MUTEX_DYNUPDATE
                    
                    /**
                     * 2136:
                     *
                     * if any RR's NAME is not
                     * within the zone specified in the Zone Section, signal NOTZONE to the
                     * requestor.
                     *
                     */

                    if(zone == NULL)
                    {
                        message_set_status(mesg, FP_UPDATE_UNKNOWN_ZONE);
                    }
                    else
                    {
                        zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
                        message_set_status(mesg, FP_INVALID_ZONE);
                    }
                }
#else
                log_err("database: update: %{dnsname}: zone seen as a master but master mode is not supported in this build", zone_origin(zone_desc));
#endif
                break;
            }

            case SLAVE:
            {
                /*
                 * UPDATE FORWARDING
                 * 
                 * TCP -> TCP
                 * UDP -> TCP or UDP
                 * 
                 * So this implementation will always to TCP
                 * 
                 * Open a connection to the master.
                 * Create a duplicate of the message changing only the ID
                 * I CANNOT EDIT THE SAME MESSAGE BECAUSE OF THE POSSIBLE TSIG
                 * TSIG if needed.
                 * Send the message.
                 * Wait for the answer and retry if needed.
                 * Forward back the answer to the caller.
                 */
                
#if HAS_ACL_SUPPORT
                if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_update_forwarding)))
                {
                    random_ctx rndctx = thread_pool_get_random_ctx();
                    u16 id = (u16)random_next(rndctx);

                    message_data_with_buffer forward_query_buff;
                    message_data *forward_query = message_data_with_buffer_init(&forward_query_buff);
                    
                    message_make_query(forward_query, id, (const u8*)"", 0, 0);  /* just initialise a basic query */

                    memcpy(message_get_buffer(forward_query), message_get_buffer_const(mesg), message_get_size(mesg));
                    message_set_size(forward_query, message_get_size(mesg));
                    
                    // if no TSIG or succeeded in TSIGing the message ...
                    
#if DNSCORE_HAS_TSIG_SUPPORT
                    if((zone_desc->masters->tsig == NULL) || ISOK(ret = message_sign_query(forward_query, zone_desc->masters->tsig)))
                    {
#endif
                        // send a TCP query to the master
                        
                        if(ISOK(ret = message_query_tcp(forward_query, zone_desc->masters)))
                        {
                            memcpy(message_get_buffer(mesg), message_get_buffer_const(forward_query), message_get_size(forward_query));
                            message_set_size(mesg, message_get_size(forward_query));
                            message_set_status(mesg, message_get_status(forward_query));
                        }
                        else
                        {
                            message_set_status(mesg, FP_RCODE_SERVFAIL);
                            ret = RCODE_ERROR_CODE(RCODE_SERVFAIL);

                            message_make_error(mesg, ret);
                        }
#if DNSCORE_HAS_TSIG_SUPPORT
                    }
#endif
                }
                else
#endif
                {
                    message_set_status(mesg, FP_CANNOT_DYNUPDATE);
                    ret = FP_CANNOT_DYNUPDATE;
                    
                    message_make_error(mesg, ret);
                }
                
                break;
            }
            default:
            {
                message_set_status(mesg, FP_CANNOT_DYNUPDATE);
                ret = FP_CANNOT_DYNUPDATE;
                
                message_make_error(mesg, ret);
                
                break;
            }
        } // end switch

        zone_unlock(zone_desc, ZONE_LOCK_DYNUPDATE);

#if ZDB_HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
        if(database_service_zone_dnssec_maintenance_start)
        {
	    log_info("database: update: %{dnsname}: DEBUG: maintenance starting", zone_origin(zone_desc));
            database_service_zone_dnssec_maintenance(zone_desc);
        }
#endif
        
        if(need_to_notify_slaves)
        {
            notify_slaves(zone_origin(zone_desc));
        }
        
        zone_release(zone_desc);
    }
    else
    {
        /* zone is not even known by the configuration  */

        message_set_status(mesg, FP_UPDATE_UNKNOWN_ZONE);
    }

    message_set_rcode(mesg, message_get_status(mesg));
    
#if DNSCORE_HAS_TSIG_SUPPORT
    if(message_has_tsig(mesg))
    {
        log_debug("database: update: %{dnsname}: signing reply", message_get_canonised_fqdn(mesg));
        
        tsig_sign_answer(mesg);
    }
#endif

    return (finger_print)ret;
}

#endif

/** @brief Close the database
 *
 *  @param[in] database
 *
 *  @retval OK
 *  @retval NOK
 */

ya_result
database_shutdown(zdb *database)
{
    database_service_stop();
    
    if(database != NULL)
    {
        zdb_destroy(database);
        free(database);
    }
    
    database_finalize();
    g_config->database = NULL;
    
    return OK;
}

/**
 * 
 * @param zone_desc
 * @return 
 */

static ya_result
database_zone_refresh_next_master(zone_desc_s *zone_desc)
{
    if(zone_desc->masters != NULL && zone_desc->masters->next != NULL)
    {
        ya_result ret = 2;
        zone_lock(zone_desc, ZONE_LOCK_SERVICE);
        host_address *head = zone_desc->masters;
        host_address *move_to_end = head;
        host_address *node = head->next;
        while(node->next != NULL)
        {
            ++ret;
            node = node->next;
        }
        node->next = move_to_end;
        move_to_end->next = NULL;
        zone_desc->masters = head;
        zone_unlock(zone_desc, ZONE_LOCK_SERVICE);
        return ret;
    }
    else
    {
        return 1;
    }
}

static ya_result
database_zone_refresh_alarm(void *args, bool cancel)
{
    database_zone_refresh_alarm_args *sszra = (database_zone_refresh_alarm_args*)args;
    
    if(cancel)
    {        
        free((char*)sszra->origin);
#if DEBUG
        memset(sszra, 0xff, sizeof(database_zone_refresh_alarm_args));
#endif
        free(sszra);
        return SUCCESS;
    }
    
    const u8 *origin = sszra->origin;
    zdb *db = g_config->database;
    zdb_zone *zone;
    ya_result return_value;
    u32 now = 0;
    u32 next_alarm_epoch = 0;
    soa_rdata soa;

    log_info("database: refresh: %{dnsname}", origin);

    zone_desc_s *zone_desc = zone_acquirebydnsname(origin);

    if(zone_desc == NULL)
    {
        log_err("database: refresh: %{dnsname}: zone not found", origin);
        free((char*)sszra->origin);
        free(sszra);
        
        return ZONE_NOT_DEFINED;
    }
    
    zone = zdb_acquire_zone_read_from_fqdn(db, zone_origin(zone_desc));
    
    if(zone != NULL)
    {
        /**
         * check if the zone is locked. postpone if it is
         */

        if(zdb_zone_trylock(zone, ZDB_ZONE_MUTEX_REFRESH))
        {
            if(FAIL(return_value = zdb_zone_getsoa(zone, &soa))) // zone is locked
            {
                zdb_zone_release(zone);
                
                /*
                 * No SOA ? It's critical
                 */

                free(sszra);

                log_quit("database: refresh: %{dnsname}: get SOA: %r", origin, return_value);
                
                return return_value;
            }
            
            now = time(NULL);
            
            // defines 3 epoch printers (to be used with %w)
            u32 rf = zone_desc->refresh.refreshed_time;
            u32 rt = zone_desc->refresh.retried_time;
            u32 un = zone_desc->refresh.zone_update_next_time;
            
            log_debug("database: refresh: %{dnsname}: refreshed=%T retried=%T next=%T refresh=%i retry=%i expire=%i",
                    origin,
                    rf,
                    rt,
                    un,
                    soa.refresh,
                    soa.retry,
                    soa.expire
                    );
            
            // if the last time refreshed is at or after the last time we retried

            if(zone_desc->refresh.refreshed_time >= zone_desc->refresh.retried_time)
            {
                // then we are not retrying ...
                
                // if now is after the last refreshed time + the refresh time
                
                if(now >= zone_desc->refresh.refreshed_time + soa.refresh)
                {
                     // then do a refresh

                    log_info("database: refresh: %{dnsname}: refresh", origin);

                    zone_desc->refresh.retried_time = zone_desc->refresh.refreshed_time + 1;

                    // next time we will check for the refresh status will be now + retry ...
                    next_alarm_epoch = now + soa.retry;
                    
                    database_zone_ixfr_query(zone_origin(zone_desc));
                }
                else
                {
                    // next time we will check for the refresh status will be now + refresh ...
                    
                    log_info("database: refresh: %{dnsname}: refresh in %d seconds", origin, zone_desc->refresh.refreshed_time + soa.refresh - now);
                    
                    next_alarm_epoch = zone_desc->refresh.refreshed_time + soa.refresh;
                }
            }
            else
            {
                // else we are retrying ...
                
                if(now < zone_desc->refresh.refreshed_time + soa.expire)                {
                    // then we have not expired yet ...
                    
                    // next time we will check for the refresh status will be now + retry ...
                    next_alarm_epoch = now + soa.retry;
                    
                    if(now >= zone_desc->refresh.retried_time + soa.retry)
                    {
                        // then do a retry ...

                        log_info("database: refresh: %{dnsname}: retry", origin);

                        database_zone_ixfr_query(zone_origin(zone_desc));
                    }
                    else
                    {
                        log_debug("database: refresh: %{dnsname}: it's not time to retry yet", origin);
                    }
                }
                else
                {
                    // else the zone is not authoritative anymore

                    log_warn("database: refresh: %{dnsname}: zone has expired", origin);
                    
                    // if it's a multi-master setup, go to the next one in the list
                    // else mark the zone as being invalid
                    
                    if(database_zone_refresh_next_master(zone_desc) > 1)
                    {
                        next_alarm_epoch = time(NULL);
                        log_warn("database: refresh: %{dnsname}: master has changed to %{hostaddr}", origin, zone_desc->masters);

                        database_zone_refresh_maintenance(db, origin, next_alarm_epoch);
                    }
                    else
                    {
                        zdb_zone_set_invalid(zone);
                    }
                }
            }

            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_REFRESH);
        }
        else
        {
            log_info("database: refresh: %{dnsname}: zone has already been locked, will retry layer", origin);
            next_alarm_epoch = time(NULL) + 2;
        }
        
        zdb_zone_release(zone);
    }
    else
    {
        log_err("database: refresh: %{dnsname}: zone is not mounted", origin);
    }

    if(next_alarm_epoch != 0)
    {
        /*
         * The alarm rang but nothing has been done
         */
         
        log_debug("database: refresh: %{dnsname}: re-arming the alarm for %T", origin, next_alarm_epoch);

        database_zone_refresh_maintenance(db, origin, next_alarm_epoch);
    }
    else
    {
        log_debug("database: refresh: %{dnsname}: alarm will not be re-armed", origin);
    }

    free((char*)sszra->origin);
    
#if DEBUG
    memset(sszra, 0xff, sizeof(database_zone_refresh_alarm_args));
#endif
    
    free(sszra);
    
    zone_release(zone_desc);

    return SUCCESS;
}

ya_result
database_zone_refresh_maintenance_wih_zone(zdb_zone* zone, u32 next_alarm_epoch)
{
    if((zone != NULL) && zdb_zone_valid(zone))
    {
        /*
         * Get the SOA from the zone
         */

        /*
         * Check the last refresh time
         * If we need to refresh, then do it
         * If we failed, check when the next time to do it is
         * If we failed too much, check if we still are authoritative
         */

        zdb_zone_lock(zone, ZDB_ZONE_MUTEX_REFRESH); /* here ! */
        u32 now = time(NULL);

        ya_result return_value;
        soa_rdata soa;

        if(next_alarm_epoch == 0)
        {
            if(FAIL(return_value = zdb_zone_getsoa(zone, &soa))) // zone is locked
            {
                /*
                 * No SOA ? It's critical
                 */

                zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_REFRESH); /* here ! */

                log_err("database_zone_refresh_maintenance: get soa: %r", return_value);
                exit(EXIT_FAILURE);
            }
            
            next_alarm_epoch = now + soa.refresh;
        }

        database_zone_refresh_alarm_args *sszra;

        MALLOC_OBJECT_OR_DIE(sszra, database_zone_refresh_alarm_args, DBREFALP_TAG);

        sszra->origin = dnsname_dup(zone->origin);

        alarm_event_node *event = alarm_event_new(
                        next_alarm_epoch,
                        ALARM_KEY_ZONE_REFRESH,
                        database_zone_refresh_alarm,
                        sszra,
                        ALARM_DUP_REMOVE_LATEST,
                        "database-zone-refresh-alarm");
        
        alarm_set(zone->alarm_handle, event);

        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_REFRESH);
    }
    else
    {
        /*
         * The zone has not been loaded (yet)
         */
        
        if(zone != NULL)
        {
            log_debug("database_zone_refresh_maintenance: called on an invalid zone: %{dnsname}", zone->origin);
        }
        else
        {
            log_debug("database_zone_refresh_maintenance: called on a NULL zone");
        }
    }
    
    return SUCCESS;
}

ya_result
database_zone_refresh_maintenance(zdb *database, const u8 *origin, u32 next_alarm_epoch)
{
    ya_result ret = SUCCESS; // no zone, no issue doing maintenance
    
    log_debug("database: refresh %{dnsname}: refresh maintenance for zone at %T", origin, next_alarm_epoch);

    zdb_zone *zone = zdb_acquire_zone_read_from_fqdn(database, origin);
    if(zone != NULL)
    {
        ret = database_zone_refresh_maintenance_wih_zone(zone, next_alarm_epoch);
        zdb_zone_release(zone);
    }
    
    return ret;
}

ya_result
database_store_zone_to_disk(zone_desc_s *zone_desc)
{
    database_zone_store(zone_origin(zone_desc));
    return SUCCESS;
}

ya_result
database_store_all_zones_to_disk()
{
    /*
     * for all zones
     * put them in an array
     * while the array is not empty
     *     for every zone in the array
     *         try to freeze zone (lock)
     *         if it worked, wait that it is frozen, then unfreeze it and remove it from the array
     * 
     */
    
    ya_result batch_return_value = 0;
    
    if(g_config->database == NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    zone_set_lock(&database_zone_desc); // unlock checked
    
    ptr_set_iterator iter;
    ptr_set_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_iterator_next_node(&iter);
        
        zone_desc_s *zone_desc = (zone_desc_s*)zone_node->value;
        
        if(zone_is_obsolete(zone_desc))
        {
            continue;
        }
                        
        database_store_zone_to_disk(zone_desc);
    }
    
    zone_set_unlock(&database_zone_desc);
    
    return batch_return_value;
}

bool
database_are_all_zones_stored_to_disk()
{
    bool can_unload;  
    
    can_unload = TRUE;
    
    zone_set_lock(&database_zone_desc); // unlock checked
    
    ptr_set_iterator iter;
    ptr_set_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_iterator_next_node(&iter);

        zone_desc_s *zone_desc = (zone_desc_s*)zone_node->value;

        if(zone_is_obsolete(zone_desc))
        {
            continue;
        }
        
        if(zone_issavingfile(zone_desc))
        {
            can_unload = FALSE;
            break;
        }
    }
    
    zone_set_unlock(&database_zone_desc);
    
    return can_unload;
}

void
database_wait_all_zones_stored_to_disk()
{
    while(!database_are_all_zones_stored_to_disk())
    {        
        log_info("database: still busy writing zone files: shutdown postponed");
        sleep(1);
    }
}

void
database_disable_all_zone_store_to_disk()
{
    zone_set_lock(&database_zone_desc); // unlock checked
    
    ptr_set_iterator iter;
    ptr_set_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_iterator_next_node(&iter);
        
        zone_desc_s *zone_desc = (zone_desc_s*)zone_node->value;
        
        if(zone_is_obsolete(zone_desc))
        {
            continue;
        }
        
        zone_setsavingfile(zone_desc, FALSE);
    }
    
    zone_set_unlock(&database_zone_desc);
}

/** @} */
