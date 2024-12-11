/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 * @defgroup server
 * @ingroup yadifad
 * @brief database functions
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
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/

#include "server_config.h"

#include <dnscore/dns_packet_reader.h>

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

#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_arc.h>
#include <dnsdb/zdb_icmtl.h>
#if HAS_DYNUPDATE_SUPPORT
#include <dnsdb/dynupdate.h>
#endif
#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb_zone_load.h>

#include <dnsdb/xfr_copy.h>
#include <dnsdb/zdb_zone_path_provider.h>
#include <dnsdb/dnssec_keystore.h>

#include <dnscore/zone_reader_text.h>
#include <dnscore/zone_reader_axfr.h>
#include <dnsdb/zdb_zone_maintenance.h>
#include <dnsdb/dynupdate_message.h>

#include "server.h"
#include "database.h"
#include "database_service.h"
#if DNSCORE_HAS_RRSIG_MANAGEMENT_SUPPORT && DNSCORE_HAS_DNSSEC_SUPPORT
#include "database_service_zone_resignature.h"
#endif

#include "server_error.h"
#include "config_error.h"

#include "notify.h"

#include "zone.h"
#include "zone_desc.h"

#if HAS_RRL_SUPPORT
#include "rrl.h"
#endif

#include "dnsdb/dynupdate_diff.h"

#ifndef HAS_DYNUPDATE_DIFF_ENABLED
#error "HAS_DYNUPDATE_DIFF_ENABLED not defined"
#endif

#define DBSCHEDP_TAG              0x5044454843534244
#define DBREFALP_TAG              0x504c414645524244

#define DNSSEC_KEY_PARAMETERS_TAG 0x4d5059454b534e44

#define MODULE_MSG_HANDLE         g_server_logger

typedef struct database_zone_refresh_alarm_args database_zone_refresh_alarm_args;

struct database_zone_refresh_alarm_args
{
    const uint8_t *origin;
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

static uint32_t database_zone_path_provider_name_hash(const uint8_t *p)
{
    uint32_t h = 0;
    uint32_t c;
    uint8_t  s = 0;
    do
    {
        c = toupper(*p++);
        c &= 0x3f;
        h += c << (s & 15);
        h += 97;
        s += 13;
    } while(c != 0);

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

static ya_result database_zone_path_provider_get_hashed_name(char *data_path, uint32_t data_path_size, const char *base_data_path, const uint8_t *origin)
{
    uint32_t h = database_zone_path_provider_name_hash(origin);

    return snformat(data_path, data_path_size, "%s/%02x/%02x", base_data_path, h & 0xff, (h >> 8) & 0xff);
}

static ya_result database_zone_path_provider(const uint8_t *domain_fqdn, char *path_buffer, uint32_t path_buffer_size, uint32_t flags)
{
    ya_result ret = ZDB_ERROR_ZONE_NOT_IN_DATABASE;

#if DEBUG
    char    *original_path_buffer = path_buffer;
    uint32_t original_flags = flags;
    original_path_buffer[0] = '\0';
#endif
    char *suffix = "";
    if((flags & ZDB_ZONE_PATH_PROVIDER_RNDSUFFIX) != 0)
    {
        flags &= ~ZDB_ZONE_PATH_PROVIDER_RNDSUFFIX;
        suffix = ".part";
    }

    zone_desc_t *zone_desc = zone_acquirebydnsname(domain_fqdn);
    if(zone_desc != NULL)
    {
        if((zone_desc->file_name == NULL) || (g_config->data_path == NULL))
        {
            zone_release(zone_desc);
            log_err("database: path provider: zone file name or data path not set");
            return INVALID_STATE_ERROR;
        }

        const char *base_data_path = (!filepath_is_absolute(zone_desc->file_name)) ? g_config->data_path : "";

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
                        // flags &= ~ZDB_ZONE_PATH_PROVIDER_MKDIR;
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
                        // flags &= ~ZDB_ZONE_PATH_PROVIDER_MKDIR;
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
                            // flags &= ~ZDB_ZONE_PATH_PROVIDER_MKDIR;
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
                        // flags &= ~ZDB_ZONE_PATH_PROVIDER_MKDIR;
                    }

                    int32_t path_size = ret;

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
                    if(!filepath_is_absolute(zone_desc->keys_path))
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

static ya_result database_info_provider(const uint8_t *origin, zdb_zone_info_provider_data *data, uint32_t flags)
{
    ya_result ret = ZONE_NOT_DEFINED;
    switch(flags)
    {
        case ZDB_ZONE_INFO_PROVIDER_STORED_SERIAL:
        {
            // get the zone desc and check

            zone_desc_t *zone_desc = zone_acquirebydnsname(origin);
            if(zone_desc != NULL)
            {
                data->_u32 = zone_desc->stored_serial;
                zone_release(zone_desc);
                ret = SUCCESS;
            }
            break;
        }
        case ZDB_ZONE_INFO_PROVIDER_JOURNAL_SIZE_MAX:
        {
            // get the zone desc and check

            zone_desc_t *zone_desc = zone_acquirebydnsname(origin);
            if(zone_desc != NULL)
            {
                yassert(zone_desc->journal_size_kb <= 8388608);
                uint64_t max_size = zone_desc->journal_size_kb;

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
                    zdb_zone_t *zone = zone_get_loaded_zone(zone_desc);
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

                if(max_size > U32_MAX) // current limitation
                {
                    max_size = U32_MAX;
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

            zone_desc_t *zone_desc = zone_acquirebydnsname(origin);
            if(zone_desc != NULL)
            {
                data->_u8 = (uint8_t)zone_desc->type;
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
            zone_desc_t *zone_desc = zone_acquirebydnsname(origin);
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
            zone_desc_t *zone_desc = zone_acquirebydnsname(origin);
            if(zone_desc != NULL)
            {
                bool saving = (zone_get_status(zone_desc) & (ZONE_STATUS_SAVETO_ZONE_FILE | ZONE_STATUS_SAVING_ZONE_FILE)) != 0;

                zone_release(zone_desc);
                ret = saving ? 1 : 0;
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

void database_init()
{
    zdb_init();
    dnscore_reset_timer();

    database_zone_path_next_provider = zdb_zone_path_get_provider();
    zdb_zone_path_set_provider(database_zone_path_provider);

    database_info_next_provider = zdb_zone_info_get_provider();
    zdb_zone_info_set_provider(database_info_provider);
}

void database_finalize()
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
ya_result database_clear_zones(zdb_t *database, zone_data_set *dset)
{
    dnsname_vector_t fqdn_vector;

    zone_set_lock(dset); // unlock checked

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&dset->set, &iter);

    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *zone_node = ptr_treemap_iterator_next_node(&iter);
        zone_desc_t        *zone_desc = (zone_desc_t *)zone_node->value;

        dnsname_to_dnsname_vector(zone_origin(zone_desc), &fqdn_vector);

        zdb_zone_t *myzone = zdb_remove_zone(database, &fqdn_vector);

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

ya_result database_startup(zdb_t **database)
{
    ya_result return_code;
    zdb_t    *db;

    /*    ------------------------------------------------------------    */

    if(g_config->data_path == NULL)
    {
        return CONFIG_ZONE_ERR;
    }

    *database = NULL;

    database_init(); /* Inits the db, starts the threads of the pool, resets the timer */

    MALLOC_OBJECT_OR_DIE(db, zdb_t, ZDBCLASS_TAG);
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

struct dnskey_parameters_s
{
    const uint8_t *fqdn;
    uint16_t       tag;
    uint16_t       flags;
    uint8_t        algorithm;
};

typedef struct dnskey_parameters_s dnskey_parameters_t;

/**
 * Adds key parameters from keys in the zone to a vector
 */

void database_add_key_parameters_from_zone(zdb_zone_t *zone, ptr_vector_t *keys)
{
    zdb_resource_record_set_const_t *dnskey_rrset = zdb_zone_get_dnskey_rrset(zone); // zone is locked

    if(dnskey_rrset != NULL)
    {
        zdb_resource_record_set_const_iterator iter;
        zdb_resource_record_set_const_iterator_init(dnskey_rrset, &iter);
        while(zdb_resource_record_set_const_iterator_has_next(&iter))
        {
            const zdb_resource_record_data_t *dnskey_record = zdb_resource_record_set_const_iterator_next(&iter);

            dnskey_parameters_t              *parameters;
            ZALLOC_OBJECT_OR_DIE(parameters, dnskey_parameters_t, DNSSEC_KEY_PARAMETERS_TAG);
            parameters->fqdn = zone->origin;

            parameters->tag = DNSKEY_TAG(dnskey_record);
            parameters->flags = DNSKEY_FLAGS(dnskey_record);
            parameters->algorithm = DNSKEY_ALGORITHM(dnskey_record);

            ptr_vector_append(keys, parameters);
        }
    }
}

/**
 * Adds key parameters from keys added by the message to a vector.
 * Adds key parameters from keys removed by the message to a vector, removes said keys from the "added" vector.
 */

ya_result database_add_key_parameters_from_message(zdb_zone_t *zone, dns_message_t *mesg, ptr_vector_t *keys, ptr_vector_t *removed_keys)
{
    dns_packet_reader_t pr;
    ya_result           ret = SUCCESS;

    dns_packet_reader_init_from_message(&pr, mesg);

    if(FAIL(dns_packet_reader_skip_section(&pr, 0)))
    {
        return MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    if(FAIL(dns_packet_reader_skip_section(&pr, 1)))
    {
        return MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    // scan for added DNSKEY

    for(uint_fast16_t records = dns_message_get_authority_count(mesg); records > 0; --records)
    {
        struct type_class_ttl_rdlen_s tctr;
        uint8_t                       fqdn[DOMAIN_LENGTH_MAX];

        if(FAIL(ret = dns_packet_reader_read_fqdn(&pr, fqdn, sizeof(fqdn))))
        {
            break;
        }
        if(FAIL(ret = dns_packet_reader_read(&pr, &tctr, 10))) // exact
        {
            break;
        }
        tctr.rdlen = ntohs(tctr.rdlen);

        if(tctr.rclass == CLASS_IN)
        {
            // load it

            if(tctr.rtype == TYPE_DNSKEY)
            {
                const void *rdata = dns_packet_reader_get_current_ptr_const(&pr, tctr.rdlen);
                if(rdata != NULL)
                {
                    dnskey_parameters_t *parameters;
                    ZALLOC_OBJECT_OR_DIE(parameters, dnskey_parameters_t, DNSSEC_KEY_PARAMETERS_TAG);
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
        else if(tctr.rclass == CLASS_NONE)
        {
            if(tctr.rtype == TYPE_DNSKEY)
            {
                const void *rdata = dns_packet_reader_get_current_ptr_const(&pr, tctr.rdlen);
                if(rdata != NULL)
                {
                    for(int_fast32_t i = 0; i <= ptr_vector_last_index(keys); ++i)
                    {
                        dnskey_parameters_t parameters;
                        parameters.fqdn = zone->origin; // useless
                        parameters.tag = dnskey_get_tag_from_rdata(rdata, tctr.rdlen);
                        parameters.flags = dnskey_get_flags_from_rdata(rdata);
                        parameters.algorithm = dnskey_get_algorithm_from_rdata(rdata);
                        dnskey_parameters_t *key_i = (dnskey_parameters_t *)ptr_vector_get(keys, i);
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
        else if(tctr.rclass == CLASS_ANY)
        {
            if(tctr.rtype == TYPE_DNSKEY)
            {
                ptr_vector_append_vector(keys, removed_keys);
                ptr_vector_clear(keys);
            }
        }

        if(FAIL(ret = dns_packet_reader_skip(&pr, tctr.rdlen)))
        {
            break;
        }
    }

    return ret;
}

/**
 * Loads the private keys (and public keys, of course) whose parameters are listed in the vector.
 */

ya_result database_ensure_private_keys_from_key_parameters_vector(zdb_zone_t *zone, ptr_vector_t *keys)
{
    ya_result ret;

    int       ksk_count = 0;
    int       zsk_count = 0;
    int       new_count = 0;

    for(int_fast32_t i = 0; i <= ptr_vector_last_index(keys); ++i)
    {
        dnskey_parameters_t *key_i = (dnskey_parameters_t *)ptr_vector_get(keys, i);
        dnskey_t            *key = NULL;

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

            if(!((key_i->flags == DNSKEY_FLAGS_KSK) && zdb_zone_get_rrsig_push_allowed(zone)))
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

void dnskey_parameters_vector_destroy(ptr_vector_t *keys)
{
    for(int_fast32_t i = 0; i <= ptr_vector_last_index(keys); ++i)
    {
        dnskey_parameters_t *key_i = (dnskey_parameters_t *)ptr_vector_get(keys, i);
        ZFREE_OBJECT(key_i);
    }
    ptr_vector_finalise(keys);
}

/**
 * Loads private keys for the zone.
 * Returns the number of keys loaded or an error code.
 */

ya_result database_zone_ensure_private_keys(zdb_zone_t *zone)
{
    ya_result return_code;

    /*
     * Fetch all private keys
     */

    log_debug("database: update: checking DNSKEY availability");

    zdb_resource_record_set_const_t *dnskey_rrset = zdb_zone_get_dnskey_rrset(zone); // zone is locked

    int                              ksk_count = 0;
    int                              zsk_count = 0;
    int                              new_count = 0;

    if(dnskey_rrset != NULL)
    {
        zdb_resource_record_set_const_iterator iter;
        zdb_resource_record_set_const_iterator_init(dnskey_rrset, &iter);
        while(zdb_resource_record_set_const_iterator_has_next(&iter))
        {
            const zdb_resource_record_data_t *dnskey_record = zdb_resource_record_set_const_iterator_next(&iter);
            uint16_t                          flags = DNSKEY_FLAGS(dnskey_record);
            uint8_t                           algorithm = DNSKEY_ALGORITHM(dnskey_record);
            uint16_t                          tag = DNSKEY_TAG(dnskey_record); // note: expensive
            dnskey_t                         *key = NULL;

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

                if(!((flags == DNSKEY_FLAGS_KSK) && zdb_zone_get_rrsig_push_allowed(zone)))
                {
                    log_warn("database: update: unable to load the private key 'K%{dnsname}+%03d+%05hd': %r", zone->origin, algorithm, tag, return_code);
                }
            }
        }

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

ya_result database_zone_ensure_private_keys_from_message(dns_message_t *mesg)
{
    dns_packet_reader_t pr;
    dnskey_t           *key;
    ya_result           ret = SUCCESS;
    int32_t             new_key_added = 0;

    bool                all_keys_removed = false;

    dns_packet_reader_init_from_message(&pr, mesg);

    if(FAIL(dns_packet_reader_skip_section(&pr, 0)))
    {
        return MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    if(FAIL(dns_packet_reader_skip_section(&pr, 1)))
    {
        return MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    // scan for added DNSKEY

    for(uint_fast16_t records = dns_message_get_authority_count(mesg); records > 0; --records)
    {
        struct type_class_ttl_rdlen_s tctr;
        uint8_t                       fqdn[DOMAIN_LENGTH_MAX];

        if(FAIL(ret = dns_packet_reader_read_fqdn(&pr, fqdn, sizeof(fqdn))))
        {
            break;
        }
        if(FAIL(ret = dns_packet_reader_read(&pr, &tctr, 10))) // exact
        {
            break;
        }
        tctr.rdlen = ntohs(tctr.rdlen);

        if(tctr.rclass == CLASS_IN)
        {
            // load it

            if(tctr.rtype == TYPE_DNSKEY)
            {
                const void *rdata = dns_packet_reader_get_current_ptr_const(&pr, tctr.rdlen);
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
        else if(tctr.rclass == CLASS_ANY)
        {
            if(tctr.rtype == TYPE_DNSKEY)
            {
                all_keys_removed = true;
            }
        }

        if(FAIL(ret = dns_packet_reader_skip(&pr, tctr.rdlen)))
        {
            break;
        }
    }

    // if at least one key was added, return the count, else if there is an error, return it, else return 0
    return (new_key_added > 0) ? new_key_added : (all_keys_removed) ? 0x40000000 : FAIL(ret) ? ret : 0;
}

#endif // ZDB_HAS_DNSSEC_SUPPORT

// ZDB_ZONE_MUTEX_DYNUPDATE

#if DNSCORE_HAS_PRIMARY_SUPPORT

ya_result database_update(zdb_t *database, dns_message_t *mesg)
{
    ya_result ret;

    uint16_t  count;
    /*    uint16_t    qdcount; */
    dns_packet_reader_t pr;
    dnsname_vector_t    name;
    zdb_zone_t         *zone;

    uint8_t             wire[DOMAIN_LENGTH_MAX + 10 + 65535];

    ret = FP_NOZONE_FOUND;

    zone_desc_t *zone_desc = zone_acquirebydnsname(dns_message_get_canonised_fqdn(mesg));

    if(zone_desc != NULL)
    {
        bool need_to_notify_secondaries = false;
#if ZDB_HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT
        bool database_service_zone_dnssec_maintenance_start = false;
#endif

        zone_lock(zone_desc, ZONE_LOCK_DYNUPDATE);
        switch(zone_desc->type)
        {
            case PRIMARY:
            {
#if ZDB_HAS_PRIMARY_SUPPORT
                dns_message_set_answer(mesg);

                /*
                 * Unpack the query
                 */
                dns_packet_reader_init_from_message(&pr, mesg);

                /*    qdcount = message_get_query_count(mesg); */

                dnsname_to_dnsname_vector(dns_message_get_canonised_fqdn(mesg), &name);

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

                            dns_message_set_status(mesg, FP_ACCESS_REJECTED);
                            dns_message_update_answer_status(mesg);
#if DNSCORE_HAS_TSIG_SUPPORT
                            if(dns_message_has_tsig(mesg)) /* NOTE: the TSIG information is in mesg */
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
                                bool needs_a_maintenance = false;
#endif
                                // the early cull optimisation is integrated in all log_* calls,
                                // message_log doesn't automatically benefit from it
                                LOGGER_EARLY_CULL_PREFIX(MSG_DEBUG)
                                dns_message_log(MODULE_MSG_HANDLE, MSG_DEBUG, mesg);

                                ptr_vector_t required_key_parameters;
                                ptr_vector_t deleted_key_parameters;

                                ptr_vector_init(&required_key_parameters);
                                ptr_vector_init(&deleted_key_parameters);

                                log_debug("database: update: %{dnsname}: looking for key(s) from the zone", zone->origin);

                                database_add_key_parameters_from_zone(zone, &required_key_parameters);
#if DEBUG
                                for(int_fast32_t i = 0; i <= ptr_vector_last_index(&required_key_parameters); ++i)
                                {
                                    dnskey_parameters_t *key_i = (dnskey_parameters_t *)ptr_vector_get(&required_key_parameters, i);
                                    log_info("database: update: %{dnsname}: <= K%{dnsname}+%03d+%05hd (%i)", zone->origin, key_i->fqdn, key_i->algorithm, key_i->tag, ntohs(key_i->flags));
                                }
#endif
                                log_debug("database: update: %{dnsname}: looking for key(s) updates from the update", zone->origin);

                                ret = database_add_key_parameters_from_message(zone, mesg, &required_key_parameters, &deleted_key_parameters);

                                if(FAIL(ret))
                                {
                                    log_info("database: update: %{dnsname}: couldn't get key parameters from message", zone->origin);
                                }
#if DEBUG
                                for(int_fast32_t i = 0; i <= ptr_vector_last_index(&required_key_parameters); ++i)
                                {
                                    dnskey_parameters_t *key_i = (dnskey_parameters_t *)ptr_vector_get(&required_key_parameters, i);
                                    log_info("database: update: %{dnsname}: => K%{dnsname}+%03d+%05hd (%i)", zone->origin, key_i->fqdn, key_i->algorithm, key_i->tag, ntohs(key_i->flags));
                                }

                                for(int_fast32_t i = 0; i <= ptr_vector_last_index(&deleted_key_parameters); ++i)
                                {
                                    dnskey_parameters_t *key_i = (dnskey_parameters_t *)ptr_vector_get(&deleted_key_parameters, i);
                                    log_info("database: update: %{dnsname}: -> K%{dnsname}+%03d+%05hd (%i)", zone->origin, key_i->fqdn, key_i->algorithm, key_i->tag, ntohs(key_i->flags));
                                }
#endif
                                ret = database_ensure_private_keys_from_key_parameters_vector(zone, &required_key_parameters);

#if !MAINTAIN_ONLY_AT_DIFF_AND_REPLAY
                                if(!ptr_vector_isempty(&deleted_key_parameters) || (ret > 0))
                                {
                                    needs_a_maintenance = true;
                                }
#endif
                                dnskey_parameters_vector_destroy(&deleted_key_parameters);
                                dnskey_parameters_vector_destroy(&required_key_parameters);

#if !MAINTAIN_ONLY_AT_DIFF_AND_REPLAY
                                if(needs_a_maintenance) // if something was loaded on the first try, and no error
                                                        // occurred
                                {
                                    log_info("database: update: %{dnsname}: updating events over key timings", zone->origin);

                                    if(zdb_zone_is_maintenance_paused(zone))
                                    {
                                        log_info("database: update: %{dnsname}: maintenance resumed", zone->origin);

                                        zdb_zone_set_maintenance_paused(zone, false);
                                    }

                                    // SMART SIGNING
                                    zdb_zone_update_keystore_keys_from_zone(zone, ZDB_ZONE_MUTEX_DYNUPDATE);
                                    database_service_zone_dnskey_set_alarms(zone); // we are in a ZT_PRIMARY case
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
                                            log_warn(
                                                "database: update: %{dnsname}: could not find private key file(s) for "
                                                "DNSKEY record(s) added by the update message: %r",
                                                zone->origin,
                                                message_dnskey_load_code);
                                        }
                                        if(FAIL(zone_dnskey_load_code))
                                        {
                                            log_warn(
                                                "database: update: %{dnsname}: could not find private key file(s) for "
                                                "DNSKEY records(s) already in the zone: %r",
                                                zone->origin,
                                                zone_dnskey_load_code);
                                        }
                                        if(FAIL(ks_dnskey_load_code))
                                        {
                                            log_warn(
                                                "database: update: %{dnsname}: could not find private key file(s) for "
                                                "keys in the keyring: %r",
                                                zone->origin,
                                                ks_dnskey_load_code);
                                        }

                                        // log_err("database: update: %{dnsname}: could not find any usable key",
                                        // zone->origin);
                                    }
                                }
#endif // MAINTAIN_ONLY_AT_DIFF_AND_REPLAY
                            }
                            else
                            {
                                log_warn(
                                    "database: update: cannot update %{dnsname} because DNSSEC maintenance has been "
                                    "disabled on the zone",
                                    zone->origin);

                                ret = RCODE_ERROR_CODE(RCODE_SERVFAIL);

                                dns_message_set_status(mesg, FP_RCODE_SERVFAIL);
                            }
                        }
#endif // ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT
                        if(ISOK(ret))
                        {
                            // The reader is positioned after the header : read the QR section

                            uint16_t query_count = dns_message_get_query_count(mesg);

                            if(query_count > 0)
                            {
                                do
                                {
                                    if(FAIL(ret = dns_packet_reader_read_zone_record(&pr, wire, sizeof(wire))))
                                    {
                                        break;
                                    }
                                } while(--query_count > 0);
                            }
                            else
                            {
                                ret = SUCCESS;
                            }

                            if(ISOK(ret))
                            {
                                // The zone is known with the previous record.
                                // Since I'm just testing the update per se, I'll ignore this.

                                count = dns_message_get_prerequisite_count(mesg);

                                // The reader is positioned after the QR section, read AN section
                                // from this point, the zone is single-locked

                                log_debug("database: update: %{dnsname}: processing %d prerequisites", zone_origin(zone_desc), count);

                                if(ISOK(ret = dynupdate_check_prerequisites(zone, &pr, count)))
                                {
                                    count = dns_message_get_update_count(mesg);

#if ZDB_HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT
                                    /*
                                     * Dry run the update for the section
                                     * (so the DB will not be broken if the query is bogus)
                                     */
                                    uint8_t zone_maintain_mode_prev = zone_get_maintain_mode(zone);

                                    if((zone_maintain_mode_prev == ZDB_ZONE_MAINTAIN_NOSEC) && ((message_dnskey_load_code > 0) || (zone_dnskey_load_code > 0) || (ks_dnskey_load_code > 0)))
                                    {
                                        zone->sig_validity_regeneration_seconds = zone_desc->signature.sig_validity_regeneration * SIGNATURE_VALIDITY_REGENERATION_S;
                                        zone->sig_validity_interval_seconds = zone_desc->signature.sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S;
                                        zone->sig_validity_jitter_seconds = zone_desc->signature.sig_validity_jitter * SIGNATURE_VALIDITY_JITTER_S;
                                    }
#endif
                                    if(ISOK(ret = dynupdate_diff(zone, &pr, count, ZDB_ZONE_MUTEX_DYNUPDATE, DYNUPDATE_DIFF_RUN | DYNUPDATE_DIFF_EXTERNAL)))
                                    {
#if ZDB_HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT
                                        uint8_t zone_maintain_mode_now = zone_get_maintain_mode(zone);
#if DEBUG
                                        log_info(
                                            "database: update: %{dnsname}: DEBUG: code = %08x, mmp=%i, mmn=%i, m=%i, "
                                            "p=%i",
                                            zone_origin(zone_desc),
                                            ret,
                                            (int)zone_maintain_mode_prev,
                                            (int)zone_maintain_mode_now,
                                            (int)zdb_zone_is_maintained(zone),
                                            (int)zdb_zone_is_maintenance_paused(zone));
#endif
                                        // if there was no maintenance and now there is, ...
                                        if((zone_maintain_mode_prev == 0) && (zone_maintain_mode_now != 0))
                                        {
                                            log_info("database: update: %{dnsname}: DEBUG: maintenance mode enabled", zone_origin(zone_desc));

                                            // if the zone was not maintained and the zone maintenance is not paused,
                                            // then the maintenance needs to be activated

                                            if(!zdb_zone_is_maintained(zone) && !zdb_zone_is_maintenance_paused(zone))
                                            {
                                                log_info(
                                                    "database: update: %{dnsname}: DEBUG: not maintained and not "
                                                    "maintenance paused => maintenance will start",
                                                    zone_origin(zone_desc));

                                                log_debug(
                                                    "database: update: %{dnsname}: zone had no maintenance mode but is "
                                                    "now %u and is not maintained: activating maintenance",
                                                    zone_origin(zone_desc),
                                                    zone_maintain_mode_now);

                                                zdb_zone_set_maintained(zone, true);

                                                database_service_zone_dnssec_maintenance_start = true;
                                            }
                                        }
                                        else if((ret & (DYNUPDATE_DIFF_RETURN_DNSKEY_UPDATED | DYNUPDATE_DIFF_RETURN_DNSKEY_ADDED)) == (DYNUPDATE_DIFF_RETURN_DNSKEY_UPDATED | DYNUPDATE_DIFF_RETURN_DNSKEY_ADDED))
                                        {
                                            zdb_zone_set_maintained(zone, true);
                                            zdb_zone_set_maintenance_paused(zone, false);

                                            database_service_zone_dnskey_set_alarms(zone); // we are in a ZT_PRIMARY case

                                            log_info(
                                                "database: update: %{dnsname}: DEBUG: key updated and added => "
                                                "maintenance will start",
                                                zone_origin(zone_desc));
                                            database_service_zone_dnssec_maintenance_start = zdb_zone_is_maintained(zone);
                                        }

                                        else if((ret & (DYNUPDATE_DIFF_RETURN_DNSKEY_UPDATED | DYNUPDATE_DIFF_RETURN_DNSKEY_REMOVED)) == (DYNUPDATE_DIFF_RETURN_DNSKEY_UPDATED | DYNUPDATE_DIFF_RETURN_DNSKEY_REMOVED))
                                        {
                                            zdb_zone_set_maintained(zone, true);
                                            zdb_zone_set_maintenance_paused(zone, false);

                                            log_info(
                                                "database: update: %{dnsname}: DEBUG: key updated and removed => "
                                                "maintenance will start",
                                                zone_origin(zone_desc));
                                            database_service_zone_dnssec_maintenance_start = zdb_zone_is_maintained(zone);
                                        }
                                        else if(ret & DYNUPDATE_DIFF_RETURN_NSEC3PARAM)
                                        {
                                            zdb_zone_set_maintained(zone, true);
                                            zdb_zone_set_maintenance_paused(zone, false);
                                            database_service_zone_dnssec_maintenance_start = zdb_zone_is_maintained(zone);
                                        }
#endif
                                        need_to_notify_secondaries = true;
                                    }
                                    else
                                    {
                                        if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                                        {
                                            // trigger a background store of the zone

                                            zdb_zone_info_background_store_zone(zone->origin);
                                        }

                                        dns_message_set_error_status_from_result(mesg, ret);
                                    }
                                }
                                else
                                {
                                    /*
                                     * ZONE CANNOT BE UPDATED (prerequisites not met)
                                     */

                                    log_warn("database: update: %{dnsname}: prerequisites not met", dns_message_get_canonised_fqdn(mesg));

                                    dns_message_set_error_status_from_result(mesg, ret);
                                }

                                zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);

                                zdb_zone_release(zone);
                                zone = NULL;
                            }
                            else
                            {
                                dns_message_set_status(mesg, FP_RCODE_FORMERR);

                                zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
                            }
                        }
                        else
                        {
                            /*
                             * ZONE CANNOT BE UPDATED (missing private keys)
                             */

                            dns_message_set_status(mesg, FP_CANNOT_DYNUPDATE);

                            zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
                        }
                    }
                    else
                    {
                        /*
                         * ZONE CANNOT BE UPDATED (frozen)
                         */

                        dns_message_set_status(mesg, FP_CANNOT_DYNUPDATE);

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
                        dns_message_set_status(mesg, FP_UPDATE_UNKNOWN_ZONE);
                    }
                    else
                    {
                        zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
                        dns_message_set_status(mesg, FP_INVALID_ZONE);
                    }
                }
#else
                log_err(
                    "database: update: %{dnsname}: zone seen as a primary but primary mode is not supported in this "
                    "build",
                    zone_origin(zone_desc));
#endif
                break;
            }

            case SECONDARY:
            {
                /*
                 * UPDATE FORWARDING
                 *
                 * TCP -> TCP
                 * UDP -> TCP or UDP
                 *
                 * So this implementation will always to TCP
                 *
                 * Open a connection to the primary.
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
                    random_ctx_t              rndctx = thread_pool_get_random_ctx();
                    uint16_t                  id = (uint16_t)random_next(rndctx);

                    dns_message_with_buffer_t forward_query_buff;
                    dns_message_t            *forward_query = dns_message_data_with_buffer_init(&forward_query_buff);

                    dns_message_make_query(forward_query, id, (const uint8_t *)"", 0, 0); /* just initialise a basic query */

                    memcpy(dns_message_get_buffer(forward_query), dns_message_get_buffer_const(mesg), dns_message_get_size(mesg));
                    dns_message_set_size(forward_query, dns_message_get_size(mesg));

                    // if no TSIG or succeeded in TSIGing the message ...

#if DNSCORE_HAS_TSIG_SUPPORT
                    if((zone_desc->primaries->tsig == NULL) || ISOK(ret = dns_message_sign_query(forward_query, zone_desc->primaries->tsig)))
                    {
#endif
                        // send a TCP query to the primary

                        log_info("database: update: %{dnsname}: forwarding update to primary at %{hostaddr}", zone_origin(zone_desc), zone_desc->primaries);

                        if(ISOK(ret = dns_message_query_tcp(forward_query, zone_desc->primaries)))
                        {
                            memcpy(dns_message_get_buffer(mesg), dns_message_get_buffer_const(forward_query), dns_message_get_size(forward_query));
                            dns_message_set_size(mesg, dns_message_get_size(forward_query));
                            dns_message_set_status(mesg, dns_message_get_status(forward_query));

                            log_info("database: update: %{dnsname}: forwarded update to primary at %{hostaddr}", zone_origin(zone_desc), zone_desc->primaries);
                        }
                        else
                        {
                            log_warn("database: update: %{dnsname}: failed to forward update to primary at %{hostaddr}: %r", zone_origin(zone_desc), zone_desc->primaries, ret);

                            dns_message_set_status(mesg, FP_RCODE_SERVFAIL);
                            ret = RCODE_ERROR_CODE(RCODE_SERVFAIL);

                            dns_message_make_error(mesg, ret);
                        }
#if DNSCORE_HAS_TSIG_SUPPORT
                    }
#endif
                }
                else
#endif
                {
                    dns_message_set_status(mesg, FP_CANNOT_DYNUPDATE);
                    ret = FP_CANNOT_DYNUPDATE;
                    dns_message_make_error(mesg, ret);
                }

                break;
            }
            default:
            {
                dns_message_set_status(mesg, FP_CANNOT_DYNUPDATE);
                ret = FP_CANNOT_DYNUPDATE;
                dns_message_make_error(mesg, ret);
                break;
            }
        } // end switch

        zone_unlock(zone_desc, ZONE_LOCK_DYNUPDATE);

#if ZDB_HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_PRIMARY_SUPPORT
        if(database_service_zone_dnssec_maintenance_start)
        {
            log_info("database: update: %{dnsname}: DEBUG: maintenance starting", zone_origin(zone_desc));
            zone = zdb_acquire_zone_read_double_lock(database, &name, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);

            if(zone != NULL && !zdb_zone_invalid(zone))
            {
                uint32_t zone_status = zdb_zone_get_status(zone);
                if(zone_status & ZDB_ZONE_STATUS_GENERATE_CHAIN)
                {
                    // enable NSEC3 mode
                    if((zone_get_maintain_mode(zone) & ZDB_ZONE_MAINTAIN_NSEC3) != 0)
                    {
                        // uint8_t optout, uint16_t iterations, const uint8_t *salt, uint8_t salt_len, uint8_t status);
                        zdb_resource_record_set_t *nsec3paramqueued_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_NSEC3PARAMQUEUED);
                        database_apply_nsec3paramqueued(zone, nsec3paramqueued_rrset, ZDB_ZONE_MUTEX_DYNUPDATE);
                    }
                    else
                    {
                        nsec_zone_set_status(zone, ZDB_ZONE_MUTEX_DYNUPDATE, NSEC_ZONE_ENABLED | NSEC_ZONE_GENERATING);
                    }
                }
                zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
                zone = NULL;
            }

            database_service_zone_dnssec_maintenance(zone_desc);
        }
#endif

        if(need_to_notify_secondaries)
        {
            notify_secondaries(zone_origin(zone_desc));
        }

        zone_release(zone_desc);
    }
    else
    {
        /* zone is not even known by the configuration  */

        dns_message_set_status(mesg, FP_UPDATE_UNKNOWN_ZONE);
    }

    dns_message_set_rcode(mesg, dns_message_get_status(mesg));

#if DNSCORE_HAS_TSIG_SUPPORT
    if(dns_message_has_tsig(mesg))
    {
        log_debug("database: update: %{dnsname}: signing reply", dns_message_get_canonised_fqdn(mesg));
        tsig_sign_answer(mesg);
    }
#endif

    return (finger_print)ret;
}

#endif

#endif // HAS_DYNUPDATE_SUPPORT

#if DNSCORE_HAS_PRIMARY_SUPPORT
ya_result database_apply_nsec3paramqueued(zdb_zone_t *zone, zdb_resource_record_set_t *rrset, uint8_t lock_owner)
{
    ya_result ret = SUCCESS;

    if(rrset != NULL)
    {
        zdb_resource_record_data_t *rr = zdb_resource_record_set_record_get(rrset, 0);

        if(rr != NULL)
        {
            const uint8_t *rdata = zdb_resource_record_data_rdata_const(rr);
            uint32_t       rdata_size = zdb_resource_record_data_rdata_size(rr);

            uint8_t        algorithm = NSEC3PARAM_RDATA_ALGORITHM(rdata);
            uint16_t       iterations = NSEC3PARAM_RDATA_ITERATIONS(rdata);
            const uint8_t *salt = NSEC3PARAM_RDATA_SALT(rdata);
            uint8_t        salt_len = NSEC3PARAM_RDATA_SALT_LEN(rdata);
            uint8_t        optout = ((zone_get_maintain_mode(zone) & ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT) == ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT) ? 1 : 0;

            if(ISOK(ret = nsec3_zone_set_status(zone, lock_owner, algorithm, optout, iterations, salt, salt_len, NSEC3_ZONE_ENABLED | NSEC3_ZONE_GENERATING)))
            {
                /// @todo 20211202 edf -- delete the TYPE_NSEC3PARAMQUEUED record
                dynupdate_message   dmsg;
                dns_packet_reader_t reader;
                dynupdate_message_init(&dmsg, zone->origin, CLASS_IN);
                dynupdate_message_del_record(&dmsg, zone->origin, TYPE_NSEC3PARAMQUEUED, 0, rdata_size, rdata);
                dynupdate_message_set_reader(&dmsg, &reader);
                uint16_t count = dynupdate_message_get_count(&dmsg);
                dns_packet_reader_skip(&reader, DNS_HEADER_LENGTH); // checked below
                dns_packet_reader_skip_fqdn(&reader);               // checked below
                dns_packet_reader_skip(&reader, 4);                 // checked below
                ret = dynupdate_diff(zone, &reader, count, lock_owner, DYNUPDATE_DIFF_RUN);

                if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                {
                    // trigger a background store of the zone
                    zdb_zone_info_background_store_zone(zone->origin);
                }

                dynupdate_message_finalize(&dmsg);
            }
        }
    }

    return ret;
}
#endif

/** @brief Close the database
 *
 *  @param[in] database
 *
 *  @retval OK
 *  @retval NOK
 */

ya_result database_shutdown(zdb_t *database)
{
    if(database == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT || DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT || DNSCORE_HAS_ZALLOC_STATISTICS_SUPPORT || DNSCORE_HAS_MMAP_DEBUG_SUPPORT
    formatln("database_shutdown(%p) begin", database);
    debug_stat(DEBUG_STAT_TAGS | DEBUG_STAT_MMAP);
    zalloc_print_stats(&__termout__);
    flushout();
    flusherr();
#endif

    database_service_stop();

    if(database != NULL)
    {
        zdb_destroy(database);
        free(database);
    }

    database_finalize();
    g_config->database = NULL;

#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT || DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT || DNSCORE_HAS_ZALLOC_STATISTICS_SUPPORT || DNSCORE_HAS_MMAP_DEBUG_SUPPORT
    formatln("database_shutdown(%p) done", database);
    debug_stat(DEBUG_STAT_SIZES | DEBUG_STAT_TAGS | DEBUG_STAT_DUMP | DEBUG_STAT_WALK | DEBUG_STAT_MMAP);
    zalloc_print_stats(&__termout__);
    flushout();
    flusherr();
#endif

    return SUCCESS;
}

/**
 *
 * @param zone_desc
 * @return
 */

static ya_result database_zone_refresh_next_primary(zone_desc_t *zone_desc)
{
    if(zone_desc->primaries != NULL && zone_desc->primaries->next != NULL)
    {
        ya_result ret = 2;
        zone_lock(zone_desc, ZONE_LOCK_SERVICE);
        host_address_t *head = zone_desc->primaries;
        host_address_t *move_to_end = head;
        host_address_t *node = head->next;
        while(node->next != NULL)
        {
            ++ret;
            node = node->next;
        }
        node->next = move_to_end;
        move_to_end->next = NULL;
        zone_desc->primaries = head;
        zone_unlock(zone_desc, ZONE_LOCK_SERVICE);
        return ret;
    }
    else
    {
        return 1;
    }
}

static ya_result database_zone_refresh_alarm(void *args, bool cancel)
{
    database_zone_refresh_alarm_args *sszra = (database_zone_refresh_alarm_args *)args;

    if(cancel)
    {
        free((char *)sszra->origin);
#if DEBUG
        memset(sszra, 0xff, sizeof(database_zone_refresh_alarm_args));
#endif
        free(sszra);
        return SUCCESS;
    }

    const uint8_t  *origin = sszra->origin;
    zdb_t          *db = g_config->database;
    zdb_zone_t     *zone;
    ya_result       return_value;
    uint32_t        now = 0;
    uint32_t        next_alarm_epoch = 0;
    zdb_soa_rdata_t soa;

    log_debug("database: refresh: %{dnsname}", origin);

    zone_desc_t *zone_desc = zone_acquirebydnsname(origin);

    if(zone_desc == NULL)
    {
        log_err("database: refresh: %{dnsname}: zone not found", origin);
        free((char *)sszra->origin);
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
            uint32_t rf = zone_desc->refresh.refreshed_time;
            uint32_t rt = zone_desc->refresh.retried_time;
            uint32_t un = zone_desc->refresh.zone_update_next_time;

            log_debug("database: refresh: %{dnsname}: refreshed=%T retried=%T next=%T refresh=%i retry=%i expire=%i", origin, rf, rt, un, soa.refresh, soa.retry, soa.expire);

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

                if(now < zone_desc->refresh.refreshed_time + soa.expire)
                {
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

                    // if it's a multi-primary setup, go to the next one in the list
                    // else mark the zone as being invalid

                    if(database_zone_refresh_next_primary(zone_desc) > 1)
                    {
                        next_alarm_epoch = time(NULL);
                        log_warn("database: refresh: %{dnsname}: primary has changed to %{hostaddr}", origin, zone_desc->primaries);

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
            log_info("database: refresh: %{dnsname}: zone has already been locked, will retry later", origin);
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

    free((char *)sszra->origin);

#if DEBUG
    memset(sszra, 0xff, sizeof(database_zone_refresh_alarm_args));
#endif

    free(sszra);

    zone_release(zone_desc);

    return SUCCESS;
}

ya_result database_zone_refresh_maintenance_wih_zone(zdb_zone_t *zone, uint32_t next_alarm_epoch)
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
        uint32_t        now = time(NULL);

        ya_result       return_value;
        zdb_soa_rdata_t soa;

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

        alarm_event_node_t *event = alarm_event_new( // zone refresh
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

ya_result database_zone_refresh_maintenance(zdb_t *database, const uint8_t *origin, uint32_t next_alarm_epoch)
{
    ya_result ret = SUCCESS; // no zone, no issue doing maintenance

    log_debug("database: refresh %{dnsname}: refresh maintenance for zone at %T", origin, next_alarm_epoch);

    zdb_zone_t *zone = zdb_acquire_zone_read_from_fqdn(database, origin);
    if(zone != NULL)
    {
        ret = database_zone_refresh_maintenance_wih_zone(zone, next_alarm_epoch);
        zdb_zone_release(zone);
    }

    return ret;
}

ya_result database_store_zone_to_disk(zone_desc_t *zone_desc)
{
    database_zone_store(zone_origin(zone_desc));
    return SUCCESS;
}

ya_result database_store_all_zones_to_disk()
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

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *zone_node = ptr_treemap_iterator_next_node(&iter);

        zone_desc_t        *zone_desc = (zone_desc_t *)zone_node->value;

        if(zone_is_obsolete(zone_desc))
        {
            continue;
        }

        database_store_zone_to_disk(zone_desc);
    }

    zone_set_unlock(&database_zone_desc);

    return batch_return_value;
}

bool database_are_all_zones_stored_to_disk()
{
    bool can_unload;

    can_unload = true;

    zone_set_lock(&database_zone_desc); // unlock checked

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *zone_node = ptr_treemap_iterator_next_node(&iter);

        zone_desc_t        *zone_desc = (zone_desc_t *)zone_node->value;

        if(zone_is_obsolete(zone_desc))
        {
            continue;
        }

        if(zone_issavingfile(zone_desc))
        {
            can_unload = false;
            break;
        }
    }

    zone_set_unlock(&database_zone_desc);

    return can_unload;
}

void database_wait_all_zones_stored_to_disk()
{
    while(!database_are_all_zones_stored_to_disk())
    {
        log_info("database: still busy writing zone files: shutdown postponed");
        sleep(1);
    }
}

void database_disable_all_zone_store_to_disk()
{
    zone_set_lock(&database_zone_desc); // unlock checked

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *zone_node = ptr_treemap_iterator_next_node(&iter);

        zone_desc_t        *zone_desc = (zone_desc_t *)zone_node->value;

        if(zone_is_obsolete(zone_desc))
        {
            continue;
        }

        zone_setsavingfile(zone_desc, false);
    }

    zone_set_unlock(&database_zone_desc);
}

/** @} */
