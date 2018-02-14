/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2018, EURid vzw. All rights reserved.
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

#include <dnszone/dnszone.h>
#include <dnszone/zone_file_reader.h>
#include <dnszone/zone_axfr_reader.h>


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
    ya_result ret = ERROR;
    
#ifdef DEBUG
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
        switch(flags & ~ZDB_ZONE_PATH_PROVIDER_MKDIR)
        {
            case ZDB_ZONE_PATH_PROVIDER_ZONE_PATH:
            {
                if(ISOK(ret = snformat(path_buffer, path_buffer_size, "%s%s", g_config->data_path, zone_desc->file_name)))
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
                        flags &= ~ZDB_ZONE_PATH_PROVIDER_MKDIR;
                    }
                }
                break;
            }
            case ZDB_ZONE_PATH_PROVIDER_ZONE_FILE:
            {
                if(ISOK(ret = snformat(path_buffer, path_buffer_size, "%s%s%s", g_config->data_path, zone_desc->file_name, suffix)))
                {
                    if((flags & ZDB_ZONE_PATH_PROVIDER_MKDIR) != 0)
                    {
                        ya_result err = mkdir_ex(path_buffer, 0750, MKDIR_EX_PATH_TO_FILE);
                        if(FAIL(err) && (err != MAKE_ERRNO_ERROR(EEXIST)))
                        {
                            log_err("database: zone file mkdir: could not create '%s': %r", path_buffer, err);
                        }
                        flags &= ~ZDB_ZONE_PATH_PROVIDER_MKDIR;
                    }
                }
                
                break;
            }
            case ZDB_ZONE_PATH_PROVIDER_AXFR_PATH:
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
                        flags &= ~ZDB_ZONE_PATH_PROVIDER_MKDIR;
                    }
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
                        flags &= ~ZDB_ZONE_PATH_PROVIDER_MKDIR;
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
    
#ifdef DEBUG
    log_debug("path-provider: %{dnsname}: %02x: path='%s': %r", domain_fqdn, original_flags, original_path_buffer, ret);
#endif
    
    return ret;
}

static ya_result
database_info_provider(const u8 *origin, zdb_zone_info_provider_data *data, u32 flags)
{
    ya_result ret = ERROR;
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
            database_zone_save(origin);
            ret = SUCCESS;
            break;
        }
        case ZDB_ZONE_INFO_PROVIDER_STORE_NOW:
        {
            zone_desc_s *zone_desc = zone_acquirebydnsname(origin);
            if(zone_desc != NULL)
            {
                ret = database_service_zone_save_ex(zone_desc, 0, data->_u8, DATABASE_SERVICE_ZONE_SAVE_IGNORE_SHUTDOWN);
            }
            else
            {
                ret = ERROR;
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
                ret = ERROR;
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
    dnszone_init();
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
    
    zone_set_lock(dset);

    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&dset->set, &iter);

    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_avl_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s*)zone_node->value;

        dnsname_to_dnsname_vector(zone_desc->origin, &fqdn_vector);
        
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

    MALLOC_OR_DIE(zdb*, db, sizeof(zdb), ZDBCLASS_TAG);
    zdb_create(db);
    
    // add all the registered zones as invalid
    
    *database = db;
    
    database_service_create_invalid_zones();
    
#if HAS_DNSSEC_SUPPORT
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
ya_result
database_zone_ensure_private_keys(zone_desc_s *zone_desc, zdb_zone *zone)
{                     
    ya_result return_code;
    
    /*
     * Fetch all private keys
     */

    log_debug("database: update: checking DNSKEY availability");

    const zdb_packed_ttlrdata *dnskey_rrset = zdb_zone_get_dnskey_rrset(zone); // zone is locked

    int ksk_count = 0;
    int zsk_count = 0;

    if(dnskey_rrset != NULL)
    {
        do
        {
            u16 flags = DNSKEY_FLAGS(*dnskey_rrset);
            //u8  protocol = DNSKEY_PROTOCOL(*dnskey_rrset);
            u8  algorithm = DNSKEY_ALGORITHM(*dnskey_rrset);
            u16 tag = DNSKEY_TAG(*dnskey_rrset);                  // note: expensive
            dnssec_key *key = NULL;

            if(FAIL(return_code = dnssec_keystore_load_private_key_from_parameters(algorithm, tag, flags, zone->origin, &key)))
            {
                log_warn("database: update: unable to load the private key 'K%{dnsname}+%03d+%05d': %r", zone->origin, algorithm, tag, return_code);
            }

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

            dnskey_rrset = dnskey_rrset->next;
        }
        while(dnskey_rrset != NULL);

        return_code = zsk_count;

        if(zsk_count == 0)
        {
            log_err("database: update: unable to load any of the ZSK private keys of zone %{dnsname}", zone->origin);
            return_code = DNSSEC_ERROR_RRSIG_NOUSABLEKEYS;
        }

        if(ksk_count == 0)
        {
            log_warn("database: update: unable to load any of the KSK private keys of zone %{dnsname}", zone->origin);
        }
    }
    else
    {
        log_err("database: update: there are no private keys in the zone %{dnsname}", zone->origin);

        return_code = DNSSEC_ERROR_RRSIG_NOZONEKEYS;
    }

    return return_code;
}
#endif

finger_print
database_update(zdb *database, message_data *mesg)
{
    ya_result return_code;

    u16 count;
    /*    u16    qdcount; */
    packet_unpack_reader_data reader;
    dnsname_vector name;
    zdb_zone *zone;
    
    u8 wire[MAX_DOMAIN_LENGTH + 10 + 65535];

    return_code = FP_NOZONE_FOUND;
    
    mesg->send_length = mesg->received;

    zone_desc_s *zone_desc = zone_acquirebydnsname(mesg->qname);

    if(zone_desc != NULL)
    {
        bool need_to_notify_slaves = FALSE;
        
        zone_lock(zone_desc, ZONE_LOCK_DYNUPDATE);
        switch(zone_desc->type)
        {
            case ZT_MASTER:
            {
                /*    ------------------------------------------------------------    */
                
                MESSAGE_HIFLAGS(mesg->buffer) |= QR_BITS;

                /*
                 * Unpack the query
                 */
                packet_reader_init(&reader, mesg->buffer, mesg->received);
                reader.offset = DNS_HEADER_LENGTH;

                /*    qdcount = MESSAGE_QD(mesg->buffer); */

                dnsname_to_dnsname_vector(mesg->qname, &name);

                /// @todo 20141006 edf -- verify class mesg->qclass
                
                zone = zdb_acquire_zone_read_double_lock(database, &name, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);

                if(zone != NULL && !ZDB_ZONE_INVALID(zone))
                {
                    /*
                     * If the zone is marked as:
                     * _ frozen
                     * _ updating
                     * _ signing
                     * _ dumping
                     * => don't do it
                     */
                    if((zone->apex->flags & ZDB_RR_APEX_LABEL_FROZEN) == 0)
                    {
#if HAS_ACL_SUPPORT
                        if(ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_update)))
                        {
                            /* notauth */

                            zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
                            
                            zone_unlock(zone_desc, ZONE_LOCK_DYNUPDATE);
                            
                            zone_release(zone_desc);
                            
                            log_info("database: update: not authorised");
                            
                            mesg->status = FP_ACCESS_REJECTED;
                            
                            return (finger_print)ACL_UPDATE_REJECTED;
                        }
#endif
                        
                        /*
                         * If the zone is DNSSEC and we don't have all the keys or don't know how to use them : SERVFAIL
                         */
                        
                        return_code = SUCCESS;
                        
#if ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT
                        if(zdb_zone_is_maintained(zone))
                        {
                            if(zone_maintains_dnssec(zone_desc))
                            {
                                if(FAIL(return_code = database_zone_ensure_private_keys(zone_desc, zone))) //  is locked
                                {
                                    log_info("database: update: %{dnsname} loading keys from keystore", zone->origin);
                                    
                                    dnssec_keystore_reload_domain(zone->origin);
                                    zdb_zone_update_keystore_keys_from_zone(zone, ZDB_ZONE_MUTEX_DYNUPDATE);
                                    database_service_zone_dnskey_set_alarms(zone); // we are in a ZT_MASTER case
                                    
                                    return_code = database_zone_ensure_private_keys(zone_desc, zone); // zone is locked
                                }
                            }
                            else
                            {
                                log_warn("database: update: cannot update %{dnsname} because DNSSEC maintenance has been disabled on the zone", zone->origin);

                                return_code = SERVER_ERROR_CODE(RCODE_SERVFAIL);
                                
                                mesg->status = (finger_print)RCODE_SERVFAIL;
                            }
                        }
#endif
                                                /// @todo 20150127 edf -- if at least one key has been loaded, it should continue
                        if(ISOK(return_code))   ///
                        {
                            /* The reader is positioned after the header : read the QR section */
                            
                            if(ISOK(return_code = packet_reader_read_zone_record(&reader, wire, sizeof(wire))))
                            {
                                /*
                                * The zone is known with the previous record.
                                * Since I'm just testing the update per se, I'll ignore this.
                                */

                                count = ntohs(MESSAGE_PR(mesg->buffer));
                                
                                /* The reader is positioned after the QR section, read AN section */

                                /// @todo 20141008 edf -- this lock is too early, it should be moved just before the actual run

                                // from this point, the zone is single-locked

                                log_debug("database: update: processing %d prerequisites", count);

                                if(ISOK(return_code = dynupdate_check_prerequisites(zone, &reader, count)))
                                {
                                    count = ntohs(MESSAGE_UP(mesg->buffer));
                                    
                                    /*
                                     * Dry run the update for the section
                                     * (so the DB will not be broken if the query is bogus)
                                     */

                                    if(ISOK(return_code = dynupdate_diff(zone, &reader, count, ZDB_ZONE_MUTEX_DYNUPDATE, DYNUPDATE_UPDATE_RUN)))
                                    {
                                        zone_set_status(zone_desc, ZONE_STATUS_MODIFIED);
                                        need_to_notify_slaves = TRUE;
                                    }
                                    else
                                    {
                                        if((return_code & 0xffff0000) == SERVER_ERROR_BASE)
                                        {
                                            mesg->status = (finger_print)SERVER_ERROR_GETCODE(return_code);
                                        }
                                        else
                                        {
                                            mesg->status = (finger_print)RCODE_SERVFAIL;
                                        }
                                    }
                                }
                                else
                                {
                                    /*
                                     * ZONE CANNOT BE UPDATED (prerequisites not met)
                                     */

                                    log_warn("database: update: prerequisites not met updating %{dnsname}", mesg->qname);

                                    mesg->status = (finger_print)RCODE_SERVFAIL;
                                }

                                zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);

                                zdb_zone_release(zone);
                            }
                            else
                            {
                                mesg->status = (finger_print)RCODE_FORMERR;
                                
                                zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
                            }
                        }
                        else
                        {
                            /*
                             * ZONE CANNOT BE UPDATED (missing private keys)                             
                             */
                            
                            mesg->status = FP_CANNOT_DYNUPDATE;
                            
                            zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
                        }
                    }
                    else
                    {
                        /*
                         * ZONE CANNOT BE UPDATED (frozen)
                         */

                        mesg->status = FP_CANNOT_DYNUPDATE;
                        
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
                        mesg->status = FP_UPDATE_UNKNOWN_ZONE;
                    }
                    else
                    {
                        zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
                        mesg->status = FP_INVALID_ZONE;
                    }
                }
                
                break;
            }
            /**
             * @todo 20120106 edf -- : dynamic update forwarding ...
             */
            case ZT_SLAVE:
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

                    message_data forward;
                    message_make_query(&forward, id, (const u8*)"", 0, 0);  /* just initialise a basic query */

                    memcpy(forward.buffer, mesg->buffer, mesg->received);
                    forward.send_length = mesg->received;
                    
                    // if no TSIG or succeeded in TSIGing the message ...
                    
#if HAS_TSIG_SUPPORT
                    if((zone_desc->masters->tsig == NULL) || ISOK(return_code = message_sign_query(&forward, zone_desc->masters->tsig)))
                    {
#endif
                        // send a TCP query to the master
                        
                        if(ISOK(return_code = message_query_tcp(&forward, zone_desc->masters)))
                        {
                            memcpy(mesg->buffer, forward.buffer, forward.received);
                            mesg->send_length = forward.received;
                            mesg->status = forward.status;
                        }
#if HAS_TSIG_SUPPORT
                    }
#endif
                }
                else
#endif
                {
                    mesg->status = FP_CANNOT_DYNUPDATE;
                    return_code = FP_CANNOT_DYNUPDATE;
                    
                    message_make_error(mesg, return_code);
                }
                
                break;
            }
            default:
            {
                mesg->status = FP_CANNOT_DYNUPDATE;
                return_code = FP_CANNOT_DYNUPDATE;
                
                message_make_error(mesg, return_code);
                
                break;
            }
        }
        
        zone_unlock(zone_desc, ZONE_LOCK_DYNUPDATE);
        
        if(need_to_notify_slaves)
        {
            notify_slaves(zone_desc->origin);
        }
        
        zone_release(zone_desc);
    }
    else
    {
        /* zone is not even known by the configuration  */

        mesg->status = FP_UPDATE_UNKNOWN_ZONE;
    }

    MESSAGE_LOFLAGS(mesg->buffer) = (MESSAGE_LOFLAGS(mesg->buffer)&~RCODE_BITS) | mesg->status;

#if HAS_TSIG_SUPPORT
    if(TSIG_ENABLED(mesg))
    {
        log_debug("database: %{dnsname}: update: signing reply", mesg->qname);
        
        tsig_sign_answer(mesg);
    }
#endif

    return (finger_print)return_code;
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
    
#ifdef DEBUG
    if(database != NULL)
    {
        zdb_destroy(database);
        free(database);
    }
#endif
    
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
#ifdef DEBUG
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
    
    zone = zdb_acquire_zone_read_from_fqdn(db, zone_desc->origin);
    
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
                    
                    database_zone_ixfr_query(zone_desc->origin);
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

                        database_zone_ixfr_query(zone_desc->origin);
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
                        zone->apex->flags |= ZDB_RR_LABEL_INVALID_ZONE;
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
    
#ifdef DEBUG
    memset(sszra, 0xff, sizeof(database_zone_refresh_alarm_args));
#endif
    
    free(sszra);
    
    zone_release(zone_desc);

    return SUCCESS;
}

ya_result
database_zone_refresh_maintenance_wih_zone(zdb_zone* zone, u32 next_alarm_epoch)
{
    if((zone != NULL) && ZDB_ZONE_VALID(zone))
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

        MALLOC_OR_DIE(database_zone_refresh_alarm_args*, sszra, sizeof(database_zone_refresh_alarm_args), DBREFALP_TAG);

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
database_save_zone_to_disk(zone_desc_s *zone_desc)
{
    database_zone_save(zone_desc->origin);
    return SUCCESS;
}

ya_result
database_save_all_zones_to_disk()
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
    
    zone_set_lock(&database_zone_desc);
    
    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_avl_iterator_next_node(&iter);
        
        zone_desc_s *zone_desc = (zone_desc_s*)zone_node->value;
        
        if(zone_is_obsolete(zone_desc))
        {
            continue;
        }
                        
        database_save_zone_to_disk(zone_desc);
    }
    
    zone_set_unlock(&database_zone_desc);
    
    return batch_return_value;
}

bool
database_are_all_zones_saved_to_disk()
{
    bool can_unload;  
    
    can_unload = TRUE;
    
    zone_set_lock(&database_zone_desc);
    
    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_avl_iterator_next_node(&iter);

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
database_wait_all_zones_saved_to_disk()
{
    while(!database_are_all_zones_saved_to_disk())
    {        
        log_info("database: still busy writing zone files: shutdown postponed");
        sleep(1);
    }
}

void
database_disable_all_zone_save_to_disk()
{
    zone_set_lock(&database_zone_desc);
    
    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_avl_iterator_next_node(&iter);
        
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
