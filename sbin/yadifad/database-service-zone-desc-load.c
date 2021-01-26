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

/** @defgroup database Routines for database manipulations
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

#include <dnscore/logger.h>
#include <dnscore/host_address.h>

#include "database-service.h"
#include "notify.h"
#include "zone-signature-policy.h"
#include "zone.h"

#if HAS_CTRL
#include "ctrl.h"
#include "zone-signature-policy.h"
#endif

#define MODULE_MSG_HANDLE g_server_logger

extern logger_handle *g_server_logger;
extern zone_data_set database_zone_desc;

void
database_load_zone_desc(zone_desc_s *zone_desc)
{
    yassert(zone_desc != NULL);
    
    log_debug1("database_load_zone_desc(%{dnsname}@%p=%i)", zone_origin(zone_desc), zone_desc, zone_desc->rc);
    
    s32 err = zone_register(&database_zone_desc, zone_desc);

    if(ISOK(err))
    {
        log_info("zone: %{dnsname}: %p: config: registered", zone_origin(zone_desc), zone_desc);
        
        zone_lock(zone_desc, ZONE_LOCK_LOAD_DESC);
        zone_set_status(zone_desc, ZONE_STATUS_REGISTERED);
        zone_clear_status(zone_desc, ZONE_STATUS_DROP_AFTER_RELOAD);
        zone_unlock(zone_desc, ZONE_LOCK_LOAD_DESC);
        
        // newly registered zone
        // used to be message->origin
        
        if(database_service_started())
        {
            database_zone_load(zone_origin(zone_desc)); // before this I should set the file name

#if HAS_MASTER_SUPPORT
            if(zone_desc->type == ZT_MASTER)
            {

            }
            else
#endif
            {

            }
        }
    }
    else
    {
        switch(err)
        {
            case DATABASE_ZONE_MISSING_DOMAIN:
            {
                log_err("zone: ?: %p: config: no domain set (not loaded)", zone_desc);
                
                if(zone_get_status(zone_desc) & ZONE_STATUS_PROCESSING)
                {
                    log_err("zone: ?: %p: is processed by %s (releasing)", zone_desc, database_service_operation_get_name(zone_desc->last_processor));
                }
                
                zone_release(zone_desc);
                
                break;
            }
            case DATABASE_ZONE_MISSING_MASTER:
            {
                log_err("zone: %{dnsname}: %p: config: slave but no master setting (not loaded)", zone_origin(zone_desc), zone_desc);
                
                if(zone_get_status(zone_desc) & ZONE_STATUS_PROCESSING)
                {
                    log_err("zone: ?: %p: is processed by %s (releasing)", zone_desc, database_service_operation_get_name(zone_desc->last_processor));
                }
                
                zone_release(zone_desc);
                
                break;
            }
            case DATABASE_ZONE_CONFIG_CLONE: // Exact copy
            {
                log_debug("zone: %{dnsname}: %p: config: has already been set (same settings)", zone_origin(zone_desc), zone_desc);
                
                zone_desc_s* current = zone_acquirebydnsname(zone_origin(zone_desc));
                
                zone_lock(current, ZONE_LOCK_REPLACE_DESC);
                zone_clear_status(current, ZONE_STATUS_DROP_AFTER_RELOAD);
                zone_unlock(current, ZONE_LOCK_REPLACE_DESC);
                zone_release(current);
                
                // whatever has been decided above, loading the zone file (if it changed) should be queued
                database_zone_load(zone_origin(zone_desc));
                
                zone_release(zone_desc);
                
                break;
            }
            case DATABASE_ZONE_CONFIG_DUP: // Not an exact copy
            {
                log_debug("zone: %{dnsname}: %p: config: has already been set (different settings)", zone_origin(zone_desc), zone_desc);
                
                // basically, most of the changes require a stop, restart of
                // any task linked to the zone
                // so let's make this a rule, whatever changed
                
                notify_clear(zone_origin(zone_desc));

                zone_desc_s *current_zone_desc = zone_acquirebydnsname(zone_origin(zone_desc));

#if DNSCORE_HAS_DYNAMIC_PROVISIONING
                host_address *notify_slaves_then_delete = NULL;
                host_address *notify_slaves = NULL;
#endif
                if(current_zone_desc != zone_desc)
                {
                    zone_lock(current_zone_desc, ZONE_LOCK_REPLACE_DESC);
                    
                    if(zone_get_status(current_zone_desc) & ZONE_STATUS_PROCESSING)
                    {
                        log_err("zone: ?: %p: is processed by %s (overwriting)", zone_desc, database_service_operation_get_name(zone_desc->last_processor));
                    }


                    free(current_zone_desc->file_name);
                    current_zone_desc->file_name = zone_desc->file_name;
                    zone_desc->file_name = NULL;
                    
                    // masters :
                    
                    log_debug7("updating %p (%u) with %p (%u): masters", current_zone_desc, current_zone_desc->lock_owner, zone_desc, zone_desc->lock_owner);
                    
                    if(host_address_list_equals(current_zone_desc->masters, zone_desc->masters))
                    {
                        host_address_delete_list(zone_desc->masters);
                    }
                    else
                    {
                        host_address_delete_list(current_zone_desc->masters);
                        current_zone_desc->masters = zone_desc->masters;
                    }
                    zone_desc->masters = NULL;
                    
                    // notifies :
                    
                    log_debug7("updating %p (%u) with %p (%u): notifies", current_zone_desc, current_zone_desc->lock_owner, zone_desc, zone_desc->lock_owner);
                    
                    if(host_address_list_equals(current_zone_desc->notifies, zone_desc->notifies))
                    {
                        host_address_delete_list(zone_desc->notifies);
                    }
                    else
                    {
                        host_address_delete_list(current_zone_desc->notifies);
                        current_zone_desc->notifies = zone_desc->notifies;
                    }
                    zone_desc->notifies = NULL;
                    
#if DNSCORE_HAS_DYNAMIC_PROVISIONING
                    
                    log_debug7("updating %p (%u) with %p (%u): slaves", current_zone_desc, current_zone_desc->lock_owner, zone_desc, zone_desc->lock_owner);
                    
                    if(host_address_list_equals(current_zone_desc->slaves, zone_desc->slaves))
                    {
#if HAS_MASTER_SUPPORT
                        if((current_zone_desc->type == ZT_MASTER) || (zone_desc->type == ZT_MASTER))
                        {
                            notify_slaves_then_delete = zone_desc->slaves;
                        }
                        else
#endif
                        {
                            host_address_delete_list(zone_desc->slaves);
                        }
                    }
                    else
                    {
#if HAS_MASTER_SUPPORT
                        if(current_zone_desc->type == ZT_MASTER)
                        {
                            notify_slaves_then_delete = current_zone_desc->slaves;
                        }
                        else
                        {
                            host_address_delete_list(current_zone_desc->slaves);
                        }
                        
                        if(zone_desc->type == ZT_MASTER)
                        {
                            notify_slaves = zone_desc->slaves;
                        }
#else
                        host_address_delete_list(current->slaves);
#endif
                        
                        current_zone_desc->slaves = zone_desc->slaves;
                    }
                    zone_desc->slaves = NULL;
                    
#endif              
                    // type : ?
                    
                    log_debug7("updating %p (%u) with %p (%u): type", current_zone_desc, current_zone_desc->lock_owner, zone_desc, zone_desc->lock_owner);
                    current_zone_desc->type = zone_desc->type;
                    
#if HAS_ACL_SUPPORT
                    // ac : apply the new one, update the zone access
                                        
                    log_debug7("updating %p (%u) with %p (%u): ac@%p with ac@%p",
                            current_zone_desc, current_zone_desc->lock_owner, zone_desc, zone_desc->lock_owner,
                            &current_zone_desc->ac, &zone_desc->ac);
                    
#if DEBUG
                    log_debug7("old@%p:", current_zone_desc);
                    log_debug7("    notify@%p",current_zone_desc->ac.allow_notify.ipv4.items);
                    log_debug7("     query@%p",current_zone_desc->ac.allow_query.ipv4.items);
                    log_debug7("  transfer@%p",current_zone_desc->ac.allow_transfer.ipv4.items);
                    log_debug7("    update@%p",current_zone_desc->ac.allow_update.ipv4.items);
                    log_debug7("forwarding@%p",current_zone_desc->ac.allow_update_forwarding.ipv4.items);
                    log_debug7("   control@%p",current_zone_desc->ac.allow_control.ipv4.items);
                    
                    log_debug7("new@%p:", zone_desc);
                    log_debug7("    notify@%p",zone_desc->ac.allow_notify.ipv4.items);
                    log_debug7("     query@%p",zone_desc->ac.allow_query.ipv4.items);
                    log_debug7("  transfer@%p",zone_desc->ac.allow_transfer.ipv4.items);
                    log_debug7("    update@%p",zone_desc->ac.allow_update.ipv4.items);
                    log_debug7("forwarding@%p",zone_desc->ac.allow_update_forwarding.ipv4.items);
                    log_debug7("   control@%p",zone_desc->ac.allow_control.ipv4.items);
#endif
                    
                    acl_unmerge_access_control(&current_zone_desc->ac);
                    acl_access_control_clear(&current_zone_desc->ac);
                    memcpy(&current_zone_desc->ac, &zone_desc->ac, sizeof(access_control));
                    ZEROMEMORY(&zone_desc->ac, sizeof(access_control));
#endif
                    // notify : reset, restart
                    
                    log_debug7("updating %p (%u) with %p (%u): notify", current_zone_desc, current_zone_desc->lock_owner, zone_desc, zone_desc->lock_owner);
                    memcpy(&current_zone_desc->notify, &zone_desc->notify, sizeof(zone_notify_s));
#if HAS_DNSSEC_SUPPORT                    
#if HAS_RRSIG_MANAGEMENT_SUPPORT
                    // signature : reset, restart
                    
                    log_debug7("updating %p (%u) with %p (%u): signature", current_zone_desc, current_zone_desc->lock_owner, zone_desc, zone_desc->lock_owner);
                    memcpy(&current_zone_desc->signature, &zone_desc->signature, sizeof(zone_signature_s));
#endif                    
                    // dnssec_mode : drop everything related to the zone, load the new config
                    
                    log_debug7("updating %p (%u) with %p (%u): dnssec_mode", current_zone_desc, current_zone_desc->lock_owner, zone_desc, zone_desc->lock_owner);
                    
                    current_zone_desc->dnssec_mode = zone_desc->dnssec_mode;
#endif

                                        
                    // refresh : update the "alarms"
                    
                    log_debug7("updating %p (%u) with %p (%u): refresh", current_zone_desc, current_zone_desc->lock_owner, zone_desc, zone_desc->lock_owner);

                    memcpy(&current_zone_desc->refresh, &zone_desc->refresh, sizeof(zone_refresh_s));
                                        
                    // dynamic_provisioning : ?
                    
                    log_debug7("updating %p (%u) with %p (%u): dynamic_provisioning", current_zone_desc, current_zone_desc->lock_owner, zone_desc, zone_desc->lock_owner);
                    
                    memcpy(&current_zone_desc->dynamic_provisioning, &zone_desc->dynamic_provisioning, sizeof(dynamic_provisioning_s));
                    
                    // slaves : update the list
                    
                    zone_unlock(current_zone_desc, ZONE_LOCK_REPLACE_DESC);
                }

                // whatever has been decided above, loading the zone file should be queued
                database_zone_load(zone_origin(zone_desc));

#if DNSCORE_HAS_DYNAMIC_PROVISIONING
                // if asking for a load of the zone_data on a master should trigger a notify of its slaves
                
                log_debug7("handling dynamic provisioning");

                if(!host_address_empty(notify_slaves_then_delete))
                {
                    log_debug("zone load desc: %{dnsname}: notifying slaves: %{hostaddrlist}", zone_origin(zone_desc), notify_slaves_then_delete);
                    
                    notify_host_list(current_zone_desc, notify_slaves_then_delete, CLASS_CTRL);
                    notify_slaves_then_delete = NULL;
                }
                
                if(!host_address_empty(notify_slaves))
                {
                    log_debug("zone load desc: %{dnsname}: notifying slaves: %{hostaddrlist}", zone_origin(zone_desc), notify_slaves);
                    
                    host_address *notify_slaves_copy = host_address_copy_list(notify_slaves);
                    notify_host_list(current_zone_desc, notify_slaves_copy, CLASS_CTRL);
                    notify_slaves = NULL;
                }
#endif
                
#if HAS_MASTER_SUPPORT && HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT
                
                if(current_zone_desc->dnssec_policy != zone_desc->dnssec_policy)
                {
                    log_info("zone: %{dnsname}: %p: config: dnssec-policy modified", zone_origin(zone_desc), zone_desc);
                    
                    if(zone_desc->dnssec_policy != NULL)
                    {
                        if(current_zone_desc->dnssec_policy != NULL)
                        {
                            log_warn("zone: %{dnsname}: %p: config: changing dnssec-policy at runtime (%s to %s)", zone_origin(zone_desc), zone_desc, current_zone_desc->dnssec_policy->name, zone_desc->dnssec_policy->name);
                            
                            if(current_zone_desc->dnssec_policy->denial != zone_desc->dnssec_policy->denial)
                            {
                                log_warn("zone: %{dnsname}: %p: config: modifications of the dnssec-policy denial setting may be ignored", zone_origin(zone_desc), zone_desc);
                            }
                        
                            dnssec_policy_release(current_zone_desc->dnssec_policy);
                            current_zone_desc->dnssec_policy = dnssec_policy_acquire_from_name(zone_desc->dnssec_policy->name);
                        }
                        else
                        {
                            log_info("zone: %{dnsname}: %p: config: dnssec-policy %s enabled", zone_origin(zone_desc), zone_desc, zone_desc->dnssec_policy->name);
                            current_zone_desc->dnssec_policy = dnssec_policy_acquire_from_name(zone_desc->dnssec_policy->name);
                        }
                    }
                    else
                    {
                        log_warn("zone: %{dnsname}: %p: config: removing policy at runtime", zone_origin(zone_desc), zone_desc);
                        dnssec_policy_release(current_zone_desc->dnssec_policy);
                        current_zone_desc->dnssec_policy = NULL;
                    }
                }
#endif
                if(current_zone_desc != zone_desc)
                {
                    log_debug7("destroying temporary zone descriptor @%p", zone_desc);

                    zone_release(zone_desc);
                }
                
                zone_clear_status(current_zone_desc, ZONE_STATUS_DROP_AFTER_RELOAD);
                
                zone_release(current_zone_desc);
                
                break;
            } // DUP
            default:
            {
                log_err("zone: %{dnsname}: %p: failed to register", zone_origin(zone_desc), zone_desc);
                break;
            }
        } // switch
    }
    
    log_debug1("database_load_zone_desc(%p) done", zone_desc);
}

/**
 * @}
 */
