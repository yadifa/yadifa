/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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

#include "config.h"

#include <dnscore/logger.h>
#include <dnscore/host_address.h>

#include "database-service.h"
#include "notify.h"

#if HAS_CTRL
#include "ctrl.h"
#endif

#define MODULE_MSG_HANDLE g_server_logger

extern logger_handle *g_server_logger;
extern zone_data_set database_zone_desc;

void
database_load_zone_desc(zone_desc_s *zone_desc)
{
    yassert(zone_desc != NULL);
    
    log_debug1("database_load_zone_desc(%{dnsname}@%p=%i)", zone_desc->origin, zone_desc, zone_desc->rc);
/*    
    zone_lock(zone_desc, ZONE_LOCK_LOAD_DESC);

    if(zone_desc->file_name == NULL)
    {
        char tmp[PATH_MAX];
        snformat(tmp, sizeof(tmp), "dynamic_%{dnsname}.zone", zone_desc->origin);
        zone_desc->file_name = strdup(tmp); //
    }

    zone_unlock(zone_desc, ZONE_LOCK_LOAD_DESC);
*/
    s32 err = zone_register(&database_zone_desc, zone_desc);

    if(ISOK(err))
    {
        log_info("zone: the zone %{dnsname} has been registered", zone_desc->origin);
        
        zone_lock(zone_desc, ZONE_LOCK_LOAD_DESC);
        zone_desc->status_flags |= ZONE_STATUS_REGISTERED;
        zone_desc->status_flags &= ~ZONE_STATUS_DROP_AFTER_RELOAD;
        zone_unlock(zone_desc, ZONE_LOCK_LOAD_DESC);
        
        // newly registered zone
        // used to be message->origin
        
        if(database_service_started())
        {
            database_zone_load(zone_desc->origin); // before this I should set the file name

#if HAS_MASTER_SUPPORT
            if(zone_desc->type == ZT_MASTER)
            {
                if(!host_address_empty(zone_desc->slaves))
                {
                    log_info("zone load desc: notifying slaves for '%{dnsname}'", zone_desc->origin);
                    host_address *slaves = host_address_copy_list(zone_desc->slaves);
                    notify_host_list(zone_desc, slaves, CLASS_CTRL);
                }
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
                log_err("config: zone: ?: no domain set (not loaded)", zone_desc->domain);
                
                if(zone_desc->status_flags & ZONE_STATUS_PROCESSING)
                {
                    log_err("destroying desc@%p being processed by %s", zone_desc, database_service_operation_get_name(zone_desc->last_processor));
                }
                
                zone_free(zone_desc);
                
                break;
            }
            case DATABASE_ZONE_MISSING_MASTER:
            {
                log_err("config: zone: %{dnsname} has no master setting (not loaded)", zone_desc->origin);
                
                if(zone_desc->status_flags & ZONE_STATUS_PROCESSING)
                {
                    log_err("destroying desc@%p being processed by %s", zone_desc, database_service_operation_get_name(zone_desc->last_processor));
                }
                
                zone_free(zone_desc);
                
                break;
            }
            case DATABASE_ZONE_CONFIG_CLONE: // Exact copy
            {
                log_debug("config: zone: the zone %{dnsname} has already been set like this", zone_desc->origin);
                
                zone_desc_s* current = zone_acquirebydnsname(zone_desc->origin);
                
                zone_lock(current, ZONE_LOCK_REPLACE_DESC);
                current->status_flags &= ~ZONE_STATUS_DROP_AFTER_RELOAD;
                zone_unlock(current, ZONE_LOCK_REPLACE_DESC);
                zone_release(current);
                
                
                // whatever has been decided above, loading the zone file (if it changed) should be queued
                database_zone_load(zone_desc->origin);
                
                zone_free(zone_desc);
                
                

                break;
            }
            case DATABASE_ZONE_CONFIG_DUP: // Not an exact copy
            {
                log_err("config: zone: the zone %{dnsname} has already been set", zone_desc->origin);
                
                // basically, most of the changes require a stop, restart of
                // any task linked to the zone
                // so let's make this a rule, whatever changed
                
                notify_clear(zone_desc->origin);
                /// @todo signature maintenance clear
                /// @todo retry clear
                
                zone_desc_s *current = zone_acquirebydnsname(zone_desc->origin);

#if HAS_DYNAMIC_PROVISIONING
                host_address *notify_slaves_then_delete = NULL;
                host_address *notify_slaves = NULL;
#endif
                if(current != zone_desc)
                {
                    zone_lock(current, ZONE_LOCK_REPLACE_DESC);
                    
                    if(current->status_flags & ZONE_STATUS_PROCESSING)
                    {
                        log_err("overwriting a desc@%p being processed by %s, with %p", current, database_service_operation_get_name(current->last_processor), zone_desc);
                    }
                    
                    // what happens if the change is on :
                    
                    // domain: impossible
                    
                    /// @todo compare before replace
                    
                    // file_name : try to load the new file (will happen anyway)
                    
                    if((current->file_name != NULL) && (zone_desc->file_name != NULL))
                    {
                        if(strcmp(current->file_name, zone_desc->file_name) != 0)
                        {
                            current->status_flags |= ZONE_STATUS_MODIFIED;
                        }
                    }
                    else if(current->file_name != zone_desc->file_name) // at least one of them is NULL
                    {
                        current->status_flags |= ZONE_STATUS_MODIFIED;
                    }
                    
                    free(current->file_name);
                    current->file_name = zone_desc->file_name;
                    zone_desc->file_name = NULL;
                    
                    // masters :
                    
                    log_debug7("updating %p (%u) with %p (%u): masters", current, current->lock_owner, zone_desc, zone_desc->lock_owner);
                    
                    if(host_address_list_equals(current->masters, zone_desc->masters))
                    {
                        host_address_delete_list(zone_desc->masters);
                    }
                    else
                    {
                        host_address_delete_list(current->masters);
                        current->masters = zone_desc->masters;
                    }
                    zone_desc->masters = NULL;
                    
                    // notifies :
                    
                    log_debug7("updating %p (%u) with %p (%u): notifies", current, current->lock_owner, zone_desc, zone_desc->lock_owner);
                    
                    if(host_address_list_equals(current->notifies, zone_desc->notifies))
                    {
                        host_address_delete_list(zone_desc->notifies);
                    }
                    else
                    {
                        host_address_delete_list(current->notifies);
                        current->notifies = zone_desc->notifies;
                    }
                    zone_desc->notifies = NULL;
                    
#if HAS_DYNAMIC_PROVISIONING
                    
                    log_debug7("updating %p (%u) with %p (%u): slaves", current, current->lock_owner, zone_desc, zone_desc->lock_owner);
                    
                    if(host_address_list_equals(current->slaves, zone_desc->slaves))
                    {
#if HAS_MASTER_SUPPORT
                        if((current->type == ZT_MASTER) || (zone_desc->type == ZT_MASTER))
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
                        if(current->type == ZT_MASTER)
                        {
                            notify_slaves_then_delete = current->slaves;
                        }
                        else
                        {
                            host_address_delete_list(current->slaves);
                        }
                        
                        if(zone_desc->type == ZT_MASTER)
                        {
                            notify_slaves = zone_desc->slaves;
                        }
#else
                        host_address_delete_list(current->slaves);
#endif
                        
                        current->slaves = zone_desc->slaves;
                    }
                    zone_desc->slaves = NULL;
                    
#endif              
                    // type : ?
                    
                    log_debug7("updating %p (%u) with %p (%u): type", current, current->lock_owner, zone_desc, zone_desc->lock_owner);
                    current->type = zone_desc->type;
                    
#if HAS_ACL_SUPPORT
                    // ac : apply the new one, update the zone access
                                        
                    log_debug7("updating %p (%u) with %p (%u): ac@%p with ac@%p",
                            current, current->lock_owner, zone_desc, zone_desc->lock_owner,
                            &current->ac, &zone_desc->ac);
                    
#ifdef DEBUG
                    log_debug7("old@%p:", current);
                    log_debug7("    notify@%p",current->ac.allow_notify.ipv4.items);
                    log_debug7("     query@%p",current->ac.allow_query.ipv4.items);
                    log_debug7("  transfer@%p",current->ac.allow_transfer.ipv4.items);
                    log_debug7("    update@%p",current->ac.allow_update.ipv4.items);
                    log_debug7("forwarding@%p",current->ac.allow_update_forwarding.ipv4.items);
                    log_debug7("   control@%p",current->ac.allow_control.ipv4.items);
                    
                    log_debug7("new@%p:", zone_desc);
                    log_debug7("    notify@%p",zone_desc->ac.allow_notify.ipv4.items);
                    log_debug7("     query@%p",zone_desc->ac.allow_query.ipv4.items);
                    log_debug7("  transfer@%p",zone_desc->ac.allow_transfer.ipv4.items);
                    log_debug7("    update@%p",zone_desc->ac.allow_update.ipv4.items);
                    log_debug7("forwarding@%p",zone_desc->ac.allow_update_forwarding.ipv4.items);
                    log_debug7("   control@%p",zone_desc->ac.allow_control.ipv4.items);
#endif
                    
                    acl_unmerge_access_control(&current->ac, &g_config->ac);
                    acl_empties_access_control(&current->ac);
                    memcpy(&current->ac, &zone_desc->ac, sizeof(access_control));
                    ZEROMEMORY(&zone_desc->ac, sizeof(access_control));
#endif
                    // notify : reset, restart
                    
                    log_debug7("updating %p (%u) with %p (%u): notify", current, current->lock_owner, zone_desc, zone_desc->lock_owner);
                    memcpy(&current->notify, &zone_desc->notify, sizeof(zone_notify_s));
                    
#if HAS_RRSIG_MANAGEMENT_SUPPORT
                    // signature : reset, restart
                    
                    log_debug7("updating %p (%u) with %p (%u): signature", current, current->lock_owner, zone_desc, zone_desc->lock_owner);
                    memcpy(&current->signature, &zone_desc->signature, sizeof(zone_signature_s));
#endif
                    
                    // dnssec_mode : drop everything related to the zone, load the new config
                    
                    log_debug7("updating %p (%u) with %p (%u): dnssec_mode", current, current->lock_owner, zone_desc, zone_desc->lock_owner);
                    
                    current->dnssec_mode = zone_desc->dnssec_mode;
                                        
                    // refresh : update the "alarms"
                    
                    log_debug7("updating %p (%u) with %p (%u): refresh", current, current->lock_owner, zone_desc, zone_desc->lock_owner);

                    memcpy(&current->refresh, &zone_desc->refresh, sizeof(zone_refresh_s));
                                        
                    // dynamic_provisioning : ?
                    
                    log_debug7("updating %p (%u) with %p (%u): dynamic_provisioning", current, current->lock_owner, zone_desc, zone_desc->lock_owner);
                    
                    memcpy(&current->dynamic_provisioning, &zone_desc->dynamic_provisioning, sizeof(dynamic_provisioning_s));
                    
                    // slaves : update the list
                    
                    zone_unlock(current, ZONE_LOCK_REPLACE_DESC);
                }

                // whatever has been decided above, loading the zone file should be queued
                database_zone_load(zone_desc->origin);

#if HAS_DYNAMIC_PROVISIONING
                // if asking for a load of the zone_data on a master should trigger a notify of its slaves
                
                log_debug7("handling dynamic provisioning");

                if(!host_address_empty(notify_slaves_then_delete))
                {
                    log_info("zone load desc: notifying slaves for '%{dnsname}': %{hostaddrlist}", zone_desc->origin, notify_slaves_then_delete);
                    
                    notify_host_list(current, notify_slaves_then_delete, CLASS_CTRL);
                    notify_slaves_then_delete = NULL;
                }
                
                if(!host_address_empty(notify_slaves))
                {
                    log_info("zone load desc: notifying slaves for '%{dnsname}': %{hostaddrlist}", zone_desc->origin, notify_slaves);
                    
                    host_address *notify_slaves_copy = host_address_copy_list(notify_slaves);
                    notify_host_list(current, notify_slaves_copy, CLASS_CTRL);
                    notify_slaves = NULL;
                }
#endif
                if(current != zone_desc)
                {
                    log_debug7("destroying temporary zone descriptor @%p", zone_desc);

                    zone_free(zone_desc);
                }
                
                current->status_flags &= ~ZONE_STATUS_DROP_AFTER_RELOAD;
                
                zone_release(current);
                
                break;
            } // DUP
        } // switch
    }
    
    log_debug1("database_load_zone_desc(%p) done", zone_desc);
}

/**
 * @}
 */

