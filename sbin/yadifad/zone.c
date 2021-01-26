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

/** @defgroup zone Routines for zone_data struct
 *  @ingroup yadifad
 *  @brief zone functions
 *
 *  Implementation of routines for the zone_data struct
 *   - add
 *   - adjust
 *   - init
 *   - parse
 *   - print
 *   - remove database
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "server-config.h"
#include <string.h>
#include <arpa/inet.h>		/* or netinet/in.h */

#include <dnscore/format.h>
#include <dnscore/timeformat.h>
#include <dnscore/logger.h>
#include <dnscore/mutex.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/parsing.h>

#if DEBUG
#include <dnscore/u64_set.h>
#endif

#include <dnsdb/zdb-config-features.h> // else we get a chicken-egg issue on the following include

#if ZDB_HAS_DNSSEC_SUPPORT
#include <dnsdb/dnssec-keystore.h>
#include "dnssec-policy.h"
#include <dnsdb/nsec3.h>
#endif

#include "server.h"
#include "zone.h"
#include "server_error.h"
#include "config_error.h"
#include "database-service.h"
#include "zone-signature-policy.h"

#define ZONEDATA_TAG 0x41544144454e4f5a
#define ZDORIGIN_TAG 0x4e494749524f445a

#define DEBUG_ARC   0

#ifndef NAME_MAX
#define NAME_MAX 1024
#endif

#define MODULE_MSG_HANDLE g_server_logger

/* Zone file variables */
extern zone_data_set database_zone_desc;


static mutex_t zone_desc_rc_mtx = MUTEX_INITIALIZER;

#if DEBUG
static u64_set zone_desc_tracked_set = U64_SET_EMPTY;
static u64 zone_desc_next_id = 0;
#endif

static const char* type_to_name[4] =
{
    "hint",
    "master",
    "slave",
    "stub"
};

static const char *dnssec_to_name[4] =
{
    "nosec",
    "nsec",
    "nsec3",
    "nsec3-optout"
};



/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

void
zone_set_lock(zone_data_set *dset)
{
    group_mutex_lock(&dset->lock, GROUP_MUTEX_READ);
}

void
zone_set_unlock(zone_data_set *dset)
{
    group_mutex_unlock(&dset->lock, GROUP_MUTEX_READ);
}

void
zone_set_writer_lock(zone_data_set *dset)
{
    group_mutex_lock(&dset->lock, GROUP_MUTEX_WRITE);
}

void
zone_set_writer_unlock(zone_data_set *dset)
{
    group_mutex_unlock(&dset->lock, GROUP_MUTEX_WRITE);
}

#if HAS_DYNAMIC_PROVISIONING
bool
zone_data_is_clone(zone_desc_s *desc)
{
    return (desc != NULL) && ((desc->dynamic_provisioning.flags & ZONE_CTRL_FLAG_CLONE) != 0);
}
#endif

static int
zone_dnsname_compare(const void *node_a, const void *node_b)
{
    const u8 *m_a = (const u8*)node_a;
    const u8 *m_b = (const u8*)node_b;

    return dnsname_compare(m_a, m_b);
}

void
zone_init(zone_data_set *dset)
{
    dset->set.root = NULL;
    dset->set.compare = zone_dnsname_compare;
    group_mutex_init(&dset->lock);
}

void
zone_finalize(zone_data_set *dset)
{
    group_mutex_destroy(&dset->lock);
    dset->set.root = NULL;
    dset->set.compare = zone_dnsname_compare;
}

/** @brief Initializing zone_data variable
 *
 *  The function not only initialize a new zone_data struct, but if needed
 *  will add the struct to the linked list
 *
 *  @param[in,out] dst the new zone_data struct
 *
 *  @retval OK
 */

zone_desc_s *
zone_alloc()
{
    zone_desc_s *zone_desc;

    /* Alloc & clear zone_data structure */
    ZALLOC_OBJECT_OR_DIE( zone_desc, zone_desc_s, ZONEDATA_TAG);
    ZEROMEMORY(zone_desc, sizeof(zone_desc_s));

    bpqueue_init(&zone_desc->commands);
    
    mutex_init(&zone_desc->lock);
    cond_init(&zone_desc->lock_cond);
    
    zone_desc->qclass = CLASS_IN;
    
#if ZDB_HAS_DNSSEC_SUPPORT
#if HAS_RRSIG_MANAGEMENT_SUPPORT
    
    zone_desc->signature.sig_validity_interval = MAX_S32;

    zone_desc->signature.sig_validity_regeneration = MAX_S32;
    /*
     * The validity of newly generated signature will be off by at most this
     */

    zone_desc->signature.sig_validity_jitter = MAX_S32;
    
    zone_desc->signature.scheduled_sig_invalid_first = MAX_S32;

#if HAS_MASTER_SUPPORT
    ptr_set_init(&zone_desc->dnssec_policy_processed_key_suites);
    zone_desc->dnssec_policy_processed_key_suites.compare = ptr_set_asciizp_node_compare;
#endif
    
#endif

#endif
    
    zone_desc->rc = 1;
    
#if DEBUG
    zone_desc->instance_time_us = timeus();
    mutex_lock(&zone_desc_rc_mtx);
    zone_desc->instance_id = zone_desc_next_id++;
    u64_node* node = u64_set_insert(&zone_desc_tracked_set, zone_desc->instance_id);
    node->value = zone_desc;
    mutex_unlock(&zone_desc_rc_mtx);
#endif
    
    log_debug6("new: ?@%p", zone_desc);
    
    return zone_desc;
}

/** \brief
 *  Frees a zone data
 *
 *  @param[in] src is a * to the zone data
 */

zone_desc_s *
zone_clone(zone_desc_s *zone_desc)
{
    zone_desc_s *clone = zone_alloc();
    
    memcpy(clone, zone_desc, sizeof(zone_desc_s));

    clone->masters = host_address_copy_list(zone_desc->masters);
    clone->notifies = host_address_copy_list(zone_desc->notifies);
    
#if HAS_ACL_SUPPORT
    /*
    acl_unmerge_access_control(&zone_setup->ac, &g_config->ac); COMMENTED OUT
    acl_access_control_clear(&zone_setup->ac);                COMMENTED OUT
    */
#endif
    
    /* Free memory */
    clone->domain = strdup(zone_domain(zone_desc));
    clone->file_name = strdup(zone_desc->file_name);
    clone->_origin = dnsname_dup(zone_origin(zone_desc));
    
    clone->rc = 1;
    
#if HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
    if(clone->dnssec_policy != NULL)
    {
        dnssec_policy_acquire(clone->dnssec_policy);
    }
#endif
    
    log_debug6("clone: %{dnsname}@%p of @%p rc=%i", zone_origin(zone_desc), clone, zone_desc, zone_desc->rc);
    
    return clone;
}

void
zone_acquire(zone_desc_s *zone_desc)
{    
    mutex_lock(&zone_desc_rc_mtx);
#if DEBUG && DEBUG_ARC
    s32 old_rc = zone_desc->rc;
    s32 rc =
#endif
    ++zone_desc->rc;
    mutex_unlock(&zone_desc_rc_mtx);
#if DEBUG && DEBUG_ARC
    log_debug6("acquire: %{dnsname}@%p rc=%i", zone_origin(zone_desc), zone_desc, rc);
    char prefix[80];
    snformat(prefix, sizeof(prefix), "acquire: %{dnsname}@%p", zone_origin(zone_desc), zone_desc);
    log_debug7("%s: RC from %i to %i", prefix, old_rc, rc);
    debug_log_stacktrace(g_server_logger, MSG_DEBUG7, prefix);
#endif
}


void
zone_dump_allocated()
{
#if DEBUG
    mutex_lock(&zone_desc_rc_mtx);
    
    u64_set_iterator iter;    
    u64_set_iterator_init(&zone_desc_tracked_set, &iter);
    while(u64_set_iterator_hasnext(&iter))
    {
        u64_node *node = u64_set_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s*)node->value;

        u32 status_flags = zone_get_status(zone_desc);
        format_writer status_flags_fw = {zone_desc_status_flags_long_format, &status_flags};
        log_debug1("zone dump: %p #%llu, %llu, rc=%u, %{dnsname} status=%w",zone_desc, zone_desc->instance_id, zone_desc->instance_time_us, zone_desc->rc, zone_origin(zone_desc), &status_flags_fw);
    }
    
    mutex_unlock(&zone_desc_rc_mtx);
#else
    // not implemented
#endif
}

/**
 * 
 * Decrements reference and eventually destroys the zone desc
 * 
 * @param zone_desc
 */

void
zone_release(zone_desc_s *zone_desc)
{
    // note: the zone MUST be locked by the caller
    
    if(zone_desc != NULL)
    {
        mutex_lock(&zone_desc_rc_mtx);
#if DEBUG && DEBUG_ARC
        s32 old_rc = zone_desc->rc;
#endif
        s32 rc = --zone_desc->rc;
        mutex_unlock(&zone_desc_rc_mtx);
        
#if DEBUG && DEBUG_ARC
        log_debug6("release: %{dnsname}@%p rc=%i", zone_origin(zone_desc), zone_desc, rc);
        
        char prefix[80];
        snformat(prefix, sizeof(prefix), "release: %{dnsname}@%p", zone_origin(zone_desc), zone_desc);
        log_debug7("%s: RC from %i to %i", prefix, old_rc, rc);
        debug_log_stacktrace(g_server_logger, MSG_DEBUG7, prefix);
#endif
        
        if(rc <= 0)
        {
            log_debug7("zone_free(%p): '%s' (%i)", zone_desc, zone_domain(zone_desc), rc);
            
            if(zone_desc->loaded_zone != NULL)
            {
                alarm_close(zone_desc->loaded_zone->alarm_handle);
                zone_desc->loaded_zone->alarm_handle = ALARM_HANDLE_INVALID;
                zdb_zone_release(zone_desc->loaded_zone);
                zone_desc->loaded_zone = NULL;
            }
            
#if DEBUG
            log_debug7("zone_free(%p): '%s' #%llu %llu", zone_desc, zone_domain(zone_desc), zone_desc->instance_id, zone_desc->instance_time_us);
            mutex_lock(&zone_desc_rc_mtx);
            u64_set_delete(&zone_desc_tracked_set, zone_desc->instance_id);
            mutex_unlock(&zone_desc_rc_mtx);
#endif
            
            host_address_delete_list(zone_desc->masters);
            zone_desc->masters = NULL;

            host_address_delete_list(zone_desc->notifies);
            zone_desc->notifies = NULL;
            
#if HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
            if(zone_desc->dnssec_policy != NULL)
            {
                dnssec_policy_release(zone_desc->dnssec_policy);
                zone_desc->dnssec_policy = NULL;
            }
#endif

#if HAS_ACL_SUPPORT
            acl_unmerge_access_control(&zone_desc->ac);
            acl_access_control_clear(&zone_desc->ac);
#endif
            // Free the  memory

            free(zone_desc->domain);
            free(zone_desc->file_name);
            free(zone_desc->_origin);

            cond_finalize(&zone_desc->lock_cond);
            mutex_destroy(&zone_desc->lock);

#if DEBUG
            memset(zone_desc, 0xfe, sizeof(zone_desc_s));
#endif
            ZFREE_OBJECT(zone_desc);
        }
    }
}

void
zone_remove_all_matching(zone_data_set *dset, zone_data_matching_callback *matchcallback)
{
    if(dset != NULL)
    {
        zone_set_lock(dset); // unlock checked
        ptr_vector candidates = PTR_VECTOR_EMPTY;
        ptr_set_iterator iter;
        ptr_set_iterator_init(&dset->set, &iter);
        
        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *zone_node = ptr_set_iterator_next_node(&iter);
            zone_desc_s *zone_desc = (zone_desc_s*)zone_node->value;

            if(zone_desc != NULL)
            {
                if(matchcallback(zone_desc))
                {
                    ptr_vector_append(&candidates, zone_desc);
                }
            }
        }

        for(s32 i = 0; i <= candidates.offset; i++)
        {
            zone_desc_s *zone_desc = (zone_desc_s*)candidates.data[i];
            ptr_set_delete(&dset->set, zone_origin(zone_desc));
            zone_release(zone_desc);
        }
        
        ptr_vector_destroy(&candidates);
        
        zone_set_unlock(dset);
    }
}

#if 1 // NOT USED
/** \brief Frees all elements of the collection
 *
 *  @param[in] src the collection
 *
 *  @return NONE
 */
void
zone_free_all(zone_data_set *dset)
{
    if(dset != NULL)
    {
        zone_set_lock(dset); // unlock checked
        
        ptr_set_iterator iter;
        ptr_set_iterator_init(&dset->set, &iter);
        
        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *zone_node = ptr_set_iterator_next_node(&iter);
            zone_desc_s *zone_desc = (zone_desc_s*)zone_node->value;

            if(zone_desc != NULL)
            {
#if DEBUG
                // status should be idle

                mutex_lock(&zone_desc_rc_mtx);
                s32 rc = zone_desc->rc;
                mutex_unlock(&zone_desc_rc_mtx);

                if(rc != 1)
                {
                    if(rc > 0)
                    {
                        log_debug5("zone: warning, zone %{dnsname} has RC=%i", zone_origin(zone_desc), rc);
                    }
                    else
                    {
                        log_debug5("zone: warning, zone ? has RC=%i", rc);
                    }
                }
#endif
                zone_release(zone_desc);
            }
        }

        ptr_set_destroy(&dset->set);
        
        zone_set_unlock(dset);
    }
}
#endif

ya_result
zone_complete_settings(zone_desc_s *zone_desc)
{
    // type
    
    if(zone_desc->type == ZT_SLAVE)
    {
        if(zone_desc->masters == NULL /* || address_matched(zone_desc->masters, g_config->listen, g_config->port) */)
        {
            return DATABASE_ZONE_MISSING_MASTER;
        }
    }
#if HAS_MASTER_SUPPORT
    else if(zone_desc->type == ZT_MASTER)
    {
        if(zone_desc->file_name == NULL || zone_desc->file_name[0] == '\0')
        {
            return ZONE_LOAD_MASTER_ZONE_FILE_UNDEFINED;
        }
    }
#endif
    else // zone type is not supported
    {
        return DATABASE_ZONE_MISSING_TYPE;
    }
    
    // origin
    
    if(zone_origin(zone_desc) == NULL)
    {
        if(zone_desc->domain == NULL)
        {
            return DATABASE_ZONE_MISSING_DOMAIN;
        }
        
        // else the origin can be set from the domain
        
        // set the domain to lower case
        
        char *p = zone_desc->domain;
        while(*p != 0)
        {
            *p = tolower(*p);
            p++;
        }

        ya_result return_code;
        
        MALLOC_OR_DIE(u8*, zone_desc->_origin, strlen(zone_domain(zone_desc)) + 2, ZDORIGIN_TAG);
        
        if(FAIL(return_code = cstr_to_dnsname(zone_desc->_origin, zone_domain(zone_desc))))
        {
            free(zone_desc->_origin);
            zone_desc->_origin = NULL;

            return return_code;
        }
    }
        
#if HAS_ACL_SUPPORT
    // acl
    
    acl_merge_access_control(&zone_desc->ac, g_config->ac);
#endif
    
#if ZDB_HAS_DNSSEC_SUPPORT
    if(zone_desc->keys_path != NULL)
    {
        dnssec_keystore_add_domain(zone_origin(zone_desc), zone_desc->keys_path);
    }
#endif
    
    return SUCCESS;
}

#define ZONE_DESC_COMPARE_FIELD_PTR(field_a_, field_b_, comparator_, flag_)   \
    if(field_a_ != field_b_)                                        \
    {                                                               \
        if((field_a_ != NULL) && (field_b_ != NULL))                \
        {                                                           \
            if(comparator_(field_a_, field_b_) != 0)                \
            {                                                       \
                return_code |= flag_;                               \
            }                                                       \
        }                                                           \
        else                                                        \
        {                                                           \
            return_code |= flag_;                                   \
        }                                                           \
    }

#define ZONE_DESC_EQUALS_FIELD_PTR(field_a_, field_b_, comparator_, flag_)   \
    if(field_a_ != field_b_)                                        \
    {                                                               \
        if((field_a_ != NULL) && (field_b_ != NULL))                \
        {                                                           \
            if(!comparator_(field_a_, field_b_))                     \
            {                                                       \
                return_code |= flag_;                               \
            }                                                       \
        }                                                           \
        else                                                        \
        {                                                           \
            return_code |= flag_;                                   \
        }                                                           \
    }

s32
zone_desc_match(const zone_desc_s *a, const zone_desc_s *b)
{
    u32 return_code = 0;
    
    if(a == b)
    {
        return 0;
    }
    
    if((a == NULL) || (b == NULL))
    {
        return MIN_S32;
    }
    
    ZONE_DESC_COMPARE_FIELD_PTR(a->_origin, b->_origin, dnsname_compare, ZONE_DESC_MATCH_ORIGIN);
    ZONE_DESC_COMPARE_FIELD_PTR(zone_domain(a),zone_domain(b),strcmp, ZONE_DESC_MATCH_DOMAIN);
    if((a->file_name != NULL) && (b->file_name != NULL))
    {
        ZONE_DESC_COMPARE_FIELD_PTR(a->file_name,b->file_name,strcmp, ZONE_DESC_MATCH_FILE_NAME);
    }
    else if(a->file_name != b->file_name)
    {
        return_code |= ZONE_DESC_MATCH_FILE_NAME;
    }
    ZONE_DESC_EQUALS_FIELD_PTR(a->masters,b->masters,host_address_list_equals, ZONE_DESC_MATCH_MASTERS);
    ZONE_DESC_EQUALS_FIELD_PTR(a->notifies,b->notifies,host_address_list_equals, ZONE_DESC_MATCH_NOTIFIES);
    
#if HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
    if(a->dnssec_policy != b->dnssec_policy)
    {
        return_code |= ZONE_DESC_MATCH_DNSSEC_POLICIES;
    }
#endif

#if HAS_ACL_SUPPORT
    if(!acl_address_control_equals(&a->ac, &b->ac))
    {
        return_code |= ZONE_DESC_MATCH_ACL;
    }
#endif
    
#if HAS_CTRL
    if(memcmp(&a->dynamic_provisioning, &b->dynamic_provisioning, sizeof(dynamic_provisioning_s)) != 0)
    {
        return_code |= ZONE_DESC_MATCH_DYNAMIC;
    }
    
    ZONE_DESC_EQUALS_FIELD_PTR(a->slaves,b->slaves,host_address_list_equals, ZONE_DESC_MATCH_SLAVES);
#endif
    /*
    if(memcmp(&a->refresh, &b->refresh, sizeof(zone_data_refresh)) != 0)
    {
        return_code |= ZONE_DESC_MATCH_REFRESH;
    }
    */
    if(memcmp(&a->notify, &b->notify, sizeof(zone_notify_s)) != 0)
    {
        return_code |= ZONE_DESC_MATCH_NOTIFY;
    }
    
#if HAS_DNSSEC_SUPPORT
    if(a->dnssec_mode != b->dnssec_mode)
    {
        return_code |= ZONE_DESC_MATCH_DNSSEC_MODE;
    }
#endif
    
    if(a->type != b->type)
    {
        return_code |= ZONE_DESC_MATCH_TYPE;
    }
    
    return return_code;
}

/**
 * Adds the zone in the collection (if it's not there already)
 * The zone must have at least it's domain set
 */

ya_result
zone_register(zone_data_set *dset, zone_desc_s *zone_desc)
{
    zone_complete_settings(zone_desc);
            
    if(zone_origin(zone_desc) == NULL)
    {
        if(zone_desc->domain == NULL)
        {
            log_err("config: zone: ?: no domain set (not loaded)", zone_domain(zone_desc));

            return DATABASE_ZONE_MISSING_DOMAIN;
        }
    }
    
    zone_set_writer_lock(dset);
    
    ptr_node *zone_desc_node = ptr_set_find(&dset->set, zone_origin(zone_desc));
    
    if(zone_desc_node != NULL)
    {
        // already known
        
        zone_desc_s *current_zone_desc = (zone_desc_s*)zone_desc_node->value;
        
        s32 zone_desc_match_bitmap = ~0;
        
        if(current_zone_desc == zone_desc)
        {
            // already
            log_debug("zone: %{dnsname} has already been set", zone_origin(zone_desc));

            zone_set_writer_unlock(dset);
            
            return SUCCESS;
        }
        else if((zone_desc_match_bitmap = zone_desc_match(zone_desc, current_zone_desc)) == 0)
        {
            // already
            log_debug("zone: %{dnsname} has already been set this way", zone_origin(zone_desc));

            zone_set_writer_unlock(dset);
            
            return DATABASE_ZONE_CONFIG_CLONE;
        }
        else
        {
            /* 
             * compare the zones are decide (overwrite or replace ?)
             * 
             * if the zones are equals : no operation
             * if the zones differs ...
             *   ask for a reload of the desc
             * 
             */
            
            log_err("zone: %{dnsname} has been set in two different way (bitmap=%08x) (ignoring duplicate)", zone_origin(zone_desc), zone_desc_match_bitmap);
            
            zone_set_writer_unlock(dset);
            
            return DATABASE_ZONE_CONFIG_DUP;
        }
    }
    else
    {
        log_debug("zone: %{dnsname} is a new zone", zone_origin(zone_desc));
        
        zone_desc->_status_flags = ZONE_STATUS_STARTING_UP;
    }
        
    if(zone_desc->type == ZT_SLAVE)
    {
        log_debug1("zone: %{dnsname} is a slave, verifying master settings", zone_origin(zone_desc));

        if(zone_desc->masters == NULL /* || address_matched(zone_desc->masters, g_config->listen, g_config->port) */)
        {
            zone_set_writer_unlock(dset);
            
            log_err("zone: %{dnsname} has no master setting (not loaded)", zone_origin(zone_desc));

            free(zone_desc->_origin);
            zone_desc->_origin = NULL;

            return DATABASE_ZONE_MISSING_MASTER;
        }
        
        log_debug("zone: %{dnsname} is a slave, master is %{hostaddr}", zone_origin(zone_desc), zone_desc->masters);
    }

    ya_result return_value;

    ptr_node *node = ptr_set_insert(&dset->set, zone_desc->_origin);

    if(node->value == NULL)
    {
        //log_info("zone: the zone %{dnsname} has been registered", zone_origin(zone_desc));
        
        node->value = zone_desc;
        
        ++dset->set_count;

        return_value = SUCCESS;
    }
    else
    {
        // already
        //log_err("zone: the zone %{dnsname} has already been set", zone_origin(zone_desc));

        free(zone_desc->_origin);
        zone_desc->_origin = NULL;

        return_value = DATABASE_ZONE_CONFIG_DUP;
    }

    zone_set_writer_unlock(dset);
    
    return return_value;
}

/**
 * Removes the zone with the given origin from the collection.
 * Returns a pointer to the zone. (The caller may destroy it if
 * he wants)
 */

zone_desc_s *
zone_unregister(zone_data_set *dset, const u8 *origin)
{
    zone_desc_s *zone_desc = NULL;

    zone_set_writer_lock(dset);
    
    ptr_node *node = ptr_set_find(&dset->set, origin);
    
    if(node != NULL)
    {
        zone_desc = (zone_desc_s*)node->value;

        if(zone_desc != NULL)
        {
            ptr_set_delete(&dset->set, origin);
            --dset->set_count;
        }
    }
    
    zone_set_writer_unlock(dset);

    return zone_desc;
}

/**
 * returns the zone_data from the zone config that's just after the name
 * in lexicographic order
 * 
 * @param name
 * @return 
 */

zone_desc_s*
zone_getafterdnsname(const u8 *name)
{
    zone_desc_s *zone_desc = NULL;
    
    zone_set_lock(&database_zone_desc); // unlock checked
    
    ptr_node *zone_node = ptr_set_find(&database_zone_desc.set, name);

    if(zone_node != NULL)
    {
        zone_node = ptr_set_node_next(zone_node);
        
        if(zone_node != NULL)
        {
            zone_desc = (zone_desc_s*)zone_node->value;
            zone_acquire(zone_desc);
        }
    }
    
    zone_set_unlock(&database_zone_desc);
    
    return zone_desc;
}

zone_desc_s*
zone_acquirebydnsname(const u8 *name)
{
    zone_desc_s *zone_desc = NULL;
    
    zone_set_lock(&database_zone_desc); // unlock checked
    
    ptr_node *zone_node = ptr_set_find(&database_zone_desc.set, name);

    if(zone_node != NULL)
    {
        zone_desc = (zone_desc_s*)zone_node->value;
        zone_acquire(zone_desc);
    }
    
    zone_set_unlock(&database_zone_desc);
    
    return zone_desc;
}





void
zone_setloading(zone_desc_s *zone_desc, bool v)
{
    const u32 mask = ZONE_STATUS_LOADING;
    
    if(v)
    {
        zone_set_status(zone_desc, mask);
    }
    else
    {
        zone_clear_status(zone_desc, mask);
    }
}

void
zone_setmustsavefile(zone_desc_s *zone_desc, bool v)
{
    const u32 mask = ZONE_STATUS_SAVETO_ZONE_FILE;
    
    if(v)
    {
        zone_set_status(zone_desc, mask);
    }
    else
    {
        zone_clear_status(zone_desc, mask);
    }
}

void
zone_setmustsaveaxfr(zone_desc_s *zone_desc, bool v)
{
    const u32 mask = ZONE_STATUS_SAVETO_AXFR_FILE;
    
    if(v)
    {
        zone_set_status(zone_desc, mask);
    }
    else
    {
        zone_clear_status(zone_desc, mask);
    }
}

void
zone_setsavingfile(zone_desc_s *zone_desc, bool v)
{
    const u32 mask = ZONE_STATUS_SAVING_ZONE_FILE;
    
    if(v)
    {
        zone_set_status(zone_desc, mask);
    }
    else
    {
        zone_clear_status(zone_desc, mask);
    }
}

void
zone_setsavingaxfr(zone_desc_s *zone_desc, bool v)
{
    const u32 mask = ZONE_STATUS_SAVING_AXFR_FILE;
    
    if(v)
    {
        zone_set_status(zone_desc, mask);
    }
    else
    {
        zone_clear_status(zone_desc, mask);
    }
}

void
zone_setstartingup(zone_desc_s *zone_desc, bool v)
{
    const u32 mask = ZONE_STATUS_STARTING_UP;
    
    if(v)
    {
        zone_set_status(zone_desc, mask);
    }
    else
    {
        zone_clear_status(zone_desc, mask);
    }
}

bool
zone_isidle(zone_desc_s *zone_desc)
{
    return (zone_get_status(zone_desc) & ZONE_STATUS_BUSY) == 0;
}

bool
zone_isfrozen(zone_desc_s *zone_desc)
{
    return (zone_get_status(zone_desc) & ZONE_STATUS_FROZEN) != 0;
}



bool
zone_isloading(zone_desc_s *zone_desc)
{
    return ((zone_get_status(zone_desc) & ZONE_STATUS_LOADING) != 0);
}

bool
zone_mustsavefile(zone_desc_s *zone_desc)
{
    return ((zone_get_status(zone_desc) & ZONE_STATUS_SAVETO_ZONE_FILE) != 0);
}

bool
zone_mustsaveaxfr(zone_desc_s *zone_desc)
{
    return ((zone_get_status(zone_desc) & ZONE_STATUS_SAVETO_AXFR_FILE) != 0);
}

bool
zone_issavingfile(zone_desc_s *zone_desc)
{
    return ((zone_get_status(zone_desc) & ZONE_STATUS_SAVING_ZONE_FILE) != 0);
}

bool
zone_issavingaxfr(zone_desc_s *zone_desc)
{
    return ((zone_get_status(zone_desc) & ZONE_STATUS_SAVING_AXFR_FILE) != 0);
}

bool
zone_isstartingup(zone_desc_s *zone_desc)
{
    return ((zone_get_status(zone_desc) & ZONE_STATUS_STARTING_UP) != 0);
}

bool
zone_isdynamicupdating(zone_desc_s *zone_desc)
{
    return ((zone_get_status(zone_desc) & ZONE_STATUS_DYNAMIC_UPDATING) != 0);
}
 
bool
zone_canbeedited(zone_desc_s *zone_desc)
{
    return ((zone_get_status(zone_desc) & (ZONE_STATUS_STARTING_UP|ZONE_STATUS_DYNAMIC_UPDATING|ZONE_STATUS_SAVING_AXFR_FILE|ZONE_STATUS_SAVING_ZONE_FILE|ZONE_STATUS_LOADING)) == 0);
}

bool
zone_ismaster(zone_desc_s *zone_desc)
{
    return zone_desc->type == ZT_MASTER;
}

ya_result
zone_wait_unlocked(zone_desc_s *zone_desc)
{
    log_debug6("zone_wait_unlocked(%{dnsname}@%p) ...", zone_origin(zone_desc), zone_desc);
    
    mutex_lock(&zone_desc->lock);
    
    if((zone_desc->lock_owner_count | zone_desc->lock_wait_count) != 0)
    {
        do
        {
            cond_wait(&zone_desc->lock_cond, &zone_desc->lock);
        }
        while((zone_desc->lock_owner_count | zone_desc->lock_wait_count) != 0);
    }

    log_debug6("zone_wait_unlocked(%{dnsname}@%p) done", zone_origin(zone_desc), zone_desc);

    cond_notify(&zone_desc->lock_cond);
        
    mutex_unlock(&zone_desc->lock);
    
    
    return SUCCESS;
}

bool
zone_is_obsolete(zone_desc_s *zone_desc)
{
    bool r;
    
    mutex_lock(&zone_desc->lock);

    r = ((zone_desc->lock_owner_count | zone_desc->lock_wait_count) == 0) &&
        ((zone_get_status(zone_desc) & (ZONE_STATUS_UNREGISTERING|ZONE_STATUS_MARKED_FOR_DESTRUCTION)) != 0);

    cond_notify(&zone_desc->lock_cond);
    mutex_unlock(&zone_desc->lock);
    
    return r;
}

ya_result
zone_try_lock(zone_desc_s *zone_desc, u8 owner_id)
{
#if DEBUG
    log_debug6("zone_try_lock(%{dnsname}@%p, %u", zone_origin(zone_desc), zone_desc, owner_id);
    debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_DEBUG6, "zone_try_lock");
#endif

    ya_result return_value = LOCK_TIMEOUT;
    
    mutex_lock(&zone_desc->lock);
    
    if((zone_desc->lock_owner == ZONE_LOCK_NOBODY) || (zone_desc->lock_owner == owner_id))
    {
        zone_desc->lock_owner = owner_id & 0x7f;

        zone_desc->lock_owner_count++;

        return_value = owner_id;
    }

    cond_notify(&zone_desc->lock_cond);
    
    mutex_unlock(&zone_desc->lock);
    
    return return_value;
}

ya_result
zone_lock(zone_desc_s *zone_desc, u8 owner_id)
{
    ya_result return_value = LOCK_FAILED;

#if DEBUG
    log_debug6("zone_lock(%{dnsname}@%p, %02x)", zone_origin(zone_desc), zone_desc, owner_id);
    debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_DEBUG6, "zone_lock");
#endif

    mutex_lock(&zone_desc->lock);
    
    if((zone_desc->lock_owner != ZONE_LOCK_NOBODY) && (zone_desc->lock_owner != owner_id))
    {
        zone_desc->lock_wait_count++;

        do
        {
            cond_wait(&zone_desc->lock_cond, &zone_desc->lock);
        }
        while((zone_desc->lock_owner != ZONE_LOCK_NOBODY) && (zone_desc->lock_owner != owner_id));

        zone_desc->lock_wait_count--;
    }

    zone_desc->lock_owner = owner_id & 0x7f;
    zone_desc->lock_owner_count++;

    return_value = owner_id;

#if ZONE_LOCK_HAS_OWNER_ID
    zone_desc->lock_last_owner_tid = thread_self();
#endif

    if((owner_id & 0x80) == 0)
    {
        cond_notify(&zone_desc->lock_cond);
    }

    mutex_unlock(&zone_desc->lock);
    
    return return_value;
}

ya_result
zone_try_lock_wait(zone_desc_s *zone_desc, u64 usec, u8 owner_id)
{
    ya_result return_value = LOCK_FAILED;

#if DEBUG
    log_debug6("zone_try_lock_wait(%{dnsname}@%p, %llu, %02x)", zone_origin(zone_desc), zone_desc, usec, owner_id);
    debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_DEBUG6, "zone_try_lock_wait");
#endif

    mutex_lock(&zone_desc->lock);
    
    if((zone_desc->lock_owner != ZONE_LOCK_NOBODY) && (zone_desc->lock_owner != owner_id))
    {
        zone_desc->lock_wait_count++;

        s64 start = timeus();

        do
        {
            cond_timedwait(&zone_desc->lock_cond, &zone_desc->lock, usec);

            s64 now = timeus();

            if(now - start >= (s64)usec)
            {
                cond_notify(&zone_desc->lock_cond);
                mutex_unlock(&zone_desc->lock);
                return LOCK_TIMEOUT;
            }
        }
        while((zone_desc->lock_owner != ZONE_LOCK_NOBODY) && (zone_desc->lock_owner != owner_id));

        zone_desc->lock_wait_count--;
    }

    zone_desc->lock_owner = owner_id & 0x7f;
    zone_desc->lock_owner_count++;

    return_value = owner_id;

#if ZONE_LOCK_HAS_OWNER_ID
    zone_desc->lock_last_owner_tid = thread_self();
#endif

    if((owner_id & 0x80) == 0)
    {
        cond_notify(&zone_desc->lock_cond);
    }

    mutex_unlock(&zone_desc->lock);
    
    return return_value;
}

void
zone_unlock(zone_desc_s *zone_desc, u8 owner_mark)
{
#if DEBUG
    log_debug6("zone_unlock(%{dnsname}@%p, %02x)", zone_origin(zone_desc), zone_desc, owner_mark);
    debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_DEBUG6, "zone_unlock");
#endif
    
    mutex_lock(&zone_desc->lock);
        
    yassert(zone_desc->lock_owner == (owner_mark & 0x7f));
    yassert(zone_desc->lock_owner_count > 0);

    if((--zone_desc->lock_owner_count) == 0)
    {
        zone_desc->lock_owner = ZONE_LOCK_NOBODY;
    }

#if ZONE_LOCK_HAS_OWNER_ID
    thread_t tid = thread_self();
    if(zone_desc->lock_last_owner_tid == tid)
    {
        zone_desc->lock_last_owner_tid = 0;
    }
#endif

    cond_notify(&zone_desc->lock_cond);
    
    mutex_unlock(&zone_desc->lock);

    (void)owner_mark; // silence warning on NDEBUG builds
}

bool
zone_islocked(zone_desc_s *zone_desc)
{
    mutex_lock(&zone_desc->lock);
    bool ret = (zone_desc->lock_owner != ZONE_LOCK_NOBODY);
    mutex_unlock(&zone_desc->lock);
    
    return ret;
}

/**
 * Sets non-static values in a zone descriptor
 * 
 * @param zone_desc
 */

void
zone_setdefaults(zone_desc_s *zone_desc)
{   
    u32 port;
        
    if(FAIL(parse_u32_check_range(g_config->server_port, &port, 1, MAX_U16, BASE_10)))
    {
        port = DNS_DEFAULT_PORT;
    }
    
    zone_desc->_status_flags = ZONE_STATUS_STARTING_UP;
    
#if HAS_ACL_SUPPORT
    acl_merge_access_control(&zone_desc->ac, g_config->ac);
#endif

#if HAS_RRSIG_MANAGEMENT_SUPPORT && HAS_DNSSEC_SUPPORT

    /*
     * The newly generated signatures will be valid for that amount of days
     */

    if(zone_desc->signature.sig_validity_interval == MAX_S32)
    {
        zone_desc->signature.sig_validity_interval = MIN(g_config->sig_validity_interval, SIGNATURE_VALIDITY_INTERVAL_MAX);  /* days */
    }

    if(zone_desc->signature.sig_validity_regeneration == MAX_S32)
    {
        zone_desc->signature.sig_validity_regeneration = MIN(g_config->sig_validity_regeneration, SIGNATURE_VALIDITY_REGENERATION_MAX);
    }

    /*
     * The validity of newly generated signature will be off by at most this
     */

    if(zone_desc->signature.sig_validity_jitter == MAX_S32)
    {
        zone_desc->signature.sig_validity_jitter = MIN(g_config->sig_validity_jitter, SIGNATURE_VALIDITY_JITTER_MAX);
    }
    
    /*
     * The first epoch when a signature will be marked as invalid.
     */
    
    zone_desc->signature.sig_invalid_first = MAX_S32;

    zone_desc->signature.scheduled_sig_invalid_first = MAX_S32;
#endif
    
#if HAS_DYNAMIC_PROVISIONING
    memset(&zone_desc->dynamic_provisioning, 0, sizeof(dynamic_provisioning_s));
    //zone->dynamic_provisioning.flags |= ZONE_CTRL_FLAG_GENERATE_ZONE;
#endif
    
    zone_desc->notify.retry_count = atoi(S_NOTIFY_RETRY_COUNT);
    zone_desc->notify.retry_period = atoi(S_NOTIFY_RETRY_PERIOD) * 60;
    zone_desc->notify.retry_period_increase = atoi(S_NOTIFY_RETRY_PERIOD_INCREASE) * 60;

    host_address_set_default_port_value(zone_desc->masters, ntohs(port));
    host_address_set_default_port_value(zone_desc->notifies, ntohs(port));

    // seems incorrect here : acl_access_control_copy(&zone_desc->ac, &g_config->ac);
}

/**
 * Merges the settings of a zone into another zone descriptor.
 * 
 * @param desc_zone_desc
 * @param src_zone_desc
 * @return 0 if the zone are equals
 *         1 if some parts have been edited
 *         or an error code
 */

ya_result
zone_setwithzone(zone_desc_s *desc_zone_desc, zone_desc_s *src_zone_desc)
{   
    bool changed = FALSE;
    
    if(desc_zone_desc->domain != NULL)
    {
        if(strcmp(zone_domain(desc_zone_desc), zone_domain(src_zone_desc)) != 0)
        {
            log_debug1("zone_setwithzone: domain does not match '%s'!='%s'", zone_domain(desc_zone_desc), zone_domain(src_zone_desc));
            return INVALID_STATE_ERROR;
        }
    }
    else
    {
        desc_zone_desc->domain = strdup(zone_domain(src_zone_desc));
        desc_zone_desc->qclass = src_zone_desc->qclass;
        desc_zone_desc->type = src_zone_desc->type;
#if ZDB_HAS_DNSSEC_SUPPORT
        desc_zone_desc->dnssec_mode = src_zone_desc->dnssec_mode;
#endif
        desc_zone_desc->dynamic_provisioning.flags = desc_zone_desc->dynamic_provisioning.flags;
        desc_zone_desc->_origin = dnsname_dup(zone_origin(src_zone_desc));
        desc_zone_desc->_status_flags = src_zone_desc->_status_flags;
        if(src_zone_desc->file_name != NULL)
        {
            desc_zone_desc->file_name = strdup(src_zone_desc->file_name);
        }
        
        changed = TRUE;
    }
        
#if HAS_ACL_SUPPORT
    acl_access_control_copy(&desc_zone_desc->ac, &src_zone_desc->ac);
#endif

#if HAS_RRSIG_MANAGEMENT_SUPPORT && HAS_DNSSEC_SUPPORT

    /*
     * The newly generated signatures will be valid for that amount of days
     */

    if(desc_zone_desc->signature.sig_validity_interval != src_zone_desc->signature.sig_validity_interval)
    {
        desc_zone_desc->signature.sig_validity_interval = src_zone_desc->signature.sig_validity_interval;
        changed = TRUE;
    }
    
    if(desc_zone_desc->signature.sig_validity_regeneration != src_zone_desc->signature.sig_validity_regeneration)
    {
        desc_zone_desc->signature.sig_validity_regeneration = src_zone_desc->signature.sig_validity_regeneration;
        changed = TRUE;
    }
    
    if(desc_zone_desc->signature.sig_validity_jitter != src_zone_desc->signature.sig_validity_jitter)
    {
        desc_zone_desc->signature.sig_validity_jitter = src_zone_desc->signature.sig_validity_jitter;
        changed = TRUE;
    }

    /*
     * The first epoch when a signature will be marked as invalid.
     */
    
    if(desc_zone_desc->signature.sig_invalid_first != src_zone_desc->signature.sig_invalid_first)
    {
        desc_zone_desc->signature.sig_invalid_first = src_zone_desc->signature.sig_invalid_first;
        changed = TRUE;
    }
    
    if(desc_zone_desc->signature.scheduled_sig_invalid_first != src_zone_desc->signature.scheduled_sig_invalid_first)
    {
        desc_zone_desc->signature.scheduled_sig_invalid_first = src_zone_desc->signature.scheduled_sig_invalid_first;
        changed = TRUE;
    }

#endif
    
#if HAS_DYNAMIC_PROVISIONING
    if(memcmp(&desc_zone_desc->dynamic_provisioning, &src_zone_desc->dynamic_provisioning, sizeof(dynamic_provisioning_s)) != 0)
    {
        memcpy(&desc_zone_desc->dynamic_provisioning, &src_zone_desc->dynamic_provisioning, sizeof(dynamic_provisioning_s));
        changed = TRUE;
    }
#endif
    
    if(desc_zone_desc->notify.retry_count != src_zone_desc->notify.retry_count)
    {
        desc_zone_desc->notify.retry_count = src_zone_desc->notify.retry_count;
        changed = TRUE;
    }
    
    if(desc_zone_desc->notify.retry_period != src_zone_desc->notify.retry_period)
    {
        desc_zone_desc->notify.retry_period = src_zone_desc->notify.retry_period;
        changed = TRUE;
    }
    
    if(desc_zone_desc->notify.retry_period_increase != src_zone_desc->notify.retry_period_increase)
    {
        desc_zone_desc->notify.retry_period_increase = src_zone_desc->notify.retry_period_increase;
        changed = TRUE;
    }
    
    if(desc_zone_desc->flags != src_zone_desc->flags)
    {
        desc_zone_desc->flags = src_zone_desc->flags;
        changed = TRUE;
    }
    
    changed |= host_address_update_host_address_list(&desc_zone_desc->masters, src_zone_desc->masters);
    changed |= host_address_update_host_address_list(&desc_zone_desc->notifies, src_zone_desc->notifies);
    changed |= host_address_update_host_address_list(&desc_zone_desc->slaves, src_zone_desc->slaves);
    
    if(src_zone_desc->file_name != NULL)
    {
        if(strcmp(desc_zone_desc->file_name, src_zone_desc->file_name) != 0)
        {
            free(desc_zone_desc->file_name);
            desc_zone_desc->file_name = strdup(src_zone_desc->file_name);
            changed = TRUE;
        }
    }
    
#if HAS_MASTER_SUPPORT
    // master zone without a file name ...
            
    if((desc_zone_desc->file_name == NULL) && (desc_zone_desc->type == ZT_MASTER))
    {
        desc_zone_desc->dynamic_provisioning.flags |= ZONE_CTRL_FLAG_GENERATE_ZONE;
        changed = TRUE;
    }
#endif
    
    return (changed)?1:0;   // 1 if changed, 0 is no operation performed
}

 

/**
 * 
 * helper formatting tool to print the zone descriptor status flags as a chain of characters
 * 
 * @param value
 * @param os
 * @param padding
 * @param pad_char
 * @param left_justified
 * @param reserved_for_method_parameters
 */

#ifdef SHORT_VERSION_IS_LESS_CLEAR


/**
 * used by zone_desc_status_flags_format
 */

static const char status_letters[32] = "IclL"
                                       "MUdD"
                                       "zZaA"
                                       "sSeE"
                                       "RxX#"
                                       "f---"
                                       "T---"
                                       "ur/!";

static void
zone_desc_status_flags_format(const void *value, output_stream *os, s32 padding, char pad_char, bool left_justified, void* reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    u32 status = *((u32*)value);
    const char *p = status_letters;
    if(status == 0)
    {
        output_stream_write(os, (const u8*)"i", 1);
    }
    else
    {
        do
        {
            if(status & 1)
            {
                output_stream_write(os, p, 1);
            }

            p++;
            status >>= 1;
        }
        while(status != 0);
    }
}

#endif

/**
 * used by zone_desc_status_flags_long_format
 */

static const char *status_words[32] =
{
    //"IDLE",
    "STARTING-UP",              // 0
    "MODIFIED",
    "LOAD",
    "LOADING",
    "MOUNTING",
    "UNMOUNTING",                // 5
    "DROP",
    "DROPPING",
    "SAVETO-ZONE-FILE",
    "SAVING-ZONE-FILE",
    "SAVETO-AXFR-FILE",          // 10
    "SAVING-AXFR-FILE",
    "SIGNATURES-UPDATE",
    "SIGNATURES-UPDATING",
    "DYNAMIC-UPDATE",
    "DYNAMIC-UPDATING",         // 15
    "READONLY",
    "DOWNLOAD-XFR-FILE",
    "DOWNLOADING-XFR-FILE",
    "DROP-AFTER-RELOAD",
    "FROZEN",                   // 20
    "?",
    "?",
    "?",
    "DOWNLOADED",
    "?",                        // 25
    "?",
    "?",
    "ZONE-STATUS-UNREGISTERING",
    "REGISTERED",
    "MARKED-FOR-DESTRUCTION",
    "PROCESSING"
};

void
zone_desc_status_flags_long_format(const void *value, output_stream *os, s32 padding, char pad_char, bool left_justified, void* reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    u32 status = *((u32*)value);
    const char **p = status_words;
    if(status == 0)
    {
        output_stream_write(os, (const u8*)"IDLE", 4);
    }
    else
    {
        do
        {
            if(status & 1)
            {
                const char *word = *p;
                output_stream_write(os, word, strlen(word));
                output_stream_write(os, (const char*)" ", 1);
            }

            p++;
            status >>= 1;
        }
        while(status != 0);
    }
}

#if HAS_ACL_SUPPORT
/**
 * 
 * helper formatting tool to print the ACL fields of the zone descriptor
 * 
 * @param value
 * @param os
 * @param padding
 * @param pad_char
 * @param left_justified
 * @param reserved_for_method_parameters
 */

static void
zone_desc_ams_format(const void *value, output_stream *os, s32 padding, char pad_char, bool left_justified, void* reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    address_match_set *ams = (address_match_set*)value;
    acl_address_match_set_to_stream(os, ams);
}

#endif

void
zone_desc_log(logger_handle* handle, u32 level, const zone_desc_s *zone_desc, const char *text)
{
    if(text == NULL)
    {
        text = "NULL";
    }
    
    if(zone_desc == NULL)
    {
        logger_handle_msg(handle, level, "%s: NULL", text);
        return;
    }
    
    logger_handle_msg(handle, level, "%s: %{dnsname} @%p '%s' file='%s'",
            text, FQDNNULL(zone_origin(zone_desc)), zone_desc, STRNULL(zone_domain(zone_desc)), STRNULL(zone_desc->file_name));
    u32 status_flags = zone_get_status(zone_desc);
    //format_writer status_flags_fw = {zone_desc_status_flags_format, &status_flags};
    format_writer status_flags_fw = {zone_desc_status_flags_long_format, &status_flags};
    logger_handle_msg(handle, level, "%s: %{dnsname} status=%w",
            text, FQDNNULL(zone_origin(zone_desc)), &status_flags_fw);
#if ZDB_HAS_DNSSEC_SUPPORT
    logger_handle_msg(handle, level, "%s: %{dnsname} dnssec=%s type=%s flags=%x lock=%02hhx #olock=%d #wlock=%d",
            text, FQDNNULL(zone_origin(zone_desc)), zone_dnssec_to_name(zone_desc->dnssec_mode), zone_type_to_name(zone_desc->type),
            zone_desc->flags, zone_desc->lock_owner, zone_desc->lock_owner_count, zone_desc->lock_wait_count);
#else
    logger_handle_msg(handle, level, "%s: %{dnsname} type=%s flags=%x lock=%02hhx #olock=%d #wlock=%d",
            text, FQDNNULL(zone_origin(zone_desc)), zone_type_to_name(zone_desc->type),
            zone_desc->flags, zone_desc->lock_owner, zone_desc->lock_owner_count, zone_desc->lock_wait_count);
#endif
    logger_handle_msg(handle, level, "%s: %{dnsname} refreshed=%d retried=%d next=%d",
            text, FQDNNULL(zone_origin(zone_desc)), zone_desc->refresh.refreshed_time, zone_desc->refresh.retried_time, zone_desc->refresh.zone_update_next_time);
   
#if ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
    
    u32 sig_invalid_first = zone_desc->signature.sig_invalid_first;
    u32 scheduled_sig_invalid_first = zone_desc->signature.scheduled_sig_invalid_first;

    logger_handle_msg(handle, level, "%s: %{dnsname} interval=%d jitter=%d regeneration=%d invalid=%T scheduled-update=%T",
            text, FQDNNULL(zone_origin(zone_desc)),
            zone_desc->signature.sig_validity_interval,
            zone_desc->signature.sig_validity_jitter,
            zone_desc->signature.sig_validity_regeneration,
            sig_invalid_first,
            scheduled_sig_invalid_first);
        
    if(zone_desc->dnssec_policy != NULL)
    {
        logger_handle_msg(handle, level, "%s: %{dnsname} dnssec-policy: '%s'", text, FQDNNULL(zone_origin(zone_desc)), STRNULL(zone_desc->dnssec_policy->name));
    }
    else
    {
        logger_handle_msg(handle, level, "%s: %{dnsname} dnssec-policy: none", text, FQDNNULL(zone_origin(zone_desc)));
    }

#endif
    
    logger_handle_msg(handle, level, "%s: %{dnsname} master=%{hostaddr}",
            text, FQDNNULL(zone_origin(zone_desc)), zone_desc->masters);
    logger_handle_msg(handle, level, "%s: %{dnsname} notified=%{hostaddrlist}",
            text, FQDNNULL(zone_origin(zone_desc)), zone_desc->notifies);
    
#if HAS_ACL_SUPPORT
    format_writer status_ams_fw = {zone_desc_ams_format, &zone_desc->ac.allow_query};
    logger_handle_msg(handle, level, "%s: %{dnsname} allow query=%w", text, FQDNNULL(zone_origin(zone_desc)), &status_ams_fw);
    
    status_ams_fw.value = &zone_desc->ac.allow_update;
    logger_handle_msg(handle, level, "%s: %{dnsname} allow update=%w", text, FQDNNULL(zone_origin(zone_desc)), &status_ams_fw);
    
    status_ams_fw.value = &zone_desc->ac.allow_update_forwarding;
    logger_handle_msg(handle, level, "%s: %{dnsname} allow update forwarding=%w", text, FQDNNULL(zone_origin(zone_desc)), &status_ams_fw);
    
    status_ams_fw.value = &zone_desc->ac.allow_transfer;
    logger_handle_msg(handle, level, "%s: %{dnsname} allow transfer=%w", text, FQDNNULL(zone_origin(zone_desc)), &status_ams_fw);
    
    status_ams_fw.value = &zone_desc->ac.allow_notify;
    logger_handle_msg(handle, level, "%s: %{dnsname} allow notify=%w", text, FQDNNULL(zone_origin(zone_desc)), &status_ams_fw);
#endif
    
#if HAS_DYNAMIC_PROVISIONING
    
#if HAS_ACL_SUPPORT
    status_ams_fw.value = &zone_desc->ac.allow_control;

    logger_handle_msg(handle, level, "%s: %{dnsname} allow control=%w", text, FQDNNULL(zone_origin(zone_desc)), &status_ams_fw);
#endif
    
    logger_handle_msg(handle, level, "%s: %{dnsname} + dp v=%hx flags=%hx expire=%x refresh=%x retry=%x ts=%x:%x",
            text, FQDNNULL(zone_origin(zone_desc)),
            zone_desc->dynamic_provisioning.version,
            zone_desc->dynamic_provisioning.flags,            
            zone_desc->dynamic_provisioning.expire, 
            zone_desc->dynamic_provisioning.refresh,
            zone_desc->dynamic_provisioning.retry,            
            zone_desc->dynamic_provisioning.timestamp,
            zone_desc->dynamic_provisioning.timestamp_lo);
    logger_handle_msg(handle, level, "%s: %{dnsname} + dp slaves=%{hostaddrlist}",
            text, FQDNNULL(zone_origin(zone_desc)), zone_desc->slaves);
    
    u32 command_count = zone_desc->commands.size;
    bpqueue_node_s *command_node = zone_desc->commands.first;
    for(u32 i = 0; i < command_count; i++)
    {
        zone_command_s *cmd = (zone_command_s*)command_node->data;
        logger_handle_msg(handle, level, "%s: %{dnsname} @%p & [%-2i] (%i) %s",
                text, FQDNNULL(zone_origin(zone_desc)), zone_desc,
                i, command_node->priority, database_service_operation_get_name(cmd->id));
        
        command_node = command_node->next;
    }
    
#endif
}

void
zone_desc_log_all(logger_handle* handle, u32 level, zone_data_set *dset, const char *text)
{
    zone_set_lock(dset); // unlock checked
    
    if(!ptr_set_isempty(&dset->set))
    {        
        ptr_set_iterator iter;
        ptr_set_iterator_init(&dset->set, &iter);

        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *zone_node = ptr_set_iterator_next_node(&iter);
            zone_desc_s *zone_desc = (zone_desc_s*)zone_node->value;

            zone_desc_log(handle, level, zone_desc, text);
        }
        
        zone_set_unlock(dset);
    }
    else
    {
        zone_set_unlock(dset);
        
#if DEBUG
        log_debug("zone_desc_log_all: %s set is empty", text);
#endif
    }
}

/**
 * 
 * Calls the callback for all zone_desc.
 * 
 * @param cb
 * @param args
 */

ya_result
zone_desc_for_all(zone_desc_for_all_callback *cb, void *args)
{
    ya_result ret = SUCCESS;
        
    zone_set_lock(&database_zone_desc); // unlock checked
        
    if(!ptr_set_isempty(&database_zone_desc.set))
    {        
        ptr_set_iterator iter;
        ptr_set_iterator_init(&database_zone_desc.set, &iter);

        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *zone_node = ptr_set_iterator_next_node(&iter);
            zone_desc_s *zone_desc = (zone_desc_s*)zone_node->value;

            if(FAIL(ret = cb(zone_desc, args)))
            {
                return ret;
            }
        }
    }

    zone_set_unlock(&database_zone_desc);
    
    return ret;
}

const char*
zone_type_to_name(zone_type t)
{
    if((t >= ZT_HINT) && (t <= ZT_STUB))
    {
        return type_to_name[t];
    }
    
    return "invalid";
}

const char*
zone_dnssec_to_name(u32 dnssec_flags)
{
    dnssec_flags &= ZONE_DNSSEC_FL_MASK;
    if(dnssec_flags < 4)
    {
        return dnssec_to_name[dnssec_flags];
    }
    
    return "invalid";
}

void
zone_enqueue_command(zone_desc_s *zone_desc, u32 id, void* parm, bool has_priority)
{
    if(!has_priority && ((zone_get_status(zone_desc) & ZONE_STATUS_MARKED_FOR_DESTRUCTION) != 0))
    {
        log_err("tried to queue to a zone marked for destruction");
        return;
    }
    
#if DEBUG
    log_debug("zone_desc: enqueue command %{dnsname}@%p=%i %c %s",
    zone_origin(zone_desc), zone_desc, zone_desc->rc, (has_priority)?'H':'L', database_service_operation_get_name(id));
#endif
    
    if(zone_desc->commands_bits & (1 << id))
    {
#if DEBUG
        log_debug("zone_desc: enqueue command %{dnsname}@%p=%i %c %s: already queued",
                  zone_origin(zone_desc), zone_desc, zone_desc->rc, (has_priority)?'H':'L', database_service_operation_get_name(id));
#endif
        return; // already queued
    }
    
    zone_command_s *cmd;
    ZALLOC_OBJECT_OR_DIE( cmd, zone_command_s, ZONECMD_TAG);
    cmd->parm.ptr = parm;
    cmd->id = id;
    bpqueue_enqueue(&zone_desc->commands, cmd, (has_priority)?0:1);
}

zone_command_s*
zone_dequeue_command(zone_desc_s *zone_desc)
{
    zone_command_s *cmd = (zone_command_s*)bpqueue_dequeue(&zone_desc->commands);
        
#if DEBUG
    if(cmd != NULL)
    {
        log_debug("zone_desc: dequeue command %{dnsname}@%p=%i - %s",
                zone_origin(zone_desc), zone_desc, zone_desc->rc, database_service_operation_get_name(cmd->id));
    }
    else
    {
        log_debug("zone_desc: dequeue command %{dnsname}@%p=%i - NULL",
                zone_origin(zone_desc), zone_desc, zone_desc->rc);
    }
#endif
    
    if(cmd != NULL)
    {
        zone_desc->commands_bits &= ~(1 << cmd->id);
    }

    return cmd;
}

void
zone_command_free(zone_command_s *cmd)
{
    ZFREE_OBJECT(cmd);
}

zdb_zone *
zone_get_loaded_zone(zone_desc_s *zone_desc)
{
    yassert(zone_islocked(zone_desc));
    
    zdb_zone *zone = zone_desc->loaded_zone; // OK
    if(zone != NULL)
    {
        zdb_zone_acquire(zone);
    }
    return zone;
}

zdb_zone *
zone_set_loaded_zone(zone_desc_s *zone_desc, zdb_zone *zone)
{
    yassert(zone_islocked(zone_desc));
    
    zdb_zone *old_zone = zone_desc->loaded_zone; // OK
    if(zone != NULL)
    {
        zdb_zone_acquire(zone);
    }
    zone_desc->loaded_zone = zone; // OK
    
    return old_zone;    
}

bool
zone_has_loaded_zone(zone_desc_s *zone_desc)
{
    yassert(zone_islocked(zone_desc));
    
    zdb_zone *zone = zone_desc->loaded_zone; // OK
    return zone != NULL;
}

void
zone_set_status(zone_desc_s *zone_desc, u32 flags)
{
#if DEBUG
    log_debug("zone: %{dnsname}: %p: status %08x + %08x -> %08x", zone_origin(zone_desc), zone_desc, zone_desc->_status_flags, flags, zone_desc->_status_flags|flags);
#endif
    zone_desc->_status_flags |= flags;
}

u32
zone_get_set_status(zone_desc_s *zone_desc, u32 flags)
{
#if DEBUG
    log_debug("zone: %{dnsname}: %p: status %08x + %08x -> %08x", zone_origin(zone_desc), zone_desc, zone_desc->_status_flags, flags, zone_desc->_status_flags|flags);
#endif
    u32 ret = zone_desc->_status_flags & flags;
    zone_desc->_status_flags |= flags;
    return ret;
}

void
zone_clear_status(zone_desc_s *zone_desc, u32 flags)
{
#if DEBUG
    log_debug("zone: %{dnsname}: %p: status %08x - %08x -> %08x", zone_origin(zone_desc), zone_desc, zone_desc->_status_flags, flags, zone_desc->_status_flags&~flags);
#endif
    
    zone_desc->_status_flags &= ~flags;
    if((flags & ZONE_STATUS_PROCESSING) == 0)
    {
        // poke
        database_fire_zone_processed(zone_desc);
    }
}

u32
zone_get_status(const zone_desc_s *zone_desc)
{
    return zone_desc->_status_flags;
}

#if ZDB_HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
void
zone_dnssec_status_update(zdb_zone *zone)
{
    u8 zone_dnssec_type = zone_policy_guess_dnssec_type(zone);
    u8 maintain_mode = zone_get_maintain_mode(zone);

    bool update_chain0 = FALSE;

    switch(zone_dnssec_type)
    {
        case ZONE_DNSSEC_FL_NOSEC:
        {
            if((maintain_mode & ZDB_ZONE_MAINTAIN_MASK) != 0)
            {
                zdb_rr_label_flag_and(zone->apex, ~(ZDB_RR_LABEL_NSEC | ZDB_RR_LABEL_NSEC3 | ZDB_RR_LABEL_NSEC3_OPTOUT));
                zone_set_maintain_mode(zone, 0);
            }
            break;
        }
        case ZONE_DNSSEC_FL_NSEC:
        {
            if((maintain_mode & ZDB_ZONE_MAINTAIN_NSEC) == 0)
            {
                zdb_rr_label_flag_or(zone->apex, ZDB_RR_LABEL_NSEC);
                zdb_rr_label_flag_and(zone->apex, ~(ZDB_RR_LABEL_NSEC3 | ZDB_RR_LABEL_NSEC3_OPTOUT));
                zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC);
            }
            break;
        }
        case ZONE_DNSSEC_FL_NSEC3:
        {
            if((maintain_mode & ZDB_ZONE_MAINTAIN_NSEC3) == 0)
            {
                zdb_rr_label_flag_or(zone->apex, ZDB_RR_LABEL_NSEC3);
                zdb_rr_label_flag_and(zone->apex, ~(ZDB_RR_LABEL_NSEC | ZDB_RR_LABEL_NSEC3_OPTOUT));
                zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3);
                update_chain0 = TRUE;
            }
            break;
        }
        case ZONE_DNSSEC_FL_NSEC3_OPTOUT:
        {
            if((maintain_mode & ZDB_ZONE_MAINTAIN_NSEC3) == 0)
            {
                zdb_rr_label_flag_or(zone->apex, ZDB_RR_LABEL_NSEC3 | ZDB_RR_LABEL_NSEC3_OPTOUT);
                zdb_rr_label_flag_and(zone->apex, ~(ZDB_RR_LABEL_NSEC));
                zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT);
                update_chain0 = TRUE;
            }
            break;
        }
    }
    
    if(update_chain0)
    {
        zdb_zone_lock(zone, ZDB_ZONE_MUTEX_LOAD);
        nsec3_zone_update_chain0_links(zone);
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_LOAD);
    }
}

u8
zone_policy_guess_dnssec_type(zdb_zone *zone)
{
    u8 zone_dnssec_type = ZONE_DNSSEC_FL_NOSEC;
       
    if(zdb_zone_has_nsec_records(zone))
    {
        zone_dnssec_type = ZONE_DNSSEC_FL_NSEC;
    }
    else if(zdb_zone_has_nsec3_records(zone))
    {
        if(zdb_zone_has_nsec3_optout_chain(zone))
        {
            zone_dnssec_type = ZONE_DNSSEC_FL_NSEC3_OPTOUT;
        }
        else
        {
             zone_dnssec_type = ZONE_DNSSEC_FL_NSEC3;
        }
    }
    
    return zone_dnssec_type;
}

bool
zone_policy_key_suite_is_marked_processed(zone_desc_s *zone_desc, const struct dnssec_policy_key_suite *kr)
{
    mutex_lock(&zone_desc->lock);
    ptr_node *node = ptr_set_find(&zone_desc->dnssec_policy_processed_key_suites, kr->name);
    mutex_unlock(&zone_desc->lock);
    return node != NULL;
}

bool
zone_policy_key_suite_mark_processed(zone_desc_s *zone_desc, const struct dnssec_policy_key_suite *kr)
{
    bool ret = FALSE;
    mutex_lock(&zone_desc->lock);
    ptr_node *node = ptr_set_insert(&zone_desc->dnssec_policy_processed_key_suites, kr->name);

    if(node->value != NULL)
    {
        node->value = (struct dnssec_policy_key_suite*)kr;
        ret = TRUE;
    }
    mutex_unlock(&zone_desc->lock);
    return ret;
}

void
zone_policy_key_suite_unmark_processed(zone_desc_s *zone_desc, const struct dnssec_policy_key_suite *kr)
{
    mutex_lock(&zone_desc->lock);
    ptr_set_delete(&zone_desc->dnssec_policy_processed_key_suites, kr->name);
    mutex_unlock(&zone_desc->lock);
}

#endif

/** @} */
