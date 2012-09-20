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
* DOCUMENTATION */
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
#include <string.h>
#include <arpa/inet.h>		/* or netinet/in.h */

#include <dnscore/format.h>
#include <dnscore/logger.h>
#include <dnscore/mutex.h>

#include "server.h"
#include "zone.h"
#include "server_error.h"
#include "config_error.h"
#include "wrappers.h"

#define ZONEDATA_TAG 0x41544144454e4f5a
#define ZDORIGIN_TAG 0x4e494749524f445a

/*
 * 2011/10/18 : EDF: disabling the debug because it makes the legitimate error output unreadable.
 */

#undef DEBUGLNF
#undef DEBUGF
#undef OSDEBUG
#undef LDEBUG
#undef OSLDEBUG
#define DEBUGLNF(...)
#define DEBUGF(...)
#define OSDEBUG(...)
#define LDEBUG(...)
#define OSLDEBUG(...)

#ifndef NAME_MAX
#define NAME_MAX 1024
#endif

#define MODULE_MSG_HANDLE g_server_logger

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

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

zone_data *
zone_alloc()
{
    zone_data *zone_desc;

    /* Alloc & clear zone_data structure */
    MALLOC_OR_DIE(zone_data*, zone_desc, sizeof (zone_data), ZONEDATA_TAG);
    ZEROMEMORY(zone_desc, sizeof(zone_data));
    
    zone_desc->qclass = CLASS_IN;
    
    smp_int_init(&zone_desc->is_saving_as_text);
    
    return zone_desc;
}

/** \brief
 *  Frees a zone data
 *
 *  @param[in] src is a * to the zone data
 */

zone_data *
zone_clone(zone_data *zone_setup)
{
    zone_data *clone = zone_alloc();
    
    memcpy(clone, zone_setup, sizeof(zone_data));
    
    clone->masters = host_address_copy_list(zone_setup->masters);
    clone->notifies = host_address_copy_list(zone_setup->notifies);
    
    /*
    acl_unmerge_access_control(&zone_setup->ac, &g_config->ac);
    acl_empties_access_control(&zone_setup->ac);
    */
    
    /* Free memory */
    clone->domain = strdup(zone_setup->domain);
    clone->file_name = strdup(zone_setup->file_name);
    clone->origin = dnsname_dup(zone_setup->origin);
    
    return clone;
}

void
zone_free(zone_data *zone_setup)
{
    if(zone_setup != NULL)
    {
        host_address_delete_list(zone_setup->masters);
        zone_setup->masters = NULL;

        host_address_delete_list(zone_setup->notifies);
        zone_setup->notifies = NULL;

        acl_unmerge_access_control(&zone_setup->ac, &g_config->ac);
        acl_empties_access_control(&zone_setup->ac);

        /* Free memory */
        free(zone_setup->domain);
        free(zone_setup->file_name);
        free(zone_setup->origin);
        
        mutex_destroy(&zone_setup->lock);

#ifndef NDEBUG
        memset(zone_setup, 0xff, sizeof(zone_data));
#endif
        free(zone_setup);
    }
}

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
        zone_set_lock(dset);
        
        treeset_avl_iterator iter;
        treeset_avl_iterator_init(&dset->set, &iter);
        
        while(treeset_avl_iterator_hasnext(&iter))
        {
            treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
            zone_data *zone_desc = (zone_data*)zone_node->data;

            if(zone_desc != NULL)
            {
                if(ISOK(zone_set_obsolete(zone_desc, ZONE_LOCK_UNREGISTER)))
                {
                    if(ISOK(zone_lock(zone_desc, ZONE_LOCK_UNREGISTER)))
                    {
                        // in theory, here, status should be idle
                        zone_free(zone_desc);
                    }
                }
            }
        }

        treeset_avl_destroy(&dset->set);
        
        zone_set_unlock(dset);
        
        mutex_destroy(&dset->lock);
    }
}

/**
 * Adds the zone in the collection (if it's not there already)
 * The zone must have at least it's domain set
 */

ya_result
zone_register(zone_data_set *dset, zone_data *zone_desc)
{
    if(zone_desc->origin == NULL)
    {
        if(zone_desc->domain == NULL)
        {
            log_err("config: zone: ?: no domain set (not loaded)", zone_desc->domain);

            return DATABASE_ZONE_MISSING_DOMAIN;
        }
        
        char *p = zone_desc->domain;
        while(*p != 0)
        {
            *p = tolower(*p);
            
            p++;
        }

        MALLOC_OR_DIE(u8*, zone_desc->origin, strlen(zone_desc->domain) + 2, ZDORIGIN_TAG);
        
        ya_result return_code;

        if(FAIL(return_code = cstr_to_dnsname(zone_desc->origin, zone_desc->domain)))
        {
            free(zone_desc->origin);
            zone_desc->origin = NULL;

            log_err("config: zone: %s: invalid domain (not loaded)", zone_desc->domain);

            return return_code;
        }
    }
    
    zone_set_lock(dset);
    
    if(treeset_avl_find(&dset->set, zone_desc->origin) != NULL)
    {
        zone_set_unlock(dset);
        
        // already
        log_err("zone: the zone %{dnsname} has already been set", zone_desc->origin);
        
        free(zone_desc->origin);
        zone_desc->origin = NULL;
        
        return DATABASE_ZONE_CONFIG_DUP;
    }
    
    if(zone_desc->type == ZT_SLAVE)
    {
        /**
        * @todo Check that the master is single and is NOT a link to one of the listen addresses of the server
        *       This could trigger a deadlock (zone needs to be "locked" at the same time for read+write-blocked
        *       and for write.)
        */
        if(zone_desc->masters == NULL /* || address_matched(zone_desc->masters, g_config->listen, g_config->port) */)
        {
            zone_set_unlock(dset);
            
            log_err("config: zone: %s: slave zone without master field (not loaded)", zone_desc->domain);

            free(zone_desc->origin);
            zone_desc->origin = NULL;

            return DATABASE_ZONE_MISSING_MASTER;
        }
    }

    ya_result return_value;

    treeset_node *node = treeset_avl_insert(&dset->set, zone_desc->origin);

    if(node->data == NULL)
    {
        log_info("zone: the zone %{dnsname} has been registered", zone_desc->origin);

        node->data = zone_desc;

        return_value = SUCCESS;
    }
    else
    {
        // already
        log_err("zone: the zone %{dnsname} has already been set", zone_desc->origin);

        free(zone_desc->origin);
        zone_desc->origin = NULL;

        return_value = DATABASE_ZONE_CONFIG_DUP;
    }

    zone_set_unlock(dset);
    
    return return_value;
}

/**
 * Removes the zone with the given origin from the collection.
 * Returns a pointer to the zone. (The caller may destroy it if
 * he wants)
 */

zone_data *
zone_unregister(zone_data_set *dset, u8 *origin)
{
    zone_data *zone_desc = NULL;

    zone_set_lock(dset);
    
    treeset_node *node = treeset_avl_find(&dset->set, origin);
    
    if(node != NULL)
    {
        zone_desc = (zone_data*)node->data;

        if(zone_desc != NULL)
        {
            if(ISOK(zone_set_obsolete(zone_desc, ZONE_LOCK_UNREGISTER)))
            {
                treeset_avl_delete(&dset->set, origin);
            }
        }
    }
    
    zone_set_unlock(dset);

    return zone_desc;
}

void
zone_set_lock(zone_data_set *dset)
{
    mutex_lock(&dset->lock);
}

void
zone_set_unlock(zone_data_set *dset)
{
    mutex_unlock(&dset->lock);
}

zone_data *
zone_getbydnsname(const u8 *name)
{
    zone_data *zone_desc = NULL;
    
    zone_set_lock(&g_config->zones);
    
    treeset_node *zone_node = treeset_avl_find(&g_config->zones.set, name);

    if(zone_node != NULL)
    {
        zone_desc = (zone_data*)zone_node->data;
    }
    
    zone_set_unlock(&g_config->zones);
    
    return zone_desc;
}

zone_data *
zone_getdynamicbydnsname(const u8 *name)
{
    zone_data *zone_desc = NULL;
    
    zone_set_lock(&g_config->dynamic_zones);
    
    treeset_node *zone_node = treeset_avl_find(&g_config->dynamic_zones.set, name);

    if(zone_node != NULL)
    {
        zone_desc = (zone_data*)zone_node->data;
    }
    
    zone_set_unlock(&g_config->dynamic_zones);
    
    return zone_desc;
}

void
zone_setmodified(zone_data *zone_desc, bool v)
{
    const u8 mask = ZONE_STATUS_MODIFIED;
    
    if(v)
    {
        zone_desc->status_flag |= mask;
    }
    else
    {
        zone_desc->status_flag &= ~mask;
    }
}

void
zone_setloading(zone_data *zone_desc, bool v)
{
    const u8 mask = ZONE_STATUS_LOADING;
    
    if(v)
    {
        zone_desc->status_flag |= mask;
    }
    else
    {
        zone_desc->status_flag &= ~mask;
    }
}

void
zone_setmustsavefile(zone_data *zone_desc, bool v)
{
    const u8 mask = ZONE_STATUS_SAVETO_ZONE_FILE;
    
    if(v)
    {
        zone_desc->status_flag |= mask;
    }
    else
    {
        zone_desc->status_flag &= ~mask;
    }
}

void
zone_setmustsaveaxfr(zone_data *zone_desc, bool v)
{
    const u8 mask = ZONE_STATUS_SAVETO_AXFR_FILE;
    
    if(v)
    {
        zone_desc->status_flag |= mask;
    }
    else
    {
        zone_desc->status_flag &= ~mask;
    }
}

void
zone_setsavingfile(zone_data *zone_desc, bool v)
{
    const u8 mask = ZONE_STATUS_SAVING_ZONE_FILE;
    
    if(v)
    {
        zone_desc->status_flag |= mask;
    }
    else
    {
        zone_desc->status_flag &= ~mask;
    }
}

void
zone_setsavingaxfr(zone_data *zone_desc, bool v)
{
    const u8 mask = ZONE_STATUS_SAVING_AXFR_FILE;
    
    if(v)
    {
        zone_desc->status_flag |= mask;
    }
    else
    {
        zone_desc->status_flag &= ~mask;
    }
}

void
zone_setstartingup(zone_data *zone_desc, bool v)
{
    const u8 mask = ZONE_STATUS_STARTING_UP;
    
    if(v)
    {
        zone_desc->status_flag |= mask;
    }
    else
    {
        zone_desc->status_flag &= ~mask;
    }
}

bool
zone_isidle(zone_data *zone_desc)
{
    return zone_desc->status_flag == 0;
}

bool
zone_ismodified(zone_data *zone_desc)
{
    return ((zone_desc->status_flag & ZONE_STATUS_MODIFIED) != 0);
}

bool
zone_isloading(zone_data *zone_desc)
{
    return ((zone_desc->status_flag & ZONE_STATUS_LOADING) != 0);
}

bool
zone_mustsavefile(zone_data *zone_desc)
{
    return ((zone_desc->status_flag & ZONE_STATUS_SAVETO_ZONE_FILE) != 0);
}

bool
zone_mustsaveaxfr(zone_data *zone_desc)
{
    return ((zone_desc->status_flag & ZONE_STATUS_SAVETO_AXFR_FILE) != 0);
}

bool
zone_issavingfile(zone_data *zone_desc)
{
    return ((zone_desc->status_flag & ZONE_STATUS_SAVING_ZONE_FILE) != 0);
}

bool
zone_issavingaxfr(zone_data *zone_desc)
{
    return ((zone_desc->status_flag & ZONE_STATUS_SAVING_AXFR_FILE) != 0);
}

bool
zone_isstartingup(zone_data *zone_desc)
{
    return ((zone_desc->status_flag & ZONE_STATUS_STARTING_UP) != 0);
}

bool
zone_isdynamicupdating(zone_data *zone_desc)
{
    return ((zone_desc->status_flag & ZONE_STATUS_DYNAMIC_UPDATING) != 0);
}
 
bool
zone_canbeedited(zone_data *zone_desc)
{
    return ((zone_desc->status_flag & (ZONE_STATUS_STARTING_UP|ZONE_STATUS_DYNAMIC_UPDATING|ZONE_STATUS_SAVING_AXFR_FILE|ZONE_STATUS_SAVING_ZONE_FILE|ZONE_STATUS_LOADING)) == 0);
}

ya_result
zone_set_obsolete(zone_data *zone, u8 destroyer_mark)
{
    ya_result return_value = ERROR;
    
    mutex_lock(&zone->lock);
    
    if(zone->obsolete_owner == 0)
    {
        zone->obsolete_owner = destroyer_mark;
        return_value = destroyer_mark;
    }
    
    mutex_unlock(&zone->lock);
    
    return return_value;
}

bool
zone_is_obsolete(zone_data *zone)
{
    bool r;
    
    mutex_lock(&zone->lock);
    
    r = (zone->obsolete_owner != 0);
    
    mutex_unlock(&zone->lock);
    
    return r;
}

ya_result zone_try_lock(zone_data *zone, u8 owner_mark)
{
    ya_result return_value = ERROR;
    
    mutex_lock(&zone->lock);
    
    if((zone->obsolete_owner == 0) || (zone->obsolete_owner == owner_mark))
    {    
        if((zone->lock_owner == 0) || (zone->lock_owner == owner_mark))
        {
            zone->lock_owner = owner_mark;
        }
        
        return_value = zone->lock_owner;
    }
    
    mutex_unlock(&zone->lock);
    
    return return_value;
}

ya_result zone_lock(zone_data *zone, u8 owner_mark)
{
    ya_result return_value = ERROR;
        
    mutex_lock(&zone->lock);
    
    while((zone->obsolete_owner == 0) || (zone->obsolete_owner == owner_mark))
    {    
        if((zone->lock_owner == 0) || (zone->lock_owner == owner_mark))
        {
            zone->lock_owner = owner_mark;
            return_value = owner_mark;
            break;
        }
        
        usleep(1000);
    }
    
    mutex_unlock(&zone->lock);
    
    return return_value;
}

ya_result zone_unlock(zone_data *zone, u8 owner_mark)
{
    ya_result return_value = ERROR;
    
    mutex_lock(&zone->lock);
    
    if(zone->lock_owner == owner_mark)
    {
        zone->lock_owner = 0;
        return_value = owner_mark;
    }
    
    mutex_unlock(&zone->lock);
    
    return return_value;
}

void zone_setdefaults(zone_data *zone)
{   
    u32 port;
        
    if(FAIL(parse_u32_check_range(g_config->server_port, &port, 1, MAX_U16, 10)))
    {
        port = DNS_DEFAULT_PORT;
    }
    
    zone->status_flag = ZONE_STATUS_STARTING_UP;
    
#if HAS_ACL_SUPPORT == 1
    acl_merge_access_control(&zone->ac, &g_config->ac);
#endif

#if HAS_DNSSEC_SUPPORT != 0

    /*
     * The newly generated signatures will be valid for that amount of days
     */

    if(zone->sig_validity_interval == MAX_S32)
    {
        zone->sig_validity_interval = MIN(g_config->sig_validity_interval, SIGNATURE_VALIDITY_INTERVAL_MAX);  /* days */
    }

    if(zone->sig_validity_regeneration == MAX_S32)
    {
        zone->sig_validity_regeneration = MIN(g_config->sig_validity_regeneration, SIGNATURE_VALIDITY_REGENERATION_MAX);
    }

    /*
     * The validity of newly generated signature will be off by at most this
     */

    if(zone->sig_validity_jitter == MAX_S32)
    {
        zone->sig_validity_jitter = MIN(g_config->sig_validity_jitter, SIGNATURE_VALIDITY_JITTER_MAX);
    }
    
    /*
     * The first epoch when a signature will be marked as invalid.
     */
    

    zone->scheduled_sig_invalid_first = MAX_S32;
#endif

    host_set_default_port_value(zone->masters, ntohs(port));
    host_set_default_port_value(zone->notifies, ntohs(port));
}

void
zone_print_all(zone_data_set *dset, const char *text, u8 flag, output_stream* fd)
{
    osformatln(fd, "ZONE FILES      :");
    osformatln(fd, "-----------------");

    zone_set_lock(dset);
    
    if(!treeset_avl_isempty(&dset->set))
    {        
        treeset_avl_iterator iter;
        treeset_avl_iterator_init(&dset->set, &iter);

        while(treeset_avl_iterator_hasnext(&iter))
        {
            treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
            zone_data *zone_desc = (zone_data*)zone_node->data;

            zone_print(zone_desc, text, flag, fd);
        }
        
        zone_set_unlock(dset);
    }
    else
    {
        zone_set_unlock(dset);
        
        osformatln(fd, "%s no zone files", text);
    }
}

void
zone_print(const zone_data *src, const char *text, u8 flag, output_stream *fd)
{
    if(flag & ZONE_NAME)
    {

        if(src == NULL)
        {
            osformat(fd, "%s no zone files\n", text);
        }

        if(src->domain != NULL)
        {
            osformat(fd, "DOMAIN          : %s\n", src->domain);
        }
        if(src->file_name != NULL)
        {
            osformat(fd, "FILENAME        : %s\n", src->file_name);
        }
    }

    if(flag & ZONE_TYPE)
    {
        switch(src->type)
        {
            case ZT_HINT:
                osformat(fd, "TYPE            : %s\n", ZT_STRING_HINT);
                break;
            case ZT_MASTER:
                osformat(fd, "TYPE            : %s\n", ZT_STRING_MASTER);
                /*list_print((*src).masters, "MASTER          : ", termout);*/
                break;
            case ZT_SLAVE:
                osformat(fd, "TYPE            : %s\n", ZT_STRING_SLAVE);
                /*list_print((*src).notifies, "NOTIFY          : ", termout);*/
                break;
            case ZT_STUB:
                osformat(fd, "TYPE            : %s\n", ZT_STRING_STUB);
                break;
            default:
                osformat(fd, "TYPE            : %s\n", ZT_STRING_UNKNOWN);
        }
    }

    if(flag & ZONE_GLOBAL_RR)
    {
        if(src->origin != NULL)
        {
            osformat(fd, "G_ORIGIN : %{dnsname}\n", src->origin);
        }

        osformat(fd, "G_CLASS  : %lu\n", src->qclass);
    }
}

const char* type_to_name[5] =
{
    "hint",
    "master",
    "slave",
    "stub"
};


const char*
zone_type_to_name(zone_type t)
{
    if((t >= ZT_HINT) && (t <= ZT_STUB))
    {
        return type_to_name[t];
    }
    
    return "invalid";
}

/** @} */

/*----------------------------------------------------------------------------*/
