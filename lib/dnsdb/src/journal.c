/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2017, EURid. All rights reserved.
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

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/** @brief Function ...
 *
 *  ...
 *
 *  @param ...
 *
 *  @retval OK
 *  @retval NOK
 */

#define ZDB_JOURNAL_CODE 1

#include "dnsdb/dnsdb-config.h"
#include <dnscore/dns_resource_record.h>
#include <dnscore/fdtools.h>
#include <dnscore/ptr_set.h>

#include "dnsdb/journal.h"
#include "dnsdb/journal_ix.h"
#include "dnsdb/journal-cjf.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/xfr_copy.h"
#include "dnsdb/zdb-zone-path-provider.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

//#define journal_default_open journal_ix_open
#define journal_default_open journal_cjf_open

/**
 * @note 20161028 edf -- this parameters tells how many dictionaries are can stay open when not used
 * 
 * This is an MRU so when a journal is released, instead of being completely flushed and closed, it is only flushed.
 * This parameter can be small for slow updates but should ideally set as "number of dynupdate-hammered zones + K"
 * 
 * Note that it keeps file descriptors open.
 * 
 */

#define MRU_SIZE_DEFAULT 128

static ptr_set journal_set = PTR_SET_DNSNAME_EMPTY;
static group_mutex_t journal_set_mtx = GROUP_MUTEX_INITIALIZER;
static mutex_t journal_mutex = MUTEX_INITIALIZER;


static list_dl_s journal_mru_list;
static mutex_t journal_mru_mtx = MUTEX_INITIALIZER;

static s32 journal_mru_size_max = 32;
static s32 journal_count = 0;
static bool journal_initialised = FALSE;

static inline void journal_mru_flag_set(journal *jh, bool value)
{
#ifdef DEBUG
    log_debug("journal: MRU: journal@%p setting flag from %i to %i", jh, jh->_mru, value);
#endif
    
    jh->_mru = value;
}

static inline bool journal_mru_flag_get(const journal *jh)
{
#ifdef DEBUG
    log_debug("journal: MRU: journal@%p flag is %i", jh, jh->_mru);
#endif
    
    return jh->_mru != 0;
}

static inline void journal_forget_flag_set(journal *jh, bool value)
{
#ifdef DEBUG
    log_debug("journal: journal@%p setting flag from %i to %i", jh, jh->_forget, value);
#endif
    
    jh->_forget = value;
}

static inline bool journal_forget_flag_get(const journal *jh)
{
#ifdef DEBUG
    log_debug("journal: journal@%p forget flag is %i", jh, jh->_forget);
#endif
    
    return jh->_forget != 0;
}

ya_result
journal_init(u32 mru_size)
{
    log_debug("journal: initialising with an MRU of %i slots", mru_size);
    
    if(!journal_initialised)
    {
        // initialises journal open/close access mutex (avoid creation/destruction races)
        // will be responsible for the journal file-descriptor resources allocation (closes least recently used journal when no more FDs are available)

        if(mru_size < 1)
        {
            mru_size = MRU_SIZE_DEFAULT;
        }
        
        journal_mru_size_max = mru_size;
        
        list_dl_init(&journal_mru_list);
        
        journal_initialised = TRUE;
    }
    else
    {
        log_debug("journal: already initialised");
    }
    
    return SUCCESS;
}

static void journal_mru_remove(journal *jh)
{
    if(journal_mru_flag_get(jh))
    {
        mutex_lock(&journal_mru_mtx); // safe
        
        list_dl_remove_node(&journal_mru_list, (list_dl_node_s*)&jh->mru_node);
        jh->mru_node.next = NULL;
        jh->mru_node.prev = NULL;
        
        journal_mru_flag_set(jh, FALSE);
        
        if(jh->zone != NULL)
        {
            log_debug("journal: %{dnsname}: MRU: journal@%p for zone@%p removed", jh->zone->origin, jh, jh->zone);
        }
        else
        {
            log_debug("journal: MRU: journal@%p removed", jh);
        }

        mutex_unlock(&journal_mru_mtx); // safe
    }
#ifdef DEBUG
    else
    {
        yassert(jh->mru_node.prev == NULL);
        yassert(jh->mru_node.next == NULL);
    }
#endif
}

/**
 * Must be called with the set locked
 * (checked)
 * 
 * called from journal_mru_enqueue(), when the size of the mru is too big
 * called from journal_mru_clear(), to clear the mru of its content
 */

static void journal_mru_close_last()
{
    list_dl_node_s *victim_node = list_dl_remove_last_node(&journal_mru_list);

    if(victim_node != NULL)
    {
        victim_node->next = NULL;
        victim_node->prev = NULL;

        journal *victim = (journal*)((u8*)victim_node - offsetof(journal, mru_node)); /* cast */
        
        u8 origin_buffer[MAX_DOMAIN_LENGTH];
        u8 *origin = NULL;
        
#ifdef DEBUG
        memcpy(origin_buffer, "\005BOGUS", 7);
#endif
        
        victim->vtbl->get_domain(victim, origin_buffer);
        
        log_debug("journal: %{dnsname}: MRU: journal@%p is being finalized", origin_buffer, victim);
        
        yassert(victim->rc == 0);
        
        log_debug("journal: %{dnsname}: MRU: journal@%p is being removed", origin_buffer, victim);

        yassert(victim->mru_node.next == NULL);
        
        ptr_node *node = ptr_set_avl_find(&journal_set, origin_buffer);
        if(node != NULL)
        {
            log_debug("journal: %{dnsname}: MRU: journal@%p is being removed from the set", origin_buffer, victim);
            
            origin = (u8*)node->key;
            ptr_set_avl_delete(&journal_set, origin_buffer);
            --journal_count;
        }
        
        if(origin != NULL)
        {
            dnsname_zfree(origin);
        }

        victim->vtbl->close(victim);        // allowed close
        victim->vtbl->destroy(victim);
        
        log_debug("journal: %{dnsname}: MRU: journal@%p finalized", origin_buffer, victim);
    }
    else
    {
        log_debug("journal: MRU: empty");
    }
}

/**
 * Must be called with the set locked
 * (checked)
 * 
 * called from journal_release(journal *jh), when a journal is not referenced anymore and could thus be closed ... soon
 */

static void journal_mru_enqueue(journal *jh)
{
    mutex_lock(&journal_mru_mtx);
    
    if(journal_mru_flag_get(jh))
    {
        list_dl_remove_node(&journal_mru_list, (list_dl_node_s*)&jh->mru_node);
        jh->mru_node.next = NULL;
        jh->mru_node.prev = NULL;
        
        journal_mru_flag_set(jh, FALSE);
    }
    
    list_dl_insert_node(&journal_mru_list, (list_dl_node_s*)&jh->mru_node);
    
    journal_mru_flag_set(jh, TRUE);
        
    if(jh->zone != NULL)
    {
        log_debug("journal: %{dnsname}: MRU: journal@%p for zone @%p added", jh->zone->origin, jh, jh->zone);
    }
    else
    {
        log_debug("journal: MRU: journal@%p added", jh);
    }
    
    while(list_dl_size(&journal_mru_list) > journal_mru_size_max)
    {
        log_debug("journal: MRU: size: %i/%i: closing oldest", list_dl_size(&journal_mru_list), journal_mru_size_max);
        
        journal_mru_close_last(); // set locked
    }
    
    log_debug("journal: MRU: size: %i/%i", list_dl_size(&journal_mru_list), journal_mru_size_max);
    
    mutex_unlock(&journal_mru_mtx);
}


/**
 * Must be called with the set locked
 * (checked)
 */

static void journal_mru_clear()
{
    log_debug("journal: MRU: clear");
    
    mutex_lock(&journal_mru_mtx);
    while(list_dl_size(&journal_mru_list) > 0)
    {
        journal_mru_close_last(); // set locked
    }
    mutex_unlock(&journal_mru_mtx);
}

void
journal_finalise()
{
    log_debug("journal: finalising");

    bool initialised = journal_initialised;
    journal_initialised = FALSE;
    
    if(initialised)
    {
        // remove the natural victims first
        

        for(;;)
        {
            group_mutex_lock(&journal_set_mtx, GROUP_MUTEX_WRITE);
            log_debug("journal: finalising: instances: %u", journal_count);
        
            journal_mru_clear(); // set locked
            
            bool empty = ptr_set_avl_isempty(&journal_set);

            group_mutex_unlock(&journal_set_mtx, GROUP_MUTEX_WRITE);
            
            if(empty)
            {
                break;
            }
            
            usleep(100000); // 0.1s
        }
        
        log_debug("journal: finalised");
        
#if DEBUG
        logger_flush();
#endif
    }
}

static ya_result
journal_acquire_from_fqdn_and_zone(journal **jhp, const u8 *origin, zdb_zone *zone, bool create)
{
    ya_result ret;
    char data_path[PATH_MAX];
    
    if(origin == NULL)
    {
        return ZDB_JOURNAL_WRONG_PARAMETERS;
    }
    
    group_mutex_lock(&journal_set_mtx, GROUP_MUTEX_WRITE); // MUST be a WRITE, not a double, not a read : a write
    
    ptr_node *node = ptr_set_avl_find(&journal_set, origin);
    if(node == NULL || node->value == NULL)
    {
        // the journal is not in the set
        
        u32 path_flags = ZDB_ZONE_PATH_PROVIDER_ZONE_PATH;
        if(create)
        {
            path_flags |= ZDB_ZONE_PATH_PROVIDER_MKDIR;
        }

        if(FAIL(ret = zdb_zone_path_get_provider()(origin, data_path, sizeof(data_path), path_flags)))
        {
            group_mutex_unlock(&journal_set_mtx, GROUP_MUTEX_WRITE);
            return ret;
        }
        
        if(FAIL(ret = journal_default_open(jhp, origin, data_path, create)))
        {
            group_mutex_unlock(&journal_set_mtx, GROUP_MUTEX_WRITE);
            return ret;
        }
        
        if(zone != NULL)
        {
            log_debug("journal: %{dnsname} new journal instance %p, linked to zone %p", origin, *jhp, zone);
            journal_link_zone(*jhp, zone);
        }
        else
        {
            log_debug("journal: %{dnsname}: new journal instance %p", origin, *jhp);
        }
        
        void *key = dnsname_zdup(origin);
        node = ptr_set_avl_insert(&journal_set, key);
        (*jhp)->rc = 1;       // nobody else has access yet, no point locking
        node->value = *jhp;
        ++journal_count;
        
        group_mutex_unlock(&journal_set_mtx, GROUP_MUTEX_WRITE);
    }
    else
    {
        int rc;
        mutex_lock(&journal_mutex); // in set write lock
        *jhp = (journal*)node->value;
        rc = ++(*jhp)->rc;
#ifdef DEBUG
        log_debug("journal: %{dnsname}: acquired: rc=%i (set)", origin, rc);
#endif
        mutex_unlock(&journal_mutex); // in set write lock
        
        log_debug("journal: %{dnsname}: got journal instance %p, rc=%i", origin, *jhp, rc);
        
        journal_mru_remove(*jhp);
        
        group_mutex_unlock(&journal_set_mtx, GROUP_MUTEX_WRITE);
        
        // the journal is not candidate for being closed anymore
        
        // at this point the journal has been found, removed from the MRU, and reference-counted
        
        // but the file may be closed (if we were in the MRU) so ...
        
        if(ISOK(ret = (*jhp)->vtbl->reopen(*jhp)))
        {
            // bind with the zone, if it was passed
            
            if(zone != NULL)
            {
                journal_link_zone(*jhp, zone);
            }
            
            // done
        }
        else
        {
            log_warn("journal: %{dnsname}: could not reopen the journal file: %r", origin, ret);
            // no journal file found, although it was in the set
            // it may have been deleted manually
            // there may be not enough file descriptors available in the system

            // no recovery from this state
            // dereference (release) and return an error

            journal_release(*jhp);
            *jhp = NULL;
        }
    }
    
    return ret;
}

ya_result
journal_acquire_from_fqdn_ex(journal **jhp, const u8 *origin, bool create)
{
    ya_result ret = journal_acquire_from_fqdn_and_zone(jhp, origin, NULL, create);
    return ret;
}

ya_result
journal_acquire_from_fqdn(journal **jhp, const u8 *origin)
{
    ya_result ret = journal_acquire_from_fqdn_ex(jhp, origin, FALSE);
    return ret;
}

/**
 * 
 * Opens the journal for a zone
 * 
 * Binds the journal to the zone (?)
 * 
 * Increments the reference count to the journal
 * 
 * @param jhp
 * @param zone
 * @param workingdir
 * @param create
 * @return 
 */

ya_result
journal_acquire_from_zone_ex(journal **jhp, zdb_zone *zone, bool create)
{
    ya_result ret = SUCCESS;
    
    yassert((jhp != NULL) && (zone != NULL));
    
    // DO NOT zdb_zone_acquire(zone);
    
    log_debug("journal: %{dnsname}: opening journal for zone @%p", zone->origin, zone);
    
    *jhp = NULL;
    ret = journal_acquire_from_fqdn_and_zone(jhp, zone->origin, zone, create);
    
    return ret;
}

ya_result
journal_acquire_from_zone(journal **jhp, zdb_zone *zone)
{
    ya_result ret = journal_acquire_from_zone_ex(jhp, zone, FALSE);
    return ret;
}

void
journal_acquire(journal *jh)
{
    mutex_lock(&journal_mutex); // journal already acquired, set is safe
    yassert(jh->rc > 0);
#ifdef DEBUG
    int rc =
#endif
    ++jh->rc;
#ifdef DEBUG
    u8 origin_buffer[MAX_DOMAIN_LENGTH];
    jh->vtbl->get_domain(jh, origin_buffer);
    log_debug("journal: %{dnsname}: acquired: rc=%i", origin_buffer, rc);
#endif
    mutex_unlock(&journal_mutex); // journal already acquired, set is safe
}

/**
 * Closes the journal
 * 
 * @param jh
 */

void
journal_release(journal *jh)
{
    if(jh != NULL)
    {
        group_mutex_lock(&journal_set_mtx, GROUP_MUTEX_WRITE);
        
        mutex_lock(&journal_mutex); // in set write lock
        
        yassert(jh->rc > 0);
        
        
#ifdef DEBUG
        int rc = --jh->rc;        
        bool not_used = (rc == 0);
        
        u8 origin_buffer[MAX_DOMAIN_LENGTH];
        jh->vtbl->get_domain(jh, origin_buffer);
        log_debug("journal: %{dnsname}: released: rc=%i", origin_buffer, rc);
#else
        bool not_used = (--jh->rc) == 0;
#endif
        
        mutex_unlock(&journal_mutex); // in set write lock
        
        if(not_used)
        {
            yassert(jh->rc == 0);
            
            // the journal is candidate for closing
            
            if(jh->zone != NULL)
            {
                log_debug("journal: %{dnsname}: closing journal@%p for zone@%p", jh->zone->origin, jh, jh->zone);
            }
            else
            {
                log_debug("journal: closing journal@%p", jh);
            }

            yassert(journal_count >= 0);
            
            jh->vtbl->flush(jh);
            
            if(!journal_forget_flag_get(jh))
            {
                log_debug("journal: enqueuing journal@%p to MRU", jh);
                journal_mru_enqueue(jh); // set locked, close later
            }
            else
            {
                log_debug("journal: closing journal@%p", jh);
                
                u8 origin_buffer[MAX_DOMAIN_LENGTH];        
                jh->vtbl->get_domain(jh, origin_buffer);
        
                ptr_set_avl_delete(&journal_set, origin_buffer);
                
                jh->vtbl->close(jh);
                jh->vtbl->destroy(jh);
            }
        }
        
        group_mutex_unlock(&journal_set_mtx, GROUP_MUTEX_WRITE);
    }
    else
    {
        //log_debug("journal: close called on a NULL journal");
    }
}

/**
 * 
 * Returns the last serial stored in a file.
 * 
 * Opens the journal file based on the fqdn.
 * Reads the serial.
 * Closes the journal.
 * 
 * @param origin
 * @param workingdir
 * @param serialp
 * @return 
 */

ya_result
journal_last_serial(const u8 *origin, u32 *serialp)
{
    journal *jh = NULL;
    ya_result ret;

    if(ISOK(ret = journal_acquire_from_fqdn(&jh, origin)))
    {
        ret = journal_get_last_serial(jh, serialp);

        journal_release(jh);
    }
    
    return ret;
}

ya_result
journal_serial_range(const u8 *origin, u32 *serialfromp, u32 *serialtop)
{
    journal *jh = NULL;
    ya_result ret;

    if(ISOK(ret = journal_acquire_from_fqdn(&jh, origin)))
    {
        ret = journal_get_serial_range(jh, serialfromp, serialtop);

        journal_release(jh);
    }
    
    return ret;
}

/**
 * 
 * Reduces the size of the journal to 0.
 * 
 * Opens the journal file based on the fqdn.
 * Truncates the journal
 * Closes the journal.
 * 
 * Opens the journal file based on the fqdn.
 * Reads the serial.
 * Closes the journal.
 * 
 * @param origin
 * @param workingdir
 * @return 
 */

ya_result
journal_truncate(const u8 *origin)
{
    journal *jh = NULL;
    ya_result ret;
    
    if(ISOK(ret = journal_acquire_from_fqdn(&jh, origin)))
    {
        ret = journal_truncate_to_size(jh, 0);
        journal_forget_flag_set(jh, TRUE);
        
        // if a journal file has been completely been emptied, then it should
        // be fully closed too
        
        journal_release(jh);
    }
#ifdef DEBUG
    else
    {
        log_debug("journal_truncate(%{dnsname}) failed with %r", origin, ret);
    }
#endif
    
    return ret;
}

/**
 * 
 * Returns the last SOA TTL + RDATA 
 * 
 * Opens the journal file based on the fqdn.
 * Reads the SOA.
 * Closes the journal.
 * 
 * @param origin
 * @param workingdir
 * @param serial
 * @param ttl
 * @param last_soa_rdata
 * @param last_soa_rdata_size
 * @return 
 */

ya_result
journal_last_soa(const u8 *origin, u32 *serial, u32 *ttl, u8 *last_soa_rdata, u16 *last_soa_rdata_size)
{
    journal *jh = NULL;
    ya_result ret;
    
    if(ISOK(ret = journal_acquire_from_fqdn(&jh, origin)))
    {
        input_stream is;
        u32 first_serial = 0;
        u32 last_serial = 0;
        u16 last_soa_rdata_size_store;
        
        dns_resource_record rr;

        if(last_soa_rdata_size == NULL)
        {
            last_soa_rdata_size = &last_soa_rdata_size_store;
        }
        
        journal_get_first_serial(jh, &first_serial);
        journal_get_last_serial(jh, &last_serial);
        
        if(first_serial != last_serial)
        {
            dns_resource_record_init(&rr);
            
            if(ISOK(ret = journal_get_ixfr_stream_at_serial(jh, first_serial, &is, &rr)))
            {
                if(last_soa_rdata_size != NULL)
                {
                    *last_soa_rdata_size = rr.rdata_size;
                    
                    if((last_soa_rdata != NULL) && (*last_soa_rdata_size >= rr.rdata_size))
                    {
                        MEMCOPY(last_soa_rdata, rr.rdata, rr.rdata_size);
                    }
                }

                if(serial != NULL)
                {
                    if(rr.rdata_size > 0)
                    {
                        ret = rr_soa_get_serial(rr.rdata, rr.rdata_size, serial);
                    }
                    else
                    {
                        log_err("jnl: %{dnsname}: empty last SOA in journal [%u;%u]", origin, first_serial, last_serial);
                    }
                }

                if(ttl != NULL)
                {
                    *ttl = htonl(rr.tctr.ttl);
                }
                
                input_stream_close(&is);
            }
            
            dns_resource_record_clear(&rr);
        }

        journal_release(jh);
    }
    
    return ret;
}

/**
 * Flushes, closes and destroys all currently unused journals (from memory)
 */

void
journal_close_unused()
{
    group_mutex_lock(&journal_set_mtx, GROUP_MUTEX_WRITE);
    journal_mru_clear(); // set locked
    group_mutex_unlock(&journal_set_mtx, GROUP_MUTEX_WRITE);
}

/**
 * 
 * Prints the status of the journal (mostly the ones in the MRU) to the logger.
 * 
 */

void
journal_log_status()
{
}

/** @} */
