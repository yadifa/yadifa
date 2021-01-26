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
#include <dnscore/packet_writer.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/rfc.h>

#include "dnsdb/journal.h"
//#include "dnsdb/journal_ix.h"
//#include "dnsdb/journal-cjf.h"
#include "dnsdb/journal-jnl.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/xfr_copy.h"
#include "dnsdb/zdb-zone-path-provider.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

//#define journal_default_open journal_ix_open

/*
#define journal_default_open journal_cjf_open
#define journal_default_finalize journal_cjf_finalize
*/

#define journal_default_open journal_jnl_open
#define journal_default_finalize journal_jnl_finalize

#ifndef JOURNAL_DEBUG
#if DEBUG
#define JOURNAL_DEBUG 1
#else
#define JOURNAL_DEBUG 0
#endif
#endif

#define JOURNAL_DEBUG_TTY 0

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

static u32 journal_mru_size_max = 32;
static s32 journal_count = 0;
static bool journal_initialised = FALSE;

static inline void
journal_mru_flag_set(journal *jh, bool value)
{
#if JOURNAL_DEBUG
    log_debug("journal: %{dnsname}: MRU: journal@%p setting flag from %i to %i", journal_get_domain_const(jh), jh, jh->_mru, value);
#endif
    
    jh->_mru = value;
}

static inline bool
journal_mru_flag_get(const journal *jh)
{
#if JOURNAL_DEBUG
    log_debug("journal: %{dnsname}: MRU: journal@%p flag is %i", journal_get_domain_const(jh), jh, jh->_mru);
#endif
    
    return jh->_mru != 0;
}

static inline void
journal_forget_flag_set(journal *jh, bool value)
{
#if JOURNAL_DEBUG
    log_debug("journal: %{dnsname}: journal@%p forget flag set from %i to %i", journal_get_domain_const(jh), jh, (int)jh->_forget, (int)value);
#endif
    
    jh->_forget = value;
}

static inline bool
journal_forget_flag_get(const journal *jh)
{
#if JOURNAL_DEBUG
    log_debug("journal: %{dnsname}: journal@%p forget flag is %i", journal_get_domain_const(jh), jh, (int)jh->_forget);
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

static void
journal_mru_remove(journal *jh)
{
    if(journal_mru_flag_get(jh))
    {
        mutex_lock(&journal_mru_mtx); // safe
        
        list_dl_remove_node(&journal_mru_list, (list_dl_node_s*)&jh->mru_node);
        jh->mru_node.next = NULL;
        jh->mru_node.prev = NULL;
        
        journal_mru_flag_set(jh, FALSE);

        log_debug("journal: %{dnsname}: MRU: journal@%p removed", journal_get_domain_const(jh), jh);

        mutex_unlock(&journal_mru_mtx); // safe
    }
#if JOURNAL_DEBUG
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

static void
journal_mru_close_last_nolock() // journal_mru_mtx must be locked;
{
    list_dl_node_s *victim_node = list_dl_remove_last_node(&journal_mru_list);

    if(victim_node != NULL)
    {
        victim_node->next = NULL;
        victim_node->prev = NULL;

        journal *victim = (journal*)((u8*)victim_node - offsetof(journal, mru_node)); /* cast */
        
        u8 origin_buffer[MAX_DOMAIN_LENGTH];
        u8 *origin = NULL;
        
#if JOURNAL_DEBUG
        memcpy(origin_buffer, "\005BOGUS", 7);
#endif
        
        victim->vtbl->get_domain(victim, origin_buffer);
        
        log_debug("journal: %{dnsname}: MRU: journal@%p is being finalized", origin_buffer, victim);
        
        yassert(victim->rc == 0);
        
        log_debug("journal: %{dnsname}: MRU: journal@%p is being removed", origin_buffer, victim);

        yassert(victim->mru_node.next == NULL);
        
        ptr_node *node = ptr_set_find(&journal_set, origin_buffer);
        if(node != NULL)
        {
            if(node->value == victim)
            {
                log_debug("journal: %{dnsname}: MRU: journal@%p is being removed from the set", origin_buffer, victim);
                
                origin = (u8*)node->key;
                ptr_set_delete(&journal_set, origin_buffer);
                --journal_count;
            }
            else
            {
                log_debug("journal: %{dnsname}: MRU: journal@%p was not in the set (another instance was)", origin_buffer, victim);
            }
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

static void
journal_mru_enqueue(journal *jh)
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
        
    log_debug("journal: %{dnsname}: MRU: journal@%p added", journal_get_domain_const(jh), jh);
    
    while(list_dl_size(&journal_mru_list) > journal_mru_size_max)
    {
        log_debug("journal: %{dnsname}: MRU: size: %i/%i: closing oldest", journal_get_domain_const(jh), list_dl_size(&journal_mru_list), journal_mru_size_max);
        
        journal_mru_close_last_nolock(); // set locked
    }
    
    log_debug("journal: %{dnsname}: MRU: size: %i/%i", journal_get_domain_const(jh), list_dl_size(&journal_mru_list), journal_mru_size_max);
    
    mutex_unlock(&journal_mru_mtx);
}


/**
 * Must be called with the set locked
 * (checked)
 */

static void
journal_mru_clear()
{
    log_debug("journal: MRU: clear");
    
    mutex_lock(&journal_mru_mtx);
    while(list_dl_size(&journal_mru_list) > 0)
    {
        journal_mru_close_last_nolock(); // set locked
    }
    mutex_unlock(&journal_mru_mtx);
}

void
journal_finalize()
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
            
            bool empty = ptr_set_isempty(&journal_set);

            if(empty)
            {
                break;
            }
            
            usleep(100000); // 0.1s
        }
        
        log_debug("journal: finalised");

        journal_default_finalize();
        
#if JOURNAL_DEBUG
        logger_flush();
#endif
    }
}

static ya_result
journal_acquire_from_fqdn_and_zone(journal **jhp, const u8 *origin, zdb_zone *zone, bool create)
{
    ya_result ret;
    char data_path[PATH_MAX];
    
#if JOURNAL_DEBUG
    log_debug3("journal_acquire_from_fqdn_and_zone(%p, %{dnsname}, %p, %i)", jhp, origin, zone, (int)create);
#endif
    
    if(origin == NULL)
    {
        log_err("journal_acquire_from_fqdn_and_zone(%p, NULL, %p, %i) failed: %r", jhp, zone, (int)create, ZDB_JOURNAL_WRONG_PARAMETERS);
        
        return ZDB_JOURNAL_WRONG_PARAMETERS;
    }
    
    group_mutex_lock(&journal_set_mtx, GROUP_MUTEX_WRITE); // MUST be a WRITE, not a double, not a read : a write
    
    ptr_node *node = ptr_set_find(&journal_set, origin);
    
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
#if JOURNAL_DEBUG
            log_debug3("journal_acquire_from_fqdn_and_zone(%p, %{dnsname}, %p, %i) failed: %r", jhp, origin, zone, (int)create, ret);
#endif
            return ret;
        }
        
        if(FAIL(ret = journal_default_open(jhp, origin, data_path, create)))
        {
            group_mutex_unlock(&journal_set_mtx, GROUP_MUTEX_WRITE);
#if JOURNAL_DEBUG
            log_debug3("journal_acquire_from_fqdn_and_zone(%p, %{dnsname}, %p, %i) failed: %r", jhp, origin, zone, (int)create, ret);
#endif
            return ret;
        }
        
        log_debug3("journal: %{dnsname}: new journal instance %p", origin, *jhp);
        
        void *key = dnsname_zdup(origin);
        node = ptr_set_insert(&journal_set, key);
        (*jhp)->rc = 1;       // nobody else has access yet, no point locking
        node->value = *jhp;
        ++journal_count;
        
        group_mutex_unlock(&journal_set_mtx, GROUP_MUTEX_WRITE);

#if JOURNAL_DEBUG_TTY
        formatln("%{dnsname} %i -> %i (first acquire with fqdn)", journal_get_domain_const((*jhp)), (*jhp)->rc - 1, (*jhp)->rc);
        debug_stacktrace_print(termout, debug_stacktrace_get());
#endif
    }
    else
    {
        int rc;
        mutex_lock(&journal_mutex); // in set write lock
        *jhp = (journal*)node->value;

#if JOURNAL_DEBUG_TTY
        formatln("%{dnsname} %i -> %i (acquire with fqdn)", journal_get_domain_const((*jhp)), (*jhp)->rc, (*jhp)->rc + 1);
        debug_stacktrace_print(termout, debug_stacktrace_get());
#endif

        rc = ++(*jhp)->rc;        
#if JOURNAL_DEBUG
        log_debug3("journal: %{dnsname}: acquired: rc=%i (set)", origin, rc);
#endif
        yassert(((journal*)node->value)->_forget == 0);
        
        mutex_unlock(&journal_mutex); // in set write lock
        
        log_debug1("journal: %{dnsname}: got journal instance %p, rc=%i", origin, *jhp, rc);
        
        journal_mru_remove(*jhp);
        
        group_mutex_unlock(&journal_set_mtx, GROUP_MUTEX_WRITE);
        
        // the journal is not candidate for being closed anymore
        
        // at this point the journal has been found, removed from the MRU, and reference-counted
        
        // but the file may be closed (if we were in the MRU) so ...
        
        if(ISOK(ret = (*jhp)->vtbl->reopen(*jhp)))
        {
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
    
    log_debug1("journal: %{dnsname}: opening journal for zone @%p", zone->origin, zone);
    
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
#if JOURNAL_DEBUG_TTY
    formatln("%{dnsname} %i -> %i (acquire)", journal_get_domain_const(jh), jh->rc, jh->rc + 1);
     debug_stacktrace_print(termout, debug_stacktrace_get());
#endif

    mutex_lock(&journal_mutex); // journal already acquired, set is safe
    yassert(jh->rc > 0);
#if JOURNAL_DEBUG
    int rc =
#endif
    ++jh->rc;
#if JOURNAL_DEBUG
    u8 origin_buffer[MAX_DOMAIN_LENGTH];
    jh->vtbl->get_domain(jh, origin_buffer);
    log_debug3("journal: %{dnsname}: acquired: rc=%i", origin_buffer, rc);
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
#if JOURNAL_DEBUG_TTY
        formatln("%{dnsname} %i -> %i (release)", journal_get_domain_const(jh), jh->rc, jh->rc - 1);
        debug_stacktrace_print(termout, debug_stacktrace_get());
#endif
        group_mutex_lock(&journal_set_mtx, GROUP_MUTEX_WRITE);
        
        mutex_lock(&journal_mutex); // in set write lock

#if JOURNAL_DEBUG
        int rc = --jh->rc;
        bool not_used = (rc == 0);
        u8 origin_buffer[MAX_DOMAIN_LENGTH];
        jh->vtbl->get_domain(jh, origin_buffer);
        log_debug3("journal: %{dnsname}: released: rc=%i", origin_buffer, rc);
        yassert(jh->rc >= 0);
#else
        yassert(jh->rc > 0);

        bool not_used = (--jh->rc) == 0;
#endif
        mutex_unlock(&journal_mutex); // in set write lock
        
        if(not_used)
        {
            yassert(jh->rc == 0);
            
            // the journal is candidate for closing
            
            log_debug3("journal: %{dnsname}: closing journal@%p", journal_get_domain_const(jh), jh);

            yassert(journal_count >= 0);
            
            jh->vtbl->flush(jh);
            
            if(!journal_forget_flag_get(jh))
            {
                log_debug3("journal: enqueuing journal@%p to MRU", jh);
                journal_mru_enqueue(jh); // set locked, close later
            }
            else
            {
                log_debug3("journal: closing journal@%p", jh);
                
                // if the journal is in the set, remove it
                ptr_node *node  = ptr_set_find(&journal_set, journal_get_domain_const(jh));
                if(node != NULL)
                {
                    if(node->value == jh)
                    {
                        u8 *origin = (u8*)node->key;
                        assert(origin != NULL);
                        ptr_set_delete(&journal_set, journal_get_domain_const(jh));
                        --journal_count;
                        dnsname_zfree(origin);
                    }
                }
                
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
    
#if JOURNAL_DEBUG
    log_debug3("journal: %{dnsname}: truncate", origin);
#endif
    
    if(ISOK(ret = journal_acquire_from_fqdn(&jh, origin)))
    {
        ret = journal_truncate_to_size(jh, 0);
        journal_forget_flag_set(jh, TRUE);
        
        // if a journal file has been completely been emptied, then it should
        // be fully closed too
        
        group_mutex_lock(&journal_set_mtx, GROUP_MUTEX_WRITE);
        
        // if the journal is in the set, remove it
        ptr_node *node  = ptr_set_find(&journal_set, journal_get_domain_const(jh));
        if(node != NULL)
        {
            if(node->value == jh)
            {
                u8 *origin = (u8*)node->key;
                assert(origin != NULL);
                ptr_set_delete(&journal_set, journal_get_domain_const(jh));
                --journal_count;
                dnsname_zfree(origin);
            }
        }
        
        // if the journal is in the mru, remove it
        journal_mru_remove(jh);
        
        group_mutex_unlock(&journal_set_mtx, GROUP_MUTEX_WRITE);
        
        journal_release(jh);
        
#if JOURNAL_DEBUG
        log_debug3("journal: %{dnsname}: truncated", origin);
#endif
    }
#if JOURNAL_DEBUG
    else
    {
        log_debug3("journal: %{dnsname}: truncate failed with %r", origin, ret);
    }
#endif
    
    return ret;
}

/**
 * Returns the last SOA TTL + RDATA 
 *
 * @param jh the journal
 * @param rr an initialised resource record
 *
 * @return an error code
 */

ya_result
journal_get_last_soa(journal *jh, dns_resource_record *rr)
{
    ya_result ret = ERROR;

    input_stream is;
    u32 first_serial = 0;
    u32 last_serial = 0;

    journal_get_serial_range(jh, &first_serial, &last_serial);

    if(first_serial != last_serial) // clion inspection says this is always false, which ignores the update of the variables in the above call
    {
        for(u32 serial = last_serial - 1; serial_ge(serial, first_serial); --serial)
        {
#if JOURNAL_DEBUG
            log_debug3("journal: %{dnsname}: get last soa, journal range is [%u, %u] looking at serial %u", journal_get_domain_const(jh), first_serial, last_serial, serial);
#endif
            if(ISOK(ret = journal_get_ixfr_stream_at_serial(jh, serial, &is, rr)))
            {
#if JOURNAL_DEBUG
                log_debug3("journal: %{dnsname}: get last soa, journal range is [%u, %u] looked at serial %u: %r", journal_get_domain_const(jh), first_serial, last_serial, serial, ret);
#endif
                if(rr->tctr.qtype == TYPE_SOA)
                {
                    ret = SUCCESS;
                }
                else
                {
                    ret = ZDB_JOURNAL_SOA_RECORD_EXPECTED;
                }

                input_stream_close(&is);

                break; // from the scan-back
            }
            else
            {
#if JOURNAL_DEBUG
                log_debug3("journal: %{dnsname}: get last soa, journal range is [%u, %u] looking at serial %u (error)", journal_get_domain_const(jh), first_serial, last_serial, serial);
#endif
            }
        }
    }
    /*
    else
    {
        ret = ERROR;
    }
    */

#if JOURNAL_DEBUG
    log_debug3("journal: %{dnsname}: get last soa, journal range is [%u, %u] returning %r", journal_get_domain_const(jh), first_serial, last_serial, ret);
#endif

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

ya_result
journal_answer_ixfr(journal *jh, message_data* mesg, int tcpfd, s32 packet_records_limit)
{
    const u8 *origin = message_get_canonised_fqdn(mesg);
    
    // TCP output stream

    output_stream tcpos;
    input_stream fis;
    packet_writer pw;
    ya_result return_value;
    u32 packet_size_limit;
    u32 packet_size_trigger;
    s32 packet_records_countdown;
    u32 serial;

#if ZDB_HAS_TSIG_SUPPORT
    tsig_tcp_message_position pos = TSIG_START;
#endif

    if(FAIL(return_value = message_get_ixfr_query_serial(mesg, &serial)))
    {
        return return_value;
    }
    
    dns_resource_record soa_rr;
    dns_resource_record_init(&soa_rr);
    
    if(FAIL(return_value = journal_get_ixfr_stream_at_serial(jh, serial, &fis, &soa_rr)))
    {
        dns_resource_record_clear(&soa_rr);
        return return_value;
    }
    
    dns_resource_record rr;
    dns_resource_record_init(&rr);
    
    packet_size_limit = message_get_buffer_size_max(mesg);
    
    packet_size_trigger = packet_size_limit / 2; // so, ~32KB, also : guarantees that there will be room for SOA & TSIG
    
    if(packet_records_limit)
    {
        packet_records_limit = MAX_S32;
    }
    packet_records_countdown = packet_records_limit;

    message_reset_buffer_size(mesg);
    
    /* attach the tcp descriptor and put a buffer filter in front of the input and the output*/

    fd_output_stream_attach(&tcpos, tcpfd);

    buffer_input_stream_init(&fis, &fis, 4096);
    buffer_output_stream_init(&tcpos, &tcpos, 4096);
    
    size_t query_size = message_get_size(mesg);
    
    packet_writer_init(&pw, message_get_buffer(mesg), query_size, packet_size_limit - 780);

    /*
     * Init
     * 
     * Write the final SOA (start of the IXFR stream)
     */
   
    packet_writer_add_dnsrr(&pw, &soa_rr);
    
    u32 last_serial;
    rr_soa_get_serial(soa_rr.rdata, soa_rr.rdata_size, &last_serial);

    u16 an_count = 1 /*2*/;

    bool end_of_stream = FALSE;
    
    for(;;)
    {
        if(FAIL(return_value = dns_resource_record_read(&rr, &fis)))
        {
            log_err("journal ixfr: %{dnsname}: %{sockaddr}: read record #%d failed: %r", origin, message_get_sender_sa(mesg), an_count, return_value);
            break;
        }
        
        u32 record_length = return_value;
        
        if(rr.tctr.qtype == TYPE_SOA)
        {
            // ensure we didn't go too far
            u32 soa_serial;
            rr_soa_get_serial(rr.rdata, rr.rdata_size, &soa_serial);
            if(serial_gt(soa_serial, last_serial))
            {
                record_length = 0; // will be seen as an EOF
            }
        }
        

        
        if(record_length == 0)
        {
#if JOURNAL_DEBUG
            log_debug3("journal ixfr: %{dnsname}: %{sockaddr}: end of stream", origin, message_get_sender(mesg));
#endif

#if ZDB_HAS_TSIG_SUPPORT
            if(pos != TSIG_START)
            {
                pos = TSIG_END;
            }
            else
            {
                pos = TSIG_WHOLE;
            }
#endif
            // Last SOA
            // There is no need to check for remaining space as packet_size_trigger guarantees there is still room
            
#if  DEBUG
            {
                log_debug3("journal ixfr: %{dnsname}: closing: %{dnsrr}", origin, &soa_rr);
            }
#endif

            packet_writer_add_dnsrr(&pw, &soa_rr);

            ++an_count;
            
            end_of_stream = TRUE;
        }
        else if(record_length > MAX_U16) // technically possible: a record too big to fit in an update (not likely)
        {
            // this is technically possible with an RDATA of 64K
            log_err("journal ixfr: %{dnsname}: %{sockaddr}: ignoring record of size %u", origin, message_get_sender_sa(mesg), record_length);          
            log_err("journal ixfr: %{dnsname}: %{sockaddr}: record is: %{dnsrr}", origin, message_get_sender_sa(mesg), return_value, &rr);
            continue;
        }
        
        // if the record puts us above the trigger, or if there is no more record to read, send the message
        
        if(pw.packet_offset + record_length >= packet_size_trigger || (packet_records_countdown-- <= 0) || end_of_stream)
        {
            // flush

            message_set_answer_count(mesg, an_count);
            message_set_size(mesg, packet_writer_get_offset(&pw));

#if ZDB_HAS_TSIG_SUPPORT
            return_value = message_terminate_then_write(mesg, &tcpos, pos);
#else
            return_value = message_terminate_then_write(mesg, &tcpos, 0);
#endif

            if(FAIL(return_value))
            {
                if(return_value == MAKE_ERRNO_ERROR(EPIPE))
                {
                    log_notice("journal ixfr: %{dnsname}: %{sockaddr}: send message failed: client closed connection", origin, message_get_sender_sa(mesg));
                }
                else
                {
                    log_notice("journal ixfr: %{dnsname}: %{sockaddr}: send message failed: %r", origin, message_get_sender_sa(mesg), return_value);
                }

                break;
            }

#if ZDB_HAS_TSIG_SUPPORT
            pos = TSIG_MIDDLE;
#endif
            packet_writer_init(&pw, message_get_buffer(mesg), query_size, packet_size_limit - 780);

            an_count = 0;
            
            if(end_of_stream)
            {
                break;
            }
            
            packet_records_countdown = packet_records_limit;
        }
        
#if  DEBUG
        {
            log_debug3("journal ixfr: %{dnsname}: sending: %{dnsrr}", origin, &rr);
        }
#endif
        packet_writer_add_dnsrr(&pw, &rr);
        
        ++an_count;
    }
    
    dns_resource_record_clear(&rr);
    dns_resource_record_clear(&soa_rr);
  
    output_stream_close(&tcpos);

    if(input_stream_valid(&fis))
    {
        input_stream_close(&fis);
    }
    
    return return_value;   
}

/** @} */
