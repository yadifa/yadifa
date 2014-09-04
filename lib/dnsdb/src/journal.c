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

#include <dnscore/dns_resource_record.h>
#include <dnscore/xfr_copy.h>

#include "dnsdb/journal.h"
#include "dnsdb/journal_ix.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_utils.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

static mutex_t journal_mutex = MUTEX_INITIALIZER;
static journal *journal_mru_first = NULL;
static journal *journal_mru_last = NULL;
static u32     journal_mru_count = 0;
static u32     journal_mru_size = 0;
static u32     journal_count = 0;
static bool    journal_initialised = FALSE;

static bool    journal_mru_remove(journal *jh);


static char *xfr_path = LOCALSTATEDIR "/zones/xfr";
static bool xfr_path_free = FALSE;

void
journal_set_xfr_path(const char *path)
{
    if(xfr_path_free)
    {
        free((char*)xfr_path);
    }
    
    if(path == NULL)
    {        
        xfr_path = LOCALSTATEDIR "/xfr";
        xfr_path_free = FALSE;
    }
    else
    {
        xfr_path = strdup(path);
        xfr_path_free = TRUE;
    }
}

const char*
journal_get_xfr_path()
{
    return xfr_path;
}

void
journal_lock()
{
    mutex_lock(&journal_mutex);
}

void
journal_unlock()
{
    mutex_unlock(&journal_mutex);
}

static void
journal_inc_reference_count(journal *jh)
{
    journal_lock();
    ++jh->rc;
    journal_unlock();
}

static bool
journal_dec_reference_count(journal *jh)
{
    journal_lock();
    
    bool destroy = (--jh->rc == 0);
    
    if(destroy) // note: don't care if the RC is < 0
    {
        // destroy
        
        if(jh->zone != NULL)
        {
            jh->zone->journal = NULL;
            jh->zone = NULL;
        }
        
        journal_mru_remove(jh); // remove only if it is in there

        jh->vtbl->close(jh);
        
        --journal_count;
    }
    journal_unlock();
    
    return destroy;
}

static bool
journal_mru_remove(journal *jh)
{
    if(jh->mru)
    {
        if(jh->prev != NULL)
        {
            jh->prev->next = jh->next;
        }
        else
        {
            // == NULL
            journal_mru_first = (journal*)jh->next;
        }

        if(jh->next != NULL)
        {
            jh->next->prev = jh->prev;
        }
        else
        {
            // == NULL
            journal_mru_last = (journal*)jh->prev;
        }
        
        jh->prev = NULL;
        jh->next = NULL;
        jh->mru = FALSE;
  
        --journal_mru_count;
        
        journal_dec_reference_count(jh);
        
        return TRUE;
    }
#ifdef DEBUG
    else
    {
        if((jh->next != NULL) || (jh->prev != NULL))
        {
            log_err("%p not in MRU but is linked!", jh);
        }
    }
#endif
    
    // was not in the MRU
    
    return FALSE;
}

/**
 * 
 * Puts the given journal at the head of the mru list.
 * Clears out the lru journal if needed.
 * 
 * @param jh
 */

static void
journal_mru_add(journal *jh)
{
    // if jh is first already, stop
    
    if(journal_mru_first == jh)
    {
#ifdef DEBUG
        log_debug("journal_mru_add(%p) (%{dnsname}) : already first", jh, jh->zone->origin);
#endif
        return;
    }
    
    // increment the reference for the MRU first, else the next remove will destroy it
    
    journal_inc_reference_count(jh);
    
    // detach from the list
    
    bool was_in_mru = journal_mru_remove(jh);
    
    // put as first
    
    jh->prev = NULL;
    jh->next = journal_mru_first;
    
    // if there is a first, link it to the new first
    
    if(journal_mru_count != 0)
    {
        journal_mru_first->prev = jh;
    }
    else
    {
        journal_mru_last = jh;
    }
    journal_mru_first = jh;
    jh->mru = TRUE;
            
    //
    
    ++journal_mru_count;
/*
    journal_inc_reference_count(jh); // referenced in the MRU
*/  
    if(!was_in_mru)
    {
        // new reference, so increase the count
        
        // slots available ?
        
        if(journal_mru_count < journal_mru_size)
        {
            // yes
           
#ifdef DEBUG
            log_debug("journal_mru_add(%p) (%{dnsname}) : new one (count = %u/%u)",
                      jh, jh->zone->origin,
                      journal_mru_count, journal_mru_size);
#endif
        }
        else
        {
#ifdef DEBUG
            log_debug("journal_mru_add(%p) (%{dnsname}) : new one (count = %u/%u), releasing least recently used (%{dnsname})",
                      jh, jh->zone->origin,
                      journal_mru_count, journal_mru_size,
                      journal_mru_last->zone->origin);
#endif
            // no, remove the last one of the MRU
            
            journal_mru_remove(journal_mru_last);
        }
    }
#ifdef DEBUG
    else
    {
        log_debug("journal_mru_add(%p) (%{dnsname}) : old one (count = %u/%u)", jh, jh->zone->origin, journal_mru_count, journal_mru_size);
    }
#endif
}

ya_result
journal_init(u32 mru_size)
{
    // initialises journal open/close access mutex (avoid creation/destruction races)
    // will be responsible for the journal file-descriptor resources allocation (closes least recently used journal when no more FDs are available)
    
    mutex_init_recursive(&journal_mutex);
    
    if(mru_size == 0)
    {
        mru_size = ZDB_JOURNAL_FD_DEFAULT;
    }
    
    journal_mru_size = MAX(MIN(mru_size, ZDB_JOURNAL_FD_MAX), ZDB_JOURNAL_FD_MIN);

    journal_initialised = TRUE;

    return SUCCESS;
}

void
journal_finalise()
{
    if(journal_initialised)
    {
	mutex_lock(&journal_mutex);
    
	while(journal_mru_first != NULL)
        {
            journal_mru_remove(journal_mru_first);
        }

        mutex_unlock(&journal_mutex);
        mutex_destroy(&journal_mutex);

	journal_initialised = FALSE;
    }
}

/**
 * 
 * Opens the journal for a zone
 * Increments the reference count to the journal
 * 
 * @param jhp
 * @param zone
 * @param workingdir
 * @param create
 * @return 
 */

ya_result
journal_open(journal **jhp, zdb_zone *zone, const char *workingdir, bool create)
{
    journal *jh = NULL;
    ya_result return_value = SUCCESS;
    char data_path[PATH_MAX];
    
    if((jhp == NULL) || (zone == NULL) || (workingdir == NULL))
    {
#ifdef DEBUG
        log_debug("journal_open(%p,%p,%s,%i) failed (%{dnsname})", jhp, zone, (workingdir!=NULL)?workingdir:"NULL", create, (zone!=NULL)?zone->origin:(const u8*)"\004NULL");
#endif
        
        return ZDB_JOURNAL_WRONG_PARAMETERS;
    }
    
    mutex_lock(&journal_mutex);

    // get the journal
    
    jh = zone->journal;
    
    if(jh == NULL)
    {
        // The zone has no journal linked yet
        
#ifdef DEBUG
        log_debug("journal_open(%p,%p,%s,%i) opening journal (%{dnsname})", jhp, zone, (workingdir!=NULL)?workingdir:"NULL", create, zone->origin);
#endif
        
        // it does not exist, so create a new one (using the IX format)
        
        // compute the path
        if(FAIL(return_value = xfr_copy_get_data_path(data_path, sizeof(data_path), workingdir, zone->origin)))
        {
            mutex_unlock(&journal_mutex);
            *jhp = NULL;
            
            return return_value;
        }

        workingdir = data_path;
        
        // open the journal
        
        if(FAIL(return_value = journal_ix_open(&jh, zone->origin, workingdir, create)))
        {
            mutex_unlock(&journal_mutex);
            *jhp = NULL;
            
            return return_value;
        }
        
        // if the journal was successfully opened, link it to the zone
        /// @note this link is weak, there is no reference count increase for it
        
        ++journal_count;
        
        zone->journal = jh;
        jh->zone = zone;
        
        // puts the journal in the head of the queue (closing the less recently used if needed)
        journal_mru_add(jh);
    }
#ifdef DEBUG
    else
    {
        log_debug("journal_open(%p,%p,%s,%i) referencing journal (%{dnsname})", jhp, zone, (workingdir!=NULL)?workingdir:"NULL", create, zone->origin);
    }
#endif
    
    // from here jh is not NULL  
    
    journal_inc_reference_count(jh);
            
    mutex_unlock(&journal_mutex);
    
    *jhp = jh;
    
    return return_value;
}

/**
 * Closes the journal
 * Decrement the count of references, closes/destroys if it reaches 0
 * 
 * @param jh
 */

void
journal_close(journal *jh)
{
    if(jh != NULL)
    {
        mutex_lock(&journal_mutex);

#ifdef DEBUG
        const u8 *origin = (jh->zone != NULL)?jh->zone->origin:(const u8*)"";
#endif
        if(journal_dec_reference_count(jh))
        {
            // nobody has this journal opened : destroy it (or set it as candidate for destruction)
       
#ifdef DEBUG
            log_debug("journal_close(%p) closed journal (%{dnsname})", jh, origin);
#endif
            
        }
#ifdef DEBUG
        else
        {
            log_debug("journal_close(%p) de-referenced journal (%{dnsname}) (rc=%i)", jh, origin, jh->rc);
        }
#endif
        mutex_unlock(&journal_mutex);
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
journal_last_serial(const u8 *origin, const char *workingdir, u32 *serialp)
{
    journal *jh = NULL;
    ya_result return_value;
    char data_path[PATH_MAX];
    
    if(origin == NULL)
    {
        return ZDB_JOURNAL_WRONG_PARAMETERS;
    }
    
    if(FAIL(return_value = xfr_copy_get_data_path(data_path, sizeof(data_path), workingdir, origin)))
    {
        return return_value;
    }
    
    workingdir = data_path;
    
    if(ISOK(return_value = journal_ix_open(&jh, origin, workingdir, FALSE)))
    {
        return_value = journal_get_last_serial(jh, serialp);
        
        jh->vtbl->close(jh);
    }
    
    return return_value;
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
journal_truncate(const u8 *origin, const char *workingdir)
{
    journal *jh = NULL;
    ya_result return_value;
    char data_path[PATH_MAX];
    
    if(origin == NULL)
    {
        return ZDB_JOURNAL_WRONG_PARAMETERS;
    }
    
    if(FAIL(return_value = xfr_copy_get_data_path(data_path, sizeof(data_path), workingdir, origin)))
    {
        return return_value;
    }
    
    workingdir = data_path;
    
    if(ISOK(return_value = journal_ix_open(&jh, origin, workingdir, FALSE)))
    {
        return_value = journal_truncate_to_size(jh, 0);
        
        jh->vtbl->close(jh);
      }
    
    return return_value;
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
journal_last_soa(const u8 *origin, const char *workingdir, u32 *serial, u32 *ttl, u8 *last_soa_rdata, u16 *last_soa_rdata_size)
{
    journal *jh = NULL;
    ya_result return_value;
    char data_path[PATH_MAX];
    
    /* check preconditions */

    if((origin == NULL)     ||  /* mandatory */
       (workingdir == NULL) ||  /* mandatory */
       (    ((last_soa_rdata == NULL) == (last_soa_rdata_size == NULL)) && /* at least one of them mandatory */
            (ttl == NULL) &&
            (serial == NULL) )  )
    {
        return ZDB_JOURNAL_WRONG_PARAMETERS;
    }
    
    /* translate path */
    
    if(FAIL(return_value = xfr_copy_get_data_path(data_path, sizeof(data_path), workingdir, origin)))
    {
        return return_value;
    }
    
    workingdir = data_path;
    
    /* open a new instance of the journal */
    
    if(ISOK(return_value = journal_ix_open(&jh, origin, workingdir, FALSE)))
    {
        jh->zone = NULL;
        
        input_stream is;
        dns_resource_record rr;
        dns_resource_record_init(&rr);
        u32 first_serial = 0;
        
        journal_get_first_serial(jh, &first_serial);
        
        if(ISOK(return_value = journal_get_ixfr_stream_at_serial(jh, first_serial, &is, &rr)))
        {
            if(last_soa_rdata != NULL) /* one not NULL => both not NULL */
            {
                if(*last_soa_rdata_size >= rr.rdata_size)
                {
                    MEMCOPY(last_soa_rdata, rr.rdata, rr.rdata_size);
                    *last_soa_rdata_size = rr.rdata_size;
                }
            }
            else
            {
                return_value = ERROR;
            }
            
            if(serial != NULL)
            {
                return_value = rr_soa_get_serial(rr.rdata, rr.rdata_size, serial);
            }
            
            if(ttl != NULL)
            {
                *ttl = htonl(rr.tctr.ttl);
            }            
        }
        
        dns_resource_record_clear(&rr);
        input_stream_close(&is);
        jh->vtbl->close(jh);
    }
    
    return return_value;
}

/**
 * 
 * Prints the status of the journal (mostly the ones in the MRU) to the logger.
 * 
 */

void
journal_log_status()
{
    mutex_lock(&journal_mutex);

    log_debug("journal: instances: %u, mru: %u/%u", journal_count, journal_mru_count, journal_mru_size);
    
    journal *jh = journal_mru_first;
    
    while(jh != NULL)
    {
        jh->vtbl->log_dump(jh);
        jh = (journal*)jh->next;
    }
    
    mutex_unlock(&journal_mutex);
}

/** @} */
