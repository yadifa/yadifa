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
/** @defgroup dnsdb Zone database
 *  @brief The zone dataBase
 *
 * @{
 */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <dnscore/logger.h>
#include <dnscore/format.h>
#include <dnscore/rdtsc.h>

#include <dnscore/sys_error.h>

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

static void
zdb_rdtsc_registations(){
    /* rdtsc_register(&rdtsc_zdb_rr_label_find); */ }

#include "dnsdb/zdb.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_dnsname.h"
#include "dnsdb/dictionary.h"

#if ZDB_DNSSEC_SUPPORT != 0
#include "dnsdb/dnssec_keystore.h"
#endif

#include <dnscore/dnscore.h>

#include <dnscore/sys_get_cpu_count.h>

#if ZDB_USE_THREADPOOL != 0
#include <dnscore/thread_pool.h>

static bool thread_pool_initialized_by_zdb = FALSE;

#endif

#if ZDB_OPENSSL_SUPPORT!=0

#include <openssl/ssl.h>
#include <openssl/engine.h>

/*
 * Required to handle openssl with multiple threads
 */

#define ZDB_SSLMUTEX_TAG 0x584554554d4c5353

static pthread_mutex_t *ssl_mutex = NULL;
static int ssl_mutex_count = 0;

static void
ssl_lock(int mode, int type, const char* file, int line)
{
    if((mode & CRYPTO_LOCK) != 0)
    {
        /* lock */

        pthread_mutex_lock(&ssl_mutex[type]);
    }
    else
    {
        /* unlock */

        pthread_mutex_unlock(&ssl_mutex[type]);
    }
}

static unsigned long
ssl_thread_id()
{
    return (unsigned long)pthread_self();
}

#endif

logger_handle* g_database_logger = NULL;

/** @brief Initializes the database internals.
 *
 *  Checks the architecture settings of the binary.
 *  Initializes the database internals.
 *  Multiple calls is a NOP.
 *
 *  This is not thread safe.
 *
 */

static volatile bool zdb_init_done = FALSE;

dnslib_fingerprint dnsdb_getfingerprint()
{
    dnslib_fingerprint ret = (dnslib_fingerprint)(0
#if HAS_TSIG_SUPPORT != 0
    | DNSLIB_TSIG
#endif
#if HAS_ACL_SUPPORT != 0
    | DNSLIB_ACL
#endif
#if HAS_NSEC_SUPPORT != 0
    | DNSLIB_NSEC
#endif
#if HAS_NSEC3_SUPPORT != 0
    | DNSLIB_NSEC3
#endif
    );

    return ret;
}

u32 dnsdb_fingerprint_mask()
{
    return DNSLIB_TSIG|DNSLIB_ACL|DNSLIB_NSEC|DNSLIB_NSEC3;
}

void
zdb_init()
{
    if(zdb_init_done)
    {
        return;
    }

    /* DO or DIE */

    if(dnscore_getfingerprint() != (dnsdb_getfingerprint() & dnscore_fingerprint_mask()))
    {
        osformatln(termerr, "Mismatched fingerprints: %08x != (%08x = %08x & %08x)",
                dnscore_getfingerprint(),
                dnsdb_getfingerprint() & dnscore_fingerprint_mask(),
                dnsdb_getfingerprint() , dnscore_fingerprint_mask());

        flusherr();
        
        exit(-1);
    }

    zdb_init_done = TRUE;

    /* Init the dns core */

    dnscore_init();

    /* Init the error table */

    zdb_register_errors();

    /* Init the hash tables */

    hash_init();

#if ZDB_OPENSSL_SUPPORT!=0

    /* Init openssl */

    ENGINE_load_openssl();
    ENGINE_load_builtin_engines();

    ssl_mutex_count = CRYPTO_num_locks();

    MALLOC_OR_DIE(pthread_mutex_t*, ssl_mutex, ssl_mutex_count * sizeof (pthread_mutex_t), ZDB_SSLMUTEX_TAG);

    int i;

    for(i = 0; i < ssl_mutex_count; i++)
    {
        pthread_mutex_init(&ssl_mutex[i], NULL);
    }

    CRYPTO_set_id_callback(ssl_thread_id);
    CRYPTO_set_locking_callback(ssl_lock);
#endif

#if ZDB_USE_THREADPOOL != 0
    /*
     *  The default value for the database.
     *  This initialization will do nothing if it has already been done.
     *
     *  The server will have to do it before calling zdb_init();
     *
     */
    
    u32 count = sys_get_cpu_count() + 2;
    
    ya_result return_value = thread_pool_init(count);
    
    if(FAIL(return_value))
    {
        log_crit("unable to initialise the thread pool to %d threads: %r", count, return_value); /* will ultimately lead to the end of the program */
        exit(-1);
    }
    
    thread_pool_initialized_by_zdb = (return_value == count);
#endif

#if ZDB_USES_ZALLOC != 0
    zdb_set_zowner(pthread_self());
#endif

    logger_start();

    zdb_rdtsc_registations();
}

void
zdb_finalize()
{
    if(!zdb_init_done)
    {
        return;
    }

    zdb_init_done = FALSE;

#if ZDB_DNSSEC_SUPPORT != 0
    dnssec_keystore_destroy();
    dnssec_keystore_resetpath();
#endif

#if ZDB_OPENSSL_SUPPORT!=0

    ERR_remove_state(0);

    /* Init openssl */

    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);

    int i;

    for(i = 0; i < ssl_mutex_count; i++)
    {
        pthread_mutex_destroy(&ssl_mutex[i]);
    }

    free(ssl_mutex);

    ENGINE_cleanup();

#endif

    logger_stop();

#if ZDB_USE_THREADPOOL != 0
    /*
     *  The default value for the database.
     *  This initialization will do nothing if it has already been done.
     *
     *  The server will have to do it before calling zdb_init();
     *
     */

    if(thread_pool_initialized_by_zdb)
    {
        thread_pool_destroy();
    }
#endif

}

/** @brief Initializes a database.
 *
 *  Initializes a database.
 *
 *  @param[in]  db a pointer to the zdb structure that will be initialized.
 *
 */

void
zdb_create(zdb* db)
{
    int i;
    for(i = HOST_CLASS_IN - 1; i < ZDB_RECORDS_MAX_CLASS; i++)
    {
        zdb_zone_label* zone_label;

        ZALLOC_OR_DIE(zdb_zone_label*, zone_label, zdb_zone_label, ZDB_ZONELABEL_TAG);
        ZEROMEMORY(zone_label, sizeof (zdb_zone_label));
        zone_label->name = dnslabel_dup(ROOT_LABEL); /* . */
        dictionary_init(&zone_label->sub);

#if ZDB_CACHE_ENABLED!=0
        btree_init(&zone_label->global_resource_record_set);
#endif
        db->root[i] = zone_label;
    }

    db->alarm_handle = alarm_open((const u8*)"\010database");
}

#if ZDB_CACHE_ENABLED!=0

/** @brief Adds a zone file to the global/cache part of the database
 *
 *  Adds a zone file to the global/cache part of the database
 *
 *  @param[in]  db a pointer to a zdb structure that will be initialized.
 *  @param[in]  filename the path to the zone file.
 *  @param[in]  dnszone the dns-name of the zone file.
 *
 *
 *  @return SUCCESS in case of success.
 */

ya_result
zdb_load_global(zdb* db, const char* filename)
{
#if ZDB_DEBUG_LOADZONE!=0
    u64 rdata_allocated_size = 0;
    u64 rdata_total_size = 0;
    u32 rdata_inline_count = 0;
#endif

    ya_result err;
    zone_data file;

    if(FAIL(err = zone_file_open(filename, &file)))
    {
        return err;
    }

    resource_record entry;

    u32 entry_count = 0;

    for(;;)
    {
        zone_file_read(&file, &entry);

        if(ZONEFILE_ENTRY_IS_EOF(entry))
        {
            rr_entry_freecontent(&entry);

            break;
        }

        /* Add the entry */

        dnsname_vector entry_name;
        DEBUG_RESET_dnsname(entry_name);
        dnsname_to_dnsname_vector(entry.name, &entry_name);

#if ZDB_DEBUG_LOADZONE!=0
        rdata_total_size += entry.data.length;
        if(entry.data.length > TTLRDATA_INLINESIZE)
        {
            rdata_allocated_size += entry.data.length;
        }
        else
        {
            rdata_inline_count++;
        }
#endif

        /* The record will be cloned in this call */
        zdb_add_global(db, entry.name, entry.class, entry.type, entry.ttl, entry.data.length, entry.data.rdata_pointer); /* 4 match, add    1 */

        entry_count++;

        rr_entry_freecontent(&entry);
    }

    db->items += entry_count;

    zone_file_close(&file);

    return err;
}

#endif

/** @brief Search for a match in the database
 *
 *  Search for a match in the database.
 *  Only the most relevant match will be returned.
 *
 *  @param[in]  db the database
 *  @param[in]  dnsname_name the name dnsname to search for
 *  @param[in]  class the class to match
 *  @param[in]  type the type to match
 *  @param[out] ttl_rdara_out a pointer to a pointer set of results (single linked list)
 *
 *  @return SUCCESS in case of success.
 */

ya_result
zdb_query(zdb* db, u8* name_, u16 zclass, u16 type, zdb_packed_ttlrdata** ttlrdata_out)
{
    zassert(ttlrdata_out != NULL);

    dnsname_vector name;
    DEBUG_RESET_dnsname(name);

    dnsname_to_dnsname_vector(name_, &name);


    /* Find closest matching label
     * Should return a stack of zones
     */

    zdb_zone_label_pointer_array zone_label_stack;

    s32 top = zdb_zone_label_match(db, &name, zclass, zone_label_stack);
    s32 sp = top;

    /* Got a stack of zone labels with and without zone cuts */
    /* Search the label on the zone files */

    while(sp >= 0)
    {
        zdb_zone_label* zone_label = zone_label_stack[sp];

        if(zone_label->zone != NULL)
        {
            if((*ttlrdata_out = zdb_zone_record_find(zone_label->zone, name.labels, name.size - sp, type)) != NULL)
            {
                /* *ttlrdata_out for the answer */
                /* zone_label->zone for the authority section */
                /* subsequent searchs for the additional */

                return SUCCESS;
            }
        }

        sp--;
    }

#if ZDB_CACHE_ENABLED!=0

    /* We exhausted the zone files direct matches.
     * We have to fallback on the global (cache) matches.
     * And it's easy because we have the answer already:
     */

    if(top == name.size)
    {
        /* We found a perfect match label in the global part of the database */

        if((*ttlrdata_out = zdb_record_find(&zone_label_stack[top]->global_resource_record_set, type)) != NULL)
        {
            return SUCCESS;
        }
    }

#endif

    return ZDB_ERROR_KEY_NOTFOUND;
}

/** @brief Search for a match in the database
 *
 *  Search for a match in the database.
 *  Only the most relevant match will be returned.
 *
 *  @param[in]  db the database
 *  @param[in]  dnsname_name the name dnsname to search for
 *  @param[in]  class the class to match
 *  @param[in]  type the type to match
 *  @param[out] ttl_rdara_out a pointer to a pointer set of results (single linked list)
 *
 *  @return SUCCESS in case of success.
 */

ya_result
zdb_query_ip_records(zdb* db, u8* name_, u16 zclass, zdb_packed_ttlrdata* * restrict ttlrdata_out_a, zdb_packed_ttlrdata* * restrict ttlrdata_out_aaaa)
{
    zassert(ttlrdata_out_a != NULL && ttlrdata_out_aaaa != NULL);

    dnsname_vector name;
    DEBUG_RESET_dnsname(name);

    dnsname_to_dnsname_vector(name_, &name);

    /* Find closest matching label
     * Should return a stack of zones
     */

    zdb_zone_label_pointer_array zone_label_stack;

    s32 top = zdb_zone_label_match(db, &name, zclass, zone_label_stack);
    s32 sp = top;

    /* Got a stack of zone labels with and without zone cuts */
    /* Search the label on the zone files */

    while(sp >= 0)
    {
        zdb_zone_label* zone_label = zone_label_stack[sp];

        if(zone_label->zone != NULL)
        {
            /* Get the label, instead of the type in the label */
            zdb_rr_label* rr_label = zdb_rr_label_find_exact(zone_label->zone->apex, name.labels, name.size - sp);

            if(rr_label != NULL)
            {
                zdb_packed_ttlrdata* a = zdb_record_find(&rr_label->resource_record_set, TYPE_A);
                zdb_packed_ttlrdata* aaaa = zdb_record_find(&rr_label->resource_record_set, TYPE_AAAA);

                if(a != NULL || aaaa != NULL)
                {
                    *ttlrdata_out_a = a;
                    *ttlrdata_out_aaaa = aaaa;
                    return SUCCESS;
                }
            }
        }

        sp--;
    }

#if ZDB_CACHE_ENABLED!=0

    /* We exhausted the zone files direct matches.
     * We have to fallback on the global (cache) matches.
     * And it's easy because we have the answer already:
     */

    if(top == name.size)
    {
        /* We found a perfect match label in the global part of the database */

        zdb_packed_ttlrdata* a = zdb_record_find(&zone_label_stack[top]->global_resource_record_set, TYPE_A);
        zdb_packed_ttlrdata* aaaa = zdb_record_find(&zone_label_stack[top]->global_resource_record_set, TYPE_AAAA);

        if(a != NULL || aaaa != NULL)
        {
            *ttlrdata_out_a = a;
            *ttlrdata_out_aaaa = aaaa;
            return SUCCESS;
        }
    }

#endif

    return ZDB_ERROR_KEY_NOTFOUND;
}

#if ZDB_CACHE_ENABLED!=0

/** @brief Search for a match in global/cache part of the database
 *
 *  Search for a match in global/cache part of the database
 *
 *  @param[in]  db the database
 *  @param[in]  dnsname_name the name dnsname to search for
 *  @param[in]  class the class to match
 *  @param[in]  type the type to match
 *  @param[out] ttl_rdara_out a pointer to a pointer set of results (single linked list)
 *
 *  @return SUCCESS in case of success.
 */


ya_result
zdb_query_global(zdb* db, u8* name_, u16 zclass, u16 type, zdb_packed_ttlrdata** ttlrdata_out)
{
    zassert(ttlrdata_out != NULL);

    dnsname_vector name;

    DEBUG_RESET_dnsname(name);

    dnsname_to_dnsname_vector(name_, &name);

    zdb_zone_label* zone_label = zdb_zone_label_find(db, &name, zclass);

    zdb_packed_ttlrdata* ttlrdata = zdb_record_find(&zone_label->global_resource_record_set, type);

    *ttlrdata_out = ttlrdata;

    return (ttlrdata != NULL) ? SUCCESS : ZDB_ERROR_KEY_NOTFOUND;
}

#endif

/** @brief Adds an entry in a zone of the database
 *
 *  Adds an entry in a zone of the database
 *
 *  @param[in]  db the database
 *  @param[in]  origin_ the zone where to add the record
 *  @param[in]  name_ the full name of the record (dns form)
 *  @param[in]  zclass the class of the record
 *  @param[in]  type the type of the record
 *  @param[in]  ttl the ttl of the record
 *  @param[in]  rdata_size the size of the rdata of the record
 *  @param[in]  rdata a pointer to the rdata of the record
 *
 *  @return SUCCESS in case of success.
 */

ya_result
zdb_add(zdb* db, u8* origin_, u8* name_, u16 zclass, u16 type, u32 ttl, u16 rdata_size, void* rdata) /* 4 match, add    1 */
{
    zassert(db != NULL && origin_ != NULL && name_ != NULL && (rdata_size == 0 || rdata != NULL));

    dnsname_vector origin;
    DEBUG_RESET_dnsname(origin);

    dnsname_to_dnsname_vector(origin_, &origin);

    dnsname_vector name;
    DEBUG_RESET_dnsname(name);

    dnsname_to_dnsname_vector(name_, &name);

    zdb_zone* zone = zdb_zone_find(db, &origin, zclass);

    if(zone != NULL)
    {
        zdb_packed_ttlrdata* ttlrdata;

        ZDB_RECORD_ZALLOC(ttlrdata, ttl, rdata_size, rdata);
        /* The record will be cloned in this call */
        zdb_zone_record_add(zone, name.labels, (name.size - origin.size) - 1, type, ttlrdata);

        /**
         * @todo: If the zone is NSEC/NSEC3 :
         *
         *  NOTE: Remember that all the intermediary labels have to be added
         *  if they do not exist yet.
         *
         *  (order an) udpate of the NSECx record
         *  (order an) update of both signatures (NSECx + record type)
         *
         */

        /**
         * @todo: If the record added is NS, update glue record status of name in the rdata
         */

        return SUCCESS;
    }

    return ZDB_ERROR_ZONENOTLOADED;
}


/** @brief Deletes an entry from a zone in the database
 *
 *  Matches and deletes an entry from a zone in the database
 *
 *  @param[in]  db the database
 *  @param[in]  origin_ the zone from which to remove the record
 *  @param[in]  name_ the name of the record
 *  @param[in]  zclass the class of the record
 *  @param[in]  type the type of the record
 *  @param[in]  ttl the ttl of the record
 *  @param[in]  rdata_size the size of the rdata of the record
 *  @param[in]  rdata a pointer to the rdata of the record
 *
 *  @return SUCCESS in case of success.
 */

ya_result
zdb_delete(zdb* db, u8* origin_, u8* name_, u16 zclass, u16 type, u32 ttl, u16 rdata_size, void* rdata) /* 5 match, delete 1 */
{
    zassert(db != NULL && origin_ != NULL && name_ != NULL && (rdata_size == 0 || rdata != NULL));

    dnsname_vector origin;
    DEBUG_RESET_dnsname(origin);

    dnsname_to_dnsname_vector(origin_, &origin);

    dnsname_vector name;
    DEBUG_RESET_dnsname(name);

    dnsname_to_dnsname_vector(name_, &name);

    zdb_zone* zone = zdb_zone_find(db, &origin, zclass);

    if(zone != NULL)
    {
        zdb_ttlrdata ttlrdata;

        ZDB_RECORD_TTLRDATA_SET(ttlrdata, ttl, rdata_size, rdata);

        /* I do not really require a record set here ... */
        return zdb_rr_label_delete_record_exact(zone, name.labels, (name.size - origin.size) - 1, type, &ttlrdata);

        /**
         * @todo: If the zone is NSEC/NSEC3 :
         *
         *  NOTE: Remember that all the intermediary labels have to be deleted
         *  if they are not relevant anymore
         *
         *  (order an) udpate of the NSECx record
         *  (order an) update of both signatures (NSECx + record type)
         *
         */

    }

    return ZDB_ERROR_ZONENOTLOADED;
}

#if ZDB_CACHE_ENABLED!=0

/** @brief Deletes an entry from the database
 *
 *  Matches and deletes an entry from the database
 *
 *  @param[in]  db the database
 *  @param[in]  name_ the name of the record
 *  @param[in]  zclass the class of the record
 *  @param[in]  type the type of the record
 *  @param[in]  ttl the ttl of the record
 *  @param[in]  rdata_size the size of the rdata of the record
 *  @param[in]  rdata a pointer to the rdata of the record
 *
 *  @return SUCCESS in case of success.
 */

ya_result
zdb_delete_global(zdb* db, u8* name_, u16 zclass, u16 type, u32 ttl, u16 rdata_size, void* rdata) /* 5 match, delete 1 */
{
    zassert(db != NULL && name_ != NULL && (rdata_size == 0 || rdata != NULL));

    dnsname_stack name;
    DEBUG_RESET_dnsname(name);

    dnsname_to_dnsname_vector(name_, &name);

    zdb_ttlrdata ttlrdata;

    ZDB_RECORD_TTLRDATA_SET(ttlrdata, ttl, rdata_size, rdata);

    /* I do not really require a record set here ... */
    return zdb_zone_label_delete_record_exact(db, &name, zclass, type, &ttlrdata);
}

#endif

/** @brief Destroys the database
 *
 *  Destroys a database. (Emtpies it)
 *
 *  @param[in]  db the database to destroy
 *
 */

void
zdb_destroy(zdb* db)
{
    int zclass;

    for(zclass = HOST_CLASS_IN - 1; zclass < ZDB_RECORDS_MAX_CLASS; zclass++)
    {
        alarm_close(db->alarm_handle);
        db->alarm_handle = ALARM_HANDLE_INVALID;
        zdb_zone_label_destroy(&db->root[zclass]);
    }
}

#ifndef NDEBUG

/** @brief DEBUG: Prints the content of the database.
 *
 *  DEBUG: Prints the content of the database.
 *
 *  @param[in]  db the database to print
 *
 */

void
zdb_print(zdb* db)
{
    int zclass;

    formatln("zdb@%p\n", (void*)db);

    if(db != NULL)
    {
        for(zclass = HOST_CLASS_IN - 1; zclass < ZDB_RECORDS_MAX_CLASS; zclass++)
        {
            u16 class_value = zclass + 1;
            formatln("zdb@%p class=%{dnsclass}\n", (void*)db, &class_value);

            zdb_zone_label_print_indented(db->root[zclass], 1);
        }
    }
}

#endif

/** @} */
