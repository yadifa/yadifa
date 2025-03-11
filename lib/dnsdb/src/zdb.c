/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 * @defgroup dnsdb Zone database
 * @brief The zone dataBase
 *
 * @{
 *----------------------------------------------------------------------------*/

#define ZDB_JOURNAL_CODE 1

#include "dnsdb/dnsdb_config.h"

#include <stdio.h>
#include <stdlib.h>
// #include <strings.h>

#include <dnscore/logger.h>
#include <dnscore/format.h>
#if HAS_RDTSC
#include <dnscore/rdtsc.h>
#endif
#include <dnscore/sys_error.h>

#include <dnscore/dnscore.h>
#include <dnscore/sys_get_cpu_count.h>

#include <dnscore/thread_pool.h>

#include <dnscore/pcg_basic.h>

extern logger_handle_t *g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#include "dnsdb/zdb.h"

#if ZDB_HAS_DNSSEC_SUPPORT
#include "dnsdb/dnssec_keystore.h"
#endif

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/dictionary.h"
#include "dnsdb/journal.h"
#include "dnsdb/zdb_zone_garbage.h"
#include "dnscore/crypto.h"

#if ZDB_OPENSSL_SUPPORT
#include <dnscore/dnskey.h> // needed
#include <dnscore/pcg_basic.h>

/*
 * Required to handle openssl with multiple threads
 */

#define ZDB_SSLMUTEX_TAG 0x584554554d4c5353

#ifndef __DATE__
#define __DATE__ "date?"
#endif

#ifndef __TIME__
#define __TIME__ "time?"
#endif

#if HAS_BUILD_TIMESTAMP
#if DEBUG
const char *dnsdb_lib = "dnsdb " __DATE__ " " __TIME__ " debug";
#else
const char *dnsdb_lib = "dnsdb " __DATE__ " " __TIME__ " release";
#endif
#else
#if DEBUG
const char *dnsdb_lib = "dnsdb debug";
#else
const char *dnsdb_lib = "dnsdb release";
#endif
#endif

void dnssec_keystore_init();

#if SSL_API_LT_110

static mutex_t *ssl_mutex = NULL;
static int      ssl_mutex_count = 0;

static void     ssl_lock(int mode, int type, const char *file, int line)
{
    if((mode & CRYPTO_LOCK) != 0)
    {
        /* lock */

        mutex_lock(&ssl_mutex[type]);
    }
    else
    {
        /* unlock */

        mutex_unlock(&ssl_mutex[type]);
    }
}

static unsigned long ssl_thread_id() { return (unsigned long)thread_self(); }

#endif

#endif

logger_handle_t *g_database_logger = LOGGER_HANDLE_SINK;

/** @brief Initializes the database internals.
 *
 *  Checks the architecture settings of the binary.
 *  Initializes the database internals.
 *  Multiple calls is a NOP.
 *
 *  This is not thread safe.
 *
 */

static initialiser_state_t zdb_init_state = INITIALISE_STATE_INIT;

dnsdb_fingerprint          dnsdb_getfingerprint()
{
    dnsdb_fingerprint ret = dnsdb_getmyfingerprint();
    return ret;
}

uint32_t dnsdb_fingerprint_mask() { return DNSCORE_TSIG | DNSCORE_ACL | DNSCORE_NSEC | DNSCORE_NSEC3; }

int      zalloc_init();

void     zdb_init_ex(uint32_t thread_pool_count)
{
    (void)thread_pool_count;

    if(initialise_state_begin(&zdb_init_state))
    {
        extern pcg32_random_t dns_packet_writer_add_rrset_rng;
        pcg32_srandom_r(&dns_packet_writer_add_rrset_rng, timeus() >> 32, timeus() >> 16);

        /* DO or DIE */

        if(dnscore_getfingerprint() != dnscore_getmyfingerprint())
        {
            flushout();
            flusherr();
            printf("dnsdb: the linked dnscore features are %08x but the lib has been compiled against one with %08x", dnscore_getfingerprint(), dnscore_getmyfingerprint());
            fflush(NULL);
            abort(); // binary incompatiblity : full stop
        }

        // Init the dns core

        dnscore_init();

        zalloc_init();

        zdb_zone_garbage_init();

        // Init the error table

        zdb_register_errors();

        crypto_init();

#if ZDB_OPENSSL_SUPPORT

        dnssec_keystore_init();
#endif

        journal_init(0); // uses the default mru size (512)

        logger_start();

        initialise_state_ready(&zdb_init_state);
    }
}

void zdb_init()
{
    uint32_t thread_pool_count = sys_get_cpu_count() + 2;

    zdb_init_ex(thread_pool_count);
}

void zdb_finalize()
{
    if(initialise_state_unready(&zdb_init_state))
    {
#if ZDB_HAS_DNSSEC_SUPPORT
#if DEBUG
        dnssec_keystore_finalise();
        dnssec_keystore_resetpath();
#endif
#endif
        zdb_zone_garbage_finalize();
        journal_finalize();
#if ZDB_OPENSSL_SUPPORT
        crypto_finalise();
#endif
        initialise_state_end(&zdb_init_state);
    }
}

/** @brief Initializes a database.
 *
 *  Initializes a database.
 *
 *  @param[in]  db a pointer to the zdb structure that will be initialized.
 *
 */

void zdb_create(zdb_t *db)
{
    zdb_zone_label_t *zone_label;

    ZALLOC_OBJECT_OR_DIE(zone_label, zdb_zone_label_t, ZDB_ZONELABEL_TAG);
    ZEROMEMORY(zone_label, sizeof(zdb_zone_label_t));
    zone_label->name = dnslabel_zdup(ROOT_LABEL); /* . */
    dictionary_init(&zone_label->sub);

#if ZDB_HAS_RRCACHE_ENABLED
    zdb_resource_record_sets_init(&zone_label->global_resource_record_set);
#endif
    db->root = zone_label; /* native order */

    db->alarm_handle = alarm_open((const uint8_t *)"\010d@tabase"); // a name that is not likely to be used for a domain as it has invalid chars

    group_mutex_init(&db->mutex);
}

/**
 *
 * Puts a zone in the DB.
 *
 * If a zone with the same name did exist, returns the old zone (to be released)
 * and replaces it with the one given as a parameter.
 *
 * This function temporarily locks the database for writing.
 * The zone added gets its RC increased.
 *
 * @param db the database
 * @param zone the zone to mount (will be RC++)
 * @return the previously mounted zone (to be RC--)
 */

zdb_zone_t *zdb_set_zone(zdb_t *db, zdb_zone_t *zone)
{
    yassert(zone != NULL);

    zdb_lock(db, ZDB_MUTEX_WRITER);
    zdb_zone_label_t *label = zdb_zone_label_add_nolock(db, &zone->origin_vector); // zdb_set_zone
    zdb_zone_t       *old_zone = label->zone;
    zdb_zone_acquire(zone);
    label->zone = zone;
#if DEBUG
    log_debug("zdb: added zone %{dnsname}@%p", zone->origin, zone);
#endif
    zdb_unlock(db, ZDB_MUTEX_WRITER);
    return old_zone;
}

zdb_zone_t *zdb_remove_zone(zdb_t *db, dnsname_vector_t *name)
{
    yassert(db != NULL && name != NULL);

    zdb_lock(db, ZDB_MUTEX_WRITER);
    zdb_zone_label_t *label = zdb_zone_label_find(db, name); // zdb_detach_zone
    zdb_zone_t       *old_zone = NULL;
    if(label != NULL)
    {
        old_zone = label->zone;
        label->zone = NULL;
#if DEBUG
        log_debug("zdb: removed zone %{dnsnamevector}@%p", name, old_zone);
#endif
        if(ZONE_LABEL_IRRELEVANT(label))
        {
            // removes the label from the database
            // if the label had been relevant (sub domains)
            // the zones below would be released and destroyed in due time

            zdb_zone_label_delete(db, name);
        }
    }
    zdb_unlock(db, ZDB_MUTEX_WRITER);
    return old_zone;
}

zdb_zone_t *zdb_remove_zone_from_dnsname(zdb_t *db, const uint8_t *fqdn)
{
    dnsname_vector_t origin;

    dnsname_to_dnsname_vector(fqdn, &origin);

    zdb_zone_t *zone = zdb_remove_zone(db, &origin);

    return zone;
}

/** @brief Search for a match in the database
 *
 *  Search for a match in the database.
 *  Only the most relevant match will be returned.
 *
 *  @param[in]  db the database
 *  @param[in]  dnsname_name the name dnsname to search for
 *  @param[in]  type the type to match
 *  @param[out] ttl_rdara_out a pointer to a pointer set of results (single linked list)
 *
 *  @return SUCCESS in case of success.
 *
 *  @note 20190109 edf -- cannot be marked as OBSOLETE as the function is used on another project.
 */

ya_result zdb_query_ip_records(zdb_t *db, const uint8_t *name_, zdb_resource_record_set_t **restrict rrset_out_a,
                               zdb_resource_record_set_t **restrict rrset_out_aaaa) // mutex checked
{
    yassert(rrset_out_a != NULL && rrset_out_aaaa != NULL);

    dnsname_vector_t name;

    dnsname_to_dnsname_vector(name_, &name);

    /* Find closest matching label
     * Should return a stack of zones
     */

#ifdef HAS_DYNAMIC_PROVISIONING
    zdb_lock(db, ZDB_MUTEX_READER); // zdb_query_ip_records
#endif

    zdb_zone_label_pointer_array zone_label_stack;

    int32_t                      top = zdb_zone_label_match(db, &name, zone_label_stack);
    int32_t                      sp = top;

    /* Got a stack of zone labels with and without zone cuts */
    /* Search the label on the zone files */

    while(sp >= 0)
    {
        zdb_zone_label_t *zone_label = zone_label_stack[sp];

        if(zone_label->zone != NULL)
        {
            /* Get the label, instead of the type in the label */
            zdb_rr_label_t *rr_label = zdb_rr_label_find_exact(zone_label->zone->apex, name.labels, name.size - sp);

            if(rr_label != NULL)
            {
                zdb_resource_record_set_t *a = zdb_resource_record_sets_find(&rr_label->resource_record_set, TYPE_A);       // zone is locked
                zdb_resource_record_set_t *aaaa = zdb_resource_record_sets_find(&rr_label->resource_record_set, TYPE_AAAA); // zone is locked

                if(a != NULL || aaaa != NULL)
                {
                    *rrset_out_a = a;
                    *rrset_out_aaaa = aaaa;

#ifdef HAS_DYNAMIC_PROVISIONING
                    zdb_unlock(db, ZDB_MUTEX_READER); // zdb_query_ip_records (success)
#endif

                    return SUCCESS;
                }
            }
        }

        sp--;
    }

#if ZDB_HAS_RRCACHE_ENABLED

    /* We exhausted the zone files direct matches.
     * We have to fallback on the global (cache) matches.
     * And it's easy because we have the answer already:
     */

    if(top == name.size)
    {
        /* We found a perfect match label in the global part of the database */

        zdb_resource_record_data_t *a = zdb_resource_record_sets_find(&zone_label_stack[top]->global_resource_record_set, TYPE_A);
        zdb_resource_record_data_t *aaaa = zdb_resource_record_sets_find(&zone_label_stack[top]->global_resource_record_set, TYPE_AAAA);

        if(a != NULL || aaaa != NULL)
        {
            *ttlrdata_out_a = a;
            *ttlrdata_out_aaaa = aaaa;

#ifdef HAS_DYNAMIC_PROVISIONING
            zdb_unlock(db, ZDB_MUTEX_READER); // zdb_query_ip_records (cache success)
#endif

            return SUCCESS;
        }
    }

#endif

#ifdef HAS_DYNAMIC_PROVISIONING
    zdb_unlock(db, ZDB_MUTEX_READER); // zdb_query_ip_records (failure)
#endif

    return ZDB_ERROR_KEY_NOTFOUND;
}

/**
 *
 * Appends all A and AAAA records found in the database for the given fqdn
 * Given the nature of the list, what is returned is a copy.
 * The call locks the database for reading, then each involved zone for reading.
 * Locks are released before the function returns.
 * The port field of the host_address is set to a given port (network order)
 *
 * @param db database
 * @param name_ fqdn
 * @param target_list list
 * @param network_order_port u16
 * @return
 */

ya_result zdb_append_ip_records_with_port_ne(zdb_t *db, const uint8_t *name_, host_address_t *target_list, uint16_t network_order_port)
{
    yassert(target_list != NULL);

    dnsname_vector_t name;

    dnsname_to_dnsname_vector(name_, &name);

    /* Find closest matching label
     * Should return a stack of zones
     */

#ifdef HAS_DYNAMIC_PROVISIONING
    zdb_lock(db, ZDB_MUTEX_READER); // zdb_query_ip_records
#endif

    zdb_zone_label_pointer_array zone_label_stack;

    int32_t                      top = zdb_zone_label_match(db, &name, zone_label_stack);
    int32_t                      sp = top;

    /* Got a stack of zone labels with and without zone cuts */
    /* Search the label on the zone files */

    while(sp >= 0)
    {
        zdb_zone_label_t *zone_label = zone_label_stack[sp];

        if(zone_label->zone != NULL)
        {
            zdb_zone_lock(zone_label->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
            /* Get the label, instead of the type in the label */
            zdb_rr_label_t *rr_label = zdb_rr_label_find_exact(zone_label->zone->apex, name.labels, name.size - sp); // zone is locked

            if(rr_label != NULL)
            {
                ya_result                              ret = 0;

                zdb_resource_record_set_t             *rrset;

                zdb_resource_record_set_const_iterator iter;

                rrset = zdb_resource_record_sets_find(&rr_label->resource_record_set, TYPE_A); // zone is locked

                if(rrset != NULL)
                {
                    zdb_resource_record_set_const_iterator_init((zdb_resource_record_set_const_t *)rrset, &iter);
                    while(zdb_resource_record_set_const_iterator_has_next(&iter))
                    {
                        const zdb_resource_record_data_t *a_record = zdb_resource_record_set_const_iterator_next(&iter);

                        host_address_append_ipv4(target_list, zdb_resource_record_data_rdata_const(a_record), network_order_port);
                        ++ret;
                    }
                }

                rrset = zdb_resource_record_sets_find(&rr_label->resource_record_set, TYPE_AAAA); // zone is locked
                if(rrset != NULL)
                {
                    zdb_resource_record_set_const_iterator_init((zdb_resource_record_set_const_t *)rrset, &iter);
                    while(zdb_resource_record_set_const_iterator_has_next(&iter))
                    {
                        const zdb_resource_record_data_t *aaaa_record = zdb_resource_record_set_const_iterator_next(&iter);

                        host_address_append_ipv6(target_list, zdb_resource_record_data_rdata_const(aaaa_record), network_order_port);
                        ++ret;
                    }
                }

                zdb_zone_unlock(zone_label->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

                zdb_unlock(db, ZDB_MUTEX_READER); // zdb_query_ip_records (success)

                return ret;
            }

            zdb_zone_unlock(zone_label->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
        }

        sp--;
    }

#if ZDB_HAS_RRCACHE_ENABLED

    /* We exhausted the zone files direct matches.
     * We have to fallback on the global (cache) matches.
     * And it's easy because we have the answer already:
     */

    if(top == name.size)
    {
        /* We found a perfect match label in the global part of the database */

        zdb_resource_record_data_t *a = zdb_resource_record_sets_find(&zone_label_stack[top]->global_resource_record_set, TYPE_A);
        zdb_resource_record_data_t *aaaa = zdb_resource_record_sets_find(&zone_label_stack[top]->global_resource_record_set, TYPE_AAAA);

        if(a != NULL || aaaa != NULL)
        {
            *ttlrdata_out_a = a;
            *ttlrdata_out_aaaa = aaaa;

#ifdef HAS_DYNAMIC_PROVISIONING
            zdb_unlock(db, ZDB_MUTEX_READER); // zdb_query_ip_records (cache success)
#endif

            return SUCCESS;
        }
    }

#endif

#ifdef HAS_DYNAMIC_PROVISIONING
    zdb_unlock(db, ZDB_MUTEX_READER); // zdb_query_ip_records (failure)
#endif

    return ZDB_ERROR_KEY_NOTFOUND;
}

/**
 *
 * Appends all A and AAAA records found in the database for the given fqdn
 * Given the nature of the list, what is returned is a copy.
 * The call locks the database for reading, then each involved zone for reading.
 * Locks are released before the function returns.
 *
 * @param db database
 * @param name_ fqdn
 * @param target_list list
 * @return
 */

ya_result zdb_append_ip_records(zdb_t *db, const uint8_t *name_, host_address_t *target_list)
{
    ya_result ret = zdb_append_ip_records_with_port_ne(db, name_, target_list, NU16(DNS_DEFAULT_PORT));
    return ret;
}

/** @brief Destroys the database
 *
 *  Destroys a database. (Empties it)
 *
 *  @param[in]  db the database to destroy
 *
 */

void zdb_destroy(zdb_t *db) // mutex checked
{
    zdb_lock(db, ZDB_MUTEX_WRITER); // zdb_destroy

    alarm_close(db->alarm_handle);
    db->alarm_handle = ALARM_HANDLE_INVALID;

    zdb_zone_label_destroy(&db->root); /* native order */

    zdb_unlock(db, ZDB_MUTEX_WRITER); // zdb_destroy

    group_mutex_destroy(&db->mutex);
}

static void zdb_signature_check_one(const char *name, int should, int is)
{
    if(is != should)
    {
        printf("critical: zdb: '%s' should be of size %i but is of size %i\n", name, is, should);
        fflush(stdout);
        abort();
    }
}

void zdb_signature_check(int so_zdb, int so_zdb_zone, int so_zdb_zone_label, int so_zdb_rr_label, int so_mutex_t)
{
    DNSCORE_API_CHECK();

    zdb_signature_check_one("zdb", sizeof(zdb_t), so_zdb);
    zdb_signature_check_one("zdb_zone", sizeof(zdb_zone_t), so_zdb_zone);
    zdb_signature_check_one("zdb_zone_label", sizeof(zdb_zone_label_t), so_zdb_zone_label);
    zdb_signature_check_one("zdb_rr_label", sizeof(zdb_rr_label_t), so_zdb_rr_label);
    zdb_signature_check_one("mutex_t", sizeof(mutex_t), so_mutex_t);
}

#if DEBUG

/** @brief DEBUG: Prints the content of the database.
 *
 *  DEBUG: Prints the content of the database.
 *
 *  @param[in]  db the database to print
 *
 */

void zdb_print(zdb_t *db, output_stream_t *os) // mutex checked
{
    osformatln(os, "zdb@%p\n", (void *)db);

    if(db != NULL)
    {
        zdb_lock(db, ZDB_MUTEX_READER); // for print db
        osformatln(os, "zdb@%p class=%{dnsclass}\n", (void *)db, &db->zclass);
        zdb_zone_label_print_indented(db->root, os, 1); /* native order */
        zdb_unlock(db, ZDB_MUTEX_READER);               // for print db
    }
}

#endif

/** @} */
