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

/** @defgroup dnsdb Zone database
 *  @brief The zone database
 *
 *  Implementation of structures and functions for the database
 *
 *  Memory usage approxymation:
 *
 *  let:
 *
 *  "digest" the size of a digest
 *  "n3pc" the number of nsec3param
 *  "r" the number of records
 *
 *  Memory usage =~ (233.3333 + ((446.666+digest) * n3pc) * r
 *
 *  Or, if the digest size is different for each n3p:
 *
 *  With "digest(n)" being the size of the digest for the n-th nsec3param
 *
 *  =~ (233.3333 + SUM[n=1..n3pc](446.666+digest(n))) * r
 *
 * @{
 */

#ifndef _ZDB_H
#define	_ZDB_H

#include <dnscore/message.h>
#include <dnscore/fingerprint.h>

#include <dnsdb/zdb_config.h>
#include <dnsdb/zdb_types.h>
#include <dnsdb/zdb_error.h>
#include <dnsdb/zdb-lock.h>

/* EDNS -> */
/* <- EDNS */

#ifdef	__cplusplus
extern "C"
{
#endif

#define ZDB_ROOT_TAG        0x544f4f5242445a    /* "ZDBROOT" */
#define ZDB_DOMAIN_ROOT_TAG 0x524e4d4442445a    /* "ZDBDMNR" */
#define ZDBZONE_TAG         0x454e4f5a42445a    /* "ZDBZONE" */

/*
 * This fingerprint feature has been added so libraries could check they are compatible
 */
    
typedef enum
{
    DNSDB_TSIG=1,
    DNSDB_ACL=2,
    DNSDB_NSEC=4,
    DNSDB_NSEC3=8,
    DNSDB_ZALLOC=16,
    DNSDB_DEBUG=32,
    DNSDB_RRCACHE=64
} dnsdb_fingerprint;

static inline dnsdb_fingerprint dnsdb_getmyfingerprint()
{
    dnsdb_fingerprint ret = (dnsdb_fingerprint)(0
    
#if ZDB_HAS_TSIG_SUPPORT
    | DNSDB_TSIG
#endif
#if ZDB_HAS_ACL_SUPPORT
    | DNSDB_ACL
#endif
#if ZDB_HAS_NSEC_SUPPORT
    | DNSDB_NSEC
#endif
#if ZDB_HAS_NSEC3_SUPPORT
    | DNSDB_NSEC3
#endif
#if ZDB_HAS_ZALLOC_SUPPORT
    | DNSDB_ZALLOC
#endif
#if DEBUG
    | DNSDB_DEBUG
#endif

    )
    ;
    
    return ret;
}

dnsdb_fingerprint dnsdb_getfingerprint();

u32 dnsdb_fingerprint_mask();

/** @brief Initializes the database internals.
 *
 *  Initializes the database internals.
 *  Multiple calls is a NOP.
 *
 *  This is not thread safe.
 *
 */

void zdb_init();

void zdb_init_ex(u32 thread_pool_count);

/** @brief Destroys the database internals.
 *
 *  Destroys the database internals.
 *  Multiple calls is a NOP.
 *
 *  This is not thread safe.
 *
 */

void zdb_finalize();

/** @brief Initializes a database.
 *
 *  Initializes a database.
 *
 *  @param[in]  db a pointer to the zdb structure that will be initialized.
 *
 */

void zdb_create(zdb *db);

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

zdb_zone *zdb_set_zone(zdb *db, zdb_zone* zone);

zdb_zone *zdb_remove_zone(zdb *db, dnsname_vector *name);

zdb_zone *zdb_remove_zone_from_dnsname(zdb *db, const u8 *dnsname);

static inline void zdb_query_ex_answer_create(zdb_query_ex_answer *ans_auth_add)
{
    ZEROMEMORY(ans_auth_add, sizeof(zdb_query_ex_answer));
}

/**
 * @brief Queries the database given a message
 * 
 * @param db the database
 * @param mesg the message
 * @param pool_buffer a big enough buffer used for the memory pool
 */

void zdb_query_and_update(zdb *db, message_data *mesg, u8 * restrict pool_buffer);

/**
 * @brief Queries the database given a message
 * 
 * @param db the database
 * @param mesg the message
 * @param pool_buffer a big enough buffer used for the memory pool
 * @param rrl_process an RRL callback that controls if the answer is to be made, truncated or dropped
 * 
 * @return the RRL status of the message (probably useless)
 */

ya_result zdb_query_and_update_with_rrl(zdb *db, message_data *mesg, u8 * restrict pool_buffer, rrl_process_callback *rrl_process);

/**
 * Destroys a zdb_query_ex_answer structure created with zdb_query_*
 * Kept for compatibility.
 * 
 * @param ans_auth_add
 */

#define zdb_query_ex_answer_destroy(unused__) ((void)unused__)

/**
 * @brief Writes the answer into the message.
 *
 * Writes the content of a zdb_query_ex_answer into a message_data.
 *
 * Returns the offset in the packet.
 * 
 * CANNOT FAIL !
 *
 * @param message
 * @param answer_set
 * @return
 */

ya_result zdb_query_message_update(message_data* message, zdb_query_ex_answer* answer_set);

/**
 * @brief Writes the answer into the message, using an RRL callback.
 *
 * Writes the content of a zdb_query_ex_answer into a message_data if the RRL callback allows it.
 *
 * Returns the offset in the packet.
 *
 * @param message
 * @param answer_set
 * @return
 */

#if 0 /* fix */
#else
static inline ya_result zdb_query_message_update_with_rrl(message_data* mesg, zdb_query_ex_answer* answer_set, rrl_process_callback *rrl_process)
{
    ya_result rrl = rrl_process(mesg, answer_set);
    
    return rrl;
}
#endif

/**
 * This function should not be used anymore. Please consider using zdb_append_ip_records instead.
 * 
 * @param db
 * @param name_
 * @param ttlrdata_out_a
 * @param ttlrdata_out_aaaa
 * @return 
 */

ya_result zdb_query_ip_records(zdb* db, const u8* name_, zdb_packed_ttlrdata **ttlrdata_out_a, zdb_packed_ttlrdata **ttlrdata_out_aaaa);

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

ya_result zdb_append_ip_records(zdb* db, const u8* name_, host_address *target_list);

/** @brief Destroys the database
 *
 *  Destroys a database. (Empties it)
 *
 *  @param[in]  db the database to destroy
 *
 */

void zdb_destroy(zdb* db);

/**
 * Looks for a zone and tells if zone is marked as invalid.
 * The zone can only be invalid if it exists.
 * 
 * @param db
 * @param origin
 * @param zclass
 * @return 
 */

bool zdb_is_zone_invalid(zdb *db, const u8 *origin);


/** @brief DEBUG: Prints the content of the database.
 *
 *  DEBUG: Prints the content of the database.
 *
 *  @param[in]  db the database to print
 *
 */

void zdb_signature_check(int so_zdb, int so_zdb_zone, int so_zdb_zone_label, int so_zdb_rr_label, int so_mutex_t);

#define ZDB_API_CHECK() zdb_signature_check(sizeof(zdb),sizeof(zdb_zone),sizeof(zdb_zone_label),sizeof(zdb_rr_label),sizeof(mutex_t))


#if DEBUG
/**
 * DEBUG
 */

void zdb_print(zdb *db, output_stream *os);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _ZDB_H */

/** @} */
