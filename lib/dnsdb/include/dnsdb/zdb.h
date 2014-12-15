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

#include <dnsdb/zdb_config.h>
#include <dnsdb/zdb_types.h>
#include <dnsdb/zdb_error.h>
#include <dnscore/message.h>
#include <dnscore/fingerprint.h>

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

dnslib_fingerprint
dnsdb_getfingerprint();
u32
dnsdb_fingerprint_mask();

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

void zdb_create(zdb* db);

/** @brief Returns all the records in a zone.
 *
 *  Returns all the records in a zone.
 *
 *
 *
 *  @param[in]  db the database
 *  @param[in]  dnsname_domain the domain dnsname to search in
 *  @param[out] out a set of results
 *
 *  @return OK in case of success.
 */
/* ya_result zdb_axfr   (zdb* db, u8* origin,zone_iterator* iterator);*/

#if 1
//#error obsolete
/** @brief Search for a single match in the database
 *
 *  Search for a match in the database.
 *  Only the most relevant match will be returned (ONE record set)
 *
 *  @param[in]  db the database
 *  @param[in]  dnsname_name the name dnsname to search for
 *  @param[in]  class the class to match
 *  @param[in]  type the type to match
 *  @param[out] ttl_rdara_out a pointer to a pointer set of results (single linked list)
 *
 *  @return SUCCESS in case of success.
 */

ya_result zdb_query(zdb* db, u8* dnsname_name, u16 class, u16 type, zdb_packed_ttlrdata** ttlrdara_out);
#endif

static inline void zdb_query_ex_answer_create(zdb_query_ex_answer *ans_auth_add)
{
    ZEROMEMORY(ans_auth_add, sizeof(zdb_query_ex_answer));
}

/**
 *  @brief Build a dns answer from a query.
 *
 *  Build a dns answer from a query.
 *
 *  Records are stored in the zdb_query_ex_answer structure (four lists)
 *
 *  After the answer has been processed, it must be destroyed using zdb_query_ex_answer_destroy
 *
 * @param db
 * @param mesg
 * @param ans_auth_add
 * @param pool_buffer
 *
 * @return
 */

finger_print zdb_query_ex(zdb *db, message_data *mesg, zdb_query_ex_answer *ans_auth_add, u8 *restrict pool_buffer);

/**
 * Destroys a zdb_query_ex_answer structure created with zdb_query_ex
 *
 * @param ans_auth_add
 */

// void zdb_query_ex_answer_destroy(zdb_query_ex_answer* ans_auth_add);
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

ya_result zdb_query_ip_records(zdb* db, const u8* name_, u16 zclass, zdb_packed_ttlrdata **ttlrdata_out_a, zdb_packed_ttlrdata **ttlrdata_out_aaaa);

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

ya_result zdb_add(zdb* db, u8* origin_, u8* name_, u16 zclass, u16 type, u32 ttl, u16 rdata_size, void* rdata); /* 4 match, add    1 */

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

ya_result zdb_delete(zdb* db, u8* origin, u8* name, u16 zclass, u16 type, u32 ttl, u16 rdata_size, void* rdata); /* 5 match, delete 1 */


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

bool zdb_is_zone_invalid(zdb *db, const u8 *origin, u16 zclass);

/** @brief DEBUG: Prints the content of the database.
 *
 *  DEBUG: Prints the content of the database.
 *
 *  @param[in]  db the database to print
 *
 */



#ifdef DEBUG
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
