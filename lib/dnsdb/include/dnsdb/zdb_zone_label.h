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

/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Internal functions for the database: zoned resource records label.
 *
 *  Internal functions for the database: zoned resource records label.
 *
 *  The ZONE LABEL is a label that can:
 *
 *  _ contains a zone cut
 *  _ contains a cached label
 *
 *  They should only be used as the top holding structure of the database
 *
 * @{
 */

#ifndef _ZONE_LABEL_H
#define	_ZONE_LABEL_H

#include <dnsdb/zdb_types.h>

#ifdef	__cplusplus
extern "C"
{
#endif

#define ZDB_ZONELABEL_TAG 0x4c424c4e5a42445a     /* "ZDBZNLBL" */

#if 0 /* fix */
#else

/**
 * @brief TRUE if the zone_label contains information (records, zone or a set of labels), else FALSE
 */

/* 2 USES */
#define ZONE_LABEL_RELEVANT(zone_label) ((zone_label)->zone!=NULL||dictionary_notempty(&(zone_label)->sub))

/**
 * @brief FALSE if the zone_label contains information (records, zone or a set of labels), else TRUE
 */

/* 4 USES */
#define ZONE_LABEL_IRRELEVANT(zone_label) ((zone_label)->zone==NULL&&dictionary_isempty(&(zone_label)->sub))

#endif
    
/**
 * @brief Search for the label of a zone in the database
 *
 * Search for the label of a zone in the database
 *
 * @param[in] db the database to explore
 * @param[in] name the dnsname_vector mapping the label
 *
 * @return a pointer to the label or NULL if it does not exists in the database.
 *
 */

/* 3 USES */
zdb_zone_label* zdb_zone_label_find(zdb* db, const dnsname_vector* name);

zdb_zone_label* zdb_zone_label_find_from_name(zdb* db, const char* name);
zdb_zone_label* zdb_zone_label_find_from_dnsname(zdb* db, const u8* dns_name);
zdb_zone_label* zdb_zone_label_find_from_dnsname_nolock(zdb* db, const u8* dns_name);
zdb_zone_label* zdb_zone_label_find_nolock(zdb *db, const dnsname_vector* origin);
zdb_zone_label* zdb_zone_label_add_nolock(zdb *db, const dnsname_vector* origin);

/**
 * @brief Destroys a label and its collections.
 *
 * Destroys a label and its collections.
 * Most likely irrelevant outside of zdb.
 *
 * @param[in] zone_labelp a pointer to a pointer to the label to destroy.
 *
 */

/* 1 USE */
void zdb_zone_label_destroy(zdb_zone_label **zone_labelp);

/**
 * @brief Gets pointers to all the zone labels along the path of a name.
 *
 * Gets pointers to all the zone labels along the path of a name.
 *
 * @param[in] db a pointer to the database
 * @param[in] name a pointer to the dns name
 * @param[in] zone_label_vector a pointer to the vector that will hold the labels pointers
 *
 * @return the top of the vector (-1 = empty)
 */

/* 1 USE */
s32 zdb_zone_label_match(zdb* db, const dnsname_vector *name, zdb_zone_label_pointer_array zone_label_vector);



/**
 * @brief Destroys a zone label and all its collections
 *
 * Destroys a zone label and all its collections
 *
 * @parm[in] db a pointer to the database
 * @parm[in] name a pointer to the name
 *
 * @return an error code
 */

/* 2 USES */
ya_result zdb_zone_label_delete(zdb* db, dnsname_vector* name);


#if DEBUG

/**
 * DEBUG: prints the label content
 */

void zdb_zone_label_print_indented(zdb_zone_label* zone_label, output_stream *os, int indent);
void zdb_zone_label_print(zdb_zone_label* zone_label, output_stream *os);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _ZONE_LABEL_H */

/** @} */
