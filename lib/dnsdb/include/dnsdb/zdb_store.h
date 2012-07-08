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
/** @defgroup dnsdb
 *  @ingroup dnsdb
 *  @brief Internal functions for the database: storage of the db.
 *
 *  Storage of the DB.
 *  The axfr, ixfr, signature, ... will make use of this format.
 *
 * @{
 */

#ifndef _ZDB_STORE_H
#define	_ZDB_STORE_H

#include <stddef.h>
#include <dnsdb/zdb_types.h>
#include <dnscore/ptr_vector.h>

/*
#include <dnscore/zonefile_reader.h>
*/

#ifdef	__cplusplus
extern "C" {
#endif

#define STORE_FORMAT_NAME "YADIFA-DB"

#define ZDB_ZONE_STORE_META_TERMINATOR  0x00
#define ZDB_ZONE_STORE_META_CHILD       0x01
#define ZDB_ZONE_STORE_META_BROTHER     0x02
#define ZDB_ZONE_STORE_META_ROOT_REMOVE 0x03
#define ZDB_ZONE_STORE_META_ROOT_ADD    0x04
#define ZDB_ZONE_STORE_META_NSEC3       0x05
#define ZDB_ZONE_STORE_META_DONE        0x06

#define ZDB_ZONE_STORE_BASE_START           "YADIFAB"
#define ZDB_ZONE_STORE_BASE_STOP            "yadifab"

#define ZDB_ZONE_STORE_INCREMENTAL_START    "YADIFAI"
#define ZDB_ZONE_STORE_INCREMENTAL_STOP     "yadifai"

    ya_result zdb_store_getfileprefix(const u8* origin, u16 zclass, char* buffer, size_t buffer_size);
    ya_result zdb_store_file_test_prefix_suffix(const char* filename, const char* prefix, u32 prefix_len, const char* suffix, u32 suffix_len);
    ya_result zdb_store_search(const u8* origin, u16 zclass, u32* bestserial_p, ptr_vector* serial_bestpath_p);

    /*
    void zdb_store_zonefile_reader_initinstance(zonefile_reader* zfrp);
    */
    
#ifdef	__cplusplus
}
#endif

#endif	/* _ZDB_ZONE_STORE_H */

/*
 * @}
 */
