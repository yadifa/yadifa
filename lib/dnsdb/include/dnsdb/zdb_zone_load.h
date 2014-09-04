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
/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 */

#ifndef __ZDB_ZONE_LOAD__H__
#define	__ZDB_ZONE_LOAD__H__

#include <dnsdb/zdb_types.h>
#include <dnsdb/zdb_zone_load_interface.h>

#ifdef	__cplusplus
extern "C"
{
#endif

/**
 * @brief Load a zone in the database.
 *
 * Load a zone in the database.
 * This is clearly MASTER oriented.
 *
 * @param[in] db a pointer to the database
 * @param[in] filename a pointer to the filename of the zone
 * @param[out] zone_pointer_out will contains a pointer to the loaded zone if the call is successful
 *
 * @return an error code.
 *
 */

#define ZDB_ZONE_MOUNT_ON_LOAD      0x01   /* put the zone in the database after a load    */
#define ZDB_ZONE_REPLAY_JOURNAL     0x02   /* replay the journal after the load            */
#define ZDB_ZONE_DESTROY_JOURNAL    0x04   /* destroys the journal after a successful load */
#define ZDB_ZONE_IS_SLAVE           0x08   /* any NSEC3 inconsistencies must trigger an AXFR reload */

#define ZDB_ZONE_DNSSEC_SHIFT           4
#define ZDB_ZONE_DNSSEC_MASK       0x0070
#define ZDB_ZONE_NOSEC             0x0000
#define ZDB_ZONE_NSEC              0x0010
#define ZDB_ZONE_NSEC3             0x0020
#define ZDB_ZONE_NSEC3_OPTOUT      0x0030

ya_result zdb_zone_load(zdb* db, zone_reader* zr, zdb_zone** zone_out, const char *incremental_data_path, const u8 *expected_origin, u16 flags);

ya_result zdb_zone_get_soa(zone_reader *zone_data, u16 *rdata_size, u8 *rdata);

ya_result zdb_zone_read_serial(zdb* db, zone_reader* zr, const char *incremental_data_path, u32 *serial, bool withjournal);


#ifdef	__cplusplus
}
#endif

#endif	/* __ZDB_ZONE_LOAD__H__ */

/** @} */
