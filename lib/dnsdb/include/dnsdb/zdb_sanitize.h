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
/** @defgroup zone Functions used to manipulate a zone
 *  @ingroup dnsdb
 *  @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 */

#ifndef _ZDB_SANITIZE_H
#define	_ZDB_SANITIZE_H

#include <dnsdb/zdb_zone.h>

#ifdef	__cplusplus
extern "C"
{
#endif

#define SANITY_ERROR_BASE                          0x800b0000

#define SANITY_UNEXPECTEDSOA          1
#define SANITY_TOOMANYSOA             2
#define SANITY_CNAMENOTALONE          4
#define SANITY_UNEXPECTEDCNAME        8
#define SANITY_EXPECTEDNS            16
#define SANITY_UNEXPECTEDDS          32
#define SANITY_TRASHATDELEGATION     64
#define SANITY_TRASHUNDERDELEGATION 128
#define SANITY_TOOMANYNSEC          256
#define SANITY_RRSIGWITHOUTKEYS     512

#define SANITY_MUSTDROPZONE    32768

ya_result zdb_sanitize_rr_set(zdb_zone *zone, zdb_rr_label *label);

ya_result zdb_sanitize_rr_label(zdb_zone *zone, zdb_rr_label *label, dnsname_stack *name);

ya_result zdb_sanitize_rr_label_with_parent(zdb_zone *zone, zdb_rr_label *label, dnsname_stack *name);

ya_result zdb_sanitize_zone(zdb_zone *zone);

#ifdef	__cplusplus
}
#endif

#endif	/* _ZDB_ZONE_H */

/** @} */
