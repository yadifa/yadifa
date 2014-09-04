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
/** @defgroup rrsig RRSIG functions
 *  @ingroup dnsdbdnssec
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnscore/ptr_vector.h>
#include <dnsdb/zdb_types.h>

/* CANNOT BE ALLOCATED BY Z-ALLOC (THREAD ISSUE) */

typedef struct zdb_canonized_packed_ttlrdata zdb_canonized_packed_ttlrdata;
struct zdb_canonized_packed_ttlrdata
{
    u16 rdata_size;
    u16 rdata_canonized_size;   /* = htons(rdata_size) */
    u8  rdata_start[1];
};


/**
 * Appends copy of the rrset with the given type to the vector.
 * Records are added in canonical order.
 * 
 * @param type
 * @param rr_sll
 * @param rrsp
 */

void rr_canonize_rrset(u16 type, zdb_packed_ttlrdata* rr_sll, ptr_vector* rrsp);

/**
 * Releases the records in the vector.
 * 
 * @param rrsp
 */

void rr_canonize_free(ptr_vector* rrsp);

/** @} */


