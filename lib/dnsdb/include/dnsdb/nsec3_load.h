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
/** @defgroup nsec3 NSEC3 functions
 *  @ingroup dnsdbdnssec
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _NSEC3_LOAD_H
#define	_NSEC3_LOAD_H

#include <dnsdb/nsec3_types.h>

#ifdef	__cplusplus
extern "C"
{
#endif

ya_result nsec3_load_init(nsec3_load_context* context, zdb_zone* zone);
void nsec3_load_destroy(nsec3_load_context* context);

ya_result nsec3_load_add_nsec3param(nsec3_load_context* context, const u8* entry_rdata, u16 entry_rdata_size);
ya_result nsec3_load_add_nsec3(nsec3_load_context* context, const u8* entry_name, u32 entry_ttl, const u8* entry_rdata, u16 entry_rdata_size);
ya_result nsec3_load_add_rrsig(nsec3_load_context* context, const u8* entry_name, u32 entry_ttl, const u8* entry_rdata, u16 entry_rdata_size);

ya_result nsec3_load_compile(nsec3_load_context* context);

bool nsec3_load_is_context_empty(nsec3_load_context* ctx);

#ifdef	__cplusplus
}
#endif

#endif	/* _NSEC3_LOAD_H */
/** @} */

/*----------------------------------------------------------------------------*/

