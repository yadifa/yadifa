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
/** @defgroup dnskey DNSSEC keys functions
 *  @ingroup dnsdbdnssec
 *  @brief 
 *
 *
 * @{
 */
#ifndef _DNSKEY_H
#define	_DNSKEY_H

#include <dnscore/sys_types.h>
#include <dnscore/rfc.h>

/*
 * Extract fields from a packed record
 *
 */

#define DNSKEY_FLAGS(x__)      (ntohs(GET_U16_AT((x__).rdata_start[0])))    /** @todo : NATIVEFLAGS */
#define DNSKEY_PROTOCOL(x__)   ((x__).rdata_start[2])
#define DNSKEY_ALGORITHM(x__)  ((x__).rdata_start[3])

/*
 * Computes the key tag from a packed record
 */

#define DNSKEY_TAG(x__)        (dnskey_getkeytag(&(x__).rdata_start[0],(x__).rdata_size))

#ifdef	__cplusplus
extern "C"
{
#endif

/** Key tag */
u16 dnskey_getkeytag(const u8* dnskey_rdata,u32 dnskey_rdata_size);

/** Key tag */
unsigned int dnskey_getkeytag_reference(unsigned char key[],  /* the RDATA part of the DNSKEY RR */
                                        unsigned int keysize  /* the RDLENGTH */
                                       );

#ifdef	__cplusplus
}
#endif

#endif	/* _DNSKEY_H */


/** @} */

/*----------------------------------------------------------------------------*/

