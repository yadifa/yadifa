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
/** @defgroup zonefile Zone file loader module
 *  @ingroup dnszone
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#ifndef RESOURCERECORD_H_
#define RESOURCERECORD_H_

#include <dnscore/output_stream.h>
#include <dnsdb/zdb_zone_load_interface.h>

#ifdef __cplusplus
extern "C" {
#endif
/*
#include    "config.h"
*/
#include    <ctype.h>
#include    <limits.h>
#include    <stdint.h>
#include    <stdio.h>

#define     RR_NAME                 0x01U
#define     RR_CLASS                0x02U
#define     RR_TYPE                 0x04U
#define     RR_TTL                  0x08U
#define     RR_RDATA                0x10U
#define     RR_PRINT_PAYLOAD        0x20U
#define     RR_ALL                  (RR_NAME | RR_CLASS | RR_TYPE | RR_TTL | RR_RDATA | RR_PRINT_PAYLOAD)


#define		BRACKET_CLOSED          0x00U
#define		BRACKET_OPEN            0x01U

int         rr_convert_2dname(u_char **, const char *);

/** @todo used only in the commented out TCL code */
ya_result   rr_convert_rdata(output_stream *os, u_char *, const u16, const u_char *);

ya_result   rr_get_origin(const char *, u8 **);     /* parse */
ya_result   rr_get_ttl(const char *, u32 *);        /* parse */

ya_result   rr_parse_line(char *textline, const u8 *origin, u8 *label, u32 default_ttl, resource_record *rr, int *bracket_status);

void        rr_print(output_stream*, resource_record *, const char *, u8);
void        rr_print_all(output_stream*, resource_record *, const char *, u8);

    /*    ------------------------------------------------------------    */

#ifdef __cplusplus
}
#endif

#endif /* RESOURCERECORD_H_ */

/*    ------------------------------------------------------------    */

/** @} */
