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

/** @defgroup 
 *  @ingroup dnsdb
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _ZDB_UTILS_H
#define	_ZDB_UTILS_H

#include <dnsdb/zdb_types.h>
#include <dnscore/serial.h>
#include <dnscore/output_stream.h>
#include <dnscore/logger.h>

#include <dnscore/timems.h>

#ifdef	__cplusplus
extern "C" {
#endif

    /*
     * FILE IOs FOR SPECIFIC TYPES
     * THE STORAGE IS NOT "RAW"
     * These will be obsoleted by the "streams"
     */

    ya_result fread_u8(FILE* f, u8* value);
    ya_result fread_u16(FILE* f, u16* valuep);
    ya_result fread_u32(FILE* f, u32* valuep);
    ya_result fread_pstr(FILE* f, u8* value, u32 maxsize);
    ya_result fread_dnsname(FILE* f, u8* value, u32 maxsize);
    ya_result fread_buffer(FILE* f, u8* buffer, u32 size);
    
    u8* fread_zalloc_pstr(FILE* f);
    u8* fread_zalloc_buffer(FILE* f,u32* size);

    /*
     * PRINT ANSWER
     */

    ya_result osprint_query_ex_section(output_stream* os, zdb_resourcerecord* section);
    void print_query_ex_section(zdb_resourcerecord* section);
    
    void osprint_query_ex(output_stream* os, zdb_query_ex_answer* answer);
    void print_query_ex(zdb_query_ex_answer* answer);

#ifdef	__cplusplus
}
#endif

#endif	/* _ZDB_UTILS_H */
/** @} */

