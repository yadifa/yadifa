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
/** @defgroup
 *  @ingroup dnsdb
 *  @brief
 *
 *
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>

#include <dnscore/sys_types.h>
#include <dnscore/dnscore.h>
#include <dnscore/format.h>

#include <dnscore/bytearray_output_stream.h>

#if ZDB_HAS_DNSSEC_SUPPORT != 0
#include "dnsdb/dnssec.h"
#endif

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_dnsname.h"
#include "dnsdb/zdb_zone_label_iterator.h"

/*
 * SOA
 */

ya_result
rr_soa_get_serial(const u8* rdata, u16 rdata_size, u32* serial)
{
    s32 soa_size = rdata_size;

    const u8* soa_start = rdata;

    u32 len = dnsname_len(soa_start);

    soa_size -= len;

    if(soa_size <= 0)
    {
        return ZDB_ERROR_CORRUPTEDSOA;
    }

    soa_start += len;

    len = dnsname_len(soa_start);
    soa_size -= len;

    if(soa_size != 5 * 4) /* Only the 5 32 bits (should) remain */
    {
        return ZDB_ERROR_CORRUPTEDSOA;
    }

    soa_start += len;

    if(serial != NULL)
    {
        *serial = ntohl(GET_U32_AT(*soa_start));
    }

    return SUCCESS;
}

ya_result
rr_soa_increase_serial(u8* rdata, u16 rdata_size, u32 increment)
{
    s32 soa_size = rdata_size;

    u8* soa_start = rdata;

    u32 len = dnsname_len(soa_start);

    soa_size -= len;

    if(soa_size <= 0)
    {
        return ZDB_ERROR_CORRUPTEDSOA;
    }

    soa_start += len;

    len = dnsname_len(soa_start);
    soa_size -= len;

    if(soa_size != 5 * 4) /* Only the 5 32 bits (should) remain */
    {
        return ZDB_ERROR_CORRUPTEDSOA;
    }

    soa_start += len;

    SET_U32_AT(*soa_start, htonl(ntohl(GET_U32_AT(*soa_start)) + increment));

    return SUCCESS;
}

ya_result
rr_soa_get_minimumttl(const u8* rdata, u16 rdata_size, u32* minimum_ttl)
{
    s32 soa_size = rdata_size;

    const u8* soa_start = rdata;

    u32 len = dnsname_len(soa_start);

    soa_size -= len;

    if(soa_size <= 0)
    {
        return ZDB_ERROR_CORRUPTEDSOA;
    }

    soa_start += len;

    len = dnsname_len(soa_start);
    soa_size -= len;

    if(soa_size != 5 * 4) /* Only the 5 32 bits (should) remain */
    {
        return ZDB_ERROR_CORRUPTEDSOA;
    }

    soa_start += len + 16;

    *minimum_ttl = ntohl(GET_U32_AT(*soa_start));

    return SUCCESS;
}

/*
 *
 */


ya_result
log_rdata(logger_handle *hndl, int level, u16 type, u8* rdata_pointer, u16 rdata_size)
{
    ya_result return_code;
    output_stream os;
    bytearray_output_stream_context os_context;
    char buffer[4096];

    bytearray_output_stream_init_ex_static(&os, (u8*)buffer, sizeof (buffer), 0, &os_context);

    if(FAIL(return_code = osprint_rdata(&os, type, rdata_pointer, rdata_size)))
    {
        return return_code;
    }

    output_stream_write_u8(&os, 0);
    buffer[sizeof (buffer) - 1] = '\0'; /* If the buffer is full, this will ensure it is terminated. */

    logger_handle_msg(hndl, level, "%s", bytearray_output_stream_buffer(&os));

    output_stream_close(&os);

    return SUCCESS;
}

ya_result
osprint_query_ex_section(output_stream* os, zdb_resourcerecord* section)
{
    while(section != NULL)
    {
        osformat(os, "%{dnsname} %-6d %{dnsclass} %{dnstype} ", section->name, section->ttl_rdata->ttl, &section->zclass, &section->rtype);
        osprint_rdata(os, section->rtype, ZDB_PACKEDRECORD_PTR_RDATAPTR(section->ttl_rdata), ZDB_PACKEDRECORD_PTR_RDATASIZE(section->ttl_rdata));
        osprintln(os, "");

        section = section->next;
    }
    osprint_char(os, '\n');
    
    return 0;
}

void
print_query_ex_section(zdb_resourcerecord* section)
{
    osprint_query_ex_section(termout, section);
}

void
osprint_query_ex(output_stream* os, zdb_query_ex_answer* answer)
{
    if(answer->answer != NULL)
    {
        osprint(os, ";; ANSWER SECTION:\n");
        osprint_query_ex_section(os, answer->answer);
    }
    if(answer->authority != NULL)
    {
        osprint(os, ";; AUTHORITY SECTION:\n");
        osprint_query_ex_section(os, answer->authority);
    }
    if(answer->additional != NULL)
    {
        osprint(os, ";; ADDITIONAL SECTION:\n");
        osprint_query_ex_section(os, answer->additional);
    }
}

void
print_query_ex(zdb_query_ex_answer* answer)
{
    osprint_query_ex(termout, answer);
}

/** @} */

/*----------------------------------------------------------------------------*/

