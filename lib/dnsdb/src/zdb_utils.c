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
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dnscore/thread.h>

#include <dnscore/sys_types.h>
#include <dnscore/dnscore.h>
#include <dnscore/format.h>

#include <dnscore/bytearray_output_stream.h>

#if ZDB_HAS_DNSSEC_SUPPORT
#include "dnsdb/dnssec.h"
#endif

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_zone_label_iterator.h"

/*
 *
 */

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
