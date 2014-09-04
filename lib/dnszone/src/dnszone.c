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
/** @defgroup dnszone Zone loader modules
 * 
 *  @brief Zone loader modules
 *
 * @{
 */

#include <stdio.h>
#include <stdlib.h>

#include "dnszone/dnszone-config.h"

#include <dnscore/output_stream.h>
#include <dnscore/logger.h>
#include <dnscore/dnscore.h>

#include <dnsdb/zdb_types.h>
#include <dnsdb/zdb.h>

#include "dnszone/dnszone.h"
#include "dnszone/zone_file_reader.h"

dnslib_fingerprint
dnszone_getfingerprint()
{
    dnslib_fingerprint ret = 0
#if HAS_TSIG_SUPPORT
    | DNSLIB_TSIG
#endif
#if HAS_ACL_SUPPORT != 0
    | DNSLIB_ACL
#endif
#if HAS_NSEC_SUPPORT != 0
    | DNSLIB_NSEC
#endif
#if HAS_NSEC3_SUPPORT != 0
    | DNSLIB_NSEC3
#endif
    ;

    return ret;
}

u32
dnszone_fingerprint_mask()
{
    return DNSLIB_TSIG|DNSLIB_ACL|DNSLIB_NSEC|DNSLIB_NSEC3;
}

static void
dnszone_register_errors()
{
    error_register(ZONEREAD_ERROR_BASE,"ZONEREAD_ERROR_BASE");
    error_register(ZRE_AXFR_FILE_NOT_FOUND,"ZRE_AXFR_FILE_NOT_FOUND");
    error_register(ZRE_NO_VALID_FILE_FOUND,"ZRE_NO_VALID_FILE_FOUND");
        
    zone_file_reader_init_error_codes();
}

logger_handle *g_zone_logger = NULL;

ya_result
dnszone_init()
{
    dnszone_register_errors();

    if(dnscore_getfingerprint() != (dnszone_getfingerprint() & dnscore_fingerprint_mask()))
    {
        fprintf(stderr, "dnszone: Mismatched fingerprint: %s: %08x != (%08x = %08x & %08x)\n",
                "core",
                dnscore_getfingerprint(),
                dnszone_getfingerprint() & dnscore_fingerprint_mask(),
                dnszone_getfingerprint() , dnscore_fingerprint_mask());

        fflush(NULL);

        exit(-1);
    }

    if(dnsdb_getfingerprint() != (dnszone_getfingerprint() & dnsdb_fingerprint_mask()))
    {
        fprintf(stderr, "dnszone: Mismatched fingerprint: %s: %08x != (%08x = %08x & %08x)\n",
                "db",
                dnsdb_getfingerprint(),
                dnszone_getfingerprint() & dnsdb_fingerprint_mask(),
                dnszone_getfingerprint() , dnsdb_fingerprint_mask());

        fflush(NULL);

        exit(-1);
    }
    
    //g_zone_logger = logger_handle_get("zone");

    return SUCCESS;
}

/** @} */
