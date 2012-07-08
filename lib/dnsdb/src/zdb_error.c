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
/** @defgroup error Database error handling
 *  @ingroup dnsdb
 *  @brief Database error handling
 *
 * @{
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <dnscore/sys_types.h>
#include "dnsdb/zdb_error.h"

/*
 *
 */

static bool zdb_register_errors_done = FALSE;

void
zdb_register_errors()
{
    if(zdb_register_errors_done)
    {
        return;
    }

    zdb_register_errors_done = TRUE;

    error_register(ZDB_ERROR_BASE, "An error occurred in the database.");

    error_register(ZDB_ERROR_KEY_NOTFOUND, "No match has been found for the current operation");
    error_register(ZDB_ERROR_DELETEFROMEMPTY, "Delete from an empty collection.");

    error_register(ZDB_ERROR_CANTOPEN, "Cannot open the zone file. Check errno");
    error_register(ZDB_ERROR_BADMAGIC, "The zone file has not been recognized as a Yadifa zone file.");
    error_register(ZDB_ERROR_CORRUPTEDDATA, "The zone file's content is corrupted.");

    error_register(ZDB_ERROR_NOSUCHCLASS, "There is no such class in the database.");

    error_register(ZDB_ERROR_FIRSTENTRYNOTSOA, "The zone file didn't start with an SOA");
    error_register(ZDB_ERROR_ZONEALREADYLOADED, "The zone has already been loaded.");
    error_register(ZDB_ERROR_WRONGNAMEFORZONE, "A name in the zone does not match the origin.");
    error_register(ZDB_ERROR_ZONENOTLOADED, "The zone has not been loaded.");

    error_register(ZDB_ERROR_NOSOAATAPEX, "ZDB_ERROR_NOSOAATAPEX");
    error_register(ZDB_ERROR_CORRUPTEDSOA, "ZDB_ERROR_CORRUPTEDSOA");

    error_register(ZDB_ERROR_MMAPFAILED, "ZDB_ERROR_MMAPFAILED");
    error_register(ZDB_ERROR_OUTOFMEMORY, "ZDB_ERROR_OUTOFMEMORY");

    error_register(ZDB_ERROR_CANTOPENDIRECTORY, "ZDB_ERROR_CANTOPENDIRECTORY");
    error_register(ZDB_ERROR_CANTOPENFILE, "ZDB_ERROR_CANTOPENFILE");
    
    error_register(ZDB_ERROR_ICMTL_NOTFOUND, "ZDB_ERROR_ICMTL_NOTFOUND");
    error_register(ZDB_ERROR_ICMTL_STATUS_INVALID,"ZDB_ERROR_ICMTL_STATUS_INVALID");
    error_register(ZDB_ERROR_ICMTL_FOLDERPATHTOOLONG,"ZDB_ERROR_ICMTL_FOLDERPATHTOOLONG");
    error_register(ZDB_ERROR_ICMTL_SOADONTMATCH, "ZDB_ERROR_ICMTL_SOADONTMATCH");
    error_register(ZDB_ERROR_ICMTL_SOANOTFOUND, "ZDB_ERROR_ICMTL_SOANOTFOUND");

    error_register(ZDB_ERROR_FILEPATH_TOOLONG, "ZDB_ERROR_FILEPATH_TOOLONG");
    error_register(ZDB_ERROR_ZONE_IS_NOT_SIGNED, "ZDB_ERROR_ZONE_IS_NOT_SIGNED");
    error_register(ZDB_ERROR_ZONE_IS_ALREADY_BEING_SIGNED, "ZDB_ERROR_ZONE_IS_ALREADY_BEING_SIGNED");

    error_register(ZDB_READER_FIRST_RECORD_NOT_SOA, "ZDB_READER_FIRST_RECORD_NOT_SOA");
    error_register(ZDB_READER_ANOTHER_DOMAIN_WAS_EXPECTED, "ZDB_READER_ANOTHER_DOMAIN_WAS_EXPECTED");
    error_register(ZDB_READER_NSEC3WITHOUTNSEC3PARAM, "ZDB_READER_NSEC3WITHOUTNSEC3PARAM");
    error_register(ZDB_READER_MIXED_DNSSEC_VERSIONS, "ZDB_READER_MIXED_DNSSEC_VERSIONS");
    error_register(ZDB_READER_ALREADY_LOADED, "ZDB_READER_ALREADY_LOADED");
    
    error_register(DNSSEC_ERROR_BASE, "DNSSEC_ERROR_BASE");

    error_register(DNSSEC_ERROR_NOENGINE, "DNSSEC_ERROR_NOENGINE");
    error_register(DNSSEC_ERROR_INVALIDENGINE, "DNSSEC_ERROR_INVALIDENGINE");
    error_register(DNSSEC_ERROR_CANTCREATETHREAD, "DNSSEC_ERROR_CANTCREATETHREAD");
    error_register(DNSSEC_ERROR_CANTPOOLTHREAD, "DNSSEC_ERROR_CANTPOOLTHREAD");

    error_register(DNSSEC_ERROR_NOSUPPORT, "DNSSEC_ERROR_NOSUPPORT");

    error_register(DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM, "DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM");
    error_register(DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM, "DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM");

    error_register(DNSSEC_ERROR_DUPLICATEKEY, "DNSSEC_ERROR_DUPLICATEKEY");
    error_register(DNSSEC_ERROR_INCOMPLETEKEY, "DNSSEC_ERROR_INCOMPLETEKEY");
    error_register(DNSSEC_ERROR_KEYSTOREPATHISTOOLONG, "DNSSEC_ERROR_KEYSTOREPATHISTOOLONG");
    error_register(DNSSEC_ERROR_UNABLETOCREATEKEYFILES, "DNSSEC_ERROR_UNABLETOCREATEKEYFILES");
    error_register(DNSSEC_ERROR_KEYWRITEERROR, "DNSSEC_ERROR_KEYWRITEERROR");
    error_register(DNSSEC_ERROR_BNISNULL, "DNSSEC_ERROR_BNISNULL");
    error_register(DNSSEC_ERROR_BNISBIGGERTHANBUFFER, "DNSSEC_ERROR_BNISBIGGERTHANBUFFER");
    error_register(DNSSEC_ERROR_UNEXPECTEDKEYSIZE, "DNSSEC_ERROR_UNEXPECTEDKEYSIZE");
    error_register(DNSSEC_ERROR_KEYISTOOBIG, "DNSSEC_ERROR_KEYISTOOBIG");

    error_register(DNSSEC_ERROR_RSASIGNATUREFAILED, "DNSSEC_ERROR_RSASIGNATUREFAILED");

    error_register(DNSSEC_ERROR_NSEC3_INVALIDZONESTATE, "DNSSEC_ERROR_NSEC3_INVALIDZONESTATE");
    error_register(DNSSEC_ERROR_NSEC3_LABELTODIGESTFAILED, "DNSSEC_ERROR_NSEC3_LABELTODIGESTFAILED");
    error_register(DNSSEC_ERROR_NSEC3_DIGESTORIGINOVERFLOW, "DNSSEC_ERROR_NSEC3_DIGESTORIGINOVERFLOW");

    error_register(DNSSEC_ERROR_RRSIG_NOENGINE, "DNSSEC_ERROR_RRSIG_NOENGINE");
    error_register(DNSSEC_ERROR_RRSIG_NOZONEKEYS, "DNSSEC_ERROR_RRSIG_NOZONEKEYS");
    error_register(DNSSEC_ERROR_RRSIG_NOUSABLEKEYS, "DNSSEC_ERROR_RRSIG_NOUSABLEKEYS");
    error_register(DNSSEC_ERROR_RRSIG_NOSOA, "DNSSEC_ERROR_RRSIG_NOSOA");
    error_register(DNSSEC_ERROR_RRSIG_NOSIGNINGKEY, "DNSSEC_ERROR_RRSIG_NOSIGNINGKEY");
    error_register(DNSSEC_ERROR_RRSIG_UNSUPPORTEDRECORD, "DNSSEC_ERROR_RRSIG_UNSUPPORTEDRECORD");
}



/** @} */
