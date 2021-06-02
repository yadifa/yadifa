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

/** @defgroup error Database error handling
 *  @ingroup dnsdb
 *  @brief Database error handling
 *
 * @{
 */

#include "dnsdb/dnsdb-config.h"
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

    error_register(ZDB_ERROR_NOSUCHCLASS, "There is no such class in the database.");

    error_register(ZDB_READER_WRONGNAMEFORZONE, "A name in the zone does not match the origin.");
    error_register(ZDB_READER_ZONENOTLOADED, "The zone has not been loaded.");

    error_register(ZDB_ERROR_NOSOAATAPEX, "ZDB_ERROR_NOSOAATAPEX");

    error_register(ZDB_ERROR_COULDNOTOOBTAINZONEIMAGE, "ZDB_ERROR_COULDNOTOOBTAINZONEIMAGE");

    error_register(ZDB_ERROR_CORRUPTEDSOA, "ZDB_ERROR_CORRUPTEDSOA");

    error_register(ZDB_ERROR_ICMTL_NOTFOUND, "ZDB_ERROR_ICMTL_NOTFOUND");
    error_register(ZDB_ERROR_ICMTL_STATUS_INVALID,"ZDB_ERROR_ICMTL_STATUS_INVALID");
    error_register(ZDB_ERROR_ICMTL_FOLDERPATHTOOLONG,"ZDB_ERROR_ICMTL_FOLDERPATHTOOLONG");

    error_register(ZDB_ERROR_ZONE_IS_NOT_SIGNED, "ZDB_ERROR_ZONE_IS_NOT_SIGNED");
    error_register(ZDB_ERROR_ZONE_IS_ALREADY_BEING_SIGNED, "ZDB_ERROR_ZONE_IS_ALREADY_BEING_SIGNED");
    error_register(ZDB_ERROR_ZONE_INVALID, "ZDB_ERROR_ZONE_INVALID");
    error_register(ZDB_ERROR_ZONE_IS_NOT_DNSSEC, "ZDB_ERROR_ZONE_IS_NOT_DNSSEC");
    error_register(ZDB_ERROR_ZONE_NO_ZSK_PRIVATE_KEY_FILE, "ZDB_ERROR_ZONE_NO_ZSK_PRIVATE_KEY_FILE");
    error_register(ZDB_ERROR_ZONE_NO_ACTIVE_DNSKEY_FOUND, "ZDB_ERROR_ZONE_NO_ACTIVE_DNSKEY_FOUND");
    error_register(ZDB_ERROR_ZONE_NOT_IN_DATABASE, "ZDB_ERROR_ZONE_NOT_IN_DATABASE");
    error_register(ZDB_ERROR_ZONE_NOT_MAINTAINED,"ZDB_ERROR_ZONE_NOT_MAINTAINED");

    error_register(ZDB_READER_FIRST_RECORD_NOT_SOA, "ZDB_READER_FIRST_RECORD_NOT_SOA");
    error_register(ZDB_READER_ANOTHER_DOMAIN_WAS_EXPECTED, "ZDB_READER_ANOTHER_DOMAIN_WAS_EXPECTED");
    error_register(ZDB_READER_NSEC3WITHOUTNSEC3PARAM, "ZDB_READER_NSEC3WITHOUTNSEC3PARAM");
    error_register(ZDB_READER_MIXED_DNSSEC_VERSIONS, "ZDB_READER_MIXED_DNSSEC_VERSIONS");
    error_register(ZDB_READER_ALREADY_LOADED, "ZDB_READER_ALREADY_LOADED");
    error_register(ZDB_READER_NSEC3PARAMWITHOUTNSEC3, "ZDB_READER_NSEC3PARAMWITHOUTNSEC3");
    
    error_register(ZDB_JOURNAL_WRONG_PARAMETERS, "ZDB_JOURNAL_WRONG_PARAMETERS");
    error_register(ZDB_JOURNAL_READING_DID_NOT_FOUND_SOA, "ZDB_JOURNAL_READING_DID_NOT_FOUND_SOA");
    error_register(ZDB_JOURNAL_SOA_RECORD_EXPECTED, "ZDB_JOURNAL_SOA_RECORD_EXPECTED");
    error_register(ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE, "ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE");
    error_register(ZDB_JOURNAL_FEATURE_NOT_SUPPORTED, "ZDB_JOURNAL_FEATURE_NOT_SUPPORTED");
    error_register(ZDB_JOURNAL_NOT_INITIALISED, "ZDB_JOURNAL_NOT_INITIALISED");
    error_register(ZDB_JOURNAL_IS_BUSY, "ZDB_JOURNAL_IS_BUSY");
    error_register(ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY, "ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY");
    error_register(ZDB_JOURNAL_LOOKS_CORRUPTED, "ZDB_JOURNAL_LOOKS_CORRUPTED");
    error_register(ZDB_JOURNAL_UNEXPECTED_MAGIC, "ZDB_JOURNAL_UNEXPECTED_MAGIC");
    error_register(ZDB_JOURNAL_SHORT_READ, "ZDB_JOURNAL_SHORT_READ");
    error_register(ZDB_JOURNAL_SIZE_LIMIT_TOO_SMALL, "ZDB_JOURNAL_SIZE_LIMIT_TOO_SMALL");
}



/** @} */
