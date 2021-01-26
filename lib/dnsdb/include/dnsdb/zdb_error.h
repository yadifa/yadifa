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

#ifndef _ZDB_ERROR_H
#define	_ZDB_ERROR_H

#include <dnscore/sys_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/** @brief a negative number that marks the start of the ZDB error codes */
#define ZDB_ERROR_BASE				0x80040000
#define ZDB_ERROR_CODE(code_)			((s32)(ZDB_ERROR_BASE+(code_)))

#define ZDB_ERROR_GENERAL			            ZDB_ERROR_CODE(0x0000)
    
#define ZDB_ERROR_KEY_NOTFOUND			        ZDB_ERROR_CODE(0x0001) // DATABASE KEY
#define ZDB_ERROR_DELETEFROMEMPTY		        ZDB_ERROR_CODE(0x0002) // DATABASE could not delete because collection is empty
#define ZDB_ERROR_NOSUCHCLASS	                ZDB_ERROR_CODE(0x0003) // DATABASE class not found
#define ZDB_ERROR_NOSOAATAPEX			        ZDB_ERROR_CODE(0x0004) // DATABASE zone has not SOA
#define ZDB_ERROR_COULDNOTOOBTAINZONEIMAGE      ZDB_ERROR_CODE(0x0005)

#define ZDB_ERROR_CORRUPTEDSOA		    	    ZDB_ERROR_CODE(0x1001) // RECORD soa is corrupted

#define ZDB_ERROR_ZONE_IS_NOT_SIGNED            ZDB_ERROR_CODE(0x3001) // DATABASE zone dnssec // not used
#define ZDB_ERROR_ZONE_IS_ALREADY_BEING_SIGNED  ZDB_ERROR_CODE(0x3002) // DATABASE zone dnssec
#define ZDB_ERROR_ZONE_INVALID                  ZDB_ERROR_CODE(0x3003) // DATABASE zone dynamic update
#define ZDB_ERROR_ZONE_IS_NOT_DNSSEC            ZDB_ERROR_CODE(0x3004) // DATABASE zone dnssec // not used
#define ZDB_ERROR_ZONE_NO_ZSK_PRIVATE_KEY_FILE  ZDB_ERROR_CODE(0x3005) // DATABASE zone dnssec
#define ZDB_ERROR_ZONE_NO_ACTIVE_DNSKEY_FOUND   ZDB_ERROR_CODE(0x3006) // DATABASE zone dnssec // not used
#define ZDB_ERROR_ZONE_NOT_IN_DATABASE          ZDB_ERROR_CODE(0x3007) // DATABASE zone
#define ZDB_ERROR_ZONE_NOT_MAINTAINED           ZDB_ERROR_CODE(0x3008) // DATABASE zone
#define ZDB_ERROR_ZONE_OPERATION_WOULD_BLOCK    ZDB_ERROR_CODE(0x3009) // DATABASE zone
    
#define ZDB_READER_WRONGNAMEFORZONE	            ZDB_ERROR_CODE(0x4001) // DATABASE zone load // not used
#define ZDB_READER_ZONENOTLOADED	            ZDB_ERROR_CODE(0x4002) // DATABASE zone load // not used
#define ZDB_READER_FIRST_RECORD_NOT_SOA         ZDB_ERROR_CODE(0x4003) // DATABASE zone load
#define ZDB_READER_ANOTHER_DOMAIN_WAS_EXPECTED  ZDB_ERROR_CODE(0x4004) // DATABASE zone load
#define ZDB_READER_NSEC3WITHOUTNSEC3PARAM       ZDB_ERROR_CODE(0x4005) // DATABASE zone load // not used
#define ZDB_READER_MIXED_DNSSEC_VERSIONS        ZDB_ERROR_CODE(0x4006) // DATABASE zone load // not used
#define ZDB_READER_ALREADY_LOADED               ZDB_ERROR_CODE(0x4007) // DATABASE zone load // not used
#define ZDB_READER_NSEC3PARAMWITHOUTNSEC3       ZDB_ERROR_CODE(0x4008) // DATABASE zone load // not used

#define ZDB_ERROR_ICMTL_NOTFOUND   		        ZDB_ERROR_CODE(0x5001) // ICMTL
#define ZDB_ERROR_ICMTL_STATUS_INVALID          ZDB_ERROR_CODE(0x5002) // ICMTL // not used
#define ZDB_ERROR_ICMTL_FOLDERPATHTOOLONG       ZDB_ERROR_CODE(0x5003) // ICMTL // not used
    
#define ZDB_JOURNAL_WRONG_PARAMETERS            ZDB_ERROR_CODE(0x6001)
#define ZDB_JOURNAL_READING_DID_NOT_FOUND_SOA   ZDB_ERROR_CODE(0x6002) // nowhere in a scan // not used
#define ZDB_JOURNAL_SOA_RECORD_EXPECTED         ZDB_ERROR_CODE(0x6003) // record being read was expected to be an SOA // not used
#define ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE   ZDB_ERROR_CODE(0x6004)
#define ZDB_JOURNAL_FEATURE_NOT_SUPPORTED       ZDB_ERROR_CODE(0x6005)
#define ZDB_JOURNAL_NOT_INITIALISED             ZDB_ERROR_CODE(0x6006)
#define ZDB_JOURNAL_IS_BUSY                     ZDB_ERROR_CODE(0x6007)
#define ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY   ZDB_ERROR_CODE(0x6008)
#define ZDB_JOURNAL_SERIAL_RANGE_LOCKED         ZDB_ERROR_CODE(0x6009)
#define ZDB_JOURNAL_LOOKS_CORRUPTED             ZDB_ERROR_CODE(0x6081)
#define ZDB_JOURNAL_UNEXPECTED_MAGIC            ZDB_ERROR_CODE(0x6082)
#define ZDB_JOURNAL_SHORT_READ                  ZDB_ERROR_CODE(0x6083)
#define ZDB_JOURNAL_SIZE_LIMIT_TOO_SMALL        ZDB_ERROR_CODE(0x6084)

#define ZDB_JOURNAL_SHOULD_NOT_BE_USED(err__) (((err__) >= ZDB_JOURNAL_LOOKS_CORRUPTED) && ((err__) <= ZDB_JOURNAL_SHORT_READ) )

void zdb_register_errors();

#ifdef	__cplusplus
}
#endif

#endif	/* _ZDB_ERROR_H */

/** @} */
