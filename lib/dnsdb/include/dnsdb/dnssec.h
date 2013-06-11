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
/** @defgroup dnsdbdnssec DNSSEC functions
 *  @ingroup dnsdb
 *  @brief 
 *
 * @{
 */
#ifndef _DNSSEC_H
#define	_DNSSEC_H
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <dnsdb/zdb_types.h>
#include <dnsdb/dnssec_config.h>
#include <dnsdb/rrsig.h>
#include <dnsdb/dnskey.h>

#include <dnsdb/dnssec_keystore.h>
#include <dnsdb/dnssec_rsa.h>
#include <dnsdb/dnssec_dsa.h>
#include <dnsdb/dnssec_scheduler.h>


/**
 * @todo NOTE: WARNING: IF THE MIN_TTL CHANGES IN THE SOA we MUST resign the NSEC* stuff.
 */

#if HAS_DNSSEC_SUPPORT != 0

#ifndef _DNSSEC_C
#include <dnscore/logger.h>
extern logger_handle *g_dnssec_logger;
#endif


#ifdef	__cplusplus
extern "C" {
#endif

#define DEFAULT_ENGINE_NAME             "openssl"

#define DNSSEC_DIGEST_TYPE_SHA1         1
#define DNSSEC_DIGEST_TYPE_SHA256       2

#define DNSSEC_MINIMUM_KEY_SIZE_BYTES   ((DNSSEC_MINIMUM_KEY_SIZE+7)/8)
#define DNSSEC_MAXIMUM_KEY_SIZE_BYTES   ((DNSSEC_MAXIMUM_KEY_SIZE+7)/8)

#define ENGINE_PRESET_DELIMITER ","
#define ENGINE_COMMAND_DELIMITER ":"

ENGINE* dnssec_loadengine(const char* engine_name);
void dnssec_unloadengine(ENGINE* engine);

void dnssec_inittask(u16 flags,dnssec_task* task);
void dnssec_finalizetask(dnssec_task* task);

int dnssec_process_getthreadcount();
void dnssec_process_setthreadcount(int count);

ya_result zdb_update_zone_signatures_alarm(void* zone);     /* zdb_zone* */
ya_result zdb_update_zone_signatures(zdb_zone* zone, bool scheduled);
ya_result zdb_update_signatures(zdb* db, bool scheduled);

/// @note MUST BE SET

void dnssec_set_xfr_path(const char* xfr_path);

#ifdef	__cplusplus
}
#endif

#endif

#endif	/* _DNSSEC_H */

    /*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/

