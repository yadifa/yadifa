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
/*----------------------------------------------------------------------------*/

#ifndef __DNSZONE_H__
#define __DNSZONE_H__

#include <dnscore/sys_types.h>
#include <dnscore/dnscore.h>
#include <dnsdb/zdb_zone_load_interface.h>

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 * This is supposed to help with huge amounts of file read only once ... except it does not really work (not always).
 * 
 */
#define     DNSDB_USE_POSIX_ADVISE  1

#define     ZONEREAD_ERROR_BASE             0x800a0000
#define     ZONEREAD_ERROR_CODE(code_)      ((s32)(ZONEREAD_ERROR_BASE+(code_)))
#define     ZRE_AXFR_FILE_NOT_FOUND         ZONEREAD_ERROR_CODE( 1)
#define     ZRE_NO_VALID_FILE_FOUND              ZONEREAD_ERROR_CODE( 2)
    
/*
 * This fingerprint feature has been added so libraries could check they are compatible
 */

dnslib_fingerprint dnszone_getfingerprint();

u32 dnszone_fingerprint_mask();

ya_result dnszone_init();

#ifdef __cplusplus
}
#endif

#endif /* __DNSZONE_H__ */

/*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/
