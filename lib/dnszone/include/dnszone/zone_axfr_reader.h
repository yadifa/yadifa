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
/** @defgroup zoneaxfr AXFR file loader module
 *  @ingroup dnszone
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#ifndef ZONE_AXFR_READER_H
#define	ZONE_AXFR_READER_H

#include <dnszone/dnszone.h>

/** @brief Opens an axfr file
 *
 *  Opens an axfr file
 *
 *  @param[in]  fullpath the path and name of the file to open
 *  @param[out] zone a pointer to a structure that will be used by the function
 *              to hold the zone-file information
 *
 *  @return     A result code
 *  @retval     OK   : the file has been opened successfully
 *  @retval     else : an error occurred
 */

ya_result zone_axfr_reader_open(const char* filepath, zone_reader *dst);

/**
 * Opens the axfr with the highest serial
 */

ya_result zone_axfr_reader_open_last(const char* axfrpath, u8 *origin, zone_reader *dst);

ya_result zone_axfr_reader_open_with_serial(const char* data_path, u8 *origin, u32 loaded_serial, zone_reader *dst);

#endif	/* ZONE_AXFR_READER_H */

/*    ------------------------------------------------------------    */

/** @} */
