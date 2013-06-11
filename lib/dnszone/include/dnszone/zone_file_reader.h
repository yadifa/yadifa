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
/** @defgroup zonefile Zone file loader module
 *  @ingroup dnszone
 *  @brief Zone file loader module
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#ifndef ZONE_FILE_READER_H_
#define ZONE_FILE_READER_H_
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include <dnszone/dnszone.h>

/*    ------------------------------------------------------------
 *
 *      VALUES
 */
/** \def ttl value used for the zone file if none provided */
#define		DEFAULT_TTL             86400
#define		DOT_DOMAIN              "."

#define		BRACKET_CLOSED          0x00U
#define		BRACKET_OPEN            0x01U
/**  flag settings for printing the zone file
 * \param 0 means not printing of the resource records
 * \param 1 means printing of the resource records
 */
#define		WITHOUT_RR		0
#define		WITH_RR                 1

/*    ------------------------------------------------------------
 *
 *      VALUES
 */

/*    ------------------------------------------------------------
 *
 *      ENUM
 */

/*    ------------------------------------------------------------
 *
 *      STRUCTS
 */

/*    ------------------------------------------------------------
 *
 *      PROTOTYPES
 */

/** @brief Opens a zone file
 *
 *  Opens a zone file
 *
 *  @param[in]  fullpath the path and name of the file to open
 *  @param[out] zone a pointer to a structure that will be used by the function
 *              to hold the zone-file information
 *
 *  @return     A result code
 *  @retval     OK   : the file has been opened successfully
 *  @retval     else : an error occurred
 */

ya_result zone_file_reader_parse_stream(input_stream *ins, zone_reader *dst);
ya_result zone_file_reader_open(const char* fullpath, zone_reader *dst);

void zone_file_reader_ignore_missing_soa(zone_reader *dst);

#endif

/*    ------------------------------------------------------------    */

/**
 * @}
 */
