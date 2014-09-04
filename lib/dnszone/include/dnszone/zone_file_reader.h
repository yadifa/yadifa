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

#pragma once

#include <dnsdb/zdb_zone_load_interface.h>

#define ZONEFILE_ERROR_BASE                       0x800A0000
#define ZONEFILE_ERROR_CODE(code_)                ((s32)(ZONEFILE_ERROR_BASE+(code_)))

#define ZONEFILE_FEATURE_NOT_SUPPORTED            ZONEFILE_ERROR_CODE(0x0001)
#define ZONEFILE_EXPECTED_FILE_PATH               ZONEFILE_ERROR_CODE(0x0002)
#define ZONEFILE_SOA_WITHOUT_CLASS                ZONEFILE_ERROR_CODE(0x0003)
#define ZONEFILE_SALT_TOO_BIG                     ZONEFILE_ERROR_CODE(0x0011)
#define ZONEFILE_TEXT_TOO_BIG                     ZONEFILE_ERROR_CODE(0x0012)
#define ZONEFILE_FLAGS_TOO_BIG                    ZONEFILE_ERROR_CODE(0x0013)
#define ZONEFILE_SERVICE_TOO_BIG                  ZONEFILE_ERROR_CODE(0x0014)
#define ZONEFILE_REGEX_TOO_BIG                    ZONEFILE_ERROR_CODE(0x0015)
#define ZONEFILE_RDATA_PARSE_ERROR                ZONEFILE_ERROR_CODE(0x0016)
#define ZONEFILE_RDATA_BUFFER_TOO_SMALL           ZONEFILE_ERROR_CODE(0x0017)
#define ZONEFILE_RDATA_SIZE_MISMATCH              ZONEFILE_ERROR_CODE(0x0018)

void zone_file_reader_init_error_codes();

ya_result zone_file_reader_parse_stream(input_stream *ins, zone_reader *zr);

ya_result zone_file_reader_open(const char *fullpath, zone_reader *zr);

ya_result zone_file_reader_set_origin(zone_reader *zr, const u8* origin);

void zone_file_reader_ignore_missing_soa(zone_reader *zr);

ya_result zone_file_reader_copy_rdata(const char *text, u16 rtype, u8 *rdata, u32 rdata_size, const u8 *origin);
