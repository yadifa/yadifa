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
/** @defgroup ### #######
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#ifndef XFR_H
#define	XFR_H

#include <dirent.h>

#include <dnscore/xfr_input_stream.h>
#include <dnscore/message.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define XFR_FULL_EXT ".axfr"
#define XFR_FULL_EXT_STRLEN 5
#define XFR_FULL_FILE_MODE      0600

#ifndef _DIRENT_HAVE_D_TYPE
#ifndef DT_UNKNOWN
#define DT_UNKNOWN  0
#endif
#ifndef DT_REG 
#define DT_REG      8
#endif
#endif
    
/**
 * Fixes an issue with the dirent not always set as expected.
 *
 * The type can be set to DT_UNKNOWN instead of file or directory.
 * In that case the function will call stats to get the type.
 */

u8 dirent_get_file_type(const char* folder, struct dirent *entry);

/**
 * 
 * Returns the hashed folder path for a zone.
 * 
 * @param data_path             the target buffer for the data path
 * @param data_path_size        the target buffer size
 * @param base_data_path        the base folder
 * @param origin                the origin of the zone
 * 
 * @return 
 */

ya_result xfr_copy_get_data_path(char *data_path, u32 data_path_size, const char *base_data_path, const u8 *origin);

/**
 * 
 * Returns the hashed folder path for a zone.  Creates the path
 * 
 * @param data_path             the target buffer for the data path
 * @param data_path_size        the target buffer size
 * @param base_data_path        the base folder
 * @param origin                the origin of the zone
 * 
 * @return 
 */

ya_result xfr_copy_mkdir_data_path(char *data_path, u32 data_path_size, const char *base_data_path, const u8 *origin);

/**
 * 
 * Deletes the AXFR wire dumps of a zone. Hashed folders are not removed.
 * 
 * @param origin
 * @param base_data_path where to remove the file from (and its hashed folders)
 * @return 
 */

ya_result xfr_delete_axfr(const u8 *origin, const char *base_data_path);

/**
 * 
 * Copies an AXFR stream from an XFR (xfr_input_stream) into a wire dump (.axfr)
 * 
 * @param xis the xfr_input_stream
 * @param base_data_path where to put the file (and its hashed folder)
 * 
 * @return an error code
 */

ya_result xfr_copy(input_stream *xis, const char *base_data_path);

#ifdef	__cplusplus
}
#endif

#endif	/* XFR_H */


/** @} */
