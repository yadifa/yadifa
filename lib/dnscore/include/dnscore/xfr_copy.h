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
/** @defgroup ### #######
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#ifndef XFR_H
#define	XFR_H

#include <dirent.h>

#include <dnscore/input_stream.h>
#include <dnscore/message.h>

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * Reads from the tcp input stream for an xfr
 * Detects the xfr
 * Copies into the right file
 *
 * @return error code
 */

typedef enum
{
    XFR_ALLOW_AXFR=1,
    XFR_ALLOW_IXFR=2,
    XFR_ALLOW_BOTH=3
} xfr_copy_flags;

#define XFR_FULL_EXT ".axfr"
#define XFR_FULL_EXT_STRLEN 5
#define XFR_FULL_FILE_MODE      0600

#define XFR_INCREMENTAL_EXT ".ix"
#define XFR_INCREMENTAL_EXT_STRLEN 3
#define XFR_INCREMENTAL_FILE_MODE      0600
#define XFR_INCREMENTAL_WIRE_FILE_FORMAT "%s/%{dnsname}%08x-%08x" XFR_INCREMENTAL_EXT

/**
 * Fixes an issue with the dirent not always set as expected.
 *
 * The type can be set to DT_UNKNOWN instead of file or directory.
 * In that case the function will call stats to get the type.
 */

u8 dirent_get_file_type(const char* folder, struct dirent *entry);

ya_result xfr_copy_get_data_path(const char *base_data_path, const u8 *origin, char *data_path, u32 data_path_size);

ya_result xfr_copy_make_data_path(const char *base_data_path, const u8 *origin, char *data_path, u32 data_path_size);

ya_result xfr_delete_axfr(const u8 *origin, const char* folder);

ya_result xfr_delete_ix(const u8 *origin, const char* folder);

ya_result xfr_opendir(const char* filepath);

ya_result xfr_unlink(const char* filepath);

/**
 * 
 * Downloads an AXFR/IXFR stream and builds (or updates) a journal on disk
 * 
 * @param is the input stream with the AXFR or IXFR, wire format
 * @param flags mostly XFR_ALLOW_AXFR or XFR_ALLOW_IXFR
 * @param origin the domain of the zone
 * @param base_data_path the folder where to put the journal (or journal hash directories and journal)
 * @param current_serial the serial currently available
 * @param loaded_serial a pointer to get the serial available after loading
 * @param message the message that led to this download
 * 
 * @return an error code, TYPE_AXFR, TYPE_IXFR, TYPE_NONE
 */

typedef struct xfr_copy_args xfr_copy_args;

struct xfr_copy_args
{
    input_stream            *is;
    u8                      *origin;
    const char              *base_data_path;
    message_data            *message;
    
    u32                     current_serial;
    u32                     out_loaded_serial;
    
    u64                     out_journal_file_append_offset;    
    u64                     out_journal_file_append_size;    
    xfr_copy_flags          flags;    
};

ya_result xfr_copy(xfr_copy_args* args);


#ifdef	__cplusplus
}
#endif

#endif	/* XFR_H */


/** @} */
