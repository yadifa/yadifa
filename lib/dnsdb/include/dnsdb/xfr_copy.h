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
#include <dnscore/fdtools.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define XFR_FULL_FILE_MODE      0600

/**
 * 
 * Deletes the AXFR wire dumps of a zone. Hashed folders are not removed.
 * 
 * @param origin
 * @param base_data_path where to remove the file from (and its hashed folders)
 * @return 
 */

ya_result xfr_delete_axfr(const u8 *origin);

/**
 * 
 * Copies an AXFR stream from an XFR (xfr_input_stream) into a wire dump (.axfr)
 * 
 * @param xis the xfr_input_stream
 * @param base_data_path where to put the file (and its hashed folder)
 * 
 * @return an error code
 */

ya_result xfr_copy(input_stream *xis, const char *base_data_path, bool base_data_path_is_target);

#ifdef	__cplusplus
}
#endif

#endif	/* XFR_H */


/** @} */
