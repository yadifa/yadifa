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

/** @defgroup streaming Streams
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _FILE_OUTPUT_STREAM_H
#define	_FILE_OUTPUT_STREAM_H

#include <dnscore/output_stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

ya_result file_output_stream_open(output_stream *os, const char *filename);

/**
 * man 2 open
 */
ya_result file_output_stream_open_ex(output_stream *os, const char *filename,int flags, mode_t mode);

/*
* This version of open_create_ex does NOT log anything, which is very important sometimes in the logger thread
*/
ya_result file_output_stream_open_ex_nolog(output_stream *os, const char *filename,int flags, mode_t mode);

void file_output_stream_close_nolog(output_stream* os);

ya_result file_output_stream_create(output_stream *stream, const char *filename,mode_t mode);

/**
 * Returns MAKE_ERRNO_ERROR(EEXIST) if the file exists already.
 */

ya_result file_output_stream_create_excl(output_stream* stream, const char* filename, mode_t mode);

/**
 * Enables or disables the write mode of the steam as "full"
 * In "full" mode, the stream will stay blocked on a write if a recoverable
 * error occurs. (ie: there is no space left).
 * 
 * Do NOT use this for the loggers as it would make it impossible to act on HUP
 * 
 * Main target: journal
 * 
 * @param stream
 * @param full_writes
 * @return 
 */

ya_result file_output_stream_set_full_writes(output_stream* stream, bool full_writes);

ya_result fd_output_stream_attach(output_stream *os, int fd);

ya_result fd_output_stream_attach_noclose(output_stream *os, int fd);

void      fd_output_stream_detach(output_stream *os);

ya_result fd_output_stream_get_filedescriptor(output_stream *os);

s64       fd_output_stream_get_size(output_stream *os);

bool      is_fd_output_stream(output_stream *os);

void      file_output_steam_advise_sequential(output_stream* os);

#ifdef	__cplusplus
}
#endif

#endif	/* _FILE_OUTPUT_STREAM_H */
/** @} */

/*----------------------------------------------------------------------------*/



