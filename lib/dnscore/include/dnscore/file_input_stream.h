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
#ifndef _FILE_INPUT_STREAM_H
#define	_FILE_INPUT_STREAM_H

#include <dnscore/input_stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

    ya_result file_input_stream_open(input_stream *stream, const char *filename);
    
    ya_result file_input_stream_open_ex(input_stream *stream, const char *filename, int flags);
    
    /* Create an input stream and assigns the fd to it. */
    ya_result fd_input_stream_attach(input_stream *stream, int fd);
        
    ya_result fd_input_stream_attach_noclose(input_stream *stream, int fd);
    
    void fd_input_stream_detach(input_stream *stream);

    ya_result fd_input_stream_get_filedescriptor(input_stream* stream);
    
    ya_result fd_input_stream_seek(input_stream* stream, u64 offset);

    bool is_fd_input_stream(input_stream* stream);
    
    void file_input_steam_advise_sequential(input_stream* stream);
    
#ifdef	__cplusplus
}
#endif

#endif	/* _FILE_INPUT_STREAM_H */
/** @} */
