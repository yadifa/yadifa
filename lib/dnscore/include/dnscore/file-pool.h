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
#pragma once

#include <dnscore/output_stream.h>
#include <dnscore/input_stream.h>

#ifdef	__cplusplus
extern "C" {
#endif
    
#ifndef __FILE_POOL_C__
struct file_pool_t_anon { const int hidden; };
typedef struct file_pool_t_anon* file_pool_t;

struct file_pool_file_t_anon { const int hidden; };
typedef struct file_pool_file_t_anon* file_pool_file_t;
#endif

file_pool_t file_pool_init_ex(const char * const pool_name, int opened_file_count_max, u32 cache_entries);  // name is for logging
file_pool_t file_pool_init(const char * const pool_name, int fd_max);  // name is for logging
file_pool_file_t file_pool_open(file_pool_t fp, const char *filename);
file_pool_file_t file_pool_open_ex(file_pool_t fp, const char *filename, int flags, mode_t mode);
file_pool_file_t file_pool_create(file_pool_t fp, const char *filename, mode_t mode);
file_pool_file_t file_pool_create_excl(file_pool_t fp, const char *filename, mode_t mode);
void file_pool_finalize(file_pool_t fp);

file_pool_file_t file_dup(file_pool_file_t file);

ya_result file_pool_unlink_from_pool_and_filename(file_pool_t fp, const char * filename);

ya_result file_pool_read(file_pool_file_t f, void *buffer, size_t bytes);
ya_result file_pool_readfully(file_pool_file_t f, void *buffer, size_t bytes);
ya_result file_pool_write(file_pool_file_t f, const void *buffer, size_t bytes);
ya_result file_pool_writefully(file_pool_file_t f, const void *buffer, size_t bytes);
ya_result file_pool_flush(file_pool_file_t f);
ssize_t file_pool_seek(file_pool_file_t f, ssize_t position, int from);
ya_result file_pool_tell(file_pool_file_t f, size_t *position);
ya_result file_pool_resize(file_pool_file_t f, size_t size);
ya_result file_pool_get_size(file_pool_file_t f, size_t *size);
ya_result file_pool_close(file_pool_file_t f); // flushes, but only closes the file when fd are needed

ya_result file_pool_unlink(file_pool_file_t f); // no reference will be kept for that inode as soon as the last reference is lost

const char *file_pool_filename(const file_pool_file_t f);

void file_pool_file_output_stream_init(output_stream *os, file_pool_file_t f);
void file_pool_file_output_stream_set_full_writes(output_stream *os, bool full_writes);
void file_pool_file_output_stream_detach(output_stream *os);
void file_pool_file_input_stream_init(input_stream *is, file_pool_file_t f);
void file_pool_file_input_stream_detach(input_stream *is);
void file_pool_file_input_stream_set_full_reads(input_stream *is, bool full_writes);

#ifdef	__cplusplus
}
#endif

/** @} */
