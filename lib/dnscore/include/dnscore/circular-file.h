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

/** @defgroup acl Access Control List
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */

#pragma once

#include <dnscore/file-pool.h>

#ifndef CIRCULAR_FILE_C
struct circular_file_s;
typedef struct circular_file_s circular_file_s;
#endif

typedef struct circular_file_s* circular_file_t;

ya_result circular_file_create(circular_file_t *cfp, file_pool_t fp, const u8 magic[4], const char* path, s64 size_max, u32 reserved_header_size);
ya_result circular_file_open(circular_file_t *cfp, file_pool_t fp, const u8 magic[4], const char *path);
ya_result circular_file_close(circular_file_t cf);
u64 circular_file_tell(circular_file_t cf);
const char *circular_file_name(circular_file_t cf);
ya_result circular_file_unlink(circular_file_t cf);

u64 circular_file_absolute_tell(circular_file_t cf);
void circular_file_absolute_seek(circular_file_t cf, u64 position);

ssize_t circular_file_seek_relative(circular_file_t cf, ssize_t relative_offset);
ssize_t circular_file_seek(circular_file_t cf, ssize_t absolute_offset);

ya_result circular_file_read(circular_file_t cf, void* buffer_, u32 n);
ya_result circular_file_write(circular_file_t cf, const void* buffer_, u32 n);
u64 circular_file_get_used_space(circular_file_t cf);
u64 circular_file_get_maximum_size(circular_file_t cf);
u64 circular_file_get_pending_size(circular_file_t cf);

u64 circular_file_get_size(circular_file_t cf);
void circular_file_set_size(circular_file_t cf, u64 size);
s64 circular_file_get_read_available(circular_file_t cf);
s64 circular_file_get_write_available(circular_file_t cf);

ya_result circular_file_grow(circular_file_t cf, s64 new_maximum_size);
ya_result circular_file_get_reserved_header_size(circular_file_t cf, s32 *reserved_size);
ya_result circular_file_read_reserved_header(circular_file_t cf, void *buffer, u32 buffer_size);
ya_result circular_file_write_reserved_header(circular_file_t cf, void *buffer, u32 buffer_size);
ya_result circular_file_flush(circular_file_t cf);
ya_result circular_file_shift(circular_file_t cf, s64 bytes);

void circular_file_dump(circular_file_t cf);

void circular_file_input_stream_init(input_stream *is, circular_file_t cf);
void circular_file_input_stream_noclose_init(input_stream *is, circular_file_t cf);

/** @} */
