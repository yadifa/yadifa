/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup dnscoretools Generic Tools
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include <stdbool.h>

struct file_mtime_set_s;
#if !FILE_MTIME_C_
typedef struct file_mtime_set_s file_mtime_set_t;

file_mtime_set_t               *file_mtime_set_get_for_file(const char *filename);
void                            file_mtime_set_add_file(file_mtime_set_t *ctx, const char *filename);
bool                            file_mtime_set_modified(file_mtime_set_t *ctx);
void                            file_mtime_set_clear(file_mtime_set_t *ctx);
void                            file_mtime_set_delete(file_mtime_set_t *ctx);
#else
struct file_mtime_set_s *file_mtime_set_get_for_file(const char *filename);
void                     file_mtime_set_add_file(struct file_mtime_set_s *ctx, const char *filename);
bool                     file_mtime_set_modified(struct file_mtime_set_s *ctx);
void                     file_mtime_set_clear(struct file_mtime_set_s *ctx);
void                     file_mtime_set_delete(struct file_mtime_set_s *ctx);
#endif

/** @} */
