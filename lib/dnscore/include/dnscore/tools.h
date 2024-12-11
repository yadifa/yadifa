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
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#include <stdlib.h>
#include <dnscore/ptr_vector.h>

void bytes_swap(void *ptr, size_t size);
void bytes_copy_swap(void *dst, const void *ptr, size_t size);

bool text_in(const char *text, const char **text_array, size_t text_array_size);
bool text_in_ignorecase(const char *text, const char **text_array, size_t text_array_size);

int  text_index_in(const char *text, const char **text_array, size_t text_array_size);
int  text_index_in_ignorecase(const char *text, const char **text_array, size_t text_array_size);

/**
 * Splits the text by separators into tokens.
 * Empty tokens aren't saved.
 * Tokens are malloc allocated.
 *
 * @param text the text
 * @param separator the separator
 * @param the array to append the tokens to
 * @param array_size the size of the array
 */

size_t text_split_to_array(const char *text, char separator, char **array, size_t array_size);

/**
 * Splits the text by separators into tokens.
 * Empty tokens aren't saved.
 * Tokens are malloc allocated.
 *
 * @param text the text
 * @param separator the separator
 * @param the vector to append the tokens to
 */

size_t   text_split_to_vector(const char *text, char separator, ptr_vector_t *array);

uint32_t isqrt(uint32_t val);

void    *memdup(const void *buffer, size_t buffer_size);

/** @} */
