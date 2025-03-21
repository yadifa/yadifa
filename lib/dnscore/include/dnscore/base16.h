/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 * @defgroup base Base conversion functions
 * @ingroup dnscore
 * @brief Base 16 codec
 *
 * Base 16 codec functions
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _BASE16_H
#define _BASE16_H

#include <dnscore/sys_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Encodes bytes into base16
 * The output size must be at least size_in * 2
 *
 * @param buffer_in     bytes to convert
 * @param size_in       number of bytes
 * @param buffer_out    output buffer of a size >= size_in * 2
 *
 * @return output size
 */

uint32_t base16_encode(const void *buffer_in, uint32_t size_in, char *buffer_out);

uint32_t base16_encode_lc(const void *buffer_in, uint32_t size_in, char *buffer_out);

/**
 * Decodes base16 into bytes
 * The output size must be at least size_in / 2
 *
 * @param buffer_in     base16 text
 * @param size_in       number of chars
 * @param buffer_out    output buffer of a size >= size_in / 2
 *
 * @return output size
 */

ya_result base16_decode(const char *buffer_in, uint32_t size_in, uint8_t *buffer_out);

/**
 * Maps a character [0-9A-Za-z] to 0..15
 *
 * @param nibble the character
 *
 * @return value of the character or 0xff if the character is not part of base16
 */

uint8_t base16_decode_nibble(char nibble);

#ifdef __cplusplus
}
#endif

#endif /* _BASE16_H */
/** @} */
