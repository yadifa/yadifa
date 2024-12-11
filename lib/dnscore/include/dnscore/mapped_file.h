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
 * @defgroup streaming Streams
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <fcntl.h>
#include <dnscore/file.h>
#include <dnscore/sys_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Opens a file.
 *
 * @param fp a pointer to a file_t that will hold the file object
 * @param filename the name of the file
 * @param flags the typical posix flags. (O_RDWR, O_RDONLY, ...) Not all flags are valid.
 */

ya_result mapped_file_open_ex(file_t *fp, const char *filename, int flags);

/**
 * Creates a file.
 *
 * @param fp a pointer to a file_t that will hold the file object
 * @param filename the name of the file
 * @param flags the typical posix flags. (O_RDWR, O_RDONLY, ...) Not all flags are valid.
 */

ya_result mapped_file_create_ex(file_t *fp, const char *filename, int flags, mode_t mode);

/**
 * Creates a memory map not backed by a file.
 *
 * @param fp a pointer to a file_t that will hold the file object
 * @param filename ignored
 * @param size the size of the memory map
 */

ya_result mapped_file_create_volatile(file_t *fp, const char *filename, size_t base_size);

/**
 * Gets a copy of the base address of the memory map at the current moment.
 * This can change after the file size changes.
 *
 *  @param f the file
 *  @param address a pointer to a pointer that will be set
 *  @param size a pointer to a size that will be set
 *  @return and error code
 */

ya_result mapped_file_get_buffer(file_t f, void **address, ssize_t *size);

/**
 * Gets a copy of the base address of the memory map at the current moment.
 * This can change after the file size changes.
 *
 *  @param f the file
 *  @param address a pointer to a pointer that will be set
 *  @param size a pointer to a size that will be set
 *  @return and error code
 */

ya_result mapped_file_get_buffer_const(file_t f, const void **address, ssize_t *size);

#ifdef __cplusplus
}
#endif

/** @} */
