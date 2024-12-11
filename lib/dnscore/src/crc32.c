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

#include "dnscore/dnscore_config_features.h"
#include "dnscore/crc32.h"

// BE           LE
// 0x04C11DB7	0xEDB88320	0xDB710641	0x82608EDB

static uint32_t crc32_table[256];

/**
 * Initialises the CRC32 table.
 */

void crc32_init()
{
#if DNSCORE_HAS_LITTLE_ENDIAN
    const uint32_t poly = 0xEDB88320;
    const uint32_t mask = 0x00000001;
    uint32_t       crc = mask;
    uint32_t       i = 128;
    do
    {
        if(crc & mask)
        {
            crc = (crc >> 1) ^ poly;
        }
        else
        {
            crc = crc >> 1;
        }
        for(uint32_t j = 0; j <= 255; j += i * 2)
        {
            crc32_table[i + j] = crc ^ crc32_table[j];
        }
        i = i >> 1;
    } while(i != 0);
#else
    const uint32_t poly = 0x04C11DB7;
    const uint32_t mask = 0x80000000;
    uint32_t       crc = mask;
    uint32_t       i = 1;
    do
    {
        if(crc & mask)
        {
            crc = (crc << 1) ^ poly;
        }
        else
        {
            crc = crc << 1;
        }
        for(uint32_t j = 0; j <= i - 1; ++j)
        {
            crc32_table[i + j] = crc ^ crc32_table[j];
        }
        i = i << 1;
    } while(i < 256);
#endif
}

/**
 * Computes the CRC32 of the provided buffer.
 *
 * @param data_ a pointer to the buffer
 * @parm size the size of the buffer
 *
 * @return the CRC32 value
 */

uint32_t crc32_get(const void *data_, size_t size)
{
    const uint8_t *data = data_;
    uint32_t       crc32 = ~0;
    for(size_t i = 0; i < size; ++i)
    {
        const uint8_t table_index = crc32 ^ data[i];
        crc32 = (crc32 >> 8) ^ crc32_table[table_index];
    }
    crc32 ^= ~0;
    return crc32;
}
