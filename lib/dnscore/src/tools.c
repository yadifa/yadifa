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
 * @defgroup dnscoretools Generic Tools
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore_config.h"
#include <stdlib.h>
#include <unistd.h>

#include "dnscore/sys_types.h"
#include "dnscore/ptr_vector.h"

void bytes_swap(void *ptr, size_t size)
{
#if !DNSCORE_HAS_MEMALIGN_ISSUES
    if((size & 7) == 0)
    {
        uint64_t *l = (uint64_t *)ptr;
        uint64_t *r = l + (size >> 3) - 1;

        while(l < r)
        {
            uint64_t lc = bswap_64(*l);
            *l = bswap_64(*r);
            *r = lc;
            ++l;
            --r;
        }
        if(l == r)
        {
            *l = bswap_64(*l);
        }
    }
    else if((size & 3) == 0)
    {
        uint32_t *l = (uint32_t *)ptr;
        uint32_t *r = l + (size >> 2) - 1;

        while(l < r)
        {
            uint32_t lc = bswap_32(*l);
            *l = bswap_32(*r);
            *r = lc;
            ++l;
            --r;
        }
        if(l == r)
        {
            *l = bswap_32(*l);
        }
    }
    else if((size & 1) == 0)
    {
        uint16_t *l = (uint16_t *)ptr;
        uint16_t *r = l + (size >> 1) - 1;

        while(l < r)
        {
            uint16_t lc = bswap_16(*l);
            *l = bswap_16(*r);
            *r = lc;
            ++l;
            --r;
        }
        if(l == r)
        {
            *l = bswap_16(*l);
        }
    }
    else
    {
#endif
        uint8_t *l = (uint8_t *)ptr;
        uint8_t *r = l + size - 1;

        while(l < r)
        {
            uint8_t lc = *l;
            *l = *r;
            *r = lc;
            ++l;
            --r;
        }
#if !DNSCORE_HAS_MEMALIGN_ISSUES
    }
#endif
}

void bytes_copy_swap(void *dst, const void *ptr, size_t size)
{
#if !DNSCORE_HAS_MEMALIGN_ISSUES
    if((size & 7) == 0)
    {
        const uint64_t *l = (const uint64_t *)ptr;
        uint64_t       *r = (uint64_t *)dst + (size >> 3) - 1;

        while(r >= (uint64_t *)dst)
        {
            *r = bswap_64(*l);
            ++l;
            --r;
        }
    }
    else if((size & 3) == 0)
    {
        const uint32_t *l = (const uint32_t *)ptr;
        uint32_t       *r = (uint32_t *)dst + (size >> 2) - 1;

        while(r >= (uint32_t *)dst)
        {
            *r = bswap_32(*l);
            ++l;
            --r;
        }
    }
    else if((size & 1) == 0)
    {
        const uint16_t *l = (const uint16_t *)ptr;
        uint16_t       *r = (uint16_t *)dst + (size >> 1) - 1;

        while(r >= (uint16_t *)dst)
        {
            *r = bswap_16(*l);
            ++l;
            --r;
        }
    }
    else
    {
#endif
        const uint8_t *l = (const uint8_t *)ptr;
        uint8_t       *r = (uint8_t *)dst + size - 1;

        while(r >= (uint8_t *)dst)
        {
            *r = *l;
            ++l;
            --r;
        }
#if !DNSCORE_HAS_MEMALIGN_ISSUES
    }
#endif
}

bool text_in(const char *text, const char **text_array, size_t text_array_size)
{
    for(size_t i = 0; i < text_array_size; ++i)
    {
        if(strcmp(text, text_array[i]) == 0)
        {
            return true;
        }
    }
    return false;
}

bool text_in_ignorecase(const char *text, const char **text_array, size_t text_array_size)
{
    for(size_t i = 0; i < text_array_size; ++i)
    {
        if(strcasecmp(text, text_array[i]) == 0)
        {
            return true;
        }
    }
    return false;
}

int text_index_in(const char *text, const char **text_array, size_t text_array_size)
{
    for(size_t i = 0; i < text_array_size; ++i)
    {
        if(strcmp(text, text_array[i]) == 0)
        {
            return i;
        }
    }
    return -1;
}

int text_index_in_ignorecase(const char *text, const char **text_array, size_t text_array_size)
{
    for(size_t i = 0; i < text_array_size; ++i)
    {
        if(strcasecmp(text, text_array[i]) == 0)
        {
            return i;
        }
    }
    return -1;
}

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

size_t text_split_to_array(const char *text, char separator, char **array, size_t array_size)
{
    const char *start = text;
    size_t      index = 0;
    while(index < array_size)
    {
        char  *next = strchr(start, separator);
        size_t len;
        if(next != NULL)
        {
            len = next - start;
        }
        else
        {
            len = strlen(start);
        }
        if(len > 0)
        {
            char *token = malloc(len + 1);
            memcpy(token, start, len);
            token[len] = '\0';
            array[index++] = token;
        }
        if(next == NULL)
        {
            break;
        }
        start = next + 1;
    }

    return index;
}

/**
 * Splits the text by separators into tokens.
 * Empty tokens aren't saved.
 * Tokens are malloc allocated.
 *
 * @param text the text
 * @param separator the separator
 * @param the vector to append the tokens to
 */

size_t text_split_to_vector(const char *text, char separator, ptr_vector_t *array)
{
    const char *start = text;

    for(;;)
    {
        char  *next = strchr(start, separator);
        size_t len;
        if(next != NULL)
        {
            len = next - start;
        }
        else
        {
            len = strlen(start);
        }
        if(len > 0)
        {
            char *token = malloc(len + 1);
            memcpy(token, start, len);
            token[len] = '\0';
            ptr_vector_append(array, token);
        }
        if(next == NULL)
        {
            break;
        }
        start = next + 1;
    }

    return ptr_vector_size(array);
}

/*
uint32_t isqrt_org(uint32_t val)
{
    if(val > 1)
    {
        uint32_t a = val >> 1;
        uint32_t b = (a + val / a) >> 1;
        while(b < a)
        {
            a = b;
            b = (a + val / a) >> 1;
        }
        return a;
    }
    else
    {
        return val;
    }
}
*/
uint32_t isqrt(uint32_t val)
{
    if(val > 1)
    {
        uint32_t a = val >> 1;
        for(;;)
        {
            uint32_t b = (a + val / a) >> 1;
            if(b >= a)
            {
                break;
            }
            a = b;
        }
        return a;
    }
    else
    {
        return val;
    }
}

void *memdup(const void *buffer, size_t buffer_size)
{
    void *cloned_memory = malloc(buffer_size);
    if(cloned_memory != NULL)
    {
        if(buffer != NULL)
        {
            memcpy(cloned_memory, buffer, buffer_size);
        }
        else
        {
            memset(cloned_memory, 0, buffer_size);
        }
    }
    return cloned_memory;
}

/** @} */
