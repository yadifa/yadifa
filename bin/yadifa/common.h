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

#pragma once

#include <stdio.h>
#include <dnscore/dnscore.h>
#include <dnscore/format.h>
#include <dnscore/timems.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define YADIFA_ERROR_BASE            0x82000000
#define YADIFA_ERROR_CODE(code_)     ((int32_t)(YADIFA_ERROR_BASE + (code_)))
#define YADIFA_MODULE_HELP_REQUESTED YADIFA_ERROR_CODE(1)

typedef int symbol_t;

#define THRESHOLD_DEFAULT 1.9f

static inline void print_name(FILE *f, const uint8_t *pname, uint8_t padding)
{
    // fputc('"', f);
    uint8_t len = pname[0];
    if(len < padding)
    {

        for(uint_fast8_t i = padding - len; i > 0; --i)
        {
            fputc(' ', f);
        }
    }
    fwrite(&pname[1], len, 1, f);
    // fputc('"', f);
}

static inline uint64_t timeus_delta(uint64_t start, uint64_t stop) { return (start < stop) ? stop - start : 0; }

static inline double   timeus_delta_s(uint64_t start, uint64_t stop)
{
    double ret = timeus_delta(start, stop);
    ret /= ONE_SECOND_US_F;
    return ret;
}

/**
 *  @fn const char * file_name_from_path ()
 *  @brief base_of_path
 *
 *  @param const char *
 *
 *  @return char *
 */
const char *filename_from_path(const char *fullpath);

int         module_verbosity_level();

void        module_arg_set(char **argv, int argc);
int         module_arg_count();
const char *module_arg_get(int index);

#ifdef __cplusplus
}
#endif
