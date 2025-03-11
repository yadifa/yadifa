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

#pragma once

/** @defgroup yadifa
 *  @ingroup ###
 *  @brief yadifa
 */

#include "module.h"

#include <dnscore/host_address.h>

struct tsig_key_s;

typedef struct yadifa_zonesign_settings_s yadifa_zonesign_settings_s;
struct yadifa_zonesign_settings_s
{
    char    *keys_path;
    char    *output_file;
    char    *input_file;
    char    *journal_file;
    char    *from_time_text;
    char    *to_time_text;
    char    *nsec3_salt_text;
    char    *now_text;
    int64_t  now;
    uint8_t *origin;
    uint32_t new_serial;
    uint32_t from_time;
    uint32_t to_time;
    uint32_t interval;
    uint32_t jitter;
    int32_t  dnskey_ttl;
    uint32_t workers;
    uint32_t dnssec_mode;
    int32_t  nsec3_salt_size;
    uint16_t nsec3_iterations;
    uint8_t  verbose;
    bool     read_journal;
    bool     nsec3_optout;
    bool     smart_signing;
    uint8_t  nsec3_salt[256];
};

#ifndef ZONSIGN_C_

extern const module_s zonesign_program;

#endif
