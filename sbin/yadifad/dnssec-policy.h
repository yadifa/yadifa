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

/** @defgroup yadifad
 *  @ingroup ###
 *  @brief
 */

#pragma once

#include <dnscore/ptr_vector.h>
#include <dnscore/sys_types.h>

#include "zone-signature-policy.h"

typedef struct dnssec_policy_desc_s dnssec_policy_desc_s;
struct dnssec_policy_desc_s
{
    char                                                            *id;

    char                                                   *description;
    char                                                        *denial;

    ptr_vector                                                key_suite;
    s32                                                          ds_ttl;

    u8                                                            flags;  // weaker-key & stronger-key
    u8                                                          max_key;
};


typedef struct key_suite_desc_s key_suite_desc_s;
struct key_suite_desc_s
{
    char                                                            *id;

    char                                                  *key_template;
    char                                                      *key_roll;
};


typedef struct key_template_desc_s key_template_desc_s;
struct key_template_desc_s
{
    char                                                            *id;

    bool                                                            ksk;
    u32                                                       algorithm;
    u16                                                            size;
    char                                                        *engine;
};


typedef struct denial_desc_s denial_desc_s;
struct denial_desc_s
{
    char                                                            *id;

    u32                                                            type;
    u32                                                       resalting;

    char                                                          *salt;

    char                                                     *algorithm;
    u8                                                    algorithm_val;
    u16                                                      iterations;
    u8                                                      salt_length;

    bool                                                         optout;
};


typedef struct key_roll_desc_s key_roll_desc_s;
struct key_roll_desc_s
{
    char                                                            *id;

    char                                                      *generate;
    char                                                       *publish;
    char                                                      *activate;
    char                                                      *inactive;
    char                                                        *remove;
    char                                                    *ds_publish;
    char                                                     *ds_remove;
};
