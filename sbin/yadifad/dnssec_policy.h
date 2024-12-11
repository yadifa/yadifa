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
 * @defgroup yadifad
 * @ingroup ###
 * @brief
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnscore/ptr_vector.h>
#include <dnscore/sys_types.h>

#include "zone_signature_policy.h"

struct dnssec_policy_desc_s
{
    char        *id;

    char        *description;
    char        *denial;

    ptr_vector_t key_suite;
    int32_t      ds_ttl;

    uint8_t      flags;   // weaker-key & stronger-key
    uint8_t      max_key; // not used
};

typedef struct dnssec_policy_desc_s dnssec_policy_desc_t;

struct key_suite_desc_s
{
    char *id;

    char *key_template;
    char *key_roll;
};

typedef struct key_suite_desc_s key_suite_desc_t;

struct key_template_desc_s
{
    char    *id;

    bool     ksk;
    uint32_t algorithm;
    uint16_t size;
    char    *engine;
};

typedef struct key_template_desc_s key_template_desc_t;

struct denial_desc_s
{
    char    *id;

    uint32_t type;
    uint32_t resalting;

    char    *salt;

    char    *algorithm;
    uint8_t  algorithm_val;
    uint16_t iterations;
    uint8_t  salt_length;

    bool     optout;
};

typedef struct denial_desc_s denial_desc_t;

struct key_roll_desc_s
{
    char *id;

    char *generate;
    char *publish;
    char *activate;
    char *inactive;
    char *remove;
    char *ds_publish;
    char *ds_remove;
};

typedef struct key_roll_desc_s key_roll_desc_t;
