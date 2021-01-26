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

/** @defgroup yadifa
 *  @ingroup ###
 *  @brief
 */

#pragma once

#include <dnscore/parser.h>
#include <dnscore/parsing.h>
#include "zone-signature-policy.h"


/*----------------------------------------------------------------------------*/
#pragma mark DEFINES


#define KEY_ROLL_LINE_CRON_TYPE     true
#define KEY_ROLL_LINE_RELATIVE_TYPE false


// key roll actions values
#define  KR_ACTION_GENERATE         0
#define  KR_ACTION_PUBLISH          1
#define  KR_ACTION_ACTIVATE         2
#define  KR_ACTION_INACTIVE         3
#define  KR_ACTION_REMOVE           4
#define  KR_ACTION_DS_PUBLISH       5
#define  KR_ACTION_DS_REMOVE        6

// key roll actions names
#define  KR_ACTION_GENERATE_NAME    "generate"
#define  KR_ACTION_PUBLISH_NAME     "publish"
#define  KR_ACTION_ACTIVATE_NAME    "activate"
#define  KR_ACTION_INACTIVE_NAME    "inactive"
#define  KR_ACTION_REMOVE_NAME      "remove"
#define  KR_ACTION_DS_PUBLISH_NAME  "ds-publish"
#define  KR_ACTION_DS_REMOVE_NAME   "ds-remove"


/*----------------------------------------------------------------------------*/
#pragma mark STRUCTS


typedef struct key_roll_line_s key_roll_line_s;

struct key_roll_line_s
{
    union
    {
        zone_policy_rule_definition_s          cron;
        zone_policy_relative_s             relative;
    } policy;

    s32                                                           action;
    s32                                                      relative_to;
    bool                                                            type;
};


/*----------------------------------------------------------------------------*/
#pragma mark PROTOTYPES


ya_result config_key_roll_parser_line(const char *key_roll_line, key_roll_line_s *krl, u8 action);


