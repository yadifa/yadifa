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

/** @defgroup dnsdbdnssec DNSSEC functions
 *  @ingroup dnsdb
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#define _DNSSEC_C

#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
//#include <strings.h>

#include <openssl/engine.h>

#include <dnscore/logger.h>

#include "dnsdb/dnssec.h"
#include "dnsdb/dnsrdata.h"

#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_error.h"

#include <dnscore/base64.h>

#define MODULE_MSG_HANDLE g_dnssec_logger

logger_handle *g_dnssec_logger = LOGGER_HANDLE_SINK;

/*
 * NOTE: strtok_r CRASHES if the first parameter is on non-writable memory (ie: "openssl" instead of strdup("openssl") )
 *       In order to avoid this, I dup the string before processing it.
 */

ENGINE*
dnssec_loadengine(const char *engine_name_const)
{
    ENGINE *engine;
    char *token_pointer = NULL;

    char *engine_name = strdup(engine_name_const);

    char *token = strtok_r(engine_name, ENGINE_COMMAND_DELIMITER, &token_pointer);

    if(token == NULL)
    {
        engine = ENGINE_by_id(engine_name);
    }
    else
    {
        engine = ENGINE_by_id(token);
        token = strtok_r(NULL, ENGINE_COMMAND_DELIMITER, &token_pointer);
    }

    if(engine == NULL)
    {
        log_err("ENGINE %s not available", engine_name);
        DIE(DNSSEC_ERROR_NOENGINE);
    }

    while(token != NULL)
    {
        char *command_pointer;
        char *command = strtok_r(token, "=", &command_pointer);

        if(command == NULL)
        {
            log_err("bad command %s", command);
            DIE(DNSSEC_ERROR_INVALIDENGINE);
        }
        char *command_value = strtok_r(NULL, "=", &command_pointer);
        if(command_value == NULL)
        {
            log_err("bad command value %s", command_value);
            DIE(DNSSEC_ERROR_INVALIDENGINE);
        }
        // command_value is not NULL because DIE stops the program.
        ENGINE_ctrl_cmd((ENGINE*)engine, command, atoi(command_value), NULL, NULL, 0);

        token = strtok_r(NULL, ENGINE_COMMAND_DELIMITER, &token_pointer);
    }

    if(ENGINE_init((ENGINE*)engine) == 0)
    {
        log_err("ENGINE_init failed");
        ENGINE_free((ENGINE*)engine); /* cfr: http://www.openssl.org/docs/crypto/engine.html */
        DIE(DNSSEC_ERROR_INVALIDENGINE);
    }

    free(engine_name);

    return engine;
}

void
dnssec_unloadengine(ENGINE *engine)
{
    ENGINE_finish((ENGINE*)engine);
    ENGINE_free((ENGINE*)engine);
}

/*    ------------------------------------------------------------    */

/** @} */
