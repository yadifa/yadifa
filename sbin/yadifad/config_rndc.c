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
 * @defgroup config Configuration handling
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "server_config.h"
#include <stdio.h>
#include <stdlib.h>

#include <dnscore/format.h>
#include <dnscore/config_settings.h>
#include <dnscore/logger.h>

extern logger_handle_t *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#if HAS_CTRL
#include "server_rndc.h"
static rndc_server_config_t rndc_server_config_tmp = {

    NULL, NULL, NULL, 1, false};

static bool rndc_registered = false;

#define CONFIG_TYPE rndc_server_config_t
CONFIG_BEGIN(config_rndc_desc)
CONFIG_BOOL(enabled, "0")
CONFIG_HOST_LIST_EX(listen, NULL, CONFIG_HOST_LIST_FLAGS_DEFAULT, 4)
CONFIG_FQDN(key_name, NULL)
CONFIG_U32_CLAMP(queries_max, "1", 1, 4)
CONFIG_ALIAS(key, key_name)
CONFIG_END(config_rndc_desc)
#undef CONFIG_TYPE

static ya_result config_rndc_section_postprocess(struct config_section_descriptor_s *csd, config_error_t *cfgerr)
{
    (void)csd;
    (void)cfgerr;

    /* here check that the settings are right */

    host_address_t **hap = &rndc_server_config_tmp.listen;
    while(*hap != NULL)
    {
        host_address_t *ha = *hap;

        if(ha->port == 0)
        {
            ha->port = NU16(RNDC_PORT_DEFAULT);
        }

        hap = &ha->next;
    }

    if(rndc_server_config_tmp.key_name != NULL)
    {
        tsig_key_t *key = tsig_get(rndc_server_config_tmp.key_name);
        if(key != NULL)
        {
            rndc_server_tsig_set(key);
            rndc_server_listen_set(rndc_server_config_tmp.listen);
            rndc_server_queries_max(rndc_server_config_tmp.queries_max);
            rndc_server_enable(rndc_server_config_tmp.enabled);
            return SUCCESS;
        }
        else
        {
#if CONFIG_SECTION_DESCRIPTOR_TRACK
            config_section_descriptor_config_error_update(cfgerr, csd, &rndc_server_config_tmp.key_name);
#endif
            return CONFIG_SECTION_ERROR;
        }
    }
    else
    {
        return SUCCESS; // not defined
    }
}

ya_result config_register_rndc(int32_t priority)
{
    if(rndc_registered)
    {
        return SUCCESS;
    }

    rndc_registered = true;

    const char *section_name = "rndc";

    ya_result   ret = config_register_struct(section_name, config_rndc_desc, &rndc_server_config_tmp, priority);

    if(ISOK(ret))
    {
        // hook a new finaliser before the standard one

        config_section_descriptor_t      *section_desc = config_section_get_descriptor(section_name);
        config_section_descriptor_vtbl_s *vtbl = (config_section_descriptor_vtbl_s *)section_desc->vtbl;
        vtbl->postprocess = config_rndc_section_postprocess;
    }

    return ret;
}

#endif

/** @} */
