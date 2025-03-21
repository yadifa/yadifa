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
#include "ctrl.h"
static config_control_t tmp_config_control = {

    NULL, true};

static bool ctrl_registered = false;

#define CONFIG_TYPE config_control_t
CONFIG_BEGIN(config_control_desc)
CONFIG_BOOL(enabled, "1")
CONFIG_HOST_LIST_EX(listen, NULL, CONFIG_HOST_LIST_FLAGS_DEFAULT, 4)
CONFIG_END(config_control_desc)
#undef CONFIG_TYPE

static ya_result config_control_section_postprocess(struct config_section_descriptor_s *csd, config_error_t *cfgerr)
{
    (void)csd;
    (void)cfgerr;

    /* here check that the settings are right */

    host_address_t **hap = &tmp_config_control.listen;
    while(*hap != NULL)
    {
        host_address_t *ha = *hap;

        if(ha->port == 0)
        {
            ha->port = NU16(CTRL_PORT_DEFAULT);
        }

        hap = &ha->next;
    }

    ctrl_set_listen(tmp_config_control.listen);

    return SUCCESS;
}

ya_result config_register_control(int32_t priority)
{
    if(ctrl_registered)
    {
        return SUCCESS;
    }

    ctrl_registered = true;

    const char *section_name = "control";

    ya_result   return_code = config_register_struct(section_name, config_control_desc, &tmp_config_control, priority);
    if(ISOK(return_code))
    {
        // hook a new finaliser before the standard one

        config_section_descriptor_t      *section_desc = config_section_get_descriptor(section_name);
        config_section_descriptor_vtbl_s *vtbl = (config_section_descriptor_vtbl_s *)section_desc->vtbl;
        vtbl->postprocess = config_control_section_postprocess;
    }

    return return_code;
}

#endif

/** @} */
