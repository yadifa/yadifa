/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
* DOCUMENTATION */
/** @defgroup config Configuration handling
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */

#include <stdio.h>
#include <stdlib.h>

#include "confs.h"

/*
 * NOT USED YET, CONTROLLER CONFIGURATION SECTION
 */

static ya_result config_control_section_init(config_data *config)
{
    return SUCCESS;
}

static ya_result config_control_section_assign(config_data *config)
{
    return SUCCESS;
}

static ya_result config_control_section_free(config_data *config)
{
    return SUCCESS;
}

static ya_result set_control_string(const char *value, const int config_command, void *config)
{
    return SUCCESS;
}

/*  Table with the parameters that can be set in the config file
 *  zone containers
 */
static const config_table control_tab[] ={
    { "net",                  set_control_string,      CC_NET              },
    { "keys",                 set_control_string,      CC_KEYS             },
    { NULL, NULL, 0}
};

static ya_result
set_variable_control(char *variable, char *value, char *argument)
{
    return SUCCESS;
}

static ya_result config_control_section_print(config_data *config)
{
    return SUCCESS;
}

static config_section_descriptor section_control =
{
    "control",
    set_variable_control,
    config_control_section_init,
    config_control_section_assign,
    config_control_section_free,
    config_control_section_print,
    FALSE
};

const config_section_descriptor *
confs_control_get_descriptor()
{
    return &section_control;
}


/** @} */
