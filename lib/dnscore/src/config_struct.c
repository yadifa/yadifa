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
*/
#include "dnscore/config_settings.h"

static ya_result
config_section_struct_init(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    return SUCCESS;
}

static ya_result
config_section_struct_start(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    return SUCCESS;
}

static ya_result
config_section_struct_stop(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    return SUCCESS;
}

static ya_result
config_section_struct_postprocess(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    return SUCCESS;
}

static ya_result
config_section_struct_finalise(struct config_section_descriptor_s *csd)
{
    if(csd != NULL)
    {
        if(csd->vtbl != NULL)
        {
            free((char*)csd->vtbl->name);
            free((config_section_descriptor_vtbl_s*)csd->vtbl);
        }
        
        free(csd);
    }
    
    return SUCCESS;
}

static ya_result
config_section_struct_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    return CONFIG_UNKNOWN_SETTING;
}

static ya_result
config_section_struct_print_wild(struct config_section_descriptor_s *csd, output_stream *os, const char *key)
{
    return CONFIG_UNKNOWN_SETTING;
}

static const config_section_descriptor_vtbl_s config_section_struct_descriptor =
{
    NULL,
    NULL,
    config_section_struct_set_wild,
    config_section_struct_print_wild,
    config_section_struct_init,
    config_section_struct_start,
    config_section_struct_stop,
    config_section_struct_postprocess,
    config_section_struct_finalise
};

/// register a simple (static) struct
ya_result
config_register_struct(const char *name, config_table_descriptor_item_s *table, void *data_struct, s32 priority)
{
    config_section_descriptor_vtbl_s *vtbl;
    MALLOC_OR_DIE(config_section_descriptor_vtbl_s*, vtbl, sizeof(config_section_descriptor_vtbl_s), GENERIC_TAG);
    memcpy(vtbl, &config_section_struct_descriptor, sizeof(config_section_descriptor_vtbl_s));
    vtbl->name = strdup(name);
    vtbl->table = table;
    
    config_section_descriptor_s *desc;
    MALLOC_OR_DIE(config_section_descriptor_s*, desc, sizeof(config_section_descriptor_s), GENERIC_TAG);
    desc->base = data_struct;
    desc->vtbl = vtbl;
    
    ya_result return_code = config_register(desc, priority);
    
    if(FAIL(return_code))
    {
        free((char*)vtbl->name);
        free(vtbl);
        free(desc);
    }
    
    return return_code; // scan-build false positive: either it is freed, either it is stored in a global collection
}
