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

#include <dnscore/format.h>
#include "dnscore/dnscore-config.h"
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
config_section_struct_finalize(struct config_section_descriptor_s *csd)
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
    (void)csd;
    (void)key;
    (void)value;

    return CONFIG_UNKNOWN_SETTING;
}

static ya_result
config_section_struct_print_wild(const struct config_section_descriptor_s *csd, output_stream *os, const char *key)
{
    (void)csd;
    (void)os;
    (void)key;

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
    config_section_struct_finalize
};

/// register a simple (static) struct
ya_result
config_register_struct(const char *name, config_table_descriptor_item_s *table, void *data_struct, s32 priority)
{
    config_section_descriptor_vtbl_s *vtbl;
    MALLOC_OBJECT_OR_DIE(vtbl, config_section_descriptor_vtbl_s, CFGSVTBL_TAG);
    memcpy(vtbl, &config_section_struct_descriptor, sizeof(config_section_descriptor_vtbl_s));
    vtbl->name = strdup(name);
    vtbl->table = table;

    const config_table_descriptor_item_s *t = table;
    while(t->name != NULL)
    {
        size_t expected = t->expected_size;
        size_t field = t->field_size;

        if(expected != field)
        {
            osformatln(termerr, "config descriptor: '%s' field '%s': expected size: %i, field size: %i", name, t->name, expected, field);
            flusherr();
        }
        ++t;
    }
    
    config_section_descriptor_s *desc;
    MALLOC_OBJECT_OR_DIE(desc, config_section_descriptor_s, CFGSDESC_TAG);
    desc->base = data_struct;
    desc->vtbl = vtbl;
    
    ya_result return_code = config_register(desc, priority);
    
    if(FAIL(return_code))
    {
        free((char*)vtbl->name);
        free(vtbl);
        free(desc);
    }
    
    return return_code;
}

void*
config_unregister_struct(const char *name, const config_table_descriptor_item_s *table)
{
    void *data_struct = NULL;
    config_section_descriptor_s *desc = config_unregister_by_name(name);
    
    if(desc != NULL)
    {
        config_section_descriptor_vtbl_s *vtbl = (config_section_descriptor_vtbl_s*)desc->vtbl;
        assert(vtbl != NULL);
        assert(vtbl->table == table);
        (void)table;
        free((char*)vtbl->name);
        free(vtbl);
        data_struct = desc->base;        
        free(desc);
    }

    return data_struct;
}

