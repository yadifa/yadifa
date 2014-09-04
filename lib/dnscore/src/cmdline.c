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
#include "dnscore/bytearray_input_stream.h"
#include "dnscore/bytearray_output_stream.h"
#include "dnscore/treeset.h"
#include "dnscore/format.h"

#include "dnscore/cmdline.h"

static treeset_tree g_cmdline_sections = TREESET_ASCIIZ_EMPTY;
static bool cmdline_init_error_codes_done = FALSE;

ya_result
cmdline_process_argument(const cmdline_desc_s *desc, const char *section_name, const char *arg)
{
    ya_result return_code; 

    if((desc->flags & CMDLINE_FLAG_ARGUMENTS) && (arg == NULL))
    {
        return CMDLINE_OPT_EXPECTS_ARGUMENT;
    }

    treeset_node *node;

    node = treeset_avl_insert(&g_cmdline_sections, (char*)section_name);

    output_stream *os; 

    if(node->data == NULL)
    {
        MALLOC_OR_DIE(output_stream*, os, sizeof(output_stream), GENERIC_TAG);
        bytearray_output_stream_init(os, NULL, 0);

        osformatln(os, "<%s>", section_name);

        node->data = os;
    }

    os = (output_stream *)node->data;

    switch(desc->flags)
    {
        case CMDLINE_FLAG_SECTION:    

            return_code = CMDLINE_PROCESSING_SECTION_AS_ARGUMENT;

            break;
        case CMDLINE_FLAG_ALIAS:
            osformatln(os, "%s \"%s\"", desc->target.alias, desc->value);

            return_code = 0;

            break;
            
        case CMDLINE_FLAG_TRANSLATOR:
            return_code = desc->target.translator(desc, os, section_name, desc->value);

            if(return_code >= 0)
            {
                return_code = 0;
            }

            break;
        case CMDLINE_FLAG_ALIAS | CMDLINE_FLAG_ARGUMENTS:
            osformatln(os, "%s \"%s\"", desc->target.alias, arg);

            return_code = 1;

            break;
        case CMDLINE_FLAG_TRANSLATOR | CMDLINE_FLAG_ARGUMENTS:
            return_code = desc->target.translator(desc, os, section_name, arg);

            break;
        default:
            return_code = CMDLINE_PROCESSING_INVALID_DESCRIPTOR;
    }

    return return_code;
}


ya_result 
cmdline_get_opt_long(const cmdline_desc_s *table, const char *name, const char *arg)
{
    ya_result return_code = CMDLINE_LONG_OPT_UNDEFINED;
    int i;
    bool internal_arg = FALSE;
    
    char clean_name[128];
    
    for(i = 0; name[i] != '\0'; i++)
    {
        if(name[i] != '=')
        {
            clean_name[i] = name[i];
        }
        else
        {
            arg = &name[i + 1];

            internal_arg = TRUE;
            
            break;
        }
    }
    clean_name[i] = '\0';

    const char *section_name = "";

    for(const cmdline_desc_s *desc = table; desc->name != NULL; desc++)
    {
        if (desc->flags == CMDLINE_FLAG_SECTION)
        {
            section_name = desc->name;

            continue;
        }

        if(strcmp(clean_name, desc->name) == 0)
        {
            if(ISOK(return_code = cmdline_process_argument(desc, section_name, arg)))
            {
                if(internal_arg)
                {
                    return_code = 0;
                }
            }
            

            break;
        }
    }

   return return_code;
}

ya_result
cmdline_get_opt_short(const cmdline_desc_s *table, const char *name, const char *arg)
{
    ya_result return_code = CMDLINE_SHORT_OPT_UNDEFINED;
    const char *section_name = "";

    while(*name != '\0')
    {
        for(const cmdline_desc_s *desc = table; desc->name != NULL; desc++)
        {
            if (desc->flags == CMDLINE_FLAG_SECTION)
            {
                section_name = desc->name;

                continue;
            }

            if(*name == desc->letter)
            {
                if(desc->flags & CMDLINE_FLAG_ARGUMENTS)
                {
                    if(name[1] != '\0')
                    {
                        arg = &name[1];
                    }

                    return_code = cmdline_process_argument(desc, section_name, arg);

                    return return_code;
                }
                else
                {
                    return_code = cmdline_process_argument(desc, section_name, arg);

                    break;
                }
            }
        }
        name++;
    }

   return return_code;

}

ya_result
cmdline_parse(const cmdline_desc_s *table, int argc, char **argv, cmdline_filter_callback *filter, void *filter_arg, input_stream *is)
{
    // ensures the IS is unusable if something goes wrong here
    input_stream_set_void(is);
            
    for(int i = 1; i < argc; i++)
    {
        char *arg = argv[i];
        int arg_len = strlen(arg);
        ya_result return_code;
        
        if((arg[0] == '-') && (arg_len > 1))
        {
            // fetch next val
            
            const char *val = NULL;
            
            if(i < argc - 1)
            {
                val = argv[i + 1];
                
                if(val[0] == '-')
                {
                    val = NULL;
                }
            }
            
            // check opt(long/short) or add

            if(arg[1] != '-')
            {
                // short argument
                
                if(FAIL(return_code = cmdline_get_opt_short(table, &arg[1], val)))
                {
                    return return_code;
                }
                
                i += return_code;
                
                continue;
            }
            else
            {
                // long argument
                
                if(arg_len > 2)
                {
                    if(FAIL(return_code = cmdline_get_opt_long(table, &arg[2], val)))
                    {
                        return return_code;
                    }
                    
                    i += return_code;
                    
                    continue;
                }
                else // == 2
                {
                    // case of "--"
                    
                    // fall outside of the if
                }
            }
        }
        
        if(filter != NULL)
        {
            return_code = filter(table, arg, filter_arg);

            switch(return_code)
            {
                case CMDLINE_ARG_STOP_PROCESSING_FLAG_OPTIONS:
                {
                    for(++i;i < argc;i++)
                    {
                        char *arg = argv[i];

                        if(FAIL(return_code = filter(table, arg, filter_arg)))
                        {
                            break;
                        }
                    }
                    break;
                }
                default:
                    break;
            }

            if(FAIL(return_code))
            {
                return return_code;
            }
        }
    }

    /// 
    output_stream complete_config_os;
    bytearray_output_stream_init(&complete_config_os, NULL, 0);

    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&g_cmdline_sections, &iter);
    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *node = treeset_avl_iterator_next_node(&iter);
        output_stream *os = (output_stream *)node->data;
        const char *section_name = (const char *)node->key;

        osformatln(os, "</%s>", section_name);

        u32 buffer_size = bytearray_output_stream_size(os);
        u8 *buffer      = bytearray_output_stream_buffer(os);

        output_stream_write(&complete_config_os, buffer, buffer_size);

        output_stream_close(os);
        node->data = NULL;
    }

    treeset_avl_destroy(&g_cmdline_sections);

    u32 buffer_size = bytearray_output_stream_size(&complete_config_os);
    u8 *buffer      = bytearray_output_stream_detach(&complete_config_os);
    
    output_stream_close(&complete_config_os);

    bytearray_input_stream_init(buffer, buffer_size, is, TRUE);

    return buffer_size;
}

void
cmdline_init_error_codes()
{
    if(cmdline_init_error_codes_done)
    {
        return;
    }
    
    cmdline_init_error_codes_done = TRUE;
    
    error_register(CMDLINE_PROCESSING_SECTION_AS_ARGUMENT, "CMDLINE_PROCESSING_SECTION_AS_ARGUMENT");
    error_register(CMDLINE_PROCESSING_INVALID_DESCRIPTOR, "CMDLINE_PROCESSING_INVALID_DESCRIPTOR");
    error_register(CMDLINE_LONG_OPT_UNDEFINED, "CMDLINE_LONG_OPT_UNDEFINED");
    error_register(CMDLINE_SHORT_OPT_UNDEFINED, "CMDLINE_SHORT_OPT_UNDEFINED");
    error_register(CMDLINE_OPT_EXPECTS_ARGUMENT, "CMDLINE_OPT_EXPECTS_ARGUMENT");
}
