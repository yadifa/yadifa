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
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#define MODULE_MSG_HANDLE g_server_logger

// TEST

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>

#include <dnscore/format.h>
#include <dnscore/logger.h>
#include <dnscore/message.h>
#include <dnscore/sys_get_cpu_count.h>

#include <dnscore/parsing.h>

#include "config.h"

#if HAS_DNSSEC_SUPPORT != 0
#include <dnsdb/dnssec.h>
#include <dnsdb/dnssec_keystore.h>
#endif

#include "server.h"

#include "confs.h"

#include "zone.h"
#include "list.h"
#include "server_error.h"
#include "config_error.h"

#include "parser.h"

#define CONFSDSP_TAG 0x50534453464e4f43
#define CONFSPL_TAG 0x4c5053464e4f43

/*
 * 2011/10/18 : EDF: disabling the debug because it makes the legitimate error output unreadable.
 */

#undef DEBUGLNF
#undef DEBUGF
#undef OSDEBUG
#undef LDEBUG
#undef OSLDEBUG
#define DEBUGLNF(...)
#define DEBUGF(...)
#define OSDEBUG(...)
#define LDEBUG(...)
#define OSLDEBUG(...)

#ifndef NAME_MAX
#define NAME_MAX 1024
#endif

logger_handle* g_statistics_logger                                       = NULL;

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

#if HAS_ACL_SUPPORT == 1
const config_section_descriptor *confs_acl_get_descriptor();
#endif

const config_section_descriptor *confs_main_get_descriptor();
const config_section_descriptor *confs_zone_get_descriptor();

#if HAS_TSIG_SUPPORT == 1
const config_section_descriptor *confs_key_get_descriptor();
#endif

const config_section_descriptor *confs_channels_get_descriptor();
const config_section_descriptor *confs_loggers_get_descriptor();
const config_section_descriptor *confs_control_get_descriptor();


#define TRIM_CF_LINE(ptr)                                                  \
    remove_comment((char *)ptr, '#');                                      \
remove_whitespace_from_right((char *)ptr);                             \
remove_whitespace_from_left((char **)&ptr);

static const char *config_error_prefix = "config: ";

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

const struct config_section_descriptor *config_sections[32] =
{
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static value_name_table true_false_enum[]=
{
    {1, "yes"},
    {1, "1"},
    {1, "enable"},
    {1, "enabled"},
    {1, "on"},
    {1, "true"},
    {0, "no"},
    {0, "0"},
    {0, "disable"},
    {0, "disabled"},
    {0, "off"},
    {0, "false"},
    {0, NULL}
};

/*------------------------------------------------------------------------------
 * FUNCTIONS */

ya_result
config_get_entry_index(const char *name, const config_table *table, const char *section_name)
{
    int count = 0;

    while(table[count].variable != NULL)
    {
        if(strcasecmp(table[count].variable, name) == 0)
        {
            return count;
        }

        count++;
    }

    return CONFIG_UNKNOWN_SETTING_ERR; /* not found */
}


/**
 * @brief Tool function printing all the known names in a table.
 */

void
print_value_name_table_names(value_name_table *table)
{
    if(table->data == NULL)
    {
        return;
    }

    for(;;)
    {
        print(table->data);
        table++;
        if(table->data == NULL)
        {
            break;
        }
        print(",");
    }
}

static ya_result
config_get_params(char *line, char **variable, char **value, char **argument)
{
    /*    ------------------------------------------------------------    */

    char *p;

    /* Search for the variable */

    p = line;
    SKIP_WHSPACE(p);

    if(*p == '\0')
    {
        return NO_VARIABLE_FOUND;
    }

    *variable = p;
    SKIP_JUST_WORD(p);

    if(*p == '\0')
    {
        return NO_VALUE_FOUND;
    }

    *p++ = '\0';
    SKIP_WHSPACE(p);

    *value = p;
    CUT_STRING(*value, p);

    if(argument != NULL)
    {
        if(*p == '\0')
        {
            return NO_ARGUMENT_FOUND;
        }
        *p++ = '\0';
        SKIP_WHSPACE(p);

        *argument = p;

        CUT_STRING(*argument, p);
    }

    return OK;
}

static ya_result
config_parse_line(char *src, char **data, int *data_size, int *bracket_status)
{
    ya_result                                             return_code = OK;

    char                                                           *needle;
    char                                                            *start;

    /*    ------------------------------------------------------------    */

    start  = src;
    SKIP_WHSPACE(start);

    needle = start;
    while(*needle)
    {
        while((*needle != '(') && (*needle != ')') && (*needle != '\0'))
        {
            ++needle;
        }
        if(*needle == '\0')
        {
            /* trim end */
            
            if(needle > start)
            {
                while((needle > start) && isspace(needle[-1]))
                {
                    needle--;
                }
                *needle = '\0';
            }
            size_t start_size = (needle - start) + 1;

            if(*data != NULL)
            {
                if(start_size > 1)
                {
                    int pdata_len = strlen(*data);

                    if(*data_size < (start_size + pdata_len + 1))
                    {
                        *data_size = (start_size + pdata_len + 1 + 1024);

                        REALLOC_OR_DIE(char*, *data, *data_size, CONFSPL_TAG);
                    }

                    /* if there is already something in the buffer, then put a space before the added text */

                    if(pdata_len > 0)
                    {
                        (*data)[pdata_len++] = ' ';
                    }

                    MEMCOPY(&(*data)[pdata_len], start, start_size);
                }
            }
            else
            {
                *data_size = MAX(start_size, 1024);
                MALLOC_OR_DIE(char*, *data, *data_size, CONFSPL_TAG);
                MEMCOPY(*data, start, start_size);
            }

            return return_code;
        }

        if(*needle == '(')
        {
            if(*bracket_status == BRACKET_OPEN)
            {
                return DUPLICATED_OPEN_BRACKET;
            }
            else
            {
                *bracket_status = BRACKET_OPEN;
            }
        }

        if(*needle == ')')
        {
            if(*bracket_status == BRACKET_CLOSED)
            {
                return DUPLICATED_CLOSED_BRACKET;
            }
            else
            {
                *bracket_status = BRACKET_CLOSED;
            }
        }

        *needle = ' ';
    }

    return return_code;
}

static bool
config_file_pop(config_reader_context *ctx)
{
    if(ctx->top >= 0)
    {
        fclose(ctx->data[ctx->top]);
        free(ctx->file_name[ctx->top]);
        
        ctx->top--;
    }
    
    return ctx->top >= 0;
}

static void
config_file_close(config_reader_context *ctx)
{
    while(config_file_pop(ctx));
}

static ya_result
config_file_push(const char *file_name_cstr, config_data *config, config_reader_context *out_ctx)
{
    /*    ------------------------------------------------------------    */
    
    FILE *file_handle;
    
    if(out_ctx->top == CONFIG_READER_CONTEXT_MAX_DEPTH - 1)
    {
        return CONFIG_FILE_INCL_FAILED;
    }
        
    /* Open zone file and parse the lines */
    if(NULL == (file_handle = fopen(file_name_cstr, "r")))
    {
        osformatln(termerr, "%s%s opening '%s'",config_error_prefix , strerror(errno), file_name_cstr);
        log_err("%s%s opening '%s'",config_error_prefix , strerror(errno), file_name_cstr);
        return CONFIG_FILE_OPEN_FAILED;
    }

    out_ctx->top++;
    out_ctx->data[out_ctx->top] = file_handle;
    out_ctx->file_name[out_ctx->top] = strdup(file_name_cstr);

            
    return OK;
}

static ya_result
config_file_open(const char *file_name_cstr, config_data *config, config_reader_context *out_ctx)
{
    /*    ------------------------------------------------------------    */
    out_ctx->top = -1;
        
    ya_result return_code = config_file_push(file_name_cstr, config, out_ctx);
    
    return return_code;
}

ya_result
config_file_read(const char *config_container, config_reader_context *ctx)
{
    char                                                          *variable;
    char                                                             *value;
    char                                                          *argument;

    config_section_init                                       *section_init;
    config_section_assign                                   *section_assign;
    config_section_setter                                         *function;

    void                                                          **section;

    char                                                       *data = NULL;

    char                                                            *needle;
    
    int                                                       data_size = 0;

    ya_result                                                   return_code;

    u32                                                     line_number = 0;

    bool                                                  start_end = FALSE;
    
    bool                                             skip_container = FALSE;

    /**
     * A configuration item is : {name}{blank}value{blank}[arguments]
     *
     * Every item has got at least ONE value
     * Some items can have arguments beyond that value (ie: channels & loggers)
     * The separator between value and argument is at least one blank
     *
     * In some other cases the the value is everyting after the name (acl items)
     *
     * So this variable tells if everything is the value, or if there are
     * arguments after the blank after the value.
     */

    bool                                                 has_params = FALSE;
    
    u32                       line_numbers[CONFIG_READER_CONTEXT_MAX_DEPTH];

    char                                                line[MAX_LINE_SIZE];
    

    static int                                               bracket_status;

    /* Variables for the zone container */



    /*    ------------------------------------------------------------    */

    /* By default: the functions do nothing */

    section        = (void**)&section;  /* Unused by default, except for a '*'. CANNOT BE NULL */

    /** Four containers are available:
     * 
     *  #- channels
     *  #- loggers
     *  #- main
     *  #- zone
     *
     *  Other function can be defined, but those are plug-in dependant
     */

    const config_section_descriptor **sectiondp = config_sections;

    while(*sectiondp != NULL)
    {
        const config_section_descriptor *sectiond = *sectiondp;
        sectiondp++;

        if(strcasecmp(sectiond->name, config_container) == 0)
        {
            function = sectiond->function_set;
            section_init = sectiond->function_init;
            section_assign = sectiond->function_assign;
            has_params = sectiond->has_params;
            
            break;
        }
    }

    if(*sectiondp == NULL)
    {
        return SUCCESS; // unknown section
    }
    
    size_t config_container_len = strlen(config_container);

    /**
     *  I presume it will require a cleanup if a return ERROR is triggered.
     */
    
    line_number = 0;

    for(;;)
    {
        if(NULL == fgets(line, sizeof(line), ctx->data[ctx->top]))
        {
            if(config_file_pop(ctx))
            {
                line_number = line_numbers[ctx->top];
                
                continue;
            }
            
            return_code = SUCCESS; // EOF
            
            break;
        }
                
        line_number++;
        
        //osformatln(termerr, "%i '%s'", line_number, line);

        if(line[0] == '#')
        {
            continue;
        }

        /* Check for a line overflow */

        if(line[ strlen(line) - 1 ] != '\n')
        {
            return_code = CFG_LINE_LIMIT_REACHED;
            
            osformatln(termerr, "%s<%s>: %r",config_error_prefix , config_container, return_code);
            log_err("%s<%s>: %r",config_error_prefix , config_container, return_code);
            
            break;
        }

        needle = line;
        TRIM_CF_LINE(needle);
        
        size_t needle_len = strlen(needle);

        if(needle_len == 0)
        {
            continue;
        }
            
        if(needle_len >= 2)
        {
            if(needle[0] == '<')
            {
                if(needle[needle_len - 1] != '>')
                {
                    return_code = CONFIG_FILE_BROKEN_TAG;
                    break;
                }
                
                if(needle[1] == '/')
                {
                    /* end of container */
                    
                    bool mismatched_container = FALSE;
                    
                    if((needle_len - 3 == config_container_len) && (memcmp(&needle[2], config_container, config_container_len) == 0))
                    {
                        if(!start_end)
                        {
                            // wrong
                            
                            mismatched_container = TRUE;
                        }
                        else
                        {
                            start_end = FALSE;
                        }
                    }
                    else
                    {
                        if(!skip_container)
                        {
                            // wrong
                            
                            mismatched_container = TRUE;
                        }
                        else
                        {
                            skip_container = FALSE;
                        }
                    }

                    if(mismatched_container)
                    {
                        osformatln(termerr, "%s: unexpected end of container found '%s'",config_error_prefix, needle);
                        log_err("%s: unexpected end of container found '%s'",config_error_prefix, needle);

                        return_code = CONFIG_FILE_BAD_CONT_END;

                        break;
                    }
                }
                else
                {
                    /* start of container */
                    
                    /* already in a container ? */
                    
                    if(skip_container || start_end)
                    {
                        osformatln(termerr, "%s: unexpected start of container found '%s'",config_error_prefix , needle);
                        log_err("%s: unexpected start of container found '%s'",config_error_prefix , needle);

                        return_code = CONFIG_FILE_BAD_CONT_START;

                        break;
                    }
                    
                    if((needle_len - 2 == config_container_len) && (memcmp(&needle[1], config_container, config_container_len) == 0))
                    {
                        start_end = TRUE;
                        
                        if(FAIL(return_code = section_init(g_config)))
                        {
                            osformatln(termerr, "%s: error initialising the container '%s': %r",config_error_prefix , needle, return_code);
                            
                            break;
                        }
                    }
                    else
                    {
                        skip_container = TRUE;
                    }
                }
                
                continue;
            }
        }

        if(skip_container)
        {
            continue;
        }
        
        /* in the expected container */
        
        if(start_end)
        {
            /* Must be a resource record so parse it */
            if(FAIL(return_code = config_parse_line(needle, &data, &data_size, &bracket_status)))
            {
                osformatln(termerr, "%s<%s>: %r ",config_error_prefix , config_container, return_code);
                log_err("%s<%s>: %r ",config_error_prefix , config_container, return_code);
                
                break;
            }

            //    OSDEBUG(termout, "Y: %s\n", needle);
            /* We have the full resource record(s) and the bracket_status is closed */
            if(bracket_status == BRACKET_CLOSED)
            {
                argument = "";

                return_code = config_get_params(data, &variable, &value, (has_params)?&argument:NULL);

                if(return_code == NO_VARIABLE_FOUND)
                {
                    continue;
                }

                if(return_code == NO_VALUE_FOUND)
                {
                    osformatln(termerr, "%s<%s>: missing value",config_error_prefix , config_container);
                    log_err("%s<%s>: missing value",config_error_prefix , config_container);

                    return_code = INCORRECT_CONFIG_LINE;
                    
                    break;
                }

                if(FAIL(return_code = (*function)(variable, value, argument)))
                {
                    osformatln(termerr, "%s<%s>: %r ( '%s' = '%s' [%s] )",config_error_prefix , config_container, return_code, variable, value, argument);
                    log_err("%s<%s>: %r ( '%s' = '%s' [%s] )",config_error_prefix , config_container, return_code, variable, value, argument);

                    break;
                }

                /* Clean up variable, value & argument params */

                data[0] = '\0';
            }
        }
        else
        {
            /*
             * If we reach this point we are outside any kind of container.
             * Only 'include' has been defined for here.
             */
            
            SKIP_WHSPACE(needle);
            /* 9 = strlen("include") + 1 space + 1 char min */
            if((needle_len >= 9) && (memcmp(needle, "include", 7) == 0))
            {
                // include
                needle += 7;
                
                if(isspace(*needle))
                {
                    needle++;
                    SKIP_WHSPACE(needle);

                    OSDEBUG(termerr, "include '%s'", needle);
                    
                    line_numbers[ctx->top] = line_number;
                    line_number = 0;
                    
                    if(ISOK(return_code == config_file_push(needle, g_config, ctx)))
                    {
                        continue;
                    }
                }
            }
            
            /*
             * plain wrong
             */
            
            return_code = CONFIG_FILE_BAD_KEYWORD;
            
            osformatln(termerr, "%s%r: '%s')",config_error_prefix, return_code, needle);
            log_err("%s%r: '%s')",config_error_prefix, return_code, needle);
            
            break;
        }
    }

    free(data);

    /* Link tmp_zones (or whatever section) to config */

    if(ISOK(return_code))
    {
        return_code = section_assign(g_config);
    }
    else
    {
        if(ctx->top >= 0)
        {
            osformatln(termerr, "%sat %s:%i: %r)", config_error_prefix , ctx->file_name[ctx->top], line_number, return_code);
            log_err("%sat %s:%i: %r)", config_error_prefix , ctx->file_name[ctx->top], line_number, return_code);
        }
        
        flusherr();
    }
    
    return return_code;
}

/*    ------------------------------------------------------------    */

ya_result
config_update(config_data* config)
{
    if(config->cpu_count_override > 0)
    {
        sys_set_cpu_count(config->cpu_count_override);
    }
    
    config->thread_count = sys_get_cpu_count() + 2;
    config->thread_count += config->max_tcp_queries;
                
    config->dnssec_thread_count = BOUND(1, config->dnssec_thread_count, sys_get_cpu_count());
   
#if HAS_DNSSEC_SUPPORT != 0
    if(config->dnssec_thread_count > 0)
    {
        dnssec_process_setthreadcount(sys_get_cpu_count());
    }

    config->thread_count += config->dnssec_thread_count + 2;           /* dnssec */

    dnssec_keystore_setpath(config->keys_path);
#endif

    config->thread_count = BOUND(2, config->thread_count, THREAD_POOL_SIZE_MAX);
   
    if(config->thread_count_by_address < 0)
    {
        log_debug("thread-count-by-address set to %i", config->thread_count_by_address);
        
        /*
         * This is broadly what we measured.
         */
        
        if(sys_get_cpu_count() <= 4)
        {
            config->thread_count_by_address = MAX((int)sys_get_cpu_count() - 1, 0);
        }
        else
        {
            config->thread_count_by_address = sys_get_cpu_count() - 2;
        }
    }
    
    if((config->thread_count_by_address > sys_get_cpu_count()))
    {
        log_warn("bounding down thread-count-by-address to the number of cpus (%d)", sys_get_cpu_count());
        config->thread_count_by_address = sys_get_cpu_count();
    }
    
    if(config->thread_count_by_address > config->thread_count)
    {
        u32 t = MAX(MIN(config->thread_count - 4, config->thread_count / 2), 1);
                
        log_warn("bounding down thread-count-by-address to %d", t);
        config->thread_count_by_address = t;
    }
    
    return config_update_network(config);
}


void
config_free()
{
    /*
     * @TODO investigate: for some reason config_free_inverse does wrong memory free (conflict with something else ?)
     config_free_inverse(config_sections);
     */


    host_address_delete_list(g_config->listen);
    g_config->listen = NULL;

    zone_free_all(&g_config->zones);
    acl_empties_access_control(&g_config->ac);
    acl_free_definitions();

    free(g_config->chroot_path);
    free(g_config->config_file);
    free(g_config->data_path);
    free(g_config->xfr_path);
    free(g_config->keys_path);
    free(g_config->log_path);
    free(g_config->pid_path);
    free(g_config->pid_file);

    free(g_config->server_port);
    free(g_config->version_chaos);
/*    
    g_statistics_logger = NULL
    g_server_logger = NULL;
    g_database_logger = NULL;
    g_zone_logger = NULL;
    #if HAS_DNSSEC_SUPPORT != 0
    g_dnssec_logger = NULL;
    #endif
    g_queries_logger = NULL;
*/
    const config_section_descriptor **sectiondp = config_sections;

    while(*sectiondp != NULL)
    {
        const config_section_descriptor *sectiond = *sectiondp;
        
        // do not free the loggers
        
        if((strcmp(sectiond->name, "loggers") != 0) && (strcmp(sectiond->name, "channels") != 0))
        {
            sectiond->function_free(g_config);
        }
        
        sectiondp++;
    }

#ifndef NDEBUG
    memset(g_config,0xff,sizeof(config_data));
#endif
    free(g_config);

    g_config = NULL;
}

/**
 * Parse the command line to retrieve the configuration file.
 */

ya_result
config_get_file(int argc, char **argv)
{
    extern char                                                     *optarg;
    int                                                         version = 0;
    int                                                            c = '\0';
    struct stat                                                    fileinfo;

    /*    ------------------------------------------------------------    */

    command_line_reset();

    /* Parse command line options */
    while(-1 != (c = command_line_next(argc, argv)))
    {
        switch(c)
        {
            case 'c':
            {
                if((optarg == NULL) || (*optarg == '\0'))
                {
                    osformatln(termerr, PROGRAM_NAME " config file path");
                    return YDF_ERROR_CONFIGURATION;
                }

                if(stat(optarg, &fileinfo) == -1)
                {
                    osformatln(termerr, PROGRAM_NAME " config file");
                    return YDF_ERROR_CONFIGURATION;
                }
                /* Is it a regular file */
                if(!S_ISREG(fileinfo.st_mode))
                {
                    osformatln(termerr, "config file '%s' is not a regular file", optarg);
                    return YDF_ERROR_CONFIGURATION;
                }
                /* Set config-file  (WARNING: THIS IS THE NAME OF A FIELD) */
                if(FAIL(config_adjust("config-file", optarg, g_config)))
                {
                    osformatln(termerr, "error setting up the config file '%s'", optarg);
                    return YDF_ERROR_CONFIGURATION;
                }

                break;
            }
            case 'V':
            {
                version++;
                break;
            }
            case '?':   /* unknown parameter found */
            case 'h':
            {
                show_usage();
                exit(EXIT_SUCCESS);
            }
            default:
            {
                break;
            }
        }
    }

    if(version > 0)
    {
        print_version(version);
        exit(EXIT_SUCCESS);
    }

    return SUCCESS;
}

/** @brief Initialize the config file with the standard settings
 *
 *  @param[out] config
 *
 *  @retval OK
 */

ya_result
config_init()
{
    /*    ------------------------------------------------------------    */

    /** @note for fun:
     * 
     *      I can do better than this.
     *      There could be an array of names from where I take names like acl, main, ...
     *      And I would get the functions dynamically so we can have dynamic yadifa modules.
     *
     *      I know I have enough room in config_sections (32) so I don't verify the lock.
     *
     *      BUT REMEMBER THERE CANNOT BE MORE THAN 32 SECTION TYPES UNTIL THAT CONSTANT IS CHANGED UP ABOVE.
     */

    const struct config_section_descriptor **config_sections_entry = config_sections;

    /*
     * There should be a default logger here, a global sink to STDOUT/STDERR
     */
    
#if HAS_TSIG_SUPPORT == 1
    *config_sections_entry++ = confs_key_get_descriptor();
#endif

#if HAS_ACL_SUPPORT == 1
    *config_sections_entry++ = confs_acl_get_descriptor();
#endif

    *config_sections_entry++ = confs_main_get_descriptor();
    
    *config_sections_entry++ = confs_channels_get_descriptor();
    *config_sections_entry++ = confs_loggers_get_descriptor();
    
    *config_sections_entry++ = confs_zone_get_descriptor();    
    *config_sections_entry++ = confs_control_get_descriptor();
    *config_sections_entry++ = NULL;

    return confs_main_get_descriptor()->function_init(g_config);
}

/** @brief Read the containers found in the config file
 *
 *  A container is a structure which start with <container> and ends with
 *  </container>
 *  @code
 *  <main>
 *  ...
 *  </main>
 *  @endcode
 *  No plug-in system is used for the moment so the only container is the
 *  main container
 *
 *  @param config_container
 *  @param[out] config
 *
 *  @retval OK
 *  @retval NOK
 */
int
config_read(const char *config_container)
{
    ya_result                                              return_code = OK;

    /*    ------------------------------------------------------------    */

    OSDEBUG(termout, "config_read: <%s>\n", config_container);
    
    config_reader_context ctx;
    ctx.top = -1;
    ctx.dynamic = FALSE;
    
    if(ISOK(return_code = config_file_open(g_config->config_file, g_config, &ctx)))
    {
        FILE *f = fopen(g_config->config_file_dynamic, "r");
        if(f != NULL)
        {
            fclose(f);
            config_file_push(g_config->config_file_dynamic, g_config, &ctx);
            
            ctx.dynamic = TRUE;
        }
        
        return_code = config_file_read(config_container, &ctx);
        
        config_file_close(&ctx);
    }
    else
    {
        osformatln(termerr, "%sunable to open '%s': %r",config_error_prefix , g_config->config_file, return_code);
    }   

    return return_code;
}

/**
 * 
 * Tries to read all known sections from the config file.
 * 
 */

ya_result
config_read_all(config_data *config)
{
    ya_result return_code = SUCCESS;

    const config_section_descriptor **sectiondp = config_sections;

    while(*sectiondp != NULL)
    {
        if(FAIL(return_code = config_read((*sectiondp)->name)))
        {
            break;
        }

        sectiondp++;
    }

    return return_code;
}

/** @brief Standard out printing of the main configuration
 *
 *  @param[in] config
 *
 *  @return NONE
 */

void
config_print(config_data *config)
{
    const config_section_descriptor **sectiondp = config_sections;

    while(*sectiondp != NULL)
    {
        (*sectiondp)->function_print(g_config);

        sectiondp++;
    }
}

/*----------------------------------------------------------------------------*/

/* config set functions */

static char
confs_filter_char(char c)
{
    if(c == '_')
    {
        return '-';
    }
    if(c == '.')
    {
        return '-';
    }

    c = tolower(c);

    return c;
}


static bool
confs_name_alike(const char *s1, const char *s2)
{
    int c1;
    int c2;

    for(;;)
    {
        c1 = confs_filter_char(*s1);
        c2 = confs_filter_char(*s2);

        int r = c1 - c2;

        if(r != 0 || c1 == 0)
        {
            return (r == 0);
        }

        s1++;
        s2++;
    }
}

ya_result
confs_init(const config_table_desc *table, void *configbase)
{
    ya_result return_code;

    while(table->name != NULL)
    {
        /* table->setter is NULL for aliases */
        if(table->setter != NULL && table->default_value_string != NULL)
        {
            intptr base = (intptr)configbase;
            intptr offs = (intptr)table->field_offset;
            void *ptr = (void*)(base + offs);

            if(FAIL(return_code = table->setter(table->default_value_string, ptr, table->function_specific)))
            {
                return return_code;
            }
        }
        table++;
    }

    return SUCCESS;
}

ya_result
confs_print(const config_table_desc *table, void *configbase)
{
    return confs_write(termout, table, configbase);
}

ya_result
confs_write(output_stream *os, const config_table_desc *table, void *configbase)
{
    char *value;
    char tmpname[128];
    char tmp[1024];

    while(table->name != NULL)
    {
        size_t name_len = strlen(table->name)+1;
        bool already = FALSE;
        
        for(size_t i = 0; i < name_len; i++)
        {
            char c = table->name[i];
            if((c=='_')||(c=='.'))
            {
                c = '-';
            }
            tmpname[i] = c;
        }
        
        /* table->setter is NULL for aliases */
        if(table->setter != NULL)
        {
            intptr base = (intptr)configbase;
            intptr offs = (intptr)table->field_offset;
            void *ptr = (void*)(base + offs);

            if(table->setter == (confs_set_field_function*)confs_set_bool)
            {
                bool b = *(bool*)ptr;
                value=(b)?"yes":"no";
            }
            else if(table->setter == (confs_set_field_function*)confs_set_flag8)
            {
                u8 *f = (u8*)ptr;
                bool b = *f & table->function_specific._u8;
                value=(b)?"yes":"no";
            }
            else if(table->setter == (confs_set_field_function*)confs_set_flag16)
            {
                u16 *f = (u16*)ptr;
                bool b = *f & table->function_specific._u16;
                value=(b)?"yes":"no";
            }
            else if(table->setter == (confs_set_field_function*)confs_set_flag32)
            {
                u32 *f = (u32*)ptr;
                bool b = *f & table->function_specific._u32;
                value=(b)?"yes":"no";
            }
            else if(table->setter == (confs_set_field_function*)confs_set_flag64)
            {
                u64 *f = (u64*)ptr;
                bool b = *f & table->function_specific._u64;
                value=(b)?"yes":"no";
            }
            else if(table->setter == (confs_set_field_function*)confs_set_u32)
            {
                u32 *v = (u32*)ptr;
                snformat(tmp, sizeof(tmp),"%d", *v);
                value = tmp;
            }
            else if(table->setter == (confs_set_field_function*)confs_set_u16)
            {
                u16 *v = (u16*)ptr;
                snformat(tmp, sizeof(tmp),"%d", *v);
                value = tmp;
            }
            else if(table->setter == (confs_set_field_function*)confs_set_u8)
            {
                u8 *v = (u8*)ptr;
                snformat(tmp, sizeof(tmp),"%d", *v);
                value = tmp;
            }
            else if(table->setter == (confs_set_field_function*)confs_set_uid_t)
            {
                uid_t *v = (uid_t*)ptr;
                snformat(tmp, sizeof(tmp),"%d", *v);
                value = tmp;
            }
            else if(table->setter == (confs_set_field_function*)confs_set_gid_t)
            {
                gid_t *v = (gid_t*)ptr;
                snformat(tmp, sizeof(tmp),"%d", *v);
                value = tmp;
            }
            else if((table->setter == (confs_set_field_function*)confs_set_string) || (table->setter == (confs_set_field_function*)confs_set_path))
            {
                value = *((char**)ptr);
                if(strlen(value) == 0)
                {
                    value = "\"\"";
                }
                
                /*
                if(value == NULL)
                {
                    value = "NULL";
                }
                */
            }
            else if(table->setter == (confs_set_field_function*)confs_set_acl_item)
            {
                address_match_set* ams = (address_match_set*)ptr;
                if(ams != NULL)
                {
                    osformat(os, "%24s", tmpname);
                    acl_address_match_set_to_stream(os, ams);                    
                    osprintln(os,"");
                }
                already = TRUE;
                value = NULL;
            }
            else if(table->setter == (confs_set_field_function*)confs_set_host_list)
            {
                host_address *v = *(host_address**)ptr;
                
                if(v != NULL)
                {
                    osformat(os, "%24s", tmpname);
                    
                    char sep = ' ';
                    
                    do
                    {
                        socketaddress sa;
                        host_address2sockaddr(&sa, v);
                        osformat(os, "%c%{sockaddrip}", sep, &sa);
                        if(v->port != DNS_DEFAULT_PORT)
                        {
                            osformat(os, " port %hd", ntohs(v->port));
                        }
                        if(v->tsig != NULL)
                        {
                            osformat(os, " key %{dnsname}", v->tsig->name);
                        }
                        sep = ',';
                        
                        v = v->next;
                    }
                    while(v != NULL);
                    
                    osprintln(os,"");
                }
                
                already = TRUE;
                value = NULL;
            }
            else if(table->setter == (confs_set_field_function*)confs_set_enum_value)
            {
                u32 *v = (u32*)ptr;
                
                value_name_table* tbl = table->function_specific._voidp;
                
                value = "?";
                
                while(tbl->data != NULL)
                {
                    if(tbl->id == *v)
                    {
                        value = tbl->data;
                        break;
                    }
                    
                    tbl++;
                }
            }
            else
            {
                osformatln(os, "# unable to dump parameter '%s'", tmpname);
                value = NULL;
            }

            if(!already)
            {
                if(value != NULL)
                {
                    osformatln(os, "%24s %s", tmpname, value);
                }
#if DEBUG
                else
                {
                    osformatln(os, "# %24s is not set", tmpname);
                }
#endif
            }
        }
        table++;
    }

    return SUCCESS;
}

ya_result
confs_set(const config_table_desc *tablebase, void *configbase, const char *name, const char *value)
{
    const config_table_desc *table = tablebase;

    while(table->name != NULL)
    {
        /* table->setter is NULL for aliases */

        if(confs_name_alike(table->name, name))
        {
            OSDEBUG(termout, "confs_set(%p,%p,%s,%s) matching with '%s'\n", tablebase, configbase, name, value, table->name);

            if(table->setter != NULL)
            {

                OSDEBUG(termout, "confs_set(%p,%p,%s,%s)\n", tablebase, configbase, name, value);

                intptr base = (intptr)configbase;
                intptr offs = (intptr)table->field_offset;
                void *ptr = (void*)(base + offs);
                return table->setter(value, ptr, table->function_specific);
            }
            else
            {
                OSDEBUG(termout, "confs_set(%p,%p,%s,%s) : alias %s = %s\n", tablebase, configbase, name, value, name, table->default_value_string);
                
                return confs_set(tablebase, configbase, table->default_value_string, value);
            }
        }
        table++;
    }

    /*
     * Unknown name
     */

    OSDEBUG(termout, "confs_set(%p,%p,%s,%s) : unknown name\n", tablebase, configbase, name, value);

    return CONFIG_UNKNOWN_SETTING_ERR;
}

/** @brief  Yes or No option value parser
 *
 *  @param[in] value in asciiz
 *  @param[out] dest to the value
 *
 *  @retval OK
 *  @retval NOK
 */
ya_result
confs_set_bool(const char *value, bool *dest, anytype notused)
{
    ya_result return_code;
    u32 integer_value;
    bool yes_or_no;

    if(ISOK(return_code = get_value_from_casename(true_false_enum, value, &integer_value)))
    {
        yes_or_no = (integer_value != 0);
        *dest = yes_or_no;
    }

    return return_code;
}

/** @brief  flag option value parser
 *
 *  @param[in] value in asciiz
 *  @param[out] dest to the value
 *
 *  @retval OK
 *  @retval NOK
 */
ya_result
confs_set_flag8(const char *value, u8 *dest, anytype mask8)
{
    ya_result return_code;
    bool b;

    if(ISOK(return_code = confs_set_bool(value, &b, mask8)))
    {
        if(b)
        {
            *dest |= mask8._u8;
        }
        else
        {
            *dest &= ~mask8._u8;
        }
    }

    return return_code;
}

/** @brief  flag option value parser
 *
 *  @param[in] value in asciiz
 *  @param[out] dest to the value
 *
 *  @retval OK
 *  @retval NOK
 */
ya_result
confs_set_flag16(const char *value, u16 *dest, anytype mask16)
{
    ya_result return_code;
    bool b;

    if(ISOK(return_code = confs_set_bool(value, &b, mask16)))
    {
        if(b)
        {
            *dest |= mask16._u16;
        }
        else
        {
            *dest &= ~mask16._u16;
        }
    }

    return return_code;
}

/** @brief  flag option value parser
 *
 *  @param[in] value in asciiz
 *  @param[out] dest to the value
 *
 *  @retval OK
 *  @retval NOK
 */
ya_result
confs_set_flag32(const char *value, u32 *dest, anytype mask32)
{
    ya_result return_code;
    bool b;

    if(ISOK(return_code = confs_set_bool(value, &b, mask32)))
    {
        if(b)
        {
            *dest |= mask32._u32;
        }
        else
        {
            *dest &= ~mask32._u32;
        }
    }

    return return_code;
}

/** @brief  flag option value parser
 *
 *  @param[in] value in asciiz
 *  @param[out] dest to the value
 *
 *  @retval OK
 *  @retval NOK
 */
ya_result
confs_set_flag64(const char *value, u64 *dest, anytype mask64)
{
    ya_result return_code;
    bool b;

    if(ISOK(return_code = confs_set_bool(value, &b, mask64)))
    {
        if(b)
        {
            *dest |= mask64._u64;
        }
        else
        {
            *dest &= ~mask64._u64;
        }
    }

    return return_code;
}

/** @brief Integer option value parser
 *
 *  @param[in] value in asciiz
 *  @param[out] dest to the value
 *
 *  @retval OK
 *  @retval NOK
 */

ya_result
confs_set_u32(const char *value,u32 *dest, anytype notused)
{
    *dest = atoi(value);

    return OK;
}

/** @brief Integer option value parser
 *
 *  @param[in] value in asciiz
 *  @param[out] dest to the value
 *
 *  @retval OK
 *  @retval NOK
 */

ya_result
confs_set_u16(const char *value,u16 *dest, anytype notused)
{

    *dest = atoi(value);

    return OK;
}

ya_result
confs_set_u8(const char *value,u8 *dest, anytype notused)
{

    *dest = atoi(value);

    return OK;
}

/** @brief String parser
 *
 *  @param[in] value
 *  @param[in] config_command
 *  @param[out] config
 *
 *  @retval OK
 *  @retval NOK
 */

ya_result
confs_set_string(const char *value, char **dest, anytype notused)
{
    if(*dest != NULL)
    {
        free(*dest);
    }

    *dest = strdup(value);

    return OK;
}

/** @brief Path parser
 *
 *  Ensures that the stored value ends with '/'
 *
 *  @param[in] value
 *  @param[in] config_command
 *  @param[out] config
 *
 *  @retval OK
 *  @retval NOK
 */

ya_result
confs_set_path(const char *value, char **dest, anytype notused)
{
    if(*dest != NULL)
    {
        free(*dest);
        *dest = NULL;
    }

    size_t len = strlen(value);

    if(value[len - 1] != '/')
    {
        char *tmp = (char*)malloc(len + 2);
        memcpy(tmp, value, len);
        tmp[len] = '/';
        tmp[len + 1 ] = '\0';
        *dest = tmp;
    }
    else
    {
        *dest = strdup(value);
    }

    return OK;
}

/** @brief UID parser
 *
 *  @param[in] value
 *  @param[in] config_command
 *  @param[out] config
 *
 *  @retval OK
 *  @retval CONFIG_BAD_UID_ERR
 */

ya_result
confs_set_uid_t(const char *value, uid_t *dest, anytype notused)
{
    struct passwd pwd;
    struct passwd *result;
    char *buffer;

    int buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);

    /*
     * This fix has been made for FreeBSD that returns -1 for the above call
     */

    if(buffer_size < 0)
    {
        buffer_size = 1024;
    }

    MALLOC_OR_DIE(char*,buffer,buffer_size,1);

    getpwnam_r(value,&pwd,buffer,buffer_size,&result);
    *dest = pwd.pw_uid;
    free(buffer);

    if(result == NULL)
    {
        u32 val;
        if(FAIL(parse_u32_check_range(value, &val, 0, MAX_U32, BASE_10)))
        {
            return CONFIG_BAD_UID_ERR;
        }
        *dest = val;
    }
    endpwent();     /* clears the db up */

    return SUCCESS;
}

/** @brief GID parser
 *
 *  @param[in] value
 *  @param[in] config_command
 *  @param[out] config
 *
 *  @retval OK
 *  @retval CONFIG_BAD_UID_ERR
 */

ya_result
confs_set_gid_t(const char *value, gid_t *dest, anytype notused)
{
    struct group grp;
    struct group *result;
    char *buffer;

    int buffer_size = sysconf(_SC_GETGR_R_SIZE_MAX);

    /*
     * This fix has been made for FreeBSD that returns -1 for the above call
     */

    if(buffer_size < 0)
    {
        buffer_size = 1024;
    }

    MALLOC_OR_DIE(char*,buffer,buffer_size,1);

    getgrnam_r(value, &grp, buffer, buffer_size, &result);
    *dest = grp.gr_gid;
    free(buffer);

    if(result == NULL)
    {
        u32 val;

        if(FAIL(parse_u32_check_range(value, &val, 0, MAX_U32, BASE_10)))
        {
            return CONFIG_BAD_GID_ERR;
        }

        *dest = val;
    }
    endgrent();

    return SUCCESS;
}

/** @brief ACL value parser
 *
 *  @param[in] value
 *  @param[in] config_command
 *  @param[out] config
 *
 *  @retval OK
 *  @retval NOK
 */

ya_result
confs_set_acl_item(const char *value, address_match_set *dest, anytype notused)
{
    ya_result return_code = SUCCESS;

    //if(*dest != NULL)
    {
        return_code = acl_build_access_control_item(dest, value);
    }

    return return_code;
}

/** @brief ACL value parser
 *
 *  @param[in] value
 *  @param[in] config_command
 *  @param[out] config
 *
 *  @retval OK
 *  @retval NOK
 */

ya_result
confs_add_list_item(const char *value, list_data **dest, anytype notused)
{
    ya_result return_code;

    return_code = list_add(dest, value);

    return return_code;
}

ya_result
confs_set_enum_value(const char *value, u32 *dest, anytype enum_value_name_table)
{
    ya_result return_code;
    u32 integer_value;

    value_name_table *table = (value_name_table*)enum_value_name_table._voidp;

    if(ISOK(return_code = get_value_from_casename(table, value, &integer_value)))
    {
        *dest = integer_value;
    }

    return return_code;
}

/*
 * IP port n, 
 */

ya_result
confs_set_host_list(const char *value, host_address **dest, anytype notused)
{
    ya_result return_code;
    const char *from = value;
    u16 ip_port = 0;
    tsig_item *tsig = NULL;
    u8 ip_size;
    bool eol = (*from == '\0');
    u8 ip_buffer[16];

    if(value == NULL)   /* nothing to do */
    {
        return ERROR;
    }

#if 1
    /* delete the content of the list */
    if(*dest != NULL)
    {
        host_address_delete_list(*dest);
        *dest = NULL;
    }
#else
    /* find the last node of the list so the new ones will be append */
    while(*dest != NULL)
    {
        dest = &(*dest)->next;
    }
#endif

    while(!eol)
    {
        /* skip the white spaces */

        SKIP_WHSPACE(from);

        const char *to = from;

        /* get the end of statement */

        SKIP_UNTIL(to,",;");

        if(to == from)
        {
            /* No new statement */
            break;
        }

        eol = (*to == '\0');

        /* now skip from until space */

        const char *port_or_key = from;

        SKIP_JUST_WORD(port_or_key);

        const char *next_word = port_or_key;

        SKIP_WHSPACE(next_word);

        bool ip_only = (next_word >= to);

        port_or_key = MIN(port_or_key, to);

        if(FAIL(return_code = parse_ip_address(from, port_or_key - from, ip_buffer, sizeof(ip_buffer))))
        {
            /* parse error, expected something */

            return INCORRECT_CONFIG_LINE;
        }

        ip_size = (u8)return_code;

        zassert(ip_size == 4 || ip_size == 16);

        ip_port = 0;
        tsig = NULL;

        if(!ip_only)
        {
            /* parse & skip 'port */

            bool got_one = FALSE;

            u8 key_dnsname[MAX_DOMAIN_LENGTH + 1];
            char key_name[MAX_DOMAIN_TEXT_LENGTH + 1];
            static const char *port_word="port";
            static const char *key_word="key";            

            if(ISOK(return_code = parse_skip_word_specific(port_or_key, to-port_or_key, &port_word, 1, NULL)))
            {
                next_word = port_or_key + return_code;

                u32 port_value;

                if(FAIL(return_code = parse_u32_check_range(next_word, &port_value, 1, MAX_U16, 10)))
                {
                    /* parse error, expected something */

                    log_err("%sport parse error around '%s'", config_error_prefix, next_word);

                    return INCORRECT_CONFIG_LINE;
                }

                SKIP_JUST_WORD(next_word);
                next_word = MIN(next_word, to);

                port_or_key = next_word;

                // SKIP_WHSPACE(port_or_key);

                ip_port = (u16)port_value;

                got_one = TRUE;
            }
            if(ISOK(return_code = parse_skip_word_specific(port_or_key, to-port_or_key, &key_word, 1, NULL)))
            {
                const char *key_name_start = port_or_key + return_code;

                SKIP_WHSPACE(key_name_start);

                next_word = key_name_start;

                SKIP_JUST_WORD(next_word);
                next_word = MIN(next_word, to);

                port_or_key = next_word;

                size_t key_name_len = next_word - key_name_start;

                if(key_name_len < MAX_DOMAIN_TEXT_LENGTH)
                {
                    memcpy(key_name, key_name_start, key_name_len);

                    key_name[key_name_len] = '\0';

                    //*next_word++ = '\0';
                    port_or_key = next_word;

                    //SKIP_WHSPACE(next_word);

                    if(ISOK(return_code = cstr_to_dnsname_with_check(key_dnsname, key_name)))
                    {
                        tsig = tsig_get(key_dnsname);

                        if(tsig == NULL)
                        {
                            log_err("%skey '%s' has not been defined",config_error_prefix ,key_name);

                            return INCORRECT_CONFIG_LINE;
                        }

                        got_one = TRUE;
                    }
                    else
                    {
                        log_err("%skey name parse error around '%s': %r",config_error_prefix , key_name, return_code);

                        return INCORRECT_CONFIG_LINE;
                    }
                }
                else
                {
                    log_err("%skey name is too big",config_error_prefix );

                    return INCORRECT_CONFIG_LINE;
                }
            }

            if(!got_one)
            {
                log_err("%sgarbage around '%s'",config_error_prefix , port_or_key);

                /* parse error, expected something */

                return INCORRECT_CONFIG_LINE;
            }
        }

        /*
         * Now we can add a host structure node
         */

        host_address *address;
        
        MALLOC_OR_DIE(host_address*, address, sizeof(host_address), HOSTADDR_TAG);

        address->next = NULL;
        address->tsig = tsig;

        switch(ip_size)
        {
            case 4:
            {
                memcpy(address->ip.v4.bytes, ip_buffer, 4);
                address->port = htons(ip_port);
                address->version = HOST_ADDRESS_IPV4;
                break;
            }
            case 16:
            {
                memcpy(address->ip.v6.bytes, ip_buffer, 16);
                address->port = htons(ip_port);
                address->version = HOST_ADDRESS_IPV6;
                break;
            }
        }

        *dest = address;
        dest = &address->next;

        from = to + 1;
    }

    return SUCCESS;
}

bool
config_check_bounds_s32(s32 minval, s32 maxval, s32 val, const char *name)
{
    s32 oldval = val;
    
    if(val < minval)
    {
       val = minval;
    }
    else if(val > maxval)
    {
        val = maxval;
    }
    
    if(val == oldval)
    {
        return TRUE;
    }
    else
    {    
        osformatln(termerr, "error: %s = %d is out of bounds [%d;%d]", name, oldval, minval, maxval);
        
        return FALSE;
    }
}

/** @} */

/*----------------------------------------------------------------------------*/
