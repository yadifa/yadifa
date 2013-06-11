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
/** @defgroup ### #######
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include <getopt.h>
#include <dnscore/format.h>
#include <dnscore/parsing.h>

#include "confs.h"

#include "server_error.h"
#include "config_error.h"

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/** \brief  Prints the help page when asked with -h or -V or a incorrect command
 *          line
 *
 *  @param NONE
 *
 *  @return NONE
 */

void
show_usage(void)
{
    puts("\n"
         "\t\toptions:\n"
         "\t\t--config/-c <config_file>   : use <config_file> as configuration\n"
		 "\n"
		 "\t\t--version/-V                : view version\n"
         "\t\t--help/-h                   : show this help text\n"
        );
}

/** \brief  Show program's name and the authors
 *
 *  @param NONE
 *
 *  @return NONE
 */
static void
show_authors(void)
{
    puts("\n"
         "\t\tYADIFA authors:\n"
         "\t\t---------------\n"
         "\t\t\n"
         "\t\tGery Van Emelen\n"
         "\t\tEric Diaz Fernandez\n"
         "\n"
		 "\t\tContact: " PACKAGE_BUGREPORT "\n"
        );
}

void
print_version(int level)
{
    switch(level)
    {
	case 1:
	    osformatln(termout, "%s %s (%s)", PROGRAM_NAME, PROGRAM_VERSION, RELEASEDATE);
	    break;
	case 2:
	    osformatln(termout, "%s %s (released %s, compiled %s)", PROGRAM_NAME, PROGRAM_VERSION, RELEASEDATE, COMPILEDATE);
	    break;
    case 3:
	    osformatln(termout, "%s %s (released %s, compiled %s)", PROGRAM_NAME, PROGRAM_VERSION, RELEASEDATE, COMPILEDATE);
        show_authors();
        break;
	default:
	    osformat(termout, "\nYou want to know too much!\n\n");
	    break;
    }
}

static const char            *short_options = "c:dD:mp:hil:L:P:rsvVz:u:g:t:";

static struct option long_options[] =
    {
        { "config",      1,          0, /*O_CONFIG*/      'c'},
        { "version",     0,          0, /*O_VERSION*/     'V'},
        { "help",        0,          0,                   'h'},
        { 0,             0,          0,                    0 }
    };

void command_line_reset()
{
    extern int                                                       optind;
    optind = 0;
}

int command_line_next(int argc, char** argv)
{
    int option_index = 0;

    int ret = getopt_long(argc, argv, short_options, long_options, &option_index);

    return ret;
}

/** \brief Reading the command line and parsing the arguments
 *
 *  Default configuration parameters will be adjusted
 *
 *  @param[in] argc
 *  @param[in] argv
 *  @param[out] config
 *
 *  @return run mode of the program (daemon, or interactive, exit, or...)
 *  @retval YDF_ERROR_CONFIGURATION
 */
int
process_command_line(int argc, char **argv, config_data *config)
{
    extern char                                                     *optarg;

    /*
    int                                                      new_config = 0;
    */
    
    int                                                         version = 0;
    int                                                            c = '\0';

    bool                                                   printing = FALSE;
    bool                                                     doexit = FALSE;
    
    /* There was a 'Z' but it's not used nor defined in the man page */
    

    /* Reinitialize optind, because we are getting thru the command line 
     * options for the second time
     */
    command_line_reset();

    /*    ------------------------------------------------------------    */

    /* Parse command line options */
    while(-1 != (c = command_line_next(argc, argv)))
    {
        switch(c)
        {
            case 'c':
            {
                /* do nothing has been done in another function */
                break;
            }

            case 'd':
            {

                if(FAIL(config_adjust("daemon", "1", config)))
                {
                    return YDF_ERROR_CONFIGURATION;
                }

                break;
            }

            case 'P':
            {
                if(FAIL(config_adjust("port", optarg, config)))
                {
                    return YDF_ERROR_CONFIGURATION;
                }

                break;
            }

            case 'V':
            {
                /* Increase the information seen when asking the version of the program */
                version++;
		
                break;
            }

            case 'u':
            {
                if(FAIL(config_adjust("uid", optarg, config)))
                {
                    return YDF_ERROR_CONFIGURATION;
                }

                break;
            }
            case 'g':
            {
                if(FAIL(config_adjust("gid", optarg, config)))
                {
                    return YDF_ERROR_CONFIGURATION;
                }

                break;
            }

#if 0
            case 't':
            {
                /* If you set the chroot path at the command line, then you want to enable chroot too ... */

                if(FAIL(config_adjust("chroot", "1", config)))
                {
                    return YDF_ERROR_CONFIGURATION;
                }
                if(FAIL(config_adjust("chrootpath", optarg, config)))
                {
                    return YDF_ERROR_CONFIGURATION;
                }

                break;
            }
#endif

            default:
            case '?': /* unknown parameter */
    	    case 'h':
            {
                /* Incorrect arguments given show the usage page */
                show_usage();
                exit(EXIT_SUCCESS);
            }
        }
    }

    /* Prints version & exits */

    if(version > 0)
    {
        print_version(version);

        doexit = TRUE;
    }

    /* Print several values:
     *  config   : the main container configurations
     *  zone     : the zone containers configurations
     *  database : select * from zonefile
     */

    if(printing)
    {
        config_print(config);
        
        doexit = TRUE;
    }

    flushout();
    
    if(doexit)
    {
        exit(EXIT_SUCCESS);
    }
    
    return OK;
}

/** @} */
