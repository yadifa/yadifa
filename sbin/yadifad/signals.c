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

/** @defgroup ### #######
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include "server-config.h"

#define _GNU_SOURCE 1

#include <dnscore/thread.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#if defined(__linux__) || defined(__gnu_hurd__)
#define _GNU_SOURCE 1
//#include <execinfo.h>
#include <sys/mman.h>
#include <ucontext.h>
#elif defined(__sun)
#include <ucontext.h>
#endif

#include <dnscore/logger.h>
#include <dnscore/format.h>
#include <dnscore/fdtools.h>
#include <dnscore/signals.h>
#include <dnscore/timems.h>
#include <dnscore/thread_pool.h>
#include <dnscore/socket-server.h>

#include "signals.h"
#include "server_context.h"
#include "server.h"
#if HAS_RRSIG_MANAGEMENT_SUPPORT && HAS_DNSSEC_SUPPORT
#include "database-service-zone-resignature.h"
#endif

#define MODULE_MSG_HANDLE g_server_logger
#define MAXTRACE 128

#define LOGGER_REOPEN_MIN_PERIOD_US 1000000

ya_result database_store_all_zones_to_disk();

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

static volatile time_t signal_task_logger_handle_reopen_last_active = 0;

static void
signal_task_reconfigure_reopen_log()
{  
    // TRY debug as else there is a risk of deadlock
    log_try_debug1("signal_task_reconfigure_reopen_log()");
    
    u64 now = timeus();
        
    if(now - signal_task_logger_handle_reopen_last_active > LOGGER_REOPEN_MIN_PERIOD_US)
    {        
        signal_task_logger_handle_reopen_last_active = now;
        
        log_try_debug1("signal_task_reconfigure_reopen_log(): setting the sink");
        
        logger_sink();
        
        if(g_config->reloadable)
        {
            log_try_debug1("signal_task_reconfigure_reopen_log(): reloading configuration");
            
            yadifad_config_update(g_config->config_file);
        }
        else
        {
            // TRY error as else there is a risk of deadlock
            log_try_err("cannot reopen configuration file(s): '%s' is outside of jail", g_config->config_file);
        }
        
#if DEBUG
        log_try_debug1("signal_task_reconfigure_reopen_log(): reopening log files");
#endif
        
        logger_reopen();
        
        if(!server_context_matches_config())
        {
            log_try_debug1("network configuration has changed");
            
            server_service_reconfigure();
        }
        else
        {
            log_try_debug1("network configuration has not changed");
        }
        
#if HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
        database_service_zone_dnskey_set_alarms_on_all_zones();
#endif
    }
#if DEBUG
    else
    {
        double dt = LOGGER_REOPEN_MIN_PERIOD_US - (now - signal_task_logger_handle_reopen_last_active);
        dt /= ONE_SECOND_US_F;
        
        log_try_debug1("signal_task_reconfigure_reopen_log(): ignore for %.3fs", dt);
    }
#endif
    
    // TRY debug as else there is a risk of deadlock
    log_try_debug1("signal_task_reconfigure_reopen_log(): end");
}

/***/

static void
signal_task_database_store_all_zones_to_disk()
{
    log_debug("signal_task_database_store_all_zones_to_disk()");
    
    if(g_config->database != NULL)
    {
        database_store_all_zones_to_disk();
    }
    
    log_debug("signal_task_database_store_all_zones_to_disk(): end");
}

/**/

static void
signal_task_shutdown()
{
#if DEBUG
    log_info("signal_task_shutdown()");
#else
    log_debug("signal_task_shutdown()");
#endif
    
    program_mode = SA_SHUTDOWN;
    
    if(!dnscore_shuttingdown())
    {
        dnscore_shutdown();

        program_mode = SA_SHUTDOWN;

        socket_server_finalize();
        server_service_stop();
        server_context_close();
#if DEBUG
        log_debug("stopping program");
#endif
    }
    
    log_debug("signal_task_shutdown(): end");
}

static void
signal_hup(u8 signum)
{
    (void)signum;
    
    // that was a bad idea as logs may be full and this is the only way
    // to save the situation :
    // log_info("signal: HUP");

    if(!dnscore_shuttingdown())
    {
        signal_task_reconfigure_reopen_log();
    }
}

static void
signal_usr1(u8 signum)
{
    (void)signum;
    log_info("signal: USR1");
    if(!dnscore_shuttingdown())
    {
        signal_task_database_store_all_zones_to_disk();
    }
}

static void
signal_usr2(u8 signum)
{
    (void)signum;
    
}

static void
signal_int(u8 signum)
{
    (void)signum;
    log_info("signal: INT");
    signal_task_shutdown();
    signal_handler_stop();
#if DEBUG
    logger_flush();
#endif
}

static void
signal_term(u8 signum)
{
    (void)signum;
    log_info("signal: TERM");
    signal_task_shutdown();
    signal_handler_stop();
#if DEBUG
    logger_flush();
#endif
}

void signal_setup()
{
    signal_handler_set(SIGHUP, signal_hup);
    signal_handler_set(SIGUSR1, signal_usr1);
    signal_handler_set(SIGUSR2, signal_usr2);
    signal_handler_set(SIGINT, signal_int);
    signal_handler_set(SIGTERM, signal_term);
}

/** @} */
