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

/**
 *  @defgroup yadifad
 *  @ingroup server
 *  @brief Server initialisation and launch
 *
 *  Starts server
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#define SERVER_C_

/** @note: here we define the variable that is holding the default logger handle for the current source file
 *         Such a handle should NEVER been set in an include file.
 */

#include <dnscore/logger.h>
#include <dnscore/format.h>
#include <dnscore/fdtools.h>
#include <dnscore/tcp_io_stream.h>

#include "signals.h"
#include "scheduler_database_load_zone.h"
#include "poll-util.h"
#include "server-st.h"
#include "server-mt.h"
#include "notify.h"
#include "server_context.h"

#define MODULE_MSG_HANDLE g_server_logger
logger_handle *g_server_logger;

#include "server.h"

server_statistics_t server_statistics;


volatile int program_mode = SA_CONT; /** @note must be volatile */

/*******************************************************************************************************************
 *
 * TCP protocol
 *
 ******************************************************************************************************************/

void
tcp_send_message_data(message_data* mesg)
{
    ya_result sent;

    mesg->buffer_tcp_len[0]       = (mesg->send_length >> 8);
    mesg->buffer_tcp_len[1]       = (mesg->send_length);

    /*
     * Message status cannot be used here to set the rcode.
     * The main reason being : it is better done when the message is built
     * The other reason being : OPT contains extended codes. A pain to parse and handle here.
     */

    //zassert(((mesg->status < 15) && ((MESSAGE_LOFLAGS(mesg->buffer) & RCODE_BITS) == mesg->status)) || (mesg->status >= 15) );

    /**
     * SAME AS READ : THERE HAS TO BE A RATE !
     */
#if !defined(HAS_DROPALL_SUPPORT)
    if(FAIL(sent = writefully_limited(mesg->sockfd, mesg->buffer_tcp_len, mesg->send_length + 2, g_config->tcp_query_min_rate_us)))
    {
        log_err("tcp write error: %r", sent);

        tcp_set_abortive_close(mesg->sockfd);
    }
#endif
}

/*******************************************************************************************************************
 *
 * UDP protocol
 *
 ******************************************************************************************************************/

void
udp_send_message_data(message_data* mesg)
{
    ssize_t sent;

#ifndef NDEBUG
    if(mesg->send_length <= 12)
    {
        log_debug("wrong output message of status %i size %i", mesg->status, mesg->send_length);
        
        log_memdump_ex(g_server_logger, LOG_DEBUG, mesg->buffer, mesg->send_length, 32, TRUE, TRUE, FALSE);
    }
#endif

#if !defined(HAS_DROPALL_SUPPORT)
    
#if UDP_USE_MESSAGES == 0
    
#ifdef DEBUG
    log_debug("udp_send_message_data: sendto(%d, %p, %d, %d, %{sockaddr}, %d)", mesg->sockfd, mesg->buffer, mesg->send_length, 0, (struct sockaddr*)&mesg->other.sa, mesg->addr_len);
#endif
    while((sent = sendto(mesg->sockfd, mesg->buffer, mesg->send_length, 0, (struct sockaddr*)&mesg->other.sa, mesg->addr_len)) < 0)
    {
        int error_code = errno;

        if(error_code != EINTR)
        {
            /** @warning server_st_process_udp needs to be modified */
            //log_err("sendto: %r", MAKE_ERRNO_ERROR(error_code));

            return /*ERROR*/;
        }
    }
#else

    udp_iovec.iov_len = mesg->send_length;
    
#ifdef DEBUG
    log_debug("udp_send_message_data: sendmsg(%d, %p, %d", mesg->sockfd, &udp_msghdr, 0);
#endif
    
    while( (sent = sendmsg(mesg->sockfd, &udp_msghdr, 0)) < 0)
    {
        int error_code = errno;

        if(error_code != EINTR)
        {
            /** @warning server_st_process_udp needs to be modified */
            log_err("sendmsg: %r", MAKE_ERRNO_ERROR(error_code));

            server_statistics.udp_send_error_count++;

            return /*ERROR*/;
        }

        server_statistics.udp_send_eintr_count++;
    }
#endif

    server_statistics.udp_output_size_total += sent;

    if(sent != mesg->send_length)
    {
        /** @warning server_st_process_udp needs to be modified */
        log_err("short byte count sent (%i instead of %i)", sent, mesg->send_length);

        /*return ERROR*/;
    }
#else
    log_debug("udp_send_message_data: drop all");
#endif

    /*return SUCCESS*/;
}


/*******************************************************************************************************************
 *
 * Server init, load, start, stop and exit
 *
 ******************************************************************************************************************/

/** @brief Startup server with all its processes
 *
 *  Never returns. Ends with the program.
 */

void
server_run()
{
    ya_result return_code;

    log_info("server starting: pid=%lu", getpid());

    /* Initializing of yadifa database */

    database_init(); /* Inits the db, starts the threads of the pool, resets the timer */

    /* Resets the statistics */

    ZEROMEMORY(&server_statistics, sizeof (server_statistics_t));
    mutex_init(&server_statistics.mtx);
    
    log_info("loading zones");
    
    if(FAIL(return_code = database_load(&g_config->database, &g_config->zones)))
    {
        log_err("loading zones: %r", return_code);

        exit(EXIT_CODE_DATABASE_LOAD_ERROR);
    }

    OSDEBUG(termout, "I come to serve ...\n");

    log_info("I come to serve ..."); /** I could not resist ... */

    /** @todo check this function */
    database_signature_maintenance(g_config->database);

    /* Initialises the TCP usage limit structure (It's global and defined at the beginning of server.c */

    poll_alloc(g_config->max_tcp_queries);

    /* Go to work */
    
    log_info("thread count by address: %i", g_config->thread_count_by_address);

    if(g_config->thread_count_by_address <= 0)
    {
        log_info("single worker engine");
        server_st_query_loop();
    }
    else
    {
        log_info("multiple workers engine");
        server_mt_query_loop();
    }

    notify_shutdown();
    
    database_load_shutdown();

    /* Proper shutdown. All this could be simply dropped since it takes time for "nothing".
     * But it's good to check that nothing is broken.
     */

    poll_free();
    
    log_info("clearing context");
    
    /* Clear config struct and close all fd's */
    server_context_clear(g_config);
    
#if ZDB_DEBUG_MALLOC != 0
    formatln("block_count=%d", debug_get_block_count());
    
    flushout();
    flusherr();
    
    debug_stat(true);

#endif

    flushout();
    flusherr();

    exit(EXIT_SUCCESS);

    /* Never reached ... */
}

/** @} */
