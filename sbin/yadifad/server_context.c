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
/** @defgroup server Server
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <netdb.h>
#include <netinet/in.h>

#include <dnscore/sys_types.h>
#include <dnscore/rfc.h>
#include <dnscore/thread_pool.h>
#include <dnscore/format.h>
#include <dnscore/ptr_vector.h>

#include <dnscore/scheduler.h>

#include <dnscore/fdtools.h>

#include "server_context.h"

#include "server.h"

#define ITFNAME_TAG 0x454d414e465449

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

struct itf_name
{
    char* name;
    u8 name_len;
};

static ptr_vector server_context_socket_name = EMPTY_PTR_VECTOR;

static void
server_context_socket_name_ensure(u16 s)
{
    s32 old_size = server_context_socket_name.size;
    
    ptr_vector_ensures(&server_context_socket_name, s + 1);
    server_context_socket_name.offset = s;
    
    for(s32 i = old_size; i < server_context_socket_name.size; i++)
    {
        struct itf_name *tmp;

        MALLOC_OR_DIE(struct itf_name*, tmp, sizeof(struct itf_name), ITFNAME_TAG);

        tmp->name = NULL;
        tmp->name_len = 0;

        server_context_socket_name.data[i] = tmp;
    }
}

static void
server_context_set_socket_name_to(u16 s, const char *text)
{    
    server_context_socket_name_ensure(s);
    
#ifndef NDEBUG
    log_debug("socket #%d is named '%s'", s, text);
#endif
    struct itf_name *tmp = server_context_socket_name.data[s];
    
    if(tmp->name != NULL)
    {
        free(tmp->name);
    }
    
    tmp->name = strdup(text);
    tmp->name_len = strlen(text);
}

static void
server_context_set_socket_name(u16 s, struct sockaddr *sa)
{
    char buffer[64];
    
      switch(sa->sa_family)
    {
        case AF_INET:
        {
            struct sockaddr_in *ipv4 = (struct sockaddr_in*)sa;
            
            if(inet_ntop(ipv4->sin_family, &ipv4->sin_addr, buffer, sizeof (buffer)) == NULL)
            {
                strcpy(buffer, "ipv4?");
            }
            break;
        }
        case AF_INET6:
        {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)sa;

            if(inet_ntop(ipv6->sin6_family, &ipv6->sin6_addr, buffer, sizeof (buffer)) == NULL)
            {
                strcpy(buffer, "ipv6?");
            }
            break;
        }
        default:
        {
            strcpy(buffer, "?");
            break;
        }
    }
      
      server_context_set_socket_name_to(s, buffer);
}

u32 server_context_append_socket_name(char *buffer, u16 s)
{
    if(s < server_context_socket_name.size)
    {
        struct itf_name *tmp = server_context_socket_name.data[s];
        memcpy(buffer, tmp->name, tmp->name_len);
        return tmp->name_len;
    }
    else
    {
        return 0;
    }
}


/*----------------------------------------------------------------------------*/

/** \brief  Close all sockets and remove pid file
 *
 *  @param[in] config
 *  @param[in] server_context
 *
 *  @retval OK
 *  @return otherwise log_quit will stop the program
 */
void
server_context_clear(config_data *config)
{
    interface *intf;
    
#ifndef NDEBUG
    log_debug("server_context_clear()");
    logger_flush();
#endif
    
    /*    ------------------------------------------------------------    */

    /**
     * @note It takes too much time to properly release the database for big zones.
     *       All this to release the memory to the system anyway.
     *       It is thus better to skip this.
     *       The database unload should only be used for scripting & debugging (if the database structure is corrupted for any reason,
     *       the unload will crash)
     * 
     *       database_finalize does NOT release the memory of the database, it just destroys threads
     */
    
    log_info("stopping timed events handler");
    
    /**
     * @note Stopping the timer will also stop the regular flush of the logger
     *       From now on it will only flush at exit or when calling a logger_flush/flushall
     */
    
    dnscore_stop_timer();
    
    log_info("closing sockets");

    /* Close all TCP & UDP connections */
    for(intf = config->interfaces; intf < config->interfaces_limit; intf++)
    {
        close_ex(intf->udp.sockfd);
        close_ex(intf->tcp.sockfd);

#if ZDB_DEBUG_MALLOC == 0               // cannot free the memory this way with debug_malloc on (freeaddrinfo needs a hook)
        freeaddrinfo(intf->udp.addr);
        freeaddrinfo(intf->tcp.addr);
#endif
    }

    config->interfaces_limit = config->interfaces;

    /* Let the scheduler-bound tasks finish to communicate (else they will block trying) */

#ifndef NDEBUG
    log_debug("scheduler: doing a proper shutdown");
    logger_flush();
#endif
    
    struct timespec timeout;
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;
    int scheduled_timeout = 0;

    do
    {
        fd_set scheduler_set;
        FD_ZERO(&scheduler_set);
        FD_SET(g_config->scheduler.sockfd, &scheduler_set);
        int return_code = pselect(g_config->scheduler.sockfd,&scheduler_set,NULL,NULL,&timeout,0);

        if(return_code > 0) /* Are any bit sets by pselect ? */
        {
#ifndef NDEBUG
            log_debug("scheduler: got something");
            logger_flush();
#endif
            
            if(FD_ISSET(g_config->scheduler.sockfd, &scheduler_set))
            {          
#ifndef NDEBUG
                log_debug("scheduler: got a process");
                logger_flush();
#endif
                scheduler_process();
                scheduled_timeout = 0;
            }
        }
        else if(return_code < 0)
        {
            return_code = errno;
            
#ifndef NDEBUG
            log_debug("scheduler: got a error: %r", MAKE_ERRNO_ERROR(return_code));
            logger_flush();
#endif
            
            if(return_code!= EINTR)
            {
                log_err("error emptying the scheduler queue: %r", MAKE_ERRNO_ERROR(return_code));
                logger_flush();
                
                scheduled_timeout++;
            }
        }
        else
        {
            scheduled_timeout++;
        }
    }
    while(scheduled_timeout <= 5);
    
#ifndef NDEBUG
    log_debug("scheduler: finalising");
    logger_flush();
#endif

    scheduler_finalize();
    
    thread_pool_destroy();
    
    database_unload(g_config->database);
    
    database_finalize();  

    config->database = NULL;
    
    log_info("releasing pid file lock");
    
    logger_flush();

    logger_stop();
        
    /* 
     * Remove the pid file
     */
    
    unlink(config->pid_file); /** @note: server_context_clear Unlink should be in another function */
    
#ifndef NDEBUG

    /* No need to free listen & server_port will be done with config_remove */

    config_free();

#endif

    // don't, it will be done automatically at exit
    
    //logger_finalize();  /* no logging allowed after this */

    /** @note: server_context_clear has to free server_context struct */
}

/** \brief  Initialize sockets and copy the config parameters into server_context_t
 *
 *  @param[in] config
 *  @param[out] server_context
 *
 *  @retval OK
 *  @return otherwise log_quit will stop the program
 */
int
config_update_network(config_data *config)
{
    ya_result return_value = SUCCESS;
    const int                                                        on = 1;
    host_address                                         *tmp_listen = NULL;
    interface                                                         *intf;

    int                                                            sched_fd;

    /*    ------------------------------------------------------------    */


    /* Copy stuff from the config file and command line options */

    tmp_listen               = config->listen;
    config->interfaces_limit = &config->interfaces[config->total_interfaces];

    for(intf = config->interfaces; intf < config->interfaces_limit; intf++)
    {
        ZEROMEMORY(intf, sizeof(interface));

        host_address2addrinfo(&intf->udp.addr, tmp_listen);
        host_address2addrinfo(&intf->tcp.addr, tmp_listen);

        tmp_listen   = tmp_listen->next;

        /* The host_address list has an IPv4/IPv6 address and a port */

        /*****************************************************************/
        /* Create UDP interfaces and initialize server_context structure */
        /*****************************************************************/

        intf->udp.sockfd = Socket(intf->udp.addr->ai_family, SOCK_DGRAM, 0);
        
        /**
         * Associate the name of the interface to the socket
         */
        
        /**
         * This is distribution/system dependent. With this we ensure that IPv6 will only listen on IPv6 addresses.
         */
        
        if(intf->udp.addr->ai_family == AF_INET6)
        {
            if(FAIL(return_value = Setsockopt(intf->udp.sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on))))
            {
                return return_value;
            }
        }

        if(FAIL(return_value = Setsockopt(intf->udp.sockfd,SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on))))
        {
            return return_value;
        }

        log_info("binding %{sockaddr}", intf->udp.addr->ai_addr);
        
        server_context_set_socket_name(intf->udp.sockfd, (struct sockaddr*)intf->udp.addr->ai_addr);
        
        if(FAIL(return_value = Bind(intf->udp.sockfd,
                (struct sockaddr*)intf->udp.addr->ai_addr,
                intf->udp.addr->ai_addrlen)))
        {
            return return_value;
        }
                

        /*****************************************************************/
        /* Create TCP interfaces and initialize server_context structure */
        /*****************************************************************/

        intf->tcp.sockfd = Socket(intf->tcp.addr->ai_family, SOCK_STREAM, 0);

        if(FAIL(return_value = Setsockopt(intf->tcp.sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on))))
        {
            return return_value;
        }
                
        
        /**
         * This is distribution/system dependent. With this we ensure that IPv6 will only listen on IPv6 addresses.
         */
        
        if(intf->tcp.addr->ai_family == AF_INET6)
        {
            if(FAIL(return_value = Setsockopt(intf->tcp.sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on))))
            {
                return return_value;
            }
        }
        
        server_context_set_socket_name(intf->tcp.sockfd, (struct sockaddr*)intf->tcp.addr->ai_addr);
        
        if(FAIL(return_value = Bind(intf->tcp.sockfd, (struct sockaddr*)intf->tcp.addr->ai_addr, intf->tcp.addr->ai_addrlen)))
        {
            return return_value;
        }
        
        fcntl(intf->tcp.sockfd, F_SETFL, Fcntl(intf->tcp.sockfd, F_GETFL, 0) | O_NONBLOCK);

        /* For TCP only, listen to it... */
        if(FAIL(return_value = Listen(intf->tcp.sockfd, TCP_LISTENQ)))
        {
            return return_value;
        }
    }

    sched_fd = scheduler_init();
    config->scheduler.sockfd = sched_fd;
    
    server_context_set_socket_name_to(intf->udp.sockfd, "scheduler");

    return OK;
}

/** @} */
