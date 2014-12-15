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
/** @defgroup server Server
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include "config.h"

#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

#include <dnscore/sys_types.h>
#include <dnscore/rfc.h>
#include <dnscore/thread_pool.h>
#include <dnscore/format.h>
#include <dnscore/ptr_vector.h>

#include <dnscore/fdtools.h>

#include <dnsdb/journal.h>

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
static bool config_update_network_done = FALSE;

static void
server_context_socket_name_free_cb(void *p)
{
    struct itf_name* itf = (struct itf_name*)p;
    if(itf != NULL)
    {
        free(itf->name);
        free(itf);
    }
}

static void
server_context_socket_name_ensure(u16 s)
{
    ptr_vector_ensures(&server_context_socket_name, s + 1);
    

    for(s32 i = ptr_vector_size(&server_context_socket_name); i < ptr_vector_capacity(&server_context_socket_name); i++)
    {
        struct itf_name *tmp;

        MALLOC_OR_DIE(struct itf_name*, tmp, sizeof(struct itf_name), ITFNAME_TAG);

        tmp->name = NULL;
        tmp->name_len = 0;

        ptr_vector_set(&server_context_socket_name, i, tmp);
    }
    
    server_context_socket_name.offset = MAX(s, server_context_socket_name.offset);
}

static void
server_context_set_socket_name_to(u16 s, const char *text)
{    
    server_context_socket_name_ensure(s);
    
#ifdef DEBUG
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

/**
 * Appends the name of the socket s to the buffer.
 * The buffer has to be big enough, no size test is performed.
 * 
 * @param buffer
 * @param s
 * 
 * @return the length of the name
 */

u32
server_context_append_socket_name(char *buffer, u16 s)
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

/** \brief Closes all sockets and remove pid file
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
    
#ifdef DEBUG
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
    
    ptr_vector_free_empties(&server_context_socket_name, server_context_socket_name_free_cb);

    /* Let the scheduler-bound tasks finish to communicate (else they will block trying) */

#ifdef NEBUG
    log_debug("cleaning up");
    logger_flush();
#endif
    
    /* 
     * Remove the pid file
     */
        
    /// @note DO NOT: logger_finalize() don't, it will be done automatically at exit

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
    
    if(config_update_network_done)
    {
        return SUCCESS;
    }

    config_update_network_done = TRUE;
    
    log_info("setting network up");

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
        /* Create UDP interfaces and initialise server_context structure */
        /*****************************************************************/
        
        if(FAIL(intf->udp.sockfd = socket(intf->udp.addr->ai_family, SOCK_DGRAM, 0)))
        {
            return_value = ERRNO_ERROR;
            ttylog_err("failed to create socket %{sockaddr}: %r", intf->udp.addr->ai_addr, return_value);
            
            return return_value;
        }

        /**
         * Associate the name of the interface to the socket
         */
        
        /**
         * This is distribution/system dependent. With this we ensure that IPv6 will only listen on IPv6 addresses.
         */
        
        if(intf->udp.addr->ai_family == AF_INET6)
        {
            if(FAIL(setsockopt(intf->udp.sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on))))
            {
                return_value = ERRNO_ERROR;
                ttylog_err("failed to force IPv6 on %{sockaddr}: %r", intf->udp.addr->ai_addr, return_value);
                return return_value;
            }
        }

        if(FAIL(setsockopt(intf->udp.sockfd,SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on))))
        {
            return_value = ERRNO_ERROR;
            ttylog_err("failed to reuse address %{sockaddr}: %r", intf->udp.addr->ai_addr, return_value);
            return return_value;
        }

        server_context_set_socket_name(intf->udp.sockfd, (struct sockaddr*)intf->udp.addr->ai_addr);
        
        if(FAIL(bind(intf->udp.sockfd,
                     (struct sockaddr*)intf->udp.addr->ai_addr,
                     intf->udp.addr->ai_addrlen)))
        {
            return_value = ERRNO_ERROR;
            ttylog_err("failed to bind address %{sockaddr}: %r", intf->udp.addr->ai_addr, return_value);
            return return_value;
        }
        
        log_info("bound to UDP interface: %{sockaddr}", intf->udp.addr->ai_addr);

        /*****************************************************************/
        /* Create TCP interfaces and initialize server_context structure */
        /*****************************************************************/

        if(FAIL(intf->tcp.sockfd = socket(intf->tcp.addr->ai_family, SOCK_STREAM, 0)))
        {
            return_value = ERRNO_ERROR;
            ttylog_err("failed to create socket %{sockaddr}: %r", intf->tcp.addr->ai_addr, return_value);
            return return_value;
        }

        if(FAIL(setsockopt(intf->tcp.sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on))))
        {
            return_value = ERRNO_ERROR;
            ttylog_err("failed to reuse address %{sockaddr}: %r", intf->tcp.addr->ai_addr, return_value);
            return return_value;
        }

        /**
         * This is distribution/system dependent. With this we ensure that IPv6 will only listen on IPv6 addresses.
         */
        
        if(intf->tcp.addr->ai_family == AF_INET6)
        {
            if(FAIL(setsockopt(intf->tcp.sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on))))
            {
                return_value = ERRNO_ERROR;
                ttylog_err("failed to force IPv6 on %{sockaddr}:%r", intf->tcp.addr->ai_addr, return_value);
                return return_value;
            }
        }
        
        server_context_set_socket_name(intf->tcp.sockfd, (struct sockaddr*)intf->tcp.addr->ai_addr);
        
        if(FAIL(bind(intf->tcp.sockfd, (struct sockaddr*)intf->tcp.addr->ai_addr, intf->tcp.addr->ai_addrlen)))
        {
            return_value = ERRNO_ERROR;
            ttylog_err("failed to bind address %{sockaddr}:%r", intf->tcp.addr->ai_addr, return_value);
            return return_value;
        }
        
        if(FAIL(return_value = fcntl(intf->tcp.sockfd, F_GETFL, 0)))
        {
            return_value = ERRNO_ERROR;
            return return_value;
        }
        
        fcntl(intf->tcp.sockfd, F_SETFL, return_value | O_NONBLOCK);

        /* For TCP only, listen to it... */
        if(FAIL(listen(intf->tcp.sockfd, TCP_LISTENQ)))
        {
            return_value = ERRNO_ERROR;
            ttylog_err("failed to listen to address %{sockaddr}: %r", intf->tcp.addr->ai_addr, return_value);
            return return_value;
        }
        
        log_info("listening to TCP interface: %{sockaddr}", intf->tcp.addr->ai_addr);
    }

    return OK;
}

/** @} */
