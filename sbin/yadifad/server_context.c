/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2017, EURid. All rights reserved.
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

#define SERVER_CONTEXT_C 1

#include "server-config.h"
#include "config.h"

#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

#include <dnscore/sys_types.h>
#include <dnscore/rfc.h>
#include <dnscore/thread_pool.h>
#include <dnscore/ptr_vector.h>

#include <dnscore/fdtools.h>

#include "server_context.h"

#include "server.h"

#define ITFNAME_TAG 0x454d414e465449

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#define SCTXSOCK_TAG 0x4b434f5358544353

struct itf_name
{
    char *name;
    u8 name_len;
};

static ptr_vector server_context_socket_name = EMPTY_PTR_VECTOR;
static volatile bool config_update_network_done = FALSE;
server_context_s server_context = SERVER_CONTEXT_INITIALISER;

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
            
            if(inet_ntop(ipv4->sin_family, &ipv4->sin_addr, buffer, sizeof(buffer)) == NULL)
            {
                strcpy(buffer, "ipv4?"); // big enough
            }
            break;
        }
        case AF_INET6:
        {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)sa;

            if(inet_ntop(ipv6->sin6_family, &ipv6->sin6_addr, buffer, sizeof(buffer)) == NULL)
            {
                strcpy(buffer, "ipv6?"); // big enough
            }
            break;
        }
        default:
        {
            strcpy(buffer, "?"); // big enough
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
server_context_stop()
{
    ya_result ret;
    
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
    
    log_info("closing sockets");
    
    for(int i = 0; i < server_context.udp_socket_count; ++i)
    {
        if(server_context.udp_socket[i] != -1)
        {
            if(ISOK(ret = fd_getsockettype(server_context.udp_socket[i])))
            {
                close_ex(server_context.udp_socket[i]);
            }
            else
            {
#if 0 /* fix */
#else
                log_debug("server: could not close UDP socket %i: %r", server_context.udp_socket[i], ret);
#endif
            }
            
            server_context.udp_socket[i] = -1;
        }
    }
    
    for(int i = 0; i < server_context.tcp_socket_count; ++i)
    {
        if(ISOK(ret = fd_getsockettype(server_context.tcp_socket[i])))
        {
            close_ex(server_context.tcp_socket[i]);
        }
        else
        {
#if 0 /* fix */
#else
            log_debug("server: could not close TCP socket %i: %r", server_context.tcp_socket[i], ret);
#endif
        }
        server_context.tcp_socket[i] = -1;
    }
    
    for(int i = 0; i < server_context.udp_interface_count; ++i)
    {
        freeaddrinfo(server_context.udp_interface[i]);
        memset(&server_context.udp_interface[i], 0, sizeof(server_context.udp_interface[i]));
    }
    
    for(int i = 0; i < server_context.tcp_interface_count; ++i)
    {
        freeaddrinfo(server_context.tcp_interface[i]);
        memset(&server_context.tcp_interface[i], 0, sizeof(server_context.tcp_interface[i]));
    }
    
    ptr_vector_free_empties(&server_context_socket_name, server_context_socket_name_free_cb);

    /* Let the scheduler-bound tasks finish to communicate (else they will block trying) */

#ifdef NEBUG
    log_debug("cleaning up");
    logger_flush();
#endif
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

static int
server_context_new_socket(struct addrinfo *udp_addr, int family, bool reuse_port)
{
    ya_result ret;
    int sockfd;
    const int on = 1;
    
    if(FAIL(sockfd = socket(udp_addr->ai_family, family, 0)))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to create socket %{sockaddr}: %r", udp_addr->ai_addr, ret);

        return ret;
    }

    /**
     * Associate the name of the interface to the socket
     */

    /**
     * This is distribution/system dependent. With this we ensure that IPv6 will only listen on IPv6 addresses.
     */

    if(udp_addr->ai_family == AF_INET6)
    {
        if(FAIL(setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on))))
        {
            ret = ERRNO_ERROR;
            ttylog_err("failed to force IPv6 on %{sockaddr}: %r", udp_addr->ai_addr, ret);
            close(sockfd);
            return ret;
        }
#if UDP_USE_MESSAGES
        if(family == SOCK_DGRAM)
        {
            if(FAIL(setsockopt(sockfd , IPPROTO_IPV6, DSTADDR_SOCKOPT, &on, sizeof(on))))
            {
                ret = ERRNO_ERROR;
                ttylog_err("failed to setup alias handling on %{sockaddr}: %r", udp_addr->ai_addr, ret);
                close(sockfd);
                return ret;
            }
        }
#endif
    }
    else
    {
#if UDP_USE_MESSAGES
        if(family == SOCK_DGRAM)
        {
            if(FAIL(setsockopt(sockfd , IPPROTO_IP, DSTADDR_SOCKOPT, &on, sizeof(on))))
            {
                ret = ERRNO_ERROR;
                ttylog_err("failed to setup alias handling on %{sockaddr}: %r", udp_addr->ai_addr, ret);
                close(sockfd);
                return ret;
            }
        }
#endif
    }

    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on))))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to reuse address %{sockaddr}: %r", udp_addr->ai_addr, ret);
        close(sockfd);
        return ret;
    }

    if(reuse_port)
    {
#ifdef SO_REUSEPORT
        if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *) &on, sizeof(on))))
        {
            ret = ERRNO_ERROR;
            ttylog_err("failed to use reuse feature: %r", ret);
            close(sockfd);
            return ret;
        }
#else
        return MAKE_ERRNO_ERROR(ENOTSUP);
#endif
    }

    if(FAIL(bind(sockfd,
                 (struct sockaddr*)udp_addr->ai_addr,
                 udp_addr->ai_addrlen)))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to bind address %{sockaddr}: %r", udp_addr->ai_addr, ret);
        close(sockfd);
        return ret;
    }
    
    return sockfd;
}

int
server_context_start(host_address *interfaces)
{
    ya_result ret = SUCCESS;
    
    if(server_context.ready == 0)
    {
        return INVALID_STATE_ERROR; // unacceptable
    }
    
    if(config_update_network_done)
    {
        return SUCCESS;
    }
    
    config_update_network_done = TRUE;
    
    log_info("setting network up");

    /*    ------------------------------------------------------------    */

    /* Copy stuff from the config file and command line options */

    server_context.listen_count = host_address_count(interfaces);
    MALLOC_OR_DIE(host_address**, server_context.listen, sizeof(host_address*) * server_context.listen_count, HOSTADDR_TAG);
    {
        host_address *ha= interfaces;
        for(int i = 0; i < server_context.listen_count; ++i, ha = ha->next)
        {
            server_context.listen[i] = ha; /// note: 20151207 edf -- a copy should be the way to go
        }
    }

    server_context.udp_interface_count = server_context.listen_count;
    assert(server_context.udp_interface_count > 0);
    MALLOC_OR_DIE(struct addrinfo**, server_context.udp_interface, sizeof(struct addrinfo*) * server_context.udp_interface_count, ADDRINFO_TAG);
    memset(server_context.udp_interface, 0, sizeof(struct addrinfo**) * server_context.udp_interface_count);
    
    server_context.tcp_interface_count = server_context.listen_count;
    assert(server_context.tcp_interface_count > 0);
    MALLOC_OR_DIE(struct addrinfo**, server_context.tcp_interface, sizeof(struct addrinfo*) * server_context.tcp_interface_count, ADDRINFO_TAG);
    memset(server_context.tcp_interface, 0, sizeof(struct addrinfo**) * server_context.tcp_interface_count);
        
    server_context.udp_socket_count = server_context.udp_interface_count;
        
    if(server_context.reuse) server_context.udp_socket_count *= server_context.udp_unit_per_interface; // times workers
    
    assert(server_context.udp_socket_count > 0);
    MALLOC_OR_DIE(int*, server_context.udp_socket, sizeof(int) * server_context.udp_socket_count, SCTXSOCK_TAG);
    memset(server_context.udp_socket, 0xff, sizeof(int) * server_context.udp_socket_count);
    
    server_context.tcp_socket_count = server_context.tcp_interface_count * server_context.tcp_unit_per_interface;
    //if(server_context.reuse) server_context.tcp_socket_count *= server_context.tcp_unit_per_interface;
    assert(server_context.tcp_socket_count > 0);
    MALLOC_OR_DIE(int*, server_context.tcp_socket, sizeof(int) * server_context.tcp_socket_count, SCTXSOCK_TAG);
    memset(server_context.tcp_socket, 0xff, sizeof(int) * server_context.tcp_socket_count);
    
    int udp_sockfd_idx = 0;
    int tcp_sockfd_idx = 0;
    
    for(int intf_idx = 0; intf_idx < server_context.listen_count; ++intf_idx)
    {
        host_address *ha = server_context.listen[intf_idx];
        
        host_address2addrinfo(&server_context.udp_interface[intf_idx], ha);
        host_address2addrinfo(&server_context.tcp_interface[intf_idx], ha);
        
        struct addrinfo *udp_addr = server_context.udp_interface[intf_idx];
        struct addrinfo *tcp_addr = server_context.tcp_interface[intf_idx];
        /*
        interface *intf = interfaces[intf_idx];        
        ZEROMEMORY(intf, sizeof(interface));        
        host_address2addrinfo(&intf->udp.addr, ha);        
        host_address2addrinfo(&intf->tcp.addr, ha);
        */
        /* The host_address list has an IPv4/IPv6 address and a port */
        
        // udp
        
        int total_udp_socket_count_for_interface = server_context.udp_socket_count / server_context.udp_interface_count;
        
        for(int n = 0; n < total_udp_socket_count_for_interface; ++n)
        {
            int sockfd;

            if(ISOK(sockfd = server_context_new_socket(udp_addr, SOCK_DGRAM, server_context.reuse)))
            {                                
                server_context_set_socket_name(sockfd, (struct sockaddr*)udp_addr->ai_addr);
                server_context.udp_socket[udp_sockfd_idx++] = sockfd;                
                
                //intf->udp.sockfd = sockfd;
                
                log_info("UDP listener socket ready for %{sockaddr}: %i %s", udp_addr->ai_addr, sockfd, (server_context.reuse)?"(REUSEPORT)":"");
                

            }
            else
            {
                return sockfd;
            }
        }
        
        log_info("bound to UDP interface: %{sockaddr}", udp_addr->ai_addr);

        // tcp

        for(int n = 0; n < server_context.tcp_unit_per_interface; ++n)
        {
            int sockfd;

            if(ISOK(sockfd = server_context_new_socket(udp_addr, SOCK_STREAM, FALSE)))
            {                                
                server_context_set_socket_name(sockfd, (struct sockaddr*)tcp_addr->ai_addr);
                
                if(FAIL(ret = fcntl(sockfd, F_GETFL, 0)))
                {
                    ret = ERRNO_ERROR;
                    return ret;
                }

                fcntl(sockfd, F_SETFL, ret | O_NONBLOCK);

                /* For TCP only, listen to it... */
                if(FAIL(listen(sockfd, TCP_LISTENQ)))
                {
                    ret = ERRNO_ERROR;
                    ttylog_err("failed to listen to address %{sockaddr}: %r", tcp_addr->ai_addr, ret);
                    return ret;
                }

                log_info("listening to TCP interface: %{sockaddr}", tcp_addr->ai_addr);
                
                server_context.tcp_socket[tcp_sockfd_idx++] = sockfd;
                //intf->tcp.sockfd = sockfd;
                
                log_info("TCP listener socket ready for %{sockaddr}: %i", tcp_addr->ai_addr, sockfd);
            }
            else
            {
                return sockfd;
            }
        }
    }

    return SUCCESS;
}

/** @} */
