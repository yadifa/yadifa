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

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>

#include <dnscore/sys_types.h>
#include <dnscore/rfc.h>
#include <dnscore/thread_pool.h>
#include <dnscore/ptr_vector.h>

#include <dnscore/fdtools.h>

#include <dnscore/socket-server.h>

#include "server_context.h"

#include "server.h"

#define ITFNAME_TAG 0x454d414e465449

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#define SCTXSOCK_TAG 0x4b434f5358544353

#define HAS_SOCKET_SERVER 1

struct itf_name
{
    char *name;
    u8 name_len;
};

static ptr_vector server_context_socket_name = PTR_VECTOR_EMPTY;
static volatile bool config_update_network_done = FALSE;
server_context_s g_server_context = SERVER_CONTEXT_INITIALISER;

static void
server_context_addresses_allocate()
{
    assert(g_server_context.udp_interface_count > 0);
    MALLOC_OBJECT_ARRAY_OR_DIE(g_server_context.udp_interface, struct addrinfo*, g_server_context.udp_interface_count, ADDRINFO_TAG);
    memset(g_server_context.udp_interface, 0, sizeof(struct addrinfo**) * g_server_context.udp_interface_count);

    assert(g_server_context.tcp_interface_count > 0);
    MALLOC_OBJECT_ARRAY_OR_DIE(g_server_context.tcp_interface, struct addrinfo*, g_server_context.tcp_interface_count, ADDRINFO_TAG);
    memset(g_server_context.tcp_interface, 0, sizeof(struct addrinfo**) * g_server_context.tcp_interface_count);

    assert(g_server_context.udp_socket_count > 0);
    MALLOC_OBJECT_ARRAY_OR_DIE(g_server_context.udp_socket, int, g_server_context.udp_socket_count, SCTXSOCK_TAG);
    memset(g_server_context.udp_socket, 0xff, sizeof(int) * g_server_context.udp_socket_count);

    g_server_context.tcp_socket_count = g_server_context.tcp_interface_count * g_server_context.tcp_unit_per_interface;
    //if(server_context.reuse) server_context.tcp_socket_count *= server_context.tcp_unit_per_interface;
    assert(g_server_context.tcp_socket_count > 0);
    MALLOC_OBJECT_ARRAY_OR_DIE(g_server_context.tcp_socket, int, g_server_context.tcp_socket_count, SCTXSOCK_TAG);
    memset(g_server_context.tcp_socket, 0xff, sizeof(int) * g_server_context.tcp_socket_count);
}

#if 0
static void
server_context_addresses_udp_remove_at(u32 index)
{
    if((g_server_context.udp_interface_count == 0) || (index >= g_server_context.udp_interface_count))
    {
        return;
    }

    if(g_server_context.udp_interface_count == 1)
    {
        g_server_context.udp_interface_count = 0;
        g_server_context.udp_socket_count = 0;
        free(g_server_context.udp_interface);
        g_server_context.udp_interface = NULL;
        free(g_server_context.udp_socket);
        g_server_context.udp_socket = NULL;
        return;
    }

    u32 new_udp_interface_count = g_server_context.udp_interface_count - 1;
    u32 new_udp_socket_count = new_udp_interface_count;

    free(g_server_context.udp_interface[index]);
    g_server_context.udp_interface[index] = NULL;

    struct addrinfo **new_udp_interface;
    MALLOC_OBJECT_ARRAY_OR_DIE(new_udp_interface, struct addrinfo*, new_udp_interface_count, ADDRINFO_TAG);
    memcpy(new_udp_interface, g_server_context.udp_interface, sizeof(struct addrinfo**) * index);
    memcpy(&new_udp_interface[index], &g_server_context.udp_interface[index + 1], sizeof(struct addrinfo**) * (new_udp_interface_count - index));

    if(g_server_context.udp_socket[index] >= 0)
    {
        close_ex(g_server_context.udp_socket[index]);
        g_server_context.udp_socket[index] = -1;
    }

    int *new_udp_socket;
    MALLOC_OBJECT_ARRAY_OR_DIE(new_udp_socket, int, new_udp_socket_count, SCTXSOCK_TAG);
    memcpy(new_udp_socket, g_server_context.udp_socket, sizeof(int) * index);
    memcpy(&new_udp_socket[index], &g_server_context.udp_socket[index + 1], sizeof(int) * (new_udp_socket_count - index));
    
    struct addrinfo **old_udp_interface = g_server_context.udp_interface;
    int *old_udp_socket = g_server_context.udp_socket;

    g_server_context.udp_interface = new_udp_interface;
    g_server_context.udp_socket = new_udp_socket;
    g_server_context.udp_interface_count = new_udp_interface_count;
    g_server_context.udp_socket_count = new_udp_socket_count;

    free(old_udp_socket);
    free(old_udp_interface);
}

static void
server_context_addresses_udp_append(u32 count)
{
    if(count == 0)
    {
        return;
    }

    u32 new_udp_interface_count = g_server_context.udp_interface_count + count;
    u32 new_udp_socket_count = new_udp_interface_count;

    struct addrinfo **new_udp_interface;
    MALLOC_OBJECT_ARRAY_OR_DIE(new_udp_interface, struct addrinfo*, new_udp_interface_count, ADDRINFO_TAG);
    memcpy(new_udp_interface, g_server_context.udp_interface, sizeof(struct addrinfo**) * g_server_context.udp_interface_count);
    memset(&new_udp_interface[g_server_context.udp_interface_count], 0, sizeof(struct addrinfo**) * (new_udp_interface_count - g_server_context.udp_interface_count));

    int *new_udp_socket;
    MALLOC_OBJECT_ARRAY_OR_DIE(new_udp_socket, int, new_udp_socket_count, SCTXSOCK_TAG);
    memcpy(new_udp_socket, g_server_context.udp_socket, sizeof(int) * g_server_context.udp_socket_count);
    memset(&new_udp_socket[g_server_context.udp_socket_count], 0xff, sizeof(int) * (new_udp_socket_count - g_server_context.udp_socket_count));

    struct addrinfo **old_udp_interface = g_server_context.udp_interface;
    int *old_udp_socket = g_server_context.udp_socket;

    g_server_context.udp_interface = new_udp_interface;
    g_server_context.udp_socket = new_udp_socket;
    g_server_context.udp_interface_count = new_udp_interface_count;
    g_server_context.udp_socket_count = new_udp_socket_count;

    free(old_udp_socket);
    free(old_udp_interface);
}

static void
server_context_addresses_udp_insert_at(u32 index)
{
    if(index > g_server_context.udp_interface_count)
    {
        return;
    }

    if(index == g_server_context.udp_interface_count)
    {
        server_context_addresses_udp_append(1);
        return;
    }

    u32 new_udp_interface_count = g_server_context.udp_interface_count + 1;
    u32 new_udp_socket_count = new_udp_interface_count;

    struct addrinfo **new_udp_interface;
    MALLOC_OBJECT_ARRAY_OR_DIE(new_udp_interface, struct addrinfo*, new_udp_interface_count, ADDRINFO_TAG);
    memcpy(new_udp_interface, g_server_context.udp_interface, sizeof(struct addrinfo**) * index);
    new_udp_interface[index] = NULL;
    memcpy(&new_udp_interface[index + 1], &g_server_context.udp_interface[index], sizeof(struct addrinfo**) * (g_server_context.udp_interface_count - index));

    int *new_udp_socket;
    MALLOC_OBJECT_ARRAY_OR_DIE(new_udp_socket, int, new_udp_socket_count, SCTXSOCK_TAG);
    memcpy(new_udp_socket, g_server_context.udp_socket, sizeof(int) * index);
    new_udp_socket[index] = -1;
    memcpy(&new_udp_socket[index + 1], &g_server_context.udp_socket[index], sizeof(int) * (g_server_context.udp_socket_count - index));

    struct addrinfo **old_udp_interface = g_server_context.udp_interface;
    int *old_udp_socket = g_server_context.udp_socket;

    g_server_context.udp_interface = new_udp_interface;
    g_server_context.udp_socket = new_udp_socket;
    g_server_context.udp_interface_count = new_udp_interface_count;
    g_server_context.udp_socket_count = new_udp_socket_count;

    free(old_udp_socket);
    free(old_udp_interface);
}

static void
server_context_addresses_tcp_remove_at(u32 index)
{
    if((g_server_context.tcp_interface_count == 0) || (index >= g_server_context.tcp_interface_count))
    {
        return;
    }

    if(g_server_context.tcp_interface_count == 1)
    {
        g_server_context.tcp_interface_count = 0;
        g_server_context.tcp_socket_count = 0;
        free(g_server_context.tcp_interface);
        g_server_context.tcp_interface = NULL;
        free(g_server_context.tcp_socket);
        g_server_context.tcp_socket = NULL;
        return;
    }

    u32 new_tcp_interface_count = g_server_context.tcp_interface_count - 1;
    u32 new_tcp_socket_count = new_tcp_interface_count * g_server_context.tcp_unit_per_interface;

    free(g_server_context.tcp_interface[index]);
    g_server_context.tcp_interface[index] = NULL;

    struct addrinfo **new_tcp_interface;
    MALLOC_OBJECT_ARRAY_OR_DIE(new_tcp_interface, struct addrinfo*, new_tcp_interface_count, ADDRINFO_TAG);
    memcpy(new_tcp_interface, g_server_context.tcp_interface, sizeof(struct addrinfo**) * index);
    memcpy(&new_tcp_interface[index], &g_server_context.tcp_interface[index + 1], sizeof(struct addrinfo**) * (new_tcp_interface_count - index));

    if(g_server_context.tcp_socket[index] >= 0)
    {
        close_ex(g_server_context.tcp_socket[index]);
        g_server_context.tcp_socket[index] = -1;
    }

    int *new_tcp_socket;
    MALLOC_OBJECT_ARRAY_OR_DIE(new_tcp_socket, int, new_tcp_socket_count, SCTXSOCK_TAG);
    memcpy(new_tcp_socket, g_server_context.tcp_socket, sizeof(int) * index);
    memcpy(&new_tcp_socket[index], &g_server_context.tcp_socket[index + 1], sizeof(int) * (new_tcp_socket_count - index));

    struct addrinfo **old_tcp_interface = g_server_context.tcp_interface;
    int *old_tcp_socket = g_server_context.tcp_socket;

    g_server_context.tcp_interface = new_tcp_interface;
    g_server_context.tcp_socket = new_tcp_socket;
    g_server_context.tcp_interface_count = new_tcp_interface_count;
    g_server_context.tcp_socket_count = new_tcp_socket_count;

    free(old_tcp_socket);
    free(old_tcp_interface);
}

static void
server_context_addresses_tcp_append(u32 count)
{
    if(count == 0)
    {
        return;
    }

    u32 new_tcp_interface_count = g_server_context.tcp_interface_count + count;
    u32 new_tcp_socket_count = new_tcp_interface_count * g_server_context.tcp_unit_per_interface;

    struct addrinfo **new_tcp_interface;
    MALLOC_OBJECT_ARRAY_OR_DIE(new_tcp_interface, struct addrinfo*, new_tcp_interface_count, ADDRINFO_TAG);
    memcpy(new_tcp_interface, g_server_context.tcp_interface, sizeof(struct addrinfo**) * g_server_context.tcp_interface_count);
    memset(&new_tcp_interface[g_server_context.tcp_interface_count], 0, sizeof(struct addrinfo**) * (new_tcp_interface_count - g_server_context.tcp_interface_count));

    int *new_tcp_socket;
    MALLOC_OBJECT_ARRAY_OR_DIE(new_tcp_socket, int, new_tcp_socket_count, SCTXSOCK_TAG);
    memcpy(new_tcp_socket, g_server_context.tcp_socket, sizeof(int) * g_server_context.tcp_socket_count);
    memset(&new_tcp_socket[g_server_context.tcp_socket_count], 0xff, sizeof(int) * (new_tcp_socket_count - g_server_context.tcp_socket_count));

    struct addrinfo **old_tcp_interface = g_server_context.tcp_interface;
    int *old_tcp_socket = g_server_context.tcp_socket;

    g_server_context.tcp_interface = new_tcp_interface;
    g_server_context.tcp_socket = new_tcp_socket;
    g_server_context.tcp_interface_count = new_tcp_interface_count;
    g_server_context.tcp_socket_count = new_tcp_socket_count;

    free(old_tcp_socket);
    free(old_tcp_interface);
}
#endif

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

        MALLOC_OBJECT_OR_DIE(tmp, struct itf_name, ITFNAME_TAG);

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
    
#if DEBUG
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

/**
 * Closes all server sockets (UDP/TCP)
 */

void
server_context_close()
{
    ya_result ret;

    log_info("closing sockets");

    if(g_server_context.udp_socket != NULL)
    {
        for(u32 i = 0; i < g_server_context.udp_socket_count; ++i)
        {
            if(g_server_context.udp_socket[i] != -1)
            {
                if(ISOK(ret = fd_getsockettype(g_server_context.udp_socket[i])))
                {
                    close_ex(g_server_context.udp_socket[i]);
                }
                else
                {
#if 0 /* fix */
#else
                    log_debug("server: could not close UDP socket %i: %r", g_server_context.udp_socket[i], ret);
#endif
                }

                g_server_context.udp_socket[i] = -1;
            }
        }
    }

    if(g_server_context.tcp_socket != NULL)
    {
        for(u32 i = 0; i < g_server_context.tcp_socket_count; ++i)
        {
            if(g_server_context.tcp_socket[i] != -1)
            {
                if(ISOK(ret = fd_getsockettype(g_server_context.tcp_socket[i])))
                {
                    close_ex(g_server_context.tcp_socket[i]);
                }
                else
                {
#if 0 /* fix */
#else
                    log_debug("server: could not close TCP socket %i: %r", g_server_context.tcp_socket[i], ret);
#endif
                }
            }
            g_server_context.tcp_socket[i] = -1;
        }
    }
}


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

#if DEBUG
    log_info("server_context_stop()");
#endif

    server_context_close();
    
    if(g_server_context.udp_interface != NULL)
    {
        for(u32 i = 0; i < g_server_context.udp_interface_count; ++i)
        {
            if(g_server_context.udp_interface[i] != NULL)
            {
                free(g_server_context.udp_interface[i]->ai_addr);
                free(g_server_context.udp_interface[i]); // not obtained through getaddrinfo
                g_server_context.udp_interface[i] = NULL;
                //memset(&g_server_context.udp_interface[i], 0, sizeof(g_server_context.udp_interface[i]));
            }
        }
    }
    
    if(g_server_context.tcp_interface != NULL)
    {        
        for(u32 i = 0; i < g_server_context.tcp_interface_count; ++i)
        {
            if(g_server_context.tcp_interface[i] != NULL)
            {
                free(g_server_context.tcp_interface[i]->ai_addr);
                free(g_server_context.tcp_interface[i]); // not obtained through getaddrinfo
                g_server_context.tcp_interface[i] = NULL;
                //memset(&g_server_context.tcp_interface[i], 0, sizeof(g_server_context.tcp_interface[i]));
            }
        }
    }
    
    ptr_vector_callback_and_clear(&server_context_socket_name, server_context_socket_name_free_cb);
    
    ptr_vector_destroy(&server_context_socket_name);

    free(g_server_context.tcp_socket);
    g_server_context.tcp_socket = NULL;
    g_server_context.tcp_socket_count = 0;
    free(g_server_context.udp_socket);
    g_server_context.udp_socket = NULL;
    g_server_context.udp_socket_count = 0;
    free(g_server_context.tcp_interface);
    g_server_context.tcp_interface = NULL;
    g_server_context.tcp_interface_count = 0;
    free(g_server_context.udp_interface);
    g_server_context.udp_interface = NULL;
    g_server_context.udp_interface_count = 0;
    
    if(g_server_context.listen != NULL)
    {
        for(u32 i = 0; i < g_server_context.listen_count; ++i)
        {
            host_address_delete(g_server_context.listen[i]);
        }
        free(g_server_context.listen);
        g_server_context.listen = NULL;
    }
    
    g_server_context.listen_count = 0;
    
    g_server_context.udp_unit_per_interface = 0;
    g_server_context.tcp_unit_per_interface = 0;
    g_server_context.thread_per_udp_worker_count = 1;
    g_server_context.thread_per_tcp_worker_count = 1;

    g_server_context.reuse = 0;
    g_server_context.ready = 0;
    
    config_update_network_done = FALSE;
    
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

// ai_family ai_addr ai_addrlen
// count * (data_len, data)

#if HAS_SOCKET_SERVER
static int
server_context_new_socket(struct addrinfo *addr, int sock_type, bool reuse_port)
{
#if !defined(SO_REUSEPORT)
    if(reuse_port)
    {
        log_err("reuseport has been requested but this feature is not available");
        return FEATURE_NOT_SUPPORTED; // feature not available on this system
    }
#endif

    ya_result ret;
    socket_server_opensocket_s ctx;
    if(FAIL(ret = socket_server_opensocket_init(&ctx, addr, sock_type)))
    {
        return ret;
    }

    const int on = 1;

    //socket_server_opensocket_setopt(socket_server_opensocket_s *ctx, int level, int optname, void* opt, socklen_t optlen)
    
    if(addr->ai_family == AF_INET6)
    {
        //static const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
        //const struct sockaddr_in6 *addr_v6 = (const struct sockaddr_in6*)addr->ai_addr->sa_data;
        //is_any = memcmp(&addr_v6->sin6_addr, &in6addr_any, 16) == 0;
 
        socket_server_opensocket_setopt(&ctx, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
        
        if(sock_type == SOCK_DGRAM)
        {
            /*
             * @note https://stackoverflow.com/questions/46353380/invalid-argument-error-for-sendmsg-on-some-freebsd-systems
             * It turns out FreeBSD is very picky when it allows the use of IP_SENDSRCADDR on a UDP socket.
             * If the socket is bound to INADDR_ANY my code works fine. If the socket is bound to a single IP,
             * then sendmsg() returns EINVAL (invalid argument).
             *
             * ...
             *
             * Note that it's not the issue that has been reported 202102xx on GitHub.
             */

#if __FreeBSD__
            if(host_address_is_any(addr))
            {
#endif
                socket_server_opensocket_setopt_ignore_error(&ctx, IPPROTO_IP, DSTADDR_SOCKOPT, &on, sizeof(on));
#if __FreeBSD__
            }
#endif

            //
#if __FreeBSD__
            if(host_address_is_any(addr))
            {
                socket_server_opensocket_setopt_ignore_error(&ctx, IPPROTO_IPV6, DSTADDR_SOCKOPT, &on, sizeof(on));
            }
#else
            socket_server_opensocket_setopt(&ctx, IPPROTO_IPV6, DSTADDR_SOCKOPT, &on, sizeof(on));
#endif
            //

            socket_server_opensocket_setopt_ignore_result(&ctx, IPPROTO_IPV6, DSTADDR6_SOCKOPT, &on, sizeof(on));
#if WIN32
#else
            socket_server_opensocket_setopt(&ctx, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
#endif
        }
    }
    else
    {
        const struct sockaddr_in *addr_v4 = (const struct sockaddr_in*)addr->ai_addr->sa_data;
        bool is_any = (addr_v4->sin_addr.s_addr == INADDR_ANY);

        if(sock_type == SOCK_DGRAM)
        {
            if(is_any)
            {
                socket_server_opensocket_setopt(&ctx, IPPROTO_IP, DSTADDR_SOCKOPT, &on, sizeof(on));
            }
        }
    }
    
    socket_server_opensocket_setopt(&ctx, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

#if defined(SO_REUSEPORT)
    if(reuse_port)
    {
        socket_server_opensocket_setopt(&ctx, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    }
#endif

#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_OMIT)
    /*
     * @note 20190315 edf -- patch received 20190323 from daisuke.higashi@gmail.com
     *                       modified to go through the socket server
     */

	/*
	 * Linux 3.15 has IP_PMTUDISC_OMIT which makes sockets
	 * ignore PMTU information and send packets with DF=0.
	 * Fragmentation is allowed if and only if the packet
	 * size exceeds the outgoing interface MTU or the packet
	 * encounters smaller MTU link in network.
	 * This mitigates DNS fragmentation attacks by preventing
	 * forged PMTU information.
	 * FreeBSD already has same semantics without setting
	 * the option.
	 */
	if(sock_type == SOCK_DGRAM)
	{
		int action_omit = IP_PMTUDISC_OMIT;
        socket_server_opensocket_setopt(&ctx, IPPROTO_IP, IP_MTU_DISCOVER, &action_omit, sizeof(action_omit));
	}
#endif /* IP_MTU_DISCOVER && IP_PMTUDISC_OMIT */

    int sockfd = socket_server_opensocket_open(&ctx);
    if(sockfd >= 0)
    {
        fd_setcloseonexec(sockfd);
    }
    else
    {
        if(YA_ERROR_BASE(sockfd) == ERRNO_ERROR_BASE)
        {
            errno = YA_ERROR_CODE(sockfd);
        }
    }
    return sockfd;
}
#else
static int
server_context_new_socket(struct addrinfo *udp_addr, int family, bool reuse_port)
{
    ya_result ret;
    int sockfd;
    static const int on = 1;
    
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
        if(family == SOCK_DGRAM)
        {
            if(FAIL(setsockopt(sockfd , IPPROTO_IPV6, DSTADDR6_SOCKOPT, &on, sizeof(on))))
            {
                ret = ERRNO_ERROR;
                ttylog_err("failed to setup alias handling on %{sockaddr}: %r", udp_addr->ai_addr, ret);
                close(sockfd);
                return ret;
            }

            socket_server_opensocket_setopt(&ctx, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
        }
    }
    else
    {
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

    if(family == SOCK_DGRAM)
    {
        setsockopt(sockfd, IPPROTO_IP, DSTADDR_SOCKOPT, &on, sizeof(on));

#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_OMIT)
        /*
         * @note 20190315 edf -- patch received 20190323 from daisuke.higashi@gmail.com
         */

        /*
         * Linux 3.15 has IP_PMTUDISC_OMIT which makes sockets
         * ignore PMTU information and send packets with DF =0.
         * Fragmentation is allowed if and only if the packet
         * size exceeds the outgoing interface MTU or the packet
         * encounters smaller MTU link in network.
         * This mitigates DNS fragmentation attacks by preventing
         * forged PMTU information.
         * FreeBSD already has same semantics without setting
         * the option.
         */

		int action_omit = IP_PMTUDISC_OMIT;
		(void)setsockopt(sockfd, IPPROTO_IP,IP_MTU_DISCOVER, &action_omit, sizeof(action_omit));

#endif /* IP_MTU_DISCOVER && IP_PMTUDISC_OMIT */
    }
    
    if(FAIL(bind(sockfd,
                 (struct sockaddr*)udp_addr->ai_addr,
                 udp_addr->ai_addrlen)))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to bind address %{sockaddr}e: %r", udp_addr->ai_addr, ret);
        close(sockfd);
        return ret;
    }
    
    return sockfd;
}
#endif

void server_context_destroy();



static ya_result
server_context_create_append_all_ipv4_callback(const char* itf_name, const socketaddress* sa, void* data)
{
    (void)itf_name;
    ya_result ret = SUCCESS;
    host_address *ha_list = (host_address *)data;
    if(sa->sa.sa_family == AF_INET)
    {
        ret = host_address_append_sockaddr_with_port(ha_list, sa, ha_list->port);
    }
    return ret;
}

static ya_result
server_context_create_append_all_ipv6_callback(const char* itf_name, const socketaddress* sa, void* data)
{
    (void)itf_name;
    ya_result ret = SUCCESS;
    host_address *ha_list = (host_address *)data;
    if(sa->sa.sa_family == AF_INET6)
    {
        u16 first_bits = GET_U16_AT(sa->sa6.sin6_addr);
        if((first_bits & NU16(0xffc0)) != NU16(0xfe80))
        {
            ret = host_address_append_sockaddr_with_port(ha_list, sa, ha_list->port);
        }
    }
    return ret;
}

host_address*
server_context_get_real_listen_addresses_from_config()
{
    ya_result ret;

    if((g_config == NULL) || (g_config->listen == NULL))
    {
        log_err("There is no listen address list instance.");
        return NULL;
    }

    host_address *real_listen = host_address_copy_list(g_config->listen);

    for(host_address *ha = real_listen; ha != NULL; ha = ha->next)
    {
        log_debug("configured to listen to %{hostaddr}", ha);
    }

    for(host_address *ha = g_config->do_not_listen; ha != NULL; ha = ha->next)
    {
        log_debug("configured to not listen to %{hostaddr}", ha);
    }

    // if ANY addresses need to be splitted, do it

    bool split_any = !host_address_empty(g_config->do_not_listen);

    if(split_any)
    {
        for(host_address *ha = real_listen; ha != NULL; )
        {
            if(host_address_is_any(ha))
            {
                log_debug("listen address %{hostaddr} will be divided into interfaces", ha);

                host_address *removed = host_address_remove_host_address(&real_listen, ha);
                // the dummy is needed in case the above operation completely empties the list

                host_address list_head_with_default_port;
                ZEROMEMORY(&list_head_with_default_port, sizeof(list_head_with_default_port));
                list_head_with_default_port.next = real_listen;

                if(ha->port != 0)
                {
                    list_head_with_default_port.port = ha->port;
                }
                else
                {
                    list_head_with_default_port.port = ntohs(g_config->server_port_value);
                }

                // split
                if(ha->version == HOST_ADDRESS_IPV4)
                {
                    ret = network_interfaces_forall(server_context_create_append_all_ipv4_callback, &list_head_with_default_port);
                }
                else if(ha->version == HOST_ADDRESS_IPV6)
                {
                    ret = network_interfaces_forall(server_context_create_append_all_ipv6_callback, &list_head_with_default_port);
                }
                else
                {
                    ret = INVALID_ARGUMENT_ERROR;
                }

                real_listen = list_head_with_default_port.next;

                if(FAIL(ret))
                {
                    log_err("an unexpected error occurred while scanning the network interfaces: %r.  Because of this, some addresses may be missing.", ret);
                }

                host_address_delete(removed);

                ha = real_listen;
            }
            else
            {
                ha = ha->next;
            }
        }

        for(host_address *ha = real_listen; ha != NULL; ha = ha->next)
        {
            log_debug("divided to listen to %{hostaddr}", ha);
        }
    }

    // remove duplicates

    for(host_address *ha = real_listen; ha != NULL; ha = ha->next)
    {
        if(ha->next != NULL)
        {
            host_address *removed;
            for(;;)
            {
                removed = host_address_remove_host_address(&ha->next, ha);
                if(removed == NULL)
                {
                    break;
                }
                log_debug("removed %{hostaddr} from the listen list (duplicate)", removed);
                host_address_delete(removed);
            }
        }
    }

    for(host_address *ha = real_listen; ha != NULL; ha = ha->next)
    {
        log_debug("compacted to listen to %{hostaddr}", ha);
    }

    // remove do-not-listen addresses

    for(host_address *ha = g_config->do_not_listen; ha != NULL; ha = ha->next)
    {
        for(;;)
        {
            host_address *removed = host_address_remove_host_address(&real_listen, ha);
            if(removed == NULL)
            {
                break;
            }
            log_debug("removed %{hostaddr} from the listen list (excluded)", removed);
            host_address_delete(removed);
        }
    }

    return real_listen;
}

int
server_context_create()
{
    ya_result ret = SUCCESS;
    
    if(g_server_context.ready == 0)
    {
        return INVALID_STATE_ERROR; // unacceptable
    }

    if(config_update_network_done)
    {
        return SUCCESS;
    }

#ifndef SO_REUSEPORT

    int total_udp_socket_count_for_interface = g_server_context.udp_socket_count / g_server_context.udp_interface_count;

    /*
     * If the system does not support SO_REUSEPORT and only one socket is open per interface, then it's not a problem :
     * We just have to disable the reuse request and proceed.
     */

    if(g_server_context.reuse)
    {
        if(total_udp_socket_count_for_interface == 1)
        {
            g_server_context.reuse = FALSE;
        }
        else
        {
            return INVALID_STATE_ERROR; // unacceptable
        }
    }
#endif

    config_update_network_done = TRUE;
    
    log_info("setting network up");

    host_address *real_listen = server_context_get_real_listen_addresses_from_config();

    for(host_address *ha = real_listen; ha != NULL; ha = ha->next)
    {
        log_info("will listen to %{hostaddr}", ha);
    }

    g_server_context.listen_count = host_address_count(real_listen);

    logger_flush();

    // Copy stuff from the config file and command line options

    MALLOC_OBJECT_ARRAY_OR_DIE(g_server_context.listen, host_address*, g_server_context.listen_count, HOSTADDR_TAG);

    {
        host_address *ha = real_listen;
        for(u32 i = 0; i < g_server_context.listen_count; ++i, ha = ha->next)
        {
            assert(ha != NULL);

            g_server_context.listen[i] = host_address_copy(ha); /// note: 20151207 edf -- a copy should be the way to go
        }
    }

    host_address_delete_list(real_listen);
    real_listen = NULL;

    g_server_context.udp_interface_count = g_server_context.listen_count;
    g_server_context.tcp_interface_count = g_server_context.listen_count;
    g_server_context.udp_socket_count = g_server_context.udp_interface_count;

    if(g_server_context.reuse)
    {
        g_server_context.udp_socket_count *= g_server_context.udp_unit_per_interface; // times workers
    }

    if(g_server_context.worker_backlog_queue_size < 4096)
    {
        g_server_context.worker_backlog_queue_size = 4096;
    }

    server_context_addresses_allocate();

    int udp_sockfd_idx = 0;
    int tcp_sockfd_idx = 0;
    
    for(u32 intf_idx = 0; intf_idx < g_server_context.listen_count; ++intf_idx)
    {
        host_address *ha = g_server_context.listen[intf_idx]; // VS false positive: it's kind of nonsense
                                                            /*
                                                                Warning	C6385	Reading invalid data from 'g_server_context.listen':
                                                                the readable size is 'sizeof(host_address *)*((g_server_context.listen_count))' bytes,
                                                                but '16' bytes may be read.yadifa
                                                                line 708 */

        host_address2addrinfo(ha, &g_server_context.udp_interface[intf_idx]);
        host_address2addrinfo(ha, &g_server_context.tcp_interface[intf_idx]);

        /* The host_address list has an IPv4/IPv6 address and a port */
        
        // udp

        {
            struct addrinfo *udp_addr = g_server_context.udp_interface[intf_idx];

            for(u32 n = 0; n < g_server_context.udp_unit_per_interface; ++n)
            {
                int sockfd;

                log_debug("UDP listener socket for %{sockaddr} will be opened %s", udp_addr->ai_addr, (g_server_context.reuse)?"(REUSEPORT)":"");

                if(ISOK(sockfd = server_context_new_socket(udp_addr, SOCK_DGRAM, g_server_context.reuse)))
                {
                    server_context_set_socket_name(sockfd, (struct sockaddr*)udp_addr->ai_addr);
                    g_server_context.udp_socket[udp_sockfd_idx++] = sockfd;

                     log_info("UDP listener socket ready for %{sockaddr}: %i %s", udp_addr->ai_addr, sockfd, (g_server_context.reuse)?"(REUSEPORT)":"");
                }
                else
                {
                    ret = sockfd;

                    ttylog_err("UDP listener failed to listen to %{sockaddr}: %r", udp_addr->ai_addr, ret);
                    server_context_destroy();
                    return ret;
                }
            }
        }
        
        // tcp

        {
            struct addrinfo *tcp_addr = g_server_context.tcp_interface[intf_idx];

            log_debug("TCP listener socket for %{sockaddr} will be opened", tcp_addr->ai_addr);

            for(u32 n = 0; n < g_server_context.tcp_unit_per_interface; ++n)
            {
                int sockfd;

                if(ISOK(sockfd = server_context_new_socket(tcp_addr, SOCK_STREAM, FALSE)))
                {
                    fd_setcloseonexec(sockfd);

                    server_context_set_socket_name(sockfd, (struct sockaddr*)tcp_addr->ai_addr);

                    /* For TCP only, listen to it... */
                    if(FAIL(listen(sockfd, g_config->tcp_queue_size)))
                    {
                        ret = ERRNO_ERROR;
                        ttylog_err("TCP listener failed to listen to %{sockaddr}: %r", tcp_addr->ai_addr, ret);
                        server_context_destroy();
                        return ret;
                    }

#if defined(SOL_TCP) && defined(TCP_FASTOPEN)
                    int queue_size = g_config->tcp_queue_size;
                    setsockopt(sockfd, SOL_TCP, TCP_FASTOPEN, &queue_size, sizeof(queue_size));
#endif
                    g_server_context.tcp_socket[tcp_sockfd_idx++] = sockfd;

                    log_info("TCP listener socket ready for %{sockaddr}: %i", tcp_addr->ai_addr, sockfd);
                }
                else
                {
                    server_context_destroy();
                    return sockfd;
                }
            }
        }
    }

    return SUCCESS;
}

void
server_context_destroy()
{
    server_context_stop();
}

bool
server_context_matches_config()
{
    /**
     * If the number of addresses is the same and
     * if all the addresses defined in the configuration are matching one address in the context
     * then the configuration are matched.
     */

    host_address *real_listen = host_address_copy_list(g_config->listen);

    u32 interfaces_count = host_address_count(real_listen);
    if(g_server_context.listen_count != interfaces_count)
    {
        host_address_delete_list(real_listen);
        return FALSE;
    }

    for(u32 i = 0; i < g_server_context.listen_count; ++i)
    {
        bool match = FALSE;
        host_address *ha = real_listen;
        while(ha != NULL)
        {
            if(host_address_equals(g_server_context.listen[i], ha))
            {
                match = TRUE;
                break;
            }
            ha = ha->next;
        }
        
        if(!match)
        {
            host_address_delete_list(real_listen);
            return FALSE;
        }
    }

    host_address_delete_list(real_listen);
    return TRUE;
}

/** @} */
