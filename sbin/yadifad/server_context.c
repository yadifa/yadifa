/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup server Server
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/

#define SERVER_CONTEXT_C 1

#include "server_config.h"

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

#include <dnscore/socket_server.h>

#include "server_context.h"

#include "server.h"

#define ITFNAME_TAG 0x454d414e465449

extern logger_handle_t *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#define SCTXSOCK_TAG      0x4b434f5358544353

#define HAS_SOCKET_SERVER 1
#define SOCKANAM_TAG      0x4d414e414b434f53

struct sockaddr_name_s
{
    socketaddress_t sa;
    int             rc;
    int             name_len;
    char            name[];
};

typedef struct sockaddr_name_s sockaddr_name_t;

union sockaddr_name_static_u
{
    sockaddr_name_t sockaddr_name;
    char            storage[sizeof(sockaddr_name_t) + 8];
};

/**
 * The socket name is implemented as an array to ensure the fastest possible access.
 */

static ptr_vector_t                 server_context_socket_name = PTR_VECTOR_EMPTY;
static volatile bool                config_update_network_done = false;
static server_context_s             g_server_context = SERVER_CONTEXT_INITIALISER;

static ptr_treemap_t                sockaddr_to_string_set;
static mutex_t                      sockaddr_to_string_mutex = MUTEX_INITIALIZER;

static initialiser_state_t          server_context_socket_name_init_state = INITIALISE_STATE_INIT;

static union sockaddr_name_static_u sockaddr_name_dummy = {
    .sockaddr_name.rc = 0x10000000,
    .sockaddr_name.name_len = 0,
};

static void server_context_addresses_allocate()
{
    assert(g_server_context.udp_interface_count > 0);
    MALLOC_OBJECT_ARRAY_OR_DIE(g_server_context.udp_interface, struct addrinfo *, g_server_context.udp_interface_count, ADDRINFO_TAG);
    memset(g_server_context.udp_interface, 0, sizeof(struct addrinfo **) * g_server_context.udp_interface_count);

    assert(g_server_context.tcp_interface_count > 0);
    MALLOC_OBJECT_ARRAY_OR_DIE(g_server_context.tcp_interface, struct addrinfo *, g_server_context.tcp_interface_count, ADDRINFO_TAG);
    memset(g_server_context.tcp_interface, 0, sizeof(struct addrinfo **) * g_server_context.tcp_interface_count);
}

// sockaddr_name_t comparator for a ptr_treemap_t

static int ptr_treemap_sockaddr_name_node_compare(const void *key_a, const void *key_b)
{
    if(key_a != NULL)
    {
        if(key_b != NULL)
        {
            sockaddr_name_t *sn_a = (sockaddr_name_t *)key_a;
            sockaddr_name_t *sn_b = (sockaddr_name_t *)key_b;
            return sockaddr_compare_addr_port(&sn_a->sa.sa, &sn_b->sa.sa);
        }
        else
        {
            return -1;
        }
    }
    else
    {
        return (key_b == NULL) ? 0 : 1;
    }
}

static void server_context_socket_name_initialise()
{
    if(initialise_state_begin(&server_context_socket_name_init_state))
    {
        mutex_init(&sockaddr_to_string_mutex);
        ptr_vector_init_empty(&server_context_socket_name);
        ptr_treemap_init(&sockaddr_to_string_set);
        sockaddr_to_string_set.compare = ptr_treemap_sockaddr_name_node_compare;
        sockaddr_name_dummy.sockaddr_name.rc = 0x10000000;
        sockaddr_name_dummy.sockaddr_name.name_len = 5;
        memcpy(sockaddr_name_dummy.sockaddr_name.name, "dummy", 6);
        initialise_state_ready(&server_context_socket_name_init_state);
    }
}

static void server_context_socket_name_free_cb(ptr_treemap_node_t *node)
{
    sockaddr_name_t *sa_item = (sockaddr_name_t *)node->key;
    ZFREE_ARRAY(sa_item, sizeof(sockaddr_name_t) + sa_item->name_len + 1);
}

static void server_context_socket_name_finalise()
{
    if(initialise_state_unready(&server_context_socket_name_init_state))
    {
        mutex_lock(&sockaddr_to_string_mutex);
        ptr_treemap_callback_and_finalise(&sockaddr_to_string_set, server_context_socket_name_free_cb);
        ptr_vector_finalise(&server_context_socket_name);
        mutex_unlock(&sockaddr_to_string_mutex);
        mutex_destroy(&sockaddr_to_string_mutex);
        initialise_state_end(&server_context_socket_name_init_state);
    }
}

static void server_context_socket_name_set(uint16_t s, struct sockaddr *sa)
{
    char buffer[64];

    mutex_lock(&sockaddr_to_string_mutex);
    sockaddr_name_t    *sa_item;
    ptr_treemap_node_t *node = ptr_treemap_find(&sockaddr_to_string_set, sa);
    if(node == NULL)
    {
        switch(sa->sa_family)
        {
            case AF_INET:
            {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)sa;
                if(inet_ntop(ipv4->sin_family, &ipv4->sin_addr, buffer, sizeof(buffer)) == NULL)
                {
                    strcpy(buffer, "ipv4?"); // big enough, and will not happen anyway
                }
                size_t buffer_len = strlen(buffer) + 1;
                ZALLOC_ARRAY_OR_DIE(sockaddr_name_t *, sa_item, sizeof(sockaddr_name_t) + buffer_len, SOCKANAM_TAG);
                memcpy(&sa_item->sa.sa4, sa, sizeof(struct sockaddr_in));
                sa_item->rc = 1;
                sa_item->name_len = buffer_len - 1;
                memcpy(&sa_item->name[0], buffer, buffer_len);
                node = ptr_treemap_insert(&sockaddr_to_string_set, &sa_item->sa);
                node->value = sa_item;
                break;
            }
            case AF_INET6:
            {
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)sa;
                if(inet_ntop(ipv6->sin6_family, &ipv6->sin6_addr, buffer, sizeof(buffer)) == NULL)
                {
                    strcpy(buffer, "ipv6?"); // big enough, and will not happen anyway
                }
                size_t buffer_len = strlen(buffer) + 1;
                ZALLOC_ARRAY_OR_DIE(sockaddr_name_t *, sa_item, sizeof(sockaddr_name_t) + buffer_len, SOCKANAM_TAG);
                memcpy(&sa_item->sa.sa6, sa, sizeof(struct sockaddr_in6));
                sa_item->rc = 1;
                sa_item->name_len = buffer_len - 1;
                memcpy(&sa_item->name[0], buffer, buffer_len);
                node = ptr_treemap_insert(&sockaddr_to_string_set, &sa_item->sa);
                node->value = sa_item;
                break;
            }
            default:
            {
                mutex_unlock(&sockaddr_to_string_mutex);
                snprintf(buffer, sizeof(buffer), "??AF_%02hx??", sa->sa_family);
                size_t buffer_len = strlen(buffer) + 1;
                ZALLOC_ARRAY_OR_DIE(sockaddr_name_t *, sa_item, sizeof(sockaddr_name_t) + buffer_len, SOCKANAM_TAG);
                memcpy(&sa_item->sa.sa, sa, sizeof(struct sockaddr));
                sa_item->rc = 1;
                sa_item->name_len = buffer_len - 1;
                memcpy(&sa_item->name[0], buffer, buffer_len);
                node = ptr_treemap_insert(&sockaddr_to_string_set, &sa_item->sa);
                node->value = sa_item;
                break;
            }
        }
    }
    else
    {
        sa_item = (sockaddr_name_t *)node->key;
        ++sa_item->rc;
    }

    int name_capacity = ptr_vector_capacity(&server_context_socket_name);
    if(s >= name_capacity)
    {
        ptr_vector_resize(&server_context_socket_name, name_capacity + 32);

        for(int_fast32_t i = ptr_vector_size(&server_context_socket_name); i < ptr_vector_capacity(&server_context_socket_name); i++)
        {
            ptr_vector_set(&server_context_socket_name, i, &sockaddr_name_dummy.sockaddr_name);
        }
    }

    server_context_socket_name.offset = MAX(s, server_context_socket_name.offset);

    sockaddr_name_t *sa_item_prev = (sockaddr_name_t *)ptr_vector_get(&server_context_socket_name, s);

    if((sa_item_prev != NULL) && (sa_item_prev != &sockaddr_name_dummy.sockaddr_name)) // note : it should never be NULL
    {
        if(--sa_item_prev->rc == 0)
        {
            // delete
            ptr_treemap_delete(&sockaddr_to_string_set, sa_item_prev);
            ZFREE_ARRAY(sa_item_prev, sizeof(sockaddr_name_t) + sa_item_prev->name_len + 1);
        }
    }

    ptr_vector_set(&server_context_socket_name, s, sa_item);

    mutex_unlock(&sockaddr_to_string_mutex);
}

static void server_context_socket_name_clear(uint16_t s)
{
    mutex_lock(&sockaddr_to_string_mutex);

    if(s < ptr_vector_size(&server_context_socket_name))
    {
        sockaddr_name_t *sa_item_prev = (sockaddr_name_t *)ptr_vector_get(&server_context_socket_name, s);

        if((sa_item_prev != NULL) && (sa_item_prev != &sockaddr_name_dummy.sockaddr_name)) // note : it should never be NULL
        {
            ptr_vector_set(&server_context_socket_name, s, &sockaddr_name_dummy.sockaddr_name);

            if(--sa_item_prev->rc == 0)
            {
                // delete
                ptr_treemap_delete(&sockaddr_to_string_set, sa_item_prev);
                ZFREE_ARRAY(sa_item_prev, sizeof(sockaddr_name_t) + sa_item_prev->name_len + 1);
            }
        }
    }
    else
    {
        // something is wrong ...
    }

    mutex_unlock(&sockaddr_to_string_mutex);
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

uint32_t server_context_append_socket_name(char *buffer, uint16_t s)
{
    if(s < server_context_socket_name.size)
    {
        sockaddr_name_t *sn = (sockaddr_name_t *)ptr_vector_get(&server_context_socket_name, s);
        memcpy(buffer, sn->name, sn->name_len);
        return sn->name_len;
    }
    else
    {
        return 0;
    }
}

/**
 * Closes all server sockets (UDP/TCP)
 */

void server_context_close()
{
    // nope
}

/** \brief Closes all sockets and remove pid file
 *
 *  @param[in] config
 *  @param[in] server_context
 *
 *  @retval OK
 *  @return otherwise log_quit will stop the program
 */

void server_context_stop()
{
    if(!config_update_network_done)
    {
        return;
    }

    /**
     * @note It takes too much time to properly release the database for big zones.
     *       All this to release the memory to the system anyway.
     *       It is thus better to skip this.
     *       The database unload should only be used for scripting & debugging (if the database structure is corrupted
     * for any reason, the unload will crash)
     *
     *       database_finalize does NOT release the memory of the database, it just destroys threads
     */

#if DEBUG
    log_info("server_context_stop()");
#endif

    server_context_close();

    if(g_server_context.udp_interface != NULL)
    {
        for(uint_fast32_t i = 0; i < g_server_context.udp_interface_count; ++i)
        {
            if(g_server_context.udp_interface[i] != NULL)
            {
                free(g_server_context.udp_interface[i]->ai_addr);
                free(g_server_context.udp_interface[i]); // not obtained through getaddrinfo
                g_server_context.udp_interface[i] = NULL;
                // memset(&g_server_context.udp_interface[i], 0, sizeof(g_server_context.udp_interface[i]));
            }
        }

        g_server_context.udp_interface = NULL;
        g_server_context.udp_interface_count = 0;
    }

    if(g_server_context.tcp_interface != NULL)
    {
        for(uint_fast32_t i = 0; i < g_server_context.tcp_interface_count; ++i)
        {
            if(g_server_context.tcp_interface[i] != NULL)
            {
                free(g_server_context.tcp_interface[i]->ai_addr);
                free(g_server_context.tcp_interface[i]); // not obtained through getaddrinfo
                g_server_context.tcp_interface[i] = NULL;
                // memset(&g_server_context.tcp_interface[i], 0, sizeof(g_server_context.tcp_interface[i]));
            }
        }

        g_server_context.tcp_interface = NULL;
        g_server_context.tcp_interface_count = 0;
    }

    // do NOT : server_context_socket_name_finalise();

    free(g_server_context.tcp_interface);
    g_server_context.tcp_interface = NULL;
    g_server_context.tcp_interface_count = 0;
    free(g_server_context.udp_interface);
    g_server_context.udp_interface = NULL;
    g_server_context.udp_interface_count = 0;

    if(g_server_context.listen != NULL)
    {
        for(uint_fast32_t i = 0; i < g_server_context.listen_count; ++i)
        {
            host_address_delete(g_server_context.listen[i]);
        }
        free(g_server_context.listen);

        g_server_context.listen = NULL;
        g_server_context.listen_count = 0;
    }

    config_update_network_done = false;

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
static int server_context_new_listening_socket(struct addrinfo *addr, int sock_type, bool reuse_port)
{
#if !defined(SO_REUSEPORT)
    if(reuse_port)
    {
        log_err("reuseport has been requested but this feature is not available");
        return FEATURE_NOT_SUPPORTED; // feature not available on this system
    }
#endif

    ya_result                  ret;
    socket_server_opensocket_t ctx;
    if(FAIL(ret = socket_server_opensocket_init(&ctx, addr, sock_type)))
    {
        return ret;
    }

    const int on = 1;

    // socket_server_opensocket_setopt(socket_server_opensocket_s *ctx, int level, int optname, void* opt, socklen_t
    // optlen)

    if(addr->ai_family == AF_INET6)
    {
        // static const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
        // const struct sockaddr_in6 *addr_v6 = (const struct sockaddr_in6*)addr->ai_addr->sa_data;
        // is_any = memcmp(&addr_v6->sin6_addr, &in6addr_any, 16) == 0;

        socket_server_opensocket_setopt(&ctx, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));

        if(sock_type == SOCK_DGRAM)
        {
            /*
             * @note
             * https://stackoverflow.com/questions/46353380/invalid-argument-error-for-sendmsg-on-some-freebsd-systems
             * It turns out FreeBSD is very picky when it allows the use of IP_SENDSRCADDR on a UDP socket.
             * If the socket is bound to INADDR_ANY my code works fine. If the socket is bound to a single IP,
             * then sendmsg() returns EINVAL (invalid argument).
             *
             * ...
             *
             * Note that it's not the issue that has been reported 202102xx on GitHub.
             */

#if __FreeBSD__
            if(addr_info_is_any(addr))
            {
#endif
                socket_server_opensocket_setopt_ignore_error(&ctx, IPPROTO_IP, DSTADDR_SOCKOPT, &on, sizeof(on));
#if __FreeBSD__
            }
#endif

            //
#if __FreeBSD__
            if(addr_info_is_any(addr))
            {
                socket_server_opensocket_setopt_ignore_error(&ctx, IPPROTO_IPV6, DSTADDR_SOCKOPT, &on, sizeof(on));
            }
#else
            socket_server_opensocket_setopt(&ctx, IPPROTO_IPV6, DSTADDR_SOCKOPT, &on, sizeof(on));
#endif
            //

            socket_server_opensocket_setopt_ignore_result(&ctx, IPPROTO_IPV6, DSTADDR6_SOCKOPT, &on, sizeof(on));
#if __unix__
            socket_server_opensocket_setopt(&ctx, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
#endif
        }
    }
    else
    {
        const struct sockaddr_in *addr_v4 = (const struct sockaddr_in *)addr->ai_addr->sa_data;
        bool                      is_any = (addr_v4->sin_addr.s_addr == INADDR_ANY);

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

        struct sockaddr *sa = addr->ai_addr;

        if(sock_type == SOCK_STREAM)
        {
            /* For TCP only, listen to it... */
            if(FAIL(listen(sockfd, g_config->tcp_queue_size)))
            {
                ret = ERRNO_ERROR;
                ttylog_err("TCP listener failed to listen to %{sockaddr}: %r", sa, ret);
                return ret;
            }

#if defined(SOL_TCP) && defined(TCP_FASTOPEN)
            int queue_size = g_config->tcp_queue_size;
            setsockopt(sockfd, SOL_TCP, TCP_FASTOPEN, &queue_size, sizeof(queue_size));
#endif

            log_info("TCP listener socket ready for %{sockaddr}: %i", sa, sockfd);
        }
        else
        {
            log_info("UDP socket ready for %{sockaddr}: %i", sa, sockfd);
        }
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
static int server_context_new_socket(struct addrinfo *udp_addr, int family, bool reuse_port)
{
    ya_result        ret;
    int              sockfd;
    static const int on = 1;

    if(FAIL(sockfd = socket(udp_addr->ai_family, family, SOCKET_PROTOCOL_FROM_TYPE(family))))
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
            if(FAIL(setsockopt(sockfd, IPPROTO_IPV6, DSTADDR6_SOCKOPT, &on, sizeof(on))))
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
            if(FAIL(setsockopt(sockfd, IPPROTO_IP, DSTADDR_SOCKOPT, &on, sizeof(on))))
            {
                ret = ERRNO_ERROR;
                ttylog_err("failed to setup alias handling on %{sockaddr}: %r", udp_addr->ai_addr, ret);
                close(sockfd);
                return ret;
            }
        }
    }

    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on))))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to reuse address %{sockaddr}: %r", udp_addr->ai_addr, ret);
        socketclose_ex(sockfd);
        return ret;
    }

    if(reuse_port)
    {
#ifdef SO_REUSEPORT
        if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on))))
        {
            ret = ERRNO_ERROR;
            ttylog_err("failed to use reuse feature: %r", ret);
            socketclose_ex(sockfd);
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
        (void)setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &action_omit, sizeof(action_omit));

#endif /* IP_MTU_DISCOVER && IP_PMTUDISC_OMIT */
    }

    if(FAIL(bind(sockfd, (struct sockaddr *)udp_addr->ai_addr, udp_addr->ai_addrlen)))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to bind address %{sockaddr}: %r", udp_addr->ai_addr, ret);
        socketclose_ex(sockfd);
        return ret;
    }

    return sockfd;
}
#endif

void             server_context_destroy();

static ya_result server_context_create_append_all_ipv4_callback(const char *itf_name, const socketaddress_t *sa, void *data)
{
    (void)itf_name;
    ya_result       ret = SUCCESS;
    host_address_t *ha_list = (host_address_t *)data;
    if(sa->sa.sa_family == AF_INET)
    {
        ret = host_address_append_sockaddr_with_port(ha_list, sa, ha_list->port);
    }
    return ret;
}

static ya_result server_context_create_append_all_ipv6_callback(const char *itf_name, const socketaddress_t *sa, void *data)
{
    (void)itf_name;
    ya_result       ret = SUCCESS;
    host_address_t *ha_list = (host_address_t *)data;
    if(sa->sa.sa_family == AF_INET6)
    {
        uint16_t first_bits = GET_U16_AT(sa->sa6.sin6_addr);
        if((first_bits & NU16(0xffc0)) != NU16(0xfe80))
        {
            ret = host_address_append_sockaddr_with_port(ha_list, sa, ha_list->port);
        }
    }
    return ret;
}

host_address_t *server_context_get_real_listen_addresses_from_config()
{
    ya_result ret;

    if((g_config == NULL) || (g_config->listen == NULL))
    {
        log_err("There is no listen address list instance.");
        return NULL;
    }

    host_address_t *real_listen = host_address_copy_list(g_config->listen);

    for(host_address_t *ha = real_listen; ha != NULL; ha = ha->next)
    {
        log_debug("configured to listen to %{hostaddr}", ha);
    }

    for(host_address_t *ha = g_config->do_not_listen; ha != NULL; ha = ha->next)
    {
        log_debug("configured to not listen to %{hostaddr}", ha);
    }

    // if ANY addresses need to be splitted, do it

    bool split_any = !host_address_empty(g_config->do_not_listen);

    if(split_any)
    {
        for(host_address_t *ha = real_listen; ha != NULL;)
        {
            if(host_address_is_any(ha))
            {
                log_debug("listen address %{hostaddr} will be divided into interfaces", ha);

                host_address_t *removed = host_address_remove_host_address(&real_listen, ha);
                // the dummy is needed in case the above operation completely empties the list

                host_address_t list_head_with_default_port;
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
                    log_err(
                        "an unexpected error occurred while scanning the network interfaces: %r.  Because of this, "
                        "some addresses may be missing.",
                        ret);
                }

                host_address_delete(removed);

                ha = real_listen;
            }
            else
            {
                ha = ha->next;
            }
        }

        for(host_address_t *ha = real_listen; ha != NULL; ha = ha->next)
        {
            log_debug("divided to listen to %{hostaddr}", ha);
        }
    }

    // remove duplicates

    for(host_address_t *ha = real_listen; ha != NULL; ha = ha->next)
    {
        if(ha->next != NULL)
        {
            host_address_t *removed;
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

    for(host_address_t *ha = real_listen; ha != NULL; ha = ha->next)
    {
        log_debug("compacted to listen to %{hostaddr}", ha);
    }

    // remove do-not-listen addresses

    for(host_address_t *ha = g_config->do_not_listen; ha != NULL; ha = ha->next)
    {
        for(;;)
        {
            host_address_t *removed = host_address_remove_host_address(&real_listen, ha);
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

int server_context_create()
{
    if(config_update_network_done)
    {
        return SUCCESS;
    }

#ifndef SO_REUSEPORT
    ya_result ret = SUCCESS;

    if(g_server_context.udp_interface_count > 0)
    {
        int total_udp_socket_count_for_interface = g_server_context.udp_socket_count / g_server_context.udp_interface_count;

        /*
         * If the system does not support SO_REUSEPORT and only one socket is open per interface, then it's not a
         * problem : We just have to disable the reuse request and proceed.
         */

        if(g_server_context.reuse)
        {
            if(total_udp_socket_count_for_interface == 1)
            {
                g_server_context.reuse = false;
            }
            else
            {
                return INVALID_STATE_ERROR; // unacceptable
            }
        }
    }
#endif

    config_update_network_done = true;

    log_info("setting network up");

    host_address_t *real_listen = server_context_get_real_listen_addresses_from_config();

    for(host_address_t *ha = real_listen; ha != NULL; ha = ha->next)
    {
        log_info("will listen to %{hostaddr}", ha);
    }

    g_server_context.listen_count = host_address_count(real_listen);

    logger_flush();

    // Copy stuff from the config file and command line options

    MALLOC_OBJECT_ARRAY_OR_DIE(g_server_context.listen, host_address_t *, g_server_context.listen_count, HOSTADDR_TAG);

    {
        host_address_t *ha = real_listen;
        for(uint_fast32_t i = 0; i < g_server_context.listen_count; ++i, ha = ha->next)
        {
            assert(ha != NULL);

            g_server_context.listen[i] = host_address_copy(ha); /// note: 20151207 edf -- a copy should be the way to go
        }
    }

    host_address_delete_list(real_listen);
    real_listen = NULL;

    g_server_context.udp_interface_count = g_server_context.listen_count;
    g_server_context.tcp_interface_count = g_server_context.listen_count;
#if 0
    g_server_context.udp_socket_count = g_server_context.udp_interface_count;

    if(g_server_context.reuse)
    {
        g_server_context.udp_socket_count *= g_server_context.udp_unit_per_interface; // times workers
    }

    if(g_server_context.worker_backlog_queue_size < 4096)
    {
        g_server_context.worker_backlog_queue_size = 4096;
    }
#endif

    server_context_addresses_allocate();

    for(uint_fast32_t intf_idx = 0; intf_idx < g_server_context.listen_count; ++intf_idx)
    {
        host_address_t *ha = g_server_context.listen[intf_idx]; // VS false positive: it's kind of nonsense
                                                                /*
                                                                    Warning	C6385	Reading invalid data from 'g_server_context.listen':
                                                                    the readable size is 'sizeof(host_address *)*((g_server_context.listen_count))' bytes,
                                                                    but '16' bytes may be read.yadifa
                                                                    line 708 */

        host_address2addrinfo(ha, &g_server_context.udp_interface[intf_idx]);
        host_address2addrinfo(ha, &g_server_context.tcp_interface[intf_idx]);
    }

    return SUCCESS;
}

void server_context_destroy() { server_context_stop(); }

/**
 * Checks the "listen" parameter.
 * Return true if it matches the previously defined one.
 */

bool server_context_matches_config()
{
    /**
     * If the number of addresses is the same and
     * if all the addresses defined in the configuration are matching one address in the context
     * then the configuration are matched.
     */

    if(g_server_context.listen_count == 0)
    {
        return false;
    }

    host_address_t *real_listen = host_address_copy_list(g_config->listen);

    uint32_t        interfaces_count = host_address_count(real_listen);
    if(g_server_context.listen_count != interfaces_count)
    {
        host_address_delete_list(real_listen);
        return false;
    }

    for(uint_fast32_t i = 0; i < g_server_context.listen_count; ++i)
    {
        bool            match = false;
        host_address_t *ha = real_listen;
        while(ha != NULL)
        {
            if(host_address_equals(g_server_context.listen[i], ha))
            {
                match = true;
                break;
            }
            ha = ha->next;
        }

        if(!match)
        {
            host_address_delete_list(real_listen);
            return false;
        }
    }

    host_address_delete_list(real_listen);
    return true;
}

uint32_t         server_context_tcp_interface_count() { return g_server_context.tcp_interface_count; }

struct addrinfo *server_context_tcp_interface(uint32_t index)
{
    if(index < g_server_context.tcp_interface_count)
    {
        return g_server_context.tcp_interface[index];
    }
    else
    {
        return NULL;
    }
}

uint32_t         server_context_udp_interface_count() { return g_server_context.udp_interface_count; }

struct addrinfo *server_context_udp_interface(uint32_t index)
{
    if(index < g_server_context.udp_interface_count)
    {
        return g_server_context.udp_interface[index];
    }
    else
    {
        return NULL;
    }
}

static ya_result server_context_track_socket(int sockfd, struct sockaddr *sa, int sock_type)
{
    (void)sock_type;
    server_context_socket_name_set(sockfd, sa);
    return sockfd;
}

static void server_context_untrack_socket(int sockfd) { server_context_socket_name_clear(sockfd); }

/**
 * sock_type : STREAM/DGRAM
 */

ya_result server_context_socket_open_bind(struct addrinfo *addr, int sock_type, bool reuse_port)
{
    int sockfd = server_context_new_listening_socket(addr, sock_type, reuse_port);

    if(ISOK(sockfd))
    {
        // keep track
        ya_result ret = server_context_track_socket(sockfd, addr->ai_addr, sock_type);

        if(FAIL(ret))
        {
            socketclose_ex(sockfd);
            sockfd = ret;
        }
    }

    return sockfd;
}

/**
 *
 * Opens and binds multiple sockets
 *
 * addr : the IP + port to bind
 * sock_type : SOCK_STREAM or SOCK_DGRAM
 * reuse_port : use the reuseport socket option
 * sockets : an array to receive all the opened file descriptors
 * socket_count : the number of file descriptors to open
 */

ya_result server_context_socket_open_bind_multiple(struct addrinfo *addr, int sock_type, bool reuse_port, int *sockets, int socket_count)
{
    for(int_fast32_t i = 0; i < socket_count; ++i)
    {
        int sockfd = server_context_new_listening_socket(addr, sock_type, reuse_port);

        if(ISOK(sockfd))
        {
            ya_result ret = server_context_track_socket(sockfd, addr->ai_addr, sock_type);
            if(ISOK(ret))
            {
                sockets[i] = sockfd;
            }
            else
            {
                socketclose_ex(sockfd);

                for(int_fast32_t j = 0; j < i; ++j)
                {
                    server_context_untrack_socket(sockets[j]);
                    close_ex(sockets[j]);
                    sockets[j] = -1;
                }

                return ret;
            }
        }
        else
        {
            for(int_fast32_t j = 0; j < i; ++j)
            {
                server_context_untrack_socket(sockets[j]);
                close_ex(sockets[j]);
                sockets[j] = -1;
            }
            return sockfd;
        }
    }

    // keep track

    return socket_count;
}

ya_result server_context_socket_close(int socket)
{
    // release track
    server_context_untrack_socket(socket);
    close_ex(socket);
    return SUCCESS;
}

ya_result server_context_socket_close_multiple(int *sockets, int socket_count)
{
    for(int_fast32_t j = 0; j < socket_count; ++j)
    {
        server_context_untrack_socket(sockets[j]);
        close_ex(sockets[j]);
        sockets[j] = -1;
    }
    return SUCCESS;
}

void             server_context_init() { server_context_socket_name_initialise(); }

void             server_context_finalise() { server_context_socket_name_finalise(); }

static ya_result network_server_dummy_configure(network_server_t *server)
{
    (void)server;
    return ERROR;
}
static ya_result network_server_dummy_start(network_server_t *server)
{
    (void)server;
    return ERROR;
}
static ya_result network_server_dummy_join(network_server_t *server)
{
    (void)server;
    return ERROR;
}
static ya_result network_server_dummy_stop(network_server_t *server)
{
    (void)server;
    return ERROR;
}
static ya_result network_server_dummy_deconfigure(network_server_t *server)
{
    (void)server;
    return ERROR;
}
static ya_result network_server_dummy_finalise(network_server_t *server)
{
    (void)server;
    return ERROR;
}
static ya_result network_server_dummy_state(network_server_t *server)
{
    (void)server;
    return ERROR;
}
static const char           *network_server_dummy_long_name() { return "dummy"; }

struct network_server_vtbl_s network_server_dummy_vtbl = {network_server_dummy_configure,
                                                          network_server_dummy_start,
                                                          network_server_dummy_join,
                                                          network_server_dummy_stop,
                                                          network_server_dummy_deconfigure,
                                                          network_server_dummy_finalise,
                                                          network_server_dummy_state,
                                                          network_server_dummy_long_name};

/** @} */
