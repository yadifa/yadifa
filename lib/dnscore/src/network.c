/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 * @defgroup
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include "dnscore/network.h"
#include "dnscore/fdtools.h"
#include "dnscore/logger.h"
#include "dnscore/tcp_io_stream.h"
#include "dnscore/parsing.h"

#define DEBUG_ACCEPT_EX 0

#if __unix__
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <poll.h>
#else
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")
#endif

extern logger_handle_t *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

bool addr_info_is_any(struct addrinfo *addr)
{
    if(addr != NULL)
    {
        bool is_any;

        if(addr->ai_family == AF_INET6)
        {
            static const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
            const struct sockaddr_in6   *addr_v6 = (const struct sockaddr_in6 *)addr->ai_addr->sa_data;
            is_any = memcmp(&addr_v6->sin6_addr, &in6addr_any, 16) == 0;
        }
        else if(addr->ai_family == AF_INET)
        {
            const struct sockaddr_in *addr_v4 = (const struct sockaddr_in *)addr->ai_addr->sa_data;
            is_any = (addr_v4->sin_addr.s_addr == INADDR_ANY);
        }
        else
        {
            // no supported, so no
            is_any = false;
        }

        return is_any;
    }
    else
    {
        return false;
    }
}

#if __unix__
ya_result network_interfaces_forall(network_interfaces_forall_callback cb, void *data)
{
    ya_result       ret = SUCCESS;
    struct ifaddrs *ia = NULL;
    if(getifaddrs(&ia) == 0)
    {
        socketaddress_t tmp;
        char            tmp_name[128];
        for(struct ifaddrs *a = ia; a != NULL; a = a->ifa_next)
        {
            if((a->ifa_flags & IFF_UP) == 0)
            {
                // interface is down
                continue;
            }

            if(a->ifa_addr == NULL)
            {
                // interface isn't usable
                continue;
            }

            socketaddressp_t sa;
            sa.sa = a->ifa_addr;
            switch(sa.sa->sa_family)
            {
                case AF_INET:
                {
                    tmp.ss = *sa.ss;
                    strcpy_ex(tmp_name, a->ifa_name, sizeof(tmp_name));
                    tmp_name[sizeof(tmp_name) - 1] = '\0';
                    ret = cb(tmp_name, &tmp, data);
                    break;
                }
                case AF_INET6:
                {
                    tmp.ss = *sa.ss;
                    strcpy_ex(tmp_name, a->ifa_name, sizeof(tmp_name));
                    tmp_name[sizeof(tmp_name) - 1] = '\0';
                    ret = cb(tmp_name, &tmp, data);
                    break;
                }
                default:
                {
                    ret = SUCCESS; // ignore
                    break;
                }
            }

            if(FAIL(ret))
            {
                break;
            }
        }

        freeifaddrs(ia);
    }
    else
    {
        ret = ERRNO_ERROR;
    }

    return ret;
}
#else
ya_result network_interfaces_forall(network_interfaces_forall_callback cb, void *data)
{
    static ULONG          families[] = {AF_INET, AF_INET6};
    size_t                n = 16;
    PIP_ADAPTER_ADDRESSES addresses = (PIP_ADAPTER_ADDRESSES)malloc(sizeof(PIP_ADAPTER_ADDRESSES) * n);
    if(addresses == NULL)
    {
        return ERROR;
    }

    for(int_fast32_t family_index = 0; family_index < 2; ++family_index)
    {
        ULONG addresses_bytesize = (ULONG)(n * sizeof(PIP_ADAPTER_ADDRESSES));
        DWORD ret = GetAdaptersAddresses(families[family_index], GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, addresses, &addresses_bytesize);

        if(ret == NO_ERROR)
        {
            PIP_ADAPTER_ADDRESSES address = addresses;
            while(address != NULL)
            {
                PIP_ADAPTER_UNICAST_ADDRESS unicast = address->FirstUnicastAddress;
                while(unicast != NULL)
                {

                    socketaddress_t sa;
                    if(unicast->Address.iSockaddrLength < sizeof(sa))
                    {
                        memcpy(&sa, unicast->Address.lpSockaddr, unicast->Address.iSockaddrLength);
                        ya_result ret = cb(address->AdapterName, &sa, data);
                        if(FAIL(ret))
                        {
                            free(addresses);
                            return ret;
                        }
                    }
                    unicast = unicast->Next;
                }
                address = address->Next;
            }
        }
        else if(ret == ERROR_BUFFER_OVERFLOW)
        {
            n *= 2;
            free(addresses);
            addresses = (PIP_ADAPTER_ADDRESSES)malloc(sizeof(PIP_ADAPTER_ADDRESSES) * n);
            if(addresses == NULL)
            {
                return ERROR;
            }
            --family_index;
        }
        else
        {
            free(addresses);
            return ERROR;
        }
    }

    free(addresses);

    return SUCCESS;
}
#endif

int sockaddr_compare_addr_port(const struct sockaddr *a, const struct sockaddr *b)
{
    int ret;
    ret = a->sa_family;
    ret -= b->sa_family;

    if(ret == 0)
    {
        switch(a->sa_family)
        {
            case AF_INET:
            {
                socketaddresscp_t saa;
                socketaddresscp_t sab;
                saa.sa = a;
                sab.sa = b;

                ret = saa.sa4->sin_port;
                ret -= sab.sa4->sin_port;

                if(ret == 0)
                {
                    ret = memcmp(&saa.sa4->sin_addr.s_addr, &sab.sa4->sin_addr.s_addr, 4);
                }
                break;
            }
            case AF_INET6:
            {
                socketaddresscp_t saa;
                socketaddresscp_t sab;
                saa.sa = a;
                sab.sa = b;

                ret = saa.sa6->sin6_port;
                ret -= sab.sa6->sin6_port;

                if(ret == 0)
                {
                    ret = memcmp(&saa.sa6->sin6_addr, &sab.sa6->sin6_addr, 16);
                }
                break;
            }
        }
    }

    return ret;
}

int socketaddress_compare_ip(const void *a, const void *b)
{
    const socketaddress_t *sa = (const socketaddress_t *)a;
    const socketaddress_t *sb = (const socketaddress_t *)b;

    if(sa != sb)
    {
        int ret = (int)sa->sa.sa_family - (int)sb->sa.sa_family;

        if(ret == 0)
        {
            switch(sa->sa.sa_family)
            {
                case AF_INET:
                    ret = memcmp(&sa->sa4.sin_addr, &sb->sa4.sin_addr, sizeof(sa->sa4.sin_addr));
                    break;
                case AF_INET6:
                    ret = memcmp(&sa->sa6.sin6_addr, &sb->sa6.sin6_addr, sizeof(sa->sa6.sin6_addr));
                    break;
                default:
                    ret = memcmp(sa, sb, sizeof(socketaddress_t));
                    break;
            }
        }

        return ret;
    }
    else
    {
        return 0;
    }
}

void socketaddress_copy(socketaddress_t *dst, const socketaddress_t *src)
{
    switch(src->sa.sa_family)
    {
        case AF_INET:
            memcpy(dst, src, sizeof(src->sa4));
            break;
        case AF_INET6:
            memcpy(dst, src, sizeof(src->sa6));
            break;
        default:
            memcpy(dst, src, sizeof(socketaddress_t));
            break;
    }
}

int sockaddr_storage_compare_ip(const void *key_a, const void *key_b)
{
    socketaddresscp_t ssap;
    ssap.sa = key_a;
    socketaddresscp_t ssbp;
    ssbp.sa = key_b;
    int d = *ssap.sa_family - *ssbp.sa_family;
    if(d == 0)
    {
        switch(*ssap.sa_family)
        {
            case AF_INET:
            {
                d = memcmp(&ssap.sa4->sin_addr, &ssbp.sa4->sin_addr, 4);
                break;
            }
            case AF_INET6:
            {
                d = memcmp(&ssap.sa6->sin6_addr, &ssbp.sa6->sin6_addr, 16);
                break;
            }
            default:
            {
                d = memcmp(ssap.ss, ssbp.ss, sizeof(socketaddress_t));
                break;
            }
        }
    }
    return d;
}

void sockaddr_storage_copy(struct sockaddr_storage *dest, const struct sockaddr_storage *src)
{
    switch(src->ss_family)
    {
        case AF_INET:
        {
            memcpy(dest, src, sizeof(struct sockaddr_in));
            break;
        }
        case AF_INET6:
        {
            memcpy(dest, src, sizeof(struct sockaddr_in6));
            break;
        }
        default:
        {
            memcpy(dest, src, sizeof(struct sockaddr_storage));
            break;
        }
    }
}

ya_result socketaddress_init_parse_with_port(socketaddress_t *sa, const char *text, int port)
{
    uint8_t   ip_buffer[16];
    ya_result ret = parse_ip_address(text, strlen(text), ip_buffer, sizeof(ip_buffer));
    if(ISOK(ret))
    {
        if(ret == 4)
        {
            sa->sa4.sin_family = AF_INET;
            sa->sa4.sin_port = htons(port);
            memcpy(&sa->sa4.sin_addr, ip_buffer, 4);
        }
        else // ret == 16
        {
            sa->sa6.sin6_family = AF_INET6;
            sa->sa6.sin6_port = htons(port);
            sa->sa6.sin6_flowinfo = 0;
            memcpy(&sa->sa6.sin6_addr, ip_buffer, 16);
            sa->sa6.sin6_scope_id = 0;
        }
    }
    return ret;
}

int socket_server(struct sockaddr *sa, socklen_t sa_len, int family, int listen_queue_size)
{
    ya_result        ret;
    int              sockfd;
    static const int on = 1;

    if(FAIL(sockfd = socket(sa->sa_family, family, 0)))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to create socket %{sockaddr}: %r", sa, ret);

        return ret;
    }

    /**
     * Associate the name of the interface to the socket
     */

    /**
     * This is distribution/system dependent. With this we ensure that IPv6 will only listen on IPv6 addresses.
     */

    if(sa->sa_family == AF_INET6)
    {
        if(FAIL(setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on))))
        {
            ret = ERRNO_ERROR;
            ttylog_err("failed to force IPv6 on %{sockaddr}: %r", sa, ret);
            close_ex(sockfd);
            return ret;
        }
    }

    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on))))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to reuse address %{sockaddr}: %r", sa, ret);
        close_ex(sockfd);
        return ret;
    }

    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on))))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to use reuse feature: %r", ret);
        close_ex(sockfd);
        return ret;
    }

    if(FAIL(bind(sockfd, sa, sa_len)))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to bind address %{sockaddr}: %r", sa, ret);
        close_ex(sockfd);
        return ret;
    }

    if(listen_queue_size <= 0)
    {
        listen_queue_size = 64;
    }

    if(family == SOCK_STREAM)
    {
        if(FAIL(listen(sockfd, listen_queue_size)))
        {
            ret = ERRNO_ERROR;
            ttylog_err("failed to listen to address %{sockaddr}: %r", sa, ret);
            close_ex(sockfd);
            return ret;
        }
    }

    return sockfd;
}

#if 0 && __linux__

int accept_ex(int sockfd, struct sockaddr *address, socklen_t *address_lenp)
{
#if DEBUG_ACCEPT_EX
    log_info("accept_ex(%i,%{sockaddr},%p)", sockfd, address, address_lenp);
#endif

    int epoll_id = epoll_create(1); // needs to be > 0

    struct epoll_event e_event;
    e_event.events = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
    e_event.data.fd = sockfd;
    epoll_ctl(epoll_id, EPOLL_CTL_ADD, sockfd, &e_event);

    fd_setnonblocking(sockfd);

    while(!dnscore_shuttingdown())
    {
        int n = epoll_wait(epoll_id, &e_event, 1, 5000);
        if(n > 0)
        {
#if DEBUG_ACCEPT_EX
            log_info("accept_ex(%i,%{sockaddr},%p) fd=%i events=%x", sockfd, address, address_lenp, e_event.data.fd, e_event.events);
#endif
            if((e_event.events & EPOLLIN) != 0)
            {
                int clientfd = accept(sockfd, address, address_lenp);
                log_info("accept_ex(%i,%{sockaddr},%p) fd=%i clientfd=%i", sockfd, address, address_lenp, e_event.data.fd, clientfd);
                fd_setblocking(sockfd);
                close_ex(epoll_id);
                return clientfd;
            }
            else if((e_event.events & (EPOLLHUP|EPOLLRDHUP)) != 0)
            {
#if DEBUG_ACCEPT_EX
                log_info("accept_ex(%i,%{sockaddr},%p) fd=%i close", sockfd, address, address_lenp, e_event.data.fd);
#endif
                //epoll_ctl(epoll_id, EPOLL_CTL_DEL, e_event.data.fd, NULL);
                fd_setblocking(sockfd);
                close_ex(epoll_id);
                return -1;
            }
            else
            {
#if DEBUG_ACCEPT_EX
                log_info("accept_ex(%i,%{sockaddr},%p) fd=%i unexpected", sockfd, address, address_lenp, e_event.data.fd);
#endif
            }
        }
    }

    fd_setblocking(sockfd);

    return -1;
}

#elif 0 && (__FreeBSD__ || __OpenBSD__)

#include <sys/event.h>

int accept_ex(int sockfd, struct sockaddr *address, socklen_t *address_lenp)
{
#if DEBUG_ACCEPT_EX
    log_info("accept_ex(%i,%{sockaddr},%p)", sockfd, address, address_lenp);
#endif

#define MONITOR_COUNT 2

    kevent monitor[MONITOR_COUNT];
    kevent event[MONITOR_COUNT];

    int    kq = kqueue();
    if(kq < 0)
    {
        return -1;
    }

    EV_SET(&monitor[0], sockfd, EVFILT_TIMER, EV_ADD | EV_ENABLE, 0, 5000, 0);
    EV_SET(&monitor[1], sockfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);

    while(!dnscore_shuttingdown())
    {
        int n = kevent(kq, &monitor[0], MONITOR_COUNT, &event, NULL);
        if(n > 0)
        {
            for(int_fast32_t i = 0; i < n; ++i)
            {
#if DEBUG_ACCEPT_EX
                log_info("accept_ex(%i,%{sockaddr},%p) fd=%i events=%x", sockfd, address, address_lenp, e_event.data.fd, e_event.events);
#endif

                if((e_event.events & EPOLLIN) != 0)
                {
                    int clientfd = accept(sockfd, address, address_lenp);
                    log_info("accept_ex(%i,%{sockaddr},%p) fd=%i clientfd=%i", sockfd, address, address_lenp, e_event.data.fd, clientfd);
                    fd_setblocking(sockfd);
                    close_ex(epoll_id);
                    return clientfd;
                }
                else if((e_event.events & (EPOLLHUP | EPOLLRDHUP)) != 0)
                {
#if DEBUG_ACCEPT_EX
                    log_info("accept_ex(%i,%{sockaddr},%p) fd=%i close", sockfd, address, address_lenp, e_event.data.fd);
#endif
                }

                close_ex(epoll_id);
                return -1;
            }
            else
            {
#if DEBUG_ACCEPT_EX
                log_info("accept_ex(%i,%{sockaddr},%p) fd=%i unexpected", sockfd, address, address_lenp, e_event.data.fd);
#endif
            }
        }
    }

    return -1;
}
#else

int accept_ex(int sockfd, struct sockaddr *address, socklen_t *address_lenp)
{
#if DEBUG_ACCEPT_EX
    log_info("accept_ex(%i,%{sockaddr},%p)", sockfd, address, address_lenp);
#endif

    tcp_set_recvtimeout(sockfd, 1, 0);

    while(!dnscore_shuttingdown())
    {
        int clientfd = accept_ex2(sockfd, address, address_lenp, 1000);
        if(clientfd >= 0)
        {
            return clientfd;
        }
        else
        {
            if(dnscore_shuttingdown())
            {
                return -1;
            }

            int err = ERRNO_ERROR_GET_ERRNO(clientfd);
            switch(err)
            {
                case EINTR:
                case EAGAIN:
                case ETIMEDOUT:
                    break;
                default:
                    return -1;
            }
        }
    }

    return -1;
}

int accept_ex2(int sockfd, struct sockaddr *address, socklen_t *address_lenp, int timeout_ms)
{
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;

    for(;;)
    {
        pfd.revents = 0;
        int ret = poll(&pfd, 1, timeout_ms);
        if(ret > 0)
        {
            for(;;)
            {
                int clientfd = accept(sockfd, address, address_lenp);

                if(clientfd >= 0)
                {
                    return clientfd;
                }
                else
                {
                    int err = errno;
                    if(err != EINTR)
                    {
                        return MAKE_ERRNO_ERROR(err);
                    }
                }
            }
        }
        else if(ret == 0)
        {
            errno = ETIMEDOUT;
            return MAKE_ERRNO_ERROR(ETIMEDOUT);
        }
        else
        {
            int err = errno;
            if(err != EINTR)
            {
                return MAKE_ERRNO_ERROR(err);
            }
        }
    } // loop
}

#endif

/** @} */
