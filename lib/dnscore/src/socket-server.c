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

/** @defgroup network
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#include <signal.h>

#include "dnscore/dnscore-config-features.h"

#if DNSCORE_HAVE_SYS_PRCTL_H
#if 0 /* fix */
#else
#define HAS_PR_SET_PDEATHSIG 0
#endif
#endif

#if HAS_PR_SET_PDEATHSIG
#include <sys/prctl.h>
#endif

#define SHUTDOWN_DETECT_BY_POLLING 0

#include "dnscore/socket-server.h"
#include "dnscore/format.h"
#include "dnscore/fdtools.h"
#include "dnscore/host_address.h"
#include "dnscore/mutex.h"
#include "dnscore/logger.h"
#include "dnscore/process.h"
#include "dnscore/thread.h"

/*
#if sizeof(socket_server_opensocket_s) < sizeof(struct socket_server_opensocket_noserver_s)
#error "socket_server_opensocket_s is smaller than socket_server_opensocket_noserver_s"
#endif
*/

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#define SOCKET_SERVER_OPERATION_ERROR_BEHAVIOUR_MASK 3
#define SOCKET_SERVER_OPERATION_ERROR_BEHAVIOUR_IGNORE 0
#define SOCKET_SERVER_OPERATION_ERROR_BEHAVIOUR_WARNING 1
#define SOCKET_SERVER_OPERATION_ERROR_BEHAVIOUR_ERROR 2 // will stop the socket creation

#ifndef WIN32

static pid_t socket_server_pid = 0;
static pid_t socket_server_parent_pid = 0;
static uid_t socket_server_parent_uid = 65535;
static int socket_server_pipe[2] = {-1, -1};
static int socket_server_sock[2] = {-1, -1};
static int socket_server_wire[2] = {-1, -1};

static group_mutex_t socket_server_mtx = GROUP_MUTEX_INITIALIZER;

static void socket_server_get_level_name(int level, char *out_buffer, size_t out_buffer_size)
{
    const char *text;
    switch(level)
    {
#ifdef IPPROTO_IP
        case IPPROTO_IP:
        {
            text = "IPPROTO_IP";
            break;
        }
#endif
#ifdef IPPROTO_IPV6
        case IPPROTO_IPV6:
        {
            text = "IPPROTO_IPV6";
            break;
        }
#endif
#ifdef SOL_SOCKET
        case SOL_SOCKET:
        {
            text = "SOL_SOCKET";
            break;
        }
#endif
        default:
            text = NULL;
            break;
    }
    if(text != NULL)
    {
        strncpy(out_buffer, text, out_buffer_size);
        out_buffer[out_buffer_size - 1] = '\0';
    }
    else
    {
        snformat(out_buffer, out_buffer_size, "%i", text);
    }
}

static void socket_server_get_optname_name(int level, int optname, char *out_buffer, size_t out_buffer_size)
{
    (void)level;
    const char *text;
    switch(optname)
    {
#ifdef IPV6_V6ONLY
        case IPV6_V6ONLY:
        {
            text = "IPV6_V6ONLY";
            break;
        }
#endif
#ifdef IP_RECVDSTADDR
        case IP_RECVDSTADDR:
        {
            text = "IP_RECVDSTADDR";
            break;
        }
#endif
#ifdef IPV6_PKTINFO
        case IPV6_PKTINFO:
        {
            text = "IPV6_PKTINFO";
            break;
        }
#endif
#ifdef IPV6_RECVPKTINFO
        case IPV6_RECVPKTINFO:
        {
            text = "IPV6_RECVPKTINFO";
            break;
        }
#endif
#ifdef SO_REUSEADDR
        case SO_REUSEADDR:
        {
            text = "SO_REUSEADDR";
            break;
        }
#endif
#ifdef SO_REUSEPORT
        case SO_REUSEPORT:
        {
            text = "SO_REUSEPORT";
            break;
        }
#endif
        default:
            text = NULL;
            break;
    }
    if(text != NULL)
    {
        strncpy(out_buffer, text, out_buffer_size);
        out_buffer[out_buffer_size - 1] = '\0';
    }
    else
    {
        snformat(out_buffer, out_buffer_size, "%i", text);
    }

}

static void socket_server_close_fd(int* fd)
{
    if((fd != NULL) && (*fd >= 0))
    {
        log_info("socket-server: closing fd %i", *fd);
        close_ex(*fd);
        *fd = -1;
    }
}

uid_t
socket_server_uid()
{
    return socket_server_parent_uid;
}

static void
socket_server_close_fds()
{
    // close
    socket_server_close_fd(&socket_server_pipe[0]); // R
    socket_server_close_fd(&socket_server_pipe[1]); // W

    socket_server_close_fd(&socket_server_sock[0]); // R
    socket_server_close_fd(&socket_server_sock[1]); // W

    socket_server_close_fd(&socket_server_wire[0]); // R
    socket_server_close_fd(&socket_server_wire[1]); // W
}

static ya_result socket_server_send_error(int fd, ya_result value)
{
    struct msghdr msg;
    struct iovec iov[1];
    
    log_warn("socket-server: answering with an error: socket %i: %r", fd, value);

    msg.msg_control = NULL;
    msg.msg_controllen = 0;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    iov[0].iov_base = &value;
    iov[0].iov_len = sizeof(value);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    
    ssize_t n;
    while((n = sendmsg(fd, &msg, 0)) < 0)
    {
        ya_result ret = errno;
        if(ret != EINTR)
        {
            ret = MAKE_ERRNO_ERROR(ret);
            
            log_err("socket-server: failed to answer with an error: socket %i: %r", fd, ret);
            
            return ret;
        }
    }
    return (ya_result)n;
}

static ya_result socket_server_send(int fd, int sockfd)
{
    struct msghdr msg;
    struct iovec iov[1];
    
    log_info("socket-server: answering: socket %i: %i", fd, sockfd);
    
    ya_result ret = 0;
    
    union
    {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int))]; /// @note 20170518 edf -- this OSX warning is said to be harmless
    } control_un;
    
    struct cmsghdr *cmptr;
    
    ZEROMEMORY(&msg, sizeof(msg));
    ZEROMEMORY(iov, sizeof(iov));
    ZEROMEMORY(&control_un, sizeof(control_un));
    
    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);
    
    cmptr = CMSG_FIRSTHDR(&msg);
    cmptr->cmsg_len = CMSG_LEN(sizeof(int));
    cmptr->cmsg_level = SOL_SOCKET;
    cmptr->cmsg_type = SCM_RIGHTS;
    int * const cmptr_sockfd_ptr = (int*)CMSG_DATA(cmptr);
    *cmptr_sockfd_ptr = sockfd;
    
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    iov[0].iov_base = &ret;
    iov[0].iov_len = sizeof(ret);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    
    ssize_t n;
    
    while((n = sendmsg(fd, &msg, 0)) < 0)
    {
        ya_result ret = errno;
        if(ret != EINTR)
        {
            ret = MAKE_ERRNO_ERROR(ret);
            
            log_err("socket-server: failed to answer: socket %i: %i: %r", fd, sockfd, ret);
            
            return ret;
        }
    }
    return (ya_result)n;
}

static ssize_t socket_server_recv(int fd, int *sockfdp)
{
    struct msghdr msg;
    struct iovec iov[1];
    ya_result ret = /**/ ERROR; // valid use of ERROR
    union
    {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr *cmptr;

    log_info("socket-server: receiving: socket %i", fd);
    
    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);
    
    cmptr = CMSG_FIRSTHDR(&msg);
    cmptr->cmsg_len = CMSG_LEN(sizeof(int));
    cmptr->cmsg_level = SOL_SOCKET;
    cmptr->cmsg_type = SCM_RIGHTS;
    
    int *data_to_set_to_zero = (int*)CMSG_DATA(cmptr);
    *data_to_set_to_zero = 0;
    
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    iov[0].iov_base = &ret;
    iov[0].iov_len = sizeof(ret);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    while(recvmsg(fd, &msg, 0) <= 0)
    {
        ya_result err = errno;
        if(err != EINTR)
        {
            err = MAKE_ERRNO_ERROR(err);
            
            log_err("socket-server: failed to receive: socket %i: %r", fd, ret);
            
            return err;
        }
    }
    
    if(
        ((cmptr = CMSG_FIRSTHDR(&msg)) != NULL)     &&
        (cmptr->cmsg_len == CMSG_LEN(sizeof(int)))
        )
    {
        if(cmptr->cmsg_level != SOL_SOCKET)
        {
            log_err("socket-server: receiving: socket %i: !SOL_SOCKET", fd);
            return ERROR;
        }
        if(cmptr->cmsg_type != SCM_RIGHTS)
        {
            log_err("socket-server: receiving: socket %i: !SCM_RIGHTS", fd);
            return ERROR;
        }
        
        int* cmsg_data = (int*)CMSG_DATA(cmptr);
        
        *sockfdp = *cmsg_data;
        
        log_info("socket-server: received: socket %i: %i", fd, *sockfdp);

        return ret;
    }
    else if((msg.msg_iovlen == 1) && (msg.msg_iov != NULL) && (msg.msg_iov->iov_len == sizeof(u32)) && (msg.msg_iov->iov_base != NULL))
    {
        ret = (s32)GET_U32_AT_P(msg.msg_iov->iov_base);
        *sockfdp = -1;
        return ret;
    }
    else
    {
        log_err("socket-server: receiving: socket %i: invalid message", fd);
        
        *sockfdp = -1;
        return ret;
    }
}

#if !SHUTDOWN_DETECT_BY_POLLING
static void*
socket_server_wire_thread(void* args)
{
    (void)args;
    static const char name[] = "wire";

    thread_set_name("wire", 0, 0);

#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_handle_set_thread_tag("wire");
#endif

    // will block when the pipe is full (4KB)
    // will trigger a SIGPIPE when every other parent is dead

    for(;;)
    {
        int n = write(socket_server_wire[1], name, sizeof(name));
        if(n < 0)
        {
            int err = errno;
            if(err == EPIPE)
            {
#if DNSCORE_HAS_LOG_THREAD_TAG
                logger_handle_clear_thread_tag();
#endif
                exit(0);
            }
        }
    }
}
#endif

static void
socket_server_server()
{
#if SHUTDOWN_DETECT_BY_POLLING
    struct  timeval timeout;
    fd_set rdset;
#endif
    u8 buffer_in[SERVER_CONTEXT_API_BUFFER_SIZE];

    thread_set_name("ynetsrv", 0, 0); // should NOT be named with "yadifa(d)*"

#if SHUTDOWN_DETECT_BY_POLLING
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
#endif

#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_handle_set_thread_tag("socksvr");
#endif

    log_info("socket-server: started");

#if DEBUG
    formatln("socket-server: started");
    flushout();
#endif

#if !SHUTDOWN_DETECT_BY_POLLING
    thread_t wire_thread = 0;

    if(thread_create(&wire_thread, socket_server_wire_thread, NULL) == 0)
    {
        log_info("socket-server: trip wire started");
#if DEBUG
        formatln("socket-server: trip wire started");
        flushout();
#endif
    }
    else
    {
        log_warn("socket-server: trip wire did not start: server may not stop without some help");
#if DEBUG
        formatln("socket-server: trip wire did not start: server may not stop without some help");
        flushout();
#endif
    }
#endif

    bool parent_ready = FALSE;

    for(;;)
    {
        ya_result ret = SUCCESS;
        // ai_family ai_addr ai_addrlen
        // count * (data_len, data)

#if SHUTDOWN_DETECT_BY_POLLING
        FD_ZERO(&rdset);
        FD_SET(socket_server_pipe[0], &rdset);

        int avail = select(socket_server_pipe[0] + 1, &rdset, NULL, NULL, &timeout);

        if(avail < 0)
        {
            log_err("socket-server: select failed with: %r", ERRNO_ERROR);
#if DEBUG
            formatln("socket-server: select failed with: %r", ERRNO_ERROR);
            flushout();
#endif
            break;
        }

        if(avail == 0)
        {
            if(getppid() == socket_server_parent_pid)
            {
                continue;
            }
            else
            {
                break;
            }
        }
#endif
        if(parent_ready)
        {
            log_info("socket-server: waiting for command");
        }
#if DEBUG
        formatln("socket-server: waiting for command");
        flushout();
#endif
        int n = read(socket_server_pipe[0], buffer_in, 1);

        if(!parent_ready)
        {
#if DEBUG
            formatln("socket-server: parent is not ready yet");
            flushout();
#endif
            logger_start();
#if DEBUG
            formatln("socket-server: logger started");
            flushout();
#endif
            logger_flush();
#if DEBUG
            formatln("socket-server: logger flushed");
            flushout();
#endif
            parent_ready = TRUE;
        }

        if(n < 0)
        {
            ret = ERRNO_ERROR;
#if DEBUG
            formatln("socket-server: read: header: %r", ret);
            flushout();
#endif
            log_err("socket-server: read: header: %r", ret);
            break;
        }
        
        if(n == 0)
        {
#if DEBUG
            formatln("socket-server: read: header: empty");
            flushout();
#endif
            log_err("socket-server: read: header: empty");
            break;
        }

        log_debug("socket-server: reading command message (%i bytes)", buffer_in[0]);
#if DEBUG
        formatln("socket-server: reading command message (%i bytes)", buffer_in[0]);
        flushout();
#endif
        if(FAIL(ret = readfully(socket_server_pipe[0], &buffer_in[1], buffer_in[0])))
        {
            ret = ERRNO_ERROR;
#if DEBUG
            formatln("socket-server: read: data: %r", ret);
            flushout();
#endif
            log_err("socket-server: read: data: %r", ret);
            break;
        }

        char level_buffer[32];
        char optname_buffer[32];

        // ai_family ai_addr ai_addrlen
        // count * (field1, field2, data_len, data[])
        u8 *p = &buffer_in[1];
        
        int sockopt_count = *p;
        ++p;
        
        int ai_family = GET_U32_AT_P(p);
        p += 4;
        
        int so_type = GET_U32_AT_P(p);
        p += 4;
        
        int so_proto = GET_U32_AT_P(p);
        p += 4;
        
        int ai_addrlen = GET_U32_AT_P(p);
        p += 4;
        
        socketaddress ai_addr;
        memcpy(&ai_addr, p, ai_addrlen);
        p += ai_addrlen;

#if DEBUG
        formatln("socket-server: sockaddr family %i %{sockaddr} (%i)  ai_addr.ss_family=%i",
                ai_family, &ai_addr, ai_addrlen, ai_addr.sa.sa_family);
        flushout();
#endif
#if DEBUG
        switch(ai_addr.sa.sa_family)
        {
            case AF_INET:
            {
#if DEBUG
                formatln("socket-server: sockaddr family %i %{sockaddr} (%i)  ai_addr.ss_family=%i v4 port=%i",
                        ai_family, &ai_addr, ai_addrlen, ai_addr.sa.sa_family, ai_addr.sa4.sin_port);
                flushout();
#endif
                if(ai_addr.sa4.sin_port == 0)
                {
                    ai_addr.sa.sa_family = AF_UNSPEC;
                }
                break;
            }
            case AF_INET6:
            {
#if DEBUG
                formatln("socket-server: sockaddr family %i %{sockaddr} (%i)  ai_addr.ss_family=%i v6 port=%i",
                        ai_family, &ai_addr, ai_addrlen, ai_addr.sa.sa_family, ai_addr.sa6.sin6_port);
                flushout();
#endif
                if(ai_addr.sa6.sin6_port == 0)
                {
                    ai_addr.sa.sa_family = AF_UNSPEC;
                }
                break;
            }
            default:
            {
                ai_addr.sa.sa_family = AF_UNSPEC;
                break;
            }
        }
#endif
        int sockfd;
        
#if DEBUG
        formatln("socket-server: socket(%i, %i, %i)", ai_family, so_type, so_proto);
        flushout();
#endif
        if(FAIL(sockfd = socket(ai_family, so_type, so_proto)))
        {
            ret = ERRNO_ERROR;
#if DEBUG
            formatln("socket-server: failed to socket(%i, %i, %i) for %{sockaddr}: %r", ai_family, so_type, so_proto, &ai_addr, ret);
            flushout();
#endif
            log_err("socket-server: socket: failed to socket(%i, %i, %i) for %{sockaddr}: %r", ai_family, so_type, so_proto, &ai_addr, ret);
            continue;
        }
        
        fd_setcloseonexec(sockfd);
        
        //HAVE_MSGHDR_MSG_CONTROL
                
        for(int i = 0; i < sockopt_count; ++i)
        {
            int operation = GET_U32_AT_P(p);
            p += sizeof(u32);

            int level = GET_U32_AT_P(p);
            p += sizeof(u32);
            
            int optname = GET_U32_AT_P(p);
            p += sizeof(u32);
            
            socklen_t optlen = GET_U32_AT_P(p);
            p += sizeof(u32);
            
            void *opt_val = p;
            p += optlen;

            socket_server_get_level_name(level, level_buffer, sizeof(level_buffer));
            socket_server_get_optname_name(level, optname, optname_buffer, sizeof(optname_buffer));
#if DEBUG
            formatln("socket-server: setsockopt(%i, %s, %s, %p, %i)", sockfd, level_buffer, optname_buffer, opt_val, optlen);
            flushout();
#endif
            if(FAIL(setsockopt(sockfd, level, optname, opt_val, optlen)))
            {
                ya_result setsockopt_ret = ERRNO_ERROR;

                if((operation & SOCKET_SERVER_OPERATION_ERROR_BEHAVIOUR_MASK) == SOCKET_SERVER_OPERATION_ERROR_BEHAVIOUR_WARNING)
                {
#if DEBUG
                    formatln("socket-server: setsockopt: failed to setsockopt(%i, %s, %s, %p, %i) for %{sockaddr}: %r",
                             sockfd, level_buffer, optname_buffer, opt_val, optlen, &ai_addr, setsockopt_ret);
                    flushout();
#endif
                    log_warn("socket-server: setsockopt: failed to setsockopt(%i, %s, %s, %p, %i) for %{sockaddr}: %r",
                            sockfd, level_buffer, optname_buffer, opt_val, optlen, &ai_addr, setsockopt_ret);
                }
                else if((operation & SOCKET_SERVER_OPERATION_ERROR_BEHAVIOUR_MASK) == SOCKET_SERVER_OPERATION_ERROR_BEHAVIOUR_ERROR)
                {
#if DEBUG
                    formatln("socket-server: setsockopt: failed to setsockopt(%i, %s, %s, %p, %i) for %{sockaddr}: %r",
                            sockfd, level_buffer, optname_buffer, opt_val, optlen, &ai_addr, setsockopt_ret);
                    flushout();
#endif
                    log_err("socket-server: setsockopt: failed to setsockopt(%i, %s, %s, %p, %i) for %{sockaddr}: %r",
                             sockfd, level_buffer, optname_buffer, opt_val, optlen, &ai_addr, setsockopt_ret);
                    socket_server_close_fd(&sockfd);
                    ret = setsockopt_ret;
                    break;
                }
            }
#if DEBUG
            formatln("socket-server: setsockopt(%i, %i, %i, %p, %i) success", sockfd, level, optname, opt_val, optlen);
#endif
        }
        
        if(ISOK(ret))
        {
#if DEBUG
            formatln("socket-server: bind(%i, %{sockadd}, %i)", sockfd, &ai_addr.sa, ai_addrlen);
            flushout();
#endif
            if(ISOK(bind(sockfd, &ai_addr.sa, ai_addrlen)))
            {
                // send the socket on its channel
#if DEBUG
                formatln("socket-server: sending %{sockaddr} on bound socked %i to the caller", &ai_addr, sockfd);
                flushout();
#endif
                log_info("socket-server: sending %{sockaddr} on bound socked %i to the caller", &ai_addr, sockfd);
        
                if(FAIL(ret = socket_server_send(socket_server_sock[1], sockfd)))
                {
#if DEBUG
                    formatln("socket-server: failed to send %{sockaddr} on bound socked %i to the caller: %r", &ai_addr, sockfd, ret);
                    flushout();
#endif
                    log_err("socket-server: failed to send %{sockaddr} on bound socked %i to the caller: %r", &ai_addr, sockfd, ret);
                }

                socket_server_close_fd(&sockfd);
            }
            else
            {
                ret = ERRNO_ERROR;
#if DEBUG
                formatln("bind: failed to bind(%i, %{sockaddr}, %i) for %{sockaddr}: %r",
                        sockfd, &ai_addr.sa, ai_addrlen, &ai_addr, ret);
                flushout();
#endif
                // log_warn("socket-server: socket server can only serve privileged ports if the uid is 0");
                
                log_err("socket-server: bind: failed to bind(%i, %{sockaddr}, %i) for %{sockaddr}: %r",
                        sockfd, &ai_addr.sa, ai_addrlen, &ai_addr, ret);

                socket_server_close_fd(&sockfd);
                
                socket_server_send_error(socket_server_sock[1], ret);
            }
        }
        else
        {
#if DEBUG
            formatln("socket-server: setsockopt(%i, ...) failed: %r", sockfd, ret);
#endif
        }
    }

#if DEBUG
    formatln("socket-server: stopped");
    flushout();
#endif

    log_info("socket-server: stopped");

    socket_server_close_fd(&socket_server_pipe[0]);

#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_handle_clear_thread_tag();
#endif

    dnscore_finalize();
    
    exit(0);
}

#else // WIN32
//
#endif

/**
 * 
 * 
 * @param ctx the struct to initialise
 * @param addr the address
 * @param sock_type e.g.: SOCK_STREAM, SOCK_DGRAM, ...
 */

ya_result
socket_server_opensocket_init(socket_server_opensocket_s *ctx, struct addrinfo *addr, int sock_type)
{
    switch(addr->ai_family)
    {
        case AF_INET:
        {
            struct sockaddr_in* sa4 = (struct sockaddr_in*)addr->ai_addr;
            if(sa4->sin_port == 0)
            {
                return INVALID_ARGUMENT_ERROR;
            }
            break;
        }
        case AF_INET6:
        {
            struct sockaddr_in6* sa6 = (struct sockaddr_in6*)addr->ai_addr;
            if(sa6->sin6_port == 0)
            {
                return INVALID_ARGUMENT_ERROR;;
            }
            break;
        }
        default:
        {
            return INVALID_ARGUMENT_ERROR;;
        }
    }

#ifndef WIN32
    if(socket_server_pid != 0)
    {
        u8 *p = ctx->buffer_out;
    
#if DEBUG
        memset(p, 0x5a, sizeof(ctx->buffer_out));
#endif
    
        *p = 0xff;        // reserved for message size
        ++p;
        *p = 0;           // reserved for message size
        ++p;

        SET_U32_AT_P(p, addr->ai_family);
        p += sizeof(u32);

        SET_U32_AT_P(p, sock_type);
        p += sizeof(u32);

        SET_U32_AT_P(p, 0);
        p += sizeof(u32);

        SET_U32_AT_P(p, addr->ai_addrlen);
        p += sizeof(u32);

        memcpy(p, addr->ai_addr, addr->ai_addrlen);
        p += addr->ai_addrlen;

        ctx->p = p;
    }
    else
#endif // WIN32
    {
        struct socket_server_opensocket_noserver_s* alt = (struct socket_server_opensocket_noserver_s*)ctx;
        alt->sockfd = socket(addr->ai_family, sock_type, 0);
        
        // fcntl(alt->sockfd, F_SETFD, FD_CLOEXEC);
        
        alt->error = (alt->sockfd >= 0)?0:ERRNO_ERROR;
        alt->family = sock_type;
        alt->addr = *addr;
        memcpy(&alt->ss, addr->ai_addr, addr->ai_addrlen);
        alt->addr.ai_addr = &alt->ss.sa;
    }

    return SUCCESS;
}

void socket_server_opensocket_setopt(socket_server_opensocket_s *ctx, int level, int optname, const void* opt, socklen_t optlen)
{
#ifndef WIN32
    if(socket_server_pid != 0)
    {
        u8 *p = ctx->p;

        assert((size_t)(&ctx->buffer_out[sizeof(ctx->buffer_out)] - p) >= (sizeof(u32) + sizeof(u32) + sizeof(u32) + optlen));

        ++ctx->buffer_out[1];

        SET_U32_AT_P(p, SOCKET_SERVER_OPERATION_ERROR_BEHAVIOUR_ERROR);     // operation is mandatory
        p += sizeof(u32);

        SET_U32_AT_P(p, level);
        p += sizeof(u32);

        SET_U32_AT_P(p, optname);
        p += sizeof(u32);

        SET_U32_AT_P(p, optlen);
        p += sizeof(u32);

        memcpy(p, opt, optlen);
        p += optlen;

        ctx->p = p;
    }
    else
#endif
    {
        struct socket_server_opensocket_noserver_s* alt = (struct socket_server_opensocket_noserver_s*)ctx;
        if(ISOK(alt->error))
        {
            if(setsockopt(alt->sockfd, level, optname, opt, optlen) < 0)
            {
                alt->error = ERRNO_ERROR;

                char level_buffer[32];
                char optname_buffer[32];
                socket_server_get_level_name(level, level_buffer, sizeof(level_buffer));
                socket_server_get_optname_name(level, optname, optname_buffer, sizeof(optname_buffer));
                log_err("socket-server: setsockopt: failed to setsockopt(%i, %s, %s, %p, %i): %r",
                         alt->sockfd, level_buffer, optname_buffer, opt, optlen, alt->error);
                close_ex(alt->sockfd);
                alt->sockfd = -1;
            }
        }
    }
}

void socket_server_opensocket_setopt_ignore_result(socket_server_opensocket_s *ctx, int level, int optname, const void* opt, socklen_t optlen)
{
#ifndef WIN32
    if(socket_server_pid != 0)
    {
        u8 *p = ctx->p;

        assert((size_t)(&ctx->buffer_out[sizeof(ctx->buffer_out)] - p) >= (sizeof(u32) + sizeof(u32) + sizeof(u32) + optlen));

        ++ctx->buffer_out[1];

        SET_U32_AT_P(p, SOCKET_SERVER_OPERATION_ERROR_BEHAVIOUR_IGNORE);     // operation failure will only log a warning
        p += sizeof(u32);

        SET_U32_AT_P(p, level);
        p += sizeof(u32);

        SET_U32_AT_P(p, optname);
        p += sizeof(u32);

        SET_U32_AT_P(p, optlen);
        p += sizeof(u32);

        memcpy(p, opt, optlen);
        p += optlen;

        ctx->p = p;
    }
    else
#endif
    {
        struct socket_server_opensocket_noserver_s* alt = (struct socket_server_opensocket_noserver_s*)ctx;
        if(ISOK(alt->error))
        {
            if(setsockopt(alt->sockfd, level, optname, opt, optlen) < 0)
            {
                alt->error = ERRNO_ERROR;

                char level_buffer[32];
                char optname_buffer[32];
                socket_server_get_level_name(level, level_buffer, sizeof(level_buffer));
                socket_server_get_optname_name(level, optname, optname_buffer, sizeof(optname_buffer));

                log_warn("socket-server: setsockopt: failed to setsockopt(%i, %s, %s, %p, %i): %r",
                         alt->sockfd, level_buffer, optname_buffer, opt, optlen, alt->error);
            }
        }
    }
}

void socket_server_opensocket_setopt_ignore_error(socket_server_opensocket_s *ctx, int level, int optname, const void* opt, socklen_t optlen)
{
#ifndef WIN32
    if(socket_server_pid != 0)
    {
        u8 *p = ctx->p;

        assert((size_t)(&ctx->buffer_out[sizeof(ctx->buffer_out)] - p) >= (sizeof(u32) + sizeof(u32) + sizeof(u32) + optlen));

        ++ctx->buffer_out[1];

        SET_U32_AT_P(p, SOCKET_SERVER_OPERATION_ERROR_BEHAVIOUR_WARNING);     // operation failure will only log a warning
        p += sizeof(u32);

        SET_U32_AT_P(p, level);
        p += sizeof(u32);

        SET_U32_AT_P(p, optname);
        p += sizeof(u32);

        SET_U32_AT_P(p, optlen);
        p += sizeof(u32);

        memcpy(p, opt, optlen);
        p += optlen;

        ctx->p = p;
    }
    else
#endif
    {
        struct socket_server_opensocket_noserver_s* alt = (struct socket_server_opensocket_noserver_s*)ctx;
        if(ISOK(alt->error))
        {
            if(setsockopt(alt->sockfd, level, optname, opt, optlen) < 0)
            {
                alt->error = ERRNO_ERROR;

                char level_buffer[32];
                char optname_buffer[32];
                socket_server_get_level_name(level, level_buffer, sizeof(level_buffer));
                socket_server_get_optname_name(level, optname, optname_buffer, sizeof(optname_buffer));

                log_warn("socket-server: setsockopt: failed to setsockopt(%i, %s, %s, %p, %i): %r",
                         alt->sockfd, level_buffer, optname_buffer, opt, optlen, alt->error);
            }
        }
    }
}

/**
 * Opens the socket and returns its file descriptor or an error code.
 * 
 * @param ctx
 * 
 * @return the file descriptor or an error code
 */

int socket_server_opensocket_open(socket_server_opensocket_s *ctx)
{
#ifndef WIN32
    if(socket_server_pid != 0) // the socket server is up
    {

        group_mutex_lock(&socket_server_mtx, GROUP_MUTEX_WRITE);
                
        ctx->buffer_out[0] = ctx->p - &ctx->buffer_out[1];

        ssize_t written = writefully(socket_server_pipe[1], ctx->buffer_out, ctx->p - ctx->buffer_out);
        if(ISOK(written))
        {
#if DEBUG
            log_info("socket_server_opensocket_open(%i) = %lli", socket_server_pipe[1], written);
#endif
        }
        else
        {
            ya_result ret = (ya_result)written;
            group_mutex_unlock(&socket_server_mtx, GROUP_MUTEX_WRITE);
            log_err("socket_server_opensocket_open(%i) = %r", socket_server_pipe[1], ret);
            return ret;
        }

        int sockfd = -2;

        ya_result ret = socket_server_recv(socket_server_sock[0], &sockfd);

        group_mutex_unlock(&socket_server_mtx, GROUP_MUTEX_WRITE);

        if(ISOK(ret))
        {
#if DEBUG
            log_info("socket_server_opensocket_open(%i, *%p = %i) = %i", socket_server_sock[0], &sockfd, sockfd, ret);
#endif
            ret = sockfd;
        }
        else
        {
            log_err("socket_server_opensocket_open(%i, *%p = %i) = %r", socket_server_sock[0], &sockfd, sockfd, ret);
        }
        
        return ret;
    }
    else
#endif // WIN32
    {
        struct socket_server_opensocket_noserver_s* alt = (struct socket_server_opensocket_noserver_s*)ctx;
        ya_result ret = alt->error;
        
        if(ISOK(ret))
        {
            if(bind(alt->sockfd, alt->addr.ai_addr, alt->addr.ai_addrlen) >= 0)
            {
                ret = alt->sockfd;
#if DEBUG
                log_info("socket_server_opensocket_open(*%p = %i) = %i", &alt->sockfd, alt->sockfd, ret);
#endif
            }
            else
            {
                alt->error = ERRNO_ERROR;
                close_ex(alt->sockfd);
                alt->sockfd = -1;
                ret = alt->error;
                log_err("socket_server_opensocket_open(*%p = %i) = %i", &alt->sockfd, alt->sockfd, alt->error);
            }
        }
        
        return ret;
    }
}

ya_result
socket_server_finalize()
{
#ifndef WIN32
    if(socket_server_pid != 0)
    {
        // send stop command

        socket_server_close_fds();

        //
        kill(socket_server_pid, SIGTERM);
        // forget
        socket_server_pid = 0;
        
        return SUCCESS;
    }
    
    return ERROR;
#else // WIN32
    return SUCCESS;
#endif
}

ya_result
socket_server_init(int argc, char **argv)
{
    log_info("socket-server: init");
#ifndef WIN32
    if(socket_server_parent_pid != 0)
    {
        log_err("socket-server: already initialised");
        return ERROR;
    }

    if(getuid() != 0)
    {
#if DEBUG
        printf("warning: socket server can only serve privileged ports if the uid is 0\n");
#endif
    }

    if(socket_server_pid != 0)
    {
        log_warn("socket-server: socket server appears to be already running");
        return ERROR;   // black magic already running
    }
    
    if(pipe(socket_server_pipe) < 0)
    {
        ya_result ret = ERRNO_ERROR;
        log_err("socket-server: could not create pipe: %r", ret);
        return ret;   // could not create ipc
    }
    
    fd_setcloseonexec(socket_server_pipe[0]);
    fd_setcloseonexec(socket_server_pipe[1]);
    
    if(socketpair(AF_LOCAL, SOCK_STREAM, 0, socket_server_sock) < 0)
    {
        ya_result ret = ERRNO_ERROR;
        
        log_err("socket-server: failed to create socketpair: %r", ret);

        socket_server_close_fds();
        
        return ret;
    }

    fd_setcloseonexec(socket_server_sock[0]);
    fd_setcloseonexec(socket_server_sock[1]);

    if(pipe(socket_server_wire) < 0)
    {
        ya_result ret = ERRNO_ERROR;
        log_err("socket-server: could not create pipe: %r", ret);

        socket_server_close_fds();

        return ret;   // could not create wire pipe
    }

    socket_server_parent_pid = getpid();

    socket_server_parent_uid = getuid();
    
    pid_t pid = fork_ex();
    
    if(pid < 0)
    {
        ya_result ret = ERRNO_ERROR;
        
        log_err("socket-server: could not fork: %r", ret);

        socket_server_close_fds();

        socket_server_parent_pid = 0;
        
        return ret;   // could not fork
    }
        
    if(pid == 0)
    {
        FILE *f;

        //MODULE_MSG_HANDLE = LOGGER_HANDLE_SINK;
        socket_server_pipe[1] = -1;
        
        f = freopen("/dev/null", "r", stdin);

        if(f == NULL)
        {
            exit(EXIT_FAILURE);
        }

#if !DEBUG
        f = freopen("/dev/null", "a", stdout);

        if(f == NULL)
        {
            exit(EXIT_FAILURE);
        }

        f = freopen("/dev/null", "a", stderr);

        if(f == NULL)
        {
            exit(EXIT_FAILURE);
        }
#else
        f = freopen("/tmp/yadifa-socket-server.out", "a", stdout);

        if(f == NULL)
        {
            if((/*f = */freopen("/dev/null", "a", stdout)) == NULL)
            {
                exit(EXIT_FAILURE);
            }
        }

        f = freopen("/tmp/yadifa-socket-server.err", "a", stderr);

        if(f == NULL)
        {
            if((/*f = */freopen("/dev/null", "a", stderr)) == NULL)
            {
                exit(EXIT_FAILURE);
            }
        }

#if __FreeBSD__
        fprintf(stdout, "FreeBSD: stdout reopened (%i)\n", getpid_ex());
        fprintf(stderr, "FreeBSD: stderr reopened (%i)\n", getpid_ex());
        fflush(NULL);
#endif

#endif

        socket_server_close_fd(&socket_server_pipe[1]);
        socket_server_close_fd(&socket_server_sock[0]);
        socket_server_close_fd(&socket_server_wire[0]);
        
        signal(SIGPIPE, SIG_DFL);

#if HAS_PR_SET_PDEATHSIG
        // linux-only code that avoids the need for polling

        prctl(PR_SET_PDEATHSIG, SIGINT);
#endif

        if((argc > 0) && (argv != NULL))
        {
            // replace the program name
            size_t argv0_len = strlen(argv[0]); // returns the size of the storage of the string, minus 1.
            strncpy(argv[0], "network", argv0_len); // not strncpy in this case

            // erase all parameters
            for(int i = 1; i < argc; ++i)
            {
                memset(argv[i], 0, strlen(argv[i]));
            }
        }

        socket_server_server();
        
        // NEVER REACHED
        
        abort(); // should never be called
    }
    else
    {
        socket_server_close_fd(&socket_server_pipe[0]);
        socket_server_close_fd(&socket_server_sock[1]);
        socket_server_close_fd(&socket_server_wire[1]);

        socket_server_pid = pid;
        socket_server_pipe[0] = -1;
    }
#else // WIN32
#endif

    return 1;
}

/** @} */
