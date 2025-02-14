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
 * @defgroup test
 * @ingroup test
 * @brief skeleton file
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * skeleton test program, will not be installed with a "make install"
 *
 * To create a new test based on the skeleton:
 *
 * _ copy the folder
 * _ replace "skeleton" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 * _ add the test to the CMakeLists.txt from the tests directory
 *
 *----------------------------------------------------------------------------*/

#define _GNU_SOURCE 1

#include <dnscore/dnscore.h>
#include <dnscore/host_address.h>
#include <dnscore/config_settings.h>
#include <dnscore/cmdline.h>
#include <dnscore/config_cmdline.h>
#include <dnscore/format.h>
#include <dnscore/dns_message.h>
#include <dnscore/signals.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/thread_pool.h>

#include <sys/socket.h>
#include "dnscore/server_setup.h"

#ifndef MSG_WAITFORONE
#pragma message("MSG_WAITFORONE not defined, this will probably not work.")
#define MSG_WAITFORONE 0
#endif

#if __windows__
#include <malloc.h>
static inline void *aligned_alloc(size_t alignment, size_t size) { return _aligned_malloc(size, alignment); }
#endif

#define SERVER_MM_PACKETS_AT_ONCE 128

#define MAIN_SETTINGS_NAME        "main"
#define VERSION                   "0.0.1"

#define NETTHCTX_TAG              0x585443485454454e

struct main_settings_s
{
    host_address_t *listen;
    uint32_t        workers;
    uint32_t        packets_at_once;
    uint32_t        mode;
    bool            daemon;
};

typedef struct main_settings_s main_settings_t;

#define CONFIG_TYPE main_settings_t
CONFIG_BEGIN(main_settings_desc)
CONFIG_HOST_LIST_EX(listen, "127.0.0.1 port 15353", CONFIG_HOST_LIST_FLAGS_DEFAULT, 1)
CONFIG_U32_RANGE(workers, "1", 1, 64)
CONFIG_U32_RANGE(packets_at_once, "128", 1, 1024)
CONFIG_U32_RANGE(mode, "0", 0, 3)
CONFIG_BOOL(daemon, "0")
CONFIG_END(main_settings_desc)
#undef CONFIG_TYPE

CMDLINE_BEGIN(main_settings_cmdline)
// main
CMDLINE_SECTION(MAIN_SETTINGS_NAME)
CMDLINE_OPT("listen", 'l', "listen")
CMDLINE_HELP("", "the address to listen to (default: '127.0.0.1 port 15353')")
CMDLINE_OPT("workers", 'w', "workers")
CMDLINE_HELP("", "the number of threads listening to the network (default: 1)")
CMDLINE_BOOL("daemon", 'd', "daemon")
CMDLINE_HELP("", "detach from console and run in the background")
CMDLINE_OPT("packets-at-once", 'p', "packets_at_once")
CMDLINE_HELP("", "how many packets can be read or written in a single system call (default: 128)")
CMDLINE_OPT("mode", 'm', "mode")
CMDLINE_HELP("", "0: send-retry, 1: send-noretry, 2: send-retry-lock, 3: send-retry-twolocks")
CMDLINE_MSG("", "")
CMDLINE_VERSION_HELP(main_settings_cmdline)
CMDLINE_END(main_settings_cmdline)

/*
int buffer = 4000000;
setsockopt(s, SOL_SOCKET, SO_SNDBUF, buffer, sizeof(buffer));
setsockopt(s, SOL_SOCKET, SO_RCVBUF, buffer, sizeof(buffer));
 */

static main_settings_t g_main_settings;

static group_mutex_t   db_mtx;

struct zone_s
{
    group_mutex_t mtx;
};

typedef struct zone_s zone_t;

static zone_t        *db_zone = NULL;

static ya_result      main_config(int argc, char *argv[])
{
    config_error_t cfgerr;
    ya_result      ret;

    config_init();

    int priority = 0;

    config_register_struct(MAIN_SETTINGS_NAME, main_settings_desc, &g_main_settings, priority++);

    config_register_cmdline(priority++); // without this line, the help will not work

    struct config_source_s sources[1];

    if(FAIL(ret = config_source_set_commandline(&sources[0], main_settings_cmdline, argc, argv)))
    {
        formatln("command line definition: %r", ret);
        return ret;
    }

    config_error_init(&cfgerr);

    if(FAIL(ret = config_read_from_sources(sources, 1, &cfgerr)))
    {
        formatln("settings: (%s:%i) %s: %r", cfgerr.file, cfgerr.line_number, cfgerr.line, ret);
        flushout();
        config_error_finalise(&cfgerr);
        return ret;
    }

    config_error_finalise(&cfgerr);

    if(cmdline_version_get())
    {
        println("\nversion: " VERSION "\n");
        return SUCCESS;
    }

    if(cmdline_help_get())
    {
        formatln("\nUsage:\n\n    %s [options]\n\nOptions:\n", argv[0]);
        cmdline_print_help(main_settings_cmdline, termout);
        formatln("");
        return SUCCESS;
    }

    formatln("listen: %{hostaddr} workers: %u packets: %u mode: %u daemon: %u", g_main_settings.listen, g_main_settings.workers, g_main_settings.packets_at_once, g_main_settings.mode, g_main_settings.daemon);

    return 1;
}

static void echo_server_retry_dbzonelock(int id, zone_t *zone)
{
    socketaddress_t sa;
    host_address2sockaddr(g_main_settings.listen, &sa);

    thread_setaffinity(thread_self(), id);

    int sockfd = -1;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if(sockfd < 0)
    {
        formatln("socket failed: %r", ERRNO_ERROR);
        return;
    }

    int on = 1;
    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on))))
    {
        formatln("setsockopt SO_REUSEADDR failed: %r", ERRNO_ERROR);
        socketclose_ex(sockfd);
        return;
    }
#ifdef SO_REUSEPORT
    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on))))
    {
        formatln("setsockopt SO_REUSEPORT failed: %r", ERRNO_ERROR);
        socketclose_ex(sockfd);
        return;
    }
#endif

    if(bind(sockfd, &sa.sa, socketaddress_len(&sa)) < 0)
    {
        formatln("bind failed: %r", ERRNO_ERROR);
        socketclose_ex(sockfd);
        return;
    }

    dns_message_t **messages;

    struct mmsghdr *udp_packets = NULL;
    struct mmsghdr *udp_packets_send = NULL;
    unsigned int    udp_packets_count = g_main_settings.packets_at_once;

    formatln("thread %p batch-size is %u", thread_self(), udp_packets_count);

    const size_t packet_size = 4096;

    uint8_t     *packet_buffers = aligned_alloc(4096, udp_packets_count * packet_size);
#if DNS_MESSAGE_HAS_POOL
    uint8_t *pool_buffers = aligned_alloc(4096, udp_packets_count * packet_size);
#endif

    MALLOC_OBJECT_ARRAY_OR_DIE(messages, dns_message_t *, udp_packets_count, SMMMSGS_TAG);
    MALLOC_OBJECT_ARRAY_OR_DIE(udp_packets, struct mmsghdr, udp_packets_count, MMSGHDR_TAG);
    // MALLOC_OBJECT_ARRAY_OR_DIE(udp_packets_send, struct mmsghdr, udp_packets_count, MMSGHDR_TAG);

    struct timespec recv_timeout = {1, 0};

    for(uint_fast32_t i = 0; i < udp_packets_count; ++i)
    {
        messages[i] = dns_message_new_instance_ex(&packet_buffers[packet_size * i], packet_size);
#if DNS_MESSAGE_HAS_POOL
        dns_message_set_pool_buffer(messages[i], &pool_buffers[packet_size * i], packet_size);
#endif
        dns_message_reset_control(messages[i]);
        dns_message_copy_msghdr(messages[i], &udp_packets[i].msg_hdr);
        udp_packets[i].msg_len = 0;
    }

    formatln("thread %p echoing", thread_self());

    while(!dnscore_shuttingdown())
    {
        int recvmmsg_ret = recvmmsg(sockfd, udp_packets, udp_packets_count, MSG_WAITFORONE, &recv_timeout);

        if(recvmmsg_ret > 0)
        {
            group_mutex_read_lock(&db_mtx);
            group_mutex_read_lock(&zone->mtx);

            for(int_fast32_t i = 0; i < recvmmsg_ret; ++i)
            {
                udp_packets[i].msg_hdr.msg_iov[0].iov_len = udp_packets[i].msg_len;
            }

            int n = recvmmsg_ret;

            udp_packets_send = udp_packets;

            group_mutex_read_unlock(&zone->mtx);
            group_mutex_read_unlock(&db_mtx);

            do
            {
                int sendmmsg_ret = sendmmsg(sockfd, udp_packets_send, n, 0);
                if(sendmmsg_ret >= 0)
                {
                    n -= sendmmsg_ret;
                    udp_packets_send += sendmmsg_ret;
                }
                else
                {
                    // nothing has been sent
                }
            } while(n > 0);

            for(int_fast32_t i = 0; i < recvmmsg_ret; ++i)
            {
                udp_packets[i].msg_hdr.msg_iov[0].iov_len = dns_message_get_buffer_size_max(messages[i]);
            }

            /*
            for(uint_fast32_t i = 0; i < n; ++i)
            {
                dns_message_reset_control(messages[i]);
                dns_message_copy_msghdr(messages[i], &udp_packets[i].msg_hdr);
            }
            */
        }
        else
        {
            int err = errno;
            switch(err)
            {
                case EBADF:
                case ECONNRESET:
                case EINVAL:
                case EMSGSIZE:
                case ENOTSOCK:
                {
                    dnscore_shutdown();
                    break;
                }
                default:
                {
                    break;
                }
            }
        }
    }

    formatln("thread %p stopping", thread_self());
    flushout();
    socketclose_ex(sockfd);
#if DNS_MESSAGE_HAS_POOL
    formatln("thread %p free pool_buffers", thread_self());
    flushout();
    free(pool_buffers);
#endif
    formatln("thread %p free packet_buffers", thread_self());
    flushout();
    free(packet_buffers);
    // formatln("thread %p free udp_packets_send", thread_self());flushout();
    // free(udp_packets_send);
    formatln("thread %p free udp_packets", thread_self());
    flushout();
    free(udp_packets);
    formatln("thread %p free messages", thread_self());
    flushout();
    free(messages);
    formatln("thread %p terminated", thread_self());
    flushout();
}

static void echo_server_retry_zonelock(int id, zone_t *zone)
{
    socketaddress_t sa;
    host_address2sockaddr(g_main_settings.listen, &sa);

    thread_setaffinity(thread_self(), id);

    int sockfd = -1;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if(sockfd < 0)
    {
        formatln("socket failed: %r", ERRNO_ERROR);
        return;
    }

    int on = 1;
    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on))))
    {
        formatln("setsockopt SO_REUSEADDR failed: %r", ERRNO_ERROR);
        socketclose_ex(sockfd);
        return;
    }
#ifdef SO_REUSEPORT
    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on))))
    {
        formatln("setsockopt SO_REUSEPORT failed: %r", ERRNO_ERROR);
        socketclose_ex(sockfd);
        return;
    }
#endif

    if(bind(sockfd, &sa.sa, socketaddress_len(&sa)) < 0)
    {
        formatln("bind failed: %r", ERRNO_ERROR);
        socketclose_ex(sockfd);
        return;
    }

    dns_message_t **messages;

    struct mmsghdr *udp_packets = NULL;
    struct mmsghdr *udp_packets_send = NULL;
    unsigned int    udp_packets_count = g_main_settings.packets_at_once;

    formatln("thread %p batch-size is %u", thread_self(), udp_packets_count);

    const size_t packet_size = 4096;

    uint8_t     *packet_buffers = aligned_alloc(4096, udp_packets_count * packet_size);
#if DNS_MESSAGE_HAS_POOL
    uint8_t *pool_buffers = aligned_alloc(4096, udp_packets_count * packet_size);
#endif

    MALLOC_OBJECT_ARRAY_OR_DIE(messages, dns_message_t *, udp_packets_count, SMMMSGS_TAG);
    MALLOC_OBJECT_ARRAY_OR_DIE(udp_packets, struct mmsghdr, udp_packets_count, MMSGHDR_TAG);
    // MALLOC_OBJECT_ARRAY_OR_DIE(udp_packets_send, struct mmsghdr, udp_packets_count, MMSGHDR_TAG);

    struct timespec recv_timeout = {1, 0};

    for(uint_fast32_t i = 0; i < udp_packets_count; ++i)
    {
        messages[i] = dns_message_new_instance_ex(&packet_buffers[packet_size * i], packet_size);
#if DNS_MESSAGE_HAS_POOL
        dns_message_set_pool_buffer(messages[i], &pool_buffers[packet_size * i], packet_size);
#endif
        dns_message_reset_control(messages[i]);
        dns_message_copy_msghdr(messages[i], &udp_packets[i].msg_hdr);
        udp_packets[i].msg_len = 0;
    }

    formatln("thread %p echoing", thread_self());

    while(!dnscore_shuttingdown())
    {
        int recvmmsg_ret = recvmmsg(sockfd, udp_packets, udp_packets_count, MSG_WAITFORONE, &recv_timeout);
        if(recvmmsg_ret > 0)
        {
            group_mutex_read_lock(&zone->mtx);

            for(int_fast32_t i = 0; i < recvmmsg_ret; ++i)
            {
                udp_packets[i].msg_hdr.msg_iov[0].iov_len = udp_packets[i].msg_len;
            }

            int n = recvmmsg_ret;

            udp_packets_send = udp_packets;

            group_mutex_read_unlock(&zone->mtx);

            do
            {
                int sendmmsg_ret = sendmmsg(sockfd, udp_packets_send, n, 0);
                if(sendmmsg_ret >= 0)
                {
                    n -= sendmmsg_ret;
                    udp_packets_send += sendmmsg_ret;
                }
                else
                {
                    // nothing has been sent
                }
            } while(n > 0);

            for(int_fast32_t i = 0; i < recvmmsg_ret; ++i)
            {
                udp_packets[i].msg_hdr.msg_iov[0].iov_len = dns_message_get_buffer_size_max(messages[i]);
            }

            /*
            for(uint_fast32_t i = 0; i < n; ++i)
            {
                dns_message_reset_control(messages[i]);
                dns_message_copy_msghdr(messages[i], &udp_packets[i].msg_hdr);
            }
            */
        }
        else
        {
            int err = errno;
            switch(err)
            {
                case EBADF:
                case ECONNRESET:
                case EINVAL:
                case EMSGSIZE:
                case ENOTSOCK:
                {
                    dnscore_shutdown();
                    break;
                }
                default:
                {
                    break;
                }
            }
        }
    }

    formatln("thread %p stopping", thread_self());
    flushout();
    socketclose_ex(sockfd);
#if DNS_MESSAGE_HAS_POOL
    formatln("thread %p free pool_buffers", thread_self());
    flushout();
    free(pool_buffers);
#endif
    formatln("thread %p free packet_buffers", thread_self());
    flushout();
    free(packet_buffers);
    // formatln("thread %p free udp_packets_send", thread_self());flushout();
    // free(udp_packets_send);
    formatln("thread %p free udp_packets", thread_self());
    flushout();
    free(udp_packets);
    formatln("thread %p free messages", thread_self());
    flushout();
    free(messages);
    formatln("thread %p terminated", thread_self());
    flushout();
}

static void echo_server_retry(int id, zone_t *zone)
{
    (void)zone;
    socketaddress_t sa;
    host_address2sockaddr(g_main_settings.listen, &sa);

    thread_setaffinity(thread_self(), id);

    int sockfd = -1;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if(sockfd < 0)
    {
        formatln("socket failed: %r", ERRNO_ERROR);
        return;
    }

    int on = 1;
    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on))))
    {
        formatln("setsockopt SO_REUSEADDR failed: %r", ERRNO_ERROR);
        socketclose_ex(sockfd);
        return;
    }
#ifdef SO_REUSEPORT
    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on))))
    {
        formatln("setsockopt SO_REUSEPORT failed: %r", ERRNO_ERROR);
        socketclose_ex(sockfd);
        return;
    }
#endif

    if(bind(sockfd, &sa.sa, socketaddress_len(&sa)) < 0)
    {
        formatln("bind failed: %r", ERRNO_ERROR);
        socketclose_ex(sockfd);
        return;
    }

    dns_message_t **messages;

    struct mmsghdr *udp_packets = NULL;
    struct mmsghdr *udp_packets_send = NULL;
    unsigned int    udp_packets_count = g_main_settings.packets_at_once;

    formatln("thread %p batch-size is %u", thread_self(), udp_packets_count);

    const size_t packet_size = 4096;

    uint8_t     *packet_buffers = aligned_alloc(4096, udp_packets_count * packet_size);
#if DNS_MESSAGE_HAS_POOL
    uint8_t *pool_buffers = aligned_alloc(4096, udp_packets_count * packet_size);
#endif

    MALLOC_OBJECT_ARRAY_OR_DIE(messages, dns_message_t *, udp_packets_count, SMMMSGS_TAG);
    MALLOC_OBJECT_ARRAY_OR_DIE(udp_packets, struct mmsghdr, udp_packets_count, MMSGHDR_TAG);
    // MALLOC_OBJECT_ARRAY_OR_DIE(udp_packets_send, struct mmsghdr, udp_packets_count, MMSGHDR_TAG);

    struct timespec recv_timeout = {1, 0};

    for(uint_fast32_t i = 0; i < udp_packets_count; ++i)
    {
        messages[i] = dns_message_new_instance_ex(&packet_buffers[packet_size * i], packet_size);
#if DNS_MESSAGE_HAS_POOL
        dns_message_set_pool_buffer(messages[i], &pool_buffers[packet_size * i], packet_size);
#endif
        dns_message_reset_control(messages[i]);
        dns_message_copy_msghdr(messages[i], &udp_packets[i].msg_hdr);
        udp_packets[i].msg_len = 0;
    }

    formatln("thread %p echoing", thread_self());

    while(!dnscore_shuttingdown())
    {
        int recvmmsg_ret = recvmmsg(sockfd, udp_packets, udp_packets_count, MSG_WAITFORONE, &recv_timeout);
        if(recvmmsg_ret > 0)
        {
            for(int_fast32_t i = 0; i < recvmmsg_ret; ++i)
            {
                udp_packets[i].msg_hdr.msg_iov[0].iov_len = udp_packets[i].msg_len;
            }

            int n = recvmmsg_ret;

            udp_packets_send = udp_packets;

            do
            {
                int sendmmsg_ret = sendmmsg(sockfd, udp_packets_send, n, 0);
                if(sendmmsg_ret >= 0)
                {
                    n -= sendmmsg_ret;
                    udp_packets_send += sendmmsg_ret;
                }
                else
                {
                    // nothing has been sent
                }
            } while(n > 0);

            for(int_fast32_t i = 0; i < recvmmsg_ret; ++i)
            {
                udp_packets[i].msg_hdr.msg_iov[0].iov_len = dns_message_get_buffer_size_max(messages[i]);
            }

            /*
            for(uint_fast32_t i = 0; i < n; ++i)
            {
                dns_message_reset_control(messages[i]);
                dns_message_copy_msghdr(messages[i], &udp_packets[i].msg_hdr);
            }
            */
        }
        else
        {
            int err = errno;
            switch(err)
            {
                case EBADF:
                case ECONNRESET:
                case EINVAL:
                case EMSGSIZE:
                case ENOTSOCK:
                {
                    dnscore_shutdown();
                    break;
                }
                default:
                {
                    break;
                }
            }
        }
    }

    formatln("thread %p stopping", thread_self());
    flushout();
    socketclose_ex(sockfd);
#if DNS_MESSAGE_HAS_POOL
    formatln("thread %p free pool_buffers", thread_self());
    flushout();
    free(pool_buffers);
#endif
    formatln("thread %p free packet_buffers", thread_self());
    flushout();
    free(packet_buffers);
    // formatln("thread %p free udp_packets_send", thread_self());flushout();
    // free(udp_packets_send);
    formatln("thread %p free udp_packets", thread_self());
    flushout();
    free(udp_packets);
    formatln("thread %p free messages", thread_self());
    flushout();
    free(messages);
    formatln("thread %p terminated", thread_self());
    flushout();
}

static void echo_server_onetry(int id, zone_t *zone)
{
    (void)zone;
    socketaddress_t sa;
    host_address2sockaddr(g_main_settings.listen, &sa);

    thread_setaffinity(thread_self(), id);

    int sockfd = -1;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if(sockfd < 0)
    {
        formatln("socket failed: %r", ERRNO_ERROR);
        return;
    }

    int on = 1;
    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on))))
    {
        formatln("setsockopt SO_REUSEADDR failed: %r", ERRNO_ERROR);
        socketclose_ex(sockfd);
        return;
    }
#ifdef SO_REUSEPORT
    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on))))
    {
        formatln("setsockopt SO_REUSEPORT failed: %r", ERRNO_ERROR);
        socketclose_ex(sockfd);
        return;
    }
#endif

    if(bind(sockfd, &sa.sa, socketaddress_len(&sa)) < 0)
    {
        formatln("bind failed: %r", ERRNO_ERROR);
        socketclose_ex(sockfd);
        return;
    }

    dns_message_t **messages;

    struct mmsghdr *udp_packets = NULL;
    struct mmsghdr *udp_packets_send = NULL;
    unsigned int    udp_packets_count = g_main_settings.packets_at_once;

    formatln("thread %p batch-size is %u", thread_self(), udp_packets_count);

    const size_t packet_size = 4096;

    uint8_t     *packet_buffers = aligned_alloc(4096, udp_packets_count * packet_size);
#if DNS_MESSAGE_HAS_POOL
    uint8_t *pool_buffers = aligned_alloc(4096, udp_packets_count * packet_size);
#endif

    MALLOC_OBJECT_ARRAY_OR_DIE(messages, dns_message_t *, udp_packets_count, SMMMSGS_TAG);
    MALLOC_OBJECT_ARRAY_OR_DIE(udp_packets, struct mmsghdr, udp_packets_count, MMSGHDR_TAG);
    // MALLOC_OBJECT_ARRAY_OR_DIE(udp_packets_send, struct mmsghdr, udp_packets_count, MMSGHDR_TAG);

    struct timespec recv_timeout = {1, 0};

    for(uint_fast32_t i = 0; i < udp_packets_count; ++i)
    {
        messages[i] = dns_message_new_instance_ex(&packet_buffers[packet_size * i], packet_size);
#if DNS_MESSAGE_HAS_POOL
        dns_message_set_pool_buffer(messages[i], &pool_buffers[packet_size * i], packet_size);
#endif
        dns_message_reset_control(messages[i]);
        dns_message_copy_msghdr(messages[i], &udp_packets[i].msg_hdr);
        udp_packets[i].msg_len = 0;
    }

    formatln("thread %p echoing", thread_self());

    while(!dnscore_shuttingdown())
    {
        int recvmmsg_ret = recvmmsg(sockfd, udp_packets, udp_packets_count, MSG_WAITFORONE, &recv_timeout);
        if(recvmmsg_ret > 0)
        {
            for(int_fast32_t i = 0; i < recvmmsg_ret; ++i)
            {
                udp_packets[i].msg_hdr.msg_iov[0].iov_len = udp_packets[i].msg_len;
            }

            udp_packets_send = udp_packets;

            sendmmsg(sockfd, udp_packets_send, recvmmsg_ret, 0);

            for(int_fast32_t i = 0; i < recvmmsg_ret; ++i)
            {
                udp_packets[i].msg_hdr.msg_iov[0].iov_len = dns_message_get_buffer_size_max(messages[i]);
            }
        }
        else
        {
            int err = errno;
            switch(err)
            {
                case EBADF:
                case ECONNRESET:
                case EINVAL:
                case EMSGSIZE:
                case ENOTSOCK:
                {
                    dnscore_shutdown();
                    break;
                }
                default:
                {
                    break;
                }
            }
        }
    }

    formatln("thread %p stopping", thread_self());
    flushout();
    socketclose_ex(sockfd);
#if DNS_MESSAGE_HAS_POOL
    formatln("thread %p free pool_buffers", thread_self());
    flushout();
    free(pool_buffers);
#endif
    formatln("thread %p free packet_buffers", thread_self());
    flushout();
    free(packet_buffers);
    // formatln("thread %p free udp_packets_send", thread_self());flushout();
    // free(udp_packets_send);
    formatln("thread %p free udp_packets", thread_self());
    flushout();
    free(udp_packets);
    formatln("thread %p free messages", thread_self());
    flushout();
    free(messages);
    formatln("thread %p terminated", thread_self());
    flushout();
}

struct echo_server_thread_args_s
{
    int id;
};

typedef struct echo_server_thread_args_s echo_server_thread_args_t;

static void                              echo_server_thread(void *args_)
{
    echo_server_thread_args_t *args = (echo_server_thread_args_t *)args_;
    switch(g_main_settings.mode)
    {
        case 0:
            echo_server_retry(args->id, db_zone);
            break;
        case 1:
            echo_server_onetry(args->id, db_zone);
            break;
        case 2:
            echo_server_retry_zonelock(args->id, db_zone);
            break;
        case 3:
            echo_server_retry_dbzonelock(args->id, db_zone);
            break;
        default:
            break;
    }
    free(args);
}

static void echo_server_wake_up()
{
    static const uint8_t buffer[1] = {0};

    for(;;)
    {
        socketaddress_t sa;
        host_address2sockaddr(g_main_settings.listen, &sa);

        int sockfd = -1;

        sockfd = socket(AF_INET, SOCK_DGRAM, 0);

        if(sockfd < 0)
        {
            formatln("socket failed: %r", ERRNO_ERROR);
            break;
        }

        tcp_set_sendtimeout(sockfd, 1, 0);

        if(sendto(sockfd, buffer, sizeof(buffer), 0, &sa.sa, socketaddress_len(&sa)) < 0)
        {
            break;
        }
    }
}

static void signal_int(uint8_t signum)
{
    (void)signum;
    dnscore_shutdown();
    echo_server_wake_up();
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    /* initializes the core library */
    dnscore_init();

    ya_result ret = main_config(argc, argv);

    if(cmdline_version_get() || cmdline_help_get() || FAIL(ret))
    {
        return 0;
    }

    if(g_main_settings.daemon)
    {
        server_setup_daemon_go();
    }

    signal_handler_init();
    signal_handler_set(SIGINT, signal_int);
    signal_handler_set(SIGTERM, signal_int);

    group_mutex_init(&db_mtx);
    ZALLOC_OBJECT_OR_DIE(db_zone, zone_t, GENERIC_TAG);
    group_mutex_init(&db_zone->mtx);

    thread_pool_task_counter_t counter;
    thread_pool_counter_init(&counter, 0);

    struct thread_pool_s *tp = thread_pool_init(g_main_settings.workers, g_main_settings.workers * 2);

    if(tp == NULL)
    {
        formatln("thread_pool_init: %r", THREAD_CREATION_ERROR);
        exit(EXIT_FAILURE);
    }

    for(uint_fast32_t i = 0; i < g_main_settings.workers; ++i)
    {
        echo_server_thread_args_t *args = malloc(sizeof(echo_server_thread_args_t));
        args->id = i;
        thread_pool_enqueue_call(tp, echo_server_thread, args, &counter, "echosvr");
    }
    thread_pool_counter_wait_equal(&counter, g_main_settings.workers);
    println("ready");
    flushout();
    thread_pool_counter_wait_below_or_equal(&counter, 0);
    println("stopped");
    thread_pool_destroy(tp);

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
