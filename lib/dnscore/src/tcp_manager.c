/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2020, EURid vzw. All rights reserved.
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

#define __TCP_MANAGER_C__ 1

#include "dnscore/dnscore-config.h"
#include "dnscore/mutex.h"
#include "dnscore/network.h"
#include "dnscore/ptr_set.h"
#include "dnscore/u32_set.h"
#if HAVE_STDATOMIC_H
#include <stdatomic.h>
#else
#include "dnscore/thirdparty/stdatomic.h"
#endif
#include <dnscore/tcp_io_stream.h>
#include <dnscore/fdtools.h>
#include <dnscore/zalloc.h>
#include <dnscore/logger.h>
#include <dnscore/list-sl.h>
#include <dnscore/list-dl.h>

#define MODULE_MSG_HANDLE g_system_logger

struct tcp_manager_address_context_s
{
    socketaddress addr;
    socklen_t addr_len;
    spinlock_t spinlock;
    volatile s32 connection_count;
    s32 connection_count_max;
    s32 connection_per_adress_max;
};

typedef struct tcp_manager_address_context_s tcp_manager_address_context_t;

struct tcp_manager_client_context_s
{
    mutex_t connection_list_mtx;
    list_dl_s connection_list;
    s32 connection_count_max;
    atomic_int rc;
    socketaddress addr;
    socklen_t addr_len;
};

typedef struct tcp_manager_client_context_s tcp_manager_client_context_t;

struct tcp_manager_socket_context_s
{
    tcp_manager_address_context_t *address_context;
    tcp_manager_client_context_t *client_context;
    int sockfd;
    atomic_int rc;
    spinlock_t spinlock;
    s64 bytes_read;
    s64 bytes_written;
    s64 read_time;
    s64 write_time;
    s64 accept_time;
    s64 close_time;
    socklen_t addr_len;
    socketaddress addr;
};

typedef struct tcp_manager_socket_context_s tcp_manager_socket_context_t;

#include "dnscore/tcp_manager.h"

static ptr_set tcp_manager_wl_ipv4 = PTR_SET_EMPTY;
static ptr_set tcp_manager_wl_ipv6 = PTR_SET_EMPTY;
static tcp_manager_address_context_t tcp_manager_global;

static u32_set tcp_manager_sockfd_set = U32_SET_EMPTY;
static mutex_t tcp_manager_sockfd_set_mtx = MUTEX_INITIALIZER;

static ptr_set client_address_set = PTR_SET_EMPTY;
static mutex_t client_address_set_mtx = MUTEX_INITIALIZER;

// sockaddr->value collection
// sockfd->value collection

static bool tcp_manager_initialised = FALSE;


static int socketaddress_compare_ip(const void *a, const void *b)
{
    const socketaddress *sa = (const socketaddress*)a;
    const socketaddress *sb = (const socketaddress*)b;

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
                    ret = (int)(intptr)(sa - sb);
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

static void
tcp_manager_address_context_init(tcp_manager_address_context_t *ctx)
{
    memset(&ctx->addr, 0, sizeof(ctx->addr));
    ctx->addr.sa.sa_family = AF_INET;
    ctx->addr_len = sizeof(ctx->addr.sa4);
    spinlock_init(&ctx->spinlock);
    ctx->connection_count_max = 32768;
}

static void
tcp_manager_client_context_release(tcp_manager_client_context_t *mcctx)
{
    mutex_lock(&client_address_set_mtx);
    int prev = atomic_fetch_sub(&mcctx->rc, 1);

    if(prev == 1)
    {
        bool in_use = list_dl_size(&mcctx->connection_list) > 0;

        if(!in_use)
        {
            ptr_set_delete(&client_address_set, &mcctx->addr);
        }
    }
    mutex_unlock(&client_address_set_mtx);
}

void
tcp_manager_init()
{
    if(!tcp_manager_initialised)
    {
        tcp_manager_initialised = TRUE;
        tcp_manager_address_context_init(&tcp_manager_global);
        tcp_manager_global.connection_count_max = 10;
        tcp_manager_global.connection_per_adress_max = 3;
        tcp_manager_wl_ipv4.compare = socketaddress_compare_ip;
        tcp_manager_wl_ipv6.compare = socketaddress_compare_ip;
        client_address_set.compare = socketaddress_compare_ip;
    }
}

void
tcp_manager_finalize()
{
}

ya_result
tcp_manager_accept(int servfd)
{
    socketaddress addr;
    socklen_t addr_len = sizeof(socketaddress);
    tcp_manager_address_context_t *context;

    int sockfd;

    while((sockfd = accept(servfd, &addr.sa, &addr_len)) < 0)
    {
        int err = errno;

        if(err != EINTR)
        {
            return err;
        }
    }

    if(sockfd >= 0)
    {
        // check if the client is whilelisted

        s64 now = timeus();

        if(addr_len > MAX(sizeof(struct sockaddr_in),sizeof(struct sockaddr_in6)))
        {
            tcp_set_abortive_close(sockfd);
            close_ex(sockfd);
            return BUFFER_WOULD_OVERFLOW;
        }

        switch(addr.sa.sa_family)
        {
            case AF_INET:
            {
                //addr.sa4.sin_addr
                ptr_node *node = ptr_set_find(&tcp_manager_wl_ipv4, &addr.sa4);
                if(node == NULL)
                {
                    // global case
                    context = &tcp_manager_global;
                }
                else
                {
                    context = (tcp_manager_address_context_t*)node->value;
                }
                break;
            }
            case AF_INET6:
            {
                ptr_node *node = ptr_set_find(&tcp_manager_wl_ipv6, &addr.sa6);
                if(node == NULL)
                {
                    // global case
                    context = &tcp_manager_global;
                }
                else
                {
                    context = (tcp_manager_address_context_t*)node->value;
                }
                break;
            }
            default:
            {
                tcp_set_abortive_close(sockfd);
                close_ex(sockfd);
                return INVALID_PROTOCOL;
            }
        }

        mutex_lock(&client_address_set_mtx);
        tcp_manager_client_context_t *mcctx;
        ptr_node *client_address_node = ptr_set_insert(&client_address_set, &addr);
        if(client_address_node->value == NULL)
        {
            // create the node

            ZALLOC_OBJECT_OR_DIE(mcctx, tcp_manager_client_context_t, GENERIC_TAG);
            mutex_init(&mcctx->connection_list_mtx);
            list_dl_init(&mcctx->connection_list);
            mcctx->connection_count_max = context->connection_per_adress_max;
            atomic_init(&mcctx->rc, 1);
            memcpy(&mcctx->addr, &addr, addr_len);
            mcctx->addr_len = addr_len;

            client_address_node->key = &mcctx->addr;
            client_address_node->value = mcctx;
        }
        else
        {
            mcctx = (tcp_manager_client_context_t*)client_address_node->value;
        }
        mutex_unlock(&client_address_set_mtx);

        spinlock_lock(&context->spinlock);
        bool has_room = (context->connection_count < context->connection_count_max);

        if(has_room)
        {
            s32 count = ++context->connection_count;

            log_debug("tcp: %{sockaddr} connection count: %i/%i (accept)", &context->addr, count, context->connection_count_max);
        }

        spinlock_unlock(&context->spinlock);

        if(has_room)
        {
            tcp_manager_socket_context_t *sockfd_context;
            ZALLOC_OBJECT_OR_DIE(sockfd_context, tcp_manager_socket_context_t, GENERIC_TAG);
            sockfd_context->address_context = context;
            sockfd_context->client_context = mcctx;
            sockfd_context->sockfd = sockfd;
            atomic_init(&sockfd_context->rc, 0);
            spinlock_init(&sockfd_context->spinlock);
            sockfd_context->bytes_read = 0;
            sockfd_context->bytes_written = 0;
            sockfd_context->read_time = 0;
            sockfd_context->write_time = 0;
            sockfd_context->accept_time = now;
            sockfd_context->close_time = 0;
            sockfd_context->addr_len = addr_len;
            memcpy(&sockfd_context->addr, &addr, addr_len);

            mutex_lock(&tcp_manager_sockfd_set_mtx);
            u32_node *sockfd_node = u32_set_insert(&tcp_manager_sockfd_set, sockfd);

            if(sockfd_node->value == NULL)
            {
                sockfd_node->value = sockfd_context;

                mutex_lock(&mcctx->connection_list_mtx);
                list_dl_append(&mcctx->connection_list, sockfd_context);

                if(list_dl_size(&mcctx->connection_list) <= (u32)mcctx->connection_count_max)
                {
                    log_debug("tcp: %{sockaddr} client connection count: %i/%i", &mcctx->addr, list_dl_size(&mcctx->connection_list), mcctx->connection_count_max);

                    mutex_unlock(&mcctx->connection_list_mtx);
                }
                else
                {
                    log_debug("tcp: %{sockaddr} client connection count: %i/%i: aborting the oldest one", &mcctx->addr, list_dl_size(&mcctx->connection_list), mcctx->connection_count_max);

                    tcp_manager_socket_context_t *oldest_sockfd_context = (tcp_manager_socket_context_t*)list_dl_remove_first(&mcctx->connection_list);
                    mutex_unlock(&mcctx->connection_list_mtx);
                    shutdown(oldest_sockfd_context->sockfd, SHUT_RDWR);
                    tcp_set_abortive_close(oldest_sockfd_context->sockfd);
                }

                tcp_manager_client_context_release(mcctx);

                mutex_unlock(&tcp_manager_sockfd_set_mtx);

                return sockfd;
            }
            else
            {
                mutex_unlock(&tcp_manager_sockfd_set_mtx);

                spinlock_lock(&context->spinlock);
                --context->connection_count;
                spinlock_unlock(&context->spinlock);

                atomic_fetch_sub(&mcctx->rc, 1);

                tcp_set_abortive_close(sockfd);
                close_ex(sockfd);   // socket not unregistered!

                return INVALID_STATE_ERROR;
            }
        }
        else
        {
            tcp_set_abortive_close(sockfd);
            close_ex(sockfd);   // quota exceeded

            return MAKE_DNSMSG_ERROR(EMFILE);
        }
    }
    else
    {
        return ERRNO_ERROR;
    }
}

tcp_manager_socket_context_t*
tcp_manager_context_acquire(int sockfd)
{
    mutex_lock(&tcp_manager_sockfd_set_mtx);
    u32_node *sockfd_node = u32_set_find(&tcp_manager_sockfd_set, sockfd);
    if(sockfd_node->value != NULL)
    {
        tcp_manager_socket_context_t *sctx = (tcp_manager_socket_context_t*)sockfd_node->value; // the cast is just a reminded for the programmer
        atomic_fetch_add(&sctx->rc, 1);
        mutex_unlock(&tcp_manager_sockfd_set_mtx);

        return sctx;
    }
    else
    {
        mutex_unlock(&tcp_manager_sockfd_set_mtx);
        return NULL;
    }
}

bool
tcp_manager_context_release(tcp_manager_socket_context_t* sctx)
{
    int old_rc_value = atomic_fetch_sub(&sctx->rc, 1);

    bool zero = (old_rc_value == 1); // 1 - 1 == 0

    if(zero)
    {
        // remove

        mutex_lock(&tcp_manager_sockfd_set_mtx);
        u32_set_delete(&tcp_manager_sockfd_set, sctx->sockfd);
        // do NOT: sctx->address_context = NULL;
        mutex_unlock(&tcp_manager_sockfd_set_mtx);

        log_debug("tcp: released %{sockaddr} r: %lli, w: %lli, accepted: %llT, last-read: %llT, last-write: %llT, closed: %llT, active: %llims, total: %llims",
                &sctx->addr, sctx->bytes_read, sctx->bytes_written, sctx->accept_time, sctx->read_time, sctx->write_time, sctx->close_time,
                (MAX(sctx->read_time, sctx->write_time) - sctx->accept_time) / 1000,
                (sctx->close_time - sctx->accept_time) / 1000);

        s32 count;

        tcp_manager_client_context_release(sctx->client_context);

        log_debug("tcp: %{sockaddr} client connection count: %i/%i", &sctx->client_context->addr, list_dl_size(&sctx->client_context->connection_list), sctx->client_context->connection_count_max);

        spinlock_lock(&sctx->address_context->spinlock);
        count = --sctx->address_context->connection_count;
        spinlock_unlock(&sctx->address_context->spinlock);

        log_debug("tcp: %{sockaddr} connection count: %i/%i (close)", &sctx->address_context->addr, count, sctx->address_context->connection_count_max);

        spinlock_destroy(&sctx->spinlock);

        ZFREE_OBJECT(sctx);
    }
    return zero;
}

ya_result
tcp_manager_write(tcp_manager_socket_context_t *sctx, const u8 *buffer, size_t buffer_size)
{
    int n = write(sctx->sockfd, buffer, buffer_size);
    if(n >= 0)
    {
        spinlock_lock(&sctx->spinlock);
        sctx->bytes_written += n;
        sctx->write_time = timeus();
        spinlock_unlock(&sctx->spinlock);
    }

    return n;
}

ya_result
tcp_manager_read(tcp_manager_socket_context_t *sctx, u8 *buffer, size_t buffer_size)
{
    int n = read(sctx->sockfd, buffer, buffer_size);
    if(n >= 0)
    {
        spinlock_lock(&sctx->spinlock);
        sctx->bytes_read += n;
        sctx->read_time = timeus();
        spinlock_unlock(&sctx->spinlock);
    }

    return n;
}

void
tcp_manager_write_update(tcp_manager_socket_context_t *sctx, size_t n)
{
    spinlock_lock(&sctx->spinlock);
    sctx->bytes_written += n;
    sctx->write_time = timeus();
    spinlock_unlock(&sctx->spinlock);
}

void
tcp_manager_read_update(tcp_manager_socket_context_t *sctx, size_t n)
{
    spinlock_lock(&sctx->spinlock);
    sctx->bytes_read += n;
    sctx->read_time = timeus();
    spinlock_unlock(&sctx->spinlock);
}

ya_result
tcp_manager_close(tcp_manager_socket_context_t *sctx)
{
    ya_result ret;

    if(ISOK(ret = close_ex(sctx->sockfd)))
    {
        spinlock_lock(&sctx->spinlock);
        sctx->close_time = timeus();
        spinlock_unlock(&sctx->spinlock);
    }

    tcp_manager_context_release(sctx);

    return ret;
}

socketaddress*
tcp_manager_socketaddress(tcp_manager_socket_context_t *sctx)
{
    return &sctx->addr;
}

socklen_t
tcp_manager_socklen(tcp_manager_socket_context_t *sctx)
{
    return sctx->addr_len;
}

int
tcp_manager_socket(tcp_manager_socket_context_t *sctx)
{
    return sctx->sockfd;
}

bool
tcp_manager_is_valid(tcp_manager_socket_context_t *sctx)
{
    return (sctx != NULL) && (sctx->sockfd >= 0) && (sctx->close_time == 0);
}
