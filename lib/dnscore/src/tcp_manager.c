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

typedef struct tcp_manager_socket_context_s tcp_manager_socket_context_t;

#include "dnscore/tcp_manager.h"

#define MODULE_MSG_HANDLE g_system_logger

// Host

struct tcp_manager_host_context_s
{
    mutex_t connection_list_mtx;
    list_dl_s connection_list;          // should be a set, I just don't know the key yet.
    atomic_int rc;                      // so it's not destroyed mid-use
    socketaddress addr;                 // the host
    socklen_t addr_len;
    u16 connection_count_max;
    bool persistent;
};

typedef struct tcp_manager_host_context_s tcp_manager_host_context_t;

struct tcp_manager_socket_context_s
{
    tcp_manager_host_context_t *host;
    int sockfd;
    atomic_int rc;
    spinlock_t spinlock;
    s64 bytes_read;
    s64 bytes_written;
    s64 read_time;
    s64 write_time;
    s64 accept_time;
    s64 close_time;
};

typedef struct tcp_manager_socket_context_s tcp_manager_socket_context_t;

static ptr_set tcp_manager_host_context_set;
static mutex_t tcp_manager_host_context_set_mtx;

static u32_set tcp_manager_socket_context_set = U32_SET_EMPTY;
static mutex_t tcp_manager_socket_context_set_mtx = MUTEX_INITIALIZER;

static void
tcp_manager_host_context_release(tcp_manager_host_context_t *ctx);

static int
tcp_manager_host_context_init_ptr_set_forall_callback(ptr_node *node, void *args_)
{
    (void)args_;
    tcp_manager_host_context_t *ctx = (tcp_manager_host_context_t*)node->value;
    tcp_manager_host_context_release(ctx);
    return SUCCESS;
}

static void
tcp_manager_host_context_init(tcp_manager_host_context_t *ctx, socketaddress *addr, socklen_t addr_len, u16 connection_count_max, bool persistent);

static void
tcp_manager_host_context_class_init()
{
    ptr_set_init(&tcp_manager_host_context_set);
    tcp_manager_host_context_set.compare = socketaddress_compare_ip;
    mutex_init(&tcp_manager_host_context_set_mtx);
}

static void
tcp_manager_host_context_class_finalize()
{
    mutex_lock(&tcp_manager_host_context_set_mtx);
    ptr_set_forall(&tcp_manager_host_context_set, tcp_manager_host_context_init_ptr_set_forall_callback, NULL);
    mutex_unlock(&tcp_manager_host_context_set_mtx);
    ptr_set_init(&tcp_manager_host_context_set);
    tcp_manager_host_context_set.compare = socketaddress_compare_ip;
    mutex_destroy(&tcp_manager_host_context_set_mtx);
}

static void
tcp_manager_host_context_init(tcp_manager_host_context_t *ctx, socketaddress *addr, socklen_t addr_len, u16 allowed_connections_max, bool persistent)
{
    if(allowed_connections_max <= 0)
    {
        allowed_connections_max = TCP_MANAGER_HOST_CONTEXT_CONNECTION_COUNT_MAX;
    }

    mutex_init(&ctx->connection_list_mtx);
    list_dl_init(&ctx->connection_list);
    ctx->rc = 1;
    memcpy(&ctx->addr, addr, addr_len);
    ctx->addr_len = addr_len;
    ctx->connection_count_max = allowed_connections_max;
    ctx->persistent = persistent;

    if(persistent)
    {
        // ++ctx->rc;  /// @todo 20210303 edf -- when persistence is fully implemented, persistent nodes can only be destroyed with the system
    }
}

static tcp_manager_host_context_t*
tcp_manager_host_context_new_instance_nolock(socketaddress *addr, socklen_t addr_len, u16 connection_count_max, bool persistent)
{
    tcp_manager_host_context_t *ctx;
    ptr_node *node = ptr_set_insert(&tcp_manager_host_context_set, addr);

    if(node->value == NULL)
    {
        ZALLOC_OBJECT_OR_DIE(ctx, tcp_manager_host_context_t, GENERIC_TAG);
        tcp_manager_host_context_init(ctx, addr, addr_len, connection_count_max, persistent);

        node->key = &ctx->addr;  /// @note it NEEDS to be the one from the node
        node->value = ctx;
    }
    else
    {
        ctx = (tcp_manager_host_context_t*)node->value;
    }
    return ctx;
}

static tcp_manager_host_context_t*
tcp_manager_host_context_new_instance(socketaddress *addr, socklen_t addr_len, u16 connection_count_max, bool persistent)
{
    tcp_manager_host_context_t *ctx;
    mutex_lock(&tcp_manager_host_context_set_mtx);

    ctx = tcp_manager_host_context_new_instance_nolock(addr, addr_len, connection_count_max, persistent);

    mutex_unlock(&tcp_manager_host_context_set_mtx);
    return ctx;
}

static void
tcp_manager_host_context_acquire(tcp_manager_host_context_t *ctx)
{
    ++ctx->rc;
}

static tcp_manager_host_context_t*
tcp_manager_host_context_acquire_or_create(socketaddress *addr, socklen_t addr_len, u16 connection_count_max, bool persistent)
{
    tcp_manager_host_context_t *ctx;
    mutex_lock(&tcp_manager_host_context_set_mtx);
    ptr_node *node = ptr_set_find(&tcp_manager_host_context_set, addr);
    if(node == NULL)
    {
        ctx = tcp_manager_host_context_new_instance_nolock(addr, addr_len, connection_count_max, persistent);
    }
    else
    {
        ctx = (tcp_manager_host_context_t*)node->value;
        ++ctx->rc;
    }
    mutex_unlock(&tcp_manager_host_context_set_mtx);
    return ctx;
}

static void
tcp_manager_host_context_delete(tcp_manager_host_context_t *ctx)
{
    assert(ctx->rc == 0);
#ifndef NDEBUG
    mutex_lock(&ctx->connection_list_mtx);
    assert(list_dl_size(&ctx->connection_list) == 0);
    mutex_unlock(&ctx->connection_list_mtx);
#endif
    mutex_lock(&tcp_manager_host_context_set_mtx);
    ptr_set_delete(&tcp_manager_host_context_set, &ctx->addr);
    mutex_unlock(&tcp_manager_host_context_set_mtx);
    mutex_destroy(&ctx->connection_list_mtx);
    ZFREE_OBJECT(ctx);
}

static void
tcp_manager_host_context_release(tcp_manager_host_context_t *ctx)
{
    if(--ctx->rc == 0)
    {
        tcp_manager_host_context_delete(ctx);
    }
}

static void
tcp_manager_socket_context_class_init()
{
    u32_set_init(&tcp_manager_socket_context_set);
    mutex_init(&tcp_manager_socket_context_set_mtx);
}

static void
tcp_manager_socket_context_class_finalize()
{
    mutex_lock(&tcp_manager_socket_context_set_mtx);
    // u32_set_callback_and_destroy(&tcp_manager_socket_context_set, ...)
    mutex_unlock(&tcp_manager_socket_context_set_mtx);
    u32_set_destroy(&tcp_manager_socket_context_set);
    mutex_destroy(&tcp_manager_socket_context_set_mtx);
}

static tcp_manager_socket_context_t*
tcp_manager_socket_context_new_instance_nolock(tcp_manager_host_context_t *ctx, int sockfd)
{
    u32_node *node = u32_set_insert(&tcp_manager_socket_context_set, sockfd);
    yassert(node->value == NULL);

    tcp_manager_socket_context_t *sctx;
    ZALLOC_OBJECT_OR_DIE(sctx, tcp_manager_socket_context_t, GENERIC_TAG);
    tcp_manager_host_context_acquire(ctx);
    sctx->host = ctx;
    sctx->sockfd = sockfd;
    sctx->rc = 1;
    spinlock_init(&sctx->spinlock);
    sctx->bytes_read = 0;
    sctx->bytes_written = 0;
    sctx->read_time = 0;
    sctx->write_time = 0;
    sctx->accept_time = 0;
    sctx->close_time = 0;

    node->value = sctx;

    return sctx;
}

static tcp_manager_socket_context_t*
tcp_manager_socket_context_new_instance(tcp_manager_host_context_t *ctx, int sockfd)
{
    tcp_manager_socket_context_t *sctx;
    mutex_lock(&tcp_manager_socket_context_set_mtx);
    sctx = tcp_manager_socket_context_new_instance_nolock(ctx, sockfd);
    mutex_unlock(&tcp_manager_socket_context_set_mtx);
    return sctx;
}

static void
tcp_manager_socket_context_mru_remove(tcp_manager_socket_context_t *sctx);

static void
tcp_manager_socket_context_delete(tcp_manager_socket_context_t *sctx)
{
    tcp_manager_socket_context_mru_remove(sctx);

    mutex_lock(&tcp_manager_socket_context_set_mtx);
    if(sctx->sockfd >= 0)
    {
        u32_set_delete(&tcp_manager_socket_context_set, sctx->sockfd);
        close_ex(sctx->sockfd);
        sctx->sockfd = -1;
    }
    spinlock_destroy(&sctx->spinlock);
    mutex_unlock(&tcp_manager_socket_context_set_mtx);
    ZFREE_OBJECT(sctx);
}

static void
tcp_manager_socket_context_acquire(tcp_manager_socket_context_t *sctx)
{
    ++sctx->rc;
}

static void
tcp_manager_socket_context_release(tcp_manager_socket_context_t *sctx)
{
    if(--sctx->rc == 0)
    {
        if(sctx->close_time > 0) // really closed
        {
            tcp_manager_socket_context_delete(sctx);
        }
    }
}

static void
tcp_manager_socket_context_mru_to_head(tcp_manager_socket_context_t *sctx)
{
    mutex_lock(&sctx->host->connection_list_mtx);
    list_dl_move_to_first_position(&sctx->host->connection_list, sctx);
    mutex_unlock(&sctx->host->connection_list_mtx);
}

static void
tcp_manager_socket_context_mru_remove(tcp_manager_socket_context_t *sctx)
{
    if(sctx->host != NULL)
    {
        tcp_manager_host_context_t *host = sctx->host;
        sctx->host = NULL;
        mutex_lock(&host->connection_list_mtx);
        list_dl_remove(&host->connection_list, sctx);
        mutex_unlock(&host->connection_list_mtx);
        tcp_manager_host_context_release(host);
    }
}

static bool
tcp_manager_socket_context_in_use(tcp_manager_socket_context_t *sctx)
{
    s64 now = timeus();
    if((sctx->close_time != 0) &&
        (
        ((sctx->read_time + sctx->write_time == 0)  && ((now - sctx->accept_time) < ONE_SECOND_US)) ||
        ((sctx->read_time > 0)  && ((now - sctx->read_time) < ONE_SECOND_US)) ||
        ((sctx->write_time > 0)  && ((now - sctx->write_time) < ONE_SECOND_US))
        )
        )
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

static ya_result
tcp_manager_host_context_add(tcp_manager_host_context_t *ctx, int sockfd, tcp_manager_socket_context_t **out_sctxp)
{
    tcp_manager_socket_context_t *oldest_sctx = NULL;

    mutex_lock(&ctx->connection_list_mtx);
    s32 mru_size = (s32)list_dl_size(&ctx->connection_list);
    if(mru_size >= ctx->connection_count_max)
    {
        list_dl_node_s* node = list_dl_last_node(&ctx->connection_list);

        // node->data
        oldest_sctx = (tcp_manager_socket_context_t*)node->data;

        if(tcp_manager_socket_context_in_use(oldest_sctx))
        {
            mutex_unlock(&ctx->connection_list_mtx);
            return ERROR;
        }

        // acquire it so it will still be valid
        tcp_manager_socket_context_acquire(oldest_sctx);
    }

    tcp_manager_socket_context_t *sctx = tcp_manager_socket_context_new_instance(ctx, sockfd);

    // insert

    //tcp_manager_socket_context_acquire(sctx);
    list_dl_insert(&ctx->connection_list, sctx);

    if(out_sctxp != NULL)
    {
        tcp_manager_socket_context_acquire(sctx);
        *out_sctxp = sctx;
    }

    tcp_manager_socket_context_release(sctx);

    mutex_unlock(&ctx->connection_list_mtx);

    if(oldest_sctx != NULL)
    {
        int fd = oldest_sctx->sockfd;
        if(fd >= 0)
        {
            oldest_sctx->close_time = timeus();
            oldest_sctx->sockfd = -1;
            u32_set_delete(&tcp_manager_socket_context_set, fd);
            close_ex(fd);
        }

        tcp_manager_socket_context_release(oldest_sctx);
    }

    return SUCCESS;
}

static bool tcp_manager_initialised = FALSE;

/**
 * Acquires a TCP connection, ensuring exclusive access to the stream.
 */
tcp_manager_socket_context_t*
tcp_manager_context_acquire(int sockfd)
{
    tcp_manager_socket_context_t* sctx = NULL;

    mutex_lock(&tcp_manager_socket_context_set_mtx);
    u32_node *node = u32_set_find(&tcp_manager_socket_context_set, sockfd);
    if(node != NULL)
    {
        sctx = (tcp_manager_socket_context_t*)node->value;
        tcp_manager_socket_context_acquire(sctx);
    }
    mutex_unlock(&tcp_manager_socket_context_set_mtx);

    return sctx;
}

/**
 * Releases a TCP connection.
 */
void
tcp_manager_context_release(tcp_manager_socket_context_t *sctx)
{
    tcp_manager_socket_context_release(sctx);
}

void
tcp_manager_context_close_and_release(tcp_manager_socket_context_t *sctx)
{
    sctx->close_time = timeus();
    tcp_manager_socket_context_release(sctx);
}

ya_result
tcp_manager_write(tcp_manager_socket_context_t *sctx, const u8 *buffer, size_t buffer_size)
{
    int n = write(sctx->sockfd, buffer, buffer_size);
    if(n > 0)
    {
        tcp_manager_socket_context_mru_to_head(sctx);

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
    if(n > 0)
    {
        tcp_manager_socket_context_mru_to_head(sctx);

        spinlock_lock(&sctx->spinlock);
        sctx->bytes_read += n;
        sctx->read_time = timeus();
        spinlock_unlock(&sctx->spinlock);
    }

    return n;
}

ya_result
tcp_manager_read_fully(tcp_manager_socket_context_t *sctx, u8 *buffer, size_t buffer_size)
{
    const u8 *buffer_limit = &buffer[buffer_size];
    const u8 *buffer_base = buffer;

    while(buffer < buffer_limit)
    {
        int n = read(sctx->sockfd, buffer, buffer_size);

        if(n > 0)
        {
            tcp_manager_socket_context_mru_to_head(sctx);

            spinlock_lock(&sctx->spinlock);
            sctx->bytes_read += n;
            sctx->read_time = timeus();
            spinlock_unlock(&sctx->spinlock);
            buffer += n;
        }
        else
        {
            if(n < 0)
            {
                int err = errno;
                if(err == EINTR)
                {
                    continue;
                }

                if(dnscore_shuttingdown())
                {
                    return STOPPED_BY_APPLICATION_SHUTDOWN;
                }
#if __FreeBSD__
                if(err == EAGAIN)
                {
                    continue;
                }
#endif
                if(err == ETIMEDOUT)
                {
                    if(buffer - buffer_base > 0)
                    {
                        // partial read and a timeout ...
                        continue;
                    }
                }

                return MAKE_ERRNO_ERROR(err);
            }
            else
            {
                // EOF
                return buffer - buffer_base;
            }
        }
    }

    return buffer - buffer_base;
}

void
tcp_manager_write_update(tcp_manager_socket_context_t *sctx, size_t n)
{
    tcp_manager_socket_context_mru_to_head(sctx);

    spinlock_lock(&sctx->spinlock);
    sctx->bytes_written += n;
    sctx->write_time = timeus();
    spinlock_unlock(&sctx->spinlock);
}

void
tcp_manager_read_update(tcp_manager_socket_context_t *sctx, size_t n)
{
    tcp_manager_socket_context_mru_to_head(sctx);

    spinlock_lock(&sctx->spinlock);
    sctx->bytes_read += n;
    sctx->read_time = timeus();
    spinlock_unlock(&sctx->spinlock);
}

ya_result
tcp_manager_close(tcp_manager_socket_context_t *sctx)
{
    ya_result ret;

    if(sctx->close_time == 0)
    {
        sctx->close_time = timeus();
        ret = SUCCESS;
    }
    else
    {
        ret = ERROR; // already closed
    }

    return ret;
}

socketaddress*
tcp_manager_socketaddress(tcp_manager_socket_context_t *sctx)
{
    return &sctx->host->addr;
}

socklen_t
tcp_manager_socklen(tcp_manager_socket_context_t *sctx)
{
    return sctx->host->addr_len;
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

void
tcp_manager_init()
{
    if(!tcp_manager_initialised)
    {
        tcp_manager_initialised = TRUE;

        tcp_manager_host_context_class_init();
        tcp_manager_socket_context_class_init();
    }
}

ya_result
tcp_manager_host_register(socketaddress *sa, socklen_t sa_len, s32 allowed_connections_max)
{
    tcp_manager_host_context_t *ctx = tcp_manager_host_context_new_instance(sa, sa_len, allowed_connections_max, TRUE);
    (void)ctx;
    return SUCCESS;
}

ya_result
tcp_manager_connection_max(s32 allowed_connections_max)
{
    if(allowed_connections_max <= 0)
    {
        allowed_connections_max = TCP_MANAGER_HOST_CONTEXT_CONNECTION_COUNT_MAX;
    }

    // unregistered_tcp_manager_host_context.connection_count_max = allowed_connections_max;
    return SUCCESS;
}

ya_result
tcp_manager_accept(int servfd)
{
    ya_result ret;
    socketaddress addr;
    socklen_t addr_len = sizeof(socketaddress);

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
        // check if the host is registered

        s64 now = timeus();

        if(addr_len > MAX(sizeof(struct sockaddr_in),sizeof(struct sockaddr_in6)))
        {
            tcp_set_abortive_close(sockfd);
            close_ex(sockfd);
            return BUFFER_WOULD_OVERFLOW;
        }

        tcp_manager_socket_context_t *sctx;
        tcp_manager_host_context_t *ctx = tcp_manager_host_context_acquire_or_create(&addr, addr_len, 1, FALSE);
        if(FAIL(ret = tcp_manager_host_context_add(ctx, sockfd, &sctx)))
        {
            tcp_manager_host_context_release(ctx);
            tcp_set_abortive_close(sockfd);
            close_ex(sockfd);
            return ERROR; // limit reached
        }

        sctx->accept_time = now;
        tcp_manager_socket_context_release(sctx);
        tcp_manager_host_context_release(ctx);

        return sockfd;
    }
    else
    {
        return ERRNO_ERROR;
    }
}

void tcp_manager_set_recvtimeout(tcp_manager_socket_context_t *sctx, int seconds, int useconds)
{
    tcp_set_recvtimeout(sctx->sockfd, seconds, useconds);
}

void tcp_manager_set_sendtimeout(tcp_manager_socket_context_t *sctx, int seconds, int useconds)
{
    tcp_set_sendtimeout(sctx->sockfd, seconds, useconds);
}

void tcp_manager_set_nodelay(tcp_manager_socket_context_t *sctx, bool enable)
{
    tcp_set_nodelay(sctx->sockfd, enable);
}

void tcp_manager_set_cork(tcp_manager_socket_context_t *sctx, bool enable)
{
    tcp_set_cork(sctx->sockfd, enable);
}

void
tcp_manager_finalize()
{
}
