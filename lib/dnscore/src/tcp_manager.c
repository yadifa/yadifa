/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2023, EURid vzw. All rights reserved.
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
#include <dnscore/service.h>

#define TCPMHCTX_TAG 0x585443484d504354
#define TCPMSCTX_TAG 0x585443534d504354

typedef struct tcp_manager_socket_context_s tcp_manager_socket_context_t;

#include "dnscore/tcp_manager.h"

#define MODULE_MSG_HANDLE g_system_logger

// Host

struct tcp_manager_host_context_s
{
    mutex_t connection_list_mtx;
    list_dl_s connection_list;          // should be a set, I just don't know the key yet.
    atomic_int _rc;                     // so it's not destroyed mid-use
    socketaddress addr;                 // the host
    socklen_t addr_len;
    u16 connection_count_max;
    bool persistent;

#if DEBUG
    ptr_set debug_owners;
    mutex_t debug_owners_mtx;
#endif
};

typedef struct tcp_manager_host_context_s tcp_manager_host_context_t;

struct tcp_manager_socket_context_s
{
    tcp_manager_host_context_t *_host;
    int _sockfd;
    atomic_int _rc;
    spinlock_t _spinlock;
    s64 _bytes_read;
    s64 _bytes_written;
    s64 _read_time;
    s64 _write_time;
    s64 _accept_time;
    s64 _close_time;

#if DEBUG
    ptr_set debug_owners;
    mutex_t debug_owners_mtx;
#endif
};

typedef struct tcp_manager_socket_context_s tcp_manager_socket_context_t;

static void tcp_manager_host_context_acquire(tcp_manager_host_context_t *ctx);

static inline tcp_manager_host_context_t *tcp_manager_socket_context_host_get(tcp_manager_socket_context_t *sctx)
{
    tcp_manager_host_context_t *host;
    spinlock_lock(&sctx->_spinlock);
    host = sctx->_host;
    spinlock_unlock(&sctx->_spinlock);
    return host;
}

static inline tcp_manager_host_context_t *tcp_manager_socket_context_host_acquire(tcp_manager_socket_context_t *sctx)
{
    tcp_manager_host_context_t *host;
    spinlock_lock(&sctx->_spinlock);
    host = sctx->_host;
    tcp_manager_host_context_acquire(host);
    spinlock_unlock(&sctx->_spinlock);
    return host;
}

static inline struct sockaddr *tcp_manager_socket_context_sockaddr_get(tcp_manager_socket_context_t *sctx)
{
    struct sockaddr *sa;
    spinlock_lock(&sctx->_spinlock);
    sa = &sctx->_host->addr.sa;
    spinlock_unlock(&sctx->_spinlock);
    return sa;
}

static inline socklen_t tcp_manager_socket_context_sockaddr_length_get(tcp_manager_socket_context_t *sctx)
{
    socklen_t addr_len;
    spinlock_lock(&sctx->_spinlock);
    addr_len = sctx->_host->addr_len;
    spinlock_unlock(&sctx->_spinlock);
    return addr_len;
}

static inline socklen_t* tcp_manager_socket_context_sockaddr_length_get_ptr(tcp_manager_socket_context_t *sctx)
{
    socklen_t *addr_lenp;
    spinlock_lock(&sctx->_spinlock);
    addr_lenp = &sctx->_host->addr_len;
    spinlock_unlock(&sctx->_spinlock);
    return addr_lenp;
}

static inline tcp_manager_host_context_t *tcp_manager_socket_context_host_get_set(tcp_manager_socket_context_t *sctx, tcp_manager_host_context_t *newvalue)
{
    tcp_manager_host_context_t *host;
    spinlock_lock(&sctx->_spinlock);
    host = sctx->_host;
    sctx->_host = newvalue;
    spinlock_unlock(&sctx->_spinlock);
    return host;
}

static inline int tcp_manager_socket_context_socket_get(tcp_manager_socket_context_t *sctx)
{
    int sockfd;
    spinlock_lock(&sctx->_spinlock);
    sockfd = sctx->_sockfd;
    spinlock_unlock(&sctx->_spinlock);
    return sockfd;
}

static inline int tcp_manager_socket_context_socket_get_set(tcp_manager_socket_context_t *sctx, int newvalue)
{
    int sockfd;
    spinlock_lock(&sctx->_spinlock);
    sockfd = sctx->_sockfd;
    sctx->_sockfd = newvalue;
    spinlock_unlock(&sctx->_spinlock);
    return sockfd;
}

static inline s64 tcp_manager_socket_context_close_time_get(tcp_manager_socket_context_t *sctx)
{
    s64 close_time;
    spinlock_lock(&sctx->_spinlock);
    close_time = sctx->_close_time;
    spinlock_unlock(&sctx->_spinlock);
    return close_time;
}

static inline void tcp_manager_socket_context_close_time_set(tcp_manager_socket_context_t *sctx, s64 t)
{
    spinlock_lock(&sctx->_spinlock);
    sctx->_close_time = t;
    spinlock_unlock(&sctx->_spinlock);
}

static inline bool tcp_manager_socket_context_close_time_set_if_zero(tcp_manager_socket_context_t *sctx, s64 t)
{
    bool zero;
    spinlock_lock(&sctx->_spinlock);
    zero = (sctx->_close_time == 0);
    if(zero)
    {
        sctx->_close_time = t;
    }
    spinlock_unlock(&sctx->_spinlock);
    return zero;
}

static inline s64 tcp_manager_socket_context_read_time_get(tcp_manager_socket_context_t *sctx)
{
    s64 read_time;
    spinlock_lock(&sctx->_spinlock);
    read_time = sctx->_read_time;
    spinlock_unlock(&sctx->_spinlock);
    return read_time;
}

static inline s64 tcp_manager_socket_context_write_time_get(tcp_manager_socket_context_t *sctx)
{
    s64 write_time;
    spinlock_lock(&sctx->_spinlock);
    write_time = sctx->_write_time;
    spinlock_unlock(&sctx->_spinlock);
    return write_time;
}

static inline void tcp_manager_socket_context_times_get(tcp_manager_socket_context_t *sctx, s64 *read_timep, s64 *write_timep, s64 *accept_timep, s64 *close_timep)
{
    spinlock_lock(&sctx->_spinlock);
    if(read_timep != NULL)
    {
        *read_timep = sctx->_read_time;
    }
    if(write_timep != NULL)
    {
        *write_timep = sctx->_write_time;
    }
    if(accept_timep != NULL)
    {
        *accept_timep = sctx->_accept_time;
    }
    if(close_timep != NULL)
    {
        *close_timep = sctx->_close_time;
    }
    spinlock_unlock(&sctx->_spinlock);
}

static inline s64 tcp_manager_socket_context_accept_time_get(tcp_manager_socket_context_t *sctx)
{
    s64 accept_time;
    spinlock_lock(&sctx->_spinlock);
    accept_time = sctx->_accept_time;
    spinlock_unlock(&sctx->_spinlock);
    return accept_time;
}

static inline void tcp_manager_socket_context_accept_time_set(tcp_manager_socket_context_t *sctx, s64 t)
{
    spinlock_lock(&sctx->_spinlock);
    sctx->_accept_time = t;
    spinlock_unlock(&sctx->_spinlock);
}

static inline void tcp_manager_socket_context_mark_closed(tcp_manager_socket_context_t *sctx)
{
    s64 now = timeus();
    spinlock_lock(&sctx->_spinlock);
    sctx->_sockfd = -1;
    sctx->_close_time = now;
    spinlock_unlock(&sctx->_spinlock);
}

static inline void tcp_manager_socket_context_bytes_written_add(tcp_manager_socket_context_t *sctx, s64 n)
{
    s64 now = timeus();
    spinlock_lock(&sctx->_spinlock);
    sctx->_bytes_written += n;
    sctx->_read_time = now;
    spinlock_unlock(&sctx->_spinlock);
}

static inline void tcp_manager_socket_context_bytes_read_add(tcp_manager_socket_context_t *sctx, s64 n)
{
    s64 now = timeus();
    spinlock_lock(&sctx->_spinlock);
    sctx->_bytes_read += n;
    sctx->_read_time = now;
    spinlock_unlock(&sctx->_spinlock);
}

static ptr_set tcp_manager_host_context_set;
static mutex_t tcp_manager_host_context_set_mtx;

static u32_set tcp_manager_socket_context_set = U32_SET_EMPTY;
static mutex_t tcp_manager_socket_context_set_mtx = MUTEX_INITIALIZER;

static int tcp_manager_unregistered_host_connection_max = 1;

static bool
tcp_manager_sockfd_eof(int sockfd)
{
    if(sockfd >= 0)
    {
        u8 tmp[1];
        int n = recv(sockfd, tmp, 1, MSG_PEEK|MSG_DONTWAIT);
        return n == 0;
    }
    else
    {
        return TRUE;
    }
}

static bool tcp_manager_socket_context_eof(tcp_manager_socket_context_t *sctx);

static struct service_s tcp_manager_socket_handler = UNINITIALIZED_SERVICE;

static int tcp_manager_socket_handler_service(struct service_worker_s *worker)
{
    ptr_vector clean_list;
    ptr_vector_init_empty(&clean_list);

    while(service_should_run(worker))
    {
        if(mutex_trylock(&tcp_manager_socket_context_set_mtx))
        {
            u32_set_iterator iter;
            u32_set_iterator_init(&tcp_manager_socket_context_set, &iter);
            while(u32_set_iterator_hasnext(&iter))
            {
                u32_node *node = u32_set_iterator_next_node(&iter);

                tcp_manager_socket_context_t *sctx = (tcp_manager_socket_context_t*)node->value;

                int fd = tcp_manager_socket_context_socket_get(sctx);

                if(fd >= 0)
                {
                    if(tcp_manager_sockfd_eof(fd))
                    {
                        ptr_vector_append(&clean_list, sctx);
                    }
                }
            }

            for(int i = 0; i <= ptr_vector_last_index(&clean_list); ++i)
            {
                tcp_manager_socket_context_t *sctx = (tcp_manager_socket_context_t*)ptr_vector_get(&clean_list, i);

                int fd = tcp_manager_socket_context_socket_get_set(sctx, -1);

                if(fd >= 0)
                {
                    u32_set_delete(&tcp_manager_socket_context_set, fd);
                    tcp_manager_socket_context_mark_closed(sctx);
                    close_ex(fd);
#if DEBUG
                    log_debug2("tcp-manager: connection %p/%i removed from socket context set", sctx, fd);
#endif
                }
            }

            ptr_vector_clear(&clean_list);

            mutex_unlock(&tcp_manager_socket_context_set_mtx);
        }

        usleep(ONE_SECOND_US);
    }

    ptr_vector_destroy(&clean_list);

    return 0;
}

static void
tcp_manager_host_context_release(tcp_manager_host_context_t *ctx);
/*
static int
tcp_manager_host_context_init_ptr_set_forall_callback(ptr_node *node, void *args_)
{
    (void)args_;
    tcp_manager_host_context_t *ctx = (tcp_manager_host_context_t*)node->value;
    tcp_manager_host_context_release(ctx);
    return SUCCESS;
}
*/
static void
tcp_manager_host_context_init(tcp_manager_host_context_t *ctx, const socketaddress *addr, socklen_t addr_len, u16 connection_count_max, bool persistent);

static void
tcp_manager_host_context_class_init()
{
    ptr_set_init(&tcp_manager_host_context_set);
    tcp_manager_host_context_set.compare = socketaddress_compare_ip;
    mutex_init_recursive(&tcp_manager_host_context_set_mtx);
}

static void
tcp_manager_host_context_class_finalize()
{
    mutex_lock(&tcp_manager_host_context_set_mtx);
    u32 count = 0;
    ptr_set_iterator iter;
    ptr_set_iterator_init(&tcp_manager_host_context_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_set_iterator_next_node(&iter);
        ++count;
    }
    if(count > 0)
    {
        tcp_manager_host_context_t **contextes;
        MALLOC_OBJECT_ARRAY_OR_DIE(contextes, tcp_manager_host_context_t*, count, TCPMHCTX_TAG);
        ptr_set_iterator_init(&tcp_manager_host_context_set, &iter);
        count = 0;
        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *node = ptr_set_iterator_next_node(&iter);
            tcp_manager_host_context_t *ctx = (tcp_manager_host_context_t*)node->value;
            contextes[count++] = ctx;
        }

        for(u32 i = 0; i < count; ++i)
        {
            tcp_manager_host_context_t *ctx = (tcp_manager_host_context_t*)contextes[i];

            if(ctx->persistent)
            {
#if HAVE_STDATOMIC_H
                assert(ctx->_rc >= 2);
#else
                assert(atomic_load(&ctx->_rc) >=  2);
#endif
                tcp_manager_host_context_release(ctx); // doesn't free the ctx
            }

#if HAVE_STDATOMIC
            if(ctx->_rc > 1) // scan-build false positive: ctx hasn't been freed
#else
            if(atomic_load(&ctx->_rc) > 1) // scan-build false positive: ctx hasn't been freed
#endif
            {
                log_err("host context: %{sockaddr} is still referenced %i times", &ctx->addr.sa, ctx->_rc);
            }

            tcp_manager_host_context_release(ctx);
        }

        free(contextes);
    }
    ptr_set_destroy(&tcp_manager_host_context_set);
    mutex_unlock(&tcp_manager_host_context_set_mtx);
    mutex_destroy(&tcp_manager_host_context_set_mtx);
}

static void
tcp_manager_host_context_init(tcp_manager_host_context_t *ctx, const socketaddress *addr, socklen_t addr_len, u16 allowed_connections_max, bool persistent)
{
    if(allowed_connections_max <= 0)
    {
        allowed_connections_max = TCP_MANAGER_HOST_CONTEXT_CONNECTION_COUNT_MAX;
    }

    mutex_init_recursive(&ctx->connection_list_mtx);
    list_dl_init(&ctx->connection_list);
#if HAVE_STDATOMIC_H
    ctx->_rc = 1;
#else
    atomic_store(&ctx->_rc, 1);
#endif
    memcpy(&ctx->addr, addr, addr_len);
    ctx->addr_len = addr_len;
    ctx->connection_count_max = allowed_connections_max;
    ctx->persistent = persistent;

#if DEBUG
    ptr_set_init(&ctx->debug_owners);
    mutex_init(&ctx->debug_owners_mtx);
    ctx->debug_owners.compare = ptr_set_ptr_node_compare;
    ptr_node *debug_owners_node = ptr_set_insert(&ctx->debug_owners, (void*)thread_self());
    ++debug_owners_node->value_s64;
#endif

    if(persistent)
    {
#if HAVE_STDATOMIC_H
        ++ctx->_rc;  /// @todo 20210303 edf -- when persistence is fully implemented, persistent nodes can only be destroyed with the system
#else
        atomic_fetch_add(&ctx->_rc, 1);
#endif
#if DEBUG
        ++debug_owners_node->value_s64;
#endif
    }

#if DEBUG
    log_debug3("tcp-manager: tcp_manager_host_context_init(%p, %{sockaddr}, %u, %u, %i) : initialised", ctx, addr, addr_len, allowed_connections_max, persistent);
#endif
}

static tcp_manager_host_context_t*
tcp_manager_host_context_new_instance_nolock(const socketaddress *addr, socklen_t addr_len, u16 connection_count_max, bool persistent)
{
    tcp_manager_host_context_t *ctx;
    /*
    socketaddress *addr_copy;
    ZALLOC_OBJECT_OR_DIE(addr_copy, socketaddress, G ENERIC_TAG);
    *addr_copy = *addr;
    ptr_node *node = ptr_set_insert(&tcp_manager_host_context_set, addr_copy);
    */
    ptr_node *node = ptr_set_insert(&tcp_manager_host_context_set, (socketaddress*)addr);

    if(node->value == NULL)
    {
#if DEBUG
        if(persistent)
        {
            log_debug1("tcp-manager: registering %{sockaddr} with %hu connections", &addr->sa, connection_count_max);
        }
#endif

        ZALLOC_OBJECT_OR_DIE(ctx, tcp_manager_host_context_t, TCPMHCTX_TAG);
        tcp_manager_host_context_init(ctx, addr, addr_len, connection_count_max, persistent);

        node->key = &ctx->addr;  /// @note it NEEDS to be the one from the node
        node->value = ctx;
#if DEBUG
        log_debug3("tcp-manager: tcp_manager_host_context_new_instance_nolock(%{sockaddr}, %u, %u, %i) : node created", addr, addr_len, connection_count_max, persistent);
#endif
    }
    else
    {
#if DEBUG
        log_debug3("tcp-manager: tcp_manager_host_context_new_instance_nolock(%{sockaddr}, %u, %u, %i) : node exists already", addr, addr_len, connection_count_max, persistent);
#endif
        /*
        ZFREE_OBJECT(addr_copy);
        */
        ctx = (tcp_manager_host_context_t*)node->value;
    }

#if DEBUG
    log_debug3("tcp-manager: tcp_manager_host_context_new_instance_nolock(%{sockaddr}, %u, %u, %i) = %p", addr, addr_len, connection_count_max, persistent, ctx);
#endif

    return ctx;
}

static tcp_manager_host_context_t*
tcp_manager_host_context_new_instance(const socketaddress *addr, socklen_t addr_len, u16 connection_count_max, bool persistent)
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
#if !DEBUG
#if HAVE_STDATOMIC_H
    ++ctx->_rc;
#else
    atomic_fetch_add(&ctx->_rc, 1);
#endif
#else
#if HAVE_STDATOMIC_H
    int rc = ++ctx->_rc;
#else
    int rc = atomic_fetch_add(&ctx->_rc, 1) + 1;
#endif
#endif

#if DEBUG
    mutex_lock(&ctx->debug_owners_mtx);
    ptr_node *debug_owner_node = ptr_set_insert(&ctx->debug_owners, (void*)pthread_self());
    ++debug_owner_node->value_s64;
    mutex_unlock(&ctx->debug_owners_mtx);
#endif
#if DEBUG
    log_debug3("tcp-manager: tcp_manager_host_context_acquire(%p) : rc=%i", ctx, rc);
#endif
}

static tcp_manager_host_context_t*
tcp_manager_host_context_acquire_or_create(socketaddress *addr, socklen_t addr_len, u16 connection_count_max, bool persistent)
{
    tcp_manager_host_context_t *ctx;
    mutex_lock(&tcp_manager_host_context_set_mtx);
    ptr_node *node = ptr_set_find(&tcp_manager_host_context_set, addr);
    if(node == NULL)
    {
#if DEBUG
        log_debug3("tcp-manager: tcp_manager_host_context_acquire_or_create(%{sockaddr}, %u, %u, %i) : creating node", addr, addr_len, connection_count_max, persistent);
#endif
        ctx = tcp_manager_host_context_new_instance_nolock(addr, addr_len, connection_count_max, persistent);
    }
    else
    {
#if DEBUG
        log_debug3("tcp-manager: tcp_manager_host_context_acquire_or_create(%{sockaddr}, %u, %u, %i) : acquiring node", addr, addr_len, connection_count_max, persistent);
#endif

        ctx = (tcp_manager_host_context_t*)node->value;
#if HAVE_STDATOMIC_H
        ++ctx->_rc;
#else
        atomic_fetch_add(&ctx->_rc, 1);
#endif
#if DEBUG
        mutex_lock(&ctx->debug_owners_mtx);
        ptr_node *debug_owner_node = ptr_set_insert(&ctx->debug_owners, (void*)pthread_self());
        ++debug_owner_node->value_s64;
        mutex_unlock(&ctx->debug_owners_mtx);
#endif
    }
#if DEBUG
    log_debug3("tcp-manager: tcp_manager_host_context_acquire_or_create(%{sockaddr}, %u, %u, %i) = %p", addr, addr_len, connection_count_max, persistent, ctx);
#endif
    mutex_unlock(&tcp_manager_host_context_set_mtx);
    return ctx;
}

static void
tcp_manager_host_context_delete(tcp_manager_host_context_t *ctx)
{
#if HAVE_STDATOMIC_H
    assert(ctx->_rc == 0);
#else
    assert(atomic_load(&ctx->_rc) == 0);
#endif

#ifndef NDEBUG
    mutex_lock(&ctx->connection_list_mtx);
    assert(list_dl_size(&ctx->connection_list) == 0);
    mutex_unlock(&ctx->connection_list_mtx);
#endif
    mutex_lock(&tcp_manager_host_context_set_mtx);
    ptr_set_delete(&tcp_manager_host_context_set, &ctx->addr);
    mutex_unlock(&tcp_manager_host_context_set_mtx);
    mutex_destroy(&ctx->connection_list_mtx);

#if DEBUG
    mutex_lock(&ctx->debug_owners_mtx);
    ptr_set_destroy(&ctx->debug_owners);
    mutex_unlock(&ctx->debug_owners_mtx);
    mutex_destroy(&ctx->debug_owners_mtx);
#endif

#if DEBUG
    log_debug3("tcp-manager: tcp_manager_host_context_delete(%p)", ctx);
#endif

    ZFREE_OBJECT(ctx);
}

static void
tcp_manager_host_context_release(tcp_manager_host_context_t *ctx)
{
#if DEBUG
    mutex_lock(&ctx->debug_owners_mtx);
    ptr_node *debug_owner_node = ptr_set_insert(&ctx->debug_owners, (void*)pthread_self());
    --debug_owner_node->value_s64;
    mutex_unlock(&ctx->debug_owners_mtx);
#endif

#if !DEBUG
    #if HAVE_STDATOMIC_H
    if(--ctx->_rc == 0)
#else
    if(atomic_fetch_sub(&ctx->_rc, 1) == 0)
#endif
    {
        tcp_manager_host_context_delete(ctx);
    }
#else
#if HAVE_STDATOMIC_H
    int rc = --ctx->_rc;
#else
    int rc = atomic_fetch_sub(&ctx->_rc, 1) - 1;
#endif
    if(rc == 0)
    {
        log_debug3("tcp-manager: tcp_manager_host_context_release(%p) : not referenced anymore", ctx);
        tcp_manager_host_context_delete(ctx);
    }
    else
    {
        log_debug3("tcp-manager: tcp_manager_host_context_release(%p) : rc=%i", ctx, rc);
    }
#endif
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

    u32_set_iterator iter;
    u32_set_iterator_init(&tcp_manager_socket_context_set, &iter);
    while(u32_set_iterator_hasnext(&iter))
    {
        u32_node *node = u32_set_iterator_next_node(&iter);

        tcp_manager_socket_context_t *sctx = (tcp_manager_socket_context_t*)node->value;

        int fd = tcp_manager_socket_context_socket_get(sctx);

        if(fd >= 0)
        {
            if(tcp_manager_sockfd_eof(fd))
            {
                tcp_manager_socket_context_mark_closed(sctx);
                close_ex(fd);
            }
        }
    }

    mutex_unlock(&tcp_manager_socket_context_set_mtx);
    u32_set_destroy(&tcp_manager_socket_context_set);
    mutex_destroy(&tcp_manager_socket_context_set_mtx);
}

static tcp_manager_socket_context_t*
tcp_manager_socket_context_new_instance_nolock(tcp_manager_host_context_t *ctx, int sockfd)
{
    u32_node *node = u32_set_insert(&tcp_manager_socket_context_set, sockfd);

    tcp_manager_socket_context_t *old_sctx = (tcp_manager_socket_context_t*)node->value;
    if(old_sctx != NULL)
    {
        tcp_manager_socket_context_mark_closed(old_sctx);
    }

    tcp_manager_socket_context_t *sctx;
    ZALLOC_OBJECT_OR_DIE(sctx, tcp_manager_socket_context_t, TCPMSCTX_TAG);
    tcp_manager_host_context_acquire(ctx);
    sctx->_host = ctx;
    sctx->_sockfd = sockfd;
#if HAVE_STDATOMIC_H
    sctx->_rc = 1;
#else
    atomic_store(&sctx->_rc, 1);
#endif
    spinlock_init(&sctx->_spinlock);
    sctx->_bytes_read = 0;
    sctx->_bytes_written = 0;
    sctx->_read_time = 0;
    sctx->_write_time = 0;
    sctx->_accept_time = 0;
    sctx->_close_time = 0;

#if DEBUG
    ptr_set_init(&sctx->debug_owners);
    mutex_init(&sctx->debug_owners_mtx);
    sctx->debug_owners.compare = ptr_set_ptr_node_compare;
    ptr_node *debug_owners_node = ptr_set_insert(&sctx->debug_owners, (void*)thread_self());
    ++debug_owners_node->value_s64;

    log_debug2("tcp-manager: connection %p/%i, +owner=%p,%lli (new)", sctx, tcp_manager_socket_context_socket_get(sctx), (void*)thread_self(), debug_owners_node->value_s64);

    log_debug3("tcp-manager: tcp_manager_socket_context_new_instance_nolock(%p, %i) = %p", ctx, sockfd, sctx);
#endif

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
#if DEBUG
    log_debug3("tcp-manager: tcp_manager_socket_context_delete(%p)", sctx);
#endif
    tcp_manager_socket_context_mru_remove(sctx);

    mutex_lock(&tcp_manager_socket_context_set_mtx);
    int fd = tcp_manager_socket_context_socket_get(sctx);
    if(fd >= 0)
    {
        u32_set_delete(&tcp_manager_socket_context_set, fd);
        tcp_manager_socket_context_mark_closed(sctx);
        close_ex(fd);
#if DEBUG
        log_debug2("tcp-manager: connection %p/%i removed from socket context set", sctx, fd);

        log_debug3("tcp-manager: tcp_manager_socket_context_delete(%p) : sockfd=%i", sctx, fd);
#endif
    }

#if DEBUG
    mutex_lock(&sctx->debug_owners_mtx);
    ptr_set_destroy(&sctx->debug_owners);
    mutex_unlock(&sctx->debug_owners_mtx);
    mutex_destroy(&sctx->debug_owners_mtx);
#endif

    spinlock_destroy(&sctx->_spinlock);
    mutex_unlock(&tcp_manager_socket_context_set_mtx);
    ZFREE_OBJECT(sctx);
}

static void
tcp_manager_socket_context_acquire(tcp_manager_socket_context_t *sctx)
{
#if !DEBUG
#if HAVE_STDATOMIC_H
    ++sctx->_rc;
#else
    atomic_fetch_add(&sctx->_rc, 1);
#endif
#else
#if HAVE_STDATOMIC_H
    int rc = ++sctx->_rc;
#else
    int rc = atomic_fetch_add(&sctx->_rc, 1) + 1;
#endif
#endif

#if DEBUG
    mutex_lock(&sctx->debug_owners_mtx);
    ptr_node *debug_owners_node = ptr_set_insert(&sctx->debug_owners, (void*)pthread_self());
    ++debug_owners_node->value_s64;

    log_debug2("tcp-manager: connection %p/%i, +owner=%p,%lli", sctx, tcp_manager_socket_context_socket_get(sctx), (void*)thread_self(), debug_owners_node->value_s64);

    mutex_unlock(&sctx->debug_owners_mtx);
#endif

#if DEBUG
    log_debug3("tcp-manager: tcp_manager_socket_context_acquire(%p) : rc=%i", sctx, rc);
#endif

#if DEBUG
    //log_debug1("tcp-manager: %{sockaddr} acquire connection %p/%i, accept=%llT write=%llT read=%llT rc=%i", tcp_manager_socket_context_sockaddr_get(sctx), sctx, tcp_manager_socket_context_socket_get(sctx), tcp_manager_socket_context_accept_time_get(sctx), tcp_manager_socket_context_write_time_get(sctx), tcp_manager_socket_context_read_time_get(sctx), sctx->_rc);
#endif
}

static void
tcp_manager_socket_context_release(tcp_manager_socket_context_t *sctx)
{
    tcp_manager_host_context_t *host = tcp_manager_socket_context_host_acquire(sctx);
    mutex_lock(&host->connection_list_mtx);

#if DEBUG
    mutex_lock(&sctx->debug_owners_mtx);
    ptr_node *debug_owners_node = ptr_set_insert(&sctx->debug_owners, (void*)pthread_self());
    --debug_owners_node->value_s64;

    log_debug2("tcp-manager: connection %p/%i, -owner=%p,%lli", sctx, tcp_manager_socket_context_socket_get(sctx), (void*)thread_self(), debug_owners_node->value_s64);

    mutex_unlock(&sctx->debug_owners_mtx);
#endif

#if !DEBUG
#if HAVE_STDATOMIC_H
    if(--sctx->_rc == 0)
#else
    if(atomic_fetch_sub(&sctx->_rc, 1) == 0)
#endif
    {
        if(tcp_manager_socket_context_close_time_get(sctx) > 0) // really closed
        {

            tcp_manager_socket_context_delete(sctx);
        }
    }

#else // DEBUG

#if HAVE_STDATOMIC_H
    int rc = --sctx->_rc;
#else
    int rc = atomic_fetch_sub(&sctx->_rc, 1) - 1;
#endif
    if(rc == 0)
    {
        log_debug3("tcp-manager: tcp_manager_socket_context_release(%p) : not referenced anymore", sctx, rc);

        if(tcp_manager_socket_context_close_time_get(sctx) > 0) // really closed
        {
            log_debug3("tcp-manager: tcp_manager_socket_context_release(%p) : has been closed", sctx, rc);

            log_debug1("tcp-manager: %{sockaddr} release connection %p/%i, accept=%llT write=%llT read=%llT close=%llT", tcp_manager_socket_context_sockaddr_get(sctx), sctx, tcp_manager_socket_context_socket_get(sctx), tcp_manager_socket_context_accept_time_get(sctx), tcp_manager_socket_context_write_time_get(sctx), tcp_manager_socket_context_read_time_get(sctx), tcp_manager_socket_context_close_time_get(sctx));
            tcp_manager_socket_context_delete(sctx);
        }
        else
        {
            log_debug1("tcp-manager: %{sockaddr} connection %p/%i, accept=%llT write=%llT read=%llT", tcp_manager_socket_context_sockaddr_get(sctx), sctx, tcp_manager_socket_context_socket_get(sctx), tcp_manager_socket_context_accept_time_get(sctx), tcp_manager_socket_context_write_time_get(sctx), tcp_manager_socket_context_read_time_get(sctx));
        }
    }
    else
    {
        log_debug1("tcp-manager: %{sockaddr} connection %p/%i, accept=%llT write=%llT read=%llT rc=%i", tcp_manager_socket_context_sockaddr_get(sctx), sctx, tcp_manager_socket_context_socket_get(sctx), tcp_manager_socket_context_accept_time_get(sctx), tcp_manager_socket_context_write_time_get(sctx), tcp_manager_socket_context_read_time_get(sctx), rc);

        log_debug3("tcp-manager: tcp_manager_socket_context_release(%p) : rc=%i", sctx, rc);
    }
#endif

    mutex_unlock(&host->connection_list_mtx);
    tcp_manager_host_context_release(host);
}

static void
tcp_manager_socket_context_mru_to_head(tcp_manager_socket_context_t *sctx)
{
    tcp_manager_host_context_t *host = tcp_manager_socket_context_host_get(sctx);

    mutex_lock(&host->connection_list_mtx);
#if DEBUG
    log_debug3("tcp-manager: tcp_manager_socket_context_mru_to_head(%p)", sctx);
#endif
    list_dl_move_to_first_position(&host->connection_list, sctx);
    mutex_unlock(&host->connection_list_mtx);
}

static void
tcp_manager_socket_context_mru_remove(tcp_manager_socket_context_t *sctx)
{
    tcp_manager_host_context_t *host = tcp_manager_socket_context_host_get_set(sctx, NULL);

    if(host != NULL)
    {
        mutex_lock(&host->connection_list_mtx);
#if DEBUG
        log_debug3("tcp-manager: tcp_manager_socket_context_mru_remove(%p)", sctx);
#endif
        list_dl_remove(&host->connection_list, sctx);
        mutex_unlock(&host->connection_list_mtx);

        tcp_manager_host_context_release(host);
    }
#if DEBUG
    else
    {
        log_debug3("tcp-manager: tcp_manager_socket_context_mru_remove(%p) : host is NULL", sctx);
    }
#endif
}

static bool
tcp_manager_socket_context_eof(tcp_manager_socket_context_t *sctx)
{
    int fd = tcp_manager_socket_context_socket_get(sctx);

    if(fd < 0)
    {
        return TRUE;
    }

    // actually closed on the other side?

    u8 tmp[1];
    int n = recv(fd, tmp, 1, MSG_PEEK|MSG_DONTWAIT);
    return n == 0;
}

static bool
tcp_manager_socket_context_in_use(tcp_manager_socket_context_t *sctx)
{
    s64 now = timeus();

    // closed ?

    if(tcp_manager_socket_context_eof(sctx))
    {
        return FALSE;
    }

    // check how long it has been IDLE.

    s64 read_time;
    s64 write_time;
    s64 accept_time;
    s64 close_time;
    tcp_manager_socket_context_times_get(sctx, &read_time, &write_time, &accept_time, &close_time);

    if((close_time != 0) &&
        (
        ((read_time + write_time == 0)  && ((now - accept_time) < ONE_SECOND_US)) ||
        ((read_time > 0)  && ((now - read_time) < ONE_SECOND_US)) ||
        ((write_time > 0)  && ((now - write_time) < ONE_SECOND_US))
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

#if DEBUG
    log_debug3("tcp-manager: tcp_manager_host_context_add(%p, %i, %p)", ctx, sockfd, out_sctxp);
#endif

    s32 mru_size = (s32)list_dl_size(&ctx->connection_list);
    if(mru_size >= ctx->connection_count_max)
    {
        list_dl_node_s* node = list_dl_last_node(&ctx->connection_list);

        // node->data
        oldest_sctx = (tcp_manager_socket_context_t*)node->data;

        if(tcp_manager_socket_context_in_use(oldest_sctx))
        {
#if DEBUG
            log_debug3("tcp-manager: tcp_manager_host_context_add(%p, %i, %p) : connection count max reached and oldest (%p) still in use = ERROR", ctx, sockfd, out_sctxp, oldest_sctx);
#endif
            mutex_unlock(&ctx->connection_list_mtx);
            return ERROR;
        }

#if DEBUG
        log_debug3("tcp-manager: tcp_manager_host_context_add(%p, %i, %p) : connection count max (%hu) reached, acquiring oldest (%p)", ctx, sockfd, out_sctxp, ctx->connection_count_max, oldest_sctx);
#endif

        // acquire it so it will still be valid
        tcp_manager_socket_context_acquire(oldest_sctx);
    }

    tcp_manager_socket_context_t *sctx = tcp_manager_socket_context_new_instance(ctx, sockfd);

    assert(sctx != NULL);

    // insert

    //tcp_manager_socket_context_acquire(sctx);
    list_dl_insert(&ctx->connection_list, sctx);

    if(out_sctxp != NULL)
    {
        tcp_manager_socket_context_acquire(sctx);
        *out_sctxp = sctx;
#if DEBUG
        log_debug3("tcp-manager: tcp_manager_host_context_add(%p, %i, %p) -> %p", ctx, sockfd, out_sctxp, sctx);
#endif
    }

    tcp_manager_socket_context_release(sctx);

    mutex_unlock(&ctx->connection_list_mtx);

    if(oldest_sctx != NULL)
    {
        int fd = tcp_manager_socket_context_socket_get(oldest_sctx);

        if(fd >= 0)
        {
            mutex_lock(&tcp_manager_socket_context_set_mtx);
            u32_set_delete(&tcp_manager_socket_context_set, fd);
            mutex_unlock(&tcp_manager_socket_context_set_mtx);
            tcp_manager_socket_context_mark_closed(oldest_sctx);
            close_ex(fd);
#if DEBUG
            log_debug2("tcp-manager: connection %p/%i removed from socket context set", oldest_sctx, fd);

            log_debug3("tcp-manager: tcp_manager_host_context_add(%p, %i, %p) closing oldest socket context", ctx, sockfd, out_sctxp);
#endif
        }

        tcp_manager_socket_context_release(oldest_sctx);
    }

#if DEBUG
    log_debug3("tcp-manager: tcp_manager_host_context_add(%p, %i, %p) = SUCCESS", ctx, sockfd, out_sctxp);
#endif

    return SUCCESS;
}

static bool tcp_manager_initialised = FALSE;

/**
 * Acquires a TCP connection, ensuring exclusive access to the stream.
 */
tcp_manager_socket_context_t*
tcp_manager_context_acquire_from_socket(int sockfd)
{
#if DEBUG
    log_debug1("tcp-manager: acquire from socket %i", sockfd);
#endif

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
 * Acquires a TCP connection, ensuring exclusive access to the stream.
 */
tcp_manager_socket_context_t*
tcp_manager_context_acquire(tcp_manager_socket_context_t *sctx)
{
    tcp_manager_socket_context_acquire(sctx);
    return sctx;
}

/**
 * Releases a TCP connection.
 */
void
tcp_manager_context_release(tcp_manager_socket_context_t *sctx)
{
#if DEBUG
    log_debug3("tcp-manager: tcp_manager_context_release(%p)", sctx);
#endif
    tcp_manager_socket_context_release(sctx);
}

void
tcp_manager_context_close_and_release(tcp_manager_socket_context_t *sctx)
{
#if DEBUG
    log_debug3("tcp-manager: tcp_manager_context_close_and_release(%p)", sctx);
#endif
    tcp_manager_socket_context_close_time_set(sctx, timeus());
    tcp_manager_socket_context_release(sctx);
}

ya_result
tcp_manager_write(tcp_manager_socket_context_t *sctx, const u8 *buffer, size_t buffer_size)
{
#if DEBUG
    log_debug3("tcp-manager: tcp_manager_write(%p, %p, %i)", sctx, buffer, buffer_size);
#endif

    int fd = tcp_manager_socket_context_socket_get(sctx);

    int n = write(fd, buffer, buffer_size);

    if(n > 0)
    {
        tcp_manager_socket_context_mru_to_head(sctx);
        tcp_manager_socket_context_bytes_written_add(sctx, n);
    }

    return n;
}

ya_result
tcp_manager_read(tcp_manager_socket_context_t *sctx, u8 *buffer, size_t buffer_size)
{
#if DEBUG
    log_debug3("tcp-manager: tcp_manager_read(%p, %p, %i)", sctx, buffer, buffer_size);
#endif
    int fd = tcp_manager_socket_context_socket_get(sctx);

    int n = read(fd, buffer, buffer_size);

    if(n > 0)
    {
        tcp_manager_socket_context_mru_to_head(sctx);
        tcp_manager_socket_context_bytes_read_add(sctx, n);
    }

    return n;
}

ya_result
tcp_manager_read_fully(tcp_manager_socket_context_t *sctx, u8 *buffer, size_t buffer_size)
{
#if DEBUG
    log_debug3("tcp-manager: tcp_manager_read_fully(%p, %p, %i)", sctx, buffer, buffer_size);
#endif

    const u8 *buffer_limit = &buffer[buffer_size];
    const u8 *buffer_base = buffer;

    int fd = tcp_manager_socket_context_socket_get(sctx);

    while(buffer < buffer_limit)
    {
        int n = read(fd, buffer, buffer_size);

        if(n > 0)
        {
            tcp_manager_socket_context_mru_to_head(sctx);
            tcp_manager_socket_context_bytes_read_add(sctx, n);
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
#if DEBUG
    log_debug3("tcp-manager: tcp_manager_write_update(%p, %i)", sctx, n);
#endif

    tcp_manager_socket_context_mru_to_head(sctx);
    tcp_manager_socket_context_bytes_written_add(sctx, n);
}

void
tcp_manager_read_update(tcp_manager_socket_context_t *sctx, size_t n)
{
#if DEBUG
    log_debug3("tcp-manager: tcp_manager_read_update(%p, %i)", sctx, n);
#endif

    tcp_manager_socket_context_mru_to_head(sctx);
    tcp_manager_socket_context_bytes_read_add(sctx, n);
}

ya_result
tcp_manager_close(tcp_manager_socket_context_t *sctx)
{
#if DEBUG
    log_debug3("tcp-manager: tcp_manager_close(%p)", sctx);
#endif

    ya_result ret;

    if(tcp_manager_socket_context_close_time_set_if_zero(sctx, timeus()))
    {
        ret = SUCCESS;
    }
    else
    {
        ret = ERROR; // already closed
    }

    return ret;
}

struct sockaddr*
tcp_manager_sockaddr(tcp_manager_socket_context_t *sctx)
{
    struct sockaddr *sa = tcp_manager_socket_context_sockaddr_get(sctx);
    return sa;
}

socklen_t
tcp_manager_socklen(tcp_manager_socket_context_t *sctx)
{
    socklen_t addr_len = tcp_manager_socket_context_sockaddr_length_get(sctx);
    return addr_len;
}

socklen_t*
tcp_manager_socklenp(tcp_manager_socket_context_t *sctx)
{
    socklen_t *addr_lenp = tcp_manager_socket_context_sockaddr_length_get_ptr(sctx);
    return addr_lenp;
}

int
tcp_manager_socket(tcp_manager_socket_context_t *sctx)
{
    int fd = tcp_manager_socket_context_socket_get(sctx);
    return fd;
}

bool
tcp_manager_is_valid(tcp_manager_socket_context_t *sctx)
{
    if(sctx != NULL)
    {
        int fd = tcp_manager_socket_context_socket_get(sctx);

        if(fd >= 0)
        {
            s64 close_time = tcp_manager_socket_context_close_time_get(sctx);

            return close_time == 0;
        }
    }

    return FALSE;
}

void
tcp_manager_init()
{
    if(!tcp_manager_initialised)
    {
        tcp_manager_initialised = TRUE;

        tcp_manager_host_context_class_init();
        tcp_manager_socket_context_class_init();

        ya_result ret;
        if(ISOK(ret = service_init(&tcp_manager_socket_handler, tcp_manager_socket_handler_service, "tcpmgr")))
        {
            service_start(&tcp_manager_socket_handler);
        }
    }
}

void
tcp_manager_finalise()
{
    if(tcp_manager_initialised)
    {
        service_finalize(&tcp_manager_socket_handler);
        tcp_manager_socket_context_class_finalize();
        tcp_manager_host_context_class_finalize();
        tcp_manager_initialised = FALSE;
    }
}

ya_result
tcp_manager_host_register(const socketaddress *sa, socklen_t sa_len, s32 allowed_connections_max)
{
    if(allowed_connections_max <= 0)
    {
        allowed_connections_max = TCP_MANAGER_REGISTERED_HOST_CONTEXT_CONNECTION_COUNT_MAX;
    }

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

    tcp_manager_unregistered_host_connection_max = allowed_connections_max;
    return SUCCESS;
}

ya_result
tcp_manager_accept(int servfd, tcp_manager_socket_context_t **sctxp)
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
            return MAKE_ERRNO_ERROR(err);
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

#if DEBUG
        log_debug1("tcp-manager: %{sockaddr} connected", &addr.sa);
#endif

        tcp_manager_socket_context_t *sctx;
        tcp_manager_host_context_t *ctx = tcp_manager_host_context_acquire_or_create(&addr, addr_len, tcp_manager_unregistered_host_connection_max, FALSE);
        if(FAIL(ret = tcp_manager_host_context_add(ctx, sockfd, &sctx)))
        {
#if DEBUG
            log_debug1("tcp-manager: %{sockaddr} host connection limit reached (%hu)", &addr.sa, ctx->connection_count_max);

            log_debug3("tcp-manager: tcp_manager_accept(%i, %p) : host connection limit reached = ERROR", servfd, sctxp);
#endif
            tcp_manager_host_context_release(ctx);
            tcp_set_abortive_close(sockfd);
            close_ex(sockfd);
            return ERROR; // limit reached
        }

#if DEBUG
        u32 ctx_connection_list_size = list_dl_size(&ctx->connection_list);
        u16 ctx_connection_count_max = ctx->connection_count_max;
#endif

        yassert(sctx != NULL);

        tcp_manager_socket_context_accept_time_set(sctx, now); // scan-build false positive: 1 + 1 - 1 > 0 => not freed

        if(sctxp != NULL)
        {
            *sctxp = sctx;
        }
        else
        {
            tcp_manager_socket_context_release(sctx);
        }
        tcp_manager_host_context_release(ctx);

#if DEBUG
        mutex_lock(&ctx->connection_list_mtx);
        log_debug1("tcp-manager: %{sockaddr} accepted (%i/%hu)", &addr.sa, ctx_connection_list_size, ctx_connection_count_max); // scan-build false positive: ctx hasn't been deleted

        log_debug3("tcp-manager: tcp_manager_accept(%i, %p) = %i", servfd, sctxp, sockfd);
        mutex_unlock(&ctx->connection_list_mtx);
#endif

        return sockfd;
    }
    else
    {
#if DEBUG
        log_debug3("tcp-manager: tcp_manager_accept(%i, %p) = ERROR", servfd, sctxp);
#endif
        return ERRNO_ERROR;
    }
}

void tcp_manager_set_recvtimeout(tcp_manager_socket_context_t *sctx, int seconds, int useconds)
{
    tcp_set_recvtimeout(tcp_manager_socket_context_socket_get(sctx), seconds, useconds);
}

void tcp_manager_set_sendtimeout(tcp_manager_socket_context_t *sctx, int seconds, int useconds)
{
    tcp_set_sendtimeout(tcp_manager_socket_context_socket_get(sctx), seconds, useconds);
}

void tcp_manager_set_nodelay(tcp_manager_socket_context_t *sctx, bool enable)
{
    tcp_set_nodelay(tcp_manager_socket_context_socket_get(sctx), enable);
}

void tcp_manager_set_cork(tcp_manager_socket_context_t *sctx, bool enable)
{
    tcp_set_cork(tcp_manager_socket_context_socket_get(sctx), enable);
}

void
tcp_manager_finalize()
{
}
