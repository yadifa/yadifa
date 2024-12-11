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

#define __TCP_MANAGER2_C__ 1

#include "dnscore/tcp_manager2.h"
#include "dnscore/zalloc.h"
#include "dnscore/fdtools.h"
#include "dnscore/dns_message.h"
#include "dnscore/thread_pool.h"
#include "dnscore/ptr_treemap.h"

#include "dnscore/logger.h"

extern logger_handle_t *g_system_logger;
#define MODULE_MSG_HANDLE                                        g_system_logger

#define TCP_MANAGER_HOST_CONTEXT_CONNECTION_COUNT_MAX            2
#define TCP_MANAGER_REGISTERED_HOST_CONTEXT_CONNECTION_COUNT_MAX 16

#define TCPM2CQU_TAG                                             0x555143324d504354

struct tcp_manager_channel_quota_s
{
    mutex_t         mtx;
    socketaddress_t sa;
    ptr_vector_t    channels;
    int             connection_max;
    bool            dynamic;
};

typedef struct tcp_manager_channel_quota_s tcp_manager_channel_quota_t;
static ptr_treemap_t                       tcp_manager_channel_quota_map = PTR_TREEMAP_SOCKETADDRESS_EMPTY;
static mutex_t                             tcp_manager_channel_quota_map_mtx = MUTEX_INITIALIZER;
static int                                 tcp_manager_channel_unregistered_host_connection_max = TCP_MANAGER_HOST_CONTEXT_CONNECTION_COUNT_MAX;

static struct thread_pool_s               *tcp_manager_thread_pool;

#if UNUSED
static ya_result tcp_manager_channel_input_stream_read(input_stream_t *stream, void *in_buffer, uint32_t in_len)
{
    tcp_manager_channel_t *tmc = (tcp_manager_channel_t *)stream->data;
    int                    n;
    uint16_t               len;
    mutex_lock(&tmc->rd_mtx);
    if((n = readfully(tmc->sock, &len, 2)) == 2)
    {
        len = ntohs(len);
        if(len <= in_len)
        {
            n = readfully(tmc->sock, in_buffer, len);
        }
        else
        {
            int  m;
            char buffer[512];
            n = readfully(tmc->sock, in_buffer, in_len);
            int dt = len - in_len;
            while(dt > (int)sizeof(buffer))
            {
                m = readfully(tmc->sock, buffer, sizeof(buffer));
                dt -= m;
            }
            m = readfully(tmc->sock, buffer, dt);
        }
    }
    mutex_unlock(&tmc->rd_mtx);
    return n;
}

static ya_result tcp_manager_channel_input_stream_skip(input_stream_t *stream, uint32_t byte_count)
{
    tcp_manager_channel_t *tmc = (tcp_manager_channel_t *)stream->data;
    int                    n = 0;
    int                    m;
    char                   buffer[512];
    mutex_lock(&tmc->rd_mtx);
    while(byte_count > sizeof(buffer))
    {
        m = readfully(tmc->sock, buffer, sizeof(buffer));
        byte_count -= m;
        n += m;
    }
    m = readfully(tmc->sock, buffer, byte_count);
    mutex_unlock(&tmc->rd_mtx);
    n += m;
    return n;
}

static void                    tcp_manager_channel_input_stream_close(input_stream_t *stream) { (void)stream; }

static const input_stream_vtbl tcp_manager_channel_input_stream_vtbl = {
    tcp_manager_channel_input_stream_read,
    tcp_manager_channel_input_stream_skip,
    tcp_manager_channel_input_stream_close,
    "tcp_manager_channel_input_stream",
};

void tcp_manager_channel_input_stream_init(input_stream_t *stream, tcp_manager_channel_t *channel)
{
    stream->data = channel;
    stream->vtbl = &tcp_manager_channel_input_stream_vtbl;
}
#endif

#if UNUSED
static ya_result tcp_manager_channel_output_stream_write(output_stream_t *stream, const uint8_t *buffer, uint32_t buffer_size)
{
    tcp_manager_channel_t *tmc = (tcp_manager_channel_t *)stream->data;
    uint16_t               len = buffer_size;
    len = htons(len);
    writefully(tmc->sock, &len, 2);
    writefully(tmc->sock, buffer, buffer_size);
    return len;
}

static ya_result tcp_manager_channel_output_stream_flush(output_stream_t *stream)
{
    (void)stream;
    return SUCCESS;
}

static void                     tcp_manager_channel_output_stream_close(output_stream_t *stream) { (void)stream; }

static const output_stream_vtbl tcp_manager_channel_output_stream_vtbl = {
    tcp_manager_channel_output_stream_write,
    tcp_manager_channel_output_stream_flush,
    tcp_manager_channel_output_stream_close,
    "tcp_manager_channel_output_stream",
};

void tcp_manager_channel_output_stream_init(output_stream_t *stream, tcp_manager_channel_t *channel)
{
    stream->data = channel;
    stream->vtbl = &tcp_manager_channel_output_stream_vtbl;
}

#endif

void tcp_manager_channel_read_thread(void *args)
{
    tcp_manager_channel_t *tmc = (tcp_manager_channel_t *)args;

    for(;;)
    {
        dns_message_t *mesg = dns_message_new_instance();
        int            n;
        uint16_t       mesg_size;
        n = readfully(tmc->sock, &mesg_size, 2);

        if(n == 2)
        {
            tmc->read_ts = timeus();

            mesg_size = ntohs(mesg_size);
            n = readfully(tmc->sock, dns_message_get_buffer(mesg), mesg_size);

            tmc->read_ts = timeus();

            if(n == mesg_size)
            {
                mesg->channel = tmc;
                // dispatch in a new thread

                thread_pool_enqueue_call(tcp_manager_thread_pool, tcp_manager_channel_read_thread, tmc, NULL, "tmcr");
            }
        }
        else
        {
            // something is wrong
        }
    }
}

static ya_result tcp_manager_channel_message_tcp_read(struct tcp_manager_channel_s *tmc, dns_message_t *mesg)
{
    int      n;
    uint16_t len;
    uint32_t len_max = dns_message_get_buffer_size_max(mesg);
    uint8_t *buffer = dns_message_get_buffer(mesg);
    mutex_lock(&tmc->rd_mtx);
    if((n = readfully(tmc->sock, &len, 2)) == 2)
    {
        len = ntohs(len);
        if(len <= len_max)
        {
            n = readfully(tmc->sock, buffer, len);
            if(n >= 0)
            {
                dns_message_set_size(mesg, n);
            }
            else
            {
                n = ERRNO_ERROR;
            }
        }
        else
        {
            char tmp[512];
            n = readfully(tmc->sock, buffer, len_max);

            if(n >= 0)
            {
                dns_message_set_size(mesg, n);

                // read the exceeding bytes
                int dt = len - n;
                if(dt > (int)sizeof(buffer))
                {
                    int m;
                    do
                    {
                        m = readfully(tmc->sock, tmp, sizeof(buffer));
                        if(m < 0)
                        {
                            break;
                        }
                        dt -= m;
                    } while(dt > (int)sizeof(buffer));

                    if(m > 0)
                    {
                        readfully(tmc->sock, tmp, dt);
                    }
                }
                else
                {
                    readfully(tmc->sock, tmp, dt);
                }
            }
            else
            {
                n = ERRNO_ERROR;
            }
        }
    }
    else // the length is wrong
    {
        if(n != 0)
        {
            if(n < 0) // it was a read error
            {
                n = ERRNO_ERROR;
            }
            else // else it's a short read
            {
                n = UNEXPECTED_EOF;
            }
        }
    }
    mutex_unlock(&tmc->rd_mtx);
    return n;
}

static ya_result tcp_manager_channel_message_tcp_write(struct tcp_manager_channel_s *tmc, dns_message_t *mesg)
{
    mutex_lock(&tmc->wr_mtx);
    ya_result ret = dns_message_send_tcp(mesg, tmc->sock);
    mutex_unlock(&tmc->wr_mtx);
    return ret;
}

static ya_result tcp_manager_channel_message_tcp_close(struct tcp_manager_channel_s *tmc)
{
    shutdown(tmc->sock, SHUT_RDWR);
    socketclose_ex(tmc->sock);
    tmc->sock = -1;
    return SUCCESS;
}

struct tcp_manager_channel_message_vtbl tcp_manager_channel_message_tcp_vtbl = {tcp_manager_channel_message_tcp_read, tcp_manager_channel_message_tcp_write, tcp_manager_channel_message_tcp_close};

/**
 * Checks the quotas.
 *  _ IP quotas
 *  _ total quotas
 * Creates a channel.
 * Creates the R&W threads for the channel. (Pool?)
 */

ya_result tcp_manager_channel_accept(int sockfd, tcp_manager_channel_t **tmcp)
{
    int                    ret;

    tcp_manager_channel_t *tmc;
    ZALLOC_OBJECT_OR_DIE(tmc, tcp_manager_channel_t, TCPM2CHN_TAG);

    socklen_t ss_len = sizeof(socketaddress_t);

    ret = accept_ex(sockfd, &tmc->ss.sa, &ss_len);

    if(ret >= 0)
    {
        // don't care about quotas now

        mutex_lock(&tcp_manager_channel_quota_map_mtx);

        tcp_manager_channel_quota_t *tmcq;
        ptr_treemap_node_t          *node = ptr_treemap_insert(&tcp_manager_channel_quota_map, &tmc->ss.sa);
        if(node->value == NULL)
        {
            ZALLOC_OBJECT_OR_DIE(tmcq, tcp_manager_channel_quota_t, TCPM2CQU_TAG);
            mutex_init(&tmcq->mtx);
            socketaddress_copy(&tmcq->sa, &tmc->ss);
            tmcq->connection_max = 1; // * tcp_manager_channel_unregistered_host_connection_max for the whole system
            tmcq->dynamic = true;
            ptr_vector_init_ex(&tmcq->channels, tmcq->connection_max);
            node->value = tmcq;
            node->key = &tmcq->sa;

            // log_info("accept: %{sockaddr} is new: %i/%i", &tmc->ss.sa, ptr_vector_size(&tmcq->channels),
            // tmcq->connection_max);
        }
        else
        {
            tmcq = (tcp_manager_channel_quota_t *)node->value;
            // log_info("accept: %{sockaddr} is old: %i/%i", &tmc->ss.sa, ptr_vector_size(&tmcq->channels),
            // tmcq->connection_max);
        }

        if(ptr_vector_size(&tmcq->channels) < tmcq->connection_max)
        {
            // quotas allow for more

            mutex_init(&tmc->rd_mtx);
            mutex_init(&tmc->wr_mtx);
            tmc->accept_ts = timeus();
            tmc->read_ts = 0;
            tmc->write_ts = 0;
            tmc->sock = ret;
            tmc->vtbl = &tcp_manager_channel_message_tcp_vtbl;
            tmc->ss_len = ss_len;
            tmc->rc = 1;

            mutex_lock(&tmcq->mtx);
            ptr_vector_append(&tmcq->channels, tmc);
            tmc->index = ptr_vector_last_index(&tmcq->channels);
            mutex_unlock(&tmcq->mtx);

            mutex_unlock(&tcp_manager_channel_quota_map_mtx);

            *tmcp = tmc;
            return SUCCESS;
        }
        else
        {
            // quotas don't allow for more

            mutex_unlock(&tcp_manager_channel_quota_map_mtx);

            close_ex(ret);

            ZFREE_OBJECT(tmc);

            return CONNECTION_QUOTA_EXCEEDED; // quota exceeded
        }
    }
    else
    {
        return ERRNO_ERROR;
    }
}

static void tcp_manager_channel_delete(tcp_manager_channel_t *tmc)
{
    // find the quota

    tmc->vtbl->close(tmc);

    mutex_lock(&tcp_manager_channel_quota_map_mtx);

    ptr_treemap_node_t *node = ptr_treemap_find(&tcp_manager_channel_quota_map, &tmc->ss.sa);

    if(node->value != NULL)
    {
        bool delete_tmcq = false;
        // remove the tmc (put it at the end, remove)

        tcp_manager_channel_quota_t *tmcq;
        tmcq = (tcp_manager_channel_quota_t *)node->value;
        mutex_lock(&tmcq->mtx);
        if(ptr_vector_size(&tmcq->channels) > 1)
        {
            tcp_manager_channel_t *tmcx = (tcp_manager_channel_t *)ptr_vector_last(&tmcq->channels);
            ptr_vector_end_swap(&tmcq->channels, tmc->index);
            int tmp = tmcx->index;
            tmcx->index = tmc->index;
            tmc->index = tmp;
        }
        ptr_vector_remove_at(&tmcq->channels, tmc->index);

        // quota empty?

        if(tmcq->dynamic && ptr_vector_isempty(&tmcq->channels))
        {
            // remove the tmcq from the quotas

            ptr_treemap_delete(&tcp_manager_channel_quota_map, &tmcq->sa);
        }

        mutex_unlock(&tmcq->mtx);

        if(delete_tmcq)
        {
            ZFREE_OBJECT(tmcq);
        }
    }

    mutex_unlock(&tcp_manager_channel_quota_map_mtx);

    // destroy the structure

    mutex_finalize(&tmc->wr_mtx);
    mutex_finalize(&tmc->rd_mtx);
    ZFREE_OBJECT(tmc);
}

void tcp_manager_channel_acquire(tcp_manager_channel_t *tmc) { ++tmc->rc; }

void tcp_manager_channel_release(tcp_manager_channel_t *tmc)
{
    if(--tmc->rc == 0)
    {
        tcp_manager_channel_delete(tmc);
    }
}

ya_result tcp_manager_host_register(const socketaddress_t *sa, socklen_t sa_len, int32_t allowed_connections_max)
{
    (void)sa_len;
    if(allowed_connections_max <= 0)
    {
        allowed_connections_max = TCP_MANAGER_REGISTERED_HOST_CONTEXT_CONNECTION_COUNT_MAX;
    }

    mutex_lock(&tcp_manager_channel_quota_map_mtx);
    tcp_manager_channel_quota_t *tmcq;
    ptr_treemap_node_t          *node = ptr_treemap_insert(&tcp_manager_channel_quota_map, (void *)sa);
    if(node->value == NULL)
    {
        ZALLOC_OBJECT_OR_DIE(tmcq, tcp_manager_channel_quota_t, TCPM2CQU_TAG);
        mutex_init(&tmcq->mtx);
        socketaddress_copy(&tmcq->sa, sa);
        tmcq->connection_max = allowed_connections_max;
        tmcq->dynamic = false;
        ptr_vector_init_ex(&tmcq->channels, tmcq->connection_max);
        node->value = tmcq;
        node->key = &tmcq->sa;
    }
    else
    {
        tmcq = (tcp_manager_channel_quota_t *)node->value;
        tmcq->connection_max = allowed_connections_max;
        ptr_vector_resize(&tmcq->channels, allowed_connections_max);
    }
    mutex_unlock(&tcp_manager_channel_quota_map_mtx);

    return SUCCESS;
}

ya_result tcp_manager_connection_max(int32_t allowed_connections_max)
{
    if(allowed_connections_max <= 0)
    {
        allowed_connections_max = TCP_MANAGER_HOST_CONTEXT_CONNECTION_COUNT_MAX;
    }

    tcp_manager_channel_unregistered_host_connection_max = allowed_connections_max;
    return SUCCESS;
}

ya_result tcp_manager_init() { return SUCCESS; }

void      tcp_manager_finalise()
{
    // should probably close all that
}
