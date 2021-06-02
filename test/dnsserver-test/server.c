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

#include "server.h"
#include "input.h"
#include "dns-stream-input.h"

#include <dnscore/host_address.h>
#include <dnscore/socket-server.h>
#include <dnscore/logger.h>
#include <dnscore/thread_pool.h>
#include <dnscore/message.h>
#include <dnscore/packet_writer.h>
#include <dnscore/tcp_io_stream.h>

extern logger_handle *g_main_logger;
#define MODULE_MSG_HANDLE g_main_logger

static int g_sockfd = -1;

/*** @todo 20210503 edf -- implement a kind of story
 *
 * At the moment, the program:
 * _ serves an AXFR stream for whatever zone is being requested, serial 1
 * _ serves an IXFR stream doing an incremental change for whatever zone is being requested but "eu.", from serial 1 to serial 2
 * _ serves a broken IXFR stream doing an incremental change of that zone from serial 1 to serial 2 for zone "eu."
 *     broken: the first "remove SOA" record has the "other." name instead of "eu."  (CVE-2021-25214)
 *
 * It could  be improved using a kind of story:
 *
 * A sequence, in about any order of:
 * _ ready an input (sets AXFR, IXFR streams)
 * _ send a notification (tells the server to do an AXFR or an IXFR)
 *
 * Each element of the sequence can tell to go one step further on the story.
 *
 * It would allow to implement several setups instead of the one.
 * Stories could be read in parallel, or just one at a time.
 */

static ya_result
reply_tcp_message(input_stream *is, message_data *mesg, int sockfd)
{
    // reads records from the input
    // for each, reply with a DNS message

    ya_result ret;
    dns_resource_record *rr = dns_resource_record_new_instance();
    packet_writer pw;

    message_set_authoritative_answer(mesg);
    message_set_answer_count(mesg, 1);
    message_set_authority_additional_counts(mesg, 0, 0);

    for(;;)
    {
        packet_writer_init_from_message(&pw, mesg);
        packet_writer_set_offset(&pw, DNS_HEADER_LENGTH + dnsname_len(&pw.packet[DNS_HEADER_LENGTH]) + 4);

        ret = dns_resource_record_read(rr, is);
        if(ret > 0)
        {
            ret = packet_writer_add_record(&pw, rr->name, rr->tctr.qtype, rr->tctr.qclass, rr->tctr.ttl, rr->rdata, rr->rdata_size);
            message_set_size(mesg, packet_writer_get_offset(&pw));
            ret = message_send_tcp(mesg, sockfd);
        }
        else
        {
            if(FAIL(ret))
            {
                log_err("reply_tcp_message: %r", ret);
            }
            else
            {
                log_info("reply_tcp_message: %i", ret);
            }
            logger_flush();
            break;
        }
    }
    dns_resource_record_free(rr);

    return ret;
}

static ya_result
read_ex(int fd, u8 *buffer, size_t buffer_size)
{
    u8 *base = buffer;
    while(buffer_size > 0)
    {
        int n = read(fd, buffer, buffer_size);

        if(n <= 0)
        {
            if(n < 0)
            {
                int err = errno;

                if(err == EINTR)
                {
                    continue;
                }

                return MAKE_ERRNO_ERROR(err);
            }
            else
            {
                return n;
            }
        }

        buffer += n;
        buffer_size -= n;
    }

    return buffer - base;
}

static int
wait_read_activity(int sockfd)
{
    int ret;

    fd_set read_set;
    struct timespec timeout;

    FD_ZERO(&read_set);
    FD_SET(sockfd, &read_set);
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;

    for(;;)
    {
        ret = pselect(sockfd + 1, &read_set, NULL, NULL, &timeout, 0);

        if(ret < 0)
        {
            int err = errno;
            if(err == EINTR)
            {
                continue;
            }

            return MAKE_ERRNO_ERROR(err);
        }

        return ret;
    }
}

static void *
server_tcp_thread(void* args)
{
    (void)args;
    ya_result ret;
    int sockfd;
    socketaddress sa;

    tcp_set_sendtimeout(g_sockfd, 5, 0);
    tcp_set_recvtimeout(g_sockfd, 5, 0);

    while(!dnscore_shuttingdown())
    {
        if(FAIL(ret = wait_read_activity(g_sockfd)))
        {
            log_err("server_tcp_thread: pselect(%i, ...): %r", g_sockfd, ret);
        }

        if(ret == 0)
        {
            continue;
        }

        socklen_t sa_len = sizeof(socketaddress);

        while((sockfd = accept(g_sockfd, &sa.sa, &sa_len)) < 0)
        {
            int err = errno;

            if(err != EINTR)
            {
                log_err("server_tcp_thread: accept(%i, %p, &%i): %r", g_sockfd, &sa.sa, sa_len, MAKE_ERRNO_ERROR(err));
                goto server_tcp_thread_exit;
            }
        }

        tcp_set_sendtimeout(sockfd, 3, 0);
        tcp_set_recvtimeout(sockfd, 3, 0);

        u16 ne_message_len;

        if((ret = read_ex(sockfd, (u8*)&ne_message_len, 2)) != 2)
        {
            if(FAIL(ret))
            {
                if((ret != MAKE_ERRNO_ERROR(ETIMEDOUT)) && (ret != MAKE_ERRNO_ERROR(EAGAIN)))
                {
                    log_err("server_tcp_thread: read (2): %r", ret);
                }
            }

            close_ex(sockfd);
            continue;
        }

        u16 message_len = ntohs(ne_message_len);

        message_data *mesg = message_new_instance();

        if((ret = read_ex(sockfd, message_get_buffer(mesg), message_len)) != message_len)
        {
            if(FAIL(ret))
            {
                if((ret != MAKE_ERRNO_ERROR(ETIMEDOUT)) && (ret != MAKE_ERRNO_ERROR(EAGAIN)))
                {
                    log_err("server_tcp_thread: read (2): %r", ret);
                }
            }

            close_ex(sockfd);
            continue;
        }

        message_set_size(mesg, ret);

        message_set_protocol(mesg, IPPROTO_TCP);

        switch(message_get_opcode(mesg))
        {
            case OPCODE_QUERY:
            {
                if(ISOK(ret = message_process_query(mesg)))
                {
                    log_info("query: %{dnstype} %{dnsclass} %{dnsname}", message_get_query_type_ptr(mesg), message_get_query_class_ptr(mesg), message_get_canonised_fqdn(mesg));
                    logger_flush();

                    const u8 *domain = message_get_canonised_fqdn(mesg);
                    input_t input;

                    if(dnsname_equals(domain, (const u8*)"\002eu"))
                    {
                        dns_stream_cve_2021_25214_input_init(&input, domain);
                    }
                    else
                    {
                        dns_stream_input_init(&input, domain);
                    }

                    if(message_get_query_type(mesg) == TYPE_AXFR)
                    {
                        input_stream axfr_is;
                        if(ISOK(ret = input_axfr_input_stream_init(&input, &axfr_is)))
                        {
                            ret = reply_tcp_message(&axfr_is, mesg, sockfd);
                        }
                        input_stream_close(&axfr_is);
                    }
                    else if(message_get_query_type(mesg) == TYPE_IXFR)
                    {
                        input_stream ixfr_is;
                        if(ISOK(ret = input_ixfr_input_stream_init(&input, 0, &ixfr_is)))
                        {
                            ret = reply_tcp_message(&ixfr_is, mesg, sockfd);
                        }
                        input_stream_close(&ixfr_is);
                    }
                    else
                    {
                        log_warn("query type is not supported");
                        ret = FEATURE_NOT_IMPLEMENTED_ERROR;
                    }

                    input_finalise(&input);
                }
                break;
            }
            default:
                log_warn("server_tcp_thread: expected a query opcode, got %u %s", message_get_opcode(mesg), dns_message_opcode_get_name(message_get_opcode(mesg)));
                ret = FEATURE_NOT_IMPLEMENTED_ERROR;
                break;
        }

        if(FAIL(ret))
        {
            log_err("query result: ", ret);
        }

        message_free(mesg);

        close_ex(sockfd);
    }

    log_info("shutting down");
    logger_flush();

    server_tcp_thread_exit:

    return NULL;
}

ya_result
server_tcp(const host_address *ha, const host_address *client)
{
    ya_result ret;
    struct addrinfo *addr = NULL;

    if(FAIL(ret = host_address2addrinfo(ha, &addr)))
    {
        log_err("failed to get addrinfo from %{hostaddr}: %r", ha, ret);
        return ret;
    }

    int sockfd;
    static const int on = 1;
    const bool reuse_port = TRUE;

    if(FAIL(sockfd = socket(addr->ai_family, SOCK_STREAM, 0)))
    {
        ret = ERRNO_ERROR;
        log_err("failed to create socket %{sockaddr}: %r", addr->ai_addr, ret);
        free(addr);
        return ret;
    }

    /**
     * Associate the name of the interface to the socket
     */

    /**
     * This is distribution/system dependent. With this we ensure that IPv6 will only listen on IPv6 addresses.
     */

    if(addr->ai_family == AF_INET6)
    {
        log_info("IPv6");
        if(FAIL(setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on))))
        {
            ret = ERRNO_ERROR;
            log_err("failed to force IPv6 on %{sockaddr}: %r", addr->ai_addr, ret);
            close(sockfd);
            free(addr);
            return ret;
        }

    }
    else if(addr->ai_family == AF_INET)
    {
        log_info("IPv4");
    }
    else
    {
        log_err("address family %i", addr->ai_family);
    }

    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on))))
    {
        ret = ERRNO_ERROR;
        log_err("failed to reuse address %{sockaddr}: %r", addr->ai_addr, ret);
        close(sockfd);
        free(addr);
        return ret;
    }

    if(reuse_port)
    {
#ifdef SO_REUSEPORT
        if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *) &on, sizeof(on))))
        {
            ret = ERRNO_ERROR;
            log_err("failed to use reuse feature: %r", ret);
            close(sockfd);
            free(addr);
            return ret;
        }
#else
        return MAKE_ERRNO_ERROR(ENOTSUP);
#endif
    }

    if(FAIL(bind(sockfd,
                 (struct sockaddr*)addr->ai_addr,
                 addr->ai_addrlen)))
    {
        ret = ERRNO_ERROR;
        log_err("failed to bind address %{sockaddr}: %r", addr->ai_addr, ret);
        close(sockfd);
        free(addr);
        return ret;
    }

    log_info("bound at %{sockaddr}", addr->ai_addr);
    logger_flush();

    if(listen(sockfd, 10) < 0)
    {
        ret = ERRNO_ERROR;
        log_err("failed to listen: %r", addr->ai_addr, ret);
        close(sockfd);
        free(addr);
        return ret;
    }

    static const int ignore_these[] = {SIGPIPE, 0};

    for(int i = 0; ignore_these[i] != 0; ++i)
    {
        signal(ignore_these[i], SIG_IGN);
    }

    // start tcp thread

    struct thread_pool_s *tp = thread_pool_init_ex(4, 4, "tcp-thread");
    thread_pool_task_counter counter;
    thread_pool_counter_init(&counter, 0);

    //thread_pool_wait_all_running(tp);

    // for all input ...

    /*
     * domain
     * axfr
     * ixfr
     */

    g_sockfd = sockfd;

    for(;;)
    {
        thread_pool_enqueue_call(tp, server_tcp_thread, NULL, &counter, "tcp-thread");
        sleep(1); // bad

        // notify server

        message_data *mesg = message_new_instance();
        message_data *answer = message_new_instance();

        static const u8* domains[2] = { (const u8 *)"\002eu", (const u8 *)"\005other"};

        while(!dnscore_shuttingdown())
        {
            for(int i = 0; i < 2; ++i)
            {
                message_make_notify(mesg, rand(), domains[i], TYPE_SOA, CLASS_IN);

                //if(ISOK(ret = message_query_udp_with_timeout_and_retries(mesg, client, 3, 0, 3, 0)))
                if(ISOK(ret = message_query_tcp_ex(mesg, ha, client, answer)))
                {
                    // wait for the thread to end
                    log_info("sent %{dnsname} notify query to %{hostaddr}: %r", domains[i], client, ret);
                }
                else
                {
                    log_err("failed to send %{dnsname} notify query to %{hostaddr}: %r", domains[i], client, ret);
                }

                logger_flush();

                sleep(2);
            }

            for(int i = 0; i < 30; ++i)
            {
                sleep(1);
                if(dnscore_shuttingdown())
                {
                    break;
                }
            }
        }

        log_info("waiting for the TCP thread to finish");
        logger_flush();

        thread_pool_counter_wait_equal(&counter, 0);

        message_free(answer);
        message_free(mesg);

        break;
    }

    // release resources

    log_info("destroying the pool");
    logger_flush();

    thread_pool_destroy(tp);
    close(sockfd);
    free(addr);
    return SUCCESS;
}
