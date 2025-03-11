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

#include "yatest.h"
#include "yatest_socket.h"
#include <dnscore/network.h>
#include <dnscore/fdtools.h>
#include <dnscore/process.h>
#include <dnscore/dnscore.h>
#include <netdb.h>

// static uint8_t ipv4_any[4] = {0,0,0,0};
// static uint8_t ipv6_any[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static uint8_t          ipv4_not_any[4] = {127, 0, 0, 1};
static uint8_t          ipv4_not_any2[4] = {127, 0, 0, 2};
static uint8_t          ipv6_not_any[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static uint8_t          ipv6_not_any2[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
static struct addrinfo *addrinfo_any_v4;
static struct addrinfo *addrinfo_not_any_v4;
static struct addrinfo *addrinfo_any_v6;
static struct addrinfo *addrinfo_not_any_v6;
static struct addrinfo *addrinfo_not_any_vX;
static socketaddress_t  sa_v4a;
static socketaddress_t  sa_v4b;
static socketaddress_t  sa_v4c;
static socketaddress_t  sa_v6a;
static socketaddress_t  sa_v6b;
static socketaddress_t  sa_v6c;
static socketaddress_t  sa_vXa;
static socketaddress_t  sa_vXb;
static socketaddress_t  sa_vXc;

static void             init()
{
    dnscore_init();
    yatest_log("sizeof(socketaddress) = %i", sizeof(socketaddress_t));
    yatest_log("sizeof(struct sockaddr_storage) = %i", sizeof(struct sockaddr_storage));

    memset(&sa_v4a, 0, sizeof(socketaddress_t));
    memset(&sa_v4b, 0, sizeof(socketaddress_t));
    memset(&sa_v4c, 0, sizeof(socketaddress_t));
    memset(&sa_v6a, 0, sizeof(socketaddress_t));
    memset(&sa_v6b, 0, sizeof(socketaddress_t));
    memset(&sa_v6c, 0, sizeof(socketaddress_t));
    memset(&sa_vXa, 0, sizeof(socketaddress_t));
    memset(&sa_vXb, 0, sizeof(socketaddress_t));
    memset(&sa_vXc, 0, sizeof(socketaddress_t));

    getaddrinfo("0.0.0.0", NULL, NULL, &addrinfo_any_v4);
    getaddrinfo("::", NULL, NULL, &addrinfo_any_v6);
    getaddrinfo("127.0.0.1", NULL, NULL, &addrinfo_not_any_v4);
    getaddrinfo("::1", NULL, NULL, &addrinfo_not_any_v6);
    getaddrinfo("::1", NULL, NULL, &addrinfo_not_any_vX);
    if(addrinfo_not_any_vX != NULL)
    {
        addrinfo_not_any_vX->ai_family = 0;
    }

    sa_v4a.sa4.sin_family = AF_INET;
    memcpy(&sa_v4a.sa4.sin_addr, ipv4_not_any, sizeof(ipv4_not_any));
    sa_v4a.sa4.sin_port = NU16(53);

    sa_v4b.sa4.sin_family = AF_INET;
    memcpy(&sa_v4b.sa4.sin_addr, ipv4_not_any, sizeof(ipv4_not_any));
    sa_v4b.sa4.sin_port = NU16(53);

    sa_v4c.sa4.sin_family = AF_INET;
    memcpy(&sa_v4c.sa4.sin_addr, ipv4_not_any2, sizeof(ipv4_not_any2));
    sa_v4c.sa4.sin_port = NU16(53);

    sa_v6a.sa6.sin6_family = AF_INET6;
    memcpy(&sa_v6a.sa6.sin6_addr, ipv6_not_any, sizeof(ipv6_not_any));
    sa_v6a.sa6.sin6_port = NU16(53);

    sa_v6b.sa6.sin6_family = AF_INET6;
    memcpy(&sa_v6b.sa6.sin6_addr, ipv6_not_any, sizeof(ipv6_not_any));
    sa_v6b.sa6.sin6_port = NU16(53);

    sa_v6c.sa6.sin6_family = AF_INET6;
    memcpy(&sa_v6c.sa6.sin6_addr, ipv6_not_any2, sizeof(ipv6_not_any2));
    sa_v6c.sa6.sin6_port = NU16(53);

    char *p = (char *)&sa_vXa;
    for(size_t i = 0; i < sizeof(sa_vXa); ++i)
    {
        p[i] = (char)i;
    }
    p = (char *)&sa_vXb;
    for(size_t i = 0; i < sizeof(sa_vXb); ++i)
    {
        p[i] = (char)i;
    }
    p = (char *)&sa_vXc;
    for(size_t i = 0; i < sizeof(sa_vXc); ++i)
    {
        p[i] = (char)~i;
    }
}

static void finalise()
{
    freeaddrinfo(addrinfo_not_any_v6);
    freeaddrinfo(addrinfo_not_any_v4);
    freeaddrinfo(addrinfo_any_v6);
    freeaddrinfo(addrinfo_any_v4);
    dnscore_finalize();
}

static int addr_info_is_any_test()
{
    init();
    if((addrinfo_any_v4 != NULL) && !addr_info_is_any(addrinfo_any_v4))
    {
        yatest_err("addr_info_is_any any v4 failed");
        return 1;
    }
    if((addrinfo_any_v6 != NULL) && !addr_info_is_any(addrinfo_any_v6))
    {
        yatest_err("addr_info_is_any any v6 failed");
        return 1;
    }
    if((addrinfo_not_any_v4 != NULL) && addr_info_is_any(addrinfo_not_any_v4))
    {
        yatest_err("addr_info_is_any not any v4 failed");
        return 1;
    }
    if((addrinfo_not_any_v6 != NULL) && addr_info_is_any(addrinfo_not_any_v6))
    {
        yatest_err("addr_info_is_any not any v6 failed");
        return 1;
    }
    if((addrinfo_not_any_vX != NULL) && addr_info_is_any(addrinfo_not_any_vX))
    {
        yatest_err("addr_info_is_any not any vX failed");
        return 1;
    }
    finalise();
    return 0;
}

static ya_result network_interfaces_forall_test_callback(const char *itf_name, const socketaddress_t *ss, void *data)
{
    (void)ss;
    (void)data;
    yatest_log("itf_name=%s", itf_name);
    return 0;
}

static int network_interfaces_forall_test()
{
    int ret;
    init();
    if((ret = network_interfaces_forall(network_interfaces_forall_test_callback, NULL)) < 0)
    {
        yatest_err("network_interfaces_forall failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int sockaddr_compare_addr_port_test()
{
    init();
    if(sockaddr_compare_addr_port(&sa_v4a.sa, &sa_v4b.sa) != 0)
    {
        yatest_err("sockaddr_compare_addr_port v4a v4b should have been a match");
        return 1;
    }
    if(sockaddr_compare_addr_port(&sa_v6a.sa, &sa_v6b.sa) != 0)
    {
        yatest_err("sockaddr_compare_addr_port v4a v4b should have been a match");
        return 1;
    }
    if(sockaddr_compare_addr_port(&sa_v4a.sa, &sa_v4c.sa) == 0)
    {
        yatest_err("sockaddr_compare_addr_port v4a v4c should not have been a match");
        return 1;
    }
    if(sockaddr_compare_addr_port(&sa_v4a.sa, &sa_v6a.sa) == 0)
    {
        yatest_err("sockaddr_compare_addr_port v4a v6a should not have been a match");
        return 1;
    }
    finalise();
    return 0;
}

static int socketaddress_compare_ip_test()
{
    init();
    if(socketaddress_compare_ip(&sa_v4a, &sa_v4a) != 0)
    {
        yatest_err("sockaddr_compare_ip v4a v4a should have been a match");
        return 1;
    }
    if(socketaddress_compare_ip(&sa_v4a, &sa_v4b) != 0)
    {
        yatest_err("sockaddr_compare_ip v4a v4b should have been a match");
        return 1;
    }
    if(socketaddress_compare_ip(&sa_v6a, &sa_v6b) != 0)
    {
        yatest_err("sockaddr_compare_ip v4a v4b should have been a match");
        return 1;
    }
    if(socketaddress_compare_ip(&sa_v4a, &sa_v4c) == 0)
    {
        yatest_err("sockaddr_compare_ip v4a v4c should not have been a match");
        return 1;
    }
    if(socketaddress_compare_ip(&sa_v4a, &sa_v6a) == 0)
    {
        yatest_err("sockaddr_compare_ip v4a v6a should not have been a match");
        return 1;
    }
    finalise();
    return 0;
}

static int sockaddr_storage_compare_ip_test()
{
    init();
    if(sockaddr_storage_compare_ip(&sa_v4a.ss, &sa_v4b.ss) != 0)
    {
        yatest_err("sockaddr_compare_ip v4a v4b should have been a match");
        return 1;
    }
    if(sockaddr_storage_compare_ip(&sa_v6a.ss, &sa_v6b.ss) != 0)
    {
        yatest_err("sockaddr_compare_ip v4a v4b should have been a match");
        return 1;
    }
    if(sockaddr_storage_compare_ip(&sa_v4a.ss, &sa_v4c.ss) == 0)
    {
        yatest_err("sockaddr_compare_ip v4a v4c should not have been a match");
        return 1;
    }
    if(sockaddr_storage_compare_ip(&sa_v4a.ss, &sa_v6a.ss) == 0)
    {
        yatest_err("sockaddr_compare_ip v4a v6a should not have been a match");
        return 1;
    }
    sa_v4a.ss.ss_family = 0;
    sa_v4b.ss.ss_family = 0;
    sa_v6a.ss.ss_family = 0;
    if(sockaddr_storage_compare_ip(&sa_v4a.ss, &sa_v4b.ss) != 0)
    {
        yatest_err("sockaddr_compare_ip v4a v6a should have been a match");
        return 1;
    }
    if(sockaddr_storage_compare_ip(&sa_v4a.ss, &sa_v6a.ss) == 0)
    {
        yatest_err("sockaddr_compare_ip v4a v6a should not have been a match");
        return 1;
    }
    finalise();
    return 0;
}

static int socketaddress_copy_test()
{
    init();
    socketaddress_t sa_copy;
    memset(&sa_copy, 0xff, sizeof(sa_copy));
    socketaddress_copy(&sa_copy, &sa_v4a);
    if(socketaddress_compare_ip(&sa_copy, &sa_v4a) != 0)
    {
        yatest_err("socketaddress_copy v4 didn't work");
        return 1;
    }
    memset(&sa_copy, 0xff, sizeof(sa_copy));
    socketaddress_copy(&sa_copy, &sa_v6a);
    if(socketaddress_compare_ip(&sa_copy, &sa_v6a) != 0)
    {
        yatest_err("socketaddress_copy v6 didn't work");
        return 1;
    }
    memset(&sa_copy, 0xff, sizeof(sa_copy));
    socketaddress_copy(&sa_copy, &sa_vXa);
    if(socketaddress_compare_ip(&sa_copy, &sa_vXa) != 0)
    {
        yatest_err("socketaddress_copy vX didn't work");
        return 1;
    }
    finalise();
    return 0;
}

static int sockaddr_storage_copy_test()
{
    init();
    socketaddress_t sa_copy;
    memset(&sa_copy, 0xff, sizeof(sa_copy));
    sockaddr_storage_copy(&sa_copy.ss, &sa_v4a.ss);
    if(socketaddress_compare_ip(&sa_copy, &sa_v4a) != 0)
    {
        yatest_err("sockaddr_storage_copy v4 didn't work");
        return 1;
    }
    memset(&sa_copy, 0xff, sizeof(sa_copy));
    sockaddr_storage_copy(&sa_copy.ss, &sa_v6a.ss);
    if(socketaddress_compare_ip(&sa_copy, &sa_v6a) != 0)
    {
        yatest_err("sockaddr_storage_copy v4 didn't work");
        return 1;
    }
    memset(&sa_copy, 0xff, sizeof(sa_copy));
    sockaddr_storage_copy(&sa_copy.ss, &sa_vXa.ss);
    if(socketaddress_compare_ip(&sa_copy, &sa_vXa) != 0)
    {
        yatest_err("sockaddr_storage_copy vX didn't work");
        return 1;
    }
    finalise();
    return 0;
}

static int accept_ex_test()
{
    int port = 10053;
    if(fork() == 0)
    {
        for(;;)
        {
            sleep(1);
            yatest_log("trying ...");
            int sockfd = yatest_socket_create("127.0.0.1", port, SOCK_STREAM);
            if(sockfd >= 0)
            {
                yatest_log("connected");
                socketclose_ex(sockfd);
                break;
            }
        }
        exit(0);
    }

    init();
    int             server_socket = yatest_serversocket_create_tcp("127.0.0.1", port);

    socketaddress_t client;
    socklen_t       client_len = sizeof(client);
    int             ret = accept_ex(server_socket, &client.sa, &client_len);
    if(ret < 0)
    {
        yatest_err("accept_ex failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    else
    {
        yatest_log("accepted");
        socketclose_ex(ret);
    }
    socketclose_ex(server_socket);
    finalise();
    return 0;
}

int socketaddress_init_parse_with_port_test()
{
    static const uint8_t expected_ipv6_address[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    static const uint8_t expected_ipv4_address[4] = {1, 2, 3, 4};
    ya_result            ret;
    socketaddress_t      sa;
    memset(&sa, 0xff, sizeof(sa));
    if((ret = socketaddress_init_parse_with_port(&sa, "1234:5678:9abc:def0:fedc:ba98:7654:3210", 0x1234)) < 0)
    {
        yatest_err("socketaddress_init_parse_with_port 1234:5678:9abc:def0:fedc:ba98:7654:3210 0x1234 failed with %08x", ret);
        return 1;
    }
    if(!((sa.sa6.sin6_family == AF_INET6) && (sa.sa6.sin6_port == NU16(0x1234)) && (sa.sa6.sin6_flowinfo == 0) && (memcmp(&sa.sa6.sin6_addr, expected_ipv6_address, 16) == 0) && (sa.sa6.sin6_scope_id == 0)))
    {
        yatest_err("socketaddress_init_parse_with_port 1234:5678:9abc:def0:fedc:ba98:7654:3210 0x1234 wrong");
        return 1;
    }
    memset(&sa, 0xff, sizeof(sa));
    if((ret = socketaddress_init_parse_with_port(&sa, "1.2.3.4", 0x1234)) < 0)
    {
        yatest_err("socketaddress_init_parse_with_port 1.2.3.4 0x1234 failed with %08x", ret);
        return 1;
    }
    if(!((sa.sa4.sin_family == AF_INET) && (sa.sa4.sin_port == NU16(0x1234)) && (memcmp(&sa.sa4.sin_addr, expected_ipv4_address, 1) == 0)))
    {
        yatest_err("socketaddress_init_parse_with_port 1.2.3.4 0x1234 wrong");
        return 1;
    }
    if((ret = socketaddress_init_parse_with_port(&sa, "-= NOT AN IP =-", 0x1234)) >= 0)
    {
        yatest_err("socketaddress_init_parse_with_port -= NOT AN IP =- 0x1234 didn't fail but returned %08x  instead", ret);
        return 1;
    }
    return 0;
}

int socket_server_test()
{
    ya_result ret;
    init();
    socketaddress_t sa;
    socketaddress_t picked;
    socketaddress_init_parse_with_port(&sa, "127.0.0.1", 0);
    if(FAIL(ret = socket_server(&sa.sa, sizeof(sa.sa4), SOCK_STREAM, 5)))
    {
        yatest_err("socket_server failed with %08x", ret);
        return 1;
    }
    int       sockfd = ret;
    socklen_t picked_size = sizeof(picked);
    getsockname(sockfd, &picked.sa, &picked_size);
    if(picked.sa.sa_family != AF_INET)
    {
        yatest_err("socket_server didn't return an AF_INET");
        return 1;
    }
    if(picked.sa4.sin_port == 0)
    {
        yatest_err("socket_server didn't pick a port");
        return 1;
    }
    yatest_log("socket: %i, port: %i", sockfd, ntohs(picked.sa4.sin_port));

    close_ex(sockfd);

    // docker doesn't necessarily have IPv6
    // socketaddress_init_parse_with_port(&sa, "::1", 0);
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(addr_info_is_any_test)
YATEST(network_interfaces_forall_test)
YATEST(sockaddr_compare_addr_port_test)
YATEST(socketaddress_compare_ip_test)
YATEST(sockaddr_storage_compare_ip_test)
YATEST(socketaddress_copy_test)
YATEST(sockaddr_storage_copy_test)
YATEST(accept_ex_test)
YATEST(socketaddress_init_parse_with_port_test)
YATEST(socket_server_test)
YATEST_TABLE_END
