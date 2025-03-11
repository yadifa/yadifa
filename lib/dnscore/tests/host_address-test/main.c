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
#include "dnscore/format.h"
#include "dnscore/tsig.h"
#include <dnscore/dnscore.h>
#include <dnscore/host_address.h>

static const uint8_t  ipv4[4] = {127, 0, 1, 2};
static const uint8_t  ipv4b[4] = {127, 0, 1, 3};
static const char     ipv4_text[] = "127.0.1.2";
static const uint8_t  ipv6[16] = {0x20, 0x02, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
static const uint8_t  ipv6b[16] = {0x20, 0x02, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17};
static const char     ipv6_text[] = "2002:0304:0506:0708:090a:0b0c:0d0e:0f10";
static const uint16_t port = 53;
static const uint16_t network_endian_port = NU16(53);
static const uint8_t  dname[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const char     dname_text[] = "yadifa.eu.";
static const uint8_t  dnameb[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'v', 0};

#define MYKEY_NAME (const uint8_t *)"\005mykey"
static const uint8_t mykey_mac[] = {0x81, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

static void          init()
{
    dnscore_init();
    int ret;

    ret = tsig_register(MYKEY_NAME, mykey_mac, sizeof(mykey_mac), HMAC_SHA1);

    if(FAIL(ret))
    {
        yatest_err("tsig_register failed with %x", ret);
        exit(1);
    }
}

static void finalise() { dnscore_finalize(); }

static int  ipv4_test()
{
    init();

    int             ret;
    host_address_t *ha0 = host_address_new_instance_ipv4(ipv4, network_endian_port);
    host_address_t *ha1 = host_address_new_instance_ipv4_tsig(ipv4, network_endian_port, NULL);
    host_address_t *ha2 = host_address_new_instance_parse(ipv4_text);
    host_address_set_default_port_value(ha2, network_endian_port);
    if(ha2->port != network_endian_port)
    {
        yatest_err("host_address_set_default_port_value didn't set the port");
        return 1;
    }
    ha2->port = ~0;
    host_address_set_port_value(ha2, network_endian_port);
    if(ha2->port != network_endian_port)
    {
        yatest_err("host_address_set_port_value didn't set the port");
        return 1;
    }
    host_address_t *ha3 = host_address_new_instance_parse_port(ipv4_text, port);
    host_address_t *ha4 = host_address_copy(ha0);
    host_address_t *ha_v6 = host_address_new_instance_ipv6(ipv6, network_endian_port);
    host_address_t *ha_d = host_address_new_instance_dname(dname, network_endian_port);

    if(!host_address_equals(ha0, ha1))
    {
        yatest_err("ha0!=ha1");
        return 1;
    }

    if(!host_address_equals(ha0, ha2))
    {
        yatest_err("ha0!=ha2");
        return 1;
    }

    if(!host_address_equals(ha0, ha3))
    {
        yatest_err("ha0!=ha3");
        return 1;
    }

    if(!host_address_equals(ha0, ha4))
    {
        yatest_err("ha0!=ha4");
        return 1;
    }

    if(host_address_equals(ha0, ha_v6))
    {
        yatest_err("ha0==ha_v6");
        return 1;
    }

    if(host_address_equals(ha0, ha_d))
    {
        yatest_err("ha0==ha_d");
        return 1;
    }

    if(!host_address_match(ha0, ha4))
    {
        yatest_err("ha0!=ha4 (match)");
        return 1;
    }

    ha4->port = 0;

    if(!host_address_match(ha0, ha4))
    {
        yatest_err("ha0!=ha4:0 (match)");
        return 1;
    }

    ha4->port = network_endian_port;

    if(host_address_match(ha0, ha_v6))
    {
        yatest_err("ha0==ha_v6 (match)");
        return 1;
    }

    if(host_address_match(ha0, ha_d))
    {
        yatest_err("ha0==ha_d (match)");
        return 1;
    }

    if(host_address_compare(ha0, ha4) != 0)
    {
        yatest_err("ha0!=ha4 (compare)");
        return 1;
    }

    if(host_address_compare(ha0, ha_v6) == 0)
    {
        yatest_err("ha0==ha_v6 (compare)");
        return 1;
    }

    if(host_address_compare(ha0, ha_d) == 0)
    {
        yatest_err("ha0==ha_d (compare)");
        return 1;
    }

    struct sockaddr *sa0;
    socketaddress_t  sa1;
    ret = host_address2allocated_sockaddr(ha0, &sa0);
    if(ret < 0)
    {
        yatest_err("host_address2allocated_sockaddr failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = host_address2sockaddr(ha0, &sa1);
    if(!sockaddr_equals(sa0, &sa1.sa))
    {
        yatest_err("sockaddr_equals returned false");
        return 1;
    }
    struct addrinfo *addr;
    ret = host_address2addrinfo(ha0, &addr);
    if(ret < 0)
    {
        yatest_err("host_address2addrinfo failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(!sockaddr_equals(sa0, addr->ai_addr))
    {
        yatest_err("sockaddr_equals returned false");
        return 1;
    }
    free(addr);

    host_address_t ha5;
    ret = host_address_set_with_socketaddress(&ha5, &sa1);
    if(ret < 0)
    {
        yatest_err("host_address_set_with_socketaddress failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(!host_address_equals(ha0, &ha5))
    {
        yatest_err("ha0!=ha5");
        return 1;
    }

    if(!host_address_list_contains_ip(ha0, &sa1))
    {
        yatest_err("host_address_list_contains_ip returned false");
        return 1;
    }

    if(!host_address_list_contains_ip_tsig(ha0, &sa1, NULL))
    {
        yatest_err("host_address_list_contains_ip_tsig returned false");
        return 1;
    }

    if(!host_address_list_contains_host(ha0, ha1))
    {
        yatest_err("host_address_list_contains_host returned false");
        return 1;
    }

    ret = host_address_append_ipv4(ha2, ipv4b, network_endian_port);
    if(ret < 0)
    {
        yatest_err("host_address_append_ipv4 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = host_address_append_ipv4(ha2, ipv4b, network_endian_port);
    if(ret != COLLECTION_DUPLICATE_ENTRY)
    {
        yatest_err("host_address_append_ipv4 expected to fail with COLLECTION_DUPLICATE_ENTRY but returned %08x", ret);
        return 1;
    }
    host_address_t *ha6 = host_address_new_instance_ipv4(ipv4b, network_endian_port);
    ret = host_address_append_host_address(ha3, ha6);
    if(ret < 0)
    {
        yatest_err("host_address_append_host_address failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = host_address_append_host_address(ha3, ha6);
    if(ret != COLLECTION_DUPLICATE_ENTRY)
    {
        yatest_err("host_address_append_host_address expected to fail with COLLECTION_DUPLICATE_ENTRY but returned %08x", ret);
        return 1;
    }
    socketaddress_t sa2;
    host_address2sockaddr(ha6, &sa2);
    ret = host_address_append_sockaddr(ha4, &sa2);
    if(ret < 0)
    {
        yatest_err("host_address_append_sockaddr failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = host_address_append_sockaddr(ha4, &sa2);
    if(ret != COLLECTION_DUPLICATE_ENTRY)
    {
        yatest_err("host_address_append_sockaddr expected to fail with COLLECTION_DUPLICATE_ENTRY but returned %08x", ret);
        return 1;
    }

    ret = host_address_append_sockaddr_with_port(&ha5, &sa2, network_endian_port);
    if(ret < 0)
    {
        yatest_err("host_address_append_sockaddr_with_port failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = host_address_append_sockaddr_with_port(&ha5, &sa2, network_endian_port);
    if(ret != SUCCESS)
    {
        yatest_err("host_address_append_sockaddr_with_port expected to return SUCCESS but returned %08x", ret);
        return 1;
    }

    if(!host_address_list_equals(ha2, ha3))
    {
        yatest_err("host_address_list_equals returned false (ha2,ha3)");
        return 1;
    }

    host_address_list_roll(&ha2);

    if(host_address_list_equals(ha2, ha3))
    {
        yatest_err("host_address_list_equals returned true (rolled ha2,ha3)");
        return 1;
    }

    host_address_list_roll(&ha2);

    if(!host_address_list_equals(ha2, ha3))
    {
        yatest_err("host_address_list_equals returned false (double-rolled ha2,ha3)");
        return 1;
    }

    host_address_t *ha7 = host_address_remove_host_address(&ha2, ha6);
    if(ha7 == NULL)
    {
        yatest_err("host_address_remove_host_address returned NULL");
        return 1;
    }
    host_address_t *ha8 = host_address_remove_host_address(&ha2, ha6);
    if(ha8 != NULL)
    {
        yatest_err("host_address_remove_host_address didn't return NULL");
        return 1;
    }
    host_address_t *ha9 = NULL /*host_address_new_instance()*/;
    formatln("ha3=%{hostaddrlist}", ha3);
    if(!host_address_update_host_address_list(&ha9, ha3))
    {
        yatest_err("host_address_update_host_address_list should have returned true");
        return 1;
    }
    formatln("ha9=%{hostaddrlist}", ha9);
    if(host_address_update_host_address_list(&ha9, ha3))
    {
        yatest_err("host_address_update_host_address_list should have returned false");
        return 1;
    }
    host_address_t *ha10 = host_address_new_instance_parse_port("1.2.3.4", port);
    formatln("ha3=%{hostaddrlist}", ha3);
    if(!host_address_update_host_address_list(&ha10, ha3))
    {
        yatest_err("host_address_update_host_address_list should have returned true");
        return 1;
    }
    formatln("ha10=%{hostaddrlist}", ha10);
    if(host_address_update_host_address_list(&ha10, ha3))
    {
        yatest_err("host_address_update_host_address_list should have returned false");
        return 1;
    }
    host_address_t *ha11 = host_address_new_instance();
    formatln("ha3=%{hostaddrlist}", ha3);
    if(!host_address_update_host_address_list(&ha11, ha3))
    {
        yatest_err("host_address_update_host_address_list should have returned true");
        return 1;
    }
    formatln("ha11=%{hostaddrlist}", ha11);
    if(host_address_update_host_address_list(&ha11, ha3))
    {
        yatest_err("host_address_update_host_address_list should have returned false");
        return 1;
    }

    char *expected_text;
    char  text[256];

    memset(text, 0, sizeof(text));
    expected_text = "127.0.1.2";
    ret = host_address_to_str(ha0, text, sizeof(text), 0);
    if(ret < 0)
    {
        yatest_err("host_address_to_str 0 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(strcmp(text, expected_text) != 0)
    {
        yatest_err("got '%s', expected '%s' (0)", text, expected_text);
        return 1;
    }

    ha0->tsig = tsig_get(MYKEY_NAME);

    memset(text, 0, sizeof(text));
    expected_text = "127.0.1.2:53*mykey.";
    ret = host_address_to_str(ha0, text, sizeof(text), HOST_ADDRESS_TO_STR_PORT | HOST_ADDRESS_TO_STR_TSIG);
    if(ret < 0)
    {
        yatest_err("host_address_to_str 0 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(strcmp(text, expected_text) != 0)
    {
        yatest_err("got '%s', expected '%s' (HOST_ADDRESS_TO_STR_PORT|HOST_ADDRESS_TO_STR_TSIG)", text, expected_text);
        return 1;
    }

    memset(text, 0, sizeof(text));
    expected_text = "127.0.1.2 port 53 key mykey.";
    ret = host_address_to_str(ha0, text, sizeof(text), HOST_ADDRESS_TO_STR_FULLPORT | HOST_ADDRESS_TO_STR_FULLTSIG);
    if(ret < 0)
    {
        yatest_err("host_address_to_str 0 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(strcmp(text, expected_text) != 0)
    {
        yatest_err("got '%s', expected '%s' (HOST_ADDRESS_TO_STR_PORT|HOST_ADDRESS_TO_STR_TSIG)", text, expected_text);
        return 1;
    }

    if(host_address_is_any(ha0))
    {
        yatest_err("host_address_is_any returned true");
        return 1;
    }

    if((ret = host_address_count(ha3)) != 2)
    {
        yatest_err("host_address_count expected to return 2, returned %i", ret);
        return 1;
    }

    host_address_finalise(&ha5);
    host_address_delete_list(ha4);
    host_address_delete_list(ha3);
    host_address_delete_list(ha2);
    host_address_delete_list(ha1);
    host_address_delete_list(ha0);

    finalise();
    return 0;
}

static int ipv6_test()
{
    init();

    int             ret;
    host_address_t *ha0 = host_address_new_instance_ipv6(ipv6, network_endian_port);
    host_address_t *ha1 = host_address_new_instance_ipv6_tsig(ipv6, network_endian_port, NULL);
    host_address_t *ha2 = host_address_new_instance_parse(ipv6_text);
    host_address_set_default_port_value(ha2, network_endian_port);
    if(ha2->port != network_endian_port)
    {
        yatest_err("host_address_set_default_port_value didn't set the port");
        return 1;
    }
    ha2->port = ~0;
    host_address_set_port_value(ha2, network_endian_port);
    if(ha2->port != network_endian_port)
    {
        yatest_err("host_address_set_port_value didn't set the port");
        return 1;
    }
    host_address_t *ha3 = host_address_new_instance_parse_port(ipv6_text, port);
    host_address_t *ha4 = host_address_copy(ha0);
    host_address_t *ha_v4 = host_address_new_instance_ipv6(ipv4, network_endian_port);
    host_address_t *ha_d = host_address_new_instance_dname(dname, network_endian_port);

    if(!host_address_equals(ha0, ha1))
    {
        yatest_err("ha0!=ha1");
        return 1;
    }

    if(!host_address_equals(ha0, ha2))
    {
        yatest_err("ha0!=ha2");
        return 1;
    }

    if(!host_address_equals(ha0, ha3))
    {
        yatest_err("ha0!=ha3");
        return 1;
    }

    if(!host_address_equals(ha0, ha4))
    {
        yatest_err("ha0!=ha4");
        return 1;
    }

    if(host_address_equals(ha0, ha_v4))
    {
        yatest_err("ha0==ha_v4");
        return 1;
    }

    if(host_address_equals(ha0, ha_d))
    {
        yatest_err("ha0==ha_d");
        return 1;
    }

    if(!host_address_match(ha0, ha4))
    {
        yatest_err("ha0!=ha4 (match)");
        return 1;
    }

    ha4->port = 0;

    if(!host_address_match(ha0, ha4))
    {
        yatest_err("ha0!=ha4:0 (match)");
        return 1;
    }

    ha4->port = network_endian_port;

    if(host_address_match(ha0, ha_v4))
    {
        yatest_err("ha0==ha_v4 (match)");
        return 1;
    }

    if(host_address_match(ha0, ha_d))
    {
        yatest_err("ha0==ha_d (match)");
        return 1;
    }

    if(host_address_compare(ha0, ha4) != 0)
    {
        yatest_err("ha0!=ha4 (compare)");
        return 1;
    }

    if(host_address_compare(ha0, ha_v4) == 0)
    {
        yatest_err("ha0==ha_v4 (compare)");
        return 1;
    }

    if(host_address_compare(ha0, ha_d) == 0)
    {
        yatest_err("ha0==ha_d (compare)");
        return 1;
    }

    struct sockaddr *sa0;
    socketaddress_t  sa1;
    ret = host_address2allocated_sockaddr(ha0, &sa0);
    if(ret < 0)
    {
        yatest_err("host_address2allocated_sockaddr failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = host_address2sockaddr(ha0, &sa1);
    if(!sockaddr_equals(sa0, &sa1.sa))
    {
        yatest_err("sockaddr_equals returned false");
        return 1;
    }
    struct addrinfo *addr;
    ret = host_address2addrinfo(ha0, &addr);
    if(ret < 0)
    {
        yatest_err("host_address2addrinfo failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(!sockaddr_equals(sa0, addr->ai_addr))
    {
        yatest_err("sockaddr_equals returned false");
        return 1;
    }
    free(addr);

    host_address_t ha5;
    ret = host_address_set_with_socketaddress(&ha5, &sa1);
    if(ret < 0)
    {
        yatest_err("host_address_set_with_socketaddress failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(!host_address_equals(ha0, &ha5))
    {
        yatest_err("ha0!=ha5");
        return 1;
    }

    if(!host_address_list_contains_ip(ha0, &sa1))
    {
        yatest_err("host_address_list_contains_ip returned false");
        return 1;
    }

    if(!host_address_list_contains_ip_tsig(ha0, &sa1, NULL))
    {
        yatest_err("host_address_list_contains_ip_tsig returned false");
        return 1;
    }

    if(!host_address_list_contains_host(ha0, ha1))
    {
        yatest_err("host_address_list_contains_host returned false");
        return 1;
    }

    ret = host_address_append_ipv6(ha2, ipv6b, network_endian_port);
    if(ret < 0)
    {
        yatest_err("host_address_append_ipv6 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = host_address_append_ipv6(ha2, ipv6b, network_endian_port);
    if(ret != COLLECTION_DUPLICATE_ENTRY)
    {
        yatest_err("host_address_append_ipv6 expected to fail with COLLECTION_DUPLICATE_ENTRY but returned %08x", ret);
        return 1;
    }
    host_address_t *ha6 = host_address_new_instance_ipv6(ipv6b, network_endian_port);
    ret = host_address_append_host_address(ha3, ha6);
    if(ret < 0)
    {
        yatest_err("host_address_append_host_address failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = host_address_append_host_address(ha3, ha6);
    if(ret != COLLECTION_DUPLICATE_ENTRY)
    {
        yatest_err("host_address_append_host_address expected to fail with COLLECTION_DUPLICATE_ENTRY but returned %08x", ret);
        return 1;
    }
    socketaddress_t sa2;
    host_address2sockaddr(ha6, &sa2);
    ret = host_address_append_sockaddr(ha4, &sa2);
    if(ret < 0)
    {
        yatest_err("host_address_append_sockaddr failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = host_address_append_sockaddr(ha4, &sa2);
    if(ret != COLLECTION_DUPLICATE_ENTRY)
    {
        yatest_err("host_address_append_sockaddr expected to fail with COLLECTION_DUPLICATE_ENTRY but returned %08x", ret);
        return 1;
    }

    ret = host_address_append_sockaddr_with_port(&ha5, &sa2, network_endian_port);
    if(ret < 0)
    {
        yatest_err("host_address_append_sockaddr_with_port failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = host_address_append_sockaddr_with_port(&ha5, &sa2, network_endian_port);
    if(ret != SUCCESS)
    {
        yatest_err("host_address_append_sockaddr_with_port expected to return SUCCESS but returned %08x", ret);
        return 1;
    }

    if(!host_address_list_equals(ha2, ha3))
    {
        yatest_err("host_address_list_equals returned false (ha2,ha3)");
        return 1;
    }

    host_address_list_roll(&ha2);

    if(host_address_list_equals(ha2, ha3))
    {
        yatest_err("host_address_list_equals returned true (rolled ha2,ha3)");
        return 1;
    }

    host_address_list_roll(&ha2);

    if(!host_address_list_equals(ha2, ha3))
    {
        yatest_err("host_address_list_equals returned false (double-rolled ha2,ha3)");
        return 1;
    }

    host_address_t *ha7 = host_address_remove_host_address(&ha2, ha6);
    if(ha7 == NULL)
    {
        yatest_err("host_address_remove_host_address returned NULL");
        return 1;
    }
    host_address_t *ha8 = host_address_remove_host_address(&ha2, ha6);
    if(ha8 != NULL)
    {
        yatest_err("host_address_remove_host_address didn't return NULL");
        return 1;
    }
    host_address_t *ha9 = NULL /*host_address_new_instance()*/;
    formatln("ha3=%{hostaddrlist}", ha3);
    if(!host_address_update_host_address_list(&ha9, ha3))
    {
        yatest_err("host_address_update_host_address_list should have returned true");
        return 1;
    }
    formatln("ha9=%{hostaddrlist}", ha9);
    if(host_address_update_host_address_list(&ha9, ha3))
    {
        yatest_err("host_address_update_host_address_list should have returned false");
        return 1;
    }
    host_address_t *ha10 = host_address_new_instance_parse_port("1.2.3.4", port);
    formatln("ha3=%{hostaddrlist}", ha3);
    if(!host_address_update_host_address_list(&ha10, ha3))
    {
        yatest_err("host_address_update_host_address_list should have returned true");
        return 1;
    }
    formatln("ha10=%{hostaddrlist}", ha10);
    if(host_address_update_host_address_list(&ha10, ha3))
    {
        yatest_err("host_address_update_host_address_list should have returned false");
        return 1;
    }
    host_address_t *ha11 = host_address_new_instance();
    formatln("ha3=%{hostaddrlist}", ha3);
    if(!host_address_update_host_address_list(&ha11, ha3))
    {
        yatest_err("host_address_update_host_address_list should have returned true");
        return 1;
    }
    formatln("ha11=%{hostaddrlist}", ha11);
    if(host_address_update_host_address_list(&ha11, ha3))
    {
        yatest_err("host_address_update_host_address_list should have returned false");
        return 1;
    }

    char *expected_text;
    char  text[256];

    memset(text, 0, sizeof(text));
    expected_text = "2002:304:506:708:90a:b0c:d0e:f10";
    ret = host_address_to_str(ha0, text, sizeof(text), 0);
    if(ret < 0)
    {
        yatest_err("host_address_to_str 0 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(strcmp(text, expected_text) != 0)
    {
        yatest_err("got '%s', expected '%s' (0)", text, expected_text);
        return 1;
    }

    ha0->tsig = tsig_get(MYKEY_NAME);

    memset(text, 0, sizeof(text));
    expected_text = "2002:304:506:708:90a:b0c:d0e:f10#53*mykey.";
    ret = host_address_to_str(ha0, text, sizeof(text), HOST_ADDRESS_TO_STR_PORT | HOST_ADDRESS_TO_STR_TSIG);
    if(ret < 0)
    {
        yatest_err("host_address_to_str 0 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(strcmp(text, expected_text) != 0)
    {
        yatest_err("got '%s', expected '%s' (HOST_ADDRESS_TO_STR_PORT|HOST_ADDRESS_TO_STR_TSIG)", text, expected_text);
        return 1;
    }

    memset(text, 0, sizeof(text));
    expected_text = "2002:304:506:708:90a:b0c:d0e:f10 port 53 key mykey.";
    ret = host_address_to_str(ha0, text, sizeof(text), HOST_ADDRESS_TO_STR_FULLPORT | HOST_ADDRESS_TO_STR_FULLTSIG);
    if(ret < 0)
    {
        yatest_err("host_address_to_str 0 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(strcmp(text, expected_text) != 0)
    {
        yatest_err("got '%s', expected '%s' (HOST_ADDRESS_TO_STR_PORT|HOST_ADDRESS_TO_STR_TSIG)", text, expected_text);
        return 1;
    }

    if(host_address_is_any(ha0))
    {
        yatest_err("host_address_is_any returned true");
        return 1;
    }

    if((ret = host_address_count(ha3)) != 2)
    {
        yatest_err("host_address_count expected to return 2, returned %i", ret);
        return 1;
    }

    host_address_finalise(&ha5);
    host_address_delete_list(ha4);
    host_address_delete_list(ha3);
    host_address_delete_list(ha2);
    host_address_delete_list(ha1);
    host_address_delete_list(ha0);

    finalise();
    return 0;
}

static int dname_test()
{
    init();

    int             ret;
    host_address_t *ha0 = host_address_new_instance_dname(dname, network_endian_port);
    host_address_t *ha1 = host_address_new_instance_dname_tsig(dname, network_endian_port, NULL);
    host_address_t *ha2 = host_address_new_instance_parse(dname_text);
    host_address_set_default_port_value(ha2, network_endian_port);
    if(ha2->port != network_endian_port)
    {
        yatest_err("host_address_set_default_port_value didn't set the port");
        return 1;
    }
    ha2->port = ~0;
    host_address_set_port_value(ha2, network_endian_port);
    if(ha2->port != network_endian_port)
    {
        yatest_err("host_address_set_port_value didn't set the port");
        return 1;
    }
    host_address_t *ha3 = host_address_new_instance_parse_port(dname_text, port);
    host_address_t *ha4 = host_address_copy(ha0);
    host_address_t *ha_v4 = host_address_new_instance_ipv4(ipv4, network_endian_port);
    host_address_t *ha_v6 = host_address_new_instance_ipv6(ipv6, network_endian_port);

    if(!host_address_equals(ha0, ha1))
    {
        yatest_err("ha0!=ha1");
        return 1;
    }

    if(!host_address_equals(ha0, ha2))
    {
        yatest_err("ha0!=ha2");
        return 1;
    }

    if(!host_address_equals(ha0, ha3))
    {
        yatest_err("ha0!=ha3");
        return 1;
    }

    if(!host_address_equals(ha0, ha4))
    {
        yatest_err("ha0!=ha4");
        return 1;
    }

    if(host_address_equals(ha0, ha_v4))
    {
        yatest_err("ha0==ha_v4");
        return 1;
    }

    if(host_address_equals(ha0, ha_v6))
    {
        yatest_err("ha0==ha_v6");
        return 1;
    }

    if(!host_address_match(ha0, ha4))
    {
        yatest_err("ha0!=ha4 (match)");
        return 1;
    }

    ha4->port = 0;

    if(!host_address_match(ha0, ha4))
    {
        yatest_err("ha0!=ha4:0 (match)");
        return 1;
    }

    ha4->port = network_endian_port;

    if(host_address_match(ha0, ha_v4))
    {
        yatest_err("ha0==ha_v4 (match)");
        return 1;
    }

    if(host_address_match(ha0, ha_v6))
    {
        yatest_err("ha0==ha_v6 (match)");
        return 1;
    }

    if(host_address_compare(ha0, ha4) != 0)
    {
        yatest_err("ha0!=ha4 (compare)");
        return 1;
    }

    if(host_address_compare(ha0, ha_v4) == 0)
    {
        yatest_err("ha0==ha_v4 (compare)");
        return 1;
    }

    if(host_address_compare(ha0, ha_v6) == 0)
    {
        yatest_err("ha0==ha_v6 (compare)");
        return 1;
    }

    ret = host_address_append_dname(ha2, dnameb, network_endian_port);
    if(ret < 0)
    {
        yatest_err("host_address_append_dname failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = host_address_append_dname(ha2, dnameb, network_endian_port);
    if(ret != COLLECTION_DUPLICATE_ENTRY)
    {
        yatest_err("host_address_append_dname expected to fail with COLLECTION_DUPLICATE_ENTRY but returned %08x", ret);
        return 1;
    }
    host_address_t *ha6 = host_address_new_instance_dname(dnameb, network_endian_port);
    ret = host_address_append_host_address(ha3, ha6);
    if(ret < 0)
    {
        yatest_err("host_address_append_host_address failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = host_address_append_host_address(ha3, ha6);
    if(ret != COLLECTION_DUPLICATE_ENTRY)
    {
        yatest_err("host_address_append_host_address expected to fail with COLLECTION_DUPLICATE_ENTRY but returned %08x", ret);
        return 1;
    }

    char *expected_text;
    char  text[256];

    memset(text, 0, sizeof(text));
    expected_text = "yadifa.eu.";
    ret = host_address_to_str(ha0, text, sizeof(text), 0);
    if(ret < 0)
    {
        yatest_err("host_address_to_str 0 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(strcmp(text, expected_text) != 0)
    {
        yatest_err("got '%s', expected '%s' (0)", text, expected_text);
        return 1;
    }

    ha0->tsig = tsig_get(MYKEY_NAME);

    memset(text, 0, sizeof(text));
    expected_text = "yadifa.eu.:53*mykey.";
    ret = host_address_to_str(ha0, text, sizeof(text), HOST_ADDRESS_TO_STR_PORT | HOST_ADDRESS_TO_STR_TSIG);
    if(ret < 0)
    {
        yatest_err("host_address_to_str 0 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(strcmp(text, expected_text) != 0)
    {
        yatest_err("got '%s', expected '%s' (HOST_ADDRESS_TO_STR_PORT|HOST_ADDRESS_TO_STR_TSIG)", text, expected_text);
        return 1;
    }

    memset(text, 0, sizeof(text));
    expected_text = "yadifa.eu. port 53 key mykey.";
    ret = host_address_to_str(ha0, text, sizeof(text), HOST_ADDRESS_TO_STR_FULLPORT | HOST_ADDRESS_TO_STR_FULLTSIG);
    if(ret < 0)
    {
        yatest_err("host_address_to_str 0 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(strcmp(text, expected_text) != 0)
    {
        yatest_err("got '%s', expected '%s' (HOST_ADDRESS_TO_STR_PORT|HOST_ADDRESS_TO_STR_TSIG)", text, expected_text);
        return 1;
    }

    if(host_address_is_any(ha0))
    {
        yatest_err("host_address_is_any returned true");
        return 1;
    }

    if((ret = host_address_count(ha3)) != 2)
    {
        yatest_err("host_address_count expected to return 2, returned %i", ret);
        return 1;
    }

    host_address_t ha12;
    host_address_set_dname(&ha12, dname, network_endian_port);
    host_address_finalise(&ha12);

    host_address_delete_list(ha4);
    host_address_delete_list(ha3);
    host_address_delete_list(ha2);
    host_address_delete_list(ha1);
    host_address_delete_list(ha0);

    finalise();
    return 0;
}

static int error_test()
{
    int ret;
    init();
    host_address_t ha12;
    host_address_t ha13;
    host_address_set_dname(&ha12, dname, network_endian_port);
    host_address_set_dname(&ha12, dnameb, network_endian_port);
    struct sockaddr *sa;
    ret = host_address2allocated_sockaddr(&ha12, &sa);
    if(ret != IP_VERSION_NOT_SUPPORTED)
    {
        yatest_err("host_address2allocated_sockaddr expected to return IP_VERSION_NOT_SUPPORTED, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    socketaddress_t ss;
    ret = host_address2sockaddr(&ha12, &ss);
    if(ret != IP_VERSION_NOT_SUPPORTED)
    {
        yatest_err("host_address2sockaddr expected to return IP_VERSION_NOT_SUPPORTED, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    struct addrinfo *addr;
    ret = host_address2addrinfo(&ha12, &addr);
    if(ret != IP_VERSION_NOT_SUPPORTED)
    {
        yatest_err("host_address2addrinfo expected to return IP_VERSION_NOT_SUPPORTED, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    memset(&ss, 0, sizeof(ss));
    ret = host_address_set_with_socketaddress(&ha12, &ss);
    if(ret != IP_VERSION_NOT_SUPPORTED)
    {
        yatest_err("host_address_set_with_socketaddress expected to return IP_VERSION_NOT_SUPPORTED, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = host_address_append_host_address(&ha12, &ha13);
    if(ret != IP_VERSION_NOT_SUPPORTED)
    {
        yatest_err("host_address_append_host_address expected to return IP_VERSION_NOT_SUPPORTED, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    ret = host_address_append_sockaddr(&ha12, NULL);
    if(ret != UNEXPECTED_NULL_ARGUMENT_ERROR)
    {
        yatest_err("host_address_append_sockaddr expected to return UNEXPECTED_NULL_ARGUMENT_ERROR, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = host_address_append_sockaddr_with_port(&ha12, NULL, network_endian_port);
    if(ret != UNEXPECTED_NULL_ARGUMENT_ERROR)
    {
        yatest_err("host_address_append_sockaddr_with_port expected to return UNEXPECTED_NULL_ARGUMENT_ERROR, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    host_address_finalise(&ha12);
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(ipv4_test)
YATEST(ipv6_test)
YATEST(dname_test)
YATEST(error_test)
YATEST_TABLE_END
