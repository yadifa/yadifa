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

#include <dnscore/dnscore.h>
#include <dnscore/dns_message.h>
#include "dnscore/dns_udp.h"

#define DNS_UDP_PORT_COUNT_OVERRIDE 32

static dns_udp_settings_t  dns_udp_default_settings = {DNS_UDP_TIMEOUT_US,
                                                       DNS_UDP_SEND_RATE,
                                                       DNS_UDP_SEND_BANDWIDTH,
                                                       DNS_UDP_RECV_BANDWIDTH,
                                                       DNS_UDP_SEND_QUEUE,
                                                       DNS_UDP_PORT_COUNT_OVERRIDE,
                                                       DNS_UDP_RETRY_COUNT,
                                                       DNS_UDP_PER_DNS_RATE,
                                                       DNS_UDP_PER_DNS_BANDWIDTH,
                                                       DNS_UDP_PER_DNS_FREQ_MIN,
                                                       DNS_UDP_READ_BUFFER_COUNT,
                                                       DNS_UDP_CALLBACK_QUEUE_SIZE,
                                                       DNS_UDP_CALLBACK_THREAD_COUNT,
                                                       DNS_UDP_TCP_THREAD_POOL_SIZE,
                                                       DNS_UDP_TCP_FALLBACK_ON_TIMEOUT};

static dns_udp_settings_t *g_dns_udp_settings = &dns_udp_default_settings;

static void                dns_message_test_callback(async_message_t *domain_message)
{
    dns_simple_message_t *simple_message = (dns_simple_message_t *)domain_message->args;
    dns_message_t        *mesg = simple_message->answer;
    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_buffer_size(mesg), 0x0f, 0);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* initializes the core library */

    dnscore_init();

    host_address_t *server = host_address_new_instance();
    server->version = HOST_ADDRESS_IPV4;
    server->ip.v4.value = 0x08080808;
    server->port = htons(53);

    dns_message_t *mesg = dns_message_new_instance_ex(NULL, 65536);
    dns_message_finalize(mesg);

    const uint8_t *fqdns[3] = {
        (const uint8_t *)"\005eurid\002eu",
        (const uint8_t *)"\011hurrikhan\002eu",
        (const uint8_t *)"\006google\002eu",
    };

    async_message_pool_init();

    dns_udp_handler_init();
    dns_udp_handler_start();
    dns_udp_handler_configure(g_dns_udp_settings);

    for(int j = 0; j < 3; ++j)
    {
        const uint8_t *fqdn = fqdns[j];

        dns_udp_send_simple_message(server, fqdn, TYPE_DNSKEY, CLASS_IN, MESSAGE_EDNS0_SIZE, dns_message_test_callback, NULL);
        dns_udp_send_recursive_message(server, fqdn, TYPE_DNSKEY, CLASS_IN, MESSAGE_EDNS0_SIZE, dns_message_test_callback, NULL);
        dns_udp_send_simple_message(server, fqdn, TYPE_SOA, CLASS_IN, MESSAGE_EDNS0_SIZE, dns_message_test_callback, NULL);
        dns_udp_send_recursive_message(server, fqdn, TYPE_SOA, CLASS_IN, MESSAGE_EDNS0_SIZE, dns_message_test_callback, NULL);
        dns_udp_send_simple_message(server, fqdn, TYPE_ANY, CLASS_IN, MESSAGE_EDNS0_SIZE, dns_message_test_callback, NULL);
        dns_udp_send_recursive_message(server, fqdn, TYPE_ANY, CLASS_IN, MESSAGE_EDNS0_SIZE, dns_message_test_callback, NULL);

        for(int i = 0; i < 10; ++i)
        {
            dns_udp_send_simple_message(server, fqdn, ntohs(i), CLASS_IN, MESSAGE_EDNS0_SIZE, dns_message_test_callback, NULL);
            dns_udp_send_recursive_message(server, fqdn, ntohs(i), CLASS_IN, MESSAGE_EDNS0_SIZE, dns_message_test_callback, NULL);
        }
    }

    sleep(600);

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
