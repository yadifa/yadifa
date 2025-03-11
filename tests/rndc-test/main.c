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
#include <dnscore/rndc.h>
#include "dnscore/base64.h"
#include "dnscore/fdtools.h"
#include "dnscore/format.h"
#include "dnscore/file_input_stream.h"
#include "dnscore/parsing.h"

#define PORT NU16(10938)

static uint8_t       *name = (uint8_t *)"\010rndc-key";
static char          *algorithm = "hmac-sha256";
static char          *secret = "HCmGmZkvl9pBbg/ZhV2kgdfj7lRwYdLCiEjRziLaqo4=";
static uint8_t        server_ip[16] = {127, 0, 0, 1};
static uint16_t       server_port = PORT;
static host_address_t ha;

#if 0
static int server_socket_init()
{
    int on = 1;

    int sockfd = socket(AF_INET, SOCK_STREAM, SOCKET_PROTOCOL_FROM_TYPE(SOCK_STREAM));
    if(sockfd < 0)
    {
        printf("socket!");
        exit(EXIT_FAILURE);
    }

    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on))))
    {
        socketclose_ex(sockfd);
        printf("reuseaddr!");
        exit(EXIT_FAILURE);
    }

#ifdef SO_REUSEPORT
    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *) &on, sizeof(on))))
    {
        perror("reuseport!");
        socketclose_ex(sockfd);
        exit(EXIT_FAILURE);
    }
#endif

    socketaddress sa;
    host_address2sockaddr(&ha, &sa);

    if(FAIL(bind(sockfd,
                 &sa.sa,
                 sizeof(sa.sa4))))
    {
        perror("bind!");
        socketclose_ex(sockfd);
        exit(EXIT_FAILURE);
    }

    listen(sockfd, 5);

    return sockfd;
}
#endif

static void cut_the_crap(char *word)
{
    size_t len = strlen(word);
    while(--len > 0)
    {
        if((word[len] == '"') || (word[len] == ';'))
        {
            word[len] = '\0';
        }
    }
}

static ya_result rndc_conf_read(const char *rndc_conf)
{
    input_stream_t is;
    ya_result      ret = file_input_stream_open(&is, rndc_conf);
    char           _line[1024];
    char           word[1024];

    if(ISOK(ret))
    {
        for(;;)
        {
            ret = input_stream_read_line(&is, _line, sizeof(_line));

            if(ret <= 0)
            {
                break;
            }

            _line[ret] = '\0';

            const char *line = parse_skip_spaces(_line);

            memset(word, 0xff, sizeof(word));

            if(sscanf(line, "key \"%s\"", word) == 1)
            {
                cut_the_crap(word);
                formatln("key='%s'", word);
                size_t word_len = strlen(word);
                name = (uint8_t *)malloc(word_len + 2);
                dnsname_init_with_cstr(name, word);
            }
            else if(sscanf(line, "algorithm \"%s\";", word) == 1)
            {
                cut_the_crap(word);
                formatln("algorithm='%s'", word);
                algorithm = strdup(word);
            }
            else if(sscanf(line, "secret \"%s\";", word) == 1)
            {
                cut_the_crap(word);
                formatln("secret='%s'", word);
                secret = strdup(word);
            }
            else if(sscanf(line, "default-server %s;", word) == 1)
            {
                cut_the_crap(word);
                formatln("default-server='%s'", word);
                parse_ip_address(word, strlen(word), server_ip, sizeof(server_ip));
            }
            else if(sscanf(line, "default-port %s;", word) == 1)
            {
                cut_the_crap(word);
                formatln("default-port=%s", word);
                server_port = htons(atoi(word));
            }
        }

        input_stream_close(&is);
    }

    flushout();

    return ret;
}

#if 0
static void *server_thread_entry(void *args)
{
    if(args == NULL)
    {
        return NULL;
    }

    socketaddress sa;
    int sockfd = *((int*)args);

    for(;;)
    {
        socklen_t sa_len = sizeof(socketaddress);
        int clientfd = accept(sockfd, &sa, &sa_len);
        if(clientfd < 0)
        {
            perror("accept!");
            socketclose_ex(sockfd);
            exit(EXIT_FAILURE);
        }

        close_ex(clientfd);

        break;
    }

    socketclose_ex(sockfd);

    return NULL;
}
#endif

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    const char *command = "status dnssec-none.eu"; // default command

    /* initializes the core library */
    dnscore_init();

    if(argc > 1)
    {
        if(FAIL(rndc_conf_read(argv[1])))
        {
            return EXIT_FAILURE;
        }
    }

    if(argc > 2)
    {
        command = argv[2];
    }

    uint32_t mac_size_expected = BASE64_DECODED_SIZE(strlen(secret));
    uint8_t *mac_bytes = (uint8_t *)malloc(mac_size_expected + 1);
    memset(mac_bytes, 0xff, mac_size_expected);
    mac_bytes[mac_size_expected] = 0xa5;
    int mac_size = base64_decode(secret, strlen(secret), mac_bytes);
    if(FAIL(mac_size))
    {
        return EXIT_FAILURE;
    }

    memset(&ha, 0, sizeof(ha));
    host_address_set_ipv4(&ha, server_ip, server_port);
    formatln("address: %{hostaddr}", &ha);
    flushout();

    tsig_register(name, mac_bytes, mac_size, tsig_get_hmac_algorithm_from_friendly_name(algorithm));

    rndc_message_t rndcmsg;

    println("connecting ...");
    ya_result ret = rndc_init_and_connect(&rndcmsg, &ha, tsig_get(name));

    if(ISOK(ret))
    {
        println("sending command ...");
        rndc_send_command(&rndcmsg, command);
        println("");
        uint32_t result = 0;
        if(ISOK(ret = rndc_result(&rndcmsg, &result)))
        {
            formatln("result: %u", result);
        }
        else
        {
            formatln("no result: %r", result);
        }

        rndc_disconnect(&rndcmsg);
    }

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
