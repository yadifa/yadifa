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
#include "dnscore/host_address.h"
#include "dnscore/tcp_io_stream.h"
#include <dnscore/dnscore.h>
#include <dnscore/crypto.h>
#include <dnscore/ssl_input_output_stream.h>

static const char *alternate_preferred_ciphers = "!NULL:!SSLv2:!RC4:!aNULL";

static void        init()
{
    dnscore_init();
    crypto_init();
}

static void finalise()
{
    crypto_finalise();
    dnscore_finalize();
}

static int simple_test()
{
    int ret;
    init();
    const char *default_preferred_ciphers = strdup(crypto_preferred_ciphers());
    yatest_log("default_preferred_ciphers=%s", default_preferred_ciphers);
    crypto_preferred_ciphers_set(alternate_preferred_ciphers);
    const char *preferred_ciphers = crypto_preferred_ciphers();
    yatest_log("preferred_ciphers=%s", preferred_ciphers);
    if(strcmp(preferred_ciphers, alternate_preferred_ciphers) != 0)
    {
        yatest_err("expected preferred cipher to be '%s', got '%s'", alternate_preferred_ciphers, preferred_ciphers);
        return 1;
    }
    crypto_preferred_ciphers_set(NULL);
    const char *reset_preferred_ciphers = crypto_preferred_ciphers();
    yatest_log("reset_preferred_ciphers=%s", reset_preferred_ciphers);
    if(strcmp(reset_preferred_ciphers, default_preferred_ciphers) != 0)
    {
        yatest_err("expected preferred cipher to be '%s', got '%s'", alternate_preferred_ciphers, reset_preferred_ciphers);
        return 1;
    }

    const uint8_t   ip[4] = {104, 16, 75, 15}; // www.eurid.eu
    host_address_t *server = host_address_new_instance_ipv4(ip, NU16(443));
    input_stream_t  is;
    output_stream_t os;

    if(ISOK(ret = tcp_input_output_stream_connect_host_address(server, &is, &os, 3)))
    {
        ssl_input_output_stream_init(&is, &is, &os, &os, NULL, NULL);
        const char *http_query = "GET /\r\n\r\n";
        ret = output_stream_write(&os, http_query, strlen(http_query));
        ret = output_stream_flush(&os);
        size_t line_size = 0x100000;
        char  *line = (char *)malloc(line_size);
        for(;;)
        {
            ret = input_stream_read_line(&is, line, line_size);
            if(ret > 0)
            {
                line[ret] = '\0';
                while((ret >= 0) && (line[ret] <= ' '))
                {
                    line[ret--] = '\0';
                }
                yatest_log("line: '%s'", line);
            }
            else
            {
                break;
            }
        }
    }

    ret = crypto_openssl_error();
    if(ret != 0)
    {
        yatest_err("crypto_openssl_error failed with %s", error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int error_test()
{
    int ret;
    init();

    const uint8_t   ip[4] = {185, 36, 4, 252}; // ns1.eurid.eu
    host_address_t *server = host_address_new_instance_ipv4(ip, NU16(53));
    input_stream_t  is;
    output_stream_t os;

    if(ISOK(ret = tcp_input_output_stream_connect_host_address(server, &is, &os, 3)))
    {
        crypto_preferred_ciphers_set("noclue");
        tcp_set_sendtimeout(fd_input_stream_get_filedescriptor(&is), 3, 0);
        tcp_set_recvtimeout(fd_output_stream_get_filedescriptor(&os), 3, 0);
        ret = ssl_input_output_stream_init(&is, &is, &os, &os, NULL, NULL);
        if(ISOK(ret))
        {
            const char *http_query = "GET /\r\n\r\n";
            ret = output_stream_write(&os, http_query, strlen(http_query));
            ret = output_stream_flush(&os);
            size_t line_size = 0x100000;
            char  *line = (char *)malloc(line_size);
            for(;;)
            {
                ret = input_stream_read_line(&is, line, line_size);
                if(ret > 0)
                {
                    line[ret] = '\0';
                    while((ret >= 0) && (line[ret] <= ' '))
                    {
                        line[ret--] = '\0';
                    }
                    yatest_log("line: '%s'", line);
                }
                else
                {
                    break;
                }
            }
        }
        else
        {
            yatest_log("ssl_input_output_stream_init failed with %s", error_gettext(ret));
        }
    }

    ret = crypto_openssl_error();
    if(ret != 0)
    {
        yatest_err("crypto_openssl_error failed with %s", error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(simple_test)
YATEST(error_test)
YATEST_TABLE_END
