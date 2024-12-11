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
 * @defgroup logging Server logging
 * @ingroup yadifad
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "server_config.h"

#include <dnscore/logger.h>

#include "log_query.h"
#include "server_context.h"

/*******************************************************************************************************************
 *
 * QUERY LOG SPECIALISED FUNCTIONS
 *
 ******************************************************************************************************************/

#define LOG_QUERY_C_

logger_handle_t    *g_queries_logger = LOGGER_HANDLE_SINK;
log_query_function *log_query = log_query_yadifa;
static uint32_t     g_log_query_mode = LOG_QUERY_MODE_YADIFA;

/**
 * Sets the query log output mode
 */

void log_query_mode_set(uint32_t mode)
{
    switch(mode)
    {
        case LOG_QUERY_MODE_YADIFA:
            log_query = log_query_yadifa;
            break;
        case LOG_QUERY_MODE_BIND:
            log_query = log_query_bind;
            break;
        case LOG_QUERY_MODE_BOTH:
            log_query = log_query_both;
            break;
        default:
            log_query = log_query_none;
            mode = LOG_QUERY_MODE_NONE;
            break;
    }
    g_log_query_mode = mode;
}

uint32_t       log_query_mode() { return g_log_query_mode; }

static uint8_t log_query_add_du16(char *dest, uint16_t v)
{
    uint8_t idx = 8;
    char    tmp[8];

    do
    {
        char c = (v % 10) + '0';
        v /= 10;

        tmp[--idx] = c;
    } while(v != 0);

    memcpy(dest, &tmp[idx], 8 - idx);

    return 8 - idx;
}

static const char __hexa__[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static uint8_t    log_query_add_xu16(char *dest, uint16_t v)
{
    dest[0] = __hexa__[(v >> 4) & 0xf];
    dest[1] = __hexa__[v & 0xf];
    dest[2] = __hexa__[(v >> 12) & 0xf];
    dest[3] = __hexa__[(v >> 8) & 0xf];

    return 4;
}

void log_query_bind(int socket_fd, dns_message_t *mesg)
{
    if(g_queries_logger == NULL)
    {
        return;
    }

    char       *buffer;
    const char *class_name;
    const char *type_name;
    char        query_text[1024];
    buffer = query_text;

    memcpy(buffer, "client ", 7);
    buffer += 7;

    uint16_t port = 0;

    switch(dns_message_get_sender_sa(mesg)->sa_family)
    {
        case AF_INET:
        {
            const struct sockaddr_in *ipv4 = dns_message_get_sender_sa4(mesg);

            if(inet_ntop(ipv4->sin_family, &ipv4->sin_addr, buffer, 64) != NULL)
            {
                buffer += strlen(buffer);
                *buffer++ = '#';
                port = ntohs(ipv4->sin_port);
            }
            break;
        }
        case AF_INET6:
        {
            const struct sockaddr_in6 *ipv6 = dns_message_get_sender_sa6(mesg);

            if(inet_ntop(ipv6->sin6_family, &ipv6->sin6_addr, buffer, 64) != NULL)
            {
                buffer += strlen(buffer);
                *buffer++ = '#';
                port = ntohs(ipv6->sin6_port);
            }
            break;
        }
    }

    buffer += log_query_add_du16(buffer, port);

    memcpy(buffer, ": query: ", 9);
    buffer += 9;

    buffer += cstr_init_with_dnsname(buffer, dns_message_get_canonised_fqdn(mesg));

    *buffer++ = ' ';

    class_name = dns_class_get_name(dns_message_get_query_class(mesg));
    if(class_name != NULL)
    {
        strcpy(buffer, class_name); // the buffer is big enough
        buffer += strlen(class_name);
    }
    else
    {
        memcpy(buffer, "CLASS", 5);
        buffer += 5;
        buffer += log_query_add_du16(buffer, dns_message_get_query_class(mesg));
    }

    *buffer++ = ' ';

    type_name = dns_type_get_name(dns_message_get_query_type(mesg));
    if(type_name != NULL)
    {
        strcpy(buffer, type_name); // the buffer is big enough
        buffer += strlen(type_name);
    }
    else
    {
        memcpy(buffer, "TYPE", 4);
        buffer += 4;
        buffer += log_query_add_du16(buffer, dns_message_get_query_type(mesg));
    }

    *buffer++ = ' ';

    *buffer++ = dns_message_has_recursion_desired(mesg) ? '+' : '-';

#if DNSCORE_HAS_TSIG_SUPPORT
    if(dns_message_tsig_get_key(mesg) != NULL)
    {
        *buffer++ = 'S';
    }
#endif

    if(dns_message_has_edns0(mesg))
    {
        *buffer++ = 'E';
    }

    if(dns_message_get_protocol(mesg) == IPPROTO_TCP)
    {
        *buffer++ = 'T';
    }

    if(dns_message_has_edns0_dnssec(mesg))
    {
        *buffer++ = 'D';
    }

    if(dns_message_has_checking_disabled(mesg))
    {
        *buffer++ = 'C';
    }

    *buffer++ = ' ';
    *buffer++ = '(';

    buffer += server_context_append_socket_name(buffer, socket_fd);

    *buffer++ = ')';
    *buffer = '\0';

    logger_handle_msg_text_ext(g_queries_logger, MSG_INFO, query_text, buffer - query_text, " queries: info: ", 16, LOGGER_MESSAGE_TIMEMS | LOGGER_MESSAGE_PREFIX);
}

void log_query_yadifa(int socket_fd, dns_message_t *mesg)
{
    (void)socket_fd;

    if(g_queries_logger == NULL)
    {
        return;
    }

    char       *buffer;
    const char *class_name;
    const char *type_name;
    char        query_text[1024];
    buffer = query_text;

    memcpy(buffer, "query [", 7);
    buffer += 7;
    buffer += log_query_add_xu16(buffer, dns_message_get_id(mesg));
    *buffer++ = ']';
    *buffer++ = ' ';

    *buffer++ = '{';
    *buffer++ = dns_message_has_recursion_desired(mesg) ? '+' : '-';
#if DNSCORE_HAS_TSIG_SUPPORT
    *buffer++ = (dns_message_tsig_get_key(mesg) != NULL) ? 'S' : '-';
#else
    *buffer++ = '-';
#endif
    *buffer++ = dns_message_has_edns0(mesg) ? 'E' : '-';
    *buffer++ = (dns_message_get_protocol(mesg) == IPPROTO_TCP) ? 'T' : '-';
    *buffer++ = dns_message_has_edns0_dnssec(mesg) ? 'D' : '-';
    *buffer++ = dns_message_has_checking_disabled(mesg) ? 'C' : '-';

    *buffer++ = '}';
    *buffer++ = ' ';

    buffer += cstr_init_with_dnsname(buffer, dns_message_get_canonised_fqdn(mesg));

    *buffer++ = ' ';

    class_name = dns_class_get_name(dns_message_get_query_class(mesg));
    if(class_name != NULL)
    {
        strcpy(buffer, class_name); // the buffer is big enough
        buffer += strlen(class_name);
    }
    else
    {
        memcpy(buffer, "CLASS", 5);
        buffer += 5;
        buffer += log_query_add_du16(buffer, dns_message_get_query_class(mesg));
    }

    *buffer++ = ' ';

    type_name = dns_type_get_name(dns_message_get_query_type(mesg));
    if(type_name != NULL)
    {
        strcpy(buffer, type_name); // the buffer is big enough
        buffer += strlen(type_name);
    }
    else
    {
        memcpy(buffer, "TYPE", 4);
        buffer += 4;
        buffer += log_query_add_du16(buffer, dns_message_get_query_type(mesg));
    }

    *buffer++ = ' ';
    *buffer++ = '(';

    uint16_t port = 0;

    switch(dns_message_get_sender_sa(mesg)->sa_family)
    {
        case AF_INET:
        {
            const struct sockaddr_in *ipv4 = dns_message_get_sender_sa4(mesg);

            if(inet_ntop(ipv4->sin_family, &ipv4->sin_addr, buffer, 64) != NULL)
            {
                buffer += strlen(buffer);
                *buffer++ = '#';
                port = ntohs(ipv4->sin_port);
            }
            break;
        }
        case AF_INET6:
        {
            const struct sockaddr_in6 *ipv6 = dns_message_get_sender_sa6(mesg);

            if(inet_ntop(ipv6->sin6_family, &ipv6->sin6_addr, buffer, 64) != NULL)
            {
                buffer += strlen(buffer);
                *buffer++ = '#';
                port = ntohs(ipv6->sin6_port);
            }
            break;
        }
    }

    buffer += log_query_add_du16(buffer, port);

    *buffer++ = ')';
    *buffer = '\0';

    logger_handle_msg_text(g_queries_logger, MSG_INFO, query_text, buffer - query_text);
}

/** @} */
