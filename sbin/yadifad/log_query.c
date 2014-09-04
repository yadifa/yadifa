/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
/** @defgroup logging Server logging
 *  @ingroup yadifad
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "config.h"

#include <dnscore/logger.h>

#include "log_query.h"
#include "server_context.h"

/*******************************************************************************************************************
 *
 * QUERY LOG SPECIALISED FUNCTIONS
 *
 ******************************************************************************************************************/

#define LOG_QUERY_C_

logger_handle* g_queries_logger = NULL;
log_query_function* log_query = log_query_yadifa;

void
log_query_set_mode(u32 mode)
{
    switch(mode)
    {
        case 1:
            log_query = log_query_yadifa;
            break;
        case 2:
            log_query = log_query_bind;
            break;
        case 3:
            log_query = log_query_both;
            break;
        default:
            log_query = log_query_none;
            break;
    }
}
    
static u8
log_query_add_du16(char *dest, u16 v)
{
    u8 idx = 8;
    char tmp[8];    
    
    do
    {   
        char c = (v%10) + '0';
        v /= 10;
        
        tmp[--idx] = c;
    }
    while(v != 0);
       
    memcpy(dest, &tmp[idx], 8 - idx);
    
    return 8 - idx;
}

static const char __hexa__[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static u8
log_query_add_xu16(char *dest, u16 v)
{
    dest[0] = __hexa__[(v>>4)&0xf];
    dest[1] = __hexa__[v&0xf];
    dest[2] = __hexa__[(v>>12)&0xf];
    dest[3] = __hexa__[(v>>8)&0xf];    
    
    return 4;
}

void
log_query_bind(int socket_fd, message_data *mesg)
{
    if(g_queries_logger == NULL)
    {
        return;
    }
    
    char *buffer;
    const char *class_name;
    const char *type_name;
    char query_text[1024];
    buffer = query_text;
        
    memcpy(buffer, "client ", 7);
    buffer+=7;
    
    u16 port = 0;
    
    switch(mesg->other.sa.sa_family)
    {
        case AF_INET:
        {
            struct sockaddr_in *ipv4 = &mesg->other.sa4;
            
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
            struct sockaddr_in6 *ipv6 = &mesg->other.sa6;

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
    
    buffer += dnsname_to_cstr(buffer, mesg->qname);
    
    *buffer++ = ' ';
    
    class_name = get_name_from_class(mesg->qclass);
    if(class_name != NULL)
    {
        strcpy(buffer, class_name);
        buffer += strlen(class_name);
    }
    else
    {
        memcpy(buffer, "CLASS", 5);
        buffer += 5;
        buffer += log_query_add_du16(buffer, mesg->qclass);        
    }
    
    *buffer++ = ' ';
    
    type_name = get_name_from_type(mesg->qtype);
    if(type_name != NULL)
    {
        strcpy(buffer, type_name);
        buffer += strlen(type_name);
    }
    else
    {
        memcpy(buffer, "TYPE", 4);
        buffer += 4;
        buffer += log_query_add_du16(buffer, mesg->qtype);        
    }

    *buffer++ = ' ';
    
    *buffer++ = (MESSAGE_RD(mesg->buffer)==0)?'-':'+';

#if HAS_TSIG_SUPPORT
    if(mesg->tsig.tsig != NULL)
    {
        *buffer++ = 'S';
    }
#endif
    
    if(mesg->edns)
    {
        *buffer++ = 'E';
    }
    
    if(mesg->protocol == IPPROTO_TCP)
    {
        *buffer++ = 'T';
    }
    
    if((mesg->rcode_ext & RCODE_EXT_DNSSEC))
    {
        *buffer++ = 'D';
    }
    
    if(MESSAGE_CD(mesg->buffer) != 0)
    {
        *buffer++ = 'C';
    }
    
    *buffer++ = ' ';
    *buffer++ = '(';
    
    buffer += server_context_append_socket_name(buffer, socket_fd);

    *buffer++ = ')';
    *buffer = '\0';
    
    logger_handle_msg_text_ext(g_queries_logger, MSG_INFO,
                                query_text, buffer - query_text,
                                " queries: info: ", 16,
                                LOGGER_MESSAGE_TIMEMS|LOGGER_MESSAGE_PREFIX);
}

void
log_query_yadifa(int socket_fd, message_data *mesg)
{
    (void)socket_fd;
    
    if(g_queries_logger == NULL)
    {
        return;
    }
    
    char *buffer;
    const char *class_name;
    const char *type_name;
    char query_text[1024];
    buffer = query_text;
    
    memcpy(buffer, "query [", 7);
    buffer+=7;    
    buffer += log_query_add_xu16(buffer, MESSAGE_ID(mesg->buffer));
    *buffer++ = ']';
    *buffer++ = ' ';
    
    *buffer++ = '{';    
    *buffer++ = (MESSAGE_RD(mesg->buffer)!=0)?'+':'-';
#if HAS_TSIG_SUPPORT
    *buffer++ = (mesg->tsig.tsig != NULL)?    'S':'-';
#else
    *buffer++ = '-';
#endif
    *buffer++ = (mesg->edns)?                 'E':'-';
    *buffer++ = (mesg->protocol == IPPROTO_TCP)?'T':'-';
    *buffer++ = ((mesg->rcode_ext & RCODE_EXT_DNSSEC)!=0)?'D':'-';
    *buffer++ = (MESSAGE_CD(mesg->buffer) != 0)?'C':'-';
    *buffer++ = (MESSAGE_AD(mesg->buffer) != 0)?'A':'-';
    *buffer++ = '}';
    *buffer++ = ' ';
    
    buffer += dnsname_to_cstr(buffer, mesg->qname);
    
    *buffer++ = ' ';
    
    class_name = get_name_from_class(mesg->qclass);
    if(class_name != NULL)
    {
        strcpy(buffer, class_name);
        buffer += strlen(class_name);
    }
    else
    {
        memcpy(buffer, "CLASS", 5);
        buffer += 5;
        buffer += log_query_add_du16(buffer, mesg->qclass);        
    }
    
    *buffer++ = ' ';
    
    type_name = get_name_from_type(mesg->qtype);
    if(type_name != NULL)
    {
        strcpy(buffer, type_name);
        buffer += strlen(type_name);
    }
    else
    {
        memcpy(buffer, "TYPE", 4);
        buffer += 4;
        buffer += log_query_add_du16(buffer, mesg->qtype);        
    }
    
    *buffer++ = ' ';
    *buffer++ = '(';
    
    u16 port = 0;
    
    switch(mesg->other.sa.sa_family)
    {
        case AF_INET:
        {
            struct sockaddr_in *ipv4 = &mesg->other.sa4;
            
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
            struct sockaddr_in6 *ipv6 = &mesg->other.sa6;

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

