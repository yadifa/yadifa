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

#include <dnscore/parser.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/timems.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/format.h>

#include "dnslg/resolv-conf.h"


#define INPUT_FILE "/etc/resolv.conf"
#define DO_PRINT 1


#define RO_NOTHING                 0   
#define RO_KEY_WORD                1
#define RO_NAME_SERVER_VALUE       2
#define RO_DOMAIN_VALUE            3
#define RO_SEARCH_VALUE            4
#define RO_OPTIONS_VALUE           5
#define RO_SORTLIST_VALUE          6
#define RO_TIMEOUT_VALUE           7
#define RO_ATTEMPTS_VALUE          8
#define RO_NDOTS_VALUE             9

#define RO_NS_MAX                  3 // the same as in the resolv.conf man page
#define RO_DOMAIN_MAX              1 // the same as in the resolv.conf man page
#define RO_SEARCH_MAX              6 // the same as in the resolv.conf man page
#define RO_TIMOUT_DEFAULT          5
#define RO_TIMEOUT_MAX             65535
#define RO_ATTEMPTS_DEFAULT        3
#define RO_ATTEMPTS_MAX            5
#define RO_NDOTS_DEFAULT           1
#define RO_NDOTS_MAX               15

#define RO_NO_TLD_QUERY_OFF        0
#define RO_NO_TLD_QUERY_ON         1
#define RO_NO_TLD_QUERY_DEFAULT    RO_NO_TLD_QUERY_OFF

#define RO_DEBUG_OFF               0
#define RO_DEBUG_ON                1
#define RO_DEBUG_DEFAULT           RO_DEBUG_OFF

#define RO_NO_DOMAIN_OR_SEARCH     0
#define RO_DOMAIN                  1
#define RO_SEARCH                  2

ya_result
config_set_search_or_domain(const char *value, struct search_or_domain_s *dest, anytype settings)
{
    ya_result return_code;
    
    yassert((settings._u8 == RO_SEARCH) || (settings._u8 == RO_DOMAIN));

    if(dest->address.list != NULL)
    {
        host_address_delete(dest->address.list);
        dest->address.domain = NULL;
    }
    
    if(settings._u8 == RO_SEARCH)
    {
        // search
        anytype settings = {._8u8 = {CONFIG_HOST_LIST_FLAGS_FQDN,3,0,0,0,0,0,0}};
        return_code = config_set_host_list(value, &dest->address.search, settings);
        dest->search_or_domain = RO_SEARCH;
        
    }
    else
    {
        // domain
        anytype settings = {._8u8 = {CONFIG_HOST_LIST_FLAGS_FQDN,1,0,0,0,0,0,0}};
        return_code = config_set_host_list(value, &dest->address.domain, settings);
        dest->search_or_domain = RO_DOMAIN;
    }
        
    return return_code;
}


void
resolver_init(resolv_s *resolver)
{
    resolver->search_or_domain.address.domain = NULL; // and search ...
    resolver->search_or_domain.search_or_domain = RO_NO_DOMAIN_OR_SEARCH;

    resolver->nameserver = NULL;
    resolver->timeout = RO_TIMOUT_DEFAULT;
    resolver->attempts = RO_ATTEMPTS_DEFAULT;
    resolver->ndots = RO_NDOTS_DEFAULT;
    resolver->no_tld_query = RO_NO_TLD_QUERY_DEFAULT;
    resolver->debug = RO_DEBUG_DEFAULT;
    
}


void
write_search(host_address *address, char *text)
{
    for(;;)
    {
        formatln("%s : %{hostaddr} ", text, address);

        if(address->next == NULL)
        {
            break;
        }
        address = address->next;
    }

    flushout();
}


void
resolv_print(resolv_s *resolver)
{
    if(resolver->search_or_domain.search_or_domain == RO_SEARCH)
    {
        if (resolver->search_or_domain.address.search != NULL)
        {
            write_search(resolver->search_or_domain.address.search, "RO SEARCH         ");
        }
    } 
    else if(resolver->search_or_domain.search_or_domain == RO_DOMAIN)
    {
        if (resolver->search_or_domain.address.domain != NULL)
        {
            write_search(resolver->search_or_domain.address.domain, "RO DOMAIN         ");
        }

    }
    if (resolver->nameserver != NULL)
    {
        write_search(resolver->nameserver, "RO NAMESE         ");
    }

    formatln("RO TIMEOUT         : %lu", resolver->timeout);
    formatln("RO ATTEMPTS        : %u", resolver->attempts);
    formatln("RO NDOTS           : %u", resolver->ndots);
    formatln("RO NO_TLD_QUERY    : %u", resolver->no_tld_query);
    formatln("RO DEBUG           : %u", resolver->debug);
    formatln("RO SEARCH_OR_DOMAIN: %u", resolver->search_or_domain);

    flushout();
}


ya_result
resolv_conf_parse_stream(resolv_s *resolver, input_stream *is)
{
    ya_result return_code;

    parser_s parser;

    const char *string_delimiters    = "\"\"''";
    const char *multiline_delimiters = "";
    const char *comment_markers      = "#";
    const char *blank_makers         = "\040\t\r:";
    const char *escape_characters    = "\\";

    if(ISOK(return_code = parser_init(&parser,
                    string_delimiters,      // by 2
                    multiline_delimiters,   // by 2
                    comment_markers,        // by 1
                    blank_makers,           // by 1
                    escape_characters)))    // by 1

    {
        parser_push_stream(&parser, is);

        u64 started_at = timeus();

        u8 search_domain_count = 0;
        u8 name_server_count = 0;
        u8 expect_word = RO_KEY_WORD;
        u8 ip_buffer[MAX_DOMAIN_LENGTH];

        // declare and init 'search FQDNs'
        host_address search_domains;
        search_domains.next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
        search_domains.tsig = NULL;
#endif
        search_domains.version = HOST_ADDRESS_NONE;

        // declare and init 'domain FQDN'
        host_address domain;
        domain.next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
        domain.tsig = NULL;
#endif

        // declare and init resolving 'name_servers'
        host_address name_servers;
        name_servers.next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
        name_servers.tsig = NULL;
#endif

        for(;;)
        {
            if(ISOK(return_code = parser_next_token(&parser)))
            {
                if(return_code & PARSER_WORD)
                {
                    u32 text_len     = parser_text_length(&parser);
                    const char *text = parser_text(&parser);

                    switch(expect_word)
                    {
                        case RO_KEY_WORD: // search for key
                            {
                                if (!strncmp(text, "nameserver", text_len) && (text_len == 10))
                                {
                                    expect_word = RO_NAME_SERVER_VALUE;
                                    // add name servers on the list
                                }
                                else if (!strncmp(text, "domain", text_len) && (text_len == 6))
                                {
                                    resolver->search_or_domain.search_or_domain = RO_DOMAIN;

                                    formatln("DOMAIN %u\n", resolver->search_or_domain.search_or_domain);
                                    expect_word = RO_DOMAIN_VALUE;
                                }
                                else if (!strncmp(text, "search", text_len) && (text_len == 6))
                                {
                                    // new line, so new list
                                    if (search_domains.next != NULL)
                                    {
                                        host_address_delete_list(search_domains.next);

                                        // re-init header
                                        search_domains.version = HOST_ADDRESS_NONE;
                                        search_domains.next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
                                        search_domains.tsig = NULL;
#endif
                                    }

                                    // reset counter and set on 'search'
                                    search_domain_count = 0;
                                    resolver->search_or_domain.search_or_domain = RO_SEARCH;

                                    formatln("SEARCH %u\n", resolver->search_or_domain.search_or_domain);

                                    expect_word = RO_SEARCH_VALUE;
                                }
                                else if (!strncmp(text, "options", text_len) && (text_len == 7))
                                {
                                    expect_word = RO_OPTIONS_VALUE;
                                }
                                else if (!strncmp(text, "sortlist", text_len) && (text_len == 8))
                                {
                                    expect_word = RO_SORTLIST_VALUE;
                                }
                                else
                                {
                                    print("INCORRECT\n");
                                    return_code = ERROR; // non-existing key found
                                }
                                break;
                            }
                        case RO_NAME_SERVER_VALUE:
                            {
                                u8 host_type           = HOST_ADDRESS_NONE;
                                u8 ip_size;

                                // re-init only 1 name server allowed
                                expect_word = RO_KEY_WORD; 

                                //                         // check if more than 1 name server on the same line
                                //                         // if so report syntax error
                                if(FAIL(return_code = parse_ip_address(text, text_len, ip_buffer, sizeof(ip_buffer))))
                                {
                                    return_code = INCORRECT_IPADDRESS;

                                    break;
                                }

                                ip_size = (u8)return_code;

                                if (ip_size == 4)
                                {
                                    host_type = HOST_ADDRESS_IPV4;
                                }

                                if (ip_size == 16)
                                {
                                    host_type = HOST_ADDRESS_IPV6;
                                }

                                // check if no more than NS_MAX
                                name_server_count++;
                                if(name_server_count > 3)
                                {
                                    break;
                                }

                                switch(host_type)
                                {
                                    case HOST_ADDRESS_IPV4:
                                        {
                                            host_address_append_ipv4(&name_servers, ip_buffer, NU16(DNS_DEFAULT_PORT));

                                            break;
                                        }
                                    case HOST_ADDRESS_IPV6:
                                        {
                                            host_address_append_ipv6(&name_servers, ip_buffer, NU16(DNS_DEFAULT_PORT));

                                            break;
                                        }
                                }

                                break;
                            }
                        case RO_DOMAIN_VALUE:
                            {
                                // re-init
                                expect_word = RO_KEY_WORD; 

                                // no need to check the amount this will be tested with "RO_KEY_WORD"
                                // check for FQDN
                                // if not a correct FQDN report syntax error, this is in the return_code
                                if(FAIL(return_code = cstr_to_dnsname_with_check_len(ip_buffer, text, text_len)))
                                {
                                    break;
                                }

                                host_address_set_dname(&domain, ip_buffer, NU16(DNS_DEFAULT_PORT));

                                break;
                            }
                        case RO_SEARCH_VALUE:
                            {
                                // check for FQDN
                                // if not a correct FQDN report syntax error, this is in the return_code
                                if(FAIL(return_code = cstr_to_dnsname_with_check_len(ip_buffer, text, text_len)))
                                {
                                    break;
                                }

                                // needs a counter, only 6 search FQDNs are allowed
                                search_domain_count++;
                                if(search_domain_count > 6)
                                {
                                    break;
                                }

                                host_address_append_dname(&search_domains, ip_buffer, NU16(DNS_DEFAULT_PORT));

                                break;
                            }
                        case RO_OPTIONS_VALUE:
                            {
                                if (!strncmp(text, "timeout", text_len) && (text_len == 7))
                                {
                                    expect_word = RO_TIMEOUT_VALUE;
                                }
                                else if (!strncmp(text, "attempts", text_len) && (text_len == 8))
                                {
                                    expect_word = RO_ATTEMPTS_VALUE;
                                }
                                else if (!strncmp(text, "ndots", text_len) && (text_len == 5))
                                {
                                    expect_word = RO_NDOTS_VALUE;
                                }
                                else if (!strncmp(text, "no_tld_query", text_len) && (text_len == 12))
                                {
                                    expect_word = RO_KEY_WORD;

                                    resolver->no_tld_query = RO_NO_TLD_QUERY_ON;
                                }
                                else if (!strncmp(text, "debug", text_len) && (text_len == 5))
                                {
                                    expect_word = RO_KEY_WORD;

                                    resolver->debug = RO_DEBUG_ON;
                                }
                                else
                                {
                                    print("INCORRECT OPTIONS\n");
                                    return_code = ERROR; // non-existing key found
                                }
                                break;
                            }
                        case RO_TIMEOUT_VALUE:
                            {
                                u32 val;
                                if(ISOK(return_code = parse_u32_check_range(text, &val, 0, MAX_U16, BASE_10)))
                                {
                                    resolver->timeout = (u16)val;
                                }

                                break;
                            }
                        case RO_ATTEMPTS_VALUE:
                            {
                                u32 val;
                                if(ISOK(return_code = parse_u32_check_range(text, &val, 0, MAX_U8, BASE_10)))
                                {
                                    resolver->attempts = (u8)val;
                                }

                                break;
                            }
                        case RO_NDOTS_VALUE:
                            {
                                u32 val;
                                if(ISOK(return_code = parse_u32_check_range(text, &val, 0, MAX_U8, BASE_10)))
                                {
                                    resolver->ndots = (u8)val;
                                }

                                break;
                            }
                        case RO_SORTLIST_VALUE: // @todo 20140507 gve -- still needs todo this when I got time
                            {
#if DO_PRINT
                                format("\n*** SORTLIST VALUE: ");
                                output_stream_write(termout, (u8*)text, text_len);
                                flushout();
#endif

                                break;
                            }
                        default: // is not defined, so did will never be reached
                            {
#if DO_PRINT
                                print("WRONG\n");
#endif

                                return_code = ERROR; // non-existing key found

                                break;
                            }
                    }
                } // PARSER_WORD
                else if(return_code & PARSER_EOL)
                {
                    /// @todo 20140507 gve -- missing 'values' for the keys found still needs to be implemented for all keys -- gery
                    if(expect_word == RO_NAME_SERVER_VALUE)
                    {
                        return_code = ERROR;

                        break;
                    }
                    expect_word = RO_KEY_WORD;
                } // PARSER_EOL
                else if(return_code & PARSER_EOF)
                {
                    input_stream *completed_stream = parser_pop_stream(&parser);
                    input_stream_close(completed_stream);

                    if(parser_stream_count(&parser) <= 0)
                    {
                        break;
                    }
                } // PARSER_EOF
            }
            else
            {
                break;
            }

            if(FAIL(return_code))
            {
                break;
            }
        }

        u64 stopped_at = timeus();
        u64 delta      = stopped_at - started_at;

        formatln("\nparsing lasted %lluus : %r", delta, return_code);           

        if(resolver->search_or_domain.search_or_domain == RO_SEARCH)
        {
            resolver->search_or_domain.address.search       = search_domains.next;
        }
        else if(resolver->search_or_domain.search_or_domain == RO_DOMAIN)
        {
            resolver->search_or_domain.address.domain       = host_address_copy(&domain);
        }
        else
        {
            resolver->search_or_domain.address.list = NULL;
        }
        
        resolver->nameserver = name_servers.next;
    }

    return return_code;
}


ya_result
resolv_conf_parse_file(const char* file_name, resolv_s *resolver)
{
    input_stream is;
    ya_result return_code;

    if(ISOK(return_code = file_input_stream_open(&is, file_name)))
    {
        if(ISOK(return_code = resolv_conf_parse_stream(resolver, &is)))
        {
#if DO_PRINT
            resolv_print(resolver);
        }
        else
        {
            formatln("oops: %r", return_code);
            flushout();
#endif
        }
    }

    return return_code;
}


ya_result
resolv_conf_parse(input_stream *out_is)
{
    resolv_s resolver;
    resolver_init(&resolver);

    resolv_conf_parse_file(INPUT_FILE, &resolver);

    // put the struct back in a stream
    output_stream os;
    bytearray_output_stream_init(&os, NULL, 0);

    osformatln(&os, "<resolver>");
    
    if(resolver.search_or_domain.search_or_domain == RO_DOMAIN)
    {
        // domain 
        osformatln(&os, "domain %{hostaddrlist}", resolver.search_or_domain.address.domain);
    }
    else if(resolver.search_or_domain.search_or_domain == RO_SEARCH)
    {
        // search`
        osformatln(&os, "search %{hostaddrlist}", resolver.search_or_domain.address.search);
    }
    
    if(resolver.nameserver != NULL)
    {
        osformatln(&os, "nameserver %{hostaddrlist}", resolver.nameserver);
    }

    osformatln(&os, "timeout %hu", resolver.timeout);
    osformatln(&os, "attempts %hhu", resolver.attempts);
    osformatln(&os, "ndots %hhu", resolver.ndots);
    osformatln(&os, "no_tld_query %hhu", resolver.no_tld_query);
    osformatln(&os, "debug %hhu", resolver.debug);
    
    osformatln(&os, "</resolver>");

    u32 buffer_size = bytearray_output_stream_size(&os);
    u8 *buffer      = bytearray_output_stream_detach(&os);

    output_stream_close(&os);

    bytearray_input_stream_init(out_is, buffer, buffer_size, TRUE);


    return buffer_size;
}

/** @} */

