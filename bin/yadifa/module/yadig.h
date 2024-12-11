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

#pragma once

/** @defgroup yadifa
 *  @ingroup ###
 *  @brief yadifa
 */

#include "module.h"
#include "dnscore/dns_message_writer.h"

#include <dnscore/host_address.h>
#include <dnscore/ptr_treemap.h>

typedef char                    tern; // when a boolean is not enough (-1 no, 1 yes, 0 maybe/don't care)

typedef struct yadig_settings_s yadig_settings_s;
struct yadig_settings_s
{
    host_address_t *servers;
    host_address_t *bound_to; // defaults to not binding a specific address/port (NULL)
    // char *keyfile;          // sign queries using the TSIG key read from that file (NULL)
    char              *pre_script;
    char              *mod_script;

    uint8_t           *qname;
    uint8_t           *tsig_key_name;
    struct tsig_key_s *tsig_key_item; // for the -y option
    uint32_t           buffer_size;
    uint32_t           epoch;
    uint32_t           tcp_size_overwrite;
    uint32_t           opcode;

    uint16_t           protocol;
    uint16_t           view_mode;
    uint16_t           question_mode;
    uint16_t           view_mode_with;

    uint16_t           server_port;
    uint16_t           qclass; // (IN)
    uint16_t           qtype;  // (A)

    //  host_address                                                     *qzone;

    //

    bool microseconds; //
    // reverse loopkups

    // dig-like '+' features

    // struct query_s

    bool aaflag; // sets the "aa" flag in the query (false)
    bool adflag; // sets the "ad" flag in the query (?)
    bool cdflag; // sets the "cd" flag in the query (false)
    // bool rdflag;            // sets the "rd" flag in the query (true)   // a.k.a recurse

    bool recurse;

    bool dnssec; // sets the "do" flag in the query (false)
    bool outgoing_hexdump;
    bool zflag; // sets the "z" (false)

    bool question;         // display the question section of the reply (default is to print as a comment)
    bool answer;           // display the answer section of the reply (true)
    bool additional;       // display the additional section of the reply (true)
    bool besteffort;       // attempt to display malformed answer (false)
    bool class_in_records; // display the class when printing records (true)
    bool cmd;              // display the printing of the initial comment (version + query options) (true)
    bool comments;         // display the comments lines in the output (true)
    bool crypto;           // display the cryptographic fields of DNSSEC records (true)
    bool identify;         // display the IP address and port that supplied the answer when +short (false if +short)
    bool multiline;        // display records in a verbose multi-line format with human-readable comments (false)
    bool onesoa;           // display only one SOA when printing an AXFR (false)
    bool qr;               // display the query as it is sent (false)
    bool rrcomments;       // display human-readable comments per record (DNSKEY tag, ...) (false unless multiline)
    bool short_answer;     // display short version of the answer (false)
    bool showsearch;       // display intermediary search results (false)
    bool stats;            // display statistics (time, reply size, ...) (true)
    bool ttlid;            // display the TTL when printing records (true)
    bool ttlunits;         // display the TTL in a human-readable format (s, m, h, d, w) (implies +ttlid) (false)
    bool unknownformat;    // display all recors in the "unknown" format (false)

    bool badcookie; // retry query with new server cookie if BADCOOKIE is replied (?)
    bool ignore;    // do not retry TC replies with TCP
    bool search;    // use the search list of resulv.conf (false)
    bool sigchase;  // chase DNSSEC signature chain (false, dig deprecated that for delv)
    bool topdown;   // performs a top-down validation when chasing DNSSEC signatures (false, deprecated for delv)
    bool trace;     // trace the delegation path from the root (implies +dnssec) (see man dig note about @server) (false)

    tern tcp;      // use TCP for queries (-1 = no, 1 = force, 0 = choose) (always use TCP for AXFR, default TCP for IXFR,
                   // UDP for anything else)
    bool keepopen; // keep the TCP socket open between queries and reuse it (false)

    bool mapped; // allow IPv4 over IPv6 (true)

    bool edns;             // uses EDNS (false)
    bool edns_negotiation; // enables EDNS negotiation (false)
    bool cookie;           // send an EDNS cookie (optional value given) (false, true with +trace)
    bool edns_expire;      // send an EDNS expire option (?)
    bool nsid;             // send an nsid request (false)
    bool nssearch;         // attempts to find the authoritative name servers for the zone and display all their SOA record for
                           // the zone (false)

    bool  idnin;  // process IDN domain names on input (true)
    bool  idnout; // process IDN domain names on output (true)

    bool  header_only; // send a query with a DNS header without a question section (false)

    bool  dscp; // sets the DSCP code point (false)
    bool  fail; // try the next server if SERVFAIL (false)

    char *trusted_key; // points to a file with a DNSKEY record on each line, to be used for +sigchase
                       // (/etc/trusted-key.key then ./trusted-key.key) (deprecated for delv)

    uint16_t bufsize;           // sets the advertised udp buffer size through EDNS0. (0 = don't advertise, implies edns0)
    uint32_t tries;             // the number of UDP queries tries (3)
    uint32_t split;             // split hex/base64 fields into chunks of N characters (neared to the nearest 4 multiple) (56, 44 if
                                // multiline, 0 = disabled)
    uint32_t      timeout;      // timeout of a query in seconds (<1 => 1) (5)
    uint8_t      *cookie_value; // see "cookie"
    size_t        cookie_size;  // see "cookie"

    uint8_t       ndots; //  number of dots to be absolute (1 or resolv.conf)

    uint8_t       dscp_value;   // sets the DSCP code point (SOL_SOCKET, SO_PRIORITY, man 7 ip)
    uint8_t       edns_version; // 0
    uint32_t      edns_flags;   // 0, if set override others EDNS0 flags settings
    ptr_treemap_t ednsopt;      // code->value EDNS options, also used for +subnet=addr[/prefix-length]
};

ya_result yadig_message_writer_init(dns_message_writer_t *dmw, output_stream_t *os, uint32_t flags);

#ifndef YADIG_C_

extern const module_s yadig_program;

#endif
