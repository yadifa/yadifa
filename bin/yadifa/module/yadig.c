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
 * @defgroup yadifa
 * @ingroup ###
 * @brief
 *----------------------------------------------------------------------------*/

#define YADIG_C_

#include "client_config.h"

#include "module/yadig.h"

#include <sys/time.h>

#include <dnscore/config_settings.h>
#include <dnscore/config_cmdline.h>
#include <dnscore/cmdline.h>

#include <dnscore/logger_handle.h>
#include <dnscore/dns_message.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/timems.h>

#include <dnslg/config_resolver.h>
#include <dnslg/dns.h>
#include <common.h>

#include "common_config.h"
#include "module.h"

#include "query_result.h"
#include "dnscore/xfr_input_stream.h"

/*----------------------------------------------------------------------------*/

#define YADIG_SECTION_NAME "yadifa-dig"

#pragma mark GLOBAL VARIABLES

extern logger_handle_t *g_client_logger;
#define MODULE_MSG_HANDLE g_client_logger

struct logger_name_handle_s
{
    const char       *name;
    logger_handle_t **handlep;
};

static const struct logger_name_handle_s logger_name_handles[] = {{"client", &g_client_logger}, {NULL, NULL}};

extern resolv_t                          config_resolver_settings;

#define DEF_VAL_CLASS         "IN"
#define DEF_VAL_TYPE          "A"
#define DEF_VAL_TEST          0
#define S_BUFFER_SIZE_DEFAULT "4096"
#define S_DNSSEC_DEFAULT      "0"
#define S_RECURSE_DEFAULT     "1"
#define S_OPCODE_DEFAULT      "0" // query
#define S_EPOCH_DEFAULT       "0" // "now"

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*----------------------------------------------------------------------------*/
#pragma mark CONFIG

// ********************************************************************************
// ***** module settings
// ********************************************************************************

static yadig_settings_s g_yadig_settings;

#define CONFIG_TYPE yadig_settings_s
CONFIG_BEGIN(yadig_settings_desc)

CONFIG_DNS_CLASS(qclass, DEF_VAL_CLASS)
CONFIG_DNS_TYPE(qtype, DEF_VAL_TYPE)
CONFIG_FQDN(qname, ".") // root .

CONFIG_FLAG16(dnssec, CONFIG_FLAG_OFF, question_mode, QM_FLAGS_DNSSEC)
CONFIG_FLAG16(ignore_tc, CONFIG_FLAG_OFF, question_mode, QM_FLAGS_INGORE_TC)
CONFIG_FLAG16(recursive, CONFIG_FLAG_ON, question_mode, QM_FLAGS_RECURSIVE)
CONFIG_FLAG16(trace, CONFIG_FLAG_OFF, question_mode, QM_FLAGS_TRACE)
CONFIG_FLAG16(round_robin, CONFIG_FLAG_ON, question_mode, QM_FLAGS_ROUND_ROBIN)

CONFIG_FLAG16(aaonly, CONFIG_FLAG_OFF, question_mode, QM_FLAGS_AAONLY)
CONFIG_FLAG16(adflag, CONFIG_FLAG_OFF, question_mode, QM_FLAGS_AD)
CONFIG_FLAG16(cdflag, CONFIG_FLAG_OFF, question_mode, QM_FLAGS_CD)

CONFIG_FLAG16(additional, CONFIG_FLAG_ON, view_mode_with, DNS_MESSAGE_WRITER_WITH_ADDITIONAL)
CONFIG_FLAG16(answer, CONFIG_FLAG_ON, view_mode_with, DNS_MESSAGE_WRITER_WITH_ANSWER)
CONFIG_FLAG16(authority, CONFIG_FLAG_ON, view_mode_with, DNS_MESSAGE_WRITER_WITH_AUTHORITY)
CONFIG_FLAG16(question, CONFIG_FLAG_ON, view_mode_with, DNS_MESSAGE_WRITER_WITH_QUESTION)
CONFIG_FLAG16(header, CONFIG_FLAG_ON, view_mode_with, DNS_MESSAGE_WRITER_WITH_HEADER)

// next 6 flags are infact mutual exclusive
CONFIG_FLAG32(parse, CONFIG_FLAG_OFF, view_mode, VM_EASYPARSE)
CONFIG_FLAG32(dig, CONFIG_FLAG_OFF, view_mode, VM_DIG)
CONFIG_FLAG32(json, CONFIG_FLAG_OFF, view_mode, VM_JSON)
CONFIG_FLAG32(xml, CONFIG_FLAG_OFF, view_mode, VM_XML)
CONFIG_FLAG32(wire, CONFIG_FLAG_OFF, view_mode, VM_WIRE)

// next 3 flags are infact mutual exclusive
CONFIG_FLAG32(short, CONFIG_FLAG_OFF, view_mode, VM_SHORT)
CONFIG_FLAG32(multiline, CONFIG_FLAG_OFF, view_mode, VM_MULTILINE)
CONFIG_FLAG32(pretty_print, CONFIG_FLAG_OFF, view_mode, VM_PRETTY_PRINT)

CONFIG_FLAG16(udp, CONFIG_FLAG_ON, protocol, QM_PROTOCOL_UDP)
CONFIG_FLAG16(tcp, CONFIG_FLAG_OFF, protocol, QM_PROTOCOL_TCP)

CONFIG_FLAG16(ipv6, CONFIG_FLAG_OFF, protocol, QM_PROTOCOL_IPV6)
CONFIG_FLAG16(ipv4, CONFIG_FLAG_ON, protocol, QM_PROTOCOL_IPV4)

CONFIG_HOST_LIST_EX(servers, "", CONFIG_HOST_LIST_FLAGS_DEFAULT | CONFIG_HOST_LIST_FLAGS_FQDN | CONFIG_HOST_LIST_FLAGS_APPEND, 3)
CONFIG_U16(server_port, DEF_VAL_SERVERPORT)
CONFIG_U32_RANGE(opcode, S_OPCODE_DEFAULT, 0, 15)
CONFIG_U32_RANGE(buffer_size, S_BUFFER_SIZE_DEFAULT, 512, 65535)
CONFIG_U32_RANGE(epoch, S_EPOCH_DEFAULT, 0, INT32_MAX)
CONFIG_U32_RANGE(tcp_size_overwrite, "65536", 0, 65536)
CONFIG_BOOL(dnssec, S_DNSSEC_DEFAULT)
CONFIG_BOOL(recurse, S_RECURSE_DEFAULT)
CONFIG_BOOL(outgoing_hexdump, "0") // because there is no way it would ever be enabled by default
CONFIG_FQDN(tsig_key_name, NULL)
CONFIG_TSIG_ITEM(tsig_key_item, NULL)

CONFIG_END(yadig_settings_desc)
#undef CONFIG_TYPE

// ********************************************************************************
// ***** module command line struct
// ********************************************************************************

// ********************************************************************************
// ***** dig-like commands states
// ********************************************************************************

enum YADIG_CMD_STATE
{
    YADIG_CMD_STATE_BEGIN = 0,
    YADIG_CMD_STATE_BUFSIZE,
    YADIG_CMD_STATE_COOKIE,
    YADIG_CMD_STATE_DOMAIN,
    YADIG_CMD_STATE_DSCP,
    YADIG_CMD_STATE_EDNS,
    YADIG_CMD_STATE_EDNSFLAGS,
    YADIG_CMD_STATE_EDNSOPT,
    YADIG_CMD_STATE_EDNSOPT_CODE,
    YADIG_CMD_STATE_NDOTS,
    YADIG_CMD_STATE_RETRY,
    YADIG_CMD_STATE_SPLIT,
    YADIG_CMD_STATE_TIMEOUT,
    YADIG_CMD_STATE_TRIES,
    YADIG_CMD_STATE_TRUSTED_KEY,
    YADIG_CMD_STATE_END
};

// ********************************************************************************
// ***** dig-like keywords enumeration, must start with 1
// ********************************************************************************

enum YADIG_KEYWORD
{
    YADIG_KEYWORD_AAFLAG = 1,
    YADIG_KEYWORD_NOAAFLAG,
    YADIG_KEYWORD_ADDITIONAL,
    YADIG_KEYWORD_NOADDITIONAL,
    YADIG_KEYWORD_ADFLAG,
    YADIG_KEYWORD_NOADFLAG,
    YADIG_KEYWORD_ALL,
    YADIG_KEYWORD_NOALL,
    YADIG_KEYWORD_ANSWER,
    YADIG_KEYWORD_NOANSWER,
    YADIG_KEYWORD_AUTHORITY,
    YADIG_KEYWORD_NOAUTHORITY,
    YADIG_KEYWORD_BADCOOKIE,
    YADIG_KEYWORD_NOBADCOOKIE,
    YADIG_KEYWORD_BESTEFFORT,
    YADIG_KEYWORD_NOBESTEFFORT,
    YADIG_KEYWORD_BUFSIZE,
    YADIG_KEYWORD_CDFLAG,
    YADIG_KEYWORD_NOCDFLAG,
    YADIG_KEYWORD_CLASS,
    YADIG_KEYWORD_NOCLASS,
    YADIG_KEYWORD_CMD,
    YADIG_KEYWORD_NOCMD,
    YADIG_KEYWORD_COMMENTS,
    YADIG_KEYWORD_NOCOMMENTS,
    YADIG_KEYWORD_COOKIE,
    YADIG_KEYWORD_NOCOOKIE,
    YADIG_KEYWORD_CRYPTO,
    YADIG_KEYWORD_NOCRYPTO,
    YADIG_KEYWORD_DEFNAME,
    YADIG_KEYWORD_NODEFNAME,
    YADIG_KEYWORD_DNSSEC,
    YADIG_KEYWORD_NODNSSEC,
    YADIG_KEYWORD_DOMAIN,
    YADIG_KEYWORD_DSCP,
    YADIG_KEYWORD_EDNS,
    YADIG_KEYWORD_NOEDNS,
    YADIG_KEYWORD_EDNSFLAGS,
    YADIG_KEYWORD_NOEDNSFLAGS,
    YADIG_KEYWORD_EDNSNEGOTIATION,
    YADIG_KEYWORD_NOEDNSNEGOTIATION,
    YADIG_KEYWORD_EDNSOPT,
    YADIG_KEYWORD_NOEDNSOPT,
    YADIG_KEYWORD_EXPIRE,
    YADIG_KEYWORD_NOEXPIRE,
    YADIG_KEYWORD_FAIL,
    YADIG_KEYWORD_NOFAIL,
    YADIG_KEYWORD_HEADER_ONLY,
    YADIG_KEYWORD_NOHEADER_ONLY,
    YADIG_KEYWORD_IDENTIFY,
    YADIG_KEYWORD_NOIDENTIFY,
    YADIG_KEYWORD_IDNIN,
    YADIG_KEYWORD_NOIDNIN,
    YADIG_KEYWORD_IDNOUT,
    YADIG_KEYWORD_NOIDNOUT,
    YADIG_KEYWORD_IGNORE,
    YADIG_KEYWORD_NOIGNORE,
    YADIG_KEYWORD_KEEPOPEN,
    YADIG_KEYWORD_NOKEEPOPEN,
    YADIG_KEYWORD_MAPPED,
    YADIG_KEYWORD_NOMAPPED,
    YADIG_KEYWORD_MULTILINE,
    YADIG_KEYWORD_NOMULTILINE,
    YADIG_KEYWORD_NDOTS,
    YADIG_KEYWORD_NSID,
    YADIG_KEYWORD_NONSID,
    YADIG_KEYWORD_NSSEARCH,
    YADIG_KEYWORD_NONSSEARCH,
    YADIG_KEYWORD_ONESOA,
    YADIG_KEYWORD_NOONESOA,
    YADIG_KEYWORD_OPCODE,
    YADIG_KEYWORD_NOOPCODE,
    YADIG_KEYWORD_QR,
    YADIG_KEYWORD_NOQR,
    YADIG_KEYWORD_QUESTION,
    YADIG_KEYWORD_NOQUESTION,
    YADIG_KEYWORD_RDFLAG,
    YADIG_KEYWORD_NORDFLAG,
    YADIG_KEYWORD_RECURSE,
    YADIG_KEYWORD_NORECURSE,
    YADIG_KEYWORD_RETRY,
    YADIG_KEYWORD_RRCOMMENTS,
    YADIG_KEYWORD_NORRCOMMENTS,
    YADIG_KEYWORD_SEARCH,
    YADIG_KEYWORD_NOSEARCH,
    YADIG_KEYWORD_SHORT,
    YADIG_KEYWORD_NOSHORT,
    YADIG_KEYWORD_SHOWSEARCH,
    YADIG_KEYWORD_NOSHOWSEARCH,
    YADIG_KEYWORD_SIGCHASE,
    YADIG_KEYWORD_NOSIGCHASE,
    YADIG_KEYWORD_SPLIT,
    YADIG_KEYWORD_STATS,
    YADIG_KEYWORD_NOSTATS,
    YADIG_KEYWORD_SUBNET,
    YADIG_KEYWORD_NOSUBNET,
    YADIG_KEYWORD_TCP,
    YADIG_KEYWORD_NOTCP,
    YADIG_KEYWORD_TIMEOUT,
    YADIG_KEYWORD_TOPDOWN,
    YADIG_KEYWORD_NOTOPDOWN,
    YADIG_KEYWORD_TRACE,
    YADIG_KEYWORD_NOTRACE,
    YADIG_KEYWORD_TRIES,
    YADIG_KEYWORD_TRUSTED_KEY,
    YADIG_KEYWORD_TTLID,
    YADIG_KEYWORD_NOTTLID,
    YADIG_KEYWORD_TTLUNITS,
    YADIG_KEYWORD_NOTTLUNITS,
    YADIG_KEYWORD_UNKNOWNFORMAT,
    YADIG_KEYWORD_NOUNKNOWNFORMAT,
    YADIG_KEYWORD_VC,
    YADIG_KEYWORD_NOVC,
    YADIG_KEYWORD_ZFLAG,
    YADIG_KEYWORD_NOZFLAG
};

// ********************************************************************************
// ***** dig-like keywords and their names
// ********************************************************************************

static const value_name_table_t yadig_keywords[] = {{YADIG_KEYWORD_AAFLAG, "aaflag"},
                                                    {YADIG_KEYWORD_NOAAFLAG, "noaaflag"},
                                                    {YADIG_KEYWORD_ADDITIONAL, "additional"},
                                                    {YADIG_KEYWORD_NOADDITIONAL, "noadditional"},
                                                    {YADIG_KEYWORD_ADFLAG, "adflag"},
                                                    {YADIG_KEYWORD_NOADFLAG, "noadflag"},
                                                    {YADIG_KEYWORD_ALL, "all"},
                                                    {YADIG_KEYWORD_NOALL, "noall"},
                                                    {YADIG_KEYWORD_ANSWER, "answer"},
                                                    {YADIG_KEYWORD_NOANSWER, "noanswer"},
                                                    {YADIG_KEYWORD_AUTHORITY, "authority"},
                                                    {YADIG_KEYWORD_NOAUTHORITY, "noauthority"},
                                                    {YADIG_KEYWORD_BADCOOKIE, "badcookie"},
                                                    {YADIG_KEYWORD_NOBADCOOKIE, "nobadcookie"},
                                                    {YADIG_KEYWORD_BESTEFFORT, "besteffort"},
                                                    {YADIG_KEYWORD_NOBESTEFFORT, "nobesteffort"},
                                                    {YADIG_KEYWORD_BUFSIZE, "bufsize"},
                                                    {YADIG_KEYWORD_CDFLAG, "cdflag"},
                                                    {YADIG_KEYWORD_NOCDFLAG, "nocdflag"},
                                                    {YADIG_KEYWORD_CLASS, "class"},
                                                    {YADIG_KEYWORD_NOCLASS, "noclass"},
                                                    {YADIG_KEYWORD_CMD, "cmd"},
                                                    {YADIG_KEYWORD_NOCMD, "nocmd"},
                                                    {YADIG_KEYWORD_COMMENTS, "comments"},
                                                    {YADIG_KEYWORD_NOCOMMENTS, "nocomments"},
                                                    {YADIG_KEYWORD_COOKIE, "cookie"},
                                                    {YADIG_KEYWORD_NOCOOKIE, "nocookie"},
                                                    {YADIG_KEYWORD_CRYPTO, "crypto"},
                                                    {YADIG_KEYWORD_NOCRYPTO, "nocrypto"},
                                                    {YADIG_KEYWORD_DEFNAME, "defname"},
                                                    {YADIG_KEYWORD_NODEFNAME, "nodefname"},
                                                    {YADIG_KEYWORD_DNSSEC, "dnssec"},
                                                    {YADIG_KEYWORD_NODNSSEC, "nodnssec"},
                                                    {YADIG_KEYWORD_DOMAIN, "domain"},
                                                    {YADIG_KEYWORD_DSCP, "dscp"},
                                                    {YADIG_KEYWORD_EDNS, "edns"},
                                                    {YADIG_KEYWORD_NOEDNS, "noedns"},
                                                    {YADIG_KEYWORD_EDNSFLAGS, "ednsflags"},
                                                    {YADIG_KEYWORD_NOEDNSFLAGS, "noednsflags"},
                                                    {YADIG_KEYWORD_EDNSNEGOTIATION, "ednsnegotiation"},
                                                    {YADIG_KEYWORD_NOEDNSNEGOTIATION, "noednsnegotiation"},
                                                    {YADIG_KEYWORD_EDNSOPT, "ednsopt"},
                                                    {YADIG_KEYWORD_NOEDNSOPT, "noednsopt"},
                                                    {YADIG_KEYWORD_EXPIRE, "expire"},
                                                    {YADIG_KEYWORD_NOEXPIRE, "noexpire"},
                                                    {YADIG_KEYWORD_FAIL, "fail"},
                                                    {YADIG_KEYWORD_NOFAIL, "nofail"},
                                                    {YADIG_KEYWORD_HEADER_ONLY, "header-only"},
                                                    {YADIG_KEYWORD_NOHEADER_ONLY, "noheader-only"},
                                                    {YADIG_KEYWORD_IDENTIFY, "identify"},
                                                    {YADIG_KEYWORD_NOIDENTIFY, "noidentify"},
                                                    {YADIG_KEYWORD_IDNIN, "idnin"},
                                                    {YADIG_KEYWORD_NOIDNIN, "noidnin"},
                                                    {YADIG_KEYWORD_IDNOUT, "idnout"},
                                                    {YADIG_KEYWORD_NOIDNOUT, "noidnout"},
                                                    {YADIG_KEYWORD_IGNORE, "ignore"},
                                                    {YADIG_KEYWORD_NOIGNORE, "noignore"},
                                                    {YADIG_KEYWORD_KEEPOPEN, "keepopen"},
                                                    {YADIG_KEYWORD_NOKEEPOPEN, "nokeepopen"},
                                                    {YADIG_KEYWORD_MAPPED, "mapped"},
                                                    {YADIG_KEYWORD_NOMAPPED, "nomapped"},
                                                    {YADIG_KEYWORD_MULTILINE, "multiline"},
                                                    {YADIG_KEYWORD_NOMULTILINE, "nomultiline"},
                                                    {YADIG_KEYWORD_NDOTS, "ndots"},
                                                    {YADIG_KEYWORD_NSID, "nsid"},
                                                    {YADIG_KEYWORD_NONSID, "nonsid"},
                                                    {YADIG_KEYWORD_NSSEARCH, "nssearch"},
                                                    {YADIG_KEYWORD_NONSSEARCH, "nonssearch"},
                                                    {YADIG_KEYWORD_ONESOA, "onesoa"},
                                                    {YADIG_KEYWORD_NOONESOA, "noonesoa"},
                                                    {YADIG_KEYWORD_OPCODE, "opcode"},
                                                    {YADIG_KEYWORD_NOOPCODE, "noopcode"},
                                                    {YADIG_KEYWORD_QR, "qr"},
                                                    {YADIG_KEYWORD_NOQR, "noqr"},
                                                    {YADIG_KEYWORD_QUESTION, "question"},
                                                    {YADIG_KEYWORD_NOQUESTION, "noquestion"},
                                                    {YADIG_KEYWORD_RDFLAG, "rdflag"},
                                                    {YADIG_KEYWORD_NORDFLAG, "nordflag"},
                                                    {YADIG_KEYWORD_RECURSE, "recurse"},
                                                    {YADIG_KEYWORD_NORECURSE, "norecurse"},
                                                    {YADIG_KEYWORD_RETRY, "retry"},
                                                    {YADIG_KEYWORD_RRCOMMENTS, "rrcomments"},
                                                    {YADIG_KEYWORD_NORRCOMMENTS, "norrcomments"},
                                                    {YADIG_KEYWORD_SEARCH, "search"},
                                                    {YADIG_KEYWORD_NOSEARCH, "nosearch"},
                                                    {YADIG_KEYWORD_SHORT, "short"},
                                                    {YADIG_KEYWORD_NOSHORT, "noshort"},
                                                    {YADIG_KEYWORD_SHOWSEARCH, "showsearch"},
                                                    {YADIG_KEYWORD_NOSHOWSEARCH, "noshowsearch"},
                                                    {YADIG_KEYWORD_SIGCHASE, "sigchase"},
                                                    {YADIG_KEYWORD_NOSIGCHASE, "nosigchase"},
                                                    {YADIG_KEYWORD_SPLIT, "split"},
                                                    {YADIG_KEYWORD_STATS, "stats"},
                                                    {YADIG_KEYWORD_NOSTATS, "nostats"},
                                                    {YADIG_KEYWORD_SUBNET, "subnet"},
                                                    {YADIG_KEYWORD_NOSUBNET, "nosubnet"},
                                                    {YADIG_KEYWORD_TCP, "tcp"},
                                                    {YADIG_KEYWORD_NOTCP, "notcp"},
                                                    {YADIG_KEYWORD_TIMEOUT, "timeout"},
                                                    {YADIG_KEYWORD_TOPDOWN, "topdown"},
                                                    {YADIG_KEYWORD_NOTOPDOWN, "notopdown"},
                                                    {YADIG_KEYWORD_TRACE, "trace"},
                                                    {YADIG_KEYWORD_NOTRACE, "notrace"},
                                                    {YADIG_KEYWORD_TRIES, "tries"},
                                                    {YADIG_KEYWORD_TRUSTED_KEY, "trusted-key"},
                                                    {YADIG_KEYWORD_TTLID, "ttlid"},
                                                    {YADIG_KEYWORD_NOTTLID, "nottlid"},
                                                    {YADIG_KEYWORD_TTLUNITS, "ttlunits"},
                                                    {YADIG_KEYWORD_NOTTLUNITS, "nottlunits"},
                                                    {YADIG_KEYWORD_UNKNOWNFORMAT, "unknownformat"},
                                                    {YADIG_KEYWORD_NOUNKNOWNFORMAT, "nounknownformat"},
                                                    {YADIG_KEYWORD_VC, "vc"},
                                                    {YADIG_KEYWORD_NOVC, "novc"},
                                                    {YADIG_KEYWORD_ZFLAG, "zflag"},
                                                    {YADIG_KEYWORD_NOZFLAG, "nozflag"},
                                                    {0, NULL}};

/**
 * Callback for the command line parser.
 */

static ya_result yadig_cmdline_filter_callback(const struct cmdline_desc_s *desc, const char *arg_name, void *callback_owned);

CMDLINE_BEGIN(yadig_cmdline)
CMDLINE_FILTER(yadig_cmdline_filter_callback, NULL) // NULL is passed to the callback as a parameter (callback_owned)
// main
CMDLINE_INDENT(4)
CMDLINE_IMSG("Using a '+' as a prefix for a long option is equivalent to using '--'", "")
CMDLINE_BLANK()
CMDLINE_IMSG("options:", "")
CMDLINE_INDENT(4)
CMDLINE_SECTION(YADIG_SECTION_NAME)
CMDLINE_OPT("config", 'c', "config_file") // we use 'c' everywhere else, swapped with "class"
CMDLINE_HELP("<32 bits signed integer>", "sets that int32_t value")
CMDLINE_OPT("qname", 'q', "qname") // why not "n" and "name" ?
CMDLINE_HELP("<FQDN>", "which FQDN to be queried")
CMDLINE_OPT("type", 't', "qtype")
CMDLINE_HELP("<type>", "which type to be queried (default:a and aaaa)")
CMDLINE_OPT("class", 'C', "qclass")
CMDLINE_HELP("<class>", "which 'class' to be queried")
CMDLINE_OPT("key", 'y', "tsig_key_item")
CMDLINE_HELP("[hmac:]name:key", "TSIG key to use for authentication (default hmac: hmac-md5)")
CMDLINE_OPT("opcode", 0, "opcode")
CMDLINE_HELP("value", "sets the opcode of the message (default: 0 a.k.a. query)")
CMDLINE_OPT("epoch", 0, "epoch")
CMDLINE_HELP("value", "sets the epoch of a TSIG to another value than \"now\" (default: 0 a.k.a. \"now\")")
CMDLINE_BOOL("outgoing-hexdump", 0, "outgoing_hexdump")
CMDLINE_OPT("tcp-size-overwrite", 0, "tcp_size_overwrite")
/*
CMDLINE_BOOL(     "aaonly",           0,  "aaonly"                     )
CMDLINE_BOOL_NOT( "noaaonly",         0,  "aaonly"                     )
CMDLINE_BOOL(     "adflag",           0,  "adflag"                     )
CMDLINE_BOOL_NOT( "noadflag",         0,  "adflag"                     )
CMDLINE_BOOL(     "cdflag",           0,  "cdflag"                     )
CMDLINE_BOOL_NOT( "nocdflag",         0,  "cdflag"                     )

CMDLINE_BOOL(     "dnssec",           0,  "dnssec"                     )
CMDLINE_BOOL(     "ignore_tc",        0,  "ignore_tc"                  )
CMDLINE_BOOL(     "trace",            0,  "trace"                      )
CMDLINE_BOOL_NOT( "notrace",          0,  "trace"                      )
CMDLINE_BOOL(     "recursive",        0,  "recursive"                  )
CMDLINE_BOOL_NOT( "norecursive",      0,  "recursive"                  )
*/
CMDLINE_BOOL("additional", 0, "additional")
CMDLINE_HELP("", "print the additional section")
CMDLINE_BOOL_NOT("noadditional", 0, "additional")
CMDLINE_HELP("", "do not print the additional section")
CMDLINE_BOOL("answer", 0, "answer")
CMDLINE_HELP("", "print the  answer section")
CMDLINE_BOOL_NOT("noanswer", 0, "answer")
CMDLINE_HELP("", "do not print the  answer section")
CMDLINE_BOOL("authority", 0, "authority")
CMDLINE_HELP("", "print the authority section")
CMDLINE_BOOL_NOT("noauthority", 0, "authority")
CMDLINE_HELP("", "do not print the authority section")
CMDLINE_BOOL("question", 0, "question")
CMDLINE_HELP("", "print the question section")
CMDLINE_BOOL_NOT("noquestion", 0, "question")
CMDLINE_HELP("", "do not print the question section")

CMDLINE_BOOL("parse", 0, "parse")
CMDLINE_BOOL("dig", 0, "dig")
CMDLINE_BOOL("json", 0, "json")
CMDLINE_BOOL("xml", 0, "xml")
CMDLINE_BOOL("wire", 0, "wire")

CMDLINE_BOOL("short", 0, "short")
CMDLINE_BOOL("multiline", 0, "multiline")
CMDLINE_BOOL("pretty_print", 0, "pretty_print")

CMDLINE_BOOL("recurse", 0, "recursive")
CMDLINE_BOOL_NOT("norecurse", 0, "recursive")
// CMDLINE_HELP("", "do not set the recursion desired flag.")

CMDLINE_BOOL("udp", 0, "udp")
CMDLINE_BOOL("tcp", 0, "tcp")
CMDLINE_HELP("", "Enables TCP by default for querying the servers.")
CMDLINE_BOOL_NOT("noudp", 0, "udp")
CMDLINE_BOOL_NOT("notcp", 0, "tcp")
CMDLINE_BOOL("ipv4", '4', "ipv4")
CMDLINE_HELP("", "querying only over ipv4")
CMDLINE_BOOL("ipv6", '6', "ipv6")
CMDLINE_HELP("", "querying only over ipv6")

CMDLINE_OPT("port", 'p', "server_port")
CMDLINE_HELP("<PORT NUMBER>", "which PORT NUMBER from the SERVER to be queried (default: 53)")
CMDLINE_OPT("server", 's', "servers")
CMDLINE_HELP("<string [port <port number>]>", "connect to <fqdn> on port <portnumber>")
CMDLINE_IMSGS("", "<string> can be a name or an IP address")
CMDLINE_OPT("test", 'T', "test")
// resolver section
CMDLINE_RESOLVER(yadig_cmdline)

// command line
CMDLINE_VERSION_HELP(yadifa_cmdline)
CMDLINE_SECTION(YADIG_SECTION_NAME) // CMDLINE_VERSION_HELP changes the section
CMDLINE_BLANK()

CMDLINE_END(yadig_cmdline)

/**
 * The filter gets all words not taken by the rest of the CMDLINE struct
 */

static ya_result yadig_cmdline_filter_callback(const struct cmdline_desc_s *desc, const char *arg_name, void *callback_owned)
{
    void *arg = CMDLINE_CALLBACK_ARG_GET(desc);
    (void)arg;
    (void)callback_owned;
    ya_result ret;

    if(arg_name[0] == '@')
    {
        // @ip

        ret = cmdline_get_opt_short(desc, "s", &arg_name[1]);
        return ret;
    }
    else if(arg_name[0] == '+')
    {
        static enum YADIG_CMD_STATE cmdline_state = YADIG_CMD_STATE_BEGIN;

        // look for the '=' and cut
        char *arg_value = strchr(arg_name, '=');
        if(arg_value != NULL)
        {
            *arg_value = '\0';
            ++arg_value;
        }
        ++arg_name;

        if(FAIL(ret = cmdline_get_opt_long(yadig_cmdline, arg_name, arg_value)))
        {
            return ret;
        }

        switch(cmdline_state)
        {
            case YADIG_CMD_STATE_BEGIN:
            {
                // find if the word has some meaning

                uint32_t keyword_enum = 0;
                if(ISOK(ret = value_name_table_get_value_from_casename(yadig_keywords, arg_name, &keyword_enum)))
                {
                    //
                }
                else
                {
                    // unknown keyword
                }

                break;
            }
            case YADIG_CMD_STATE_BUFSIZE:
            {
                ret = cmdline_get_opt_long(desc, "bufsize", arg_value);
                break;
            }
            case YADIG_CMD_STATE_COOKIE:
            {
                break;
            }
            case YADIG_CMD_STATE_DOMAIN:
            {
                break;
            }
            case YADIG_CMD_STATE_DSCP:
            {
                break;
            }
            case YADIG_CMD_STATE_EDNS:
            {
                break;
            }
            case YADIG_CMD_STATE_EDNSFLAGS:
            {
                break;
            }
            case YADIG_CMD_STATE_EDNSOPT:
            {
                break;
            }
            case YADIG_CMD_STATE_EDNSOPT_CODE:
            {
                break;
            }
            case YADIG_CMD_STATE_NDOTS:
            {
                break;
            }
            case YADIG_CMD_STATE_RETRY:
            {
                break;
            }
            case YADIG_CMD_STATE_SPLIT:
            {
                break;
            }
            case YADIG_CMD_STATE_TIMEOUT:
            {
                break;
            }
            case YADIG_CMD_STATE_TRIES:
            {
                break;
            }
            case YADIG_CMD_STATE_TRUSTED_KEY:
            {
                break;
            }
            case YADIG_CMD_STATE_END:
            {
                break;
            }
        };
    }
    else
    {
        // word could be fqdn, class, type
        ret = SUCCESS;
    }

    return ret;
}

// ********************************************************************************
// ***** command help usage
// ********************************************************************************

#if 0 /// @todo 20240927 gve -- check with the command line inlined help and remove
static const char yadig_cmdline_help[] =
        "command: yadifa [-c config] [-s server] [-v] command\n\n"
        "\toptions:\n"
        "\t\t--config/-c <config_file>   : use <config_file> as configuration\n"

         "Question options:\n"
         "\t\t--class/-c <class>                        : which 'class' to be queried\n"
         "\t\t--type/-t <type>                          : which type to be queried(default:a and aaaa)\n"
         "\t\t-x                                        : TYPE = PTR to be queried\n"
         "\t\t--name/-q <FQDN>                          : which FQDN to be queried\n"
         "\t\t--server/-s <string [port <port number>]> : connect to <fqdn> on port <portnumber>\n"
         "\t\t                                            <string> can be a name or an IP address\n"

         "\t\t--port/-p <PORT NUMBER>                   : which PORT NUMBER from the SERVER to be queried (default: 53)\n"
         "\t\t--source/-b <IPADRESS#PORT>               : which PORT NUMBER and source IP address to be used for querying\n" // NOT USED
         "\n"
         "\t\t-y <hmac:name:key>                        : base64 TSIG key\n"
         "\t\t-k <FILENAME>                             : filename with base64 tsig key in\n"
         "\n"
         "IP Protocol options:\n"
         "\n"
         "\t\t--protocol <PROTOCOL>                     : which protocols to be used for quering (default: udp,tcp,4,6)\n"
         "\t\t-4                                        : querying only over ipv4\n"
         "\t\t-6                                        : querying only over ipv6\n"
         "\t\t--udp-tries <number>                      : number of udp attempts (default: 3)\n"
         "\t\t--udp-retry <number>                      : number of udp retries (default: 3)\n"
         "\t\t--udp-time  <number>                      : query timeout\n"
         "\n"
         "DNS Question options:\n"
         "\t\t--edns <NUMBER>                           : set EDNS version\n"
         "\t\t--edns_max <NUMBER>                       : set EDNS max UDP packet size\n"
         "\t\t--[no]tc                                  : ignore or do not ignore TC flag\n"
         "\t\t--[no]recursive                           : recursive mode (default: recursive)\n"
         "\t\t--[no]dnssec                              : request dnssec records (default: no dnssec)\n"
         "\t\t--flags <string>                          : set flags (default: AAonly,CD,AD)\n"
         "\t\t--trace                                   : trace delegation down from root\n"
         "\n"
         "View options:\n"
         "\t\t--view <string>                           : set view mode (default: yadifa style)\n"
         "\t\t                                                          string can be bind\n"
         "\t\t                                            string can be json\n"
         "\t\t                                            string can be multiline\n"
         "\t\t                                            string can be short\n"
         "\t\t                                            string can be xml\n"
         "\t\t                                            string can be yadifa\n"
         "\t\t--[no]additional                          : display additional part of query\n"
         "\t\t--[no]answer                              : display answer part of query\n"
         "\t\t--[no]authority                           : display authority part of query\n"
         "\t\t--[no]question                            : display question part of query\n"
         "\n"
         "\t\t--version/-V                              : view version\n"
         "\t\t--help/-h                                 : show this help text\n";

#endif

// ********************************************************************************
// ***** module initializer
// ********************************************************************************

static ya_result yadig_init()
{
    // 1. log handling. Is this really needed?  /// @todo 20140520 gve -- revisiting maybe this can be removed or put in
    // some kind of option
    for(const struct logger_name_handle_s *name_handle = logger_name_handles; name_handle->name != NULL; name_handle++)
    {
        logger_handle_create(name_handle->name, name_handle->handlep);
    }

    return SUCCESS;
}

// ********************************************************************************
// ***** module finalizer
// ********************************************************************************

static ya_result yadig_finalize() { return SUCCESS; }

// ********************************************************************************
// ***** module register
// ********************************************************************************

static int yadig_config_register(int priority)
{
    ya_result return_code;

    /*    ------------------------------------------------------------    */

    // 1. register resolver options like: udp_time, udp_tries, ...
    //
    if(FAIL(return_code = config_register_resolver(++priority)))
    {
        return return_code;
    }

    // 2. register main options: qname, qclass, qtype, ...
    //
    // init and register main settings container
    ZEROMEMORY(&g_yadig_settings, sizeof(g_yadig_settings));
    if(FAIL(return_code = config_register_struct(YADIG_SECTION_NAME, yadig_settings_desc, &g_yadig_settings, ++priority)))
    {
        return return_code;
    }

    return return_code;
}

// ********************************************************************************
// ***** module setup
// ********************************************************************************

static int yadig_setup()
{
    return SUCCESS; // returns anything else than 0 => program will exit
}

static ya_result yadig_help_print(const module_s *m, output_stream_t *os)
{
    (void)m;

    cmdline_print_help(m->cmdline_table, os);

    return SUCCESS;
}

// ********************************************************************************
// ***** module run
// ********************************************************************************

ya_result message_query_tcp_with_timeout2(dns_message_t *mesg, host_address_t *address, uint8_t to_sec);

/*------------------------------------------------------------------------------
 * FUNCTIONS */

void host_address_show_list(host_address_t *host)
{
    uint32_t total = host_address_count(host);
    while(host != NULL)
    {
        formatln("kind       : %d", host->version);
        formatln("host       : %{hostaddr}", host);
        formatln("port number: %d\n", ntohs(host->port));
        host = host->next;
    }

    formatln("TOTAL: %d", total);
}

ya_result yadig_message_writer_init(dns_message_writer_t *dmw, output_stream_t *os, uint32_t flags)
{
    dns_message_writer_method *writer_method;
    switch(g_yadig_settings.view_mode)
    {
        case VM_DEFAULT:
        {
            writer_method = dns_message_writer_dig;
            break;
        }
        case VM_DIG:
        {
            writer_method = dns_message_writer_dig;
            break;
        }
        case VM_JSON:
        {
            writer_method = dns_message_writer_json;
            break;
        }
        case VM_EASYPARSE:
        {
            writer_method = dns_message_writer_easyparse;
            break;
        }

        default: // you can only have one 1 bit set of the first 16 bits
        {
            osformatln(os, "you can set one view mode at the time (e.g. --json)");
            return INVALID_ARGUMENT_ERROR;
        }
    }

    dns_message_writer_init(dmw, termout, writer_method, flags);
    return SUCCESS;
}

static ya_result yadig_query_message_process(dns_message_t *mesg, dns_message_t *recv_mesg, const host_address_t *server, int64_t duration_ms)
{
    ya_result ret;
    bool      has_fqdn = false;
    uint8_t   fqdn[DOMAIN_LENGTH_MAX + 1];

    // if there is a query section, copy the FQDN

    if(dns_message_get_query_count_ne(mesg) != 0)
    {
        has_fqdn = true;
        dnsname_copy(fqdn, dns_message_get_buffer_const(mesg) + 12);
    }

    // copy TSIG signature information from the query to the receiver

    dns_message_tsig_copy_from(recv_mesg, mesg);

    dns_message_writer_t dmw;
    yadig_message_writer_init(&dmw, termout, DNS_MESSAGE_WRITER_SIMPLE_QUERY);
    dns_message_writer_message_t msg;
    dns_message_writer_message_init_with_dns_message(&msg, recv_mesg);
    msg.time_duration_ms = MAX(duration_ms, 0);
    msg.server = server;

    if(FAIL(ret = query_result_view(&dmw, &msg, SUCCESS)))
    {
        return ret;
    }

    flushout();

    if(ISOK(ret = dns_message_process_lenient(recv_mesg)))
    {
        // check the domain is right

        if(!has_fqdn || dnsname_equals(fqdn, dns_message_get_canonised_fqdn(recv_mesg)))
        {
            // everything checks up

            dns_message_copy_sender_from(mesg, recv_mesg);
            mesg->_ar_start = &mesg->_buffer[recv_mesg->_ar_start - recv_mesg->_buffer];
            mesg->_iovec.iov_len = recv_mesg->_iovec.iov_len;
            mesg->_edns0_opt_ttl.as_u32 = recv_mesg->_edns0_opt_ttl.as_u32;
            mesg->_status = recv_mesg->_status;

            if(mesg->_buffer_size < mesg->_iovec.iov_len)
            {
                mesg->_buffer_size = mesg->_iovec.iov_len;
            }

            mesg->_query_type = recv_mesg->_query_type;
            mesg->_query_class = recv_mesg->_query_class;
            dns_message_opt_copy_from(mesg, recv_mesg);

            if((mesg->_control_buffer_size = recv_mesg->_control_buffer_size) > 0)
            {
                memcpy(mesg->_msghdr_control_buffer, recv_mesg->_msghdr_control_buffer, recv_mesg->_control_buffer_size);
            }

            dnsname_copy(mesg->_canonised_fqdn, recv_mesg->_canonised_fqdn);

            memcpy(mesg->_buffer, recv_mesg->_buffer, recv_mesg->_iovec.iov_len);
        }
        else
        {
            ret = MESSAGE_UNEXPECTED_ANSWER_DOMAIN;
        }
    }

    return ret;
}

static inline ssize_t yadig_message_write_tcp(dns_message_t *mesg, output_stream_t *os)
{
    ssize_t  ret;
    uint16_t tcp_len;
    uint16_t tcp_len_ne;
    if(g_yadig_settings.tcp_size_overwrite > U16_MAX)
    {
        tcp_len = dns_message_get_size_u16(mesg);
    }
    else
    {
        if(g_yadig_settings.tcp_size_overwrite > dns_message_get_buffer_size(mesg))
        {
            g_yadig_settings.tcp_size_overwrite = dns_message_get_buffer_size(mesg);
        }
        osformatln(termout, "; tcp-size-overwrite=%hu", g_yadig_settings.tcp_size_overwrite);
        tcp_len = g_yadig_settings.tcp_size_overwrite;
        int32_t pad_len = g_yadig_settings.tcp_size_overwrite - dns_message_get_size(mesg);
        if(pad_len > 0)
        {
            memset(dns_message_get_buffer(mesg) + dns_message_get_size(mesg), 0, pad_len);
        }
    }

    tcp_len_ne = ntohs(tcp_len);

    if(ISOK(ret = output_stream_write_fully(os, &tcp_len_ne, 2)))
    {
        ret = output_stream_write_fully(os, dns_message_get_buffer_const(mesg), tcp_len);
    }
    return ret;
}

static ya_result yadig_simple_query_tcp_with_timeout(dns_message_t *mesg, const host_address_t *address, uint8_t to_sec)
{
    ya_result       return_value;
    input_stream_t  tis;
    output_stream_t tos;

    /*    ------------------------------------------------------------    */

    uint16_t qtype = dns_message_get_query_type(mesg);
    if((qtype == TYPE_AXFR) || (qtype == TYPE_IXFR))
    {
        return INVALID_STATE_ERROR;
    }

    int64_t start = timeus();

    if(ISOK(return_value = tcp_input_output_stream_connect_host_address(address, &tis, &tos, to_sec)))
    {
        int fd = fd_input_stream_get_filedescriptor(&tis);

        tcp_set_sendtimeout(fd, 3, 0);
        tcp_set_recvtimeout(fd, 3, 0);

        if(ISOK(return_value = yadig_message_write_tcp(mesg, &tos)))
        {
            output_stream_flush(&tos);

            dns_message_with_buffer_t recv_mesg_buff;
            dns_message_t            *recv_mesg = dns_message_data_with_buffer_init(&recv_mesg_buff);

            // output_stream_t *os = termout; /// @todo 20150708 gve -- must be a setting from config or command_line

            // not a message stream:

            if(ISOK(return_value = dns_message_read_tcp(recv_mesg, &tis)))
            {
                int64_t stop = timeus();

                return_value = yadig_query_message_process(mesg, recv_mesg, address, (stop - start) / 1000);
            }

            dns_message_finalize(recv_mesg);
        }

        output_stream_close(&tos);
        output_stream_close(&tis);
    }

    return return_value;
}

static ya_result yadig_xfr_query_tcp_with_timeout(dns_message_t *mesg, const host_address_t *address, uint8_t to_sec)
{
    ya_result      ret;
    input_stream_t xfris;

    uint16_t       qtype = dns_message_get_query_type(mesg);
    if((qtype != TYPE_AXFR) && (qtype != TYPE_IXFR))
    {
        return INVALID_STATE_ERROR;
    }

    const uint8_t *fqdn = dns_message_get_canonised_fqdn(mesg);
    const uint8_t *soa_rdata = NULL;
    int            soa_rdata_len = 0;
    /// @note also exists: xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn,
    /// rtype, rclass, serial, xfr_flags);

    int64_t time_begin_ms = timems();

    ret = xfr_input_stream_init_with_query_and_timeout(&xfris, address, fqdn, 86400, soa_rdata, soa_rdata_len, XFR_ALLOW_BOTH, to_sec);

    if(ret < 0)
    {
        osformatln(termerr, "%{dnstype} query to %{dnsname} failed with %r", &qtype, fqdn, ret);
        return ret;
    }

    ret = xfr_input_stream_get_type(&xfris);
    if(ret != qtype)
    {
        uint16_t answer_type = ret;
        osformatln(termerr, "%{dnstype} query to %{dnsname} returned an %{dnstype} answer", &qtype, fqdn, &answer_type);
        return INVALID_MESSAGE;
    }

    const uint8_t *xfr_origin = xfr_input_stream_get_origin(&xfris);
    if(!dnsname_equals(xfr_origin, fqdn))
    {
        osformatln(termerr, "%{dnstype} query to %{dnsname} returned an answer for %{dnsname}", &qtype, fqdn, xfr_origin);
        return INVALID_MESSAGE;
    }

    output_stream_t *os = termout; /// @todo 20150708 gve -- must be a setting from config or command_line

    /*
    ; <<>> DiG 9.20.1 <<>> @192.168.254.53 -p 10053 eu AXFR
    ; (1 server found)
    ;; global options: +cmd
    */

    dns_resource_record_t *dnsrr = dns_resource_record_new_instance();
    int64_t                record_count;
    for(record_count = 0;; ++record_count)
    {
        ret = dns_resource_record_read(dnsrr, &xfris);
        if(ret <= 0)
        {
            if(ret < 0)
            {
                osformatln(termerr, "%{dnstype} query to %{dnsname} failed with", &qtype, fqdn, ret);
                dns_resource_record_delete(dnsrr);
                input_stream_close(&xfris);
                return ret;
            }
            break;
        }

        osformatln(os, "%{dnsrr}", dnsrr);
    }

    dns_resource_record_delete(dnsrr);

    int64_t time_end_ms = timems();

    /*
    ;; Query time: 10476 msec
    ;; SERVER: 192.168.254.53#10053(192.168.254.53) (TCP)
    ;; WHEN: Tue Sep 24 10:35:30 CEST 2024
    ;; XFR size: 1116012 records (messages 986, bytes 32259013)
    */

    (void)record_count;
    time_t timestamp = time_begin_ms / 1000;

    osformatln(os,
               ";; Query time: %li msec\n"
               ";; SERVER: %{hostaddr}(%{hostaddrip}) (TCP)\n"
               ";; WHEN: %s\n"
               ";; XFR size: %lu records (messages %u, bytes %lu)",
               time_end_ms - time_begin_ms,
               address,
               address,
               ctime(&timestamp),
               xfr_input_stream_get_record_count(&xfris),
               xfr_input_stream_get_message_count(&xfris),
               xfr_input_stream_get_size_total(&xfris));
    input_stream_close(&xfris);

    return ret;
}

static ya_result yadig_query_tcp_with_timeout(dns_message_t *mesg, const host_address_t *address, uint8_t to_sec)
{
    ya_result ret;
    uint16_t  qtype = dns_message_get_query_type(mesg);
    if((qtype != TYPE_AXFR) && (qtype != TYPE_IXFR))
    {
        ret = yadig_simple_query_tcp_with_timeout(mesg, address, to_sec);
    }
    else
    {
        ret = yadig_xfr_query_tcp_with_timeout(mesg, address, to_sec);
    }

    return ret;
}

static ya_result yadig_query_udp_with_timeout(dns_message_t *mesg, const host_address_t *server, int seconds)
{
    yassert(mesg != NULL);
    yassert(server != NULL);

    /* connect the server */

    ya_result ret;

    uint16_t  id;

    if(ISOK(ret = dns_message_set_sender_from_host_address(mesg, server)))
    {
        int sockfd;

        if((sockfd = socket(dns_message_get_sender_sa(mesg)->sa_family, SOCK_DGRAM, 0)) >= 0)
        {
            fd_setcloseonexec(sockfd);

            tcp_set_recvtimeout(sockfd, seconds, 0); /* half a second for UDP is a lot ... */

            int     send_size = dns_message_get_size(mesg);

            ssize_t n;

            if((n = dns_message_send_udp(mesg, sockfd)) == send_size)
            {
                id = dns_message_get_id(mesg);

                dns_message_with_buffer_t recv_mesg_buff;
                dns_message_t            *recv_mesg = dns_message_data_with_buffer_init(&recv_mesg_buff);

                // recv_mesg._tsig.hmac = mesg->_tsig.hmac;

                int64_t time_limit = seconds;
                time_limit *= ONE_SECOND_US;
                // time_limit += 0;
                time_limit += timeus();

                ret = SUCCESS;

                int64_t start = timeus();

                while((n = dns_message_recv_udp(recv_mesg, sockfd)) >= 0)
                {
#if DEBUG
                    log_memdump_ex(g_system_logger, MSG_DEBUG5, dns_message_get_buffer_const(recv_mesg), n, 16, OSPRINT_DUMP_HEXTEXT);
#endif
                    // check the id is right

                    if(dns_message_get_id(recv_mesg) == id)
                    {
                        // check that the sender is the one we spoke to

                        if(sockaddr_equals(dns_message_get_sender_sa(mesg), dns_message_get_sender_sa(recv_mesg)))
                        {
                            int64_t stop = timeus();

                            if(!dns_message_is_truncated(mesg))
                            {
                                ret = yadig_query_message_process(mesg, recv_mesg, server, (stop - start) / 1000);
                            }
                            else
                            {
                                // note that the message was truncated
                                ret = yadig_query_tcp_with_timeout(mesg, server, seconds);
                            }

                            // ret is set to an error

                            break;
                        }
                        else
                        {
                            ret = INVALID_MESSAGE;
                        }
                    }
                    else
                    {
                        ret = MESSAGE_HAS_WRONG_ID;
                    }

                    int64_t time_now = timeus();

                    if(time_now >= time_limit)
                    {
                        ret = MAKE_ERRNO_ERROR(EAGAIN);
                        break;
                    }

                    int64_t time_remaining = time_limit - time_now;

                    tcp_set_recvtimeout(sockfd, time_remaining / 1000000ULL, time_remaining % 1000000ULL); /* half a second for UDP is a lot ... */
                }

                dns_message_finalize(recv_mesg);

                // recv_mesg._tsig.hmac = NULL;

                if((n < 0) && ISOK(ret))
                {
                    ret = ERRNO_ERROR;
                }

                /* timeout */
            }
            else
            {
                ret = (n < 0) ? n : ERROR;
            }

            socketclose_ex(sockfd);
        }
        else
        {
            ret = ERRNO_ERROR;
        }
    }

    return ret;
}

ya_result yadig_run()
{
    ya_result                 return_code;

    uint8_t                   go_tcp = NOK; /// @todo 20150708 gve -- change this back to 'OK'. 'NOK' is just for testing some AXFR stuff !!!!!!

    dns_message_with_buffer_t mesg_buff;
    dns_message_t            *mesg;

    /* give ID from config or randomized */
    uint16_t id = dns_new_id();

    uint16_t qtype = htons(g_yadig_settings.qtype);
    uint16_t qclass = htons(g_yadig_settings.qclass);
    uint16_t protocol = g_yadig_settings.protocol;

    //    uint16_t question_mode          = g_yadig_main_settings.question_mode;
    uint16_t question_mode = 0;

    uint8_t *qname = g_yadig_settings.qname; /// @todo 20150713 gve -- this is really not good, CHECK THIS!!!!!! gery
#if 0
    uint8_t udp_retries = resolver_retry_get();
    uint8_t udp_time = resolver_time_get();
    uint8_t udp_tries = resolver_tries_get();
#endif
    // 0. put the right name server list in place in the 'resolver'
    if(g_yadig_settings.servers != NULL)
    {
        uint16_t port = g_yadig_settings.server_port;
        // set port or default port
        host_address_set_default_port_value(g_yadig_settings.servers, ntohs(port));
        // remove list
        host_address_delete_list(config_resolver_settings.nameserver);
        // add new list
        config_resolver_settings.nameserver = host_address_copy(g_yadig_settings.servers);
    }

#if 0 // DEBUG
    formatln("show me the goodies");
//  resolv_print(&config_resolver_settings);
    formatln("show me the goodies");
    flushout();

    formatln("QTYPE     : %lu", ntohs(qtype));
    formatln("QCLASS    : %lu", ntohs(qclass));

    formatln("RETRY     : %u", udp_retries);
    formatln("TIME      : %u", udp_time);
    formatln("TRIES     : %u", udp_tries);
//    formatln("PORT      : %d", port);

    formatln("QNAME     : %{dnsname}", qname);

    formatln("server    : %{hostaddr}", config_resolver_settings.nameserver);
#endif

#if 1
    uint8_t connect_timeout = 1;
#endif

    if((g_yadig_settings.view_mode == VM_DEFAULT) || (g_yadig_settings.view_mode == VM_DIG))
    {
        print("; <<>> yadifa dig <<>>");
        for(int_fast32_t i = 1; i < module_arg_count(); ++i)
        {
            print(" ");
            print(module_arg_get(i));
        }
        println("");
    }

    mesg = dns_message_data_with_buffer_init(&mesg_buff);

    /* 1. check first if udp is needed and go for it */

    if(protocol & QM_PROTOCOL_TCP)
    {
        protocol &= ~QM_PROTOCOL_UDP;
    }

    /* CLASS_CTRL is always in TCP mode */

    if(qtype == TYPE_AXFR)
    {
        protocol &= ~QM_PROTOCOL_UDP;
        protocol |= QM_PROTOCOL_TCP;
    }

    if(g_yadig_settings.buffer_size > 0)
    {
        dns_message_edns0_setmaxsize(g_yadig_settings.buffer_size);
        dns_message_set_edns0(mesg, true);
    }

    /* A. make the message to be sent */
    dns_message_make_query_ex(mesg, id, qname, qtype, qclass, 0);

    dns_message_set_opcode(mesg, dns_message_make_opcode(g_yadig_settings.opcode));

    if(g_yadig_settings.recurse)
    {
        dns_message_set_recursion_desired(mesg);
    }

    const uint8_t *tsig_key_name = (g_yadig_settings.tsig_key_item != NULL) ? g_yadig_settings.tsig_key_item->name : g_yadig_settings.tsig_key_name;

    if(tsig_key_name != NULL)
    {
        int64_t epoch = g_yadig_settings.epoch;

        if(epoch == 0)
        {
            epoch = timeus() / ONE_SECOND_US;
        }

        if(FAIL(return_code = dns_message_sign_query_by_name_with_epoch_and_fudge(mesg, tsig_key_name, epoch, 300)))
        {
            if(return_code == TSIG_BADKEY)
            {
                osformatln(termerr, "The key %{dnsname} is not supported.\n", tsig_key_name);
                flusherr();
            }
            else if(return_code == TSIG_SIZE_LIMIT_ERROR)
            {
                osformatln(termerr, "The size of the key %{dnsname} is not supported.\n", tsig_key_name);
                flusherr();
            }

            dns_message_finalize(mesg);

            return return_code;
        }
    }

    /* B. send the message via UDP */

    ya_result query_return_code;

    if(g_yadig_settings.outgoing_hexdump)
    {
        osprintln(termout, "; outgoing message hexadecimal dump begin");
        osprint_dump(termout, dns_message_get_buffer(mesg), dns_message_get_size(mesg), 16, OSPRINT_DUMP_OFFSET | OSPRINT_DUMP_HEX | OSPRINT_DUMP_TEXT);
        osprintln(termout, "\n; outgoing message hexadecimal dump end");
        flushout();
    }

    if(protocol & QM_PROTOCOL_UDP)
    {
        if(FAIL(query_return_code = yadig_query_udp_with_timeout(mesg, config_resolver_settings.nameserver, connect_timeout)))
        {
            dns_message_finalize(mesg);
            return query_return_code;
        }
    }
    else if(protocol & QM_PROTOCOL_TCP)
    {
        if(FAIL(return_code = yadig_query_tcp_with_timeout(mesg, config_resolver_settings.nameserver, connect_timeout)))
        {
            return return_code;
        }
    }

    /* C. check the result of the query + check if TCP query is needed */
    if(FAIL(return_code = query_result_check(id, protocol, question_mode, mesg, &go_tcp)))
    {
        return return_code;
    }

    /* D. show the result of the message depending on the :
     *       * view_mode
     *       * view_mode_with
     */

    /* 2. check first if tcp is needed and go for it */

    /* do TCP if asked, if --noudp, or TC bit is on */
    if((protocol & QM_PROTOCOL_TCP) && go_tcp == OK)
    {
        //        message_make_query(mesg, id, qname->ip.dname.dname, qtype, qclass);
        dns_message_make_query(mesg, id, qname, qtype, qclass);

        if(FAIL(return_code = yadig_query_tcp_with_timeout(mesg, config_resolver_settings.nameserver, connect_timeout)))
        {
            return return_code;
        }
        /*
                if (FAIL(return_code = check_query_result(id, protocol, question_mode, mesg, &go_tcp)))
                {
                    return return_code;
                }
        */
        flushout();
    }

    /* 3. SHOW THE RESULT */

    dns_message_finalize(mesg);

    return OK;
}

// ********************************************************************************
// ***** module virtual table
// ********************************************************************************

const module_s yadig_program = {
    yadig_init,            // module initialiser
    yadig_finalize,        // module finaliser
    yadig_config_register, // module register
    yadig_setup,           // module setup
    yadig_run,             // module run
    yadig_help_print,

    yadig_cmdline, // module command line struct
    NULL,          // module command line callback
    NULL,          // module filter arguments

    "yadifa dig", // module public name
    "dig",        // module command (name as executable match)
    "dig",        // module parameter (name as first parameter)
    NULL,         // module text to be printed upon help request
    ".yadig.rc"   // module rc file (ie: ".modulerc"
};

// ********************************************************************************
// ***** FUNCTIONS
// ********************************************************************************
