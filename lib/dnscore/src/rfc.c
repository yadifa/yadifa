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
 * @defgroup
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <strings.h>

#include "dnscore/rfc.h"
#include "dnscore/ctrl_rfc.h"
#include "dnscore/string_set.h"
#include "dnscore/ptr_treemap.h"
#include "dnscore/u32_treemap.h"
#include "dnscore/format.h"
#include "dnscore/mutex.h"
#include "dnscore/dnscore_extension.h"
#include "dnscore/string_set.h"

#define DNSCORE_RFC_C

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

static string_treemap_node_t *class_set = NULL;
static string_treemap_node_t *type_set = NULL;
static string_treemap_node_t *dnssec_algo_set = NULL;
static string_treemap_t       word_set = NULL;
static initialiser_state_t    rfc_init_state = INITIALISE_STATE_INIT;

const class_table_t           qclass[] = {{CLASS_IN, CLASS_IN_NAME},
                                          {CLASS_CS, CLASS_CS_NAME},
                                          {CLASS_CH, CLASS_CH_NAME},
                                          {CLASS_HS, CLASS_HS_NAME},
                                          {CLASS_CTRL, CLASS_CTRL_NAME},

                                          {CLASS_NONE, CLASS_NONE_NAME},
                                          {CLASS_ANY, CLASS_ANY_NAME},
                                          {0, NULL}};

const type_table_t            qtype[] = {{TYPE_A, TYPE_A_NAME},                   // 1
                                         {TYPE_NS, TYPE_NS_NAME},                 // 2
                                         {TYPE_MD, TYPE_MD_NAME},                 // 3
                                         {TYPE_MF, TYPE_MF_NAME},                 // 4
                                         {TYPE_CNAME, TYPE_CNAME_NAME},           // 5
                                         {TYPE_SOA, TYPE_SOA_NAME},               // 6
                                         {TYPE_MB, TYPE_MB_NAME},                 // 7
                                         {TYPE_MG, TYPE_MG_NAME},                 // 8
                                         {TYPE_MR, TYPE_MR_NAME},                 // 9
                                         {TYPE_NULL, TYPE_NULL_NAME},             // 10
                                         {TYPE_WKS, TYPE_WKS_NAME},               // 11
                                         {TYPE_PTR, TYPE_PTR_NAME},               // 12
                                         {TYPE_HINFO, TYPE_HINFO_NAME},           // 13
                                         {TYPE_MINFO, TYPE_MINFO_NAME},           // 14
                                         {TYPE_MX, TYPE_MX_NAME},                 // 15
                                         {TYPE_TXT, TYPE_TXT_NAME},               // 16
                                         {TYPE_RP, TYPE_RP_NAME},                 // 17
                                         {TYPE_AFSDB, TYPE_AFSDB_NAME},           // 18
                                         {TYPE_X25, TYPE_X25_NAME},               // 19
                                         {TYPE_ISDN, TYPE_ISDN_NAME},             // 20
                                         {TYPE_RT, TYPE_RT_NAME},                 // 21
                                         {TYPE_NSAP, TYPE_NSAP_NAME},             // 22
                                         {TYPE_NSAP_PTR, TYPE_NSAP_PTR_NAME},     // 23
                                         {TYPE_SIG, TYPE_SIG_NAME},               // 24
                                         {TYPE_KEY, TYPE_KEY_NAME},               // 25
                                         {TYPE_PX, TYPE_PX_NAME},                 // 26
                                         {TYPE_GPOS, TYPE_GPOS_NAME},             // 27
                                         {TYPE_AAAA, TYPE_AAAA_NAME},             // 28
                                         {TYPE_LOC, TYPE_LOC_NAME},               // 29
                                         {TYPE_NXT, TYPE_NXT_NAME},               // 30
                                         {TYPE_EID, TYPE_EID_NAME},               // 31
                                         {TYPE_NIMLOC, TYPE_NIMLOC_NAME},         // 32
                                         {TYPE_SRV, TYPE_SRV_NAME},               // 33
                                         {TYPE_ATMA, TYPE_ATMA_NAME},             // 34
                                         {TYPE_NAPTR, TYPE_NAPTR_NAME},           // 35
                                         {TYPE_KX, TYPE_KX_NAME},                 // 36
                                         {TYPE_CERT, TYPE_CERT_NAME},             // 37
                                         {TYPE_A6, TYPE_A6_NAME},                 // 38
                                         {TYPE_DNAME, TYPE_DNAME_NAME},           // 39
                                         {TYPE_SINK, TYPE_SINK_NAME},             // 40
                                         {TYPE_OPT, TYPE_OPT_NAME},               // 41
                                         {TYPE_APL, TYPE_APL_NAME},               // 42
                                         {TYPE_DS, TYPE_DS_NAME},                 // 43
                                         {TYPE_SSHFP, TYPE_SSHFP_NAME},           // 44
                                         {TYPE_IPSECKEY, TYPE_IPSECKEY_NAME},     // 45
                                         {TYPE_RRSIG, TYPE_RRSIG_NAME},           // 46
                                         {TYPE_NSEC, TYPE_NSEC_NAME},             // 47
                                         {TYPE_DNSKEY, TYPE_DNSKEY_NAME},         // 48
                                         {TYPE_DHCID, TYPE_DHCID_NAME},           // 49
                                         {TYPE_NSEC3, TYPE_NSEC3_NAME},           // 50
                                         {TYPE_NSEC3PARAM, TYPE_NSEC3PARAM_NAME}, // 51
                                         {TYPE_TLSA, TYPE_TLSA_NAME},             // 52
                                         {TYPE_HIP, TYPE_HIP_NAME},               // 55
                                         {TYPE_NINFO, TYPE_NINFO_NAME},           // 56
                                         {TYPE_RKEY, TYPE_RKEY_NAME},             // 57
                                         {TYPE_TALINK, TYPE_TALINK_NAME},         // 58
                                         {TYPE_CDS, TYPE_CDS_NAME},               // 59

                                         {TYPE_CDNSKEY, TYPE_CDNSKEY_NAME},       // 60
                                         {TYPE_OPENPGPKEY, TYPE_OPENPGPKEY_NAME}, // 61
                                         {TYPE_CSYNC, TYPE_CSYNC_NAME},           // 62

                                         {TYPE_SPF, TYPE_SPF_NAME},     // 99
                                         {TYPE_UINFO, TYPE_UINFO_NAME}, // 100

                                         {TYPE_UID, TYPE_UID_NAME},       // 101
                                         {TYPE_GID, TYPE_GID_NAME},       // 102
                                         {TYPE_UNSPEC, TYPE_UNSPEC_NAME}, // 103

                                         {TYPE_NID, TYPE_NID_NAME},     // 104
                                         {TYPE_L32, TYPE_L32_NAME},     // 105
                                         {TYPE_L64, TYPE_L64_NAME},     // 106
                                         {TYPE_LP, TYPE_LP_NAME},       // 107
                                         {TYPE_EUI48, TYPE_EUI48_NAME}, // 108
                                         {TYPE_EUI64, TYPE_EUI64_NAME}, // 109

                                         {TYPE_TKEY, TYPE_TKEY_NAME},   // 249
                                         {TYPE_TSIG, TYPE_TSIG_NAME},   // 250
                                         {TYPE_IXFR, TYPE_IXFR_NAME},   // 251
                                         {TYPE_AXFR, TYPE_AXFR_NAME},   // 252
                                         {TYPE_MAILB, TYPE_MAILB_NAME}, // 253
                                         {TYPE_MAILA, TYPE_MAILA_NAME}, // 254
                                         {TYPE_ANY, TYPE_ANY_NAME},     // 255
                                         {TYPE_URI, TYPE_URI_NAME},     // 256
                                         {TYPE_CAA, TYPE_CAA_NAME},     // 257
                                         {TYPE_AVC, TYPE_AVC_NAME},     // 258
                                         {TYPE_TA, TYPE_TA_NAME},       // 32768
                                         {TYPE_DLV, TYPE_DLV_NAME},     // 32769

                                         {TYPE_CTRL_SRVCFGRELOAD, TYPE_CTRL_SRVCFGRELOAD_NAME},
                                         {TYPE_CTRL_SRVQUERYLOG, TYPE_CTRL_SRVQUERYLOG_NAME},
                                         {TYPE_CTRL_SRVLOGREOPEN, TYPE_CTRL_SRVLOGREOPEN_NAME},
                                         {TYPE_CTRL_SRVLOGLEVEL, TYPE_CTRL_SRVLOGLEVEL_NAME},
                                         {TYPE_CTRL_SRVSHUTDOWN, TYPE_CTRL_SHUTDOWN_NAME},
                                         {TYPE_CTRL_ZONECFGRELOAD, TYPE_CTRL_ZONECFGRELOAD_NAME},
                                         {TYPE_CTRL_ZONECFGRELOADALL, TYPE_CTRL_ZONECFGRELOADALL_NAME},
                                         {TYPE_CTRL_ZONEFREEZE, TYPE_CTRL_ZONEFREEZE_NAME},
                                         {TYPE_CTRL_ZONEFREEZEALL, TYPE_CTRL_ZONEFREEZEALL_NAME},
                                         {TYPE_CTRL_ZONERELOAD, TYPE_CTRL_ZONERELOAD_NAME},
                                         {TYPE_CTRL_ZONEUNFREEZE, TYPE_CTRL_ZONEUNFREEZE_NAME},
                                         {TYPE_CTRL_ZONEUNFREEZEALL, TYPE_CTRL_ZONEUNFREEZEALL_NAME},
                                         {TYPE_CTRL_ZONESYNC, TYPE_CTRL_ZONESYNC_NAME},
                                         {TYPE_CTRL_ZONENOTIFY, TYPE_CTRL_ZONENOTIFY_NAME},
                                         {0, NULL}};

const dnssec_algo_table_t     dnssec_algo[] = {
    /// @note 20160512 gve -- 3 algorithms are not used ( deprecated or not implemented )
    //  { DNSKEY_ALGORITHM_RSAMD5, DNSKEY_ALGORITHM_RSAMD5_NAME                   },     //  1
    //  { DNSKEY_ALGORITHM_DIFFIE_HELLMAN, DNSKEY_ALGORITHM_DIFFIE_HELLMAN_NAME   },     //  2
    {DNSKEY_ALGORITHM_DSASHA1, DNSKEY_ALGORITHM_DSASHA1_NAME},                 //  3
    {DNSKEY_ALGORITHM_RSASHA1, DNSKEY_ALGORITHM_RSASHA1_NAME},                 //  5
    {DNSKEY_ALGORITHM_DSASHA1_NSEC3, DNSKEY_ALGORITHM_DSASHA1_NSEC3_NAME},     //  6
    {DNSKEY_ALGORITHM_RSASHA1_NSEC3, DNSKEY_ALGORITHM_RSASHA1_NSEC3_NAME},     //  7
    {DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_ALGORITHM_RSASHA256_NSEC3_NAME}, //  8
    {DNSKEY_ALGORITHM_RSASHA512_NSEC3, DNSKEY_ALGORITHM_RSASHA512_NSEC3_NAME}, // 10
    //  { DNSKEY_ALGORITHM_GOST,            DNSKEY_ALGORITHM_GOST_NAME            },     // 12
    {DNSKEY_ALGORITHM_ECDSAP256SHA256, DNSKEY_ALGORITHM_ECDSAP256SHA256_NAME}, // 13
    {DNSKEY_ALGORITHM_ECDSAP384SHA384, DNSKEY_ALGORITHM_ECDSAP384SHA384_NAME}, // 14
    {DNSKEY_ALGORITHM_ED25519, DNSKEY_ALGORITHM_ED25519_NAME},                 // 15
    {DNSKEY_ALGORITHM_ED448, DNSKEY_ALGORITHM_ED448_NAME},                     // 16
#if DNSCORE_HAS_OQS_SUPPORT
    {DNSKEY_ALGORITHM_DILITHIUM2, DNSKEY_ALGORITHM_DILITHIUM2_NAME},                       // 24
    {DNSKEY_ALGORITHM_DILITHIUM3, DNSKEY_ALGORITHM_DILITHIUM3_NAME},                       // 25
    {DNSKEY_ALGORITHM_DILITHIUM5, DNSKEY_ALGORITHM_DILITHIUM5_NAME},                       // 26
    {DNSKEY_ALGORITHM_FALCON512, DNSKEY_ALGORITHM_FALCON512_NAME},                         // 27
    {DNSKEY_ALGORITHM_FALCON1024, DNSKEY_ALGORITHM_FALCON1024_NAME},                       // 28
    {DNSKEY_ALGORITHM_FALCONPAD512, DNSKEY_ALGORITHM_FALCONPAD512_NAME},                   // 29
    {DNSKEY_ALGORITHM_FALCONPAD1024, DNSKEY_ALGORITHM_FALCONPAD1024_NAME},                 // 30
    {DNSKEY_ALGORITHM_SPHINCSSHA2128F, DNSKEY_ALGORITHM_SPHINCSSHA2128F_NAME},             // 31
    {DNSKEY_ALGORITHM_SPHINCSSHA2128S, DNSKEY_ALGORITHM_SPHINCSSHA2128S_NAME},             // 32
    {DNSKEY_ALGORITHM_SPHINCSSHA2192F, DNSKEY_ALGORITHM_SPHINCSSHA2192F_NAME},             // 33
    {DNSKEY_ALGORITHM_SPHINCSSHA2192S, DNSKEY_ALGORITHM_SPHINCSSHA2192S_NAME},             // 34
    {DNSKEY_ALGORITHM_SPHINCSSHA2256F, DNSKEY_ALGORITHM_SPHINCSSHA2256F_NAME},             // 35
    {DNSKEY_ALGORITHM_SPHINCSSHA2256S, DNSKEY_ALGORITHM_SPHINCSSHA2256S_NAME},             // 36
    {DNSKEY_ALGORITHM_SPHINCSSHAKE128F, DNSKEY_ALGORITHM_SPHINCSSHAKE128F_NAME},           // 37
    {DNSKEY_ALGORITHM_SPHINCSSHAKE128S, DNSKEY_ALGORITHM_SPHINCSSHAKE128S_NAME},           // 38
    {DNSKEY_ALGORITHM_SPHINCSSHAKE192F, DNSKEY_ALGORITHM_SPHINCSSHAKE192F_NAME},           // 39
    {DNSKEY_ALGORITHM_SPHINCSSHAKE192S, DNSKEY_ALGORITHM_SPHINCSSHAKE192S_NAME},           // 40
    {DNSKEY_ALGORITHM_SPHINCSSHAKE256F, DNSKEY_ALGORITHM_SPHINCSSHAKE256F_NAME},           // 41
    {DNSKEY_ALGORITHM_SPHINCSSHAKE256S, DNSKEY_ALGORITHM_SPHINCSSHAKE256S_NAME},           // 42
    {DNSKEY_ALGORITHM_MAYO1, DNSKEY_ALGORITHM_MAYO1_NAME},                                 // 43
    {DNSKEY_ALGORITHM_MAYO2, DNSKEY_ALGORITHM_MAYO2_NAME},                                 // 44
    {DNSKEY_ALGORITHM_MAYO3, DNSKEY_ALGORITHM_MAYO3_NAME},                                 // 45
    {DNSKEY_ALGORITHM_MAYO5, DNSKEY_ALGORITHM_MAYO5_NAME},                                 // 46
    {DNSKEY_ALGORITHM_CROSS_RSDP128BALANCED, DNSKEY_ALGORITHM_CROSS_RSDP128BALANCED_NAME}, // 47
    {DNSKEY_ALGORITHM_CROSS_RSDP128FAST, DNSKEY_ALGORITHM_CROSS_RSDP128FAST_NAME},         // 48
    {DNSKEY_ALGORITHM_CROSS_RSDP128SMALL, DNSKEY_ALGORITHM_CROSS_RSDP128SMALL_NAME},       // 49
    {DNSKEY_ALGORITHM_CROSS_RSDP192BALANCED, DNSKEY_ALGORITHM_CROSS_RSDP192BALANCED_NAME}, // 50
    {DNSKEY_ALGORITHM_CROSS_RSDP192FAST, DNSKEY_ALGORITHM_CROSS_RSDP192FAST_NAME},         // 51
    {DNSKEY_ALGORITHM_CROSS_RSDP192SMALL, DNSKEY_ALGORITHM_CROSS_RSDP192SMALL_NAME},       // 52
    {DNSKEY_ALGORITHM_CROSS_RSDP256BALANCED, DNSKEY_ALGORITHM_CROSS_RSDP256BALANCED_NAME}, // 53
    //{ DNSKEY_ALGORITHM_CROSS_RSDP256FAST, DNSKEY_ALGORITHM_CROSS_RSDP256FAST_NAME}, // 54
    {DNSKEY_ALGORITHM_CROSS_RSDP256SMALL, DNSKEY_ALGORITHM_CROSS_RSDP256SMALL_NAME},         // 55
    {DNSKEY_ALGORITHM_CROSS_RSDPG128BALANCED, DNSKEY_ALGORITHM_CROSS_RSDPG128BALANCED_NAME}, // 56
    {DNSKEY_ALGORITHM_CROSS_RSDPG128FAST, DNSKEY_ALGORITHM_CROSS_RSDPG128FAST_NAME},         // 57
    {DNSKEY_ALGORITHM_CROSS_RSDPG128SMALL, DNSKEY_ALGORITHM_CROSS_RSDPG128SMALL_NAME},       // 58
    {DNSKEY_ALGORITHM_CROSS_RSDPG192BALANCED, DNSKEY_ALGORITHM_CROSS_RSDPG192BALANCED_NAME}, // 59
    {DNSKEY_ALGORITHM_CROSS_RSDPG192FAST, DNSKEY_ALGORITHM_CROSS_RSDPG192FAST_NAME},         // 60
    {DNSKEY_ALGORITHM_CROSS_RSDPG192SMALL, DNSKEY_ALGORITHM_CROSS_RSDPG192SMALL_NAME},       // 61
    {DNSKEY_ALGORITHM_CROSS_RSDPG256BALANCED, DNSKEY_ALGORITHM_CROSS_RSDPG256BALANCED_NAME}, // 62
    {DNSKEY_ALGORITHM_CROSS_RSDPG256FAST, DNSKEY_ALGORITHM_CROSS_RSDPG256FAST_NAME},         // 63
    {DNSKEY_ALGORITHM_CROSS_RSDPG256SMALL, DNSKEY_ALGORITHM_CROSS_RSDPG256SMALL_NAME},       // 64
#endif
#ifdef DNSKEY_ALGORITHM_DUMMY
    {DNSKEY_ALGORITHM_DUMMY, DNSKEY_ALGORITHM_DUMMY_NAME}, // 122
#endif
    {DNSKEY_ALGORITHM_PRIVATEOID, DNSKEY_ALGORITHM_PRIVATEOID_NAME}, // 254
    {0, NULL}};

static char *opcode[16] = {"QUERY",  // 0
                           "IQUERY", // 1 obsolete
                           "STATUS",
                           "OPCODE3",
                           "NOTIFY",
                           "UPDATE",
                           "OPCODE6",
                           "OPCODE7",

                           "OPCODE8", // 8
                           "CTRL",    /* special for yadifa client for view the result in verbose mode */
                           "OPCODE10",
                           "OPCODE11",
                           "OPCODE12",
                           "OPCODE13",
                           "OPCODE14",
                           "OPCODE15"};

static char *rcode[32] = {"NOERROR",  //   0       /* No error                           rfc 1035 */
                          "FORMERR",  //   1       /* Format error                       rfc 1035 */
                          "SERVFAIL", //   2       /* Server failure                     rfc 1035 */
                          "NXDOMAIN", //   3       /* Name error                         rfc 1035 */
                          "NOTIMP",   //   4       /* Not implemented                    rfc 1035 */
                          "REFUSED",  //   5       /* Refused                            rfc 1035 */

                          "YXDOMAIN", //   6       /* Name exists when it should not     rfc 2136 */
                          "YXRRSET",  //   7       /* RR Set exists when it should not   rfc 2136 */
                          "NXRRSET",  //   8       /* RR set that should exist doesn't   rfc 2136 */
                          "NOTAUTH",  //   9       /* Server not Authortative for zone   rfc 2136 */
                                      //   9       /* Not Authorized                     rfc 2845 */
                          "NOTZONE",  //   10      /* Name not contained in zone         rfc 2136 */

                          "RCODE11",
                          "RCODE12",
                          "RCODE13",
                          "RCODE14",
                          "RCODE15",

                          "BADVERS", // or BADSIG   //   16      /* Bad OPT Version         rfc 2671 / rfc 6891 */

                          "BADKEY",
                          "BADTIME",
                          "BADMODE",

                          "BADNAME",
                          "BADALG",
                          "BADTRUNC",

                          "RCODE23",

                          "RCODE24",
                          "RCODE25",
                          "RCODE26",
                          "RCODE27",

                          "RCODE28",
                          "RCODE29",
                          "RCODE30",
                          "RCODE31"};

static char *rfc_word_get(const char *w)
{
    string_treemap_node_t *node = string_treemap_insert(&word_set, w); // assumes new value set to 0
    if(node->value == 0)
    {
        node->key = strdup(w);
    }

    if(node->value < 0xffff)
    {
        ++node->value;
    }

    return (char *)node->key;
}

static void rfc_word_destroy_cb(string_treemap_node_t *node)
{
    free((char *)node->key);
    node->key = NULL;
}

static void rfc_word_destroy() { string_treemap_callback_and_finalise(&word_set, rfc_word_destroy_cb); }

const char *dns_message_opcode_get_name(uint16_t o) { return opcode[o & 0x0f]; }
const char *dns_message_rcode_get_name(uint16_t r) { return rcode[r & 0x1f]; }
const char *dns_class_get_name(uint16_t c)
{
    switch(c)
    {
        case CLASS_IN:
            return CLASS_IN_NAME;
        case CLASS_CH:
            return CLASS_CH_NAME;
        case CLASS_HS:
            return CLASS_HS_NAME;
        case CLASS_CTRL:
            return CLASS_CTRL_NAME;
        case CLASS_NONE:
            return CLASS_NONE_NAME;
        case CLASS_ANY:
            return CLASS_ANY_NAME;
        default:
            return NULL;
    }
}

const char *dns_type_get_name(uint16_t t)
{
    switch(t)
    {
        case TYPE_A:
            return TYPE_A_NAME;
        case TYPE_NS:
            return TYPE_NS_NAME;
        case TYPE_MD:
            return TYPE_MD_NAME;
        case TYPE_MF:
            return TYPE_MF_NAME;
        case TYPE_CNAME:
            return TYPE_CNAME_NAME;
        case TYPE_SOA:
            return TYPE_SOA_NAME;
        case TYPE_MB:
            return TYPE_MB_NAME;
        case TYPE_MG:
            return TYPE_MG_NAME;
        case TYPE_MR:
            return TYPE_MR_NAME;
        case TYPE_NULL:
            return TYPE_NULL_NAME;
        case TYPE_WKS:
            return TYPE_WKS_NAME;
        case TYPE_PTR:
            return TYPE_PTR_NAME;
        case TYPE_HINFO:
            return TYPE_HINFO_NAME;
        case TYPE_MINFO:
            return TYPE_MINFO_NAME;
        case TYPE_MX:
            return TYPE_MX_NAME;
        case TYPE_TXT:
            return TYPE_TXT_NAME;
        case TYPE_RP:
            return TYPE_RP_NAME;
        case TYPE_AFSDB:
            return TYPE_AFSDB_NAME;
        case TYPE_X25:
            return TYPE_X25_NAME;
        case TYPE_ISDN:
            return TYPE_ISDN_NAME;
        case TYPE_RT:
            return TYPE_RT_NAME;
        case TYPE_NSAP:
            return TYPE_NSAP_NAME;
        case TYPE_NSAP_PTR:
            return TYPE_NSAP_PTR_NAME;
        case TYPE_SIG:
            return TYPE_SIG_NAME;
        case TYPE_KEY:
            return TYPE_KEY_NAME;
        case TYPE_PX:
            return TYPE_PX_NAME;
        case TYPE_GPOS:
            return TYPE_GPOS_NAME;
        case TYPE_AAAA:
            return TYPE_AAAA_NAME;
        case TYPE_LOC:
            return TYPE_LOC_NAME;
        case TYPE_NXT:
            return TYPE_NXT_NAME;
        case TYPE_EID:
            return TYPE_EID_NAME;
        case TYPE_NIMLOC:
            return TYPE_NIMLOC_NAME;
        case TYPE_SRV:
            return TYPE_SRV_NAME;
        case TYPE_ATMA:
            return TYPE_ATMA_NAME;
        case TYPE_NAPTR:
            return TYPE_NAPTR_NAME;
        case TYPE_KX:
            return TYPE_KX_NAME;
        case TYPE_CERT:
            return TYPE_CERT_NAME;
        case TYPE_A6:
            return TYPE_A6_NAME;
        case TYPE_DNAME:
            return TYPE_DNAME_NAME;
        case TYPE_SINK:
            return TYPE_SINK_NAME;
        case TYPE_OPT:
            return TYPE_OPT_NAME;
        case TYPE_APL:
            return TYPE_APL_NAME;
        case TYPE_DS:
            return TYPE_DS_NAME;
        case TYPE_SSHFP:
            return TYPE_SSHFP_NAME;
        case TYPE_IPSECKEY:
            return TYPE_IPSECKEY_NAME;
        case TYPE_RRSIG:
            return TYPE_RRSIG_NAME;
        case TYPE_NSEC:
            return TYPE_NSEC_NAME;
        case TYPE_DNSKEY:
            return TYPE_DNSKEY_NAME;
        case TYPE_DHCID:
            return TYPE_DHCID_NAME;
        case TYPE_NSEC3:
            return TYPE_NSEC3_NAME;
        case TYPE_NSEC3PARAM:
            return TYPE_NSEC3PARAM_NAME;
        case TYPE_TLSA:
            return TYPE_TLSA_NAME;
        case TYPE_HIP:
            return TYPE_HIP_NAME;
        case TYPE_NINFO:
            return TYPE_NINFO_NAME;
        case TYPE_RKEY:
            return TYPE_RKEY_NAME;
        case TYPE_TALINK:
            return TYPE_TALINK_NAME;
        case TYPE_CDS:
            return TYPE_CDS_NAME;
        case TYPE_CDNSKEY:
            return TYPE_CDNSKEY_NAME;
        case TYPE_OPENPGPKEY:
            return TYPE_OPENPGPKEY_NAME;

        case TYPE_SPF:
            return TYPE_SPF_NAME;
        case TYPE_UINFO:
            return TYPE_UINFO_NAME;

        case TYPE_NID:
            return TYPE_NID_NAME;
        case TYPE_L32:
            return TYPE_L32_NAME;
        case TYPE_L64:
            return TYPE_L64_NAME;
        case TYPE_LP:
            return TYPE_LP_NAME;
        case TYPE_EUI48:
            return TYPE_EUI48_NAME;
        case TYPE_EUI64:
            return TYPE_EUI64_NAME;
        case TYPE_TKEY:
            return TYPE_TKEY_NAME;
        case TYPE_TSIG:
            return TYPE_TSIG_NAME;
        case TYPE_IXFR:
            return TYPE_IXFR_NAME;
        case TYPE_AXFR:
            return TYPE_AXFR_NAME;
        case TYPE_MAILB:
            return TYPE_MAILB_NAME;
        case TYPE_MAILA:
            return TYPE_MAILA_NAME;
        case TYPE_ANY:
            return TYPE_ANY_NAME;
        case TYPE_URI:
            return TYPE_URI_NAME;
        case TYPE_CAA:
            return TYPE_CAA_NAME;
        case TYPE_TA:
            return TYPE_TA_NAME;
        case TYPE_DLV:
            return TYPE_DLV_NAME;
        case TYPE_UID:
            return TYPE_UID_NAME;
        case TYPE_GID:
            return TYPE_GID_NAME;
        case TYPE_UNSPEC:
            return TYPE_UNSPEC_NAME;
        case TYPE_AVC:
            return TYPE_AVC_NAME;

#if DNSCORE_HAS_CTRL
        case TYPE_CTRL_SRVSHUTDOWN:
            return TYPE_CTRL_SHUTDOWN_NAME;
        case TYPE_CTRL_ZONEFREEZE:
            return TYPE_CTRL_ZONEFREEZE_NAME;
        case TYPE_CTRL_ZONEFREEZEALL:
            return TYPE_CTRL_ZONEFREEZEALL_NAME;
        case TYPE_CTRL_ZONEUNFREEZE:
            return TYPE_CTRL_ZONEUNFREEZE_NAME;
        case TYPE_CTRL_ZONEUNFREEZEALL:
            return TYPE_CTRL_ZONEUNFREEZEALL_NAME;
        case TYPE_CTRL_ZONERELOAD:
            return TYPE_CTRL_ZONERELOAD_NAME;
        case TYPE_CTRL_SRVLOGREOPEN:
            return TYPE_CTRL_LOGREOPEN_NAME;
        case TYPE_CTRL_SRVCFGRELOAD:
            return TYPE_CTRL_SRVCFGRELOAD_NAME;
        case TYPE_CTRL_ZONECFGRELOADALL:
            return TYPE_CTRL_ZONECFGRELOADALL_NAME;
        case TYPE_CTRL_ZONECFGRELOAD:
            return TYPE_CTRL_ZONECFGRELOAD_NAME;
        case TYPE_CTRL_ZONESYNC:
            return TYPE_CTRL_ZONESYNC_NAME;
        case TYPE_CTRL_SRVQUERYLOG:
            return TYPE_CTRL_SRVQUERYLOG_NAME;
        case TYPE_CTRL_SRVLOGLEVEL:
            return TYPE_CTRL_SRVLOGLEVEL_NAME;
        case TYPE_CTRL_ZONENOTIFY:
            return TYPE_CTRL_ZONENOTIFY_NAME;
            // case TYPE_CTRL_%:
            //     return TYPE_CTRL_SCFGMERGE_NAME;
            // case TYPE_CTRL_CFGSAVE:
            //     return TYPE_CTRL_CFGSAVE_NAME;
            // case TYPE_CTRL_CFGLOAD:
            //     return TYPE_CTRL_CFGLOAD_NAME;
#endif
        default:
            return NULL;
    }
}

const char *dns_encryption_algorithm_get_name(uint16_t d)
{
    switch(d)
    {
        case DNSKEY_ALGORITHM_RSAMD5:
            return DNSKEY_ALGORITHM_RSAMD5_NAME;
        case DNSKEY_ALGORITHM_DIFFIE_HELLMAN:
            return DNSKEY_ALGORITHM_DIFFIE_HELLMAN_NAME;
        case DNSKEY_ALGORITHM_DSASHA1:
            return DNSKEY_ALGORITHM_DSASHA1_NAME;
        case DNSKEY_ALGORITHM_RSASHA1:
            return DNSKEY_ALGORITHM_RSASHA1_NAME;
        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
            return DNSKEY_ALGORITHM_DSASHA1_NSEC3_NAME;
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
            return DNSKEY_ALGORITHM_RSASHA1_NSEC3_NAME;
        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
            return DNSKEY_ALGORITHM_RSASHA256_NSEC3_NAME;
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            return DNSKEY_ALGORITHM_RSASHA512_NSEC3_NAME;
        case DNSKEY_ALGORITHM_GOST:
            return DNSKEY_ALGORITHM_GOST_NAME;
        case DNSKEY_ALGORITHM_ECDSAP256SHA256:
            return DNSKEY_ALGORITHM_ECDSAP256SHA256_NAME;
        case DNSKEY_ALGORITHM_ECDSAP384SHA384:
            return DNSKEY_ALGORITHM_ECDSAP384SHA384_NAME;
        case DNSKEY_ALGORITHM_ED25519:
            return DNSKEY_ALGORITHM_ED25519_NAME;
        case DNSKEY_ALGORITHM_ED448:
            return DNSKEY_ALGORITHM_ED448_NAME;
#if DNSCORE_HAS_OQS_SUPPORT
        case DNSKEY_ALGORITHM_DILITHIUM2:
            return DNSKEY_ALGORITHM_DILITHIUM2_NAME;
        case DNSKEY_ALGORITHM_DILITHIUM3:
            return DNSKEY_ALGORITHM_DILITHIUM3_NAME;
        case DNSKEY_ALGORITHM_DILITHIUM5:
            return DNSKEY_ALGORITHM_DILITHIUM5_NAME;
        case DNSKEY_ALGORITHM_FALCON512:
            return DNSKEY_ALGORITHM_FALCON512_NAME;
        case DNSKEY_ALGORITHM_FALCON1024:
            return DNSKEY_ALGORITHM_FALCON1024_NAME;
        case DNSKEY_ALGORITHM_FALCONPAD512:
            return DNSKEY_ALGORITHM_FALCONPAD512_NAME;
        case DNSKEY_ALGORITHM_FALCONPAD1024:
            return DNSKEY_ALGORITHM_FALCONPAD1024_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHA2128F:
            return DNSKEY_ALGORITHM_SPHINCSSHA2128F_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHA2128S:
            return DNSKEY_ALGORITHM_SPHINCSSHA2128S_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHA2192F:
            return DNSKEY_ALGORITHM_SPHINCSSHA2192F_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHA2192S:
            return DNSKEY_ALGORITHM_SPHINCSSHA2192S_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHA2256F:
            return DNSKEY_ALGORITHM_SPHINCSSHA2256F_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHA2256S:
            return DNSKEY_ALGORITHM_SPHINCSSHA2256S_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHAKE128F:
            return DNSKEY_ALGORITHM_SPHINCSSHAKE128F_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHAKE128S:
            return DNSKEY_ALGORITHM_SPHINCSSHAKE128S_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHAKE192F:
            return DNSKEY_ALGORITHM_SPHINCSSHAKE192F_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHAKE192S:
            return DNSKEY_ALGORITHM_SPHINCSSHAKE192S_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHAKE256F:
            return DNSKEY_ALGORITHM_SPHINCSSHAKE256F_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHAKE256S:
            return DNSKEY_ALGORITHM_SPHINCSSHAKE256S_NAME;
        case DNSKEY_ALGORITHM_MAYO1:
            return DNSKEY_ALGORITHM_MAYO1_NAME;
        case DNSKEY_ALGORITHM_MAYO2:
            return DNSKEY_ALGORITHM_MAYO2_NAME;
        case DNSKEY_ALGORITHM_MAYO3:
            return DNSKEY_ALGORITHM_MAYO3_NAME;
        case DNSKEY_ALGORITHM_MAYO5:
            return DNSKEY_ALGORITHM_MAYO5_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP128BALANCED:
            return DNSKEY_ALGORITHM_CROSS_RSDP128BALANCED_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP128FAST:
            return DNSKEY_ALGORITHM_CROSS_RSDP128FAST_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP128SMALL:
            return DNSKEY_ALGORITHM_CROSS_RSDP128SMALL_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP192BALANCED:
            return DNSKEY_ALGORITHM_CROSS_RSDP192BALANCED_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP192FAST:
            return DNSKEY_ALGORITHM_CROSS_RSDP192FAST_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP192SMALL:
            return DNSKEY_ALGORITHM_CROSS_RSDP192SMALL_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP256BALANCED:
            return DNSKEY_ALGORITHM_CROSS_RSDP256BALANCED_NAME;
        /*case DNSKEY_ALGORITHM_CROSS_RSDP256FAST:
            return DNSKEY_ALGORITHM_CROSS_RSDP256FAST_NAME;*/
        case DNSKEY_ALGORITHM_CROSS_RSDP256SMALL:
            return DNSKEY_ALGORITHM_CROSS_RSDP256SMALL_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG128BALANCED:
            return DNSKEY_ALGORITHM_CROSS_RSDPG128BALANCED_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG128FAST:
            return DNSKEY_ALGORITHM_CROSS_RSDPG128FAST_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG128SMALL:
            return DNSKEY_ALGORITHM_CROSS_RSDPG128SMALL_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG192BALANCED:
            return DNSKEY_ALGORITHM_CROSS_RSDPG192BALANCED_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG192FAST:
            return DNSKEY_ALGORITHM_CROSS_RSDPG192FAST_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG192SMALL:
            return DNSKEY_ALGORITHM_CROSS_RSDPG192SMALL_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG256BALANCED:
            return DNSKEY_ALGORITHM_CROSS_RSDPG256BALANCED_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG256FAST:
            return DNSKEY_ALGORITHM_CROSS_RSDPG256FAST_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG256SMALL:
            return DNSKEY_ALGORITHM_CROSS_RSDPG256SMALL_NAME;
#endif
#ifdef DNSKEY_ALGORITHM_DUMMY
        case DNSKEY_ALGORITHM_DUMMY:
            return DNSKEY_ALGORITHM_DUMMY_NAME;
#endif
        case DNSKEY_ALGORITHM_PRIVATEOID:
            return DNSKEY_ALGORITHM_PRIVATEOID_NAME;
        default:
            return NULL;
    }
}

/** \brief Check in search table of class for the value
 *
 *  @param[in]  src data to be found in table
 *  @param[out] dst value found in table
 *
 *  @retval OK
 *  @retval NOK
 */
int dns_class_from_name(const char *src, uint16_t *dst)
{
    const string_treemap_node_t *node = string_treemap_find(&class_set, (const char *)src);

    if(node != NULL)
    {
        uint16_t c = node->value;
        *dst = c;

        return c;
    }
    else
    {
        /** @note supports CLASS# syntax (rfc 3597) */

        if(strncasecmp(src, "CLASS", 5) == 0)
        {
            char         *endptr;
            long long int val;

            src += 5;

            val = strtoll(src, &endptr, 10);

            int err = errno;

            if(!((endptr == src) || (err == EINVAL) || (err == ERANGE) || ((val & 0xffffLL) != val)))
            {
                uint16_t c = htons((uint16_t)val);
                *dst = c;

                return c;
            }
        }

        return UNKNOWN_DNS_CLASS;
    }
}

/** \brief Check in global table qtype for the value
 *
 *  @param[in]  src data to be found in table
 *  @param[oet] dst value found in table
 *
 *  @retval OK
 *  @retval NOK
 */
int dns_type_from_name(const char *src, uint16_t *dst)
{
    string_treemap_node_t *node = string_treemap_find(&type_set, (const char *)src);

    if(node != NULL)
    {
        uint16_t t = node->value;
        *dst = t;
        return 0;
    }
    else
    {
        /** @note supports TYPE# syntax (rfc 3597) */

        if(strncasecmp(src, "TYPE", 4) == 0)
        {
            char         *endptr;
            long long int val;

            src += 4;

            errno = 0;

            val = strtoll(src, &endptr, 10);

            int err = errno;

            if(!((endptr == src) || (err == EINVAL) || (err == ERANGE) || ((val & 0xffffLL) != val)))
            {
                uint16_t t = htons((uint16_t)val);
                *dst = t;
                return 1;
            }
        }

        return UNKNOWN_DNS_TYPE;
    }
}

/** \brief Check in search table of class for the value
 *
 *  @param[in]  src data to be found in table
 *  @param[out] dst value found in table
 *
 *  @retval OK
 *  @retval NOK
 */
int dns_encryption_algorithm_from_name(const char *src, uint8_t *dst)
{
    const string_treemap_node_t *node = string_treemap_find(&dnssec_algo_set, (const char *)src);

    if(node != NULL)
    {
        uint8_t c = node->value;
        *dst = c;

        return c;
    }

    return DNSSEC_ALGORITHM_UNKOWN;
}

int dns_class_from_case_name(const char *src, uint16_t *dst)
{
    char   txt[16];
    size_t n = strlen(src);
    if(n >= sizeof(txt))
    {
        return UNKNOWN_DNS_CLASS;
    }

    for(size_t i = 0; i < n; i++)
    {
        txt[i] = toupper(src[i]);
    }

    txt[n] = '\0';

    return dns_class_from_name(txt, dst);
}

int dns_type_from_case_name(const char *src, uint16_t *dst)
{
    char   txt[16];
    size_t n = strlen(src);
    if(n >= sizeof(txt))
    {
        return UNKNOWN_DNS_TYPE;
    }

    for(size_t i = 0; i < n; i++)
    {
        txt[i] = toupper(src[i]);
    }

    txt[n] = '\0';

    ya_result ret = dns_type_from_name(txt, dst);

    return ret;
}

int dns_encryption_algorithm_from_case_name(const char *src, uint8_t *dst)
{
    char   txt[32];
    size_t n = strlen(src);
    if(n >= sizeof(txt))
    {
        return DNSSEC_ALGORITHM_UNKOWN;
    }

    for(size_t i = 0; i < n; i++)
    {
        txt[i] = toupper(src[i]);
    }

    txt[n] = '\0';

    return dns_encryption_algorithm_from_name(txt, dst);
}

int dns_type_from_case_name_length(const char *src, int src_len, uint16_t *dst)
{
    char txt[16];

    if(src_len >= (int)sizeof(txt))
    {
        return UNKNOWN_DNS_TYPE;
    }

    for(int_fast32_t i = 0; i < src_len; i++)
    {
        txt[i] = toupper(src[i]);
    }

    txt[src_len] = '\0';

    ya_result ret = dns_type_from_name(txt, dst);

    return ret;
}

static ptr_treemap_t     dns_cert_type_name_to_id_set = PTR_TREEMAP_ASCIIZCASE_EMPTY;
static u32_treemap_t     dns_cert_type_id_to_name_set = U32_TREEMAP_EMPTY;

const value_name_table_t dns_cert_id_type_name_table[] = {{1, "PKIX"}, {2, "SPKI"}, {3, "PGP"}, {4, "IPKIX"}, {5, "ISPKI"}, {6, "IPGP"}, {7, "ACPKIX"}, {8, "IACPKIX"}, {253, "URI"}, {254, "OID"}, {0, NULL}};

static void              dns_cert_type_value_from_name_init()
{
    for(int i = 0; dns_cert_id_type_name_table[i].data != NULL; ++i)
    {
        {
            ptr_treemap_node_t *node = ptr_treemap_insert(&dns_cert_type_name_to_id_set, dns_cert_id_type_name_table[i].data);
            node->value = (void *)(intptr)dns_cert_id_type_name_table[i].id;
        }
        {
            u32_treemap_node_t *node = u32_treemap_insert(&dns_cert_type_id_to_name_set, dns_cert_id_type_name_table[i].id);
            node->value = dns_cert_id_type_name_table[i].data;
        }
    }
}

static void dns_cert_type_value_from_name_finalise()
{
    ptr_treemap_finalise(&dns_cert_type_name_to_id_set);
    u32_treemap_finalise(&dns_cert_type_id_to_name_set);
}

/**
 * For CERT type parsing
 * Obtain the type from the mnemonic
 *
 * @param name the mnemonic
 * @param type_value a pointer that will receive the mnemonic value
 *
 * @return the mnemonic value or an error code
 */

int dns_cert_type_value_from_name(const char *name, uint16_t *type_value)
{
    ptr_treemap_node_t *node = ptr_treemap_find(&dns_cert_type_name_to_id_set, name);

    if(node != NULL)
    {
        *type_value = (int)(intptr)node->value;
        return *type_value;
    }
    else
    {
        return ERROR;
    }
}

/**
 * For CERT type printing
 * Obtain the mnemonic from the type id
 *
 * @param id the type id
 *
 * @return the mnemonic or NULL
 */

const char *dns_cert_type_name_from_id(uint16_t id)
{
    u32_treemap_node_t *node = u32_treemap_find(&dns_cert_type_id_to_name_set, id);
    if(node != NULL)
    {
        return (const char *)node->value;
    }
    else
    {
        return NULL;
    }
}

static ptr_treemap_t protocol_name_to_id_set = PTR_TREEMAP_ASCIIZCASE_EMPTY;
static u32_treemap_t protocol_id_to_name_set = U32_TREEMAP_EMPTY;
static ptr_treemap_t server_name_to_port_set = PTR_TREEMAP_ASCIIZCASE_EMPTY;
static u32_treemap_t server_port_to_name_set = U32_TREEMAP_EMPTY;

static void          protocol_name_to_id_init()
{
#if __unix__
    if(ptr_treemap_isempty(&protocol_name_to_id_set))
    {
        for(;;)
        {
            struct protoent *ent;

            if((ent = getprotoent()) == NULL) // this is allocated
            {
                break;
            }

            ptr_treemap_node_t *node = ptr_treemap_insert(&protocol_name_to_id_set, ent->p_name);
            node->key = rfc_word_get(ent->p_name);

            if(node->value != NULL)
            {
                continue;
            }

            node->value = (void *)(intptr_t)ent->p_proto;

            u32_treemap_node_t *id_node = u32_treemap_insert(&protocol_id_to_name_set, ent->p_proto);
            id_node->value = node->key;

            char **a = ent->p_aliases;
            if(a != NULL)
            {
                while(*a != NULL)
                {
                    node = ptr_treemap_insert(&protocol_name_to_id_set, *a);

                    if(node->value == NULL)
                    {
                        node->key = rfc_word_get(*a);
                        node->value = (void *)(intptr_t)ent->p_proto;
                    }
                    ++a;
                }
            }
        }

        endprotoent();
    }
#endif
}

static void protocol_name_to_id_finalize()
{
    ptr_treemap_finalise(&protocol_name_to_id_set);
    u32_treemap_finalise(&protocol_id_to_name_set);
}

ya_result protocol_name_to_id(const char *name, int *out_proto)
{
    ya_result ret = PARSEINT_ERROR;

    if(sscanf(name, "%d", &ret) <= 0)
    {
        ptr_treemap_node_t *node = ptr_treemap_find(&protocol_name_to_id_set, name);

        if(node != NULL)
        {
            ret = (int)(intptr_t)node->value;
        }
    }
    else
    {
        if(ret > 255)
        {
            ret = INVALID_STATE_ERROR;
        }
    }

    if(ISOK(ret) && (out_proto != NULL))
    {
        *out_proto = ret;
    }

    return ret;
}

ya_result protocol_id_to_name(int proto, char *name, size_t name_len)
{
    u32_treemap_node_t *proto_node = u32_treemap_find(&protocol_id_to_name_set, proto);
    if(proto_node != NULL)
    {
        return snformat(name, name_len, "%s", (const char *)proto_node->value);
    }
    else
    {
        return snformat(name, name_len, "%i", proto);
    }
}

static void server_name_to_port_init()
{
#if __unix__
    if(ptr_treemap_isempty(&server_name_to_port_set))
    {
        struct servent *ent;

        for(;;)
        {
            if((ent = getservent()) == NULL)
            {
                break;
            }

            ptr_treemap_node_t *node = ptr_treemap_insert(&server_name_to_port_set, ent->s_name);

            if(node->value != NULL)
            {
                continue;
            }

            node->key = rfc_word_get(ent->s_name);
            uint16_t hport = ntohs(ent->s_port);
            node->value = (void *)(intptr_t)hport;

            u32_treemap_node_t *port_node = u32_treemap_insert(&server_port_to_name_set, hport);
            port_node->value = node->key;

            char **a = ent->s_aliases;
            if(a != NULL)
            {
                while(*a != NULL)
                {
                    node = ptr_treemap_insert(&server_name_to_port_set, *a);
                    if(node->value == NULL)
                    {
                        node->key = rfc_word_get(*a);
                        node->value = (void *)(intptr_t)ntohs(ent->s_port);
                    }

                    ++a;
                }
            }
        }
        endservent();
    }
#endif
}

static void server_name_to_port_finalize()
{
    if(!ptr_treemap_isempty(&server_name_to_port_set))
    {
        ptr_treemap_finalise(&server_name_to_port_set);
        u32_treemap_finalise(&server_port_to_name_set);
    }
}

ya_result server_name_to_port(const char *name, int *out_port)
{
    ya_result ret = PARSEINT_ERROR;

    if(sscanf(name, "%d", &ret) <= 0)
    {
        ptr_treemap_node_t *node = ptr_treemap_find(&server_name_to_port_set, name);

        if(node != NULL)
        {
            ret = (int)(intptr_t)node->value;
        }
    }
    else
    {
        if(ret > 65535)
        {
            ret = INVALID_STATE_ERROR;
        }
    }

    if(ISOK(ret) && (out_port != NULL))
    {
        *out_port = ret;
    }

    return ret;
}

ya_result server_port_to_name(int port, char *name, size_t name_len)
{
    u32_treemap_node_t *port_node = u32_treemap_find(&server_port_to_name_set, port);
    if(port_node != NULL)
    {
        return snformat(name, name_len, "%s", (const char *)port_node->value);
    }
    else
    {
        return snformat(name, name_len, "%i", port);
    }
}

static void rfc_dnssec_algo_init()
{
    int i;

    string_treemap_init(&dnssec_algo_set);

    for(i = 0; dnssec_algo[i].id != 0; i++)
    {
        string_treemap_node_t *node = string_treemap_insert(&dnssec_algo_set, dnssec_algo[i].data);
        node->value = dnssec_algo[i].id;
    }

    // alias
    {
        string_treemap_node_t *node = string_treemap_insert(&dnssec_algo_set, DNSKEY_ALGORITHM_DSASHA1_NSEC3_NAME2);
        node->value = DNSKEY_ALGORITHM_DSASHA1_NSEC3;
    }

    // alias
    {
        string_treemap_node_t *node = string_treemap_insert(&dnssec_algo_set, DNSKEY_ALGORITHM_RSASHA1_NSEC3_NAME2);
        node->value = DNSKEY_ALGORITHM_RSASHA1_NSEC3;
    }
}

static void rfc_dnssec_algo_finalize() { string_treemap_finalise(&dnssec_algo_set); }

void        rfc_init()
{
    if(initialise_state_begin(&rfc_init_state))
    {
        int i;

        string_treemap_init(&class_set);

        for(i = 0; qclass[i].id != 0; i++)
        {
            string_treemap_node_t *node = string_treemap_insert(&class_set, qclass[i].data);
            node->value = qclass[i].id;
        }

        for(i = 0;; ++i)
        {
            uint16_t          rclass;
            const char *const rclass_name;
            if(!dnscore_dns_extension_get_class(i, &rclass, &rclass_name))
            {
                break;
            }
            string_treemap_node_t *node = string_treemap_insert(&class_set, rclass_name);
            node->value = rclass;
        }

        string_treemap_init(&type_set);

        for(i = 0; qtype[i].id != 0; i++)
        {
            string_treemap_node_t *node = string_treemap_insert(&type_set, qtype[i].data);
            node->value = qtype[i].id;
        }

        for(i = 0;; ++i)
        {
            uint16_t          rtype;
            const char *const rtype_name;
            if(!dnscore_dns_extension_get_type(i, &rtype, &rtype_name))
            {
                break;
            }
            string_treemap_node_t *node = string_treemap_insert(&type_set, rtype_name);
            node->value = rtype;
        }

        protocol_name_to_id_init();
        server_name_to_port_init();
        rfc_dnssec_algo_init();
        dns_cert_type_value_from_name_init();

        initialise_state_ready(&rfc_init_state);
    }
}

void rfc_finalize()
{
    if(initialise_state_unready(&rfc_init_state))
    {
        dns_cert_type_value_from_name_finalise();
        rfc_dnssec_algo_finalize();
        server_name_to_port_finalize();
        protocol_name_to_id_finalize();
        string_treemap_finalise(&type_set);
        string_treemap_finalise(&class_set);
        rfc_word_destroy();

        initialise_state_end(&rfc_init_state);
    }
}

ya_result value_name_table_get_value_from_casename(const value_name_table_t *table, const char *name, uint32_t *out_value)
{
    while(table->data != NULL)
    {
        if(strcasecmp(table->data, name) == 0)
        {
            *out_value = table->id;

            return SUCCESS;
        }

        table++;
    }

    return UNKNOWN_NAME;
}

ya_result value_name_table_get_name_from_value(const value_name_table_t *table, uint32_t value, const char **out_name)
{
    while(table->data != NULL)
    {
        if(table->id == value)
        {
            *out_name = table->data;
            return SUCCESS;
        }

        table++;
    }

    return INVALID_ARGUMENT_ERROR;
}

/*
 * SOA
 */

ya_result rr_soa_get_serial(const uint8_t *rdata, uint16_t rdata_size, uint32_t *out_serial)
{
    int32_t        soa_size = rdata_size;
    const uint8_t *soa_start = rdata;
    uint32_t       len = dnsname_len(soa_start);
    soa_size -= len;
    if(soa_size <= 0)
    {
        return INCORRECT_RDATA;
    }

    soa_start += len;
    len = dnsname_len(soa_start);
    soa_size -= len;
    if(soa_size != 5 * 4) /* Only the 5 32 bits (should) remain */
    {
        return INCORRECT_RDATA;
    }

    soa_start += len;
    if(out_serial != NULL)
    {
        *out_serial = ntohl(GET_U32_AT(*soa_start));
    }

    return SUCCESS;
}

ya_result rr_soa_increase_serial(uint8_t *rdata, uint16_t rdata_size, uint32_t increment)
{
    int32_t  soa_size = rdata_size;

    uint8_t *soa_start = rdata;

    uint32_t len = dnsname_len(soa_start);

    soa_size -= len;

    if(soa_size <= 0)
    {
        return INCORRECT_RDATA;
    }

    soa_start += len;

    len = dnsname_len(soa_start);
    soa_size -= len;

    if(soa_size != 5 * 4) /* Only the 5 32 bits (should) remain */
    {
        return INCORRECT_RDATA;
    }

    soa_start += len;

    SET_U32_AT(*soa_start, htonl(ntohl(GET_U32_AT(*soa_start)) + increment));

    return SUCCESS;
}

ya_result rr_soa_set_serial(uint8_t *rdata, uint16_t rdata_size, uint32_t serial)
{
    int32_t  soa_size = rdata_size;

    uint8_t *soa_start = rdata;

    uint32_t len = dnsname_len(soa_start);

    soa_size -= len;

    if(soa_size <= 0)
    {
        return INCORRECT_RDATA;
    }

    soa_start += len;

    len = dnsname_len(soa_start);
    soa_size -= len;

    if(soa_size != 5 * 4) /* Only the 5 32 bits (should) remain */
    {
        return INCORRECT_RDATA;
    }

    soa_start += len;

    SET_U32_AT(*soa_start, htonl(serial));

    return SUCCESS;
}

ya_result rr_soa_get_minimumttl(const uint8_t *rdata, uint16_t rdata_size, int32_t *out_minimum_ttl)
{
    int32_t        soa_size = rdata_size;

    const uint8_t *soa_start = rdata;

    uint32_t       len = dnsname_len(soa_start);

    soa_size -= len;

    if(soa_size <= 0)
    {
        return INCORRECT_RDATA;
    }

    soa_start += len;

    len = dnsname_len(soa_start);
    soa_size -= len;

    if(soa_size != 5 * 4) /* Only the 5 32 bits (should) remain */
    {
        return INCORRECT_RDATA;
    }

    soa_start += len + 16;

    *out_minimum_ttl = ntohl(GET_U32_AT(*soa_start));

    return SUCCESS;
}

/** @} */
