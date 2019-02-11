/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2019, EURid vzw. All rights reserved.
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
/** @defgroup
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/


#include "dnscore/dnscore-config.h"
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "dnscore/rfc.h"
#include "dnscore/ctrl-rfc.h"
#include "dnscore/string_set.h"

#define DNSCORE_RFC_C

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

static string_node* class_set = NULL;
static string_node* type_set = NULL;
static string_node* dnssec_algo_set = NULL;

const class_table qclass[] = {
    { CLASS_IN,   CLASS_IN_NAME   },
    { CLASS_CS,   CLASS_CS_NAME   },
    { CLASS_CH,   CLASS_CH_NAME   },
    { CLASS_HS,   CLASS_HS_NAME   },
    { CLASS_CTRL, CLASS_CTRL_NAME },

    { CLASS_NONE, CLASS_NONE_NAME },
    { CLASS_ANY,  CLASS_ANY_NAME  },
    { 0,          NULL            }
};


const type_table qtype[] = {
    { TYPE_A,          TYPE_A_NAME          }, // 1
    { TYPE_NS,         TYPE_NS_NAME         }, // 2
    { TYPE_MD,         TYPE_MD_NAME         }, // 3
    { TYPE_MF,         TYPE_MF_NAME         }, // 4
    { TYPE_CNAME,      TYPE_CNAME_NAME      }, // 5
    { TYPE_SOA,        TYPE_SOA_NAME        }, // 6
    { TYPE_MB,         TYPE_MB_NAME         }, // 7
    { TYPE_MG,         TYPE_MG_NAME         }, // 8
    { TYPE_MR,         TYPE_MR_NAME         }, // 9
    { TYPE_NULL,       TYPE_NULL_NAME       }, // 10
    { TYPE_WKS,        TYPE_WKS_NAME        }, // 11 
    { TYPE_PTR,        TYPE_PTR_NAME        }, // 12
    { TYPE_HINFO,      TYPE_HINFO_NAME      }, // 13
    { TYPE_MINFO,      TYPE_MINFO_NAME      }, // 14
    { TYPE_MX,         TYPE_MX_NAME         }, // 15
    { TYPE_TXT,        TYPE_TXT_NAME        }, // 16 
    { TYPE_RP,         TYPE_RP_NAME         }, // 17
    { TYPE_AFSDB,      TYPE_AFSDB_NAME      }, // 18
    { TYPE_X25,        TYPE_X25_NAME        }, // 19
    { TYPE_ISDN,       TYPE_ISDN_NAME       }, // 20
    { TYPE_RT,         TYPE_RT_NAME         }, // 21
    { TYPE_NSAP,       TYPE_NSAP_NAME       }, // 22
    { TYPE_NSAP_PTR,   TYPE_NSAP_PTR_NAME   }, // 23
    { TYPE_SIG,        TYPE_SIG_NAME        }, // 24
    { TYPE_KEY,        TYPE_KEY_NAME        }, // 25
    { TYPE_PX,         TYPE_PX_NAME         }, // 26
    { TYPE_GPOS,       TYPE_GPOS_NAME       }, // 27
    { TYPE_AAAA,       TYPE_AAAA_NAME       }, // 28
    { TYPE_LOC,        TYPE_LOC_NAME        }, // 29
    { TYPE_NXT,        TYPE_NXT_NAME        }, // 30
    { TYPE_EID,        TYPE_EID_NAME        }, // 31
    { TYPE_NIMLOC,     TYPE_NIMLOC_NAME     }, // 32
    { TYPE_SRV,        TYPE_SRV_NAME        }, // 33
    { TYPE_ATMA,       TYPE_ATMA_NAME       }, // 34
    { TYPE_NAPTR,      TYPE_NAPTR_NAME      }, // 35
    { TYPE_KX,         TYPE_KX_NAME         }, // 36
    { TYPE_CERT,       TYPE_CERT_NAME       }, // 37
    { TYPE_A6,         TYPE_A6_NAME         }, // 38
    { TYPE_DNAME,      TYPE_DNAME_NAME      }, // 39
    { TYPE_SINK,       TYPE_SINK_NAME       }, // 40
    { TYPE_OPT,        TYPE_OPT_NAME        }, // 41
    { TYPE_APL,        TYPE_APL_NAME        }, // 42
    { TYPE_DS,         TYPE_DS_NAME         }, // 43
    { TYPE_SSHFP,      TYPE_SSHFP_NAME      }, // 44
    { TYPE_IPSECKEY,   TYPE_IPSECKEY_NAME   }, // 45
    { TYPE_RRSIG,      TYPE_RRSIG_NAME      }, // 46
    { TYPE_NSEC,       TYPE_NSEC_NAME       }, // 47
    { TYPE_DNSKEY,     TYPE_DNSKEY_NAME     }, // 48
    { TYPE_DHCID,      TYPE_DHCID_NAME      }, // 49
    { TYPE_NSEC3,      TYPE_NSEC3_NAME      }, // 50
    { TYPE_NSEC3PARAM, TYPE_NSEC3PARAM_NAME }, // 51
    { TYPE_TLSA,       TYPE_TLSA_NAME       }, // 52
    { TYPE_HIP,        TYPE_HIP_NAME        }, // 55
    { TYPE_NINFO,      TYPE_NINFO_NAME      }, // 56
    { TYPE_RKEY,       TYPE_RKEY_NAME       }, // 57
    { TYPE_TALINK,     TYPE_TALINK_NAME     }, // 58
    { TYPE_CDS,        TYPE_CDS_NAME        }, // 59



    { TYPE_SPF,        TYPE_SPF_NAME        }, // 99
    { TYPE_UINFO,      TYPE_UINFO_NAME      }, // 100



    { TYPE_NID,        TYPE_NID_NAME        }, // 104
    { TYPE_L32,        TYPE_L32_NAME        }, // 105
    { TYPE_L64,        TYPE_L64_NAME        }, // 106
    { TYPE_LP,         TYPE_LP_NAME         }, // 107
    { TYPE_EUI48,      TYPE_EUI48_NAME      }, // 108
    { TYPE_EUI64,      TYPE_EUI64_NAME      }, // 109



    { TYPE_TKEY,       TYPE_TKEY_NAME       }, // 249
    { TYPE_TSIG,       TYPE_TSIG_NAME       }, // 250
    { TYPE_IXFR,       TYPE_IXFR_NAME       }, // 251
    { TYPE_AXFR,       TYPE_AXFR_NAME       }, // 252
    { TYPE_MAILB,      TYPE_MAILB_NAME      }, // 253
    { TYPE_MAILA,      TYPE_MAILA_NAME      }, // 254
    { TYPE_ANY,        TYPE_ANY_NAME        }, // 255
    { TYPE_URI,        TYPE_URI_NAME        }, // 256
    { TYPE_CAA,        TYPE_CAA_NAME        }, // 257
    { TYPE_TA,         TYPE_TA_NAME         }, // 32768
    { TYPE_DLV,        TYPE_DLV_NAME        }, // 32769
    
#if HAS_DYNAMIC_PROVISIONING
    { TYPE_ZONE_TYPE,           TYPE_ZONE_TYPE_NAME         },
    { TYPE_ZONE_FILE,           TYPE_ZONE_FILE_NAME         },
    { TYPE_ZONE_NOTIFY,         TYPE_ZONE_NOTIFY_NAME       },
    { TYPE_ZONE_MASTER,         TYPE_ZONE_MASTER_NAME       },
    { TYPE_ZONE_DNSSEC,         TYPE_ZONE_DNSSEC_NAME       },
    { TYPE_ZONE_SLAVES,         TYPE_ZONE_SLAVES_NAME       },
    { TYPE_SIGINTV,             TYPE_SIGINTV_NAME           },
    { TYPE_SIGREGN,             TYPE_SIGREGN_NAME           },
    { TYPE_SIGJITR,             TYPE_SIGJITR_NAME           },
    { TYPE_NTFRC,               TYPE_NTFRC_NAME             },
    { TYPE_NTFRP,               TYPE_NTFRP_NAME             },
    { TYPE_NTFRPI,              TYPE_NTFRPI_NAME            },
    { TYPE_NTFAUTO,             TYPE_NTFAUTO_NAME           },
#endif
    
#if 1//HAS_CTRL
    { TYPE_CTRL_SRVCFGRELOAD,     TYPE_CTRL_SRVCFGRELOAD_NAME     },
    { TYPE_CTRL_SRVQUERYLOG,      TYPE_CTRL_SRVQUERYLOG_NAME      },
    { TYPE_CTRL_SRVLOGREOPEN,     TYPE_CTRL_SRVLOGREOPEN_NAME     },
    { TYPE_CTRL_SRVLOGLEVEL,      TYPE_CTRL_SRVLOGLEVEL_NAME      },
    { TYPE_CTRL_SRVSHUTDOWN,      TYPE_CTRL_SHUTDOWN_NAME         },
    { TYPE_CTRL_ZONECFGRELOAD,    TYPE_CTRL_ZONECFGRELOAD_NAME    },
    { TYPE_CTRL_ZONECFGRELOADALL, TYPE_CTRL_ZONECFGRELOADALL_NAME },
    { TYPE_CTRL_ZONEFREEZE,       TYPE_CTRL_ZONEFREEZE_NAME       },
    { TYPE_CTRL_ZONEFREEZEALL,    TYPE_CTRL_ZONEFREEZEALL_NAME    },
    { TYPE_CTRL_ZONERELOAD,       TYPE_CTRL_ZONERELOAD_NAME       },
    { TYPE_CTRL_ZONEUNFREEZE,     TYPE_CTRL_ZONEUNFREEZE_NAME     },
    { TYPE_CTRL_ZONEUNFREEZEALL,  TYPE_CTRL_ZONEUNFREEZEALL_NAME  },
    { TYPE_CTRL_ZONESYNC,         TYPE_CTRL_ZONESYNC_NAME         },

#endif  
    { 0,               NULL                 }
};


const dnssec_algo_table dnssec_algo[] = {
/// @note 20160512 gve -- 3 algorithms are not used ( deprecated or not implemented )
//  { DNSKEY_ALGORITHM_RSAMD5, DNSKEY_ALGORITHM_RSAMD5_NAME                   },     //  1
//  { DNSKEY_ALGORITHM_DIFFIE_HELLMAN, DNSKEY_ALGORITHM_DIFFIE_HELLMAN_NAME   },     //  2
    { DNSKEY_ALGORITHM_DSASHA1,         DNSKEY_ALGORITHM_DSASHA1_NAME         },     //  3
    { DNSKEY_ALGORITHM_RSASHA1,         DNSKEY_ALGORITHM_RSASHA1_NAME         },     //  5
    { DNSKEY_ALGORITHM_DSASHA1_NSEC3,   DNSKEY_ALGORITHM_DSASHA1_NSEC3_NAME   },     //  6
    { DNSKEY_ALGORITHM_RSASHA1_NSEC3,   DNSKEY_ALGORITHM_RSASHA1_NSEC3_NAME   },     //  7
    { DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_ALGORITHM_RSASHA256_NSEC3_NAME },     //  8
    { DNSKEY_ALGORITHM_RSASHA512_NSEC3, DNSKEY_ALGORITHM_RSASHA512_NSEC3_NAME },     // 10
//  { DNSKEY_ALGORITHM_GOST,            DNSKEY_ALGORITHM_GOST_NAME            },     // 12
    { DNSKEY_ALGORITHM_ECDSAP256SHA256, DNSKEY_ALGORITHM_ECDSAP256SHA256_NAME },     // 13
    { DNSKEY_ALGORITHM_ECDSAP384SHA384, DNSKEY_ALGORITHM_ECDSAP384SHA384_NAME },     // 14
    { 0,                                NULL                                  }
};


static char *opcode[16] =
{
    "QUERY",
    "IQUERY",
    "STATUS",
    "NOTIFY",

    "UPDATE",
    "?",
    "?",
    "?",

    "?",
    "CTRL", /* special for yadifa client for view the result in verbose mode */
    "?",
    "?",

    "?",
    "?",
    "?",
    "?"
};

static char *rcode[32] =
{
    "NOERROR",                //   0       /* No error                           rfc 1035 */
    "FORMERR",                //   1       /* Format error                       rfc 1035 */
    "SERVFAIL",               //   2       /* Server failure                     rfc 1035 */
    "NXDOMAIN",               //   3       /* Name error                         rfc 1035 */
    "NOTIMP",                 //   4       /* Not implemented                    rfc 1035 */
    "REFUSED",                //   5       /* Refused                            rfc 1035 */

    "YXDOMAIN",               //   6       /* Name exists when it should not     rfc 2136 */
    "YXRRSET",                //   7       /* RR Set exists when it should not   rfc 2136 */
    "NXRRSET",                //   8       /* RR set that should exist doesn't   rfc 2136 */
    "NOTAUTH",                //   9       /* Server not Authortative for zone   rfc 2136 */
                              //   9       /* Not Authorized                     rfc 2845 */
    "NOTZONE",                //   10      /* Name not contained in zone         rfc 2136 */

    "?",
    "?",
    "?",
    "?",
    "?",

    "BADVERS",                //   16      /* Bad OPT Version         rfc 2671 / rfc 6891 */

#if 0 /* fix */
#else // THX

    "-",
    "-",
    "-",

    "-",
    "-",
    "-",

#endif // THX
    "-",
    
    "-",
    "-",
    "-",
    "-",
    
    "-",
    "-",
    "-",
    "-"
};

const char*
get_opcode(u16 o)
{
    return opcode[o & 0x0f];
}


const char*
get_rcode(u16 r)
{
    return rcode[r & 0x1f];
}


const char*
get_name_from_class(u16 c)
{
    switch(c)
    {
        case CLASS_IN:
            return CLASS_IN_NAME;
        case CLASS_HS:
            return CLASS_HS_NAME;
        case CLASS_CH:
            return CLASS_CH_NAME;
        case CLASS_CTRL:
            return CLASS_CTRL_NAME;
        case CLASS_ANY:
            return CLASS_ANY_NAME;
        default:
            return NULL;
    }
}


const char*
get_name_from_type(u16 t)
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

        case TYPE_SPF:
            return TYPE_SPF_NAME;
        case TYPE_UINFO:
            return TYPE_UINFO_NAME;


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
            

        default:
            return NULL;
    }
}

const char*
get_name_from_dnssec_algo(u16 d)
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
int
get_class_from_name(const char *src, u16 *dst)
{
    const string_node *node = string_set_avl_find(&class_set, (const char *)src);

    if(node != NULL)
    {
        u16 c = node->value;
        *dst = c;
        
        return c;
    }
    else
    {
        /** @note supports CLASS# syntax (rfc 3597) */

        if(strncasecmp(src, "CLASS", 5) == 0)
        {
            char          *endptr;
            long long int  val;

            src    += 5;

            val     = strtoll(src, &endptr, 10);

            int err = errno;

            if(!((endptr == src) || (err == EINVAL) || (err == ERANGE) || ((val & 0xffffLL) != val)))
            {
                u16 c = htons((u16)val);
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
int
get_type_from_name(const char *src, u16 *dst)
{
    string_node *node = string_set_avl_find(&type_set, (const char *)src);

    if(node != NULL)
    {
        u16 t = node->value;
        *dst = t;
        return 0;
    }
    else
    {
        /** @note supports TYPE# syntax (rfc 3597) */

        if(strncasecmp(src, "TYPE", 4) == 0)
        {
            char          *endptr;
            long long int  val;

            src    += 4;

            errno = 0;
            
            val     = strtoll(src, &endptr, 10);

            int err = errno;

            if(!((endptr == src) || (err == EINVAL) || (err == ERANGE) || ((val & 0xffffLL) != val)))
            {
                u16 t = htons((u16)val);
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
int
get_dnssec_algo_from_name(const char *src, u8 *dst)
{
    const string_node *node = string_set_avl_find(&dnssec_algo_set, (const char *)src);

    if(node != NULL)
    {
        u8 c = node->value;
        *dst = c;

        return c;
    }

    return UNKNOWN_DNSSEC_ALGO;
}


int
get_class_from_case_name(const char *src, u16 *dst)
{
    char txt[16];
    s32 n = strlen(src);
    if(n > sizeof(txt))
    {
        return UNKNOWN_DNS_CLASS;
    }
    
    for(s32 i = 0; i < n; i++)
    {
        txt[i] = toupper(src[i]);
    }
    
    txt[n] = '\0';
    
    return get_class_from_name(txt, dst);
}


int
get_type_from_case_name(const char *src, u16 *dst)
{
    char txt[16];
    s32 n = strlen(src);
    if(n > sizeof(txt))
    {
        return UNKNOWN_DNS_TYPE;
    }
    
    for(s32 i = 0; i < n; i++)
    {
        txt[i] = toupper(src[i]);
    }
    
    txt[n] = '\0';
    
    ya_result ret = get_type_from_name(txt, dst);
    
    return ret;
}


int
get_dnssec_algo_from_case_name(const char *src, u8 *dst)
{
    char txt[16];
    s32 n = strlen(src);
    if(n > sizeof(txt))
    {
        return UNKNOWN_DNSSEC_ALGO;
    }

    for(s32 i = 0; i < n; i++)
    {
        txt[i] = toupper(src[i]);
    }

    txt[n] = '\0';

    return get_dnssec_algo_from_name(txt, dst);
}


int
get_type_from_case_name_len(const char *src, int src_len, u16 *dst)
{
    char txt[16];

    if(src_len > sizeof(txt))
    {
        return UNKNOWN_DNS_TYPE;
    }
    
    for(s32 i = 0; i < src_len; i++)
    {
        txt[i] = toupper(src[i]);
    }
    
    txt[src_len] = '\0';
    
    ya_result ret = get_type_from_name(txt, dst);
    
    return ret;
}


void
rfc_init()
{
    int i;

    string_set_avl_init(&class_set);

    for(i = 0; qclass[i].id != 0; i++)
    {
        string_node* node = string_set_avl_insert(&class_set, qclass[i].data);
        node->value       = qclass[i].id;
    }

    string_set_avl_init(&type_set);

    for(i = 0; qtype[i].id != 0; i++)
    {
        string_node* node = string_set_avl_insert(&type_set, qtype[i].data);
        node->value       = qtype[i].id;
    }
}

void
rfc_finalize()
{
    string_set_avl_destroy(&class_set);
    string_set_avl_destroy(&type_set);
}


void
rfc_dnssec_algo_init()
{
    int i;

    string_set_avl_init(&dnssec_algo_set);

    for(i = 0; dnssec_algo[i].id != 0; i++)
    {
        string_node* node = string_set_avl_insert(&dnssec_algo_set, dnssec_algo[i].data);
        node->value       = dnssec_algo[i].id;
    }
}

void
rfc_dnssec_algo_finalize()
{
    string_set_avl_destroy(&dnssec_algo_set);
}



ya_result
get_value_from_casename(const value_name_table *table, const char *name, u32 *out_value)
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

/** @} */

/*----------------------------------------------------------------------------*/

