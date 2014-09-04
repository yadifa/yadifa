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
/** @defgroup
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/


#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "dnscore-config.h"

#include "dnscore/rfc.h"
#include "dnscore/ctrl-rfc.h"
#include "dnscore/string_set.h"

#define DNSCORE_RFC_C

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

static string_node* class_set = NULL;
static string_node* type_set = NULL;

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
    { TYPE_A,          TYPE_A_NAME          },
    { TYPE_NS,         TYPE_NS_NAME         },
    { TYPE_MD,         TYPE_MD_NAME         },
    { TYPE_MF,         TYPE_MF_NAME         },
    { TYPE_CNAME,      TYPE_CNAME_NAME      },
    { TYPE_SOA,        TYPE_SOA_NAME        },
    { TYPE_MB,         TYPE_MB_NAME         },
    { TYPE_MG,         TYPE_MG_NAME         },
    { TYPE_MR,         TYPE_MR_NAME         },
    { TYPE_NULL,       TYPE_NULL_NAME       },
    { TYPE_WKS,        TYPE_WKS_NAME        },
    { TYPE_PTR,        TYPE_PTR_NAME        },
    { TYPE_HINFO,      TYPE_HINFO_NAME      },
    { TYPE_MINFO,      TYPE_MINFO_NAME      },
    { TYPE_MX,         TYPE_MX_NAME         },
    { TYPE_TXT,        TYPE_TXT_NAME        },
    { TYPE_RP,         TYPE_RP_NAME         },
    { TYPE_ASFDB,      TYPE_ASFDB_NAME      },
    { TYPE_X25,        TYPE_X25_NAME        },
    { TYPE_ISDN,       TYPE_ISDN_NAME       },
    { TYPE_RT,         TYPE_RT_NAME         },
    { TYPE_NSAP,       TYPE_NSAP_NAME       },
    { TYPE_NSAP_PTR,   TYPE_NSAP_PTR_NAME   },
    { TYPE_SIG,        TYPE_SIG_NAME        },
    { TYPE_KEY,        TYPE_KEY_NAME        },
    { TYPE_PX,         TYPE_PX_NAME         },
    { TYPE_GPOS,       TYPE_GPOS_NAME       },
    { TYPE_AAAA,       TYPE_AAAA_NAME       },
    { TYPE_LOC,        TYPE_LOC_NAME        },
    { TYPE_NXT,        TYPE_NXT_NAME        },
    { TYPE_EID,        TYPE_EID_NAME        },
    { TYPE_NIMLOC,     TYPE_NIMLOC_NAME     },
    { TYPE_SRV,        TYPE_SRV_NAME        },
    { TYPE_ATMA,       TYPE_ATMA_NAME       },
    { TYPE_NAPTR,      TYPE_NAPTR_NAME      },
    { TYPE_KX,         TYPE_KX_NAME         },
    { TYPE_CERT,       TYPE_CERT_NAME       },
    { TYPE_A6,         TYPE_A6_NAME         },
    { TYPE_DNAME,      TYPE_DNAME_NAME      },     
    { TYPE_SINK,       TYPE_SINK_NAME       },
    { TYPE_OPT,        TYPE_OPT_NAME        },
    { TYPE_APL,        TYPE_APL_NAME        },
    { TYPE_DS,         TYPE_DS_NAME         },
    { TYPE_SSHFP,      TYPE_SSHFP_NAME      },
    { TYPE_IPSECKEY,   TYPE_IPSECKEY_NAME   },
    { TYPE_RRSIG,      TYPE_RRSIG_NAME      },
    { TYPE_NSEC,       TYPE_NSEC_NAME       },
    { TYPE_DNSKEY,     TYPE_DNSKEY_NAME     },
    { TYPE_DHCID,      TYPE_DHCID_NAME      },
    { TYPE_NSEC3,      TYPE_NSEC3_NAME      },
    { TYPE_NSEC3PARAM, TYPE_NSEC3PARAM_NAME },
    { TYPE_TLSA,       TYPE_TLSA_NAME       },
    { TYPE_HIP,        TYPE_HIP_NAME        },
    { TYPE_NINFO,      TYPE_NINFO_NAME      },
    { TYPE_RKEY,       TYPE_RKEY_NAME       },
    { TYPE_TALINK,     TYPE_TALINK_NAME     },
    { TYPE_CDS,        TYPE_CDS_NAME        },
    { TYPE_SPF,        TYPE_SPF_NAME        },
    { TYPE_UINFO,      TYPE_UINFO_NAME      },
    { TYPE_UID,        TYPE_UID_NAME        },
    { TYPE_GID,        TYPE_GID_NAME        },
    { TYPE_UNSPEC,     TYPE_UNSPEC_NAME     },
    { TYPE_NID,        TYPE_NID_NAME        },
    { TYPE_L32,        TYPE_L32_NAME        },
    { TYPE_L64,        TYPE_L64_NAME        },
    { TYPE_LP,         TYPE_LP_NAME         },
    { TYPE_EUI48,      TYPE_EUI48_NAME      },
    { TYPE_EUI64,      TYPE_EUI64_NAME      },
    { TYPE_TKEY,       TYPE_TKEY_NAME       },
    { TYPE_TSIG,       TYPE_TSIG_NAME       },
    { TYPE_IXFR,       TYPE_IXFR_NAME       },
    { TYPE_AXFR,       TYPE_AXFR_NAME       },
    { TYPE_MAILB,      TYPE_MAILB_NAME      },
    { TYPE_MAILA,      TYPE_MAILA_NAME      },
    { TYPE_ANY,        TYPE_ANY_NAME        },
    { TYPE_URI,        TYPE_URI_NAME        },
    { TYPE_CAA,        TYPE_CAA_NAME        },
    { TYPE_TA,         TYPE_TA_NAME         },
    { TYPE_DLV,        TYPE_DLV_NAME        },
    
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
    { TYPE_CTRL_SRVLOGREOPEN,     TYPE_CTRL_SRVLOGREOPEN_NAME     },
    { TYPE_CTRL_SRVSHUTDOWN,      TYPE_CTRL_SHUTDOWN_NAME         },
    { TYPE_CTRL_ZONECFGRELOAD,    TYPE_CTRL_ZONECFGRELOAD_NAME    },
    { TYPE_CTRL_ZONECFGRELOADALL, TYPE_CTRL_ZONECFGRELOADALL_NAME },
    { TYPE_CTRL_ZONEFREEZE,       TYPE_CTRL_ZONEFREEZE_NAME       },
    { TYPE_CTRL_ZONEFREEZEALL,    TYPE_CTRL_ZONEFREEZEALL_NAME    },
    { TYPE_CTRL_ZONERELOAD,       TYPE_CTRL_ZONERELOAD_NAME       },
    { TYPE_CTRL_ZONEUNFREEZE,     TYPE_CTRL_ZONEUNFREEZE_NAME     },
    { TYPE_CTRL_ZONEUNFREEZEALL,  TYPE_CTRL_ZONEUNFREEZEALL_NAME  },

#endif  
    { 0,               NULL                 }
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
    "?",
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
    "NOTZONE",                //   10      /* Name not contained in zone         rfc 2136 */

    "?",
    "?",
    "?",
    "?",
    "?",

    "BADVERS",                //   16      /* Bad OPT Version                    rfc 2671 */
    
    "-",
    "-",
    "-",
    
    "-",
    "-",
    "-",
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
        case TYPE_ASFDB:
            return TYPE_ASFDB_NAME;
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
        case TYPE_UID:
            return TYPE_UID_NAME;
        case TYPE_GID:
            return TYPE_GID_NAME;
        case TYPE_UNSPEC:
            return TYPE_UNSPEC_NAME;
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

