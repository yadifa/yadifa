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

/** @defgroup 
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef RFC_H_
#define RFC_H_

#include <dnscore/sys_types.h>
#include <netinet/in.h>

/*    ------------------------------------------------------------
 *
 *      INCLUDES
 */

/*    ------------------------------------------------------------
 *
 *      VALUES
 */
/* http://en.wikipedia.org/wiki/List_of_DNS_record_types */

/* dns */
#define     DNS_HEADER_LENGTH               12      /*                                    rfc 1035 */
#define     MAX_LABEL_LENGTH                63      /*                                    rfc 1034 */
#define     MAX_DOMAIN_TEXT_LENGTH          (MAX_DOMAIN_LENGTH - 1)     /*                rfc 1034 */
#define     MAX_DOMAIN_LENGTH               255     /*                                    rfc 1034 */
#define     MAX_LABEL_COUNT                 ((MAX_DOMAIN_LENGTH + 1) / 2)
#define     MAX_SOA_RDATA_LENGTH            (255 + 255 + 20)

#define     DNS_DEFAULT_PORT                53

/* edns0 */
#define     EDNS0_MAX_LENGTH                65535    /* See 4.5.5 in RFC                  rfc 2671 */
#define     EDNS0_MIN_LENGTH                512      /*                                   rfc 2671 */
#define     EDNS0_DO                        0        /* DNSSEC OK flag                             */
#define     EDNS0_OPT_0                     0        /* Reserverd                         rfc 2671 */
#define     EDNS0_OPT_3                     3        /* NSID                              rfc 5001 */

#define     DNSPACKET_MAX_LENGTH            0xffff
#define     UDPPACKET_MAX_LENGTH            512
#define     RDATA_MAX_LENGTH                0xffff


/* dnssec (dns & bind) */
#define     DNSSEC_AD                       0x20     /* Authenticated Data flag                    */
#define     DNSSEC_CD                       0x10     /* Checking Disabled flag                     */

#define     RRSIG_RDATA_HEADER_LEN          18      /* The length of an RRSIG rdata without the
                                                     * signer_name and the signature: MUST BE 18 ! */

#define     ID_BITS                         0xFF    /*                                    rfc 1035 */

// HIGH flags

#define     QR_BITS                         0x80U    /*                                    rfc 1035 */
#define     OPCODE_BITS                     0x78U    /*                                    rfc 1035 */
#define     OPCODE_SHIFT                    3U
#define     AA_BITS                         0x04U    /*                                    rfc 1035 */
#define     TC_BITS                         0x02U    /*                                    rfc 1035 */
#define     RD_BITS                         0x01U    /*                                    rfc 1035 */

// LOW flags

#define     RA_BITS                         0x80U    /*                                    rfc 1035 */
#define     Z_BITS                          0x40U    /*                                    rfc 1035 */
#define     AD_BITS                         0x20U    /*                                    rfc 2065 */
#define     CD_BITS                         0x10U    /*                                    rfc 2065 */
#define     RCODE_BITS                      0x0FU    /*                                    rfc 1035 */

#ifdef WORDS_BIGENDIAN
// BIG endian

#define     DNS_FLAGS_HAS_QR(f_)             (f_ & ((u16)QR_BITS << 8))
#define     DNS_FLAGS_GET_OPCODE(f_)         ((f_ >> (OPCODE_SHIFT + 8)) & OPCODE_BITS)
#define     DNS_FLAGS_HAS_AA(f_)             (f_ & ((u16)AA_BITS << 8))
#define     DNS_FLAGS_HAS_TC(f_)             (f_ & ((u16)TC_BITS << 8))
#define     DNS_FLAGS_HAS_RD(f_)             (f_ & ((u16)RD_BITS << 8))

#define     DNS_FLAGS_HAS_RA(f_)             (f_ & ((u16)RA_BITS))
#define     DNS_FLAGS_HAS_Z(f_)              (f_ & ((u16)Z_BITS))
#define     DNS_FLAGS_HAS_AD(f_)             (f_ & ((u16)AD_BITS))
#define     DNS_FLAGS_HAS_CD(f_)             (f_ & ((u16)CD_BITS))
#define     DNS_FLAGS_GET_RCODE(f_)          (f_ & RCODE_BITS)

#else

#define     DNS_FLAGS_HAS_QR(f_)             (f_ & ((u16)QR_BITS))
#define     DNS_FLAGS_GET_OPCODE(f_)         ((f_ >> OPCODE_SHIFT) & OPCODE_BITS)
#define     DNS_FLAGS_HAS_AA(f_)             (f_ & ((u16)AA_BITS))
#define     DNS_FLAGS_HAS_TC(f_)             (f_ & ((u16)TC_BITS))
#define     DNS_FLAGS_HAS_RD(f_)             (f_ & ((u16)RD_BITS))

#define     DNS_FLAGS_HAS_RA(f_)             (f_ & ((u16)RA_BITS << 8))
#define     DNS_FLAGS_HAS_Z(f_)              (f_ & ((u16)Z_BITS  << 8))
#define     DNS_FLAGS_HAS_AD(f_)             (f_ & ((u16)AD_BITS << 8))
#define     DNS_FLAGS_HAS_CD(f_)             (f_ & ((u16)CD_BITS << 8))
#define     DNS_FLAGS_GET_RCODE(f_)          ((f_ >> 8) & RCODE_BITS)

#endif

#define     QDCOUNT_BITS                    0xFFFF  /* number of questions                rfc 1035 */
#define     ANCOUNT_BITS                    0xFFFF  /* number of resource records         rfc 1035 */
#define     NSCOUNT_BITS                    0xFFFF  /* name servers in the author.rec.    rfc 1035 */
#define     ARCOUNT_BITS                    0xFFFF  /* additional records                 rfc 1035 */
#define     ZOCOUNT_BITS                    0xFFFF  /* Number of RRs in the Zone Sect.    rfc 2136 */
#define     PRCOUNT_BITS                    0xFFFF  /* Number of RRs in the Prereq. Sect. rfc 2136 */
#define     UPCOUNT_BITS                    0xFFFF  /* Number of RRs in the Upd. Sect.    rfc 2136 */
#define     ADCOUNT_BITS                    0xFFFF  /* Number of RRs in the Add Sect.     rfc 2136 */

#define     OPCODE_QUERY                    (0<<OPCODE_SHIFT)       /* a standard query (QUERY)           rfc 1035 */
#define     OPCODE_IQUERY                   (1<<OPCODE_SHIFT)       /* an inverse query (IQUERY)          rfc 3425 */
#define     OPCODE_STATUS                   (2<<OPCODE_SHIFT)       /* a server status request (STATUS)   rfc 1035 */
#define     OPCODE_NOTIFY                   (4<<OPCODE_SHIFT)       /*                                    rfc 1996 */
#define     OPCODE_UPDATE                   (5<<OPCODE_SHIFT)       /* update                             rfc 2136 */

#define     RCODE_OK                        0       /* No error                           rfc 1035 */
#define     RCODE_NOERROR                   0       /* No error                           rfc 1035 */
#define     RCODE_FE                        1       /* Format error                       rfc 1035 */
#define     RCODE_FORMERR                   1       /* Format error                       rfc 1035 */
#define     RCODE_SF                        2       /* Server failure                     rfc 1035 */
#define     RCODE_SERVFAIL                  2       /* Server failure                     rfc 1035 */
#define     RCODE_NE                        3       /* Name error                         rfc 1035 */
#define     RCODE_NXDOMAIN                  3       /* Name error                         rfc 1035 */
#define     RCODE_NI                        4       /* Not implemented                    rfc 1035 */
#define     RCODE_NOTIMP                    4       /* Not implemented                    rfc 1035 */
#define     RCODE_RE                        5       /* Refused                            rfc 1035 */
#define     RCODE_REFUSED                   5       /* Refused                            rfc 1035 */

#define     RCODE_YXDOMAIN                  6       /* Name exists when it should not     rfc 2136 */
#define     RCODE_YXRRSET                   7       /* RR Set exists when it should not   rfc 2136 */
#define     RCODE_NXRRSET                   8       /* RR set that should exist doesn't   rfc 2136 */
#define     RCODE_NOTAUTH                   9       /* Server not Authortative for zone   rfc 2136 */
#define     RCODE_NOTZONE                   10      /* Name not contained in zone         rfc 2136 */

#define     RCODE_BADVERS                   16      /* Bad OPT Version                    rfc 2671 */
#define     RCODE_BADSIG                    16      /* TSIG Signature Failure             rfc 2845 */
#define     RCODE_BADKEY                    17      /* Key not recognized                 rfc 2845 */
#define     RCODE_BADTIME                   18      /* Signatue out of time window        rfc 2845 */
#define     RCODE_BADMODE                   19      /* Bad TKEY Mode                      rfc 2930 */
#define     RCODE_BADNAME                   20      /* Duplicate key name                 rfc 2930 */
#define     RCODE_BADALG                    21      /* Algorithm not supported            rfc 2930 */
#define     RCODE_BADTRUNC                  22      /* Bad Truncation                     rfc 4635 */

/* EDNS0 */

#define     RCODE_EXT_DNSSEC                0x00800000  /* Network-order, DNSSEC requested */

#define     TYPE_NONE                           0
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    ADDRESS                    |    32 bit address
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_A                          NU16(1)     /* a host address                   rfc 1035 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                    NSDNAME                    /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_NS                         NU16(2)     /* an authoritative name server     rfc 1035 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                    MADNAME                    /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_MD                         NU16(3)     /* mail destination - OBSOLETE      rfc 1035 rfc 882 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                    MADNAME                    /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_MF                         NU16(4)     /* mail forwarder - OBSOLETE        rfc 1035 rfc 882 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                     CNAME                     /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_CNAME                      NU16(5)     /* the canonical name of a alias    rfc 1035 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                     MNAME                     /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                     RNAME                     /    dns formatted domain name with local-part.
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+    Can have '\' before '.'
   |                    SERIAL                     |    32 bit 
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    REFRESH                    |    32 bit 
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     RETRY                     |    32 bit 
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    EXPIRE                     |    32 bit 
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    MINIMUM                    |    32 bit 
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_SOA                        NU16(6)     /* start of a zone of authority     rfc 1035 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                    MADNAME                    /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_MB                         NU16(7)     /* mailbox domain name - EXPERIMENTAL   rfc 1035 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                    MMGNAME                    /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_MG                         NU16(8)     /* mail group member - EXPERIMENTAL rfc 1035 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                    NEWNAME                    /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_MR                         NU16(9)     /* mail rename domain name - EXPERIMENTAL   rfc 1035 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                  <ANYTHING>                   /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_NULL                       NU16(10)    /* a null RR - EXPERIMENTAL         rfc 1035 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    ADDRESS                    |    32 bit address ARPA Internet address
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |       PROTOCOL        |                       |    PROTOCOL: 8 bit IP protocol number
   +--+--+--+--+--+--+--+--+                       |
   /                   <BIT MAP>                   /    BIT MAP: variable length bit map. The bit map
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+    must be a multiple of 8 bits long.
*/
#define     TYPE_WKS                        NU16(11)    /* a well known service description rfc 1035 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   PTRNAME                     /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_PTR                        NU16(12)    /* a domain name pointer            rfc 1035 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                      CPU                      /    character-string
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                       OS                      /    character-string
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_HINFO                      NU16(13)    /* host information                 rfc 1035 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   RMAILBX                     /    character-string
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   EMAILBX                     /    character-string
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_MINFO                      NU16(14)    /* mailbox or mail list information rfc 1035 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  PREFERENCE                   |    16 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   EXCHANGE                    /    dns formatted domain name
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_MX                         NU16(15)    /* mail exchange                    rfc 1035 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   TXT-DATA                    /    one or more <character string>s (pascal string)
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_TXT                        NU16(16)    /* text strings                     rfc 1035 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                  MBOX-DNAME                   /    dns formatted domain name local-part. Can have '\'before .
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   TXT-DNAME                   /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
#define     TYPE_RP                         NU16(17)    /* For Responsible Person           rfc 1183 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    SUBTYPE                    |    16 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   HOSTNAME                    /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_AFSDB                      NU16(18)    /* AFS Data Base location           rfc 1183 rfc 5864 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   PSDN-ADDRESS                /    pascal string (numeric only)
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_X25                        NU16(19)    /* X.25 PSDN address                rfc 1183 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   ISDN-ADDRESS                /    pascal string (IA5 allowed)
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                        SA                     /    pascal string (numeric BCD) (OPTIONAL)
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_ISDN                       NU16(20)    /* ISDN address                     rfc 1183 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  PREFERENCE                   |    16 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /               INTERMEDIATE-HOST               /    dns formatted domain name
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */ 
#define     TYPE_RT                         NU16(21)    /* Route Through                    rfc 1183 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   NSAP (in hex)               /    binary encoding of NSAP in hex
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
/*
          |--------------|
          | <-- IDP -->  |
          |--------------|-------------------------------------|
          | AFI |  IDI   |            <-- DSP -->              |
          |-----|--------|-------------------------------------|
          | 47  |  0005  | DFI | AA |Rsvd | RD |Area | ID |Sel |
          |-----|--------|-----|----|-----|----|-----|----|----|
   octets |  1  |   2    |  1  | 3  |  2  | 2  |  2  | 6  | 1  |
          |-----|--------|-----|----|-----|----|-----|----|----|

                IDP    Initial Domain Part
                AFI    Authority and Format Identifier
                IDI    Initial Domain Identifier
                DSP    Domain Specific Part
                DFI    DSP Format Identifier
                AA     Administrative Authority
                Rsvd   Reserved
                RD     Routing Domain Identifier
                Area   Area Identifier
                ID     System Identifier
                SEL    NSAP Selector
   */
#define     TYPE_NSAP                       NU16(22)    /* NSAP address, NSAP style A record    rfc 1706 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   PTRNAME                     /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_NSAP_PTR                   NU16(23)    /* domain name pointer, NSAP style  rfc 1348 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  TYPE COVERED                 |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |      ALGORITHM        |        LABELS         |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   ORIGINAL TTL                |    32 bit
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                 SIGNATURE EXPIRATION          |    32 bit
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                 SIGNATURE INCEPTION           |    32 bit
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     KEY TAG                   |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                  SIGNER'S NAME                / 
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                    SIGNATURE                  /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_SIG                        NU16(24)    /* for security signature           rfc 4034 rfc 3755 rfc 2535 rfc 2536 rfc 2537 rfc 2931 rfc 3110 rfc 3008 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   FLAGS                       |    16 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |        PROTOCOL       |       ALGORITHM       |    PROTOCOL: 8 bit, ALGORITHM: 8 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                   PUBLIC KEY                  /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
/* flags
                                             1   1   1   1   1   1
     0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   |  A/C  | Z | XT| Z | Z | NAMTYP| Z | Z | Z | Z |      SIG      |
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   */
#define     TYPE_KEY                        NU16(25)    /* for security key                 rfc 4034 rfc 3755 rfc 2535 rfc 2536 rfc 2537 rfc 2539 rfc 3008 rfc 3110 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  PREFERENCE                   |    16 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                    MAP822                     /    dns formatted domain name
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                    MAPX400                    /    dns formatted domain name
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_PX                         NU16(26)    /* X.400 mail mapping information   rfc 2163 */
/*
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                 LONGITUDE                     /    c-string (representing a real number)
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                  LATITUDE                     /    c-string (representing a real number)
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                  ALTITUDE                     /    c-string (representing a real number)
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_GPOS                       NU16(27)    /* Geographical Position            rfc 1712 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    ADDRESS                    |    32 bit address address
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    ADDRESS                    |    32 bit address address
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    ADDRESS                    |    32 bit address address
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    ADDRESS                    |    32 bit address address
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_AAAA                       NU16(28)    /* IP6 Address                      rfc 3596 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |        VERSION        |         SIZE          |    VERSION: 8 bit int, SIZE: 8 bit int
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |       HORIZ PRE       |       VERT PRE        |    HORIZ PRE: 8 bit int, VERT PRE: 8 bit int
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   LATITUDE                    |    32 bit integer
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   LONGITUDE                   |    32 bit integer
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   ALTITUDE                    |    32 bit integer
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_LOC                        NU16(29)    /* Location information             rfc 1876 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /               NEXT DOMAIN NAME                /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                 TYPE BIT MAPS                 /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_NXT                        NU16(30)    /* Next Domain - OBSOLETE           rfc 3755 rfc 2535 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /             ENDPOINT IDENTIFIER               /    string of octets. (Binary encoding of the Identifier,
   /                                               /    meaningful only to the system utilizing it)
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_EID                        NU16(31)    /* Endpoint Identifier              @note undocumented see draft-ietf-nimrod-dns-01.txt */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                 NIMROD LOCATOR                /    variable string of octets. (Binary encoding of the Locator
   /                                               /    specified in the Nimrod protocol)
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_NIMLOC                     NU16(32)    /* Nimrod Locator                   @note undocumented see draft-ietf-nimrod-dns-01.txt */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  PRIORITY                     |   16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   WEIGHT                      |   16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    PORT                       |   16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   TARGET                      /   dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_SRV                        NU16(33)    /* Server selection                 rfc 2782 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |          FORMAT       |                       |    FORMAT: 8 bit 
   +--+--+--+--+--+--+--+--+                       |    ADDRESS: c-string
   /                    ADDRESS                    /
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
#define     TYPE_ATMA                       NU16(34)    /* ATM Address                      @note undocumented see ATM Name System V2.0 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     ORDER                     |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   PREFERENCE                  |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                     FLAGS                     /   character-string (a-z0-9) can be empty
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   SERVICES                    /   character-string (a-z0-9) can be empty
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                    REGEXP                     /   character-string
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                  REPLACEMENT                  /   <domain name>
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_NAPTR                      NU16(35)    /* Naming Authority Pointer         rfc 2915 rfc 2168 rfc 3403 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  PREFERENCE                   |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   EXCHANGER                   /    dns formatted domain name
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_KX                         NU16(36)    /* Key Exchanger                    rfc 2230 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     TYPE                      |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    KEY TAG                    |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |       ALGORITHM       |                       /
   +--+--+--+--+--+--+--+--+                       /
   /                                               /
   /               CERTIFICATE OR CRL              /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */   
#define     TYPE_CERT                       NU16(37)    /* CERT                             rfc 4398 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |         PREFIX        |                       /    8 bit unsigned integer
   +--+--+--+--+--+--+--+--+                       / 
   /                                               /
   /                 ADDRESS SUFFIX                /    0..16 octets
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   PREFIX NAME                 /    uncompressed domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_A6                         NU16(38)    /* A6                               rfc 3226 rfc 2874 rfc 6563 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                      DNAME                    /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_DNAME                      NU16(39)    /* DNAME                            rfc 6672 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |         CODING        |       SUBCODING       |    CODING: 8 bit, SUBCODING: 8 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                                               /    c-string
   /                     DATA                      /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_SINK                       NU16(40)    /* SINK                             @note undocumented see The Kitchen Sink Resource Record */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  OPTION-CODE                  |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                 OPTION-LENGTH                 |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                                               |
   /                  OPTION-DATA                  /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */ 
/*
 * @todo 20171121 thx -- this is not about RDATA, fix this (maybe it should not
 *                       be here at all ?)
 * 
 *
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |     EXTENDED-RCODE    |       VERSION         |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                       Z                       |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_OPT                        NU16(41)    /* edns0 flag                       rfc 6891 rfc 3225 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                ADDRESSFAMILY                  |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |        PREFIX      | N|       AFDLENGTH       |    PREFIX: 8 bit unsigned binary coded, N: 1 bit,
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+    ADFLENGTH: 7 bit unsigned 
   /                                               /
   /                   AFDPART                     /    address family dependent
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_APL                        NU16(42)    /* APL                              rfc 3123 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    KEY TAG                    |    16 bit 
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |       ALGORITHM       |       DIGEST TYPE     |    ALGORITHM: 8 bit, DIGEST TYPE: 8 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                      DIGEST                   /    digest dependent
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_DS                         NU16(43)    /* Delegation Signer                rfc 4034 rfc 3658 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |       ALGORITHM       |        FP TYPE        |    ALGORITHM: 8 bit, FP TYPE: 8 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                  FINGERPRINT                  /    
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_SSHFP                      NU16(44)    /* SSH Key Fingerprint              rfc 4255 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |       PRECEDENCE      |     GATEWAY TYPE      |    PRECEDENCE: 8 bit, GATEWAY TYPE: 8 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |        ALGORITHM      |                       |    ALGORITHM: 8 bit
   +--+--+--+--+--+--+--+--+                       |
   |                   GATEWAY                     |    GATEWAY: 32 bit IPv4 / 128 bit IPv6 / uncompressed domain name
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                    PUBLIC KEY                 /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_IPSECKEY                   NU16(45)    /* IPSECKEY                         rfc 4025 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  TYPE COVERED                 |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |      ALGORITHM        |        LABELS         |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   ORIGINAL TTL                |    32 bit
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                 SIGNATURE EXPIRATION          |    32 bit
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                 SIGNATURE INCEPTION           |    32 bit
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     KEY TAG                   |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                  SIGNER'S NAME                / 
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                    SIGNATURE                  /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_RRSIG                      NU16(46)    /* RRSIG                            rfc 4034 rfc 3755 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /              NEXT DOMAIN NAME                 /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /               TYPE NIT MAPS                   /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_NSEC                       NU16(47)    /* NSEC                             rfc 4034 rfc 3755 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   FLAGS                       |    16 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |        PROTOCOL       |       ALGORITHM       |    PROTOCOL: 8 bit, ALGORITHM: 8 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                   PUBLIC KEY                  /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_DNSKEY                     NU16(48)    /* DNSKEY                           rfc 4034 rfc 3755 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |               IDENTIFIER TYPE                 |    16 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |      DIGEST TYPE      |                       /    8 bit
   +--+--+--+--+--+--+--+--+                       /
   /                    DIGEST                     /    dependent on the digest type
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_DHCID                      NU16(49)    /* DHCID                            rfc 4701 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |     HASH ALGORITHM    |         FLAGS         |    HASH ALGORITHM: 8 bit, FLAGS: 8 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   ITERATIONS                  |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |      SALT LENGTH      |                       /    8 bit unsigned integer
   +--+--+--+--+--+--+--+--+                       /
   /                     SALT                      /    Can be zero length
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |      HASH LENGTH      |                       /    8 bit unsigned integer
   +--+--+--+--+--+--+--+--+                       /
   /            NEXT HASHED OWNER NAME             /    unmodified binary hash value.
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                 TYPE BIT MAPS                 /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
/* Flags
    0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+
   |             |O|
   +-+-+-+-+-+-+-+-+
                  ^ 
               OPT-OUT flag
   */
#define     TYPE_NSEC3                      NU16(50)    /* NSEC3                            rfc 5155 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |     HASH ALGORITHM    |         FLAGS         |    HASH ALGORITHM: 8 bit, FLAGS: 8 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   ITERATIONS                  |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |      SALT LENGTH      |                       /    8 bit unsigned integer
   +--+--+--+--+--+--+--+--+                       /
   /                     SALT                      /    Can be zero length
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_NSEC3PARAM                 NU16(51)    /* NSEC3PARAM                       rfc 5155 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |   CERTIFICATE USAGE   |        SELECTOR       |    CERTIFICATE USAGE: 8 bit, SELECTOR: 8 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /      MATCHING TYPE    |                       /
   +--+--+--+--+--+--+--+--+                       /
   /                                               /
   /          CERTIFICATE ASSOCIATION DATA         /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_TLSA                       NU16(52)    /* TLSA                             rfc 6698 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |        HIT LENGTH     |     PK ALGORITHM      |    HIT LENGTH: 8 bit unsigned integer, 
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+    PK ALGORITHM: 8 bit unsigned integer
   |                   PK LENGTH                   |    PK LENTH: 16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                      HIT                      /    binary value in network order
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                  PUBLIC KEY                   /    dependent on the type
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                RENDEZVOUS SERVERS             /    dns formatted domain name
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_HIP                        NU16(55)    /* Host Identity Protocol           rfc 5205 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                 NINFO-DATA                    /    one or more c-strings
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_NINFO                      NU16(56)    /* NINFO                            @note undocumented see draft-reid-dnsext-zs-01.txt */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   FLAGS                       |    16 bit: (value 0)
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |        PROTOCOL       |       ALGORITHM       |    PROTOCOL: 8 bit (value 1), ALGORITHM: 8 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                   PUBLIC KEY                  /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_RKEY                       NU16(57)    /* RKEY                             @note undocumented see draft-reid-dnsext-rkey-00.txt */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /             TALINK START/PREVIOUS             /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /               TALINK NEXT/END                 /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_TALINK                     NU16(58)    /* Trust Anchor LINK                @note undocumented see talink-completed-template */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    KEY TAG                    |    16 bit 
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |       ALGORITHM       |       DIGEST TYPE     |    ALGORITHM: 8 bit, DIGEST TYPE: 8 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                      DIGEST                   /    digest dependent
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_CDS                        NU16(59)    /* Child DS                         rfc 7344 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   FLAGS                       |    16 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |        PROTOCOL       |       ALGORITHM       |    PROTOCOL: 8 bit, ALGORITHM: 8 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                   PUBLIC KEY                  /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_CDNSKEY                    NU16(60)    /* DNSKEY(s) the Child wants reflected in DS rfc 7344 */
/*

                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               / 
   /             OPENPGP PUBLIC KEY                /    single OpenPGP public key as defined in Section 5.5.1.1 of [RFC4880].  
   /                                               /    without ASCII armor or base64 encoding
   /                                               / 
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

   */
#define     TYPE_OPENPGPKEY                 NU16(61)    /* OpenPGP Key                      @note undocumented see draft-ietf-dane-openpgpkey-03 */

/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  SOA SERIAL                   |    32 bit
   |                                               | 
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    FLAGS                      |    16 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                TYPE BIT MAP                   /    
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_CSYNC                      NU16(62)    /* Child-To-Parent Synchronization  rfc 7477 */

/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   SPF-DATA                    /    one or more c-strings
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_SPF                        NU16(99)    /* SPF                                rfc7208 */

#define     TYPE_UINFO                      NU16(100)   /* IANA-Reserved */
#define     TYPE_UID                        NU16(101)   /* IANA-Reserved */
#define     TYPE_GID                        NU16(102)   /* IANA-Reserved */
#define     TYPE_UNSPEC                     NU16(103)   /* IANA-Reserved */

/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  PREFERENCE                   |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                                               |
   |                    NODEID                     |    64 bit
   |                                               |
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_NID                        NU16(104)   /* NODE ID                          rfc 6742 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  PREFERENCE                   |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   LOCATOR32                   |    32 bit unsigned integer
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_L32                        NU16(105)   /* LOCATOR 32                       rfc 6742 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  PREFERENCE                   |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                                               |
   |                   LOCATOR64                   |    64 bit unsigned integer
   |                                               |
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_L64                        NU16(106)   /* LOCATOR 64                       rfc 6742 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  PREFERENCE                   |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                     FQDN                      /    dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_LP                         NU16(107)   /* LOCATOR POINTER                  rfc 6742 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                                               |
   |                EUI-48 ADDRESS                 |    48 bit (MUST be represented as six two-digit hexadecimal
   |                                               |            numbers separated by hyphens)
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
#define     TYPE_EUI48                      NU16(108)   /* EUI-48 address                   rfc 7043 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                                               |
   |                EUI-64 ADDRESS                 |    64 bit (MUST be represented as six two-digit hexadecimal
   |                                               |            numbers separated by hyphens)
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
#define     TYPE_EUI64                      NU16(109)   /* EUI-64 address                   rfc 7043 */

/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                  ALGORITHM                    /    algorithm in dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  INCEPTION                    |    32 bit unsigned integer
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  EXPIRATION                   |    32 bit unsigned integer
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     MODE                      |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     ERROR                     |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    KEY SIZE                   |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                    KEY DATA                   /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   OTHER SIZE                  |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   OTHER DATA                  /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_TKEY                       NU16(249)   /* Transaction Key                  rfc 2930 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                  ALGORITHM                    /    algorithm in dns formatted domain name
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                                               |
   |                  INCEPTION                    |    48 bit unsigned integer
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     FUDGE                     |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    MAC SIZE                   |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                      MAC                      /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  ORIGINAL ID                  |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     ERROR                     |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   OTHER SIZE                  |    16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                   OTHER DATA                  /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_TSIG                       NU16(250)   /* Transaction Signature            rfc 2845 */
#define     TYPE_IXFR                       NU16(251)   /* Incremental Transfer             rfc 1995 */
#define     TYPE_AXFR                       NU16(252)   /* Transfer of an entire zone       rfc 1035 rfc 5936 */
#define     TYPE_MAILB                      NU16(253)   /* A request for mailbox-related records (MB, MG or MR) rfc 1035 */
#define     TYPE_MAILA                      NU16(254)   /* A request for mail agent RRs (Obsolete - see MX) rfc 1035 */
#define     TYPE_ANY                        NU16(255)   /* a request for all records        rfc 1035 rfc 6895 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                  PRIORITY                     |   16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   WEIGHT                      |   16 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                   TARGET                      /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_URI                        NU16(256)   /* URI                              @note undocumented see draft-faltstrom-uri-14 */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |         FLAGS         |       TAG LENGTH      |    FLAGS: 8 bit, TAG LENGTH: 8 bit unsigned integer
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                      TAG                      /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                     VALUE                     /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_CAA                        NU16(257)   /* Certification Authority Authorization rfc 6844 */


#define     TYPE_AVC                        NU16(258)   // Visibility and control, no rfc yet

/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    KEY TAG                    |    16 bit 
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |       ALGORITHM       |       DIGEST TYPE     |    ALGORITHM: 8 bit, DIGEST TYPE: 8 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                      DIGEST                   /    digest dependent
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_TA                         NU16(32768) /* DNSSEC Trust Authorities         @note undocumented see Deploying DNSSEC Without a Signed Root */
/*
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    KEY TAG                    |    16 bit 
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |       ALGORITHM       |       DIGEST TYPE     |    ALGORITHM: 8 bit, DIGEST TYPE: 8 bit
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                                               /
   /                      DIGEST                   /    digest dependent
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
#define     TYPE_DLV                        NU16(32769) /* DNSSEC Lookaside Validation      rfc 4431 */

#define     TYPE_PRIVATE_FIRST              NU16(65280)
#define     TYPE_PRIVATE_LAST               NU16(65534)

#define     HOST_CLASS_IN                   1             /* the Internet                      rfc 1025 */

#define     CLASS_IN                        NU16(HOST_CLASS_IN) /* the Internet                rfc 1025 */
#define     CLASS_CS                        NU16(2)       /* CSNET class                       rfc 1025 */
#define     CLASS_CH                        NU16(3)       /* the CHAOS class                   rfc 1025 */
#define     CLASS_HS                        NU16(4)       /* Hesiod                            rfc 1025 */
#define     CLASS_CTRL                      NU16(0x2A)    /* @note Yadifa controller class */

#if HAS_WHOIS
#define     CLASS_WHOIS                     NU16(0x2B)    /* @note WHOIS class */
#endif  // HAS_WHOIS

#define     CLASS_NONE                      NU16(254)     /* rfc 2136                          rfc 2136 */
#define     CLASS_ANY                       NU16(255)     /* rfc 1035  QCLASS ONLY             rfc 1025 */


/* -----------------------------------------------------------------*/

#define     AXFR_TSIG_PERIOD                100

/* -----------------------------------------------------------------*/

#ifdef WORDS_BIGENDIAN
#define     DNSKEY_FLAG_KEYSIGNINGKEY       0x0001
#define     DNSKEY_FLAG_ZONEKEY             0x0100
#else
#define     DNSKEY_FLAG_KEYSIGNINGKEY       0x0100
#define     DNSKEY_FLAG_ZONEKEY             0x0001
#endif

#define     DNSKEY_PROTOCOL_FIELD               3       /* MUST be this */

#define     DNSKEY_ALGORITHM_RSAMD5             1       // DEPRECATED
#define     DNSKEY_ALGORITHM_DIFFIE_HELLMAN     2       // NOT USED
#define     DNSKEY_ALGORITHM_DSASHA1            3
#define     DNSKEY_ALGORITHM_RSASHA1            5
#define     DNSKEY_ALGORITHM_DSASHA1_NSEC3      6
#define     DNSKEY_ALGORITHM_RSASHA1_NSEC3      7
#define     DNSKEY_ALGORITHM_RSASHA256_NSEC3    8       /* RFC 5702 */
#define     DNSKEY_ALGORITHM_RSASHA512_NSEC3   10       /* RFC 5702 */
#define     DNSKEY_ALGORITHM_GOST              12       /* RFC 5933, not supported by YADIFA */
#define     DNSKEY_ALGORITHM_ECDSAP256SHA256   13       /* RFC 6605 */
#define     DNSKEY_ALGORITHM_ECDSAP384SHA384   14       /* RFC 6605 */
#define     DNSKEY_ALGORITHM_ED25519           15       /* RFC 8080 */
#define     DNSKEY_ALGORITHM_ED448             16       /* RFC 8080 */

#define     DS_DIGEST_SHA1                      1
#define     DS_DIGEST_SHA256                    2

#define     NSEC3_FLAGS_OPTOUT                  1           /*  */

#define     DNSKEY_ALGORITHM_RSAMD5_NAME             "RSAMD5"               /* RFC 4034 */ // RSA // DEPRECATED
#define     DNSKEY_ALGORITHM_DIFFIE_HELLMAN_NAME     "DH"                   /* RFC 2539 */ // NOT USED
#define     DNSKEY_ALGORITHM_DSASHA1_NAME            "DSA"                  /* RFC 3755 */
#define     DNSKEY_ALGORITHM_RSASHA1_NAME            "RSASHA1"              /* RFC 4034 */
#define     DNSKEY_ALGORITHM_DSASHA1_NSEC3_NAME      "DSA-NSEC3-SHA1"       /* RFC 5155 */ // NSEC3DSA"
#define     DNSKEY_ALGORITHM_RSASHA1_NSEC3_NAME      "RSASHA1-NSEC3-SHA1"   /* RFC 5155 */ // NSEC3RSASHA1
#define     DNSKEY_ALGORITHM_RSASHA256_NSEC3_NAME    "RSASHA256"            /* RFC 5702 */
#define     DNSKEY_ALGORITHM_RSASHA512_NSEC3_NAME    "RSASHA512"            /* RFC 5702 */
#define     DNSKEY_ALGORITHM_GOST_NAME               "ECC-GOST" // GOST     /* RFC 5933 */ // not supported by YADIFA
#define     DNSKEY_ALGORITHM_ECDSAP256SHA256_NAME    "ECDSAP256SHA256"      /* RFC 6605 */
#define     DNSKEY_ALGORITHM_ECDSAP384SHA384_NAME    "ECDSAP384SHA384"      /* RFC 6605 */
#define     DNSKEY_ALGORITHM_ED25519_NAME            "ED25519"              /* RFC 8080 */
#define     DNSKEY_ALGORITHM_ED448_NAME              "ED448"                /* RFC 8080 */

#define     DNSKEY_ALGORITHM_DSASHA1_NSEC3_NAME2     "NSEC3DSA"
#define     DNSKEY_ALGORITHM_RSASHA1_NSEC3_NAME2     "NSEC3RSASHA1"

#ifdef DNSKEY_ALGORITHM_DUMMY
#define     DNSKEY_ALGORITHM_DUMMY_NAME "DUMMY"
#endif

#define     IS_TYPE_PRIVATE(t)              (((t) >= 65280) && ( (t) <= 65534))
#define     IS_TYPE_NPRIVATE(t)             ((NU16(t) >= 65280) && ( NU16(t) <= 65534))

/*
 *      STRUCTS
 */

#define EDNS0_RECORD_SIZE                   11

/* rfc 2671 */
struct edns0_data
{
    u8                 domain_name;    /* must be empty            */
    u16                        opt;
    u16               payload_size;
    u8              extended_rcode;    /* extended rcode and flags */
    u8                     version;    /* extended rcode and flags */
    u8                      z_bits;    /* extended rcode and flags */
    u8                 option_code;
    u16              option_length;
};

typedef struct edns0_data edns0_data;

/* - */

typedef struct value_name_table value_name_table;

struct value_name_table
{
    u32                        id;
    char                    *data;
};


typedef value_name_table class_table;
typedef value_name_table type_table;
typedef value_name_table dnssec_algo_table;

typedef struct message_header message_header;

struct message_header
{
    u16                         id;
    u8                      opcode;
    u8                       flags;
    u16                    qdcount;
    u16                    ancount;
    u16                    nscount;
    u16                    arcount;
};

/*    ------------------------------------------------------------    */

#define     CLASS_IN_NAME                   "IN"
#define     CLASS_CS_NAME                   "CS"
#define     CLASS_CH_NAME                   "CH"
#define     CLASS_HS_NAME                   "HS"
#define     CLASS_CTRL_NAME                 "CTRL"  /* @note YADIFA's personal class, maybe one day in a RFC */

#if HAS_WHOIS
#define     CLASS_WHOIS_NAME                "WHOIS"
#endif // HAS_WHOIS

#define     CLASS_NONE_NAME                 "NONE"
#define     CLASS_ANY_NAME                  "ANY"

extern const class_table qclass[];

#define     TYPE_A_NAME                     "A"
#define     TYPE_NS_NAME                    "NS"
#define     TYPE_MD_NAME                    "MD"
#define     TYPE_MF_NAME                    "MF"
#define     TYPE_CNAME_NAME                 "CNAME"
#define     TYPE_SOA_NAME                   "SOA"
#define     TYPE_MB_NAME                    "MB"
#define     TYPE_MG_NAME                    "MG"
#define     TYPE_MR_NAME                    "MR"
#define     TYPE_NULL_NAME                  "NULL"
#define     TYPE_WKS_NAME                   "WKS"
#define     TYPE_PTR_NAME                   "PTR"
#define     TYPE_HINFO_NAME                 "HINFO"
#define     TYPE_MINFO_NAME                 "MINFO"
#define     TYPE_MX_NAME                    "MX"
#define     TYPE_TXT_NAME                   "TXT"
#define     TYPE_RP_NAME                    "RP"
#define     TYPE_AFSDB_NAME                 "AFSDB"
#define     TYPE_X25_NAME                   "X25"
#define     TYPE_ISDN_NAME                  "ISDN"
#define     TYPE_RT_NAME                    "RT"
#define     TYPE_NSAP_NAME                  "NSAP"
#define     TYPE_NSAP_PTR_NAME              "NSAP-PTR"
#define     TYPE_SIG_NAME                   "SIG"
#define     TYPE_KEY_NAME                   "KEY"
#define     TYPE_PX_NAME                    "PX"
#define     TYPE_GPOS_NAME                  "GPOS"
#define     TYPE_AAAA_NAME                  "AAAA"
#define     TYPE_LOC_NAME                   "LOC"
#define     TYPE_NXT_NAME                   "NXT"
#define     TYPE_EID_NAME                   "EID"       /* @note undocumented see draft-lewis-dns-undocumented-types-01 */
#define     TYPE_NIMLOC_NAME                "NIMLOC"    /* @note undocumented see draft-lewis-dns-undocumented-types-01 */
#define     TYPE_SRV_NAME                   "SRV"
#define     TYPE_ATMA_NAME                  "ATMA"
#define     TYPE_NAPTR_NAME                 "NAPTR"
#define     TYPE_KX_NAME                    "KX"
#define     TYPE_CERT_NAME                  "CERT"
#define     TYPE_A6_NAME                    "A6"
#define     TYPE_DNAME_NAME                 "DNAME"
#define     TYPE_SINK_NAME                  "SINK"      /* @note undocumented see draft-lewis-dns-undocumented-types-01 */
#define     TYPE_OPT_NAME                   "OPT"
#define     TYPE_APL_NAME                   "APL"
#define     TYPE_DS_NAME                    "DS"
#define     TYPE_SSHFP_NAME                 "SSHFP"
#define     TYPE_IPSECKEY_NAME              "IPSECKEY"
#define     TYPE_RRSIG_NAME                 "RRSIG"
#define     TYPE_NSEC_NAME                  "NSEC"
#define     TYPE_DNSKEY_NAME                "DNSKEY"
#define     TYPE_DHCID_NAME                 "DHCID"
#define     TYPE_NSEC3_NAME                 "NSEC3"
#define     TYPE_NSEC3PARAM_NAME            "NSEC3PARAM"
#define     TYPE_TLSA_NAME                  "TLSA"
#define     TYPE_HIP_NAME                   "HIP"
#define     TYPE_NINFO_NAME                 "NINFO"     /* @note undocumented see draft-lewis-dns-undocumented-types-01 */
#define     TYPE_RKEY_NAME                  "RKEY"      /* @note undocumented see draft-lewis-dns-undocumented-types-01 */
#define     TYPE_TALINK_NAME                "TALINK"    /* @note undocumented see draft-lewis-dns-undocumented-types-01 */
#define     TYPE_CDS_NAME                   "CDS"
#define     TYPE_CDNSKEY_NAME               "CDNSKEY"
#define     TYPE_OPENPGPKEY_NAME            "OPENPGPKEY"
#define     TYPE_CSYNC_NAME                 "CSYNC"
#define     TYPE_SPF_NAME                   "SPF"
#define     TYPE_UINFO_NAME                 "UINFO"
#define     TYPE_UID_NAME                   "UID"
#define     TYPE_GID_NAME                   "GID"
#define     TYPE_UNSPEC_NAME                "UNSPEC"
#define     TYPE_NID_NAME                   "NID"
#define     TYPE_L32_NAME                   "L32"
#define     TYPE_L64_NAME                   "L64"
#define     TYPE_LP_NAME                    "LP"
#define     TYPE_EUI48_NAME                 "EUI48"
#define     TYPE_EUI64_NAME                 "EUI64"

#define     TYPE_TKEY_NAME                  "TKEY"
#define     TYPE_TSIG_NAME                  "TSIG"
#define     TYPE_IXFR_NAME                  "IXFR"
#define     TYPE_AXFR_NAME                  "AXFR"
#define     TYPE_MAILB_NAME                 "MAILB"
#define     TYPE_MAILA_NAME                 "MAILA"
#define     TYPE_ANY_NAME                   "ANY"  /** @note type ANY's string was set to '*' ? 
                                                    *  Setting this to anything else will break
                                                    *        dnsformat:358
                                                    */
#define     TYPE_URI_NAME                   "URI"       /* @note undocumented see draft-lewis-dns-undocumented-types-01 */
#define     TYPE_CAA_NAME                   "CAA"       /* @note undocumented see draft-lewis-dns-undocumented-types-01 */
#define     TYPE_AVC_NAME                   "AVC"   /* visibility and control */

#define     TYPE_TA_NAME                    "TA"        /* @note undocumented see draft-lewis-dns-undocumented-types-01 */
#define     TYPE_DLV_NAME                   "DLV"

#define     OPT_NSID                        3       // the option value for NSID

extern const type_table qtype[];

/**
 * Static asciiz representation of a dns class
 * 
 * @param c
 * @return the c-string
 */

const char *dns_class_get_name(u16 c);

/**
 * Static asciiz representation of a dns type
 * 
 * @param c
 * @return the c-string
 */

const char *dns_type_get_name(u16 t);

/** \brief Get the numeric value of a class (network order) from its name
 *
 *  @param[in]  src the name of the class
 *  @param[out] dst value of the class, network order
 *
 *  @retval OK
 *  @retval NOK
 */
int dns_class_from_name(const char *src, u16 *dst);

/** \brief Get the numeric value of a class (network order) from its name
 *  Case insensitive
 *
 *  @param[in]  src the name of the class (case insensitive)
 *  @param[out] dst value of the class, network order
 *
 *  @retval OK
 *  @retval NOK
 */
int dns_class_from_case_name(const char *src, u16 *dst);

/** \brief Get the numeric value of a type (network order) from its name
 *
 *  @param[in]  src the name of the type
 *  @param[out] dst value of the type, network order
 *
 *  @retval OK
 *  @retval NOK
 */
int dns_type_from_name(const char *src, u16 *dst);

/** \brief Get the numeric value of a type (network order) from its name
 *  Case insensitive
 *
 *  @param[in]  src the name of the type (case insensitive)
 *  @param[out] dst value of the type, network order
 *
 *  @retval OK
 *  @retval NOK
 */
int dns_type_from_case_name(const char *src, u16 *dst);

int dns_type_from_case_name_length(const char *src, int src_len, u16 *dst);

/**
 * @brief Case-insensitive search for the name in the table, returns the value
 * 
 * @param table the name->value table
 * @param name the name to look for
 * @param out_value a pointer to an u32 that will hold the value in case of a match
 * 
 * @return SUCCESS iff the name was matched
 */
ya_result value_name_table_get_value_from_casename(const value_name_table *table, const char *name, u32 *out_value);
ya_result value_name_table_get_name_from_value(const value_name_table *table, u32 value, const char** out_name);

const char* dns_encryption_algorithm_get_name(u16 d);
int dns_encryption_algorithm_from_name(const char *src, u8 *dst);
int dns_encryption_algorithm_from_case_name(const char *src, u8 *dst);

/**
 * @brief Static asciiz representation of a dns opcode
 * 
 * @param c
 *
 * @return the c-string
 */
const char *dns_message_opcode_get_name(u16 c);

/**
 * @brief Static asciiz representation of a dns rcode
 * 
 * @param c
 *
 * @return the c-string
 */
const char *dns_message_rcode_get_name(u16 c);

#if DNSCORE_HAS_NSID_SUPPORT

#ifndef DNSCORE_RFC_C
extern u32 edns0_record_size;
extern u8 *edns0_rdatasize_nsid_option_wire;
extern u32 edns0_rdatasize_nsid_option_wire_size;
#endif

void edns0_set_nsid(u8 *bytes, u16 size);
#endif

ya_result protocol_name_to_id(const char* name, int *out_port);
ya_result protocol_id_to_name(int proto, char *name, size_t name_len);

ya_result server_name_to_port(const char* name, int *out_value);
ya_result server_port_to_name(int port, char *name, size_t name_len);

/*
 * SOA
 */

ya_result rr_soa_get_serial(const u8* rdata, u16 rdata_size, u32* out_serial);
ya_result rr_soa_increase_serial(u8* rdata, u16 rdata_size, u32 increment);
ya_result rr_soa_set_serial(u8* rdata, u16 rdata_size, u32 increment);

ya_result rr_soa_get_minimumttl(const u8* rdata, u16 rdata_size, s32* out_minimum_ttl);

static inline u16 rrsig_get_type_covered_from_rdata(const void *rdata, u16 rdata_size)
{
    u16 tc = TYPE_NONE;
    if(rdata_size >= 2)
    {
        tc = GET_U16_AT_P(rdata);
    }
    return tc;
}

static inline u8 rrsig_get_algorithm_from_rdata(const void *rdata, u16 rdata_size)
{
    u8 a = 0;
    if(rdata_size >= 3)
    {
        a = ((const u8*)rdata)[2];
    }
    return a;
}

static inline u8 rrsig_get_labels_from_rdata(const void *rdata, u16 rdata_size)
{
    u8 l = 0;
    if(rdata_size >= 4)
    {
        l = ((const u8*)rdata)[3];
    }
    return l;
}

static inline s32 rrsig_get_original_ttl_from_rdata(const void *rdata, u16 rdata_size)
{
    s32 ottl = 0;
    if(rdata_size >= 8)
    {
        ottl = ntohl(GET_U32_AT(((const u8*)rdata)[4]));
    }
    return ottl;
}

static inline u32 rrsig_get_valid_until_from_rdata(const void *rdata, u16 rdata_size)
{
    u32 t = 0;
    if(rdata_size >= RRSIG_RDATA_HEADER_LEN)
    {
        t = ntohl(GET_U32_AT(((const u8*)rdata)[8]));
    }
    return t;
}

static inline u32 rrsig_get_valid_from_from_rdata(const void *rdata, u16 rdata_size)
{
    u32 t = 0;
    if(rdata_size >= RRSIG_RDATA_HEADER_LEN)
    {
        t = ntohl(GET_U32_AT(((const u8*)rdata)[12]));
    }
    return t;
}

static inline u16 rrsig_get_key_tag_from_rdata(const void *rdata, u16 rdata_size)
{
    u16 tag = 0;
    if(rdata_size >= RRSIG_RDATA_HEADER_LEN)
    {
        tag = ntohs(GET_U16_AT(((const u8*)rdata)[16]));
    }
    return tag;
}

static inline const u8* rrsig_get_signer_name_from_rdata(const void *rdata, u16 rdata_size)
{
    const u8 *signer_name = NULL;
    if(rdata_size >= RRSIG_RDATA_HEADER_LEN)
    {
        signer_name = &((const u8*)rdata)[18];
    }
    return signer_name;
}

#endif /* RFC_H_ */

/** @} */

