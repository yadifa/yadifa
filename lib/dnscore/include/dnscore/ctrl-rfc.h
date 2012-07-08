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
* DOCUMENTATION */
/** @defgroup 
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#define     TYPE_ZONE_TYPE_NAME             "ZONETYPE"
#define     TYPE_ZONE_FILE_NAME             "ZONEFILE"
#define     TYPE_ZONE_ALSO_NOTIFY_NAME      "ZONENOTIFY"
#define     TYPE_ZONE_MASTER_NAME           "MASTER"
#define     TYPE_ZONE_DNSSEC_NAME           "DNSSEC"

#define     TYPE_CTRL_SHUTDOWN_NAME         "SHUTDOWN"
#define     TYPE_CTRL_ZONEFREEZE_NAME       "FREEZE"
#define     TYPE_CTRL_ZONEUNFREEZE_NAME     "UNFREEZE"
#define     TYPE_CTRL_ZONERELOAD_NAME       "RELOAD"
#define     TYPE_CTRL_LOGREOPEN_NAME        "LOGREOPEN"
#define     TYPE_CTRL_CFGMERGE_NAME         "CFGMERGE"
#define     TYPE_CTRL_CFGSAVE_NAME          "CFGSAVE"
#define     TYPE_CTRL_CFGLOAD_NAME          "CFGLOAD"

/*
 * CTRL UPDATE Configuration, Zone
 */

#define     ZT_HINT         0       /**< zone file: hint */
#define     ZT_MASTER       1       /**< zone file: master */
#define     ZT_SLAVE        2       /**< zone file: slave */
#define     ZT_STUB         3       /**< zone file: stub */

/*
    
    0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            TYPE                               |    8 bits type
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define     TYPE_ZONE_TYPE                  NU16(0x2a01)                /* a host address                     rfc 1035 */

/*
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                            PATH                               /    utf-8 text, on windows '/' are converted to '\'
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define     TYPE_ZONE_FILE                  NU16(0x2a02) /* an authoritative name server       rfc 1035 */

#define REMOTE_SERVER_FLAGS_IP_MASK 0x0f
#define REMOTE_SERVER_FLAGS_PORT_MASK 0x10
#define REMOTE_SERVER_FLAGS_KEY_MASK 0x20

/*
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   / IPVER | PORT | KEY |                                          /    4 bits + 1 bit + 1 bit ( 8 bits )
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                            IP                                 /    variable size (4 or 16)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                           PORT                                /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                       TSIG KEYNAME                            /    dns formated domain name
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   
 * ALSONOTIFY 1.2.3.4#8053 my-key
 * ALSONOTIFY ::1#8053 my-key
 * 
 */

#define     TYPE_ZONE_ALSO_NOTIFY           NU16(0x2a03) /* CANONIZE - OBSOLETE                rfc 882 */


/*
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   / IPVER | PORT | KEY |                                          /    4 bits + 1 bit + 1 bit ( 8 bits )
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                            MASTER                             /    
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                           PORT                                /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                       TSIG KEYNAME                            /    dns formated domain name
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#define     TYPE_ZONE_MASTER                NU16(0x2a04) /* CANONIZE - OBSOLETE                rfc 882 */

#define ZD_DNSSEC_NONE         0
#define ZD_DNSSEC_NSEC         1
#define ZD_DNSSEC_NSEC3        2
#define ZD_DNSSEC_NSEC3_OPTOUT 3

/*
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                       DNSSEC MODE                             /    dns formated domain name
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define     TYPE_ZONE_DNSSEC                NU16(0x2a05) /* the canonical name of a alias      rfc 1035 */

/*
 * CTRL QUERY Command, Zone
 */

/* DOMAIN NAME = . */
/* RDATASIZE = 0 */

#define     TYPE_CTRL_SHUTDOWN              NU16(0x2b01)

/* DOMAIN NAME = zone */
/* RDATASIZE = 0 */

#define     TYPE_CTRL_ZONEFREEZE            NU16(0x2b02)

/* DOMAIN NAME = zone */
/* RDATASIZE = 0 */

#define     TYPE_CTRL_ZONEUNFREEZE          NU16(0x2b03)

/* DOMAIN NAME = zone */
/* RDATASIZE = 0 */

#define     TYPE_CTRL_ZONERELOAD            NU16(0x2b08)

/* DOMAIN NAME = . */
/* RDATASIZE = 0 */

#define     TYPE_CTRL_LOGREOPEN             NU16(0x2b04)

/* DOMAIN NAME = . */
/* RDATASIZE = 0 */

#define     TYPE_CTRL_CFGMERGE              NU16(0x2b05)

/* DOMAIN NAME = . */
/* RDATASIZE = 0 */

#define     TYPE_CTRL_CFGSAVE               NU16(0x2b06)

/* DOMAIN NAME = . */
/* RDATASIZE = 0 */

#define     TYPE_CTRL_CFGLOAD               NU16(0x2b07)

/**
 * @}
 */
