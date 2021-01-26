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

#define HAS_DYNAMIC_PROVISIONING 1

#if HAS_DYNAMIC_PROVISIONING
#define     TYPE_ZONE_TYPE_NAME             "ZONETYPE"
#define     TYPE_ZONE_FILE_NAME             "ZONEFILE"
#define     TYPE_ZONE_NOTIFY_NAME           "ZONENOTIFY"
#define     TYPE_ZONE_MASTER_NAME           "MASTER"
#define     TYPE_ZONE_SLAVES_NAME           "SLAVES"
#define     TYPE_ZONE_DNSSEC_NAME           "DNSSEC"
#define     TYPE_ZONE_COMMENT               "COMMENT"
#define     TYPE_SIGINTV_NAME               "SIGINTV"
#define     TYPE_SIGREGN_NAME               "SIGREGN"
#define     TYPE_SIGJITR_NAME               "SIGJITR"
#define     TYPE_NTFRC_NAME                 "NTFRC"
#define     TYPE_NTFRP_NAME                 "NTFRP"
#define     TYPE_NTFRPI_NAME                "NTFRPI"
#define     TYPE_NTFAUTO_NAME               "NTFAUTO"

#define     OPCODE_CTRL                     (9<<OPCODE_SHIFT)

/*
 ACL is a chain of accept/reject triggers on IPv4 IPv6 TSIGs (...)
 valid values are usually any, none, allow ip/mask(4/6), reject ip/mask(4/6), allow tsig
 reject tsig does not makes sense

 0 : any      + 80 none
 1 : v4            !v4
 2 : v6            !v6
 3 : tsig          nonsense

 or

 [0..7] any none v4 !v4 v6 !v6 tsig

 It can only be a single record because order is important
*/

#define     TYPE_ZONE_ALLOW_QUERY           "ACLQUERY" // QUERYCL ?
// ..

#endif

// until all code check the two defines ...

#define     TYPE_CTRL_SHUTDOWN_NAME         "SHUTDOWN"
#define     TYPE_CTRL_ZONERELOAD_NAME       "RELOAD"
#define     TYPE_CTRL_LOGREOPEN_NAME        "LOGREOPEN"     /// @todo 20140528 gve -- needs to be removed (twice declared)
#define     TYPE_CTRL_SRVQUERYLOG_NAME      "QUERYLOG"
#define     TYPE_CTRL_SRVLOGLEVEL_NAME      "LOGLEVEL"


#define     TYPE_CTRL_ZONEFREEZE_NAME       "FREEZE"
#define     TYPE_CTRL_ZONEUNFREEZE_NAME     "UNFREEZE"
#define     TYPE_CTRL_ZONEFREEZEALL_NAME    "FREEZEALL"     // NI
#define     TYPE_CTRL_ZONEUNFREEZEALL_NAME  "UNFREEZEALL"   // NI
#define     TYPE_CTRL_ZONESYNC_NAME         "SYNC"

#define     TYPE_CTRL_SRVLOGREOPEN_NAME     "LOGREOPEN"     /// @todo 20150217 gve -- needs to be removed (twice declared)
#define     TYPE_CTRL_SRVCFGRELOAD_NAME     "CFGRELOAD"

#define     TYPE_CTRL_ZONENOTIFY_NAME       "NOTIFY"



#define     TYPE_CTRL_CFGLOAD_NAME          "CFGLOAD"


#define     TYPE_CTRL_ZONECFGRELOAD_NAME     "ZONECFGRELOAD"
#define     TYPE_CTRL_ZONECFGRELOADALL_NAME  "ZONECFGRELOADALL"
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

#define     TYPE_ZONE_TYPE                  NU16(0x2a01)

/*
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                            PATH                               /    utf-8 text, on windows '/' are converted to '\'
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define     TYPE_ZONE_FILE                  NU16(0x2a02)

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

#define     TYPE_ZONE_NOTIFY           NU16(0x2a03)


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

#define     TYPE_ZONE_MASTER                NU16(0x2a04)

#define ZD_DNSSEC_NONE         0
#define ZD_DNSSEC_NSEC         1
#define ZD_DNSSEC_NSEC3        2
#define ZD_DNSSEC_NSEC3_OPTOUT 3

/*
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                       DNSSEC MODE                             /    8 bits
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define     TYPE_ZONE_DNSSEC                NU16(0x2a05) /* the canonical name of a alias      rfc 1035 */

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

#define     TYPE_ZONE_SLAVES                NU16(0x2a06)

/*
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                             VALUE                             /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define     TYPE_SIGINTV                NU16(0x2a07)

/*
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                             VALUE                             /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define     TYPE_SIGREGN                NU16(0x2a08)

/*
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                             VALUE                             /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define     TYPE_SIGJITR                NU16(0x2a09)

/*
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                             VALUE                             /    notify request count
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define     TYPE_NTFRC                  NU16(0x2a0a)

/*
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                             VALUE                             /    notify request period
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define     TYPE_NTFRP                  NU16(0x2a0b)

/*
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                             VALUE                             /    notify request increment
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define     TYPE_NTFRPI                 NU16(0x2a0c)

/*
                    
    0 1 2 3 4 5 6 7 
   +-+-+-+-+-+-+-+-+
   /V|             /
   +-+-+-+-+-+-+-+-+
*/

#define     TYPE_NTFAUTO                 NU16(0x2a0d)

/*
 * Q: . SRVSHUTDOWN CTRL
 * C: . SRVSHUTDOWN
 */

#define     TYPE_CTRL_SRVSHUTDOWN        NU16(0x2b01)

/*
 * Q: . SRVLOGREOPEN CTRL
 * C: . SRVLOGREOPEN
 */

#define     TYPE_CTRL_SRVLOGREOPEN       NU16(0x2b02)

/*
 * Q: . SRVCFGRELOAD CTRL
 * C: . SRVCFGRELOAD
 */

#define     TYPE_CTRL_SRVCFGRELOAD       NU16(0x2b03)

/*
 * Q: . SRVQUERYLOG CTRL
 * C: . SRVQUERYLOG on_off
 */

#define     TYPE_CTRL_SRVQUERYLOG        NU16(0x2b04)

/*
 * Q: . SRVLOGLEVEL CTRL
 * C: . SRVLOGLEVEL level
 * 
 * level is one byte, values 0->15 (4 higher bits reserved) ... or don't we set a limit ?
 */

#define     TYPE_CTRL_SRVLOGLEVEL        NU16(0x2b05)

/*
 * Q: . ZONEFREEZE CTRL
 * C: . ZONEFREEZE [fqdn class view]
 * 
 * if rdata size > 0, rdata is FQDN [2 bytes] [0->n utf8/asciiz? bytes]
 */

#define     TYPE_CTRL_ZONEFREEZE            NU16(0x2b06)

/*
 * Q: . ZONEUNFREEZE CTRL
 * C: . ZONEUNFREEZE [fqdn class view]
 * 
 * if rdata size > 0, rdata is FQDN [2 bytes] [0->n utf8/asciiz? bytes]
 */

#define     TYPE_CTRL_ZONEUNFREEZE          NU16(0x2b07)

/*
 * Q: . ZONESYNC CTRL
 * C: . ZONESYNC clean [fqdn class view]
 * 
 * clean is one byte, values 0->1 (7 higher bits reserved)
 * if rdata size > 0, rdata is FQDN [2 bytes] [0->n utf8/asciiz? bytes]
*/

#define     TYPE_CTRL_ZONESYNC              NU16(0x2b08)

/*
 * Q: . ZONENOTIFY CTRL
 * C: . ZONENOTIFY fqdn [class view]
 * 
 * rdata is FQDN [2 bytes] [0->n utf8/asciiz? bytes]
 */

#define     TYPE_CTRL_ZONENOTIFY            NU16(0x2b09)

/*
 * Q: . ZONERELOAD CTRL
 * C: . ZONERELOAD fqdn class view
 * 
 * rdata is FQDN [2 bytes] [0->n utf8/asciiz? bytes]
 */

#define     TYPE_CTRL_ZONERELOAD            NU16(0x2b0a)

/*
 * Q: . ZONECFGRELOAD CTRL
 * C: . ZONECFGRELOAD [fqdn [class [view]]]
 * 
 * rdata is FQDN [2 bytes] [0->n utf8/asciiz? bytes]
 */

#define     TYPE_CTRL_ZONECFGRELOAD         NU16(0x2b0b)
#define     TYPE_CTRL_ZONECFGRELOADALL      NU16(0x2b0c)


/* DOMAIN NAME = zone */
/* RDATASIZE = 0 */

#define     TYPE_CTRL_ZONEFREEZEALL         NU16(0x2b0d)

/* DOMAIN NAME = zone */
/* RDATASIZE = 0 */

#define     TYPE_CTRL_ZONEUNFREEZEALL       NU16(0x2b0e)

/* DOMAIN NAME = . */
/* RDATASIZE = 0 */


/**
 * @}
 */
