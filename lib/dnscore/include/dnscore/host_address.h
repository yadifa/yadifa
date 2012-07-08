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
/** @defgroup dnscoretools Generic Tools
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#ifndef HOST_ADDRESS_H
#define HOST_ADDRESS_H

#include <dnscore/dnscore.h>
#include <dnscore/tsig.h>

#include <dnscore/network.h>

#define HOSTADDR_TAG 0x5244444154534f48
#define SOCKADD4_TAG 0x344444414b434f53
#define SOCKADD6_TAG 0x364444414b434f53

struct addrinfo;
struct sockaddr;

#define HOST_ADDRESS_IPV4  0x04
#define HOST_ADDRESS_IPV6  0x06
#define HOST_ADDRESS_DNAME 0xfe

typedef union addressv4 addressv4;

union addressv4
{
    u8 bytes[4];
    u32 value;
};


/*
 * Returns true if all the address bits are set respectively to 0
 */
    
#define IPV6_ADDRESS_ALL0(_a_) (((_a_).lohi[0] == 0) && ((_a_).lohi[1] == 0))

/*
 * Returns true if all the address bits are set respectively to 1
 */

#define IPV6_ADDRESS_ALL1(_a_) (((_a_).lohi[0] == ~0) && ((_a_).lohi[1] == ~0))
    

typedef union addressv6 addressv6;

union addressv6
{
    u8  bytes[16];
    u64 lohi[2];
};

/*
 * The host_address is also used for notify.
 * It needs to be able to store names as well
 */

typedef union addressdname addressdname;

union addressdname
{
    u8 *dname;
};

/*
 * Represents an ip:port.  Linkable.
 * First made for the notification list.
 */

typedef struct host_address host_address;
struct host_address
{
    struct host_address *next;
    tsig_item *tsig;                /* pointer to the structure used for TSIG, to be used in relevant cases */
    union
    {
        addressv4 v4;
        addressv6 v6;
        addressdname dname;
    } ip;
    u16 port;
    u8 version;
};

host_address *host_address_copy_list(host_address *address);
void host_address_delete(host_address *address);
void host_address_delete_list(host_address *address);
void host_set_default_port_value(host_address *address, u16 port);
u32 host_address_count(host_address *address);
ya_result host_address2addrinfo(struct addrinfo **sa, host_address *address);
ya_result host_address2allocated_sockaddr(struct sockaddr **sap, host_address *address);
ya_result host_address2sockaddr(socketaddress *sap, host_address *address);
ya_result host_address_set_with_sockaddr(host_address *address, const socketaddress *sa);
bool host_address_list_contains_ip(host_address *address, const socketaddress *sa);
bool host_address_list_contains_host(host_address *address, const host_address *ha);
bool host_address_equals(host_address *a, host_address *b);
bool host_address_match(host_address *a, host_address *b);
void host_address_set_ipv4(host_address *address, u8 *ipv4, u16 port);
void host_address_set_ipv6(host_address *address, u8 *ipv6, u16 port);
void host_address_set_dname(host_address *address, u8 *dname, u16 port);
ya_result host_address_append_ipv4(host_address *address, u8 *ipv4, u16 port);
ya_result host_address_append_ipv6(host_address *address, u8 *ipv6, u16 port);
ya_result host_address_append_dname(host_address *address, u8 *dname, u16 port);
ya_result host_address_append_host_address(host_address *address, host_address *ha);
ya_result host_address_append_hostent(host_address *address, struct hostent *he, u16 port);
host_address *host_address_remove_host_address(host_address **address, host_address *ha_match);

#endif /* HOST_ADDRESS_H */

/** @} */

