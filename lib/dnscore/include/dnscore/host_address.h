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

/** @defgroup dnscoretools Generic Tools
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#ifndef HOST_ADDRESS_H
#define HOST_ADDRESS_H

#include <netdb.h>
#include <sys/socket.h>

#include <dnscore/dnscore.h>
#include <dnscore/network.h>

#define HOSTADDR_TAG 0x5244444154534f48
#define SOCKADD4_TAG 0x344444414b434f53
#define SOCKADD6_TAG 0x364444414b434f53
#define ADDRINFO_TAG 0x4f464e4952444441

struct addrinfo;
struct sockaddr;

#define HOST_ADDRESS_IPV4  0x04
#define HOST_ADDRESS_IPV6  0x06
#define HOST_ADDRESS_DNAME 0xfe
#define HOST_ADDRESS_NONE  0x00

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

/*
 * Flag values for the host_address_to_str(...) function
 */

#define HOST_ADDRESS_TO_STR_PORT            1U  // "1.2.3.4:1234"
#define HOST_ADDRESS_TO_STR_FULLPORT        2U  // "1.2.3.4 port 1234"
#define HOST_ADDRESS_TO_STR_TSIG            4U  // "1.2.3.4*mykey."
#define HOST_ADDRESS_TO_STR_FULLTSIG        8U  // "1.2.3.4 key mykey."
#define HOST_ADDRESS_TO_STR_SHOW_PORT_ZERO 16U  // else hides it

typedef union addressv6 addressv6;

union addressv6
{
    u8  bytes[16];
    u32 dwords[4];
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

//typedef struct tsig_item tsig_item;
#if DNSCORE_HAS_TSIG_SUPPORT
struct tsig_item;
#endif

typedef struct host_address host_address;
struct host_address
{
    struct host_address *next;
#if DNSCORE_HAS_TSIG_SUPPORT
    const struct tsig_item *tsig;                /* pointer to the structure used for TSIG, to be used in relevant cases */
#endif
    union
    {
        addressv4 v4;
        addressv6 v6;
        addressdname dname;
    } ip;
    u16 port;
    u8 version;
};

#define HOST_ADDRESS_EMPTY {NULL, NULL, .ip.v4.value=0, 0, HOST_ADDRESS_NONE}

host_address *host_address_alloc();

host_address *host_address_copy(const host_address *address);


host_address *host_address_copy_list(const host_address *address);

/**
 * Clears the content of a host_address (mostly : deletes the dname if it's
 * what it contains.
 * 
 * @param the host address
 */

void host_address_clear(host_address *address);

/**
 * Deletes a single host addresse
 * 
 * @param the host address
 */

void host_address_delete(host_address *address);

/**
 * Deletes a list of host addresses
 * 
 * @param the first host address from the list
 */


void host_address_delete_list(host_address *address);
void host_address_set_default_port_value(host_address *address, u16 port);
u32 host_address_count(const host_address *address);

static inline bool
host_address_empty(host_address *address)
{
    return (address == NULL);
}

ya_result host_address2addrinfo(const host_address *address, struct addrinfo **sa);
ya_result host_address2allocated_sockaddr(const host_address *address, struct sockaddr **sap);
ya_result host_address2sockaddr(const host_address *address, socketaddress *sap);

/**
 * It does not set the "next" pointer, NONE of the "set" functions do.
 * 
 * @param sa
 * @param address
 * @return 
 */

ya_result host_address_set_with_sockaddr(host_address *address, const socketaddress *sa);
bool host_address_list_contains_ip(const host_address *address_list, const socketaddress *sa);
#if DNSCORE_HAS_TSIG_SUPPORT
bool host_address_list_contains_ip_tsig(const host_address *address_list, const socketaddress *sa, const struct tsig_item *tsig);
#endif
bool host_address_list_contains_host(const host_address *address_list, const host_address *ha);
bool host_address_list_equals(const host_address *a, const host_address *b);

/**
 * Moves the first item at the end of the list.
 * 
 * @param firstp pointer to pointer to the first item of the list
 */

void host_address_list_roll(host_address **firstp);
bool host_address_equals(const host_address *a, const host_address *b);
s32  host_address_compare(const host_address *a, const host_address *b);
bool host_address_is_any(const host_address *ha);
bool host_address_match(const host_address *a, const host_address *b);
void host_address_set_ipv4(host_address *address, const u8 *ipv4, u16 port);
void host_address_set_ipv6(host_address *address, const u8 *ipv6, u16 port);

/**
 * It does not set the "next" pointer, NONE of the "set" functions do.
 * An address set like this will need to be freed with host_address_clear()
 * or deleted with host_address_delete or host_address_delete_list
 * 
 * @param address
 * @param dname
 * @param port
 */

void host_address_set_dname(host_address *address, const u8 *dname, u16 port);
ya_result host_address_append_ipv4(host_address *address, const u8 *ipv4, u16 port);
ya_result host_address_append_ipv6(host_address *address, const u8 *ipv6, u16 port);
ya_result host_address_append_dname(host_address *address, const u8 *dname, u16 port);
ya_result host_address_append_host_address(host_address *address, const host_address *ha);
ya_result host_address_append_hostent(host_address *address, struct hostent *he, u16 port);
ya_result host_address_append_sockaddr(host_address *address, const socketaddress *sa);
ya_result host_address_append_sockaddr_with_port(host_address *address, const socketaddress *sa, u16 port);
host_address *host_address_remove_host_address(host_address **address, host_address *ha_match);
bool host_address_update_host_address_list(host_address **dp, const host_address *s);

static inline const host_address *host_address_get_at_index(const host_address *ha_list, u32 idx)
{
    while((idx > 0) && (ha_list != NULL))
    {
        ha_list = ha_list->next;
        idx--;
    }
    
    return ha_list;
}

/**
 * 
 * host_address_to_str
 * 
 * writes an address to a string, with optional details
 * 
 * @param address
 * @param str
 * @param len
 * @param flags
 * @return 
 */

ya_result host_address_to_str(const host_address *address, char *str, int len, u8 flags);

#endif /* HOST_ADDRESS_H */

/** @} */

