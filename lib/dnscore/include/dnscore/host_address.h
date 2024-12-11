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

/**-----------------------------------------------------------------------------
 * @defgroup dnscoretools Generic Tools
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

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
#define SOCKADDS_TAG 0x534444414b434f53

struct addrinfo;
struct sockaddr;

#define HOST_ADDRESS_IPV4  0x04
#define HOST_ADDRESS_IPV6  0x06
#define HOST_ADDRESS_DNAME 0xfe
#define HOST_ADDRESS_NONE  0x00

typedef union addressv4 addressv4;

union addressv4
{
    uint8_t  bytes[4];
    uint32_t value;
};

#if __unix__
#define SOCKET_PROTOCOL_FROM_TYPE(sock_type__) 0
#else
#define SOCKET_PROTOCOL_FROM_TYPE(sock_type__) (((sock_type__) == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP)
#endif

/*
 * Returns true if all the address bits are set respectively to 0
 */

#define IPV6_ADDRESS_ALL0(_a_)             (((_a_).lohi[0] == 0) && ((_a_).lohi[1] == 0))

/*
 * Returns true if all the address bits are set respectively to 1
 */

#define IPV6_ADDRESS_ALL1(_a_)             (((_a_).lohi[0] == ~0) && ((_a_).lohi[1] == ~0))

/*
 * Flag values for the host_address_to_str(...) function
 */

#define HOST_ADDRESS_TO_STR_PORT           1U  // "1.2.3.4:1234"
#define HOST_ADDRESS_TO_STR_FULLPORT       2U  // "1.2.3.4 port 1234"
#define HOST_ADDRESS_TO_STR_TSIG           4U  // "1.2.3.4*mykey."
#define HOST_ADDRESS_TO_STR_FULLTSIG       8U  // "1.2.3.4 key mykey."
#define HOST_ADDRESS_TO_STR_SHOW_PORT_ZERO 16U // else hides it

typedef union addressv6 addressv6;

union addressv6
{
    uint8_t  bytes[16];
    uint32_t dwords[4];
    uint64_t lohi[2];
};

/*
 * The host_address is also used for notify.
 * It needs to be able to store names as well
 */

typedef union addressdname addressdname;

union addressdname
{
    uint8_t *dname;
};

/*
 * Represents an ip:port.  Linkable.
 * First made for the notification list.
 */

#if DNSCORE_HAS_TSIG_SUPPORT
struct tsig_key_s;
#endif

#define HOST_ADDRESS_TLS_NOT_SET 0
#define HOST_ADDRESS_TLS_DISABLE 1
// #define HOST_ADDRESS_TLS_TRY 2    /// @note 20230612 edf -- wanting TLS but allowing clear fallback seems like a bad
// idea
#define HOST_ADDRESS_TLS_ENFORCE 3

struct host_address_s
{
    struct host_address_s *next;
#if DNSCORE_HAS_TSIG_SUPPORT
    const struct tsig_key_s *tsig; /* pointer to the structure used for TSIG, to be used in relevant cases */
#endif
    union
    {
        addressv4    v4;
        addressv6    v6;
        addressdname dname;
    } ip;
    uint16_t port; // network order
    uint8_t  version;
    uint8_t  tls; // 0 = undefined, 1 = disable, 2 = try, 3 = force
};

typedef struct host_address_s host_address_t;

#define HOST_ADDRESS_EMPTY {NULL, NULL, .ip.v4.value = 0, 0, HOST_ADDRESS_NONE}

host_address_t *host_address_new_instance();

/**
 * Allocates a new instance of host_address with a 4 bytes array and a network-endian port.
 *
 * @param ipv4 4 bytes containing a network-endian IPv4
 * @param port network-endian port
 */

host_address_t *host_address_new_instance_ipv4(const uint8_t *ipv4, uint16_t network_endian_port);

/**
 * Allocates a new instance of host_address with a 16 bytes array and a network-endian port.
 *
 * @param ipv6 16 bytes containing a network-endian IPv6
 * @param port network-endian port
 */

host_address_t *host_address_new_instance_ipv6(const uint8_t *ipv6, uint16_t network_endian_port);

/**
 * Allocates a new instance of host_address with an fqdn and a network-endian port.
 *
 * @param dname an fqdn
 * @param port network-endian port
 */

host_address_t *host_address_new_instance_dname(const uint8_t *dname, uint16_t network_endian_port);
host_address_t *host_address_new_instance_socketaddress(const socketaddress_t *sa);

/**
 * Allocates a new instance of host_address with a 4 bytes array, a network-endian port and a TSIG key.
 *
 * @param ipv4 4 bytes containing a network-endian IPv4
 * @param port network-endian port
 * @param tsig the tsig key
 */

host_address_t *host_address_new_instance_ipv4_tsig(const uint8_t *ipv4, uint16_t network_endian_port, const struct tsig_key_s *tsig);

/**
 * Allocates a new instance of host_address with a 16 bytes array, a network-endian port and a TSIG key.
 *
 * @param ipv6 16 bytes containing a network-endian IPv6
 * @param port network-endian port
 * @param tsig the tsig key
 */

host_address_t *host_address_new_instance_ipv6_tsig(const uint8_t *ipv6, uint16_t network_endian_port, const struct tsig_key_s *tsig);

/**
 * Allocates a new instance of host_address with an fqdn, a network-endian port and a TSIG key.
 *
 * @param dname an fqdn
 * @param port network-endian port
 * @param tsig the tsig key
 */

host_address_t *host_address_new_instance_dname_tsig(const uint8_t *dname, uint16_t network_endian_port, const struct tsig_key_s *tsig);

/**
 * Allocates a new instance of host_address from the text-representation of an IP address.
 *
 * @param ip_to_parse the text representation of an IP address
 */

host_address_t *host_address_new_instance_parse(const char *ip_to_parse);

/**
 * Allocates a new instance of host_address from the text-representation of an IP address, as well as a port
 *
 * @param ip_to_parse the text representation of an IP address
 * @param port the native representation of a port
 */

host_address_t *host_address_new_instance_parse_port(const char *ip_to_parse, int port);

host_address_t *host_address_copy(const host_address_t *address);

host_address_t *host_address_copy_list(const host_address_t *address);

/**
 * Clears the content of a host_address (mostly : deletes the dname if it's
 * what it contains.
 *
 * @param the host address
 */

void host_address_finalise(host_address_t *address);

/**
 * Deletes a single host addresse
 *
 * @param the host address
 */

void host_address_delete(host_address_t *address);

/**
 * Deletes a list of host addresses
 *
 * @param the first host address from the list
 */

void host_address_delete_list(host_address_t *address);
// sets the port value to port for all addresses in that list where port is set to 0
void host_address_set_default_port_value(host_address_t *address, uint16_t network_endian_port);
// sets the port value to port for all addresses in that list
void               host_address_set_port_value(host_address_t *address, uint16_t network_endian_port);
uint32_t           host_address_count(const host_address_t *address);

static inline bool host_address_empty(host_address_t *address) { return (address == NULL); }

/**
 * Converts an host_address to a addrinfo
 * Must can be freed by "free"
 */

ya_result host_address2addrinfo(const host_address_t *address, struct addrinfo **sa);
ya_result host_address2allocated_sockaddr(const host_address_t *address, struct sockaddr **sap);
ya_result host_address2sockaddr(const host_address_t *address, socketaddress_t *sap);

/**
 * It does not set the "next" pointer, NONE of the "set" functions do.
 *
 * @param sa
 * @param address
 * @return
 */

ya_result host_address_set_with_socketaddress(host_address_t *address, const socketaddress_t *sa);
bool      host_address_list_contains_ip(const host_address_t *address_list, const socketaddress_t *sa);
#if DNSCORE_HAS_TSIG_SUPPORT
bool host_address_list_contains_ip_tsig(const host_address_t *address_list, const socketaddress_t *sa, const struct tsig_key_s *tsig);
#endif
bool host_address_list_contains_host(const host_address_t *address_list, const host_address_t *ha);
bool host_address_list_equals(const host_address_t *a, const host_address_t *b);

/**
 * Moves the first item at the end of the list.
 *
 * @param firstp pointer to pointer to the first item of the list
 */

void host_address_list_roll(host_address_t **firstp);

/**
 * Compares the host address
 * The port is not part of the comparison.
 *
 * @param a host_address_t
 * @param b host_address_t
 * @return true if a & b are the same type and have the same ip/domain (port being ignored)
 */

bool host_address_equals(const host_address_t *a, const host_address_t *b);

/**
 * Compares the host address
 *
 * Compares, in order, version/ip/port/tls
 *
 * @param a host_address_t
 * @param b host_address_t
 * @return <0 if a < b, 0 if a == b, >0 if a > b
 */

int32_t host_address_compare(const host_address_t *a, const host_address_t *b);
bool    host_address_is_any(const host_address_t *ha);
bool    host_address_match(const host_address_t *a, const host_address_t *b);
void    host_address_set_ipv4(host_address_t *address, const uint8_t *ipv4, uint16_t network_endian_port);
void    host_address_set_ipv6(host_address_t *address, const uint8_t *ipv6, uint16_t network_endian_port);

/**
 * It does not set the "next" pointer, NONE of the "set" functions do.
 * An address set like this will need to be freed with host_address_finalise()
 * or deleted with host_address_delete or host_address_delete_list
 *
 * @param address
 * @param dname
 * @param port network-endian port
 */

void      host_address_set_dname(host_address_t *address, const uint8_t *dname, uint16_t network_endian_port);
ya_result host_address_append_ipv4(host_address_t *address, const uint8_t *ipv4, uint16_t network_endian_port);
ya_result host_address_append_ipv6(host_address_t *address, const uint8_t *ipv6, uint16_t network_endian_port);
ya_result host_address_append_dname(host_address_t *address, const uint8_t *dname, uint16_t network_endian_port);
ya_result host_address_append_host_address(host_address_t *address, const host_address_t *ha);
#if DEPRECATED
ya_result host_address_append_hostent(host_address_t *address, struct hostent *he, uint16_t network_endian_port);
#endif
ya_result host_address_append_sockaddr(host_address_t *address, const socketaddress_t *sa);
/**
 * Ignores duplicates.
 */
ya_result       host_address_append_sockaddr_with_port(host_address_t *address, const socketaddress_t *sa, uint16_t network_endian_port);
host_address_t *host_address_remove_host_address(host_address_t **address, host_address_t *ha_match);

/**
 * Replaces host_address_t from the first list with the ones from the second list.
 * Avoids reallocations: items already present are kept.
 *
 * @param dp the first list
 * @param s the second list
 *
 * @return true iff the first list has been changed.
 */

bool                                host_address_update_host_address_list(host_address_t **dp, const host_address_t *s);

static inline const host_address_t *host_address_get_at_index(const host_address_t *ha_list, uint32_t idx)
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

ya_result host_address_to_str(const host_address_t *address, char *str, int len, uint8_t flags);

#endif /* HOST_ADDRESS_H */

/** @} */
