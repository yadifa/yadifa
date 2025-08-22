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
 * @defgroup dnspacket DNS Messages
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

/*    ------------------------------------------------------------    */

#include <dnscore/dnscore_config_features.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <dnscore/thread.h>

#include <dnscore/rfc.h>
#include <dnscore/sys_types.h>
#include <dnscore/fingerprint.h>
#include <dnscore/host_address.h>
#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>
#include <dnscore/tsig.h>
#include <dnscore/network.h>
#include <dnscore/fdtools.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/format.h>

#include <dnscore/logger.h>

// Processing flags

#define PROCESS_FL_ADDITIONAL_AUTH         0x01
#define PROCESS_FL_AUTHORITY_AUTH          0x02
#define PROCESS_FL_ADDITIONAL_CACHE        0x04
#define PROCESS_FL_AUTHORITY_CACHE         0x08
#define PROCESS_FL_RECURSION               0x20
#define PROCESS_FL_TCP                     0x80

#define NETWORK_BUFFER_SIZE                65536

#define DNS_MESSAGE_HAS_POOL               0

#define DNSCORE_MESSAGE_PAYLOAD_IS_POINTER 1

#define DNSCORE_MESSAGE_HAS_TIMINGS        0

/**
 * @note buffer MUST be aligned on 16 bits
 */

#define MESSAGE_HIFLAGS(buffer_)           ((buffer_)[2])
#define MESSAGE_LOFLAGS(buffer_)           ((buffer_)[3])

#define MESSAGE_FLAGS(buffer_)             GET_U16_AT((buffer_)[2])

#if DNSCORE_HAS_TSIG_SUPPORT
#define TSIGOTHR_TAG 0x5248544f47495354
#endif

#define SMMMSGS_TAG 0x5347534d4d4d53
#define MMSGHDR_TAG 0x52444847534d4d

/* Only use constants with this */
#if AVOID_ANTIALIASING

static inline void MESSAGE_FLAGS_OR_P(void *address, uint16_t f)
{
    uint16_t *p = (uint16_t *)address;
    *p |= f;
}

static inline void MESSAGE_FLAGS_AND_P(void *address, uint16_t f)
{
    uint16_t *p = (uint16_t *)address;
    *p &= f;
}

struct dns_packet_writer;
struct dns_resource_record;

#ifdef WORDS_BIGENDIAN
#define MESSAGE_FLAGS_OR(buffer_, hi_, lo_)  MESSAGE_FLAGS_OR_P(&(buffer_)[2], (uint16_t)((uint16_t)((lo_) & 0xff) | ((uint16_t)(hi_) << 8)))
#define MESSAGE_FLAGS_AND(buffer_, hi_, lo_) MESSAGE_FLAGS_AND_P(&(buffer_)[2], (uint16_t)((uint16_t)((lo_) & 0xff) | ((uint16_t)(hi_) << 8)))
#define MESSAGE_FLAGS_SET(buffer_, hi_, lo_) SET_U16_AT_P(&(buffer_)[2], (uint16_t)((uint16_t)((lo_) & 0xff) | ((uint16_t)hi_ << 8)))
#else
#define MESSAGE_FLAGS_OR(buffer_, hi_, lo_)  MESSAGE_FLAGS_OR_P(&(buffer_)[2], (uint16_t)(((uint16_t)((hi_) & 0xff)) | (((uint16_t)(lo_)) << 8)))
#define MESSAGE_FLAGS_AND(buffer_, hi_, lo_) MESSAGE_FLAGS_AND_P(&(buffer_)[2], (uint16_t)(((uint16_t)((hi_) & 0xff)) | (((uint16_t)(lo_)) << 8)))
#define MESSAGE_FLAGS_SET(buffer_, hi_, lo_) SET_U16_AT_P(&(buffer_)[2], (uint16_t)(((uint16_t)((hi_) & 0xff)) | (((uint16_t)(lo_)) << 8)))
#endif

#define MESSAGE_ID(buffer_)          GET_U16_AT_P(&(buffer_)[0])
#define MESSAGE_SET_ID(buffer_, id_) SET_U16_AT_P(&(buffer_)[0], (id_))

#else

#ifdef WORDS_BIGENDIAN
#define MESSAGE_FLAGS_OR(buffer_, hi_, lo_)  *((uint16_t *)&(buffer_[2])) |= (lo_ | ((uint16_t)hi_ << 8))
#define MESSAGE_FLAGS_AND(buffer_, hi_, lo_) *((uint16_t *)&(buffer_[2])) &= (lo_ | ((uint16_t)hi_ << 8))
#define MESSAGE_FLAGS_SET(buffer_, hi_, lo_) *((uint16_t *)&(buffer_[2])) = (lo_ | ((uint16_t)hi_ << 8))
#else
#define MESSAGE_FLAGS_OR(buffer_, hi_, lo_)  *((uint16_t *)&(buffer_[2])) |= (hi_ | ((uint16_t)lo_ << 8))
#define MESSAGE_FLAGS_AND(buffer_, hi_, lo_) *((uint16_t *)&(buffer_[2])) &= (hi_ | ((uint16_t)lo_ << 8))
#define MESSAGE_FLAGS_SET(buffer_, hi_, lo_) *((uint16_t *)&(buffer_[2])) = (hi_ | ((uint16_t)lo_ << 8))
#endif

#define MESSAGE_ID(buffer)           (*((uint16_t *)&(buffer)[0]))
#define MESSAGE_SET_ID(buffer_, id_) (*((uint16_t *)&(buffer)[0])) = (id_)

#endif

#define MESSAGE_QR(buffer_)                    (MESSAGE_HIFLAGS(buffer_) & QR_BITS)
#define MESSAGE_OP(buffer_)                    (MESSAGE_HIFLAGS(buffer_) & OPCODE_BITS)
#define MESSAGE_AA(buffer_)                    (MESSAGE_HIFLAGS(buffer_) & AA_BITS)
#define MESSAGE_TC(buffer_)                    (MESSAGE_HIFLAGS(buffer_) & TC_BITS)
#define MESSAGE_RD(buffer_)                    (MESSAGE_HIFLAGS(buffer_) & RD_BITS)

#define MESSAGE_RA(buffer_)                    (MESSAGE_LOFLAGS(buffer_) & RA_BITS)
#define MESSAGE_ZF(buffer_)                    (MESSAGE_LOFLAGS(buffer_) & Z_BITS)
#define MESSAGE_AD(buffer_)                    (MESSAGE_LOFLAGS(buffer_) & AD_BITS)
#define MESSAGE_CD(buffer_)                    (MESSAGE_LOFLAGS(buffer_) & CD_BITS)
#define MESSAGE_RCODE(buffer_)                 (MESSAGE_LOFLAGS(buffer_) & RCODE_BITS)

// the size of the section by index [0;3]

#define MESSAGE_SECTION_COUNT(buffer_, index_) GET_U16_AT(((buffer_)[4 + ((index_) << 1)]))

#define MESSAGE_QD(buffer_)                    GET_U16_AT((buffer_)[4])
#define MESSAGE_AN(buffer_)                    GET_U16_AT((buffer_)[6])
#define MESSAGE_NS(buffer_)                    GET_U16_AT((buffer_)[8])
#define MESSAGE_AR(buffer_)                    GET_U16_AT((buffer_)[10])
#define MESSAGE_NSAR(buffer_)                  GET_U32_AT((buffer_)[8])

#define MESSAGE_SET_OP(buffer_, val_)          (MESSAGE_HIFLAGS(buffer_) = (MESSAGE_HIFLAGS(buffer_) & ~OPCODE_BITS) | (val_))

#define MESSAGE_SET_QD(buffer_, val_)          SET_U16_AT((buffer_)[4], (val_))
#define MESSAGE_SET_AN(buffer_, val_)          SET_U16_AT((buffer_)[6], (val_))
#define MESSAGE_SET_NS(buffer_, val_)          SET_U16_AT((buffer_)[8], (val_))
#define MESSAGE_SET_AR(buffer_, val_)          SET_U16_AT((buffer_)[10], (val_))
#define MESSAGE_SET_NSAR(buffer_, val_)        SET_U32_AT((buffer_)[8], (val_))

/* DYNUPDATE rfc 2136 */
#define MESSAGE_ZO(buffer_)                    GET_U16_AT((buffer_)[4])
#define MESSAGE_PR(buffer_)                    GET_U16_AT((buffer_)[6])
#define MESSAGE_UP(buffer_)                    GET_U16_AT((buffer_)[8])

#define MESSAGE_SET_ZO(buffer_, val_)          SET_U16_AT((buffer_)[4], (val_))
#define MESSAGE_SET_PR(buffer_, val_)          SET_U16_AT((buffer_)[6], (val_))
#define MESSAGE_SET_UP(buffer_, val_)          SET_U16_AT((buffer_)[8], (val_))

// #define MESSAGE_AD(buffer)	(*((uint16_t*)&(buffer)[10]))

#define MESGDATA_TAG                           0x415441444753454d

#define MESSAGE_OPT_EDNS0                      1
#define MESSAGE_OPT_NSID                       2
#define MESSAGE_OPT_COOKIE                     4

#if DNSCORE_HAS_TSIG_SUPPORT

struct message_tsig_s
{
    const tsig_key_t *tsig;

    uint16_t          reserved_0; /* ALIGN32 */
    uint16_t          timehi;     /* NETWORK */

    uint32_t          timelo; /* NETWORK */

    uint16_t          fudge;    /* NETWORK */
    uint16_t          mac_size; /* NATIVE  */

    uint16_t          original_id; /* NETWORK */
    uint16_t          error;       /* NETWORK */

    uint16_t          other_len;   /* NETWORK */
    uint16_t          tsig_offset; // keeps the tsig_offset in the message for internal processing, do not use directly

    uint32_t          reserved_2; /* ALIGN64 */

    uint8_t           mac[64];
    uint8_t          *other; // the 'other' field in the TSIG wire

    tsig_hmac_t       hmac;               /* only used for tcp */
    int8_t            tcp_tsig_countdown; /* maximum value is supposed to be 100 */
    uint8_t           mac_algorithm;
};

typedef struct message_tsig_s message_tsig_t;

#endif

/* A memory pool for the lookup's benefit */

#define MESSAGE_POOL_SIZE                0x20000

// flags for MESSAGE_MAKE_QUERY_EX
#define MESSAGE_EDNS0_SIZE               0x4000 // any bit that is not set in EDNS0

#define MESSAGE_BUFFER_SIZE              0x10500

#define MESSAGE_DATA_CONTROL_BUFFER_SIZE 64

#if DNSCORE_HAS_LITTLE_ENDIAN

#define MESSAGE_EDNS0_DNSSEC 0x00800000

struct dns_message_opt_ttl_s
{
    uint8_t  extended_rcode;
    uint8_t  version;
    uint16_t flags;
};

#else

#define MESSAGE_EDNS0_DNSSEC 0x0080

struct dns_message_opt_ttl_s
{
    uint16_t flags;
    uint8_t  version;
    uint8_t  extended_rcode;
};
#endif

union dns_message_opt_ttl_u
{
    struct dns_message_opt_ttl_s fields;
    uint32_t                     as_u32;
};

typedef union dns_message_opt_ttl_u dns_message_opt_ttl_t;

#define DNS_MESSAGE_COOKIE_CLIENT_SIZE     8
#define DNS_MESSAGE_COOKIE_SERVER_SIZE     8
#define DNS_MESSAGE_COOKIE_SERVER_SIZE_MAX 32

struct dns_message_cookie_s
{
    uint8_t bytes[40];
    // uint8_t _client_cookie[8];
    // uint8_t _server_cookie[32];
    int size;
};

typedef struct dns_message_cookie_s dns_message_cookie_t;

struct dns_message_s
{
    struct msghdr   _msghdr;
    struct iovec    _iovec;
    socketaddress_t _sender;   // who the sender is
    uint8_t        *_ar_start; // for the TSIG

    // THIS CROUP IS COPIED USING A MEMCPY IN message_dup() ->

    dns_message_opt_ttl_t _edns0_opt_ttl; // network endian
    finger_print          _status;        // contains an RCODE
#if DNSCORE_MESSAGE_PAYLOAD_IS_POINTER
    uint32_t _message_data_size; // the size of the allocated message structure
#endif
    uint16_t _query_type;
    uint16_t _query_class;

    uint8_t  _opt;

    uint8_t  _referral;
    uint8_t  _control_buffer_size;
#if NOTUSED
    uint8_t _tcp_serial;
#endif

    /* bool is_delegation; for quick referral : later */

    uint32_t _buffer_size;       // 32 bits aligned      // the maximum number of bytes we are ready to fill (can be changed)
    uint32_t _buffer_size_limit; //                      // the maximum number of bytes we can ever fill (as the buffer
                                 //                      size is limited and )

#if DNS_MESSAGE_HAS_POOL // prior versions of yadifa needed a pool, not anymore
    void *_pool;         // a pool to be used as a quick memory for the message
    int   _pool_size;    // a zdb query will store some temporary records in it. Consider size to be from 64K to 128K.
#endif

#if DNSCORE_HAS_TSIG_SUPPORT
    message_tsig_t _tsig;
#endif

    void *channel;

#if DNSCORE_MESSAGE_HAS_TIMINGS
    volatile uint64_t recv_us;
    volatile uint64_t pushed_us;
    volatile uint64_t popped_us;
#endif

    // <- THIS GROUP IS COPIED USING A MEMCPY IN message_dup()

    uint8_t _msghdr_control_buffer[(MESSAGE_DATA_CONTROL_BUFFER_SIZE + 7) & ~7]; // receives the destination address,
                                                                                 // IF MOVED, YOU NEED TO LOOK AT
                                                                                 // message_new_instance() ZEROMEMORY
                                                                                 // call
    uint8_t _canonised_fqdn[(DOMAIN_LENGTH_MAX + 7) & ~7];

    dns_message_cookie_t _cookie;

    /* Ensure (buffer - buffer_tcp_len) is equal to 2 ! */
#if DNSCORE_MESSAGE_PAYLOAD_IS_POINTER
    uint8_t *_buffer;
#else
    uint64_t __reserved_force_align__1;    // 64 bits aligned
    uint16_t __reserved_force_align__2;    // 32 bits aligned
    uint8_t  _buffer_tcp_len[2];           // DON'T SEPARATE THESE TWO (FIRST)
    uint8_t  _buffer[NETWORK_BUFFER_SIZE]; // DON'T SEPARATE THESE TWO (SECOND)
#endif
};

typedef struct dns_message_s dns_message_t;

#define DNSMSGB_TAG 0x4247534d534e44

struct dns_message_with_buffer_s
{
    dns_message_t message;
#if DNSCORE_MESSAGE_PAYLOAD_IS_POINTER
    uint64_t __reserved_force_align__1;    // 64 bits aligned
    uint8_t  _buffer[NETWORK_BUFFER_SIZE]; // DON'T SEPARATE THESE TWO (SECOND)
    uint8_t  _buffer_limit[1];
#endif
};

typedef struct dns_message_with_buffer_s dns_message_with_buffer_t;

struct dns_message_update_s
{
    struct dns_message_update_s *next;
    uint32_t                     zttl;
    uint16_t                     ztype;
    uint16_t                     zclass;
    uint8_t                      zname[DOMAIN_LENGTH_MAX];
    output_stream_t              zrdata[RDATA_LENGTH_MAX + 1];
    uint8_t                     *zrdata2;
    uint16_t                     zrdata_len;
};

typedef struct dns_message_update_s dns_message_update_t;

/**
 * A message_map is a message_data wrapper that got the records indexed
 * Each vector entry points to the FQDN of a record in the message.
 */

struct dns_message_map_s
{
    const dns_message_t *mesg;
    ptr_vector_t         records;
    uint16_t             section_base[4];
};

typedef struct dns_message_map_s dns_message_map_t;

/*    ------------------------------------------------------------    */

/**
 * Sets the global value for the TSIG fudge parameter.
 * Default: 300
 *
 * It's not a good idea to change this value.
 *
 * @param fudge the fudge value in seconds
 */

void dns_message_fudge_set(uint16_t fudge);

/**
 * This sets a default, global, rate for functions supporting it.
 * Rate is used in TCP streaming so that if the other end reads or writes
 * too slowly then the connection is severed, harshly.
 *
 * @param rate
 */

void dns_message_set_minimum_troughput_default(double rate);

/*    ------------------------------------------------------------    */

static inline void dns_message_set_protocol(dns_message_t *mesg, uint8_t protocol)
{
    // THIS SEEMS POINTLESS AS IT'S ONLY USED FOR LOGGING
    (void)mesg;
    (void)protocol;
}

static inline uint8_t dns_message_get_protocol(const dns_message_t *mesg)
{
    // THIS SEEMS POINTLESS AS IT'S ONLY USED FOR LOGGING
    (void)mesg;
    return 0;
}

/**
 *
 * The hope here is that the compiler will be smart enough to translates this as
 * one move. (mov)
 *
 * @param mesg
 * @param qd
 * @param an
 * @param ns
 * @param ar
 */

static inline void dns_message_set_query_answer_authority_additional_counts_ne(dns_message_t *mesg, uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar)
{
#ifdef WORDS_BIGENDIAN
    uint64_t value = (((uint64_t)qd) << 48) | (((uint64_t)an) << 32) | (((uint64_t)ns) << 16) | (((uint64_t)ar));
#else
    uint64_t value = (((uint64_t)qd)) | (((uint64_t)an) << 16) | (((uint64_t)ns) << 32) | (((uint64_t)ar) << 48);
#endif
    SET_U64_AT(mesg->_buffer[4], value);
}

static inline void dns_message_set_query_answer_authority_additional_counts(dns_message_t *mesg, uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar)
{
#ifdef WORDS_BIGENDIAN
    uint64_t value = (((uint64_t)ntohs(qd)) << 48) | (((uint64_t)ntohs(an)) << 32) | (((uint64_t)ntohs(ns)) << 16) | (((uint64_t)ntohs(ar)));
#else
    uint64_t value = (((uint64_t)ntohs(qd))) | (((uint64_t)ntohs(an)) << 16) | (((uint64_t)ntohs(ns)) << 32) | (((uint64_t)ntohs(ar)) << 48);
#endif
    SET_U64_AT(mesg->_buffer[4], value);
}

static inline void dns_message_set_authority_additional_counts_ne(dns_message_t *mesg, uint16_t ns, uint16_t ar)
{
#ifdef WORDS_BIGENDIAN
    uint32_t value = (((uint32_t)ns) << 16) | (((uint32_t)ar));
#else
    uint32_t value = (((uint32_t)ns)) | (((uint32_t)ar) << 16);
#endif
    MESSAGE_SET_NSAR(mesg->_buffer, value);
}

#if DNS_MESSAGE_HAS_POOL
static inline void dns_message_set_pool_buffer(dns_message_t *mesg, void *p, int size)
{
    mesg->_pool = p;
    mesg->_pool_size = size;
}

static inline void *dns_message_get_pool_buffer(const dns_message_t *mesg) { return mesg->_pool; }

static inline int   dns_message_get_pool_size(const dns_message_t *mesg) { return mesg->_pool_size; }
#endif

static inline uint8_t dns_message_get_opcode(const dns_message_t *mesg) { return MESSAGE_OP(mesg->_buffer); }

static inline uint8_t dns_message_make_opcode(uint8_t unshifted_opcode) { return unshifted_opcode << OPCODE_SHIFT; }

static inline void    dns_message_set_opcode(dns_message_t *mesg, uint8_t opcode) { MESSAGE_SET_OP(mesg->_buffer, opcode); }

static inline void    dns_message_set_referral(dns_message_t *mesg, uint8_t referral) { mesg->_referral = referral; }

static inline uint8_t dns_message_get_referral(const dns_message_t *mesg) { return mesg->_referral; }

// Network Endian operations

static inline uint16_t dns_message_get_query_count_ne(const dns_message_t *mesg) { return MESSAGE_QD(mesg->_buffer); }

static inline void     dns_message_set_answer_count_ne(dns_message_t *mesg, uint16_t network_endian_value) { MESSAGE_SET_AN(mesg->_buffer, network_endian_value); }

static inline uint16_t dns_message_get_answer_count_ne(const dns_message_t *mesg) { return MESSAGE_AN(mesg->_buffer); }

static inline void     dns_message_set_authority_count_ne(dns_message_t *mesg, uint16_t network_endian_value) { MESSAGE_SET_NS(mesg->_buffer, network_endian_value); }

static inline uint16_t dns_message_get_authority_count_ne(const dns_message_t *mesg) { return MESSAGE_NS(mesg->_buffer); }

static inline void     dns_message_set_additional_count_ne(dns_message_t *mesg, uint16_t network_endian_value) { MESSAGE_SET_AR(mesg->_buffer, network_endian_value); }

static inline uint16_t dns_message_get_additional_count_ne(const dns_message_t *mesg) { return MESSAGE_AR(mesg->_buffer); }

static inline void     dns_message_set_update_count_ne(dns_message_t *mesg, uint16_t network_endian_value) { MESSAGE_SET_UP(mesg->_buffer, network_endian_value); }

static inline uint16_t dns_message_get_update_count_ne(const dns_message_t *mesg) { return MESSAGE_UP(mesg->_buffer); }

static inline uint16_t dns_message_get_prerequisite_count_ne(const dns_message_t *mesg) { return MESSAGE_PR(mesg->_buffer); }

static inline uint16_t dns_message_get_section_count_ne(const dns_message_t *mesg, int section) { return MESSAGE_SECTION_COUNT(mesg->_buffer, section); }

// Host endian

static inline uint16_t dns_message_get_query_count(const dns_message_t *mesg) { return ntohs(dns_message_get_query_count_ne(mesg)); }

static inline void     dns_message_set_answer_count(dns_message_t *mesg, uint16_t host_endian_value) { dns_message_set_answer_count_ne(mesg, htons(host_endian_value)); }

static inline uint16_t dns_message_get_answer_count(const dns_message_t *mesg) { return ntohs(dns_message_get_answer_count_ne(mesg)); }

static inline void     dns_message_set_authority_count(dns_message_t *mesg, uint16_t host_endian_value) { dns_message_set_authority_count_ne(mesg, htons(host_endian_value)); }

static inline uint16_t dns_message_get_authority_count(const dns_message_t *mesg) { return ntohs(dns_message_get_authority_count_ne(mesg)); }

static inline void     dns_message_set_additional_count(dns_message_t *mesg, uint16_t host_endian_value) { dns_message_set_additional_count_ne(mesg, htons(host_endian_value)); }

static inline uint16_t dns_message_get_additional_count(const dns_message_t *mesg) { return ntohs(dns_message_get_additional_count_ne(mesg)); }

static inline void     dns_message_add_additional_count(dns_message_t *mesg, uint16_t value) { dns_message_set_additional_count(mesg, dns_message_get_additional_count(mesg) + value); }

static inline void     dns_message_sub_additional_count(dns_message_t *mesg, uint16_t value) { dns_message_set_additional_count(mesg, dns_message_get_additional_count(mesg) - value); }

static inline void     dns_message_set_update_count(dns_message_t *mesg, uint16_t host_endian_value) { dns_message_set_update_count_ne(mesg, htons(host_endian_value)); }

static inline uint16_t dns_message_get_update_count(const dns_message_t *mesg) { return ntohs(dns_message_get_update_count_ne(mesg)); }

static inline void     dns_message_add_update_count(dns_message_t *mesg, uint16_t host_endian_value) { dns_message_set_update_count(mesg, dns_message_get_update_count(mesg) + host_endian_value); }

static inline uint16_t dns_message_get_prerequisite_count(const dns_message_t *mesg) { return ntohs(dns_message_get_prerequisite_count_ne(mesg)); }

static inline uint16_t dns_message_get_section_count(const dns_message_t *mesg, int section) { return ntohs(dns_message_get_section_count_ne(mesg, section)); }

//

static inline bool dns_message_is_query(const dns_message_t *mesg) { return MESSAGE_QR(mesg->_buffer) == 0; }

static inline bool dns_message_is_answer(const dns_message_t *mesg) { return MESSAGE_QR(mesg->_buffer) != 0; }

static inline void dns_message_set_truncated(dns_message_t *mesg, bool truncated)
{
    if(truncated)
    {
        MESSAGE_HIFLAGS(mesg->_buffer) |= TC_BITS;
    }
    else
    {
        MESSAGE_HIFLAGS(mesg->_buffer) &= ~TC_BITS;
    }
}

static inline void    dns_message_set_answer(dns_message_t *mesg) { MESSAGE_HIFLAGS(mesg->_buffer) |= QR_BITS; }

static inline void    dns_message_clear_answer(dns_message_t *mesg) { MESSAGE_HIFLAGS(mesg->_buffer) &= ~QR_BITS; }

static inline bool    dns_message_has_recursion_desired(const dns_message_t *mesg) { return MESSAGE_RD(mesg->_buffer) != 0; }

static inline bool    dns_message_has_recursion_available(const dns_message_t *mesg) { return MESSAGE_RA(mesg->_buffer) != 0; }

static inline bool    dns_message_has_authenticated_data(const dns_message_t *mesg) { return MESSAGE_AD(mesg->_buffer) != 0; }

static inline bool    dns_message_has_checking_disabled(const dns_message_t *mesg) { return MESSAGE_CD(mesg->_buffer) != 0; }

static inline uint8_t dns_message_get_rcode(const dns_message_t *mesg) { return MESSAGE_RCODE(mesg->_buffer); }

/**
 * Sets the RCODE value in the message and in the _rcode_ext field that will be written with the EDNS0 OPT record
 */

static inline void dns_message_set_rcode(dns_message_t *mesg, uint8_t rcode)
{
    MESSAGE_LOFLAGS(mesg->_buffer) = (MESSAGE_LOFLAGS(mesg->_buffer) & ~RCODE_BITS) | (rcode & 0x0f);
    mesg->_edns0_opt_ttl.fields.extended_rcode = rcode >> 4;
}

static inline void dns_message_or_rcode(dns_message_t *mesg, uint8_t rcode)
{
    MESSAGE_LOFLAGS(mesg->_buffer) |= rcode & 0x0f;

    if(rcode > 0x0f)
    {
        mesg->_edns0_opt_ttl.fields.extended_rcode = rcode >> 4;
    }
}

static inline void dns_message_or_answer_rcode(dns_message_t *mesg, uint8_t rcode)
{
    uint16_t *flags = (uint16_t *)&mesg->_buffer[2];
#if DNSCORE_HAS_LITTLE_ENDIAN
    *flags |= (uint16_t)QR_BITS | ((((uint16_t)(rcode & 0xf))) << 8);
#else
    *flags |= (((uint16_t)QR_BITS) << 8) | (((uint16_t)(rcode & RCODE_BITS)));
#endif
    if(rcode > 0x0f)
    {
        mesg->_edns0_opt_ttl.fields.extended_rcode = rcode >> 4;
    }
}

static inline void dns_message_or_answer_rcode_var(dns_message_t *mesg, uint8_t rcode)
{
    uint16_t *flags = (uint16_t *)&mesg->_buffer[2];
#if DNSCORE_HAS_LITTLE_ENDIAN
    *flags |= (uint16_t)QR_BITS | ((((uint16_t)(rcode & 0xf))) << 8);
#else
    *flags |= (((uint16_t)QR_BITS) << 8) | (((uint16_t)(rcode & RCODE_BITS)));
#endif
    mesg->_edns0_opt_ttl.fields.extended_rcode = rcode >> 4;
}

static inline void dns_message_or_authoritative_answer_rcode(dns_message_t *mesg, uint8_t rcode)
{
    uint16_t *flags = (uint16_t *)&mesg->_buffer[2];
#if DNSCORE_HAS_LITTLE_ENDIAN
    *flags |= (uint16_t)(QR_BITS | AA_BITS) | ((((uint16_t)(rcode & RCODE_BITS))) << 8);
#else
    *flags |= (((uint16_t)(QR_BITS | AA_BITS)) << 8) | (((uint16_t)(rcode & 0xf)));
#endif
    if(rcode > 0x0f)
    {
        mesg->_edns0_opt_ttl.fields.extended_rcode = rcode >> 4;
    }
}

static inline void dns_message_or_authoritative_answer_rcode_var(dns_message_t *mesg, uint8_t rcode)
{
    uint16_t *flags = (uint16_t *)&mesg->_buffer[2];
#if DNSCORE_HAS_LITTLE_ENDIAN
    *flags |= (uint16_t)(QR_BITS | AA_BITS) | ((((uint16_t)(rcode & RCODE_BITS))) << 8);
#else
    *flags |= (((uint16_t)(QR_BITS | AA_BITS)) << 8) | (((uint16_t)(rcode & 0xf)));
#endif
    mesg->_edns0_opt_ttl.fields.extended_rcode = rcode >> 4;
}

static inline uint32_t dns_message_get_edns0_opt_ttl(const dns_message_t *mesg) { return mesg->_edns0_opt_ttl.as_u32; }

static inline bool     dns_message_has_edns0_dnssec(const dns_message_t *mesg) { return (mesg->_edns0_opt_ttl.as_u32 & RCODE_EXT_DNSSEC) != 0; }

static inline void     dns_message_set_authoritative_answer(dns_message_t *mesg) { MESSAGE_HIFLAGS(mesg->_buffer) |= AA_BITS | QR_BITS; }

static inline void     dns_message_set_truncated_answer(dns_message_t *mesg) { MESSAGE_HIFLAGS(mesg->_buffer) |= TC_BITS | QR_BITS; }

static inline bool     dns_message_is_truncated(const dns_message_t *mesg) { return (MESSAGE_HIFLAGS(mesg->_buffer) & TC_BITS) != 0; }

static inline void     dns_message_set_authoritative(dns_message_t *mesg) { MESSAGE_HIFLAGS(mesg->_buffer) |= AA_BITS; }

static inline void     dns_message_clear_authoritative(dns_message_t *mesg) { MESSAGE_HIFLAGS(mesg->_buffer) &= ~AA_BITS; }

static inline void     dns_message_set_recursion_desired(dns_message_t *mesg) { MESSAGE_HIFLAGS(mesg->_buffer) |= RD_BITS; }

static inline void     dns_message_clear_recursion_desired(dns_message_t *mesg) { MESSAGE_HIFLAGS(mesg->_buffer) &= ~RD_BITS; }

static inline void     dns_message_set_authenticated_data(dns_message_t *mesg) { MESSAGE_LOFLAGS(mesg->_buffer) |= AD_BITS; }

static inline bool     dns_message_is_authoritative(const dns_message_t *mesg) { return (MESSAGE_HIFLAGS(mesg->_buffer) & AA_BITS) != 0; }

static inline void     dns_message_apply_mask(dns_message_t *mesg, int hi, int lo) { MESSAGE_FLAGS_AND(mesg->_buffer, (uint8_t)hi, (uint8_t)lo); }

static inline void     dns_message_apply_lo_mask(dns_message_t *mesg, uint8_t lo) { MESSAGE_LOFLAGS(mesg->_buffer) &= lo; }

/**
 *  Only works if the message has been processed.
 */

static inline uint16_t dns_message_get_query_type(const dns_message_t *mesg) { return mesg->_query_type; }

/**
 * Mostly for printing with format.
 *
 * Only works if the message has been processed.
 */

static inline const uint16_t *dns_message_get_query_type_ptr(const dns_message_t *mesg) { return &mesg->_query_type; }

static inline void            dns_message_set_query_type(dns_message_t *mesg, uint16_t qtype) { mesg->_query_type = qtype; }

/**
 * Only works if the message has been processed.
 */

static inline uint16_t dns_message_get_query_class(const dns_message_t *mesg) { return mesg->_query_class; }

/**
 * Mostly for printing with format.
 *
 * Only works if the message has been processed.
 */

static inline const uint16_t *dns_message_get_query_class_ptr(const dns_message_t *mesg) { return &mesg->_query_class; }

static inline void            dns_message_set_query_class(dns_message_t *mesg, uint16_t qclass) { mesg->_query_class = qclass; }

static inline uint16_t        dns_message_get_size_u16(const dns_message_t *mesg) { return (uint16_t)mesg->_msghdr.msg_iov[0].iov_len; }

static inline size_t          dns_message_get_size(const dns_message_t *mesg) { return mesg->_msghdr.msg_iov[0].iov_len; }

static inline void            dns_message_set_size(dns_message_t *mesg, size_t size) { mesg->_msghdr.msg_iov[0].iov_len = size; }

static inline void            dns_message_increase_size(dns_message_t *mesg, size_t size) { mesg->_msghdr.msg_iov[0].iov_len += size; }

static inline const uint8_t  *dns_message_get_buffer_const(const dns_message_t *mesg) { return mesg->_buffer; }

static inline uint8_t        *dns_message_get_buffer(dns_message_t *mesg) { return mesg->_buffer; }

static inline uint16_t        dns_message_get_flags(const dns_message_t *mesg) { return MESSAGE_FLAGS(mesg->_buffer); }

static inline uint8_t         dns_message_get_flags_hi(const dns_message_t *mesg) { return MESSAGE_HIFLAGS(mesg->_buffer); }

static inline uint8_t         dns_message_get_flags_lo(const dns_message_t *mesg) { return MESSAGE_LOFLAGS(mesg->_buffer); }

static inline void            dns_message_set_flags_hi(dns_message_t *mesg, uint8_t hi) { MESSAGE_HIFLAGS(mesg->_buffer) = hi; }

static inline void            dns_message_set_flags_lo(dns_message_t *mesg, uint8_t lo) { MESSAGE_LOFLAGS(mesg->_buffer) = lo; }

static inline uint8_t         dns_message_get_op(const dns_message_t *mesg) { return MESSAGE_OP(mesg->_buffer); }

/**
 * Returns a pointer to the first byte not set in the buffer (&buffer[size])
 * MAY BE RENAMED INTO message_get_buffer_end(mesg)
 * @param mesg
 * @return
 */

static inline uint8_t       *dns_message_get_buffer_limit(dns_message_t *mesg) { return &mesg->_buffer[dns_message_get_size(mesg)]; }

static inline const uint8_t *dns_message_get_buffer_limit_const(const dns_message_t *mesg) { return &mesg->_buffer[dns_message_get_size(mesg)]; }

/**
 * The maximum size of the buffer is, of course, a constant.
 * This value is the one used to artificially limit the writing in the buffer.
 * This is mostly used to reserve room for additional records (EDNS, TSIG)
 *
 * The parameter MUST be a value <= dns_message_get_buffer_size_max(mesg)
 *
 * @param mesg the message
 * @param size the size <= dns_message_get_buffer_size_max(mesg)
 * @return
 */

static inline void dns_message_set_buffer_size(dns_message_t *mesg, uint32_t size)
{
    assert(size <= mesg->_buffer_size_limit);
    mesg->_buffer_size = size;
}

static inline void dns_message_reserve_buffer_size(dns_message_t *mesg, uint32_t size)
{
    assert(size <= mesg->_buffer_size);
    mesg->_buffer_size -= size;
}

static inline void dns_message_increase_buffer_size(dns_message_t *mesg, uint32_t size)
{
    assert(size + mesg->_buffer_size <= mesg->_buffer_size_limit);
    mesg->_buffer_size += size;
}

static inline uint32_t dns_message_get_buffer_size(const dns_message_t *mesg) { return mesg->_buffer_size; }

static inline void     dns_message_reset_buffer_size(dns_message_t *mesg) { mesg->_buffer_size = mesg->_buffer_size_limit; }

static inline uint32_t dns_message_get_buffer_size_max(const dns_message_t *mesg) { return mesg->_buffer_size_limit; }

/**
 * Copies the data content into the buffer
 */

static inline void dns_message_copy_buffer(const dns_message_t *mesg, void *out_data, size_t data_size)
{
    yassert(data_size >= dns_message_get_size(mesg));
    (void)data_size;
    memcpy(out_data, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg));
}

static inline void dns_message_copy_into_buffer(dns_message_t *mesg, const void *in_data, size_t data_size)
{
    yassert(data_size <= dns_message_get_buffer_size(mesg));
    memcpy(dns_message_get_buffer(mesg), in_data, data_size);
    dns_message_set_size(mesg, data_size);
}

/**
 * Copies the control content into the buffer
 */

static inline uint8_t dns_message_copy_control(const dns_message_t *mesg, void *out_data, size_t data_size)
{
#if __unix__
    yassert(data_size >= mesg->_msghdr.msg_controllen);
    (void)data_size;
    memcpy(out_data, mesg->_msghdr.msg_control, mesg->_msghdr.msg_controllen);
    return mesg->_msghdr.msg_controllen;
#else
    return 0;
#endif
}

static inline uint8_t dns_message_control_size(const dns_message_t *mesg)
{
#if __unix__
    return mesg->_msghdr.msg_controllen;
#else
    return mesg->_msghdr.msg_control.len;
#endif
}

static inline void dns_message_set_control(dns_message_t *mesg, const void *data, size_t data_size)
{
#if __unix__
    yassert(data_size <= sizeof(mesg->_msghdr_control_buffer));
    memcpy(mesg->_msghdr_control_buffer, data, data_size);
    mesg->_msghdr.msg_controllen = data_size;
#if __FreeBSD__ || __OpenBSD__
    if(data_size != 0)
    {
        mesg->_msghdr.msg_control = mesg->_msghdr_control_buffer;
    }
    else
    {
        mesg->_msghdr.msg_control = NULL;
    }
#endif
#else
#endif
}

static inline void dns_message_reset_control_size(dns_message_t *mesg)
{
#if __unix__
#if __FreeBSD__ || __OpenBSD__
    mesg->_msghdr.msg_control = mesg->_msghdr_control_buffer;
#endif
    mesg->_msghdr.msg_controllen = sizeof(mesg->_msghdr_control_buffer);
#else
    mesg->_msghdr.msg_control.buf = (CHAR *)mesg->_msghdr_control_buffer;
    mesg->_msghdr.msg_control.len = sizeof(mesg->_msghdr_control_buffer);
    WSACMSGHDR *hdr = (WSACMSGHDR *)mesg->_msghdr.msg_control.buf;
    ZeroMemory(hdr, sizeof(WSACMSGHDR));
#endif
}

static inline void dns_message_reset_control(dns_message_t *mesg)
{
#if __unix__
    mesg->_msghdr.msg_control = mesg->_msghdr_control_buffer;
    mesg->_msghdr.msg_controllen = sizeof(mesg->_msghdr_control_buffer);
#else
    mesg->_msghdr.msg_control.buf = mesg->_msghdr_control_buffer;
    mesg->_msghdr.msg_control.len = sizeof(mesg->_msghdr_control_buffer);
    WSACMSGHDR *hdr = (WSACMSGHDR *)mesg->_msghdr.msg_control.buf;
    ZeroMemory(hdr, sizeof(WSACMSGHDR));
#endif
}

static inline void dns_message_clear_control(dns_message_t *mesg)
{
#if __unix__
    mesg->_msghdr.msg_control = NULL;
    mesg->_msghdr.msg_controllen = 0;
#else
    mesg->_msghdr.msg_control.buf = NULL;
    mesg->_msghdr.msg_control.len = 0;
#endif
}

/**
 * Gets the global edns0 maximum size
 *
 * @return
 */

uint16_t           dns_message_edns0_getmaxsize();

static inline void dns_message_set_edns0(dns_message_t *mesg, bool enabled)
{
    if(enabled)
    {
        mesg->_opt |= MESSAGE_OPT_EDNS0;
    }
    else
    {
        mesg->_opt &= ~MESSAGE_OPT_EDNS0;
    }
}

static inline void dns_message_edns0_set(dns_message_t *mesg) { mesg->_opt |= MESSAGE_OPT_EDNS0; }

static inline void dns_message_edns0_clear(dns_message_t *mesg) { mesg->_opt &= ~(MESSAGE_OPT_EDNS0|MESSAGE_OPT_NSID|MESSAGE_OPT_COOKIE); }

static inline bool dns_message_has_edns0(const dns_message_t *mesg) { return mesg->_opt & MESSAGE_OPT_EDNS0; }

static inline void dns_message_nsid_set(dns_message_t *mesg) { mesg->_opt |= MESSAGE_OPT_NSID; }

static inline void dns_message_clear_nsid(dns_message_t *mesg) { mesg->_opt &= ~MESSAGE_OPT_NSID; }

static inline bool dns_message_has_nsid(const dns_message_t *mesg) { return mesg->_opt & MESSAGE_OPT_NSID; }

static inline void dns_message_cookie_copy_from(dns_message_t *mesg, const dns_message_t *from_mesg)
{
    mesg->_cookie.size = from_mesg->_cookie.size;
    memcpy(mesg->_cookie.bytes, from_mesg->_cookie.bytes, mesg->_cookie.size);
}

static inline void dns_message_opt_copy_from(dns_message_t *mesg, const dns_message_t *from_mesg)
{
    mesg->_opt = from_mesg->_opt;
    dns_message_cookie_copy_from(mesg, from_mesg);
}

static inline uint8_t dns_message_opt_get(const dns_message_t *mesg) { return mesg->_opt; }

static inline void    dns_message_clear_cookie(dns_message_t *mesg) { mesg->_cookie.size = 0; }

static inline bool    dns_message_has_cookie(const dns_message_t *mesg) { return mesg->_cookie.size > 0; }

static inline bool    dns_message_has_tsig(const dns_message_t *mesg) { return mesg->_tsig.tsig != NULL; }

/**
 * Frees and clears the HMAC from a TSIG item in a DNS message.
 *
 * @param mesg the message
 */

static inline void dns_message_free_allocated_hmac(dns_message_t *mesg)
{
    hmac_free(mesg->_tsig.hmac);
    mesg->_tsig.hmac = NULL;
}

/**
 * Frees and clears the hmac from a TSIG item in a DNS message.
 * Checks if the HMAC has been allocated to begin with.
 *
 * @param mesg the message
 */

static inline void dns_message_clear_hmac(dns_message_t *mesg)
{
    if(mesg->_tsig.hmac != NULL)
    {
        dns_message_free_allocated_hmac(mesg);
    }
}

static inline const uint8_t *dns_message_tsig_get_name(const dns_message_t *mesg) { return mesg->_tsig.tsig->name; }

static inline int64_t        dns_message_tsig_get_epoch(const dns_message_t *mesg)
{
    uint64_t then = (uint64_t)ntohs(mesg->_tsig.timehi);
    then <<= 32;
    then |= (uint64_t)ntohl(mesg->_tsig.timelo);
    return (int64_t)then;
}

static inline int64_t dns_message_tsig_get_fudge(const dns_message_t *mesg)
{
    uint64_t then = (uint64_t)ntohs(mesg->_tsig.fudge);
    return (int64_t)then;
}

static inline int            dns_message_tsig_mac_get_size(const dns_message_t *mesg) { return mesg->_tsig.mac_size; }

static inline void           dns_message_tsig_set_error(dns_message_t *mesg, uint16_t err) { mesg->_tsig.error = err; }

static inline uint16_t       dns_message_tsig_get_error(dns_message_t *mesg) { return mesg->_tsig.error; }

static inline void           dns_message_tsig_mac_copy(const dns_message_t *mesg, uint8_t *to) { memcpy(to, mesg->_tsig.mac, dns_message_tsig_mac_get_size(mesg)); }

static inline const uint8_t *dns_message_tsig_mac_get_const(const dns_message_t *mesg) { return mesg->_tsig.mac; }

static inline void           dns_message_tsig_copy_from(dns_message_t *mesg, const dns_message_t *source)
{
    message_tsig_t       *d = &mesg->_tsig;
    const message_tsig_t *s = &source->_tsig;
    memcpy(d, s, offsetof(message_tsig_t, mac));
    memcpy(d->mac, s->mac, s->mac_size);
    if((s->other != NULL) && (s->other_len > 0))
    {
        MALLOC_OR_DIE(uint8_t *, d->other, s->other_len, TSIGOTHR_TAG);
        memcpy(d->other, s->other, s->other_len);
    }
    else
    {
        d->other = NULL;
    }
    d->hmac = s->hmac;
    d->tcp_tsig_countdown = s->tcp_tsig_countdown;
    d->mac_algorithm = s->mac_algorithm;
}

static inline void dns_message_tsig_set_key(dns_message_t *mesg, const tsig_key_t *key)
{
    mesg->_tsig.tsig = key;
    mesg->_tsig.mac_algorithm = key->mac_algorithm;
}

static inline const tsig_key_t *dns_message_tsig_get_key(const dns_message_t *mesg) { return mesg->_tsig.tsig; }

static inline void              dns_message_tsig_clear_key(dns_message_t *mesg) { mesg->_tsig.tsig = NULL; }

static inline const uint8_t    *dns_message_tsig_get_key_bytes(const dns_message_t *mesg) { return mesg->_tsig.tsig->mac; }

static inline uint16_t          dns_message_tsig_get_key_size(const dns_message_t *mesg) { return mesg->_tsig.tsig->mac_size; }

/**
 * This will add an OPT record to the end of the message.
 * It doesn't check there is already an OPT present.
 * Cookies, if set, are added.
 * NSID isn't handled at this level so it is ignored.
 *
 * @param mesg the message
 *
 * @return an error code (e.g. the buffer is full)
 */

ya_result                           dns_message_add_opt(dns_message_t *mesg);

static inline dns_message_header_t *dns_message_get_header(dns_message_t *mesg) { return (dns_message_header_t *)dns_message_get_buffer(mesg); }

#if DEBUG
static inline void dns_message_debug_trash_buffer(dns_message_t *mesg) { memset(dns_message_get_buffer(mesg), 0xee, dns_message_get_buffer_size_max(mesg)); }
#else
static inline void dns_message_debug_trash_buffer(dns_message_t *mesg) { (void)mesg; }
#endif

static inline void dns_message_copy_msghdr(const dns_message_t *mesg, struct msghdr *copyto) { memcpy(copyto, &mesg->_msghdr, sizeof(mesg->_msghdr)); }

ya_result          dns_message_process_query(dns_message_t *mesg);

int                dns_message_process(dns_message_t *mesg);
int                dns_message_process_lenient(dns_message_t *mesg);

void               dns_message_transform_to_error(dns_message_t *mesg);
void               dns_message_transform_to_signed_error(dns_message_t *mesg);

/* global */

void dns_message_edns0_setmaxsize(uint16_t maxsize);

/**
 * Clears extended RCODE, length set version to 0
 * Only keeps the DNSSEC (DO) flag
 *
 * @arg mesg the message
 */

static inline void dns_message_edns0_clear_undefined_flags(dns_message_t *mesg) // all but DO
{
    mesg->_edns0_opt_ttl.as_u32 &= RCODE_EXT_DNSSEC; // note: only works because EDNS version is 0
}

/**
 * Create a query message.
 *
 * @param mesg the message
 * @param id the id of the message
 * @param qname the fqdn to query
 * @param qtype the type to query
 * @param qclass the class to query
 */

void dns_message_make_query(dns_message_t *mesg, uint16_t id, const uint8_t *qname, uint16_t qtype, uint16_t qclass);

/**
 * Create a query message.
 *
 * @param mesg the message
 * @param id the id of the message
 * @param qname the fqdn to query
 * @param qtype the type to query
 * @param qclass the class to query
 * @param flags adds an OPT if not zero
 */

void dns_message_make_query_ex(dns_message_t *mesg, uint16_t id, const uint8_t *qname, uint16_t qtype, uint16_t qclass, uint32_t flags);

/**
 * Create a query message.
 *
 * @param mesg the message
 * @param id the id of the message
 * @param qname the fqdn to query
 * @param qtype the type to query
 * @param qclass the class to query
 * @param edns0_ttl sets the extended rcode
 */

void dns_message_make_query_ex_with_edns0(dns_message_t *mesg, uint16_t id, const uint8_t *qname, uint16_t qtype, uint16_t qclass, uint32_t edns0_ttl);

struct dns_packet_writer_s;

void      dns_message_make_message(dns_message_t *mesg, uint16_t id, const uint8_t *qname, uint16_t qtype, uint16_t qclass, struct dns_packet_writer_s *uninitialised_packet_writer);

ya_result dns_message_update_init(dns_message_t *mesg, uint16_t id, const uint8_t *zzone, uint16_t zclass, uint32_t max_size, struct dns_packet_writer_s *uninitialised_pw);
ya_result dns_message_update_delete_all_rrsets(dns_message_t *mesg, struct dns_packet_writer_s *pw, const uint8_t *fqdn);
ya_result dns_message_update_delete_rrset(dns_message_t *mesg, struct dns_packet_writer_s *pw, const uint8_t *fqdn, uint16_t rtype);
ya_result dns_message_update_delete_record(dns_message_t *mesg, struct dns_packet_writer_s *pw, const uint8_t *fqdn, uint16_t rtype, uint16_t rdata_size, const uint8_t *rdata);
ya_result dns_message_update_delete_dns_resource_record(dns_message_t *mesg, struct dns_packet_writer_s *pw, const struct dns_resource_record_s *rr);
ya_result dns_message_update_delete_dnskey(dns_message_t *mesg, struct dns_packet_writer_s *pw, dnskey_t *key);
ya_result dns_message_update_add_record(dns_message_t *mesg, struct dns_packet_writer_s *pw, const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t rttl, uint16_t rdata_size, const uint8_t *rdata);
ya_result dns_message_update_add_dns_resource_record(dns_message_t *mesg, struct dns_packet_writer_s *pw, const struct dns_resource_record_s *rr);
ya_result dns_message_update_add_dnskey(dns_message_t *mesg, struct dns_packet_writer_s *pw, dnskey_t *key, int32_t ttl);
ya_result dns_message_update_finalize(dns_message_t *mesg, struct dns_packet_writer_s *pw);

/**
 *
 * @param mesg
 * @param qname
 * @param qtype
 * @param qclass
 * @param id
 */

void dns_message_make_notify(dns_message_t *mesg, uint16_t id, const uint8_t *qname, uint16_t qtype /* TYPE_SOA */, uint16_t qclass /* CLASS_IN */);

void dns_message_make_ixfr_query(dns_message_t *mesg, uint16_t id, const uint8_t *qname, int32_t soa_ttl, uint16_t soa_rdata_size, const uint8_t *soa_rdata);

#if DNSCORE_HAS_TSIG_SUPPORT

ya_result dns_message_sign_query_by_name(dns_message_t *mesg, const uint8_t *tsig_name);

ya_result dns_message_sign_query_by_name_with_epoch_and_fudge(dns_message_t *mesg, const uint8_t *tsig_name, int64_t epoch, uint16_t fudge);

ya_result dns_message_sign_query(dns_message_t *mesg, const tsig_key_t *key);

ya_result dns_message_sign_query_with_epoch_and_fudge(dns_message_t *mesg, const tsig_key_t *key, int64_t epoch, uint16_t fudge);

ya_result dns_message_sign_answer(dns_message_t *mesg);

#endif

/**
 * Creates an empty answer with an error code
 *
 * @param mesg
 * @param error_code
 */

void dns_message_make_error(dns_message_t *mesg, uint16_t error_code);

/**
 * Creates an empty answer with an error code and TSIG signs it if needed
 *
 * @param mesg
 * @param error_code
 */

void      dns_message_make_signed_error(dns_message_t *mesg, uint16_t error_code);

ya_result dns_message_make_error_and_reply_tcp(dns_message_t *mesg, uint16_t error_code, int tcpfd);

ssize_t   dns_message_make_error_and_reply_tcp_with_default_minimum_throughput(dns_message_t *mesg, uint16_t error_code, int tcpfd);
/**
 * Creates an answer with an OPT error code
 */

void                    dns_message_make_error_ext(dns_message_t *mesg, uint32_t error_code);

static inline ya_result dns_message_set_sender_from_host_address(dns_message_t *mesg, const host_address_t *ha)
{
    ya_result ret = host_address2sockaddr(ha, &mesg->_sender);
    if(ISOK(ret))
    {
        mesg->_msghdr.msg_namelen = ret;
    }
    return ret;
}

static inline int                        dns_message_get_sender_size(const dns_message_t *mesg) { return mesg->_msghdr.msg_namelen; }

static inline const socketaddress_t     *dns_message_get_sender(const dns_message_t *mesg) { return &mesg->_sender; }

ya_result                                dns_message_set_sender_port(dns_message_t *mesg, uint16_t port);

uint8_t                                 *dns_message_get_sender_address_ptr(dns_message_t *mesg);

uint32_t                                 dns_message_get_sender_address_size(dns_message_t *mesg);

static inline const struct sockaddr     *dns_message_get_sender_sa(const dns_message_t *mesg) { return &mesg->_sender.sa; }

static inline sa_family_t                dns_message_get_sender_sa_family(const dns_message_t *mesg) { return mesg->_sender.sa.sa_family; }

size_t                                   dns_message_get_sender_sa_family_size(const dns_message_t *mesg);

static inline const struct sockaddr_in  *dns_message_get_sender_sa4(const dns_message_t *mesg) { return &mesg->_sender.sa4; }

static inline const struct sockaddr_in6 *dns_message_get_sender_sa6(const dns_message_t *mesg) { return &mesg->_sender.sa6; }

static inline void                       dns_message_copy_sender_from(dns_message_t *mesg, const dns_message_t *original)
{
    memcpy(&mesg->_sender, &original->_sender, dns_message_get_sender_size(original));
    mesg->_msghdr.msg_name = &mesg->_sender.sa;
    mesg->_msghdr.msg_namelen = original->_msghdr.msg_namelen;
}

static inline void dns_message_copy_sender_from_sa(dns_message_t *mesg, const struct sockaddr *sa, socklen_t sa_len)
{
    memcpy(&mesg->_sender, sa, sa_len);
    mesg->_msghdr.msg_namelen = sa_len;
}

static inline ya_result dns_message_copy_sender_from_socket(dns_message_t *mesg, int client_sockfd)
{
    mesg->_msghdr.msg_namelen = sizeof(mesg->_sender);
    if(getpeername(client_sockfd, &mesg->_sender.sa, &mesg->_msghdr.msg_namelen) >= 0)
    {
        mesg->_msghdr.msg_name = &mesg->_sender.sa;
        return SUCCESS;
    }
    else
    {
        return ERRNO_ERROR;
    }
}

static inline void     dns_message_copy_sender_to_sa(const dns_message_t *mesg, struct sockaddr *bigenoughforipv6) { memcpy(bigenoughforipv6, dns_message_get_sender_sa(mesg), dns_message_get_sender_size(mesg)); }

static inline uint16_t dns_message_get_u16_at(const dns_message_t *mesg, int offset) { return GET_U16_AT(mesg->_buffer[offset]); }

static inline void     dns_message_send_udp_reset(dns_message_t *mesg)
{
    mesg->_msghdr.msg_namelen = sizeof(mesg->_sender);
    mesg->_iovec.iov_len = mesg->_buffer_size;
}

#if !DEBUG
static inline int32_t dns_message_send_udp(const dns_message_t *mesg, int sockfd)
{
    int32_t n;
    while((n = sendmsg(sockfd, &mesg->_msghdr, 0)) < 0)
    {
        int err = errno;

        if(err != EINTR)
        {
            return MAKE_ERRNO_ERROR(err);
        }
    }

    return n;
}
#else
int32_t               dns_message_send_udp_debug(const dns_message_t *mesg, int sockfd);

static inline int32_t dns_message_send_udp(const dns_message_t *mesg, int sockfd)
{
    int32_t ret = dns_message_send_udp_debug(mesg, sockfd);
    return ret;
}
#endif

static inline void dns_message_recv_udp_reset(dns_message_t *mesg)
{
    mesg->_msghdr.msg_namelen = sizeof(mesg->_sender);
    mesg->_iovec.iov_len = mesg->_buffer_size;
}

static inline ssize_t dns_message_recv_udp(dns_message_t *mesg, int sockfd)
{
    ssize_t ret = recvmsg(sockfd, &mesg->_msghdr, 0);
    if(ret >= 0)
    {
        dns_message_set_size(mesg, ret);
#if __FreeBSD__ || __OpenBSD__
        if(mesg->_msghdr.msg_controllen == 0)
        {
            mesg->_msghdr.msg_control = NULL;
        }
#endif
    }
    else
    {
        ret = ERRNO_ERROR;
    }
    return ret;
}

static inline const uint8_t *dns_message_parse_query_fqdn(const dns_message_t *mesg)
{
    if(dns_message_get_query_count_ne(mesg) != 0)
    {
        return &mesg->_buffer[DNS_HEADER_LENGTH];
    }
    else
    {
        return NULL;
    }
}

static inline uint16_t dns_message_parse_query_type(const dns_message_t *mesg)
{
    if(dns_message_get_query_count_ne(mesg) != 0)
    {
        const uint8_t *fqdn = &mesg->_buffer[DNS_HEADER_LENGTH];
        fqdn += dnsname_len(fqdn);
        return GET_U16_AT_P(fqdn);
    }
    else
    {
        return TYPE_NONE;
    }
}

static inline uint16_t dns_message_parse_query_class(const dns_message_t *mesg)
{
    if(dns_message_get_query_count_ne(mesg) != 0)
    {
        const uint8_t *fqdn = &mesg->_buffer[DNS_HEADER_LENGTH];
        fqdn += (intptr_t)dnsname_len(fqdn) + 2;
        return GET_U16_AT_P(fqdn);
    }
    else
    {
        return TYPE_NONE;
    }
}

static inline const uint8_t *dns_message_get_canonised_fqdn(const dns_message_t *mesg) { return mesg->_canonised_fqdn; }

static inline void           dns_message_set_canonised_fqdn(dns_message_t *mesg, const uint8_t *canonised_fqdn) { dnsname_copy(mesg->_canonised_fqdn, canonised_fqdn); }

static inline int            dns_message_get_maximum_size(const dns_message_t *mesg) { return mesg->_buffer_size; }

static inline uint8_t       *dns_message_get_query_section_ptr(dns_message_t *mesg) { return &mesg->_buffer[DNS_HEADER_LENGTH]; }

static inline uint8_t       *dns_message_get_additional_section_ptr(dns_message_t *mesg) { return mesg->_ar_start; }

static inline const uint8_t *dns_message_get_additional_section_ptr_const(const dns_message_t *mesg) { return mesg->_ar_start; }

static inline bool           dns_message_is_additional_section_ptr_set(const dns_message_t *mesg) { return mesg->_ar_start != NULL; }

static inline void           dns_message_set_additional_section_ptr(dns_message_t *mesg, void *ptr) { mesg->_ar_start = (uint8_t *)ptr; }

static inline finger_print   dns_message_get_status(const dns_message_t *mesg) { return mesg->_status; }

static inline void           dns_message_set_status(dns_message_t *mesg, finger_print fp) { mesg->_status = fp; }

static inline void           dns_message_set_error_status_from_result(dns_message_t *mesg, ya_result error_code)
{
    finger_print fp;

    if(YA_ERROR_BASE(error_code) == RCODE_ERROR_BASE)
    {
        fp = RCODE_ERROR_GETCODE(error_code);
    }
    else
    {
        fp = FP_RCODE_SERVFAIL;
    }

    dns_message_set_status(mesg, fp);
}

static inline void dns_message_set_status_from_result(dns_message_t *mesg, ya_result error_code)
{
    finger_print fp;

    if(ISOK(error_code))
    {
        fp = (finger_print)RCODE_NOERROR;
    }
    else if(YA_ERROR_BASE(error_code) == RCODE_ERROR_BASE)
    {
        fp = (finger_print)RCODE_ERROR_GETCODE(error_code);
    }
    else
    {
        fp = FP_RCODE_SERVFAIL;
    }

    dns_message_set_status(mesg, fp);
}

static inline void     dns_message_clear_status(dns_message_t *mesg) { MESSAGE_FLAGS_AND(mesg->_buffer, 0xff, 0xf0); }

static inline void     dns_message_update_answer_status(dns_message_t *mesg) { MESSAGE_FLAGS_OR(mesg->_buffer, QR_BITS, mesg->_status); }

static inline void     dns_message_update_truncated_answer_status(dns_message_t *mesg) { MESSAGE_FLAGS_OR(mesg->_buffer, QR_BITS | TC_BITS, mesg->_status); }

static inline uint16_t dns_message_get_id(const dns_message_t *mesg) { return MESSAGE_ID(mesg->_buffer); }

#if DNSCORE_MESSAGE_PAYLOAD_IS_POINTER

static inline ssize_t dns_message_recv_tcp(dns_message_t *mesg, int sockfd)
{
    uint16_t tcp_len;

    ssize_t  ret = readfully(sockfd, &tcp_len, 2);

    if(ret < 0)
    {
        return ret;
    }

    tcp_len = ntohs(tcp_len);

    if(tcp_len < dns_message_get_maximum_size(mesg))
    {
        ret = readfully(sockfd, mesg->_buffer, tcp_len);

        if(ISOK(ret))
        {
            dns_message_set_size(mesg, ret);
        }

        return ret;
    }
    else
    {
        return BUFFER_WOULD_OVERFLOW;
    }
}

/// @note returns the size of the message, without the 2 bytes header.

static inline ssize_t dns_message_write_tcp(const dns_message_t *mesg, output_stream_t *os)
{
    ssize_t  ret;
    uint16_t tcp_len = htons(dns_message_get_size_u16(mesg));
    if(ISOK(ret = output_stream_write_fully(os, &tcp_len, 2)))
    {
        ret = output_stream_write_fully(os, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg));
    }
    return ret;
}

static inline ssize_t dns_message_read_tcp(dns_message_t *mesg, input_stream_t *is)
{
    uint16_t tcp_len;

    ssize_t  ret = input_stream_read_fully(is, &tcp_len, 2);

    if(ret < 0)
    {
        return ret;
    }

    tcp_len = ntohs(tcp_len);

    if(tcp_len < dns_message_get_maximum_size(mesg))
    {
        ret = input_stream_read_fully(is, mesg->_buffer, tcp_len);

        if(ISOK(ret))
        {
            dns_message_set_size(mesg, ret);
        }

        return ret;
    }
    else
    {
        return BUFFER_WOULD_OVERFLOW;
    }
}

#if 0
static inline ssize_t dns_message_send_tcp(const dns_message_t *mesg, int sockfd)
{
    ssize_t ret;

    uint16_t tcp_len = htons(message_get_size_u16(mesg));
    if(ISOK(ret = writefully(sockfd, &tcp_len, 2)))
    {
        if(ISOK(ret = writefully(sockfd, message_get_buffer_const(mesg), message_get_size(mesg))))
        {
            ret += 2;
        }
    }

    return ret;
}
#else
ssize_t dns_message_send_tcp(const dns_message_t *mesg, int sockfd);
#endif

static inline ssize_t dns_message_send_tcp_with_minimum_throughput(const dns_message_t *mesg, int sockfd, double minimum_rate)
{
    ssize_t  ret;
    uint16_t tcp_len = htons(dns_message_get_size_u16(mesg));

#if __unix__
    ret = writefully_limited(sockfd, &tcp_len, 2, minimum_rate);
#else
    ret = sendfully_limited(sockfd, &tcp_len, 2, 0, minimum_rate);
#endif

    if(ISOK(ret))
    {
        assert(ret == 2);

#if __unix__
        ret = writefully_limited(sockfd, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), minimum_rate);
#else
        ret = sendfully_limited(sockfd, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0, minimum_rate);
#endif

        if(ISOK(ret))
        {
            assert(ret == (ssize_t)dns_message_get_size(mesg));

            return ret + 2;
        }
    }
    return ret;
}

static inline ssize_t dns_message_update_length_send_tcp_with_minimum_throughput(dns_message_t *mesg, int sockfd, double minimum_rate)
{
    ssize_t ret = dns_message_send_tcp_with_minimum_throughput(mesg, sockfd, minimum_rate);
    return ret;
}

extern double         g_message_data_minimum_troughput_default;

static inline ssize_t dns_message_update_length_send_tcp_with_default_minimum_throughput(dns_message_t *mesg, int sockfd)
{
    ssize_t ret = dns_message_send_tcp_with_minimum_throughput(mesg, sockfd, g_message_data_minimum_troughput_default);
    return ret;
}

#else
static inline void dns_message_update_tcp_length(dns_message_t *mesg)
{
    uint16_t len = message_get_size_u16(mesg);
    SET_U16_AT(mesg->_buffer_tcp_len[0], htons(len));
}

static inline uint32_t dns_message_get_tcp_length(const dns_message_t *mesg)
{
    uint16_t len = GET_U16_AT(mesg->_buffer_tcp_len[0]);
    return ntohs(len);
}

static inline const uint8_t *dns_message_get_tcp_buffer_const(const dns_message_t *mesg) { return mesg->_buffer_tcp_len; }

static inline uint8_t       *dns_message_get_tcp_buffer(dns_message_t *mesg) { return mesg->_buffer_tcp_len; }

static inline ssize_t        dns_message_recv_tcp(dns_message_t *mesg, int sockfd)
{
    ssize_t ret = readfully(sockfd, mesg->_buffer_tcp_len, 2);

    if(ret < 0)
    {
        return ret;
    }

    ret = message_get_tcp_length(mesg);

    if(ret > 0)
    {
        ret = readfully(sockfd, mesg->_buffer, ret);

        if(ISOK(ret))
        {
            message_set_size(mesg, ret);
        }
    }

    return ret;
}

static inline ssize_t dns_message_write_tcp(const dns_message_t *mesg, output_stream_t *os)
{
    message_update_tcp_length(mesg);
    ssize_t ret = output_stream_write(os, message_get_tcp_buffer_const(mesg), message_get_size_u16(mesg) + 2);
    return ret;
}

static inline ssize_t dns_message_read_tcp(dns_message_t *mesg, input_stream_t *is)
{
    ssize_t ret = input_stream_read(is, mesg->_buffer_tcp_len, 2);
    if(ret < 0)
    {
        return ret;
    }
    ret = message_get_tcp_length(mesg);
    if(ret > 0)
    {
        ret = input_stream_read(is, message_get_buffer(mesg), ret);

        if(ISOK(ret))
        {
            message_set_size(mesg, ret);
        }
    }
    return ret;
}

static inline ssize_t dns_message_send_tcp(const dns_message_t *mesg, int sockfd)
{
    ssize_t ret = writefully(sockfd, message_get_tcp_buffer_const(mesg), message_get_size_u16(mesg) + 2);
    return ret;
}

static inline ssize_t dns_message_send_tcp_with_minimum_throughput(const dns_message_t *mesg, int sockfd, double minimum_rate)
{
    ssize_t ret = writefully_limited(sockfd, message_get_tcp_buffer_const(mesg), message_get_size_u16(mesg) + 2, minimum_rate);
    return ret;
}

static inline ssize_t dns_message_update_length_send_tcp_with_minimum_throughput(dns_message_t *mesg, int sockfd, double minimum_rate)
{
    message_update_tcp_length(mesg);
    ssize_t ret = message_send_tcp_with_minimum_throughput(mesg, sockfd, minimum_rate);
    return ret;
}

extern double         g_dns_message_minimum_troughput_default;

static inline ssize_t dns_message_update_length_send_tcp_with_default_minimum_throughput(dns_message_t *mesg, int sockfd)
{
    message_update_tcp_length(mesg);
    ssize_t ret = message_send_tcp_with_minimum_throughput(mesg, sockfd, g_dns_message_minimum_troughput_default);
    return ret;
}

#endif

static inline void dns_message_set_id(dns_message_t *mesg, uint16_t id) { MESSAGE_SET_ID(mesg->_buffer, id); }

static inline void dns_message_make_truncated_empty_answer(dns_message_t *mesg)
{
    dns_message_set_truncated_answer(mesg);
    dns_message_set_query_answer_authority_additional_counts_ne(mesg, 0, 0, 0, 0);
    dns_message_set_size(mesg, DNS_HEADER_LENGTH);
}

#if NOTUSED
/**
 * To be called on a message at the beginning of a TCP stream
 *
 * @param mesg
 */

static inline void dns_message_tcp_serial_reset(dns_message_t *mesg) { mesg->_tcp_serial = 0; }

/**
 * To be called on a message when reading a following TCP stream message
 *
 * @param mesg
 */

static inline void dns_message_tcp_serial_increment(dns_message_t *mesg) { ++mesg->_tcp_serial; }
#endif

ya_result dns_message_query_tcp_with_timeout(dns_message_t *mesg, const host_address_t *server, uint8_t to_sec);
ya_result dns_message_query_tcp_with_timeout_ex(dns_message_t *mesg, const host_address_t *server, dns_message_t *answer, uint8_t to_sec);
ya_result dns_message_query_tcp(dns_message_t *mesg, const host_address_t *server);
ya_result dns_message_query_tcp_ex(dns_message_t *mesg, const host_address_t *bindto, const host_address_t *server, dns_message_t *answer);
ya_result dns_message_query_udp(dns_message_t *mesg, const host_address_t *server);
ya_result dns_message_query_udp_with_timeout(dns_message_t *mesg, const host_address_t *server, int seconds, int useconds);

#define MESSAGE_QUERY_UDP_FLAG_RESET_ID 1

/**
 * Note: doesn't work well with signed messages.
 */

ya_result dns_message_query_udp_with_timeout_and_retries(dns_message_t *mesg, const host_address_t *server, int seconds, int useconds, uint8_t retries, uint8_t flags);

ya_result dns_message_query(dns_message_t *mesg, const host_address_t *server);

ya_result dns_message_query_serial(const uint8_t *origin, const host_address_t *server, uint32_t *serial_out);

ya_result dns_message_get_ixfr_query_serial(dns_message_t *mesg, uint32_t *serialp);

#if NOTUSED
/**
 * Writes the edns0 (if present),
 * applies the TSIG for the right position in the stream (if needed),
 *
 * Write the message to the (tcp) stream.
 *
 * @param mesg
 * @param tcpos
 * @param pos
 * @return
 */

#if ZDB_HAS_TSIG_SUPPORT
ya_result dns_message_terminate_then_write(dns_message_t *mesg, output_stream_t *tcpos, tsig_tcp_message_position pos);
#else
ya_result dns_message_terminate_then_write(dns_message_t *mesg, output_stream_t *tcpos, tsig_tcp_message_position unused);
#endif
#endif

#if DNSCORE_MESSAGE_PAYLOAD_IS_POINTER
void                         dns_message_init_ex(dns_message_t *mesg, uint32_t mesg_size, void *buffer, size_t buffer_size);

static inline dns_message_t *dns_message_data_with_buffer_init(dns_message_with_buffer_t *mesg_buff)
{
    dns_message_init_ex(&mesg_buff->message, sizeof(struct dns_message_with_buffer_s), mesg_buff->_buffer, mesg_buff->_buffer_limit - mesg_buff->_buffer);
    return &mesg_buff->message;
}
#else
void                         dns_message_init(message_data *mesg);

static inline dns_message_t *dns_message_data_with_buffer_init(dns_message_with_buffer_t *mesg_buff)
{
    dns_message_init(&mesg_buff->message);
    return &mesg_buff->message;
}
#endif

/**
 * Allocates and initialises an empty DNS message.
 *
 * Uses the specified buffer and size to hold the wire.
 *
 * If pointer is NULL, the structure and buffer will be allocated together
 * Note that in the current implementation, 8 bytes are reserved for TCP
 *
 * @param ptr a pointer to the buffer or NULL
 * @param message_size the size of the buffer
 *
 * @return a dns message
 */

dns_message_t *dns_message_new_instance_ex(void *ptr, uint32_t message_size); // should be size of edns0 or 64K for TCP

/**
 * Allocates and initialises a 64KB empty DNS message.
 *
 * @return a dns message
 */

dns_message_t *dns_message_new_instance(); // message_new_instance_ex(64K)

void           dns_message_finalize(dns_message_t *mesg);

/**
 * Finalise and free the message instance.
 * Checks for NULL
 *
 * @param mesg the message instance
 *
 */

void               dns_message_delete(dns_message_t *mesg);

static inline void dns_message_free(dns_message_t *mesg) { dns_message_delete(mesg); }

/*
 * Does not clone the pool.
 */

dns_message_t *dns_message_dup(const dns_message_t *mesg);

ya_result      dns_message_ixfr_query_get_serial(const dns_message_t *mesg, uint32_t *serial);

/**
 * Maps records in a message to easily access them afterward.
 *
 * @param map the message map to initialise
 * @param mesg the message to map
 *
 * @return an error code
 */

ya_result dns_message_map_init(dns_message_map_t *map, const dns_message_t *mesg);

/**
 * Gets the fqdn of the record at index
 *
 * @param map
 * @param index
 * @param fqdn
 * @param fqdn_size
 *
 * @return an error code
 */

ya_result dns_message_map_get_fqdn(const dns_message_map_t *map, int index, uint8_t *fqdn, int fqdn_size);

/**
 * Gets the type class ttl rdata_size of the record at index
 *
 * @param map
 * @param index
 * @param tctr
 *
 * @return an error code
 */

ya_result dns_message_map_get_tctr(const dns_message_map_t *map, int index, struct type_class_ttl_rdlen_s *tctr);

/**
 * Gets the rdata of the record at index
 *
 * @param map
 * @param index
 * @param rdata
 * @param rdata_size
 *
 * @return the rdata size or an error code
 */

ya_result dns_message_map_get_rdata(const dns_message_map_t *map, int index, uint8_t *rdata, int rdata_size);

/**
 * Gets the type of the record at index
 *
 * @param map
 * @param index
 *
 * @return the record type or an error code
 */

ya_result dns_message_map_get_type(const dns_message_map_t *map, int index);

/**
 * Gets the class of the record at index
 *
 * @param map
 * @param index
 *
 * @return the record class or an error code
 */

ya_result dns_message_map_get_class(const dns_message_map_t *map, int index);

/**
 *
 * @param map
 *
 * @return the number of records mapped
 */

int dns_message_map_record_count(const dns_message_map_t *map);

/**
 * Returns the index of the next record with the given type
 * from, and including, a given index.
 *
 * @param map
 * @param index
 * @param type
 * @return
 */

int dns_message_map_get_next_record_from(const dns_message_map_t *map, int index, uint16_t type);

/**
 * Returns the index of the next record with the given type
 * from, and including, a given index in a given section (0 to 3).
 *
 * @param map
 * @param index
 * @param type
 * @return
 */

int dns_message_map_get_next_record_from_section(const dns_message_map_t *map, int section, int index, uint16_t type);

/**
 * Returns the base index of a section
 *
 * @param map
 * @param section
 * @return
 */

static inline int dns_message_map_get_section_base(const dns_message_map_t *map, int section) { return map->section_base[section]; }

static inline int dns_message_map_get_section_count(const dns_message_map_t *map, int section) { return dns_message_get_section_count(map->mesg, section); }

/**
 * Sorts records by section so that:
 * _ SOA is first,
 * _ NSEC is last,
 * _ NSEC3 labels are at the end,
 * _ RRSIG follows its RRSET
 *
 * @param map
 */

void dns_message_map_reorder(dns_message_map_t *map);

void dns_message_map_print(const dns_message_map_t *map, output_stream_t *os);

/**
 * Releases the memory used by the map
 *
 * @param map
 */

void dns_message_map_finalize(dns_message_map_t *map);

struct logger_handle;

void                   dns_message_log(struct logger_handle_s *logger, int level, const dns_message_t *mesg);

ya_result              dns_message_print_format_dig(output_stream_t *os, const uint8_t *buffer, uint32_t length, uint32_t view_mode_with, int32_t time_duration_ms);

ya_result              dns_message_print_format_dig_buffer(output_stream_t *os_, const uint8_t *buffer, uint32_t length, uint32_t view_mode_with);

ya_result              dns_message_print_format_json(output_stream_t *os_, const uint8_t *buffer, uint32_t length, uint32_t view_mode_with, int32_t time_duration);
ya_result              dns_message_print_format_json_buffer(output_stream_t *os_, const uint8_t *buffer, uint32_t length, uint32_t view_mode_with);

ya_result              dns_message_print_format_easyparse(output_stream_t *os_, const uint8_t *buffer, uint32_t length, uint32_t view_mode_with, int32_t time_duration);
ya_result              dns_message_print_buffer_format_easyparse(output_stream_t *os_, const uint8_t *buffer, uint32_t length, uint32_t view_mode_with);

static inline uint8_t *dns_message_client_cookie_ptr(dns_message_t *mesg) { return &mesg->_cookie.bytes[0]; }

static inline uint8_t *dns_message_server_cookie_ptr(dns_message_t *mesg) { return &mesg->_cookie.bytes[DNS_MESSAGE_COOKIE_CLIENT_SIZE]; }

int                    dns_message_client_cookie_size(dns_message_t *mesg);

int                    dns_message_server_cookie_size(dns_message_t *mesg);

/**
 * Sets the client cookie and enable cookies for the message.
 * Usage is not recommended. One should use a server-address base generation.
 *
 * @param mesg the message
 * @param cookie the client cookie
 */

void dns_message_set_client_cookie(dns_message_t *mesg, uint64_t cookie);

/**
 * Sets the initial client_cookie for the given server address.
 *
 * @param mesg the message
 * @param address the address as a byte array
 * @param address_size the size of the address in bytes
 */

void dns_message_set_client_cookie_for_server_address(dns_message_t *mesg, const uint8_t *address, int address_size);

/**
 * Sets the initial client_cookie for the given server address.
 *
 * @param mesg the message
 * @param sa the struct sockaddr of the address
 */

void dns_message_set_client_cookie_for_server_sockaddr(dns_message_t *mesg, const socketaddress_t *sa);

/**
 * Sets the initial client_cookie for the given server address.
 *
 * @param mesg the message
 * @param sa the host_address_t of the address
 */

void dns_message_set_client_cookie_for_server_host_address(dns_message_t *mesg, const host_address_t *ha);

/**
 * Takes a message with the client cookie set (assumed)
 * Sets the server cookie in that message.
 */

void dns_message_cookie_server_set(dns_message_t *mesg);

/**
 * Takes a message with the client cookie set (assumed)
 * Checks if the server cookie in that message matches the expected value.
 *
 * Returns true iff the value is matched.
 */

bool dns_message_cookie_server_check(dns_message_t *mesg);

#if DNSCORE_HAS_QUERY_US_DEBUG
void dns_message_log_query_us(dns_message_t *mesg, int64_t from_us, int64_t to_us);
#endif

#ifdef __cplusplus
}
#endif

/** @} */
