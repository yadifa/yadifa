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

/** @defgroup dnspacket DNS Messages
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

    /*    ------------------------------------------------------------    */

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

#define PROCESS_FL_ADDITIONAL_AUTH      0x01
#define PROCESS_FL_AUTHORITY_AUTH       0x02
#define PROCESS_FL_ADDITIONAL_CACHE     0x04
#define PROCESS_FL_AUTHORITY_CACHE      0x08
#define PROCESS_FL_RECURSION            0x20
#define PROCESS_FL_TCP                  0x80
    
#define NETWORK_BUFFER_SIZE 65536

#define MESSAGE_PAYLOAD_IS_POINTER      1
    
    /**
     * @note buffer MUST be aligned on 16 bits
     */

#define MESSAGE_HIFLAGS(buffer_) ((buffer_)[ 2])
#define MESSAGE_LOFLAGS(buffer_) ((buffer_)[ 3])

#define MESSAGE_FLAGS(buffer_) GET_U16_AT((buffer_)[ 2])

/* Only use constants with this */
#if AVOID_ANTIALIASING
    
static inline void MESSAGE_FLAGS_OR_P(void* address, u16 f)
{
    u16 *p = (u16*)address;
    *p |= f;
}

static inline void MESSAGE_FLAGS_AND_P(void* address, u16 f)
{
    u16 *p = (u16*)address;
    *p &= f;
}

struct packet_writer;
struct dns_resource_record;

#ifdef WORDS_BIGENDIAN
#define MESSAGE_FLAGS_OR(buffer_, hi_, lo_)   MESSAGE_FLAGS_OR_P(&(buffer_)[2], (u16)((u16)((lo_) & 0xff) | ((u16)(hi_) << 8)))
#define MESSAGE_FLAGS_AND(buffer_, hi_, lo_)  MESSAGE_FLAGS_AND_P(&(buffer_)[2], (u16)((u16)((lo_) & 0xff) | ((u16)(hi_) << 8)))
#define MESSAGE_FLAGS_SET(buffer_, hi_, lo_)  SET_U16_AT_P(&(buffer_)[2], (u16)((u16)((lo_) & 0xff) | ((u16)hi_ << 8)))
#else
#define MESSAGE_FLAGS_OR(buffer_, hi_, lo_)   MESSAGE_FLAGS_OR_P(&(buffer_)[2], (u16)(((u16)((hi_) & 0xff)) | (((u16)(lo_)) << 8)))
#define MESSAGE_FLAGS_AND(buffer_, hi_, lo_)  MESSAGE_FLAGS_AND_P(&(buffer_)[2], (u16)(((u16)((hi_) & 0xff)) | (((u16)(lo_)) << 8)))
#define MESSAGE_FLAGS_SET(buffer_, hi_, lo_)  SET_U16_AT_P(&(buffer_)[2], (u16)(((u16)((hi_) & 0xff)) | (((u16)(lo_)) << 8)))
#endif

#define MESSAGE_ID(buffer_)                   GET_U16_AT_P(&(buffer_)[0])
#define MESSAGE_SET_ID(buffer_,id_)           SET_U16_AT_P(&(buffer_)[0],(id_))

#else

#ifdef WORDS_BIGENDIAN
#define MESSAGE_FLAGS_OR(buffer_, hi_, lo_)  *((u16*)&(buffer_[2])) |= (lo_ | ((u16)hi_ << 8))
#define MESSAGE_FLAGS_AND(buffer_, hi_, lo_) *((u16*)&(buffer_[2])) &= (lo_ | ((u16)hi_ << 8))
#define MESSAGE_FLAGS_SET(buffer_, hi_, lo_) *((u16*)&(buffer_[2]))  = (lo_ | ((u16)hi_ << 8))
#else
#define MESSAGE_FLAGS_OR(buffer_, hi_, lo_)  *((u16*)&(buffer_[2])) |= (hi_ | ((u16)lo_ << 8))
#define MESSAGE_FLAGS_AND(buffer_, hi_, lo_) *((u16*)&(buffer_[2])) &= (hi_ | ((u16)lo_ << 8))
#define MESSAGE_FLAGS_SET(buffer_, hi_, lo_) *((u16*)&(buffer_[2]))  = (hi_ | ((u16)lo_ << 8))
#endif

#define MESSAGE_ID(buffer)	(*((u16*)&(buffer)[ 0]))
#define MESSAGE_SET_ID(buffer_,id_)	(*((u16*)&(buffer)[ 0])) = (id_)

#endif

#define MESSAGE_QR(buffer_)     (MESSAGE_HIFLAGS(buffer_) & QR_BITS)
#define MESSAGE_OP(buffer_)     (MESSAGE_HIFLAGS(buffer_) & OPCODE_BITS)
#define MESSAGE_AA(buffer_)     (MESSAGE_HIFLAGS(buffer_) & AA_BITS)
#define MESSAGE_TC(buffer_)  	(MESSAGE_HIFLAGS(buffer_) & TC_BITS)
#define MESSAGE_RD(buffer_)     (MESSAGE_HIFLAGS(buffer_) & RD_BITS)

#define MESSAGE_RA(buffer_)  	(MESSAGE_LOFLAGS(buffer_) & RA_BITS)
#define MESSAGE_ZF(buffer_)  	(MESSAGE_LOFLAGS(buffer_) & Z_BITS)
#define MESSAGE_AD(buffer_)     (MESSAGE_LOFLAGS(buffer_) & AD_BITS)
#define MESSAGE_CD(buffer_)     (MESSAGE_LOFLAGS(buffer_) & CD_BITS)
#define MESSAGE_RCODE(buffer_)  (MESSAGE_LOFLAGS(buffer_) & RCODE_BITS)

// the size of the section by index [0;3]

#define MESSAGE_SECTION_COUNT(buffer_,index_)   GET_U16_AT(((buffer_)[4 + ((index_)<< 1)]))
    
#define MESSAGE_QD(buffer_)   GET_U16_AT((buffer_)[4])
#define MESSAGE_AN(buffer_)   GET_U16_AT((buffer_)[6])
#define MESSAGE_NS(buffer_)   GET_U16_AT((buffer_)[8])
#define MESSAGE_AR(buffer_)   GET_U16_AT((buffer_)[10])
#define MESSAGE_NSAR(buffer_) GET_U32_AT((buffer_)[8])

#define MESSAGE_SET_OP(buffer_, val_)   (MESSAGE_HIFLAGS(buffer_) = (MESSAGE_HIFLAGS(buffer_) & ~OPCODE_BITS) | (val_))

#define MESSAGE_SET_QD(buffer_,val_)   SET_U16_AT((buffer_)[4],(val_))
#define MESSAGE_SET_AN(buffer_,val_)   SET_U16_AT((buffer_)[6],(val_))
#define MESSAGE_SET_NS(buffer_,val_)   SET_U16_AT((buffer_)[8],(val_))
#define MESSAGE_SET_AR(buffer_,val_)   SET_U16_AT((buffer_)[10],(val_))
#define MESSAGE_SET_NSAR(buffer_,val_) SET_U32_AT((buffer_)[8],(val_))
    
    /* DYNUPDATE rfc 2136 */
#define MESSAGE_ZO(buffer_)   GET_U16_AT((buffer_)[4])
#define MESSAGE_PR(buffer_)   GET_U16_AT((buffer_)[6])
#define MESSAGE_UP(buffer_)   GET_U16_AT((buffer_)[8])

#define MESSAGE_SET_ZO(buffer_, val_)   SET_U16_AT((buffer_)[4],(val_))
#define MESSAGE_SET_PR(buffer_, val_)   SET_U16_AT((buffer_)[6],(val_))
#define MESSAGE_SET_UP(buffer_, val_)   SET_U16_AT((buffer_)[8],(val_))

//#define MESSAGE_AD(buffer)	(*((u16*)&(buffer)[10]))
    
#define MESGDATA_TAG 0x415441444753454d

#if DNSCORE_HAS_TSIG_SUPPORT

typedef struct message_tsig message_tsig;

struct message_tsig
{
    const tsig_item *tsig;

    u16 reserved_0; /* ALIGN32 */
    u16 timehi;     /* NETWORK */
    
    u32 timelo;     /* NETWORK */    
    
    u16 fudge;      /* NETWORK */    
    u16 mac_size;   /* NATIVE  */    
    
    u16 original_id;/* NETWORK */    
    u16 error;      /* NETWORK */
    
    u16 other_len;  /* NETWORK */
    u16 reserved_1; /* ALIGN32 */
    
    u32 reserved_2; /* ALIGN64 */    

    u8 mac[64];
    u8 *other;

    tsig_hmac_t hmac;       /* only used for tcp */
    s8 tcp_tsig_countdown;  /* maximum value is supposed to be 100 */
    u8 mac_algorithm;
};

#endif

/* A memory pool for the lookup's benefit */

#define MESSAGE_POOL_SIZE 0x20000

// flags for MESSAGE_MAKE_QUERY_EX
#define MESSAGE_EDNS0_SIZE      0x4000 // any bit that is not set in EDNS0
#define MESSAGE_EDNS0_DNSSEC    0x8000

#define MESSAGE_BUFFER_SIZE     0x10500

#define MESSAGE_DATA_CONTROL_BUFFER_SIZE 64

struct message_data
{
    struct msghdr _msghdr;
    struct iovec  _iovec;
    socketaddress _sender;  // who the sender is
    u8 *_ar_start;          // for the TSIG
    
    // THIS CROUP IS COPIED USING A MEMCPY IN message_dup() ->
    
    u32 _rcode_ext;         // network endian
    finger_print _status;   // contains an RCODE, why is it separated from the buffer ?
#if MESSAGE_PAYLOAD_IS_POINTER
    u32 _message_data_size; // the size of the allocated message structure
#endif
    u16 _query_type;
    u16 _query_class;
    bool _edns;
    bool _nsid;
    char _protocol;         // will probably be removed
    u8 _referral;
    u8 _control_buffer_size;
    u8 _tcp_serial;
    
    /* bool is_delegation; for quick referral : later */
    
    u32 _buffer_size;                   // 32 bits aligned      // the maximum number of bytes we are ready to fill (can be changed)
    u32 _buffer_size_limit;             //                      // the maximum number of bytes we can ever fill (as the buffer size is limited and )

    void    *_pool;                     // a pool to be used as a quick memory for the message
    int     _pool_size;                 // a zdb query will store some temporary records in it. Consider size to be from 64K to 128K.

#if DNSCORE_HAS_TSIG_SUPPORT
    message_tsig _tsig;
#endif

    volatile u64 recv_us;
    volatile u64 pushed_us;
    volatile u64 popped_us;

    // <- THIS GROUP IS COPIED USING A MEMCPY IN message_dup()

    u8 _msghdr_control_buffer[(MESSAGE_DATA_CONTROL_BUFFER_SIZE + 7) & ~7]; // receives the destination address, IF MOVED, YOU NEED TO LOOK AT message_new_instance() ZEROMEMORY call
    u8 _canonised_fqdn[(MAX_DOMAIN_LENGTH + 7) & ~7];
    
    /* Ensure (buffer - buffer_tcp_len) is equal to 2 ! */
#if MESSAGE_PAYLOAD_IS_POINTER
    u8 *_buffer;
#else
    u64 __reserved_force_align__1;      // 64 bits aligned
    u16 __reserved_force_align__2;      // 32 bits aligned
    u8  _buffer_tcp_len[2];             // DON'T SEPARATE THESE TWO (FIRST)
    u8  _buffer[NETWORK_BUFFER_SIZE];   // DON'T SEPARATE THESE TWO (SECOND)
#endif
};

typedef struct message_data message_data;

struct message_data_with_buffer
{
    message_data message;
#if MESSAGE_PAYLOAD_IS_POINTER
    u64 __reserved_force_align__1;      // 64 bits aligned
    u8 _buffer[NETWORK_BUFFER_SIZE];    // DON'T SEPARATE THESE TWO (SECOND)
    u8 _buffer_limit[1];
#endif
};

typedef struct message_data_with_buffer message_data_with_buffer;

struct message_dnsupdate_data
{
    struct message_dnsupdate_data                                 *next;
    u32                                                            zttl;
    u16                                                           ztype;
    u16                                                          zclass;
    u8                                         zname[MAX_DOMAIN_LENGTH];
    output_stream                           zrdata[RDATA_MAX_LENGTH +1];
    u8                                                         *zrdata2;
    u16                                                      zrdata_len;
};

typedef struct message_dnsupdate_data message_dnsupdate_data;

/**
 * A message_map is a message_data wrapper that got the records indexed
 * Each vector entry points to the FQDN of a record in the message.
 */

struct message_map
{
    const message_data *mesg;
    ptr_vector records;
    u16 section_base[4];
};

typedef struct message_map message_map;


/*    ------------------------------------------------------------    */

/**
 * This sets a default, global, rate for functions supporting it.
 * Rate is used in TCP streaming so that if the other end reads or writes
 * too slowly then the connection is severed, harshly.
 * 
 * @param rate
 */

void message_set_minimum_troughput_default(double rate);

/*    ------------------------------------------------------------    */

static inline void message_set_protocol(message_data *mesg, u8 protocol)
{
    // THIS SEEMS POINTLESS AS IT'S ONLY USED FOR LOGGING
    (void)mesg;
    (void)protocol;
}

static inline u8 message_get_protocol(const message_data *mesg)
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

static inline void message_set_query_answer_authority_additional_counts_ne(message_data *mesg, u16 qd, u16 an, u16 ns, u16 ar)
{
#ifdef WORDS_BIGENDIAN
    u64 value = (((u64)qd) << 48) | (((u64)an) << 32) | (((u64)ns) << 16) | (((u64)ar)      );
#else
    u64 value = (((u64)qd)      ) | (((u64)an) << 16) | (((u64)ns) << 32) | (((u64)ar) << 48);
#endif
    SET_U64_AT(mesg->_buffer[4], value);
}

static inline void message_set_query_answer_authority_additional_counts(message_data *mesg, u16 qd, u16 an, u16 ns, u16 ar)
{
#ifdef WORDS_BIGENDIAN
    u64 value = (((u64)ntohs(qd)) << 48) | (((u64)ntohs(an)) << 32) | (((u64)ntohs(ns)) << 16) | (((u64)ntohs(ar))      );
#else
    u64 value = (((u64)ntohs(qd))      ) | (((u64)ntohs(an)) << 16) | (((u64)ntohs(ns)) << 32) | (((u64)ntohs(ar)) << 48);
#endif
    SET_U64_AT(mesg->_buffer[4], value);
}

static inline void message_set_authority_additional_counts(message_data *mesg, u16 ns, u16 ar)
{
#ifdef WORDS_BIGENDIAN
    u32 value = (((u32)ns) << 16) | (((u32)ar)      );
#else
    u32 value = (((u32)ns)      ) | (((u32)ar) << 16);
#endif
    MESSAGE_SET_NSAR(mesg->_buffer, value);
}

static inline void message_set_pool_buffer(message_data *mesg, void *p, int size)
{
    mesg->_pool = p;
    mesg->_pool_size = size;
}

static inline void* message_get_pool_buffer(const message_data *mesg)
{
    return mesg->_pool;
}

static inline int message_get_pool_size(const message_data *mesg)
{
    return mesg->_pool_size;
}

static inline u8 message_get_opcode(const message_data *mesg)
{
    return MESSAGE_OP(mesg->_buffer);
}

static inline void message_set_opcode(message_data *mesg, u8 op)
{
    MESSAGE_SET_OP(mesg->_buffer, op);
}

static inline void message_set_referral(message_data *mesg, u8 referral)
{
    mesg->_referral = referral;
}

static inline u8 message_get_referral(const message_data *mesg)
{
    return mesg->_referral;
}

// Network Endian operations

static inline u16 message_get_query_count_ne(const message_data *mesg)
{
    return MESSAGE_QD(mesg->_buffer);
}

static inline void message_set_answer_count_ne(message_data *mesg, u16 network_endian_value)
{
    MESSAGE_SET_AN(mesg->_buffer, network_endian_value);
}

static inline u16 message_get_answer_count_ne(const message_data *mesg)
{
    return MESSAGE_AN(mesg->_buffer);
}

static inline void message_set_authority_count_ne(message_data *mesg, u16 network_endian_value)
{
    MESSAGE_SET_NS(mesg->_buffer, network_endian_value);
}

static inline u16 message_get_authority_count_ne(const message_data *mesg)
{
    return MESSAGE_NS(mesg->_buffer);
}

static inline void message_set_additional_count_ne(message_data *mesg, u16 network_endian_value)
{
    MESSAGE_SET_AR(mesg->_buffer, network_endian_value);
}

static inline u16 message_get_additional_count_ne(const message_data *mesg)
{
    return MESSAGE_AR(mesg->_buffer);
}

static inline void message_set_update_count_ne(message_data *mesg, u16 network_endian_value)
{
    MESSAGE_SET_UP(mesg->_buffer, network_endian_value);
}

static inline u16 message_get_update_count_ne(const message_data *mesg)
{
    return MESSAGE_UP(mesg->_buffer);
}

static inline u16 message_get_prerequisite_count_ne(const message_data *mesg)
{
    return MESSAGE_PR(mesg->_buffer);
}

static inline u16 message_get_section_count_ne(const message_data *mesg, int section)
{
    return MESSAGE_SECTION_COUNT(mesg->_buffer, section);
}

// Host endian

static inline u16 message_get_query_count(const message_data *mesg)
{
    return ntohs(message_get_query_count_ne(mesg));
}

static inline void message_set_answer_count(message_data *mesg, u16 host_endian_value)
{
    message_set_answer_count_ne(mesg, htons(host_endian_value));
}

static inline u16 message_get_answer_count(const message_data *mesg)
{
    return ntohs(message_get_answer_count_ne(mesg));
}

static inline void message_set_authority_count(message_data *mesg, u16 host_endian_value)
{
    message_set_authority_count_ne(mesg, htons(host_endian_value));
}

static inline u16 message_get_authority_count(const message_data *mesg)
{
    return ntohs(message_get_authority_count_ne(mesg));
}

static inline void message_set_additional_count(message_data *mesg, u16 host_endian_value)
{
    message_set_additional_count_ne(mesg, htons(host_endian_value));
}

static inline u16 message_get_additional_count(const message_data *mesg)
{
    return ntohs(message_get_additional_count_ne(mesg));
}

static inline void message_add_additional_count(message_data *mesg, u16 value)
{
    message_set_additional_count(mesg, message_get_additional_count(mesg) + value);
}

static inline void message_sub_additional_count(message_data *mesg, u16 value)
{
    message_set_additional_count(mesg, message_get_additional_count(mesg) - value);
}

static inline void message_set_update_count(message_data *mesg, u16 host_endian_value)
{
    message_set_update_count_ne(mesg, htons(host_endian_value));
}

static inline u16 message_get_update_count(const message_data *mesg)
{
    return ntohs(message_get_update_count_ne(mesg));
}

static inline void message_add_update_count(message_data *mesg, u16 host_endian_value)
{
    message_set_update_count(mesg, message_get_update_count(mesg) + host_endian_value);
}

static inline u16 message_get_prerequisite_count(const message_data *mesg)
{
    return ntohs(message_get_prerequisite_count_ne(mesg));
}

static inline u16 message_get_section_count(const message_data *mesg, int section)
{
    return ntohs(message_get_section_count_ne(mesg, section));
}

//

static inline bool message_isquery(const message_data *mesg)
{
    return MESSAGE_QR(mesg->_buffer) == 0;
}

static inline bool message_isanswer(const message_data *mesg)
{
    return MESSAGE_QR(mesg->_buffer) != 0;
}

static inline bool message_istruncated(const message_data *mesg)
{
    return MESSAGE_TC(mesg->_buffer) != 0;
}

static inline void message_set_truncated(message_data *mesg, bool truncated)
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

static inline void message_set_answer(message_data *mesg)
{
    MESSAGE_HIFLAGS(mesg->_buffer) |= QR_BITS;
}

static inline void message_clear_answer(message_data *mesg)
{
    MESSAGE_HIFLAGS(mesg->_buffer) &= ~QR_BITS;
}

static inline bool message_has_recursion_desired(const message_data *mesg)
{
    return MESSAGE_RD(mesg->_buffer) != 0;
}

static inline bool message_has_recursion_available(const message_data *mesg)
{
    return MESSAGE_RA(mesg->_buffer) != 0;
}

static inline bool message_has_authenticated_data(const message_data *mesg)
{
    return MESSAGE_AD(mesg->_buffer) != 0;
}

static inline bool message_has_checking_disabled(const message_data *mesg)
{
    return MESSAGE_CD(mesg->_buffer) != 0;
}

static inline u8 message_get_rcode(const message_data *mesg)
{
    return MESSAGE_RCODE(mesg->_buffer);
}

static inline void message_or_rcode(message_data *mesg, u8 rcode)
{
    MESSAGE_LOFLAGS(mesg->_buffer) |= rcode;
}

static inline void message_set_rcode(message_data *mesg, u8 rcode)
{
    MESSAGE_LOFLAGS(mesg->_buffer) = (MESSAGE_LOFLAGS(mesg->_buffer) & ~RCODE_BITS) | rcode;
}

static inline u32 message_get_rcode_ext(const message_data *mesg)
{
    return mesg->_rcode_ext;
}

static inline bool message_has_rcode_ext_dnssec(const message_data *mesg)
{
    return (mesg->_rcode_ext & RCODE_EXT_DNSSEC) != 0;
}

static inline void message_set_authoritative_answer(message_data *mesg)
{
    MESSAGE_HIFLAGS(mesg->_buffer) |= AA_BITS|QR_BITS;
}

static inline void message_set_truncated_answer(message_data *mesg)
{
    MESSAGE_HIFLAGS(mesg->_buffer) |= TC_BITS|QR_BITS;
}

static inline void message_set_authoritative(message_data *mesg)
{
    MESSAGE_HIFLAGS(mesg->_buffer) |= AA_BITS;
}

static inline void message_disable_authoritative(message_data *mesg)
{
    MESSAGE_HIFLAGS(mesg->_buffer) &= ~AA_BITS;
}

static inline void message_set_recursion_desired(message_data *mesg)
{
    MESSAGE_HIFLAGS(mesg->_buffer) |= RD_BITS;
}

static inline void message_set_authenticated_data(message_data *mesg)
{
    MESSAGE_LOFLAGS(mesg->_buffer) |= AD_BITS;
}

static inline bool  message_isauthoritative(const message_data *mesg)
{
    return (MESSAGE_HIFLAGS(mesg->_buffer) & AA_BITS) != 0;
}

static inline void message_apply_mask(message_data *mesg, int hi, int lo)
{
    MESSAGE_FLAGS_AND(mesg->_buffer, (u8)hi, (u8)lo);
}

static inline void message_apply_lo_mask(message_data *mesg, u8 lo)
{
    MESSAGE_LOFLAGS(mesg->_buffer) &= lo;
}

static inline u16 message_get_query_type(const message_data *mesg)
{
    return mesg->_query_type;
}

static inline const u16* message_get_query_type_ptr(const message_data *mesg)
{
    return &mesg->_query_type;
}

static inline void message_set_query_type(message_data *mesg, u16 qtype)
{
    mesg->_query_type = qtype;
}

static inline u16 message_get_query_class(const message_data *mesg)
{
    return mesg->_query_class;
}

// mostly for printing with format

static inline const u16* message_get_query_class_ptr(const message_data *mesg)
{
    return &mesg->_query_class;
}

static inline void message_set_query_class(message_data *mesg, u16 qclass)
{
    mesg->_query_class = qclass;
}

static inline u16 message_get_size_u16(const message_data *mesg)
{
    return (u16)mesg->_msghdr.msg_iov[0].iov_len;
}

static inline size_t message_get_size(const message_data *mesg)
{
    return mesg->_msghdr.msg_iov[0].iov_len;
}

static inline void message_set_size(message_data *mesg, size_t size)
{
    mesg->_msghdr.msg_iov[0].iov_len = size;
}

static inline void message_increase_size(message_data *mesg, size_t size)
{
    mesg->_msghdr.msg_iov[0].iov_len += size;
}

static inline const u8 *message_get_buffer_const(const message_data *mesg)
{
    return mesg->_buffer;
}

static inline u8 *message_get_buffer(message_data *mesg)
{
    return mesg->_buffer;
}

static inline u16 message_get_flags(const message_data *mesg)
{
    return MESSAGE_FLAGS(mesg->_buffer);
}

static inline u8 message_get_flags_hi(const message_data *mesg)
{
    return MESSAGE_HIFLAGS(mesg->_buffer);
}

static inline u8 message_get_flags_lo(const message_data *mesg)
{
    return MESSAGE_LOFLAGS(mesg->_buffer);
}

static inline void message_set_flags_hi(message_data *mesg, u8 hi)
{
    MESSAGE_HIFLAGS(mesg->_buffer) = hi;
}

static inline void message_set_flags_lo(message_data *mesg, u8 lo)
{
    MESSAGE_LOFLAGS(mesg->_buffer) = lo;
}

static inline u8 message_get_op(message_data *mesg)
{
    return MESSAGE_OP(mesg->_buffer);
}

/**
 * Returns a pointer to the first byte not set in the buffer (&buffer[size])
 * WILL BE RENAMED INTO message_get_buffer_end(mesg)
 * @param mesg
 * @return 
 */

static inline u8 *message_get_buffer_limit(message_data *mesg)
{
    return &mesg->_buffer[message_get_size(mesg)];
}

static inline const u8 *message_get_buffer_limit_const(const message_data *mesg)
{
    return &mesg->_buffer[message_get_size(mesg)];
}

/**
 * The maximum size of the buffer is, of course, a constant.
 * This value is the one used to artificially limit the writing in the buffer.
 * This is mostly used to reserve room for additional records (EDNS, TSIG)
 * 
 * @param 
 * @return 
 */

static inline void message_set_buffer_size(message_data *mesg, u32 size)
{
    assert(size <= mesg->_buffer_size_limit);
    mesg->_buffer_size = size;    
}

static inline void message_reserve_buffer_size(message_data *mesg, u32 size)
{
    assert(size <= mesg->_buffer_size);
    mesg->_buffer_size -= size;
}

static inline void message_increase_buffer_size(message_data *mesg, u32 size)
{
    assert(size + mesg->_buffer_size <= mesg->_buffer_size_limit);
    mesg->_buffer_size += size;
}

static inline u32 message_get_buffer_size(const message_data *mesg)
{
    return mesg->_buffer_size;
}

static inline void message_reset_buffer_size(message_data *mesg)
{
    mesg->_buffer_size = mesg->_buffer_size_limit;
}

static inline u32 message_get_buffer_size_max(const message_data *mesg)
{
    return mesg->_buffer_size_limit;
}

/**
 * Copies the data content into the buffer
 */

static inline void message_copy_buffer(const message_data *mesg, void *out_data, size_t data_size)
{
    yassert(data_size >= message_get_size(mesg));
    (void)data_size;
    memcpy(out_data, message_get_buffer_const(mesg), message_get_size(mesg));
}

static inline void message_copy_into_buffer(message_data *mesg, const void *in_data, size_t data_size)
{
    if(data_size > message_get_buffer_size(mesg))
    {
        formatln("message_copy_into_buffer: %p data_size=%llu <= buffer_size=%u", mesg, data_size, message_get_buffer_size(mesg));
    }
    yassert(data_size <= message_get_buffer_size(mesg));
    memcpy(message_get_buffer(mesg), in_data, data_size);
    message_set_size(mesg, data_size);
}

/**
 * Copies the control content into the buffer
 */

static inline u8 message_copy_control(const message_data *mesg, void *out_data, size_t data_size)
{
#ifndef WIN32
    yassert(data_size >= mesg->_msghdr.msg_controllen);
    (void)data_size;
    memcpy(out_data, mesg->_msghdr.msg_control, mesg->_msghdr.msg_controllen);
    return mesg->_msghdr.msg_controllen;
#else
    return 0;
#endif
}

static inline u8 message_control_size(const message_data *mesg)
{
    return mesg->_msghdr.msg_controllen;
}

static inline void message_set_control(message_data *mesg, const void *data, size_t data_size)
{
#ifndef WIN32
    yassert(data_size <= sizeof(mesg->_msghdr_control_buffer));
    memcpy(mesg->_msghdr_control_buffer, data, data_size);
    mesg->_msghdr.msg_controllen = data_size;
#if __FreeBSD__
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

static inline void message_reset_control_size(message_data *mesg)
{
#ifndef WIN32
#if __FreeBSD__
    mesg->_msghdr.msg_control = mesg->_msghdr_control_buffer;
#endif
    mesg->_msghdr.msg_controllen = sizeof(mesg->_msghdr_control_buffer);
#else
#endif
}

static inline void message_reset_control(message_data *mesg)
{
#ifndef WIN32
    mesg->_msghdr.msg_control = mesg->_msghdr_control_buffer;
    mesg->_msghdr.msg_controllen = sizeof(mesg->_msghdr_control_buffer);
#else
#endif
}

static inline void message_clear_control(message_data *mesg)
{
#ifndef WIN32
    mesg->_msghdr.msg_control = NULL;
    mesg->_msghdr.msg_controllen = 0;
#else
#endif
}
    
static inline void message_set_edns0(message_data *mesg, bool enabled)
{
    mesg->_edns = enabled;
}

static inline bool message_is_edns0(const message_data *mesg)
{
    return mesg->_edns;
}

static inline bool message_has_nsid(const message_data *mesg)
{
    return mesg->_nsid;
}

static inline bool message_has_tsig(const message_data *mesg)
{
    return mesg->_tsig.tsig != NULL;
}

static inline void message_clear_hmac(message_data *mesg)
{
    if(mesg->_tsig.hmac != NULL)
    {
        hmac_free(mesg->_tsig.hmac);
        mesg->_tsig.hmac = NULL;
    }
}

static inline const u8 *message_tsig_get_name(const message_data *mesg)
{
    return mesg->_tsig.tsig->name;
}

static inline s64 message_tsig_get_epoch(const message_data *mesg)
{
    u64 then = (u64)ntohs(mesg->_tsig.timehi);
    then <<= 32;
    then |= (u64)ntohl(mesg->_tsig.timelo);
    return (s64)then;
}

static inline s64 message_tsig_get_fudge(const message_data *mesg)
{
    u64 then = (u64)ntohs(mesg->_tsig.fudge);
    return (s64)then;
}

static inline int message_tsig_mac_get_size(const message_data *mesg)
{
    return mesg->_tsig.mac_size;
}

static inline void message_tsig_set_error(message_data *mesg, u16 err)
{
    mesg->_tsig.error = err;
}

static inline void message_tsig_mac_copy(const message_data *mesg, u8 *to)
{
    memcpy(to, mesg->_tsig.mac, message_tsig_mac_get_size(mesg));
}

static inline const u8* message_tsig_mac_get_const(const message_data *mesg)
{
    return mesg->_tsig.mac;
}

static inline void message_tsig_copy_from(message_data *mesg, const message_data *source)
{
    message_tsig *d  = &mesg->_tsig;
    const message_tsig *s = &source->_tsig;
    memcpy(d, s, offsetof(message_tsig, mac));
    memcpy(d->mac, s->mac, s->mac_size);
    d->other = s->other;
    d->hmac = s->hmac;
    d->tcp_tsig_countdown = s->tcp_tsig_countdown;
    d->mac_algorithm = s->mac_algorithm;
}

static inline void message_tsig_set_key(message_data *mesg, const tsig_item *key)
{
    mesg->_tsig.tsig = key;
    mesg->_tsig.mac_algorithm = key->mac_algorithm;
}

static inline const tsig_item *message_tsig_get_key(const message_data *mesg)
{
    return mesg->_tsig.tsig;
}

static inline void message_tsig_clear_key(message_data *mesg)
{
    mesg->_tsig.tsig = NULL ;
}

static inline const u8 *message_tsig_get_key_bytes(const message_data *mesg)
{
    return mesg->_tsig.tsig->mac;
}

static inline u16 message_tsig_get_key_size(const message_data *mesg)
{
    return mesg->_tsig.tsig->mac_size;
}

static inline message_header *message_get_header(message_data *mesg)
{
    return (message_header*)message_get_buffer(mesg);
}

#if DEBUG
static inline void message_debug_trash_buffer(message_data *mesg)
{
    memset(message_get_buffer(mesg), 0xee, message_get_buffer_size_max(mesg));
}
#else
static inline void message_debug_trash_buffer(message_data *mesg)
{
    (void)mesg;
}
#endif

static inline void message_copy_msghdr(const message_data *mesg, struct msghdr *copyto)
{
    memcpy(copyto, &mesg->_msghdr, sizeof(mesg->_msghdr));
}

ya_result message_process_query(message_data *mesg);

int message_process(message_data *);
int message_process_lenient(message_data *mesg);

void message_transform_to_error(message_data *mesg);

/* global */

void message_edns0_setmaxsize(u16 maxsize);

static inline void message_edns0_clear_undefined_flags(message_data *mesg) // all but DO
{
    mesg->_rcode_ext &= RCODE_EXT_DNSSEC;
}

/**
    * 
    * @param mesg
    * @param qname
    * @param qtype
    * @param qclass
    * @param id
    */

void message_make_query(message_data *mesg, u16 id, const u8 *qname, u16 qtype, u16 qclass);

void message_make_query_ex(message_data *mesg, u16 id, const u8 *qname, u16 qtype, u16 qclass, u16 flags);

struct packet_writer;

void message_make_message(message_data *mesg, u16 id, const u8 *qname, u16 qtype, u16 qclass, struct packet_writer* uninitialised_packet_writer);

void message_make_dnsupdate_init(message_data *mesg, u16 id, const u8 *zzone, u16 zclass, u32 max_size, struct packet_writer *uninitialised_pw);
ya_result message_make_dnsupdate_delete_all_rrsets(message_data *mesg, struct packet_writer *pw, const u8 *fqdn);
ya_result message_make_dnsupdate_delete_rrset(message_data *mesg, struct packet_writer *pw, const u8 *fqdn, u16 rtype);
ya_result message_make_dnsupdate_delete_record(message_data *mesg, struct packet_writer *pw, const u8 *fqdn, u16 rtype, u16 rdata_size, const u8 *rdata);
ya_result message_make_dnsupdate_delete_dns_resource_record(message_data *mesg, struct packet_writer *pw, const struct dns_resource_record *rr);
ya_result message_make_dnsupdate_delete_dnskey(message_data *mesg, struct packet_writer *pw, dnssec_key *key);
ya_result message_make_dnsupdate_add_record(message_data *mesg, struct packet_writer *pw, const u8 *fqdn, u16 rtype, u16 rclass, s32 rttl, u16 rdata_size, const u8 *rdata);
ya_result message_make_dnsupdate_add_dns_resource_record(message_data *mesg, struct packet_writer *pw, const struct dns_resource_record *rr);
ya_result message_make_dnsupdate_add_dnskey(message_data *mesg, struct packet_writer *pw, dnssec_key *key, s32 ttl);
ya_result message_make_dnsupdate_finalize(message_data *mesg, struct packet_writer *pw);

/**
    *
    * @param mesg
    * @param qname
    * @param qtype
    * @param qclass
    * @param id
    */

void message_make_notify(message_data *mesg, u16 id, const u8 *qname, u16 qtype /* TYPE_SOA */, u16 qclass /* CLASS_IN */);

void message_make_ixfr_query(message_data *mesg, u16 id, const u8 *qname, u32 soa_ttl, u16 soa_rdata_size, const u8 *soa_rdata);

#if DNSCORE_HAS_TSIG_SUPPORT

ya_result message_sign_query_by_name(message_data *mesg, const u8 *tsig_name);

ya_result message_sign_answer_by_name(message_data *mesg, const u8 *tsig_name);

ya_result message_sign_query(message_data *mesg, const tsig_item *key);

ya_result message_sign_answer(message_data *mesg, const tsig_item *key);

#endif

/**
 * Creates an empty answer with an error code
 * 
 * @param mesg
 * @param error_code
 */

void message_make_error(message_data *mesg, u16 error_code);

/**
 * Creates an empty answer with an error code and TSIG signs it if needed
 * 
 * @param mesg
 * @param error_code
 */

void message_make_signed_error(message_data *mesg, u16 error_code);

ya_result message_make_error_and_reply_tcp(message_data *mesg, u16 error_code, int tcpfd);

ssize_t message_make_error_and_reply_tcp_with_default_minimum_throughput(message_data *mesg, u16 error_code, int tcpfd);
/**
 * Creates an answer with an OPT error code
 */

void message_make_error_ext(message_data *mesg, u32 error_code);

static inline ya_result message_set_sender_from_host_address(message_data *mesg, const host_address *ha)
{
    ya_result ret = host_address2sockaddr(ha, &mesg->_sender);
    if(ISOK(ret))
    {
        mesg->_msghdr.msg_namelen = ret;
    }
    return ret;
}

static inline int message_get_sender_size(const message_data *mesg)
{
    return mesg->_msghdr.msg_namelen;
}

static inline const socketaddress *message_get_sender(const message_data *mesg)
{
    return &mesg->_sender;
}

static inline ya_result message_set_sender_port(message_data *mesg, u16 port)
{
    switch(mesg->_sender.sa.sa_family)
    {
        case AF_INET:
        {
            mesg->_sender.sa4.sin_port = port;
            return port;
        }
        case AF_INET6:
        {
            mesg->_sender.sa6.sin6_port = port;
            return port;
        }
        default:
        {
            return INVALID_STATE_ERROR;
        }
    }
}

static inline const struct sockaddr *message_get_sender_sa(const message_data *mesg)
{
    return &mesg->_sender.sa;
}

static inline sa_family_t message_get_sender_sa_family(const message_data *mesg)
{
    return mesg->_sender.sa.sa_family;
}

static inline size_t message_get_sender_sa_family_size(const message_data *mesg)
{
    switch(mesg->_sender.sa.sa_family)
    {
        case AF_INET:
        {
            return sizeof(struct sockaddr_in);
        }
        case AF_INET6:
        {
            return sizeof(struct sockaddr_in6);
        }
        default:
        {
            return 0;
        }
    }
}

static inline const struct sockaddr_in *message_get_sender_sa4(const message_data *mesg)
{
    return &mesg->_sender.sa4;
}

static inline const struct sockaddr_in6 *message_get_sender_sa6(const message_data *mesg)
{
    return &mesg->_sender.sa6;
}

static inline void message_copy_sender_from(message_data *mesg, const message_data *original)
{
    memcpy(&mesg->_sender, &original->_sender, message_get_sender_size(original));
    mesg->_msghdr.msg_name = &mesg->_sender;
    mesg->_msghdr.msg_namelen = original->_msghdr.msg_namelen;
}

static inline void message_copy_sender_from_sa(message_data *mesg, const struct sockaddr *sa, socklen_t sa_len)
{
    memcpy(&mesg->_sender, sa, sa_len);
    mesg->_msghdr.msg_namelen = sa_len;
}

static inline ya_result message_copy_sender_from_socket(message_data *mesg, int client_sockfd)
{
    mesg->_msghdr.msg_namelen = sizeof(mesg->_sender);
    if(getpeername(client_sockfd, (struct sockaddr*)&mesg->_sender, &mesg->_msghdr.msg_namelen) >= 0)
    {
        mesg->_msghdr.msg_name = &mesg->_sender;
        return SUCCESS;
    }
    else
    {
        return ERRNO_ERROR;
    }
}

static inline void message_copy_sender_to_sa(const message_data *mesg, struct sockaddr *bigenoughforipv6)
{
    memcpy(bigenoughforipv6, message_get_sender_sa(mesg), message_get_sender_size(mesg));
}

static inline u16 message_get_u16_at(const message_data *mesg, int offset)
{
    return GET_U16_AT(mesg->_buffer[offset]);
}

static inline void message_send_udp_reset(message_data *mesg)
{
    mesg->_msghdr.msg_namelen = sizeof(mesg->_sender);
    mesg->_iovec.iov_len = mesg->_buffer_size;
}

#if !DEBUG
static inline s32 message_send_udp(const message_data *mesg, int sockfd)
{
    s32 n;

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
s32 message_send_udp_debug(const message_data *mesg, int sockfd);

static inline s32 message_send_udp(const message_data *mesg, int sockfd)
{
    s32 ret = message_send_udp_debug(mesg, sockfd);
    return ret;
}
#endif

static inline void message_recv_udp_reset(message_data *mesg)
{
    mesg->_msghdr.msg_namelen = sizeof(mesg->_sender);
    mesg->_iovec.iov_len = mesg->_buffer_size;
}

static inline ssize_t message_recv_udp(message_data *mesg, int sockfd)
{
    ssize_t ret = recvmsg(sockfd, &mesg->_msghdr, 0);
    if(ret >= 0)
    {
        message_set_size(mesg, ret);
#if __FreeBSD__
        if(mesg->_msghdr.msg_controllen == 0)
        {
            mesg->_msghdr.msg_control = NULL;
        }
#endif
    }
    return ret;
}
/*
static inline ssize_t message_send_udp(message_data *mesg, int sockfd)
{
    mesg->_iovec.iov_len = message_get_size(mesg);
    ssize_t ret = sendmsg(sockfd, &mesg->_msghdr, 0);
    return ret;
}
*/

static inline const u8 *message_parse_query_fqdn(const message_data *mesg)
{
    if(message_get_query_count_ne(mesg) != 0)
    {
        return &mesg->_buffer[DNS_HEADER_LENGTH];
    }
    else
    {
        return NULL;
    }
}

static inline u16 message_parse_query_type(const message_data *mesg)
{
    if(message_get_query_count_ne(mesg) != 0)
    {
        const u8 *fqdn = &mesg->_buffer[DNS_HEADER_LENGTH];
        fqdn += dnsname_len(fqdn);
        return GET_U16_AT_P(fqdn);
    }
    else
    {
        return TYPE_NONE;
    }
}

static inline u16 message_parse_query_class(const message_data *mesg)
{
    if(message_get_query_count_ne(mesg) != 0)
    {
        const u8 *fqdn = &mesg->_buffer[DNS_HEADER_LENGTH];
        fqdn += dnsname_len(fqdn) + 2;
        return GET_U16_AT_P(fqdn);
    }
    else
    {
        return TYPE_NONE;
    }
}

static inline const u8 *message_get_canonised_fqdn(const message_data *mesg)
{
    return mesg->_canonised_fqdn;
}

static inline void message_set_canonised_fqdn(message_data *mesg, const u8 *canonised_fqdn)
{
    dnsname_copy(mesg->_canonised_fqdn, canonised_fqdn);
}

static inline int message_get_maximum_size(const message_data *mesg)
{
    return mesg->_buffer_size;
}

static inline u8* message_get_query_section_ptr(message_data *mesg)
{
    return &mesg->_buffer[DNS_HEADER_LENGTH];
}

static inline u8* message_get_additional_section_ptr(message_data *mesg)
{
    return mesg->_ar_start;
}

static inline const u8* message_get_additional_section_ptr_const(const message_data *mesg)
{
    return mesg->_ar_start;
}

static inline bool message_is_additional_section_ptr_set(const message_data *mesg)
{
    return mesg->_ar_start != NULL;
}

static inline void message_set_additional_section_ptr(message_data *mesg, void *ptr)
{
    mesg->_ar_start = (u8*)ptr;
}

static inline finger_print message_get_status(const message_data *mesg)
{
    return mesg->_status;
}

static inline void message_set_status(message_data *mesg, finger_print fp)
{
    mesg->_status = fp;
}

static inline void message_set_error_status_from_result(message_data *mesg, ya_result error_code)
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

    message_set_status(mesg, fp);
}

static inline void message_set_status_from_result(message_data *mesg, ya_result error_code)
{
    finger_print fp;

    if(ISOK(error_code))
    {
        fp = RCODE_NOERROR;
    }
    else if(YA_ERROR_BASE(error_code) == RCODE_ERROR_BASE)
    {
        fp = RCODE_ERROR_GETCODE(error_code);
    }
    else
    {
        fp = FP_RCODE_SERVFAIL;
    }

    message_set_status(mesg, fp);
}

static inline void message_update_answer_status(message_data *mesg)
{
    MESSAGE_FLAGS_OR(mesg->_buffer, QR_BITS, mesg->_status);
}

static inline void message_update_truncated_answer_status(message_data *mesg)
{
    MESSAGE_FLAGS_OR(mesg->_buffer, QR_BITS|TC_BITS, mesg->_status);
}

static inline u16 message_get_id(const message_data *mesg)
{
    return MESSAGE_ID(mesg->_buffer);
}

#if MESSAGE_PAYLOAD_IS_POINTER

static inline ssize_t message_recv_tcp(message_data *mesg, int sockfd)
{
    u16 tcp_len;

    ssize_t ret = readfully(sockfd, &tcp_len, 2);

    if(ret < 0)
    {
        return ret;
    }

    tcp_len = ntohs(tcp_len);

    if(tcp_len < message_get_maximum_size(mesg))
    {
        ret = readfully(sockfd, mesg->_buffer, tcp_len);

        if(ISOK(ret))
        {
            message_set_size(mesg, ret);
        }

        return ret;
    }
    else
    {
        return BUFFER_WOULD_OVERFLOW;
    }
}

static inline ssize_t message_write_tcp(const message_data *mesg, output_stream *os)
{
    ssize_t ret;
    u16 tcp_len = htons(message_get_size_u16(mesg));
    if(ISOK(ret = output_stream_write_fully(os, &tcp_len, 2)))
    {
        ret = output_stream_write_fully(os, message_get_buffer_const(mesg), message_get_size(mesg));
    }
    return ret;
}

static inline ssize_t message_read_tcp(message_data *mesg, input_stream *is)
{
    u16 tcp_len;

    ssize_t ret = input_stream_read_fully(is, &tcp_len, 2);

    if(ret < 0)
    {
        return ret;
    }

    tcp_len = ntohs(tcp_len);

    if(tcp_len < message_get_maximum_size(mesg))
    {
        ret = input_stream_read_fully(is, mesg->_buffer, tcp_len);

        if(ISOK(ret))
        {
            message_set_size(mesg, ret);
        }

        return ret;
    }
    else
    {
        return BUFFER_WOULD_OVERFLOW;
    }
}

#if 0
static inline ssize_t message_send_tcp(const message_data *mesg, int sockfd)
{
    ssize_t ret;

    u16 tcp_len = htons(message_get_size_u16(mesg));
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
ssize_t message_send_tcp(const message_data *mesg, int sockfd);
#endif

static inline ssize_t message_send_tcp_with_minimum_throughput(const message_data *mesg, int sockfd, double minimum_rate)
{
    ssize_t ret;
    u16 tcp_len = htons(message_get_size_u16(mesg));
    if(ISOK(ret = writefully_limited(sockfd, &tcp_len, 2, minimum_rate)))
    {
        assert(ret == 2);

        if(ISOK(ret = writefully_limited(sockfd, message_get_buffer_const(mesg), message_get_size(mesg), minimum_rate)))
        {
            assert(ret == (ssize_t)message_get_size(mesg));

            return ret + 2;
        }
    }
    return ret;
}

static inline ssize_t message_update_length_send_tcp_with_minimum_throughput(message_data *mesg, int sockfd, double minimum_rate)
{
    ssize_t ret = message_send_tcp_with_minimum_throughput(mesg, sockfd, minimum_rate);
    return ret;
}

extern double g_message_data_minimum_troughput_default;

static inline ssize_t message_update_length_send_tcp_with_default_minimum_throughput(message_data *mesg, int sockfd)
{
    ssize_t ret = message_send_tcp_with_minimum_throughput(mesg, sockfd, g_message_data_minimum_troughput_default);
    return ret;
}

#else
static inline void message_update_tcp_length(message_data *mesg)
{
    u16 len = message_get_size_u16(mesg);
    SET_U16_AT(mesg->_buffer_tcp_len[0], htons(len));
}

static inline u32 message_get_tcp_length(const message_data *mesg)
{
    u16 len = GET_U16_AT(mesg->_buffer_tcp_len[0]);
    return ntohs(len);
}

static inline const u8 *message_get_tcp_buffer_const(const message_data *mesg)
{
    return mesg->_buffer_tcp_len;
}

static inline u8 *message_get_tcp_buffer(message_data *mesg)
{
    return mesg->_buffer_tcp_len;
}

static inline ssize_t message_recv_tcp(message_data *mesg, int sockfd)
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

static inline ssize_t message_write_tcp(const message_data *mesg, output_stream *os)
{
    message_update_tcp_length(mesg);
    ssize_t ret = output_stream_write(os, message_get_tcp_buffer_const(mesg), message_get_size_u16(mesg) + 2);
    return ret;
}

static inline ssize_t message_read_tcp(message_data *mesg, input_stream *is)
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

static inline ssize_t message_send_tcp(const message_data *mesg, int sockfd)
{
    ssize_t ret = writefully(sockfd, message_get_tcp_buffer_const(mesg), message_get_size_u16(mesg) + 2);
    return ret;
}

static inline ssize_t message_send_tcp_with_minimum_throughput(const message_data *mesg, int sockfd, double minimum_rate)
{
    ssize_t ret = writefully_limited(sockfd, message_get_tcp_buffer_const(mesg), message_get_size_u16(mesg) + 2, minimum_rate);
    return ret;
}

static inline ssize_t message_update_length_send_tcp_with_minimum_throughput(message_data *mesg, int sockfd, double minimum_rate)
{
    message_update_tcp_length(mesg);
    ssize_t ret = message_send_tcp_with_minimum_throughput(mesg, sockfd, minimum_rate);
    return ret;
}

extern double g_message_data_minimum_troughput_default;

static inline ssize_t message_update_length_send_tcp_with_default_minimum_throughput(message_data *mesg, int sockfd)
{
    message_update_tcp_length(mesg);
    ssize_t ret = message_send_tcp_with_minimum_throughput(mesg, sockfd, g_message_data_minimum_troughput_default);
    return ret;
}

#endif

static inline void message_set_id(message_data *mesg, u16 id)
{
    MESSAGE_SET_ID(mesg->_buffer, id);
}

static inline void message_make_truncated_empty_answer(message_data *mesg)
{
    message_set_truncated_answer(mesg);
    message_set_query_answer_authority_additional_counts_ne(mesg, 0, 0, 0, 0);
    message_set_size(mesg, DNS_HEADER_LENGTH);
}

/**
 * To be called on a message at the beginning of a TCP stream
 * 
 * @param mesg
 */

static inline void message_tcp_serial_reset(message_data *mesg)
{
    mesg->_tcp_serial = 0;
}

/**
 * To be called on a message when reading a following TCP stream message
 * 
 * @param mesg
 */

static inline void message_tcp_serial_increment(message_data *mesg)
{
    ++mesg->_tcp_serial;
}

ya_result message_query_tcp_with_timeout(message_data *mesg, const host_address *server, u8 to_sec);
ya_result message_query_tcp_with_timeout_ex(message_data *mesg, const host_address *server, message_data *answer, u8 to_sec);
ya_result message_query_tcp(message_data *mesg, const host_address *server);
ya_result message_query_tcp_ex(message_data *mesg, const host_address *bindto, const host_address *server, message_data *answer);
ya_result message_query_udp(message_data *mesg, const host_address *server);
ya_result message_query_udp_with_timeout(message_data *mesg, const host_address *server, int seconds, int useconds);

#define MESSAGE_QUERY_UDP_FLAG_RESET_ID 1

ya_result message_query_udp_with_timeout_and_retries(message_data *mesg, const host_address *server, int seconds, int useconds, u8 retries, u8 flags);

ya_result message_query(message_data *mesg, const host_address *server);

ya_result message_query_serial(const u8 *origin, const host_address *server, u32 *serial_out);

ya_result message_get_ixfr_query_serial(message_data *mesg, u32 *serialp);

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
ya_result message_terminate_then_write(message_data *mesg, output_stream *tcpos, tsig_tcp_message_position pos);
#else
ya_result message_terminate_then_write(message_data *mesg, output_stream *tcpos, int unused);
#endif

#if MESSAGE_PAYLOAD_IS_POINTER
void message_init_ex(message_data* mesg, u32 mesg_size, void *buffer, size_t buffer_size);

static inline message_data *message_data_with_buffer_init(message_data_with_buffer *mesg_buff)
{
    message_init_ex(&mesg_buff->message, sizeof(struct message_data_with_buffer), mesg_buff->_buffer, mesg_buff->_buffer_limit - mesg_buff->_buffer);
    return &mesg_buff->message;
}
#else
void message_init(message_data* mesg);

static inline message_data *message_data_with_buffer_init(message_data_with_buffer *mesg_buff)
{
    message_init(&mesg_buff->message);
    return &mesg_buff->message;
}
#endif

/**
 * If pointer is NULL, the structure and buffer will be allocated together
 * Note that in the current implementation, 8 bytes are reserved for TCP
 */

message_data* message_new_instance_ex(void *ptr, u32 message_size);    // should be size of edns0 or 64K for TCP

message_data* message_new_instance(); // message_new_instance_ex(64K)

void message_finalize(message_data *mesg);

void message_free(message_data *mesg);

/*
 * Does not clone the pool.
 */

message_data* message_dup(const message_data *mesg);

ya_result message_ixfr_query_get_serial(const message_data *mesg, u32 *serial);

/**
 * Maps records in a message to easily access them afterward.
 * 
 * @param map the message map to initialise
 * @param mesg the message to map
 * 
 * @return an error code
 */

ya_result message_map_init(message_map *map, const message_data *mesg);

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

ya_result message_map_get_fqdn(const message_map *map, int index, u8 *fqdn, int fqdn_size);

/**
 * Gets the type class ttl rdata_size of the record at index
 * 
 * @param map
 * @param index
 * @param tctr
 * 
 * @return an error code
 */


ya_result message_map_get_tctr(const message_map *map, int index, struct type_class_ttl_rdlen *tctr);

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

ya_result message_map_get_rdata(const message_map *map, int index, u8 *rdata, int rdata_size);

/**
 * Gets the type of the record at index
 * 
 * @param map
 * @param index
 * 
 * @return the record type or an error code  
 */

ya_result message_map_get_type(const message_map *map, int index);

/**
 * 
 * @param map
 * 
 * @return the number of records mapped
 */

int message_map_record_count(const message_map *map);

/**
 * Returns the index of the next record with the given type
 * from, and including, a given index.
 * 
 * @param map
 * @param index
 * @param type
 * @return 
 */

int message_map_get_next_record_from(const message_map *map, int index, u16 type);

/**
 * Returns the index of the next record with the given type
 * from, and including, a given index in a given section (0 to 3).
 * 
 * @param map
 * @param index
 * @param type
 * @return 
 */

int message_map_get_next_record_from_section(const message_map *map, int section, int index, u16 type);

/**
 * Returns the base index of a section
 * 
 * @param map
 * @param section
 * @return 
 */

static inline int message_map_get_section_base(const message_map *map, int section)
{
    return map->section_base[section];
}

/**
 * Sorts records by section so that:
 * _ SOA is first,
 * _ NSEC is last,
 * _ NSEC3 labels are at the end,
 * _ RRSIG follows its RRSET
 * 
 * @param map
 */

void message_map_reorder(message_map *map);

void message_map_print(const message_map *map, output_stream *os);

/**
 * Releases the memory used by the map
 * 
 * @param map
 */

void message_map_finalize(message_map *map);

/**
 * Gets the global edns0 maximum size
 * 
 * @return 
 */

u16 message_edns0_getmaxsize();

static inline void message_set_rd_flag(message_data *mesg)
{
    MESSAGE_HIFLAGS(mesg->_buffer) |= RD_BITS;
}

struct logger_handle;

void message_log(struct logger_handle *logger, int level, const message_data *mesg);

ya_result message_print_format_multiline(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);
ya_result message_print_format_short(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);
ya_result message_print_format_wire(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);
ya_result message_print_format_wire_ext(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);

ya_result message_print_format_dig(output_stream *os_, const u8 *buffer, u32 length, u16 view_mode_with, long time_duration);
ya_result message_print_format_dig_buffer(output_stream *os_, const u8 *buffer, u32 length, u16 view_mode_with);

ya_result message_print_format_json(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);
ya_result message_print_format_json_buffer(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with);

ya_result message_print_format_parse(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);
ya_result message_print_buffer_format_parse(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with);

ya_result message_print_format_xml(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);
ya_result message_print_format_xml_buffer(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with);

#ifdef __cplusplus
}
#endif

/** @} */
