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
/** @defgroup dnspacket DNS Messages
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#ifndef MESSAGE_H_
#define MESSAGE_H_

#ifdef __cplusplus
extern "C"
{
#endif

    /*    ------------------------------------------------------------    */

#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <pthread.h>

#include <dnscore/rfc.h>
#include <dnscore/fingerprint.h>
#include <dnscore/tsig.h>
#include <dnscore/host_address.h>
#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>
#include <dnscore/packet_writer.h>

    /*    ------------------------------------------------------------    */

    /* Processing flags */
#define PROCESS_FL_ADDITIONAL_AUTH      0x01
#define PROCESS_FL_AUTHORITY_AUTH       0x02
#define PROCESS_FL_ADDITIONAL_CACHE     0x04
#define PROCESS_FL_AUTHORITY_CACHE      0x08
#define PROCESS_FL_RECURSION            0x20
#define PROCESS_FL_TCP                  0x80
    
#define NETWORK_BUFFER_SIZE 65536
    
    /**
     * @note buffer MUST be aligned on 16 bits
     */
#define MESSAGE_ID(buffer)	(*((u16*)&(buffer)[ 0]))

#define MESSAGE_HIFLAGS(buffer_) ((buffer_)[ 2])
#define MESSAGE_LOFLAGS(buffer_) ((buffer_)[ 3])

/* Only use constants with this */
#ifdef WORDS_BIGENDIAN
#define MESSAGE_FLAGS_OR(buffer_, hi_, lo_) *((u16*)&(buffer_[2])) |= (lo_ | ((u16)hi_ << 8))
#define MESSAGE_FLAGS_AND(buffer_, hi_, lo_) *((u16*)&(buffer_[2])) &= (lo_ | ((u16)hi_ << 8))
#define MESSAGE_FLAGS_SET(buffer_, hi_, lo_) *((u16*)&(buffer_[2])) = (lo_ | ((u16)hi_ << 8))
#else
#define MESSAGE_FLAGS_OR(buffer_, hi_, lo_) *((u16*)&(buffer_[2])) |= (hi_ | ((u16)lo_ << 8))
#define MESSAGE_FLAGS_AND(buffer_, hi_, lo_) *((u16*)&(buffer_[2])) &= (hi_ | ((u16)lo_ << 8))
#define MESSAGE_FLAGS_SET(buffer_, hi_, lo_) *((u16*)&(buffer_[2])) = (hi_ | ((u16)lo_ << 8))
#endif

#define MESSAGE_QR(buffer)      (MESSAGE_HIFLAGS(buffer)&QR_BITS)
#define MESSAGE_OP(buffer)      (MESSAGE_HIFLAGS(buffer)&OPCODE_BITS)
#define MESSAGE_AA(buffer)      (MESSAGE_HIFLAGS(buffer)&AA_BITS)
#define MESSAGE_TC(buffer)  	(MESSAGE_HIFLAGS(buffer)&TC_BITS)
#define MESSAGE_RD(buffer)      (MESSAGE_HIFLAGS(buffer)&RD_BITS)

#define MESSAGE_RA(buffer)  	(MESSAGE_LOFLAGS(buffer)&RA_BITS)
#define MESSAGE_ZF(buffer)  	(MESSAGE_LOFLAGS(buffer)&Z_BITS)
#define MESSAGE_AD(buffer)      (MESSAGE_LOFLAGS(buffer)&AD_BITS)
#define MESSAGE_CD(buffer)      (MESSAGE_LOFLAGS(buffer)&CD_BITS)
#define MESSAGE_RCODE(buffer)	(MESSAGE_LOFLAGS(buffer)&RCODE_BITS)

#define MESSAGE_QD(buffer)	(*((u16*)&(buffer)[ 4]))
#define MESSAGE_AN(buffer)	(*((u16*)&(buffer)[ 6]))
#define MESSAGE_NS(buffer)	(*((u16*)&(buffer)[ 8]))
#define MESSAGE_AR(buffer)	(*((u16*)&(buffer)[10]))
#define MESSAGE_NSAR(buffer) (*((u32*)&(buffer)[ 8]))

    /* DYNUPDATE rfc 2136 */
#define MESSAGE_ZO(buffer)	(*((u16*)&(buffer)[ 4]))
#define MESSAGE_PR(buffer)	(*((u16*)&(buffer)[ 6]))
#define MESSAGE_UP(buffer)	(*((u16*)&(buffer)[ 8]))
//#define MESSAGE_AD(buffer)	(*((u16*)&(buffer)[10]))

#if HAS_TSIG_SUPPORT == 1

#define MESSAGE_HAS_TSIG(__message) ((__message).tsig.tsig != NULL)
#define MESSAGEP_HAS_TSIG(__message) ((__message)->tsig.tsig != NULL)

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

    HMAC_CTX ctx;   /* only used for tcp */
    s8 tcp_tsig_countdown;  /* Maximum value is supposed to be 100 */
    u8 mac_algorithm;
};

#endif

/* A memory pool for the lookup's benefit @TODO: maybe this should be increased in size */

#define MESSAGE_POOL_SIZE 0x20000

// flags for MESSAGE_MAKE_QUERY_EX
#define MESSAGE_EDNS0_SIZE      0x4000 // any bit that is not set in EDNS0
#define MESSAGE_EDNS0_DNSSEC    0x8000

typedef struct message_data message_data;

struct message_data
{
    u8 *ar_start; /* for the TSIG */

    socketaddress other;

    u16 received;
    u16 size_limit;
    u16 send_length;
    u16 reserved_;

    socklen_t addr_len;

    int sockfd;

    finger_print status;

    u32 rcode_ext;

    bool edns;

    process_flags_t process_flags;

    u16 qtype;
    u16 qclass;

    char protocol;
    u8 referral;
    /* bool is_delegation; for quick referral : later */

#if HAS_TSIG_SUPPORT
    message_tsig tsig;
#endif

    u_char qname[MAX_DOMAIN_LENGTH];

    /* Ensure (buffer - buffer_tcp_len) is equal to 2 ! */
    u64 __reserved_force_align__1;
    u32 __reserved_force_align__2;
    u16 __reserved_force_align__3;
    u8  buffer_tcp_len[2];           /* DON'T SEPARATE THESE TWO (FIRST)  */
    u8  buffer[NETWORK_BUFFER_SIZE]; /* DON'T SEPARATE THESE TWO (SECOND) */
    u64 __reserved_force_align__4;
    u8  pool_buffer[MESSAGE_POOL_SIZE]; /* A memory pool for the lookup's benefit @TODO: maybe this should be increased in size */
};

/*    ------------------------------------------------------------    */

static inline bool message_isquery(message_data *mesg)
{
    return MESSAGE_QR(mesg->buffer) == 0;
}

static inline bool message_isanswer(message_data *mesg)
{
    return MESSAGE_QR(mesg->buffer) != 0;
}

int message_process(message_data *);
int message_process_lenient(message_data *mesg);

int message_trim(message_data *);
void message_transform_to_error(message_data *mesg);

/* global */

void message_edns0_setmaxsize(u16 maxsize);

/**
    * 
    * @param mesg
    * @param qname
    * @param qtype
    * @param qclass
    * @param id
    */

void message_make_query(message_data *mesg, u16 id, const u8 *qname, u16 qtype, u16 qclass);

void message_make_message(message_data *mesg, u16 id, const u8 *qname, u16 qtype, u16 qclass, packet_writer* uninitialised_packet_writer);

/**
    *
    * @param mesg
    * @param qname
    * @param qtype
    * @param qclass
    * @param id
    */

void message_make_notify(message_data *mesg, u16 id, const u8 *qname);

void message_make_ixfr_query(message_data *mesg, u16 id, const u8 *qname, u32 soa_ttl, u16 soa_rdata_size, const u8 *soa_rdata);

ya_result message_sign_query_by_name(message_data *mesg, const u8 *tsig_name);

ya_result message_sign_answer_by_name(message_data *mesg, const u8 *tsig_name);

ya_result message_sign_query(message_data *mesg, const tsig_item *key);

ya_result message_sign_answer(message_data *mesg, const tsig_item *key);

/**
    * Creates an empty answer with an error code
    */

void message_make_error(message_data *mesg, u16 error_code);

/**
    * Creates an answer with an OPT error code
    */

void message_make_error_ext(message_data *mesg, u16 error_code);

static inline void message_update_tcp_length(message_data *mesg)
{
    u16 len = mesg->send_length;

    mesg->buffer_tcp_len[0] = (u8)(len>>8);
    mesg->buffer_tcp_len[1] = (u8)(len   );
}

static inline u16 message_get_tcp_length(message_data *mesg)
{
    u16 len;

    len = mesg->buffer_tcp_len[0];
    len <<= 8;
    len |= mesg->buffer_tcp_len[1];

    return len;
}


ya_result message_query_tcp(message_data *mesg, host_address *server);
ya_result message_query_udp(message_data *mesg, host_address *server);
ya_result message_query_serial(const u8 *origin, host_address *server, u32 *serial_out);

ya_result message_ixfr_query_get_serial(const message_data *mesg, u32 *serial);

ya_result message_print_buffer(output_stream *os, const u8 *buffer, u16 length);

#ifdef __cplusplus
}
#endif

#endif /* MESSAGE_H_ */

/** @} */
