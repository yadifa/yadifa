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
#include <dnscore/sys_types.h>
#include <dnscore/fingerprint.h>
#include <dnscore/host_address.h>
#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>
#include <dnscore/packet_writer.h>
#include <dnscore/tsig.h>

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

#define MESSAGE_HIFLAGS(buffer_) ((buffer_)[ 2])
#define MESSAGE_LOFLAGS(buffer_) ((buffer_)[ 3])

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

/* A memory pool for the lookup's benefit */

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
#if HAS_NSID_SUPPORT
    bool nsid;
#endif

    process_flags_t process_flags;

    u16 qtype;
    u16 qclass;

    char protocol;
    u8 referral;
    /* bool is_delegation; for quick referral : later */

#if DNSCORE_HAS_TSIG_SUPPORT
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


typedef struct message_dnsupdate_data message_dnsupdate_data;

struct message_dnsupdate_data
{
    message_dnsupdate_data                                        *next;
    u32                                                            zttl;
    u16                                                           ztype;
    u16                                                          zclass;
    u8 zname[MAX_DOMAIN_LENGTH];
    output_stream                           zrdata[RDATA_MAX_LENGTH +1];
    u8                                                         *zrdata2;
    u16                                                      zrdata_len;
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

ya_result message_process_query(message_data *mesg);

int message_process(message_data *);
int message_process_lenient(message_data *mesg);

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

void message_make_query_ex(message_data *mesg, u16 id, const u8 *qname, u16 qtype, u16 qclass, u16 flags);

void message_make_message(message_data *mesg, u16 id, const u8 *qname, u16 qtype, u16 qclass, packet_writer* uninitialised_packet_writer);

void message_make_dnsupdate_init(message_data *mesg, u16 id, const u8 *zzone, u16 zclass, u16 max_size, packet_writer *uninitialised_pw);
ya_result message_make_dnsupdate_delete_all_rrsets(message_data *mesg, packet_writer *pw, const u8 *fqdn);
ya_result message_make_dnsupdate_delete_rrset(message_data *mesg, packet_writer *pw, const u8 *fqdn, u16 rtype);
ya_result message_make_dnsupdate_delete_record(message_data *mesg, packet_writer *pw, const u8 *fqdn, u16 rtype, u16 rdata_size, const u8 *rdata);
ya_result message_make_dnsupdate_add_record(message_data *mesg, packet_writer *pw, const u8 *fqdn, u16 rtype, u16 rclass, u32 rttl, u16 rdata_size, const u8 *rdata);
ya_result message_make_dnsupdate_finalize(message_data *mesg, packet_writer *pw);

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


ya_result message_query_tcp_with_timeout(message_data *mesg, host_address *server,  u8 to_sec);
ya_result message_query_tcp(message_data *mesg, host_address *server);
ya_result message_query_tcp_ex(message_data *mesg, host_address *server, message_data *answer);
ya_result message_query_udp(message_data *mesg, host_address *server);
ya_result message_query_udp_with_time_out(message_data *mesg, host_address *server, int seconds, int useconds);
ya_result message_query_udp_with_time_out_and_retries(message_data *mesg, host_address *server, int seconds, int useconds, u8 retries, u8 flags); 
ya_result message_query_serial(const u8 *origin, host_address *server, u32 *serial_out);

/*
 * Does not clone the pool.
 */

message_data* message_dup(message_data *mesg);

ya_result message_ixfr_query_get_serial(const message_data *mesg, u32 *serial);

ya_result message_print_buffer(output_stream *os, const u8 *buffer, u16 length);

u16 message_edns0_getmaxsize();


ya_result message_print_format_multiline(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);
ya_result message_print_format_short(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);
ya_result message_print_format_wire(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);
ya_result message_print_format_wire_ext(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);

ya_result message_print_format_dig(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);
ya_result message_print_format_dig_buffer(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with);

ya_result message_print_format_json(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);
ya_result message_print_format_json_buffer(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with);

ya_result message_print_format_parse(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);
ya_result message_print_buffer_format_parse(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with);

ya_result message_print_format_xml(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with, long time_duration);
ya_result message_print_format_xml_buffer(output_stream *os_, const u8 *buffer, u16 length, u16 view_mode_with);
#ifdef __cplusplus
}
#endif

#endif /* MESSAGE_H_ */

/** @} */
