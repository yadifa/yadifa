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
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <unistd.h>

#include "dnscore/message.h"
#include "dnscore/logger.h"
#include "dnscore/dnscore.h"
#include "dnscore/format.h"
#include "dnscore/fingerprint.h"
#include "dnscore/packet_reader.h"
#include "dnscore/packet_writer.h"
#include "dnscore/tsig.h"
#include "dnscore/fdtools.h"
#include "dnscore/tcp_io_stream.h"
#include "dnscore/counter_output_stream.h"

#include "dnscore/thread_pool.h"

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#include "dnscore/rdtsc.h"

#define		SA_LOOP                 3
#define		SA_PRINT                4

/*------------------------------------------------------------------------------
 * FUNCTIONS */

u16 edns0_maxsize = EDNS0_MAX_LENGTH;

void message_edns0_setmaxsize(u16 maxsize)
{
    edns0_maxsize = maxsize;
}

u16 message_edns0_getmaxsize()
{
    return edns0_maxsize;
}

static ya_result
message_process_additionals(message_data *mesg, u8* s, u16 ar_count)
{
    /*
     * @note: I've moved this in the main function (the one calling this one)
     */

    //zassert(ar_count != 0 && ar_count == MESSAGE_AR(mesg->buffer));

    u8 *buffer = mesg->buffer;
    ya_result return_code;

    ar_count = ntohs(MESSAGE_AR(buffer));

    /*
     * rfc2845
     *
     * If there is a TSIG then
     * _ It must be put aside, safely
     * _ It must be removed from the query
     * _ It must be processed
     *
     * rfc2671
     *
     * Handle OPT
     *
     */

    /*
     * Read DNS name (decompression on)
     * Read type (TSIG = 250)
     * Read class (ANY)
     * Read TTL (0)
     * Read RDLEN
     *
     */

    u32 query_end = mesg->received;

    packet_unpack_reader_data purd;
    purd.packet = buffer;        
    purd.packet_size = mesg->received;

    if(mesg->ar_start == NULL)
    {
        u32 ar_index = ntohs(MESSAGE_AN(buffer)) + ntohs(MESSAGE_NS(buffer));

        purd.offset = DNS_HEADER_LENGTH; /* Header */
        packet_reader_skip_fqdn(&purd); /* Query DNAME */
        purd.offset += 4; /* TYPE CLASS */

        while(ar_index > 0) /* Skip all until AR records */
        {
            /*
             * It should be in this kind of processing that we read the EDNS0 flag
             */

            packet_reader_skip_record(&purd);

            ar_index--;
        }

        query_end = purd.offset;

        mesg->ar_start = &mesg->buffer[purd.offset];
    }
    else
    {
        purd.offset = mesg->ar_start - mesg->buffer;
    }

    /* We are now at the start of the ar */

    struct type_class_ttl_rdlen tctr;
    u8 tsigname[MAX_DOMAIN_LENGTH];
    u32 record_offset;

    while(ar_count-- > 0)
    {
        record_offset = purd.offset;

        if(FAIL(packet_reader_read_fqdn(&purd, tsigname, sizeof (tsigname))))
        {
            /* oops */
            
            mesg->status = FP_ERROR_READING_QUERY;

            return UNPROCESSABLE_MESSAGE;
        }

        if(packet_reader_read(&purd, (u8*) &tctr, 10) == 10 )
        {
            /*
             * EDNS (0)
             */
            
            if(tctr.qtype == TYPE_OPT)
            {
                /**
                 * Handle EDNS
                 *
                 * @todo improve the EDNS handling
                 * @todo handle extended RCODE (supposed to be 0, but could be set to something else : FORMERR)
                 */

                if((tctr.ttl & NU32(0x00ff0000)) == 0) /* ensure version is 0 */
                {
                    if(tsigname[0] == '\0')
                    {
                        mesg->size_limit = MAX(EDNS0_MIN_LENGTH, ntohs(tctr.qclass)); /* our own limit, taken from the config file */
                        mesg->edns = TRUE;
                        mesg->rcode_ext = tctr.ttl;

                        log_debug("EDNS: udp-size=%d rcode-ext=%08x desc=%04x", mesg->size_limit, tctr.ttl, ntohs(tctr.rdlen));
                        continue;
                    }
                }
                else
                {
                   mesg->status = FP_EDNS_BAD_VERSION;
                   mesg->size_limit = MAX(EDNS0_MIN_LENGTH, ntohs(tctr.qclass));
                   mesg->edns = TRUE;
                   mesg->rcode_ext = 0;
                }
                
                log_debug("OPT record is not processable (broken or not supported)");

                return UNPROCESSABLE_MESSAGE;
            }
#if HAS_TSIG_SUPPORT == 1
            
            /*
             * TSIG
             */
            
            else if(tctr.qtype == TYPE_TSIG)
            {
                if(ar_count == 0)
                {
                    /*
                     * It looks like a TSIG ...
                     */
                    
                    if(message_isquery(mesg))
                    {
                        if(FAIL(return_code = tsig_process_query(mesg, &purd, record_offset, tsigname, &tctr)))
                        {
                            log_err("%r query error from %{sockaddr}", return_code, &mesg->other.sa);

                            /* Must be set BEFORE the signature */

                            mesg->status = FP_TSIG_ERROR; /** @todo NOTAUTH / FORMERR */

                            switch(return_code)
                            {
                                case TSIG_BADKEY:
                                case TSIG_BADTIME:
                                case TSIG_BADSIG:
                                    /* There is a TSIG and it's bad : NOTAUTH
                                     *
                                     * The query TSIG has been removed already.
                                     * A new TSIG with no-mac one with the return_code set in the error field must be added to the result.
                                     */

                                    tsig_append_error(mesg);

                                    break;
                                default:
                                    /*
                                     * discard : FORMERR
                                     */
                                    break;
                            }

                            return UNPROCESSABLE_MESSAGE;
                        }
                    }
                    else
                    {
#if 0
                        u8 old_mac[64];
#endif                   
                        tsig_item *key = tsig_get(tsigname);
                        
                        if(key != NULL)
                        {
                            if(FAIL(return_code = tsig_process(mesg, &purd, record_offset, key, &tctr)))
                            {
                                log_err("%r answer error from %{sockaddr}", return_code, &mesg->other.sa);

                                mesg->status = FP_TSIG_ERROR; /** @todo NOTAUTH / FORMERR */

                                return UNPROCESSABLE_MESSAGE;
                            }
#if 0
                            if(dnsname_equals(tsigname, mesg->tsig.tsig->name)) /* NOP */
                            {
                                u16 old_mac_size = mesg->tsig.mac_size;
                                memcpy(old_mac, mesg->tsig.mac, old_mac_size);

                                if(FAIL(return_code = tsig_process_answer(mesg, &purd, record_offset, mesg->tsig.tsig, &tctr, old_mac, old_mac_size)))
                                {
                                    log_err("%r answer error from %{sockaddr}", return_code, &mesg->other.sa);

                                    mesg->status = FP_TSIG_ERROR; /** @todo NOTAUTH / FORMERR */

                                    return UNPROCESSABLE_MESSAGE;
                                }
                            }
#endif
                        }
                        else
                        {
                            log_err("answer error from %{sockaddr}: TSIG when none expected", &mesg->other.sa);

                            mesg->status = FP_TSIG_ERROR; /** @todo NOTAUTH / FORMERR */

                            return INVALID_MESSAGE;
                        }
                    }

                    break;  /* we know there is no need to loop anymore */
                }
                else
                {
                    /*
                     * Error: TSIG is not the last AR record
                     */

                    log_debug("TSIG record is not the last AR");
                    
                    mesg->status = FP_TSIG_IS_NOT_LAST;

                    return UNPROCESSABLE_MESSAGE;
                }
            }
#endif
            else
            {
                /* Unhandled AR TYPE */

                log_debug("Unhandled AR type %{dnstype}", &tctr.qtype);
                
                mesg->status = FP_UNEXPECTED_RR_IN_QUERY;                

                return UNPROCESSABLE_MESSAGE;
            }
        }
    } /* While there are AR to process */

    mesg->received = query_end;

    return SUCCESS;
}

static ya_result
message_process_answer_additionals(message_data *mesg, u8* s, u16 ar_count)
{
    /*
     * @note: I've moved this in the main function (the one calling this one)
     */

    zassert(ar_count != 0 && ar_count == MESSAGE_AR(mesg->buffer));

    ya_result return_code;

    u8 *buffer = mesg->buffer;

    ar_count = ntohs(ar_count);

    /*
     * rfc2845
     *
     * If there is a TSIG then
     * _ It must be put aside, safely
     * _ It must be removed from the query
     * _ It must be processed
     *
     * rfc2671
     *
     * Handle OPT
     *
     */

    /*
     * Read DNS name (decompression on)
     * Read type (TSIG = 250)
     * Read class (ANY)
     * Read TTL (0)
     * Read RDLEN
     *
     */

    u32 query_end = mesg->received;

    packet_unpack_reader_data purd;
    purd.packet = buffer;        
    purd.packet_size = mesg->received;

    if(mesg->ar_start == NULL)
    {
        u32 ar_index = ntohs(MESSAGE_AN(buffer)) + ntohs(MESSAGE_NS(buffer));

        purd.offset = DNS_HEADER_LENGTH; /* Header */
        packet_reader_skip_fqdn(&purd); /* Query DNAME */
        purd.offset += 4; /* TYPE CLASS */

        while(ar_index > 0) /* Skip all until AR records */
        {
            /*
             * It should be in this kind of processing that we read the EDNS0 flag
             */

            packet_reader_skip_record(&purd);

            ar_index--;
        }

        query_end = purd.offset;

        mesg->ar_start = &mesg->buffer[purd.offset];
    }
    else
    {
        purd.offset = mesg->ar_start - mesg->buffer;
    }

    /* We are now at the start of the ar */

    struct type_class_ttl_rdlen tctr;
    u8 tsigname[MAX_DOMAIN_LENGTH];
    u32 record_offset;

    while(ar_count-- > 0)
    {
        record_offset = purd.offset;

        if(FAIL(packet_reader_read_fqdn(&purd, tsigname, sizeof (tsigname))))
        {
            /* oops */
            
            mesg->status = FP_ERROR_READING_QUERY;

            return UNPROCESSABLE_MESSAGE;
        }

        if(packet_reader_read(&purd, (u8*) &tctr, 10) == 10 )
        {
            /*
             * EDNS (0)
             */
            
            if(tctr.qtype == TYPE_OPT)
            {
                /**
                 * Handle EDNS
                 *
                 * @todo improve the EDNS handling
                 * @todo handle extended RCODE (supposed to be 0, but could be set to something else : FORMERR)
                 */

                if((tctr.ttl & NU32(0x00ff0000)) == 0) /* ensure version is 0 */
                {
                    if(tsigname[0] == '\0')
                    {
                        mesg->size_limit = edns0_maxsize; /* our own limit, taken from the config file */
                        mesg->edns = TRUE;
                        mesg->rcode_ext = tctr.ttl;

                        log_debug("EDNS: udp-size=%d rcode-ext=%08x desc=%04x", mesg->size_limit, tctr.ttl, ntohs(tctr.rdlen));
                        continue;
                    }
                }
                else
                {
                   mesg->status = FP_EDNS_BAD_VERSION;
                   mesg->size_limit = edns0_maxsize;
                   mesg->edns = TRUE;
                   mesg->rcode_ext = 0;
                   
                   /* we are after tctr in the packet : rewind by 6 */
                   /*
                   MESSAGE_FLAGS_OR(buffer, QR_BITS, FP_EDNS_BAD_VERSION & 15);
                   buffer[purd.offset - 6] = (FP_EDNS_BAD_VERSION >> 4);
                   buffer[purd.offset - 5] = 0;
                   */
                }
                
                log_debug("OPT record is not processable (broken or not supported)");

                return UNPROCESSABLE_MESSAGE;
            }
#if HAS_TSIG_SUPPORT == 1
            
            /*
             * TSIG
             */
            
            else if(tctr.qtype == TYPE_TSIG)
            {
                if(ar_count == 0)
                {
                    /*
                     * It looks like a TSIG ...
                     */
                    
                    if(message_isquery(mesg))
                    {
                        if(FAIL(return_code = tsig_process_query(mesg, &purd, record_offset, tsigname, &tctr)))
                        {
                            log_err("%r query error from %{sockaddr}", return_code, &mesg->other.sa);

                            /* Must be set BEFORE the signature */

                            mesg->status = FP_TSIG_ERROR; /** @todo NOTAUTH / FORMERR */

                            switch(return_code)
                            {
                                case TSIG_BADKEY:
                                case TSIG_BADTIME:
                                case TSIG_BADSIG:
                                    /* There is a TSIG and it's bad : NOTAUTH
                                     *
                                     * The query TSIG has been removed already.
                                     * A new TSIG with no-mac one with the return_code set in the error field must be added to the result.
                                     */

                                    tsig_append_error(mesg);

                                    break;
                                default:
                                    /*
                                     * discard : FORMERR
                                     */
                                    break;
                            }

                            return UNPROCESSABLE_MESSAGE;
                        }
                    }
                    else // not a query (an answer)
                    {
                        u8 old_mac[64];
                        
                        if(mesg->tsig.tsig != NULL)
                        {
                            if(dnsname_equals(tsigname, mesg->tsig.tsig->name))
                            {                        
                                u16 old_mac_size = mesg->tsig.mac_size;
                                memcpy(old_mac, mesg->tsig.mac, old_mac_size);

                                if(FAIL(return_code = tsig_process_answer(mesg, &purd, record_offset, mesg->tsig.tsig, &tctr, old_mac, old_mac_size)))
                                {
                                    log_err("%r answer error from %{sockaddr}", return_code, &mesg->other.sa);

                                    mesg->status = FP_TSIG_ERROR; /** @todo NOTAUTH / FORMERR */

                                    return UNPROCESSABLE_MESSAGE;
                                }
                            }
                        }
                        else // no tsig
                        {
                            log_err("answer error from %{sockaddr}: TSIG when none expected", &mesg->other.sa);

                            mesg->status = FP_TSIG_ERROR; /** @todo NOTAUTH / FORMERR */

                            return UNPROCESSABLE_MESSAGE;
                        }
                    }

                    break;  /* we know there is no need to loop anymore */
                }
                else
                {
                    /*
                     * Error: TSIG is not the last AR record
                     */

                    log_debug("TSIG record is not the last AR");
                    
                    mesg->status = FP_TSIG_IS_NOT_LAST;

                    return UNPROCESSABLE_MESSAGE;
                }
            }
#endif
            else
            {
                /* Unhandled AR TYPE */

                log_debug("skipping AR type %{dnstype}", &tctr.qtype);

                purd.offset += ntohs(tctr.rdlen);

                query_end = purd.offset;
            }
        }
    } /* While there are AR to process */

    mesg->received = query_end;

    return SUCCESS;
}

/** \brief Processing DNS packet
 *
 *  @param mesg
 *
 *  @retval OK
 *  @return status of message is written in mesg->status
 */
/*
   static rdtsc_t mpb;
   */

/* Defines a mask and the expected result for the 4 first 16 bits of the header */
#ifdef WORDS_BIGENDIAN
#define MESSAGE_HEADER_MASK     (( (u64) 0 )                                      |  \
        ( (u64) (/* QR_BITS |*/ AA_BITS | TC_BITS ) << 24 )  |  \
        ( (u64) ( RA_BITS | RCODE_BITS ) << 16 )         |  \
        ( (u64) 1LL << 0 ))
#define MESSAGE_HEADER_RESULT   ( ((u64) 1LL) << 0 )

#else
#define MESSAGE_HEADER_MASK     (( (u64) 0LL )                                        |  \
        ( ((u64) ( QR_BITS | AA_BITS | RA_BITS | TC_BITS )) << 16 ) |  \
        ( ((u64) ( RA_BITS | RCODE_BITS )) << 24 )            |  \
        ( ((u64) 1LL) << 40 ))

#define MESSAGE_HEADER_RESULT   ( ((u64) 1LL) << 40 )

/* Bind gives "RA" here (seems irrelevant, nonsense, but we need to accept it) */

#define NOTIFY_MESSAGE_HEADER_MASK     (( (u64) 0LL )             |  \
        ( ((u64) ( TC_BITS )) << 16 )                             |  \
        ( ((u64) 1LL) << 40 ))

#define NOTIFY_MESSAGE_HEADER_RESULT   ( ((u64) 1LL) << 40 )

#endif

/* EDF: this takes about 150 cycles [144;152] with peaks at 152 */
static inline u8*
message_process_copy_fqdn(message_data *mesg)
{
    u8 *src = &mesg->buffer[DNS_HEADER_LENGTH];
    u8 *dst = &mesg->qname[0];

    u8 *base = dst;
    u32 len;

    for(;;)
    {
        len = *src++;
        *dst++ = len;

        if(len == 0)
        {
            break;
        }

        if( (len & 0xC0) == 0 )
        {
            u8 *limit = dst + len;

            if(limit - base < MAX_DOMAIN_LENGTH)
            {
                do
                {
                    *dst++ = LOCASE(*src++); /* Works with the dns character set */
                }
                while(dst < limit);
            }
            else
            {
                mesg->status = FP_NAME_TOO_LARGE;
                //mesg->send_length = mesg->received;

                DERROR_MSG("FP_NAME_TOO_LARGE");

                return NULL;
            }
        }
        else
        {
			/*
			if((len & 0xC0) == 0xC0)
			{
				len &= 0x3f;
				len <<= 8;
				len |= *src;
    			src = &mesg->buffer[len];
			}
			else
			{
				mesg->status = FP_NAME_FORMAT_ERROR;

				return NULL;
			}
			*/
			mesg->status = ((len & 0xC0)==0xC0)?FP_QNAME_COMPRESSED:FP_NAME_FORMAT_ERROR;

			return NULL;
        }
    }

    /* Get qtype & qclass */
    mesg->qtype  = GET_U16_AT(src[0]); /** @note : NATIVETYPE  */
    mesg->qclass = GET_U16_AT(src[2]); /** @note : NATIVECLASS */

    return src + 4;
}

int
message_process(message_data *mesg)
{
    u8 *buffer = mesg->buffer;
    
    switch(MESSAGE_OP(buffer))
    {
        case OPCODE_QUERY:
        {
            /** CHECK DNS HEADER */
            /** Drop dns packet if query is answer or does not have correct header length */

            /*
             * +5 <=> 1 qd record ar least
             */

            u64 *h64 = (u64*)buffer;
            u64 m64 = MESSAGE_HEADER_MASK;
            u64 r64 = MESSAGE_HEADER_RESULT;

            if(     (mesg->received < DNS_HEADER_LENGTH + 5) ||
                    ((  *h64 & m64) != r64 ) )
            {
                /** Return if QDCOUNT is not 1
                 *
                 *  @note Previous test was actually testing if QDCOUNT was > 1
                 *        I assumed either 0 or >1 is wrong for us so I used the same trick than for QCCOUNT
                 */
                
                if(MESSAGE_QR(buffer))
                {
                    return INVALID_MESSAGE;
                }
                
                MESSAGE_FLAGS_AND(buffer, OPCODE_BITS|RD_BITS, 0);

                if(NETWORK_ONE_16 != MESSAGE_QD(buffer))
                {
                    if(0 == MESSAGE_QD(buffer))
                    {
                        DERROR_MSG("FP_QDCOUNT_IS_0");
                        
                        return INVALID_MESSAGE; /* will be dropped */
                    }
                    else
                    {
                        mesg->status = FP_QDCOUNT_BIG_1;

                        DERROR_MSG("FP_QDCOUNT_BIG_1");
                    }
                }
                else if( MESSAGE_NS(buffer) != 0)
                {
                    mesg->status = FP_NSCOUNT_NOT_0;
                }
                else
                {                
                    mesg->status = FP_PACKET_DROPPED;
                }

                return UNPROCESSABLE_MESSAGE;
            }

            /*
            rdtsc_start(&mpb);
            */
            
            /**
             * @note Past this point, a message could be processable.
             *       It's the right place to reset the message's defaults.
             *
             */

            mesg->size_limit = UDPPACKET_MAX_LENGTH;
            mesg->ar_start   = NULL;
            mesg->tsig.tsig  = NULL;
            mesg->edns       = FALSE;
            mesg->rcode_ext  = 0;
            
            u8 *s = message_process_copy_fqdn(mesg);

            if(s == NULL)
            {
                return UNPROCESSABLE_MESSAGE;
            }

            /*
            rdtsc_stop(&mpb);
            rdtsc_log(&mpb);
            */
            
            /*
             * If there is a TSIG, it is here ...
             */

#if HAS_TSIG_SUPPORT == 1
            {
                ya_result return_code;
                u32 nsar_count;

                if((nsar_count = MESSAGE_NSAR(buffer)) != 0)
                {
                    if(FAIL(return_code = message_process_additionals(mesg, s, nsar_count)))
                    {
                        mesg->received = s - buffer;
                        
                        return return_code;
                    }
                }
                
                if(mesg->qtype != TYPE_IXFR)
                {
                    mesg->received = s - buffer;
                }
            }
#else
            /* cut the trash here */
            
            mesg->received = s - buffer;
#endif

            /* At this point the TSIG has been computed and removed */
            /* Clear zome bits */
            MESSAGE_FLAGS_AND(mesg->buffer, ~(QR_BITS|TC_BITS|AA_BITS), ~(Z_BITS|RA_BITS|RCODE_BITS));
            //MESSAGE_LOFLAGS(buffer) &= ~(Z_BITS|AD_BITS|CD_BITS|RCODE_BITS);

            mesg->status = FP_MESG_OK;

            return OK;
        }
        case OPCODE_NOTIFY:
        {
            MESSAGE_LOFLAGS(buffer) &= ~(Z_BITS|AD_BITS|CD_BITS);
            
            /*
             rdtsc_init(&mpb);
             */
            /*    ------------------------------------------------------------    */

            /** CHECK DNS HEADER */
            /** Drop dns packet if query is answer or does not have correct header length */

            /*
             * +5 <=> 1 qd record ar least
             */

            u64 *h64 = (u64*)buffer;
            u64 m64 = NOTIFY_MESSAGE_HEADER_MASK;
            u64 r64 = NOTIFY_MESSAGE_HEADER_RESULT;
            /* ... A400 0001 ... */
            if(     (mesg->received < DNS_HEADER_LENGTH + 5) ||
                    ((  *h64 & m64) != r64 ) )
            {
                /** Return if QDCOUNT is not 1
                 *
                 *  @note Previous test was actually testing if QDCOUNT was > 1
                 *        I assumed either 0 or >1 is wrong for us so I used the same trick than for QCCOUNT
                 */
                MESSAGE_FLAGS_AND(buffer, OPCODE_BITS, 0);
                

                if(NETWORK_ONE_16 != MESSAGE_QD(buffer))
                {
                    if(0 == MESSAGE_QD(buffer))
                    {
                        DERROR_MSG("FP_QDCOUNT_IS_0");
                        
                        return INVALID_MESSAGE;
                    }
                    else
                    {
                        mesg->status = FP_QDCOUNT_BIG_1;

                        DERROR_MSG("FP_QDCOUNT_BIG_1");
                    }
                }
                else
                {
                    mesg->status = FP_PACKET_DROPPED;
                }

                return UNPROCESSABLE_MESSAGE;
            }

            /*
            rdtsc_start(&mpb);
            */

            u8 *s = message_process_copy_fqdn(mesg);

            if(s == NULL)
            {
                /* mesg->status has already been set */
                return UNPROCESSABLE_MESSAGE;
            }

            /*
            rdtsc_stop(&mpb);
            rdtsc_log(&mpb);
            */

            /**
             * @note Past this point, a message could be processable.
             *       It's the right place to reset the message's defaults.
             *
             */

            mesg->size_limit = UDPPACKET_MAX_LENGTH;
            mesg->ar_start   = NULL;
            mesg->tsig.tsig  = NULL;
            mesg->edns       = FALSE;
            mesg->rcode_ext  = 0;

            /*
             * If there is a TSIG, it is here ...
             */

#if HAS_TSIG_SUPPORT == 1
            {
                ya_result return_code;
                u16 ar_count;

                if((ar_count = MESSAGE_AR(buffer)) != 0)
                {
                    if(FAIL(return_code = message_process_additionals(mesg, s, ar_count)))
                    {
                        return return_code;
                    }
                }
            }
#endif
            /* At this point the TSIG has been computed and removed */

            // MESSAGE_FLAGS_AND(mesg->buffer, ~(TC_BITS|AA_BITS), ~(RA_BITS|RCODE_BITS));

            mesg->status = FP_MESG_OK;

            return OK;
        }
        case OPCODE_UPDATE:
        {
            MESSAGE_LOFLAGS(buffer) &= ~(Z_BITS|AD_BITS|CD_BITS|RCODE_BITS);
            
            /*
               rdtsc_init(&mpb);
             */
            /*    ------------------------------------------------------------    */

            /** CHECK DNS HEADER */
            /** Drop dns packet if query is answer or does not have correct header length */

            /*
             * +5 <=> 1 qd record ar least
             */

            u64 *h64 = (u64*)buffer;
            u64 m64 = MESSAGE_HEADER_MASK;
            u64 r64 = MESSAGE_HEADER_RESULT;

            if(     (mesg->received < DNS_HEADER_LENGTH + 5) ||
                    ((  *h64 & m64) != r64 ) )
            {
                /** Return if QDCOUNT is not 1
                 *
                 *  @note Previous test was actually testing if QDCOUNT was > 1
                 *        I assumed either 0 or >1 is wrong for us so I used the same trick than for QCCOUNT
                 */
                
                if(MESSAGE_QR(buffer))
                {
                    return INVALID_MESSAGE;
                }
                
                MESSAGE_FLAGS_AND(buffer, OPCODE_BITS, 0);

                if(NETWORK_ONE_16 != MESSAGE_QD(buffer))
                {
                    if(0 == MESSAGE_QD(buffer))
                    {
                        DERROR_MSG("FP_QDCOUNT_IS_0");
                        
                        return INVALID_MESSAGE;
                    }
                    else
                    {
                        mesg->status = FP_QDCOUNT_BIG_1;

                        DERROR_MSG("FP_QDCOUNT_BIG_1");
                    }

                    return UNPROCESSABLE_MESSAGE;
                }

                mesg->status = FP_PACKET_DROPPED;

                return UNPROCESSABLE_MESSAGE;
            }

            /*
            rdtsc_start(&mpb);
            */

            u8 *s = message_process_copy_fqdn(mesg);

            if(s == NULL)
            {
                /* mesg->status has already been set */
                return UNPROCESSABLE_MESSAGE;
            }

            /*
            rdtsc_stop(&mpb);
            rdtsc_log(&mpb);
            */

            /**
             * @note Past this point, a message could be processable.
             *       It's the right place to reset the message's defaults.
             *
             */

            mesg->size_limit = UDPPACKET_MAX_LENGTH;
            mesg->ar_start   = NULL;
            mesg->tsig.tsig  = NULL;
            mesg->edns       = FALSE;
            mesg->rcode_ext  = 0;

            /*
             * If there is a TSIG, it is here ...
             */
            
#if HAS_TSIG_SUPPORT == 1
            {
                ya_result return_code;
                u16 ar_count;

                if((ar_count = MESSAGE_AR(buffer)) != 0)
                {
                    if(FAIL(return_code = message_process_additionals(mesg, s, ar_count)))
                    {
                        return return_code;
                    }
                }
            }
#endif

            /* At this point the TSIG has been computed and removed */

            MESSAGE_FLAGS_AND(mesg->buffer, ~(QR_BITS|TC_BITS|AA_BITS), ~(RA_BITS|RCODE_BITS));

            mesg->status = FP_MESG_OK;
            
            return OK;
        }
        default:
        {
            u8 hf = MESSAGE_HIFLAGS(buffer);
            if((hf & QR_BITS) == 0)
            {
                MESSAGE_LOFLAGS(buffer) &= ~(Z_BITS|AD_BITS|CD_BITS|RCODE_BITS);
                MESSAGE_FLAGS_AND(buffer, OPCODE_BITS, 0);

                mesg->size_limit = UDPPACKET_MAX_LENGTH;
                mesg->ar_start   = NULL;
#if HAS_TSIG_SUPPORT==1
                mesg->tsig.tsig  = NULL;
#endif
                mesg->edns       = FALSE;
                mesg->rcode_ext  = 0;

                mesg->status = FP_NOT_SUPP_OPC;
                mesg->received = DNS_HEADER_LENGTH;
                SET_U32_AT(mesg->buffer[4],0);    /* aligned to 32 bits, so two 32 bits instead of one 64 */
                SET_U32_AT(mesg->buffer[8],0);

                /* reserved for future use */
                
                return UNPROCESSABLE_MESSAGE;
            }
            else
            {
                mesg->status = FP_PACKET_DROPPED;
                
                return INVALID_MESSAGE;
            }
        }
    }
}

int
message_process_lenient(message_data *mesg)
{
    u8 *buffer = mesg->buffer;
        
    u8 *s = message_process_copy_fqdn(mesg);

    if(s == NULL)
    {
        return UNPROCESSABLE_MESSAGE;
    }

    /**
        * @note Past this point, a message could be processable.
        *       It's the right place to reset the message's defaults.
        *
        */

    mesg->size_limit = UDPPACKET_MAX_LENGTH;
    mesg->ar_start   = NULL;
    mesg->edns       = FALSE;
    mesg->rcode_ext  = 0;

    /*
     * If there is a TSIG, it is here ...
     */

#if HAS_TSIG_SUPPORT == 1
    {
        ya_result return_code;
        u16 ar_count;

        if((ar_count = MESSAGE_AR(buffer)) != 0)
        {
            if(FAIL(return_code = message_process_answer_additionals(mesg, s, ar_count)))
            {
                return return_code;
            }
        }
        else
        {
            mesg->tsig.tsig  = NULL;
            
            /* cut the trash here */
            /*mesg->received = s - buffer;*/
        }
    }
#else
    /* cut the trash here */

    mesg->received = s - buffer;
#endif

    /* At this point the TSIG has been computed and removed */

    mesg->status = FP_MESG_OK;

    return OK;
}


/** \brief Add rcode to dns header
 *
 *  and clear QDCOUNT, ANCOUNT, NSCOUNT and ARCOUNT
 *
 *  @param mesg
 *
 *  @retval OK
 */
int
message_trim(message_data *mesg)
{
    /* Trim packet to minimal */
    mesg->send_length = DNS_HEADER_LENGTH;

    /** @note message_trim needs to be rechecked */
    /* Add rcode to dns header */
    /** @todo ZF is uspposed to be 0 isn't it ? Why take it ??? */
    /*MESSAGE_LOFLAGS(buffer) = MESSAGE_ZF(buffer) | mesg->status;*/

    /** @todo Recursion available should be put here, but is not available on yadifa
    */
    MESSAGE_LOFLAGS(mesg->buffer) = /*MESSAGE_RA(buffer) |*/ mesg->status;

    /* Clear stuff that's not needed for rcoded answer */

#if HAS_MEMALIGN_ISSUES == 0
    /**
     * @note This will not work on Niagara cpus (alignment)
     */

    SET_U64_AT(mesg->buffer[4], 0); /* Clear QDCOUNT & ANCOUNT & NSCOUNT & ARCOUNT */
#else
    SET_U32_AT(mesg->buffer[4], 0); /* Clear QDCOUNT & ANCOUNT */
    SET_U32_AT(mesg->buffer[8], 0); /* Clear NSCOUNT & ARCOUNT */
#endif

    return OK;
}

void
message_transform_to_error(message_data *mesg)
{
    if(!mesg->edns)
    {
        MESSAGE_FLAGS_OR(mesg->buffer, QR_BITS, mesg->status);

        if(mesg->status == RCODE_FORMERR)
        {
            SET_U32_AT(mesg->buffer[4],0);    /* aligned to 32 bits, so two 32 bits instead of one 64 */
            SET_U32_AT(mesg->buffer[8],0);
            mesg->send_length = DNS_HEADER_LENGTH;
        }
        else
        {
            mesg->send_length = mesg->received;
        }
    }
    else
    {
        /* 00 0029 0200 EE 00 00000000 */
        
        if(mesg->status == RCODE_FORMERR)
        {
            SET_U32_AT(mesg->buffer[4],0);    /* aligned to 32 bits, so two 32 bits instead of one 64 */
            SET_U32_AT(mesg->buffer[8],0);
            mesg->send_length = DNS_HEADER_LENGTH;
        }
        else
        {
            mesg->send_length = mesg->ar_start - mesg->buffer;
        }

        /* rcode */
        //MESSAGE_LOFLAGS(mesg->buffer) &= RCODE_BITS;
        MESSAGE_HIFLAGS(mesg->buffer) |= QR_BITS;
        MESSAGE_LOFLAGS(mesg->buffer) |= mesg->status & 15;
        
        /* #AR = 1 */
        mesg->buffer[DNS_HEADER_LENGTH - 1] = 1;    /* AR count was 0, now it is 1 */
        
        /* append opt *//* */
        u8 *buffer = &mesg->buffer[mesg->send_length];
        buffer[ 0] = 0;
        buffer[ 1] = 0;
        buffer[ 2] = 0x29;        
        buffer[ 3] = edns0_maxsize>>8;
        buffer[ 4] = edns0_maxsize;
        buffer[ 5] = (mesg->status >> 4);
        buffer[ 6] = mesg->rcode_ext >> 16;
        buffer[ 7] = mesg->rcode_ext >> 8;
        buffer[ 8] = mesg->rcode_ext;
        buffer[ 9] = 0;
        buffer[10] = 0;
        
        mesg->send_length += 11;
    }
}

void
message_make_query(message_data *mesg, u16 id, const u8 *qname, u16 qtype, u16 qclass)
{
#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->buffer[0], 0x0000000000010000LL);
    SET_U32_AT(mesg->buffer[8], 0);
#else
    SET_U64_AT(mesg->buffer[0], 0x0000010000000000LL);
    SET_U32_AT(mesg->buffer[8], 0);
#endif
    MESSAGE_ID(mesg->buffer) = id;
    ya_result qname_len = dnsname_len(qname);
    u8 *tc = &mesg->buffer[DNS_HEADER_LENGTH];
    memcpy(tc, qname, qname_len);
    tc += qname_len;
    SET_U16_AT(tc[0], qtype);
    tc += 2;
    SET_U16_AT(tc[0], qclass);
    tc += 2;
    mesg->tsig.tsig = NULL;
    mesg->ar_start = tc;
    mesg->size_limit = UDPPACKET_MAX_LENGTH;
    mesg->send_length = tc - &mesg->buffer[0];
    mesg->status = FP_MESG_OK;
    mesg->rcode_ext = 0;
}


void message_make_message(message_data *mesg, u16 id, const u8 *qname, u16 qtype, u16 qclass, packet_writer* uninitialised_packet_writer)
{
    assert(uninitialised_packet_writer != NULL);
    
    #ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->buffer[0], 0x0000000000010000LL);
    SET_U32_AT(mesg->buffer[8], 0);
#else
    SET_U64_AT(mesg->buffer[0], 0x0000010000000000LL);
    SET_U32_AT(mesg->buffer[8], 0);
#endif
    MESSAGE_ID(mesg->buffer) = id;
    
    packet_writer_create(uninitialised_packet_writer, mesg->buffer, DNSPACKET_MAX_LENGTH);

    packet_writer_add_fqdn(uninitialised_packet_writer, qname);
    packet_writer_add_u16(uninitialised_packet_writer, qtype);
    packet_writer_add_u16(uninitialised_packet_writer, qclass);
    
    mesg->tsig.tsig = NULL;
    mesg->ar_start = &mesg->buffer[uninitialised_packet_writer->packet_offset];
    mesg->send_length = uninitialised_packet_writer->packet_offset;
    
    if(mesg->send_length < UDPPACKET_MAX_LENGTH)
    {
        mesg->size_limit = UDPPACKET_MAX_LENGTH;
    }
    else
    {
        mesg->size_limit = DNSPACKET_MAX_LENGTH;
    }
    
    mesg->status = FP_MESG_OK;
}


void
message_make_notify(message_data *mesg, u16 id, const u8 *qname)
{
#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->buffer[0], 0x0000200000010000LL);
    SET_U32_AT(mesg->buffer[8], 0);
#else
    SET_U64_AT(mesg->buffer[0], 0x0000010000200000LL);
    SET_U32_AT(mesg->buffer[8], 0);
#endif
    MESSAGE_ID(mesg->buffer) = id;
    ya_result qname_len = dnsname_len(qname);
    u8 *tc = &mesg->buffer[DNS_HEADER_LENGTH];
    memcpy(tc, qname, qname_len);
    tc += qname_len;
    SET_U16_AT(tc[0], TYPE_SOA);
    tc += 2;
    SET_U16_AT(tc[0], CLASS_IN);
    tc += 2;
    mesg->tsig.tsig = NULL;
    mesg->size_limit = UDPPACKET_MAX_LENGTH;
    mesg->ar_start = tc;
    mesg->send_length = tc - &mesg->buffer[0];
    mesg->status = FP_MESG_OK;
}

void
message_make_ixfr_query(message_data *mesg, u16 id, const u8 *qname, u32 soa_ttl, u16 soa_rdata_size, const u8 *soa_rdata)
{
    packet_writer pw;
    
#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->buffer[0], 0x0000000000010000LL);
    SET_U32_AT(mesg->buffer[8], 0x00010000);
#else
    SET_U64_AT(mesg->buffer[0], 0x0000010000000000LL);
    SET_U32_AT(mesg->buffer[8], 0x00000100);
#endif

    MESSAGE_ID(mesg->buffer) = id;

    packet_writer_create(&pw, mesg->buffer, UDPPACKET_MAX_LENGTH);

    packet_writer_add_fqdn(&pw, qname);
    packet_writer_add_u16(&pw, TYPE_IXFR);
    packet_writer_add_u16(&pw, CLASS_IN);

    packet_writer_add_fqdn(&pw, qname);
    packet_writer_add_u16(&pw, TYPE_SOA);
    packet_writer_add_u16(&pw, CLASS_IN);
    packet_writer_add_u32(&pw, htonl(soa_ttl));
    packet_writer_add_rdata(&pw, TYPE_SOA, soa_rdata, soa_rdata_size);

    mesg->tsig.tsig = NULL;
    mesg->ar_start = &mesg->buffer[pw.packet_offset];
    mesg->size_limit = UDPPACKET_MAX_LENGTH;
    mesg->send_length = pw.packet_offset;
    mesg->status = FP_MESG_OK;
}

ya_result
message_sign_answer_by_name(message_data *mesg, const u8 *tsig_name)
{
    const tsig_item *key = tsig_get(tsig_name);

    return message_sign_answer(mesg, key);
}

ya_result
message_sign_query_by_name(message_data *mesg, const u8 *tsig_name)
{
    const tsig_item *key = tsig_get(tsig_name);

    return message_sign_query(mesg, key);
}

ya_result
message_sign_answer(message_data *mesg, const tsig_item *key)
{
    if(key != NULL)
    {
        ZEROMEMORY(&mesg->tsig, sizeof(message_tsig));

        mesg->tsig.tsig = key;
        mesg->tsig.mac_size = mesg->tsig.tsig->mac_size;

        u64 now = time(NULL);
        mesg->tsig.timehi = htons((u16)(now >> 32));
        mesg->tsig.timelo = htonl((u32)now);

        mesg->tsig.fudge  = htons(300);    /* 5m */

        mesg->tsig.mac_algorithm = key->mac_algorithm;

        mesg->tsig.original_id = GET_U16_AT(mesg->buffer[0]);
        
        return tsig_sign_answer(mesg);
    }

    return TSIG_BADKEY;
}

ya_result
message_sign_query(message_data *mesg, const tsig_item *key)
{
    if(key != NULL)
    {
        ZEROMEMORY(&mesg->tsig, sizeof(message_tsig));

        mesg->tsig.tsig = key;
        mesg->tsig.mac_size = mesg->tsig.tsig->mac_size;

        u64 now = time(NULL);
        mesg->tsig.timehi = htons((u16)(now >> 32));
        mesg->tsig.timelo = htonl((u32)now);

        mesg->tsig.fudge  = htons(300);    /* 5m */

        mesg->tsig.mac_algorithm = key->mac_algorithm;

        mesg->tsig.original_id = GET_U16_AT(mesg->buffer[0]);

        return tsig_sign_query(mesg);
    }

    return TSIG_BADKEY;
}

void
message_make_error(message_data *mesg, u16 error_code)
{
    MESSAGE_FLAGS_OR(mesg->buffer, QR_BITS, error_code);
#ifdef WORDS_BIGENDIAN
    SET_U32_AT(mesg->buffer[4], 0x00010000);
    SET_U32_AT(mesg->buffer[8], 0x00000000);
#else
    SET_U32_AT(mesg->buffer[4], 0x00000100);
    SET_U32_AT(mesg->buffer[8], 0x00000000);
#endif

    mesg->size_limit = UDPPACKET_MAX_LENGTH;
    mesg->send_length = DNS_HEADER_LENGTH + 4;
    mesg->send_length += dnsname_len(&mesg->buffer[DNS_HEADER_LENGTH]);
    mesg->ar_start = &mesg->buffer[mesg->send_length];
    mesg->status = (finger_print)error_code;
}

void
message_make_error_ext(message_data *mesg, u16 error_code)
{
    zassert(FALSE);  /** @todo implement */
}

ya_result
message_query_tcp(message_data *mesg, host_address *server)
{
    /* connect the server */
    
    ya_result return_value;
    
    socketaddress sa;
        
    if(ISOK(return_value = host_address2sockaddr(&sa, server)))
    {
        int s;
        
        if((s = socket(sa.sa.sa_family, SOCK_STREAM, 0)) >=0)
        {
            socklen_t sa_len = return_value;
            
            if(connect(s, (struct sockaddr*)&sa, sa_len) == 0)
            {
                message_update_tcp_length(mesg);
                
                ssize_t n;
                
                if((n = writefully(s, &mesg->buffer_tcp_len[0], mesg->send_length + 2)) == mesg->send_length + 2)
                {
                    u16 tcp_len;
                    
                    if((n = readfully(s, &tcp_len, 2)) == 2)
                    {
                        tcp_len = ntohs(tcp_len);
                        
                        if(readfully(s, mesg->buffer, tcp_len) == tcp_len)
                        {
                            /*
                             * test the answser
                             * test the TSIG if any
                             */
                            
                            mesg->received = tcp_len;
                            
                            return_value = message_process_lenient(mesg);
                        }
                    }                    
                }
            }
            else
            {
                // Linux quirk ...
                
                if(errno != EINPROGRESS)
                {
                    return_value = ERRNO_ERROR;
                }
                else
                {
                    return_value = MAKE_ERRNO_ERROR(ETIMEDOUT);
                }
            }
            
            close_ex(s);
        }
        else
        {
            return_value = ERRNO_ERROR;
        }
    }
    
    return return_value;
}

ya_result
message_query_udp(message_data *mesg, host_address *server)
{
    /* connect the server */
    
    ya_result return_value;
    
    socketaddress sa;
        
    if(ISOK(return_value = host_address2sockaddr(&sa, server)))
    {
        int s;
        
        if((s = socket(sa.sa.sa_family, SOCK_DGRAM, 0)) >=0)
        {
            socklen_t sa_len = return_value;
            int n;
            
            tcp_set_recvtimeout(s, 0, 500000); /* half a second for UDP is a lot ... */
            
            if((n = sendto(s, mesg->buffer, mesg->send_length, 0, (struct sockaddr*)&sa, sa_len)) == mesg->send_length)
            {
                struct sockaddr ans_sa;
                socklen_t ans_sa_len = sizeof(ans_sa);
                
                while((n = recvfrom(s, mesg->buffer, sizeof(mesg->buffer), 0, &ans_sa, &ans_sa_len)) >= 0)
                {
                    /* check that the sender is the one we spoke to */
                    
                    if((sa_len == ans_sa_len) && (memcmp(&sa, &ans_sa, sa_len) == 0))
                    {
                        mesg->received = n;

                        return_value = message_process_lenient(mesg);
                        
                        break;
                    }
                }
                
                if(n < 0)
                {
                    return_value = ERRNO_ERROR;
                }
                
                /* timeout */
            }
            
            close_ex(s);
        }
        else
        {
            return_value = ERRNO_ERROR;
        }
    }
    
    return return_value;
}

ya_result
message_ixfr_query_get_serial(const message_data *mesg, u32 *serial)
{
    packet_unpack_reader_data purd;
    ya_result return_value;
    
    u8 domain_fqdn[MAX_DOMAIN_LENGTH];
    u8 soa_fqdn[MAX_DOMAIN_LENGTH];
    
    purd.packet = (u8*)mesg->buffer;
    purd.packet_size = mesg->received;
    purd.offset = DNS_HEADER_LENGTH;

    /* Keep only the query */

    if(ISOK(return_value = packet_reader_read_fqdn(&purd, domain_fqdn, sizeof(domain_fqdn))))
    {
        purd.offset += 4;

        /* Get the queried serial */

        if(ISOK(return_value = packet_reader_read_fqdn(&purd, soa_fqdn, sizeof(soa_fqdn))))
        {
            if(dnsname_equals(domain_fqdn, soa_fqdn))
            {
                u16 soa_type;
                u16 soa_class;
                u32 soa_ttl;
                u16 soa_rdata_size;
                u32 soa_serial;

                if(ISOK(return_value = packet_reader_read_u16(&purd, &soa_type)))
                {
                    if(soa_type == TYPE_SOA)
                    {        
                        packet_reader_read_u16(&purd, &soa_class);
                        packet_reader_read_u32(&purd, &soa_ttl);
                        packet_reader_read_u16(&purd, &soa_rdata_size);

                        packet_reader_skip_fqdn(&purd);
                        packet_reader_skip_fqdn(&purd);
                        packet_reader_read_u32(&purd, &soa_serial);
                        *serial=ntohl(soa_serial);
                    }
                }
            }
        }
    }
    
    return return_value;
}

static char* message_print_buffer_opcode[16] =
{
    "QUERY",
    "IQUERY",
    "STATUS",
    "NOTIFY",
    
    "UPDATE",
    "?",
    "?",
    "?",
    
    "?",
    "?",
    "?",
    "?",
    
    "?",
    "?",
    "?",
    "?"
};

static char* message_print_buffer_rcode[17] =
{
    
    "NOERROR",                //   0       /* No error                           rfc 1035 */
    "FORMERR",                //   1       /* Format error                       rfc 1035 */
    "SERVFAIL",               //   2       /* Server failure                     rfc 1035 */
    "NXDOMAIN",               //   3       /* Name error                         rfc 1035 */
    "NOTIMP",                 //   4       /* Not implemented                    rfc 1035 */
    "REFUSED",                //   5       /* Refused                            rfc 1035 */

    "YXDOMAIN",               //   6       /* Name exists when it should not     rfc 2136 */
    "YXRRSET",                //   7       /* RR Set exists when it should not   rfc 2136 */
    "NXRRSET",                //   8       /* RR set that should exist doesn't   rfc 2136 */
    "NOTAUTH",                //   9       /* Server not Authortative for zone   rfc 2136 */
    "NOTZONE",                //   10      /* Name not contained in zone         rfc 2136 */

    "?",
    "?",
    "?",
    "?",
    "?",
    
    "BADVERS",                //   16      /* Bad OPT Version                    rfc 2671 */    
};


static char* message_print_buffer_count_names[4] =
{
    "QUERY", "ANSWER", "AUTHORITY", "ADDITIONAL"
};
    
static char* message_print_buffer_count_update_names[4] =
{
    "ZONE", "PREREQUISITES", "UPDATE", "ADDITIONAL"
};

static char* message_print_buffer_section_names[4] =
{
    "QUESTION SECTION", "ANSWER SECTION", "AUTHORITY SECTION", "ADDITIONAL SECTION"
};

static char* message_print_buffer_section_update_names[4] =
{
    "ZONE", "PREREQUISITES", "UPDATE RECORDS", "ADDITIONAL RECORDS"
};

ya_result
message_print_buffer(output_stream *os_, const u8 *buffer, u16 length)
{
    ya_result return_value;
    
    /*
     * There is no padding support for formats on complex types (padding is ignored)
     * Doing it would be relatively expensive for it's best doing it manually when needed (afaik: only here)
     */
    
    counter_output_stream_data counters;
    output_stream cos;
    counter_output_stream_init(os_, &cos, &counters);
    
    output_stream *os = &cos;    
    
    packet_unpack_reader_data purd;
    
    u8 record_wire[MAX_DOMAIN_LENGTH + 10 + 65535];
    
    purd.packet = buffer;
    purd.packet_size = length;
    purd.offset = DNS_HEADER_LENGTH;
    
    u16 id = ntohs(MESSAGE_ID(buffer));
    
    u8 opcode = MESSAGE_OP(buffer);
    opcode >>= OPCODE_SHIFT;
    
    u8 rcode = MESSAGE_RCODE(buffer);
    
    char *opcode_txt = message_print_buffer_opcode[opcode];
    char *status_txt = message_print_buffer_rcode[rcode];
        
    char **count_name = (opcode != OPCODE_UPDATE)?message_print_buffer_count_names:message_print_buffer_count_update_names;
    char **section_name = (opcode != OPCODE_UPDATE)?message_print_buffer_section_names:message_print_buffer_section_update_names;
    
    u16 count[4];
    
    count[0] = ntohs(MESSAGE_QD(buffer));
    count[1] = ntohs(MESSAGE_AN(buffer));
    count[2] = ntohs(MESSAGE_NS(buffer));
    count[3] = ntohs(MESSAGE_AR(buffer));
    
    osformat(os, ";; ->>HEADER<<- opcode: %s, status: %s, id: %hd\n", opcode_txt, status_txt, id);
    osformat(os, ";; flags: ");
    
    if(MESSAGE_QR(buffer) != 0) osprint(os, "qr ");
    if(MESSAGE_AA(buffer) != 0) osprint(os, "aa ");
    if(MESSAGE_TC(buffer) != 0) osprint(os, "tc ");
    if(MESSAGE_RD(buffer) != 0) osprint(os, "rd ");
    if(MESSAGE_RA(buffer) != 0) osprint(os, "ra ");
    if(MESSAGE_ZF(buffer) != 0) osprint(os, "zf ");
    if(MESSAGE_AD(buffer) != 0) osprint(os, "ad ");
    if(MESSAGE_CD(buffer) != 0) osprint(os, "cd ");
    
    osformat(os, "%s: %hd, %s: %hd, %s: %hd, %s: %hd\n",
             count_name[0], count[0],
             count_name[1], count[1],
             count_name[2], count[2],
             count_name[3], count[3]
             );
    
    {
        u32 section_idx = 0;
        
        osformat(os, ";; %s:\n", section_name[section_idx]);
        
        for(u16 n = count[section_idx]; n > 0; n--)
        {
            if(FAIL(return_value = packet_reader_read_fqdn(&purd, record_wire, sizeof(record_wire))))
            {
                return return_value;
            }
            
            u64 next;
            
            next = counters.write_count + 24 + 8;
                                    
            osformat(os, ";%{dnsname}", record_wire, ' ' );
            
            while(counters.write_count < next)
            {
                output_stream_write_u8(os, (u8)' ');
            }
            
            output_stream_write_u8(os, (u8)' ');
            
            u16 rtype;
            u16 rclass;

            if(FAIL(return_value = packet_reader_read_u16(&purd, &rtype)))
            {
                return return_value;
            }
                                    
            if(FAIL(return_value = packet_reader_read_u16(&purd, &rclass)))
            {
                return return_value;
            }
            
            next = counters.write_count + 7;
            
            osformat(os, "%7{dnsclass}", &rclass);
            
            while(counters.write_count < next)
            {
                output_stream_write_u8(os, (u8)' ');
            }
            
            output_stream_write_u8(os, (u8)' ');
            
            next = counters.write_count + 7;

            osformat(os, "%7{dnstype}", &rtype);
            
            while(counters.write_count < next)
            {
                output_stream_write_u8(os, (u8)' ');
            }
            
            output_stream_write_u8(os, (u8)' ');
            
            osprintln(os, "");
        }
        osprintln(os, "");
    }    
    
    for(u32 section_idx = 1; section_idx < 4; section_idx++)
    {
        osformat(os, ";; %s:\n", section_name[section_idx]);
        
        for(u16 n = count[section_idx]; n > 0; n--)
        {
            if(FAIL(return_value = packet_reader_read_record(&purd, record_wire, sizeof(record_wire))))
            {
                return return_value;
            }
            
            u8 *rname  = record_wire;
            u8 *rdata  = rname + dnsname_len(rname);
            u16 rtype  = GET_U16_AT(rdata[0]);
            u16 rclass = GET_U16_AT(rdata[2]);
            u16 rttl   = ntohl(GET_U32_AT(rdata[4]));
            
            u64 next;
            
            next = counters.write_count + 24;
                                    
            osformat(os, "%{dnsname}", rname);
            
            while(counters.write_count < next)
            {
                output_stream_write_u8(os, (u8)' ');
            }
            
            output_stream_write_u8(os, (u8)' ');
            
            osformat(os, "%7d", rttl);
            
            output_stream_write_u8(os, (u8)' ');
            
            next = counters.write_count + 7;
            
            osformat(os, "%7{dnsclass}", &rclass);
            
            while(counters.write_count < next)
            {
                output_stream_write_u8(os, (u8)' ');
            }
            
            output_stream_write_u8(os, (u8)' ');
            
            next = counters.write_count + 7;
            
            osformat(os, "%7{dnstype} ", &rtype);
            
            while(counters.write_count < next)
            {
                output_stream_write_u8(os, (u8)' ');
            }
            
            output_stream_write_u8(os, (u8)' ');
            
            u16 rdata_size = ntohs(GET_U16_AT(rdata[8]));
            rdata += 10;
            
            osprint_rdata(os, rtype, rdata, rdata_size);
            
            osprintln(os, "");
        }
        osprintln(os, "");
    }
             
    return 0;
}

ya_result
message_query_serial(const u8 *origin, host_address *server, u32 *serial_out)
{
    /* do an SOA query */
    
    ya_result return_value;
    
    random_ctx rndctx = thread_pool_get_random_ctx();
    message_data soa_query_mesg;

    for(u16 countdown = 5; countdown > 0; countdown--)
    {
        u16 id = (u16)random_next(rndctx);

        message_make_query(&soa_query_mesg, id, origin, TYPE_SOA, CLASS_IN);

        if(ISOK(return_value = message_query_udp(&soa_query_mesg, server)))
        {
            u8 *buffer = soa_query_mesg.buffer;

            if((MESSAGE_ID(buffer) == id) && MESSAGE_QR(buffer) &&(MESSAGE_RCODE(buffer) == RCODE_NOERROR) && (MESSAGE_QD(buffer) == NETWORK_ONE_16)&& ((MESSAGE_AN(buffer) == NETWORK_ONE_16) || (MESSAGE_NS(buffer) == NETWORK_ONE_16)))
            {
                packet_unpack_reader_data reader;
                packet_reader_init(buffer, soa_query_mesg.received, &reader);
                reader.offset =  DNS_HEADER_LENGTH;
                packet_reader_skip_fqdn(&reader);
                packet_reader_skip(&reader, 4);
                
                u8 tmp[MAX_DOMAIN_LENGTH];
    
                /* read and expect an SOA */

                packet_reader_read_fqdn(&reader, tmp, sizeof(tmp));

                if(dnsname_equals(tmp, origin))
                {
                    struct type_class_ttl_rdlen tctr;

                    if(packet_reader_read(&reader, (u8*)&tctr, 10) == 10)
                    {
                        if((tctr.qtype == TYPE_SOA) && (tctr.qclass == CLASS_IN))
                        {
                            if(ISOK(return_value = packet_reader_skip_fqdn(&reader)))
                            {
                                if(ISOK(return_value = packet_reader_skip_fqdn(&reader)))
                                {
                                    if(packet_reader_read(&reader, tmp, 4) == 4)
                                    {
                                        *serial_out = ntohl(*((u32*)tmp));

                                        return SUCCESS;
                                    }
                                }
                            }
                        }
                        else
                        {
                            return MESSAGE_UNEXCPECTED_ANSWER_TYPE_CLASS;
                        }
                    }
                }

                return_value = MESSAGE_UNEXCPECTED_ANSWER_DOMAIN;
            }
            else if(MESSAGE_ID(buffer) != id)
            {
                return_value = MESSAGE_HAS_WRONG_ID;
            }
            else if(!MESSAGE_QR(buffer))
            {
                return_value = MESSAGE_IS_NOT_AN_ANSWER;
            }
            else if(MESSAGE_RCODE(buffer) != RCODE_NOERROR)
            {
                return_value = DNS_ERROR_CODE(MESSAGE_AN(buffer));
            }
            else
            {
                return_value = INVALID_MESSAGE;
            }
            
            return return_value;
        }
        
        if((return_value != MAKE_ERRNO_ERROR(EAGAIN)) && return_value != MAKE_ERRNO_ERROR(EINTR))
        {
            /*
             * Do not retry for any other kind of error
             */
            
            break;
        }
        
        if(countdown > 0)
        {
            usleep(10000);  /* 10 ms */
        }
    }
    
    return return_value;
}

/*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/
