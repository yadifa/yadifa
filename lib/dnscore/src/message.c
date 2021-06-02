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
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnscore/dnscore-config.h"

#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>

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
#include "dnscore/network.h"

#include "dnscore/thread_pool.h"

#if HAS_CTRL
#include "dnscore/ctrl-rfc.h"
#endif

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger



#define		SA_LOOP                 3
#define		SA_PRINT                4

/*------------------------------------------------------------------------------
 * FUNCTIONS */

u16 edns0_maxsize = EDNS0_MAX_LENGTH;

double g_message_data_minimum_troughput_default = 0;

void message_set_minimum_troughput_default(double rate)
{
    if(rate >= 0)
    {
        g_message_data_minimum_troughput_default = rate;
    }
}

void message_edns0_setmaxsize(u16 maxsize)
{
    edns0_maxsize = maxsize;
}

u16 message_edns0_getmaxsize()
{
    return edns0_maxsize;
}

// Handles OPT and TSIG

static ya_result
message_process_additionals(message_data *mesg, u8* s, u16 ar_count)
{
    (void)s;
    /*
     * @note: I've moved this in the main function (the one calling this one)
     */

    //yassert(ar_count != 0 && ar_count == message_get_additional_count(mesg));

    u8 *buffer = mesg->_buffer;

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

    u32 query_end = message_get_size(mesg);

    packet_unpack_reader_data purd;
    purd.packet = buffer;        
    purd.packet_size = query_end;

    if(mesg->_ar_start == NULL)
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

        query_end = purd.offset; // ready to remove all additionals in one fell swoop

        mesg->_ar_start = &mesg->_buffer[purd.offset];
    }
    else
    {
        purd.offset = message_get_additional_section_ptr(mesg) - mesg->_buffer;
    }

    /* We are now at the start of the ar */

    struct type_class_ttl_rdlen tctr;
    u8 tsigname[MAX_DOMAIN_LENGTH];
#if DNSCORE_HAS_TSIG_SUPPORT
    u32 record_offset;
#endif

    while(ar_count-- > 0)
    {
#if DNSCORE_HAS_TSIG_SUPPORT
        record_offset = purd.offset;
#endif

        if(FAIL(packet_reader_read_fqdn(&purd, tsigname, sizeof(tsigname))))
        {
            /* oops */
            
            message_set_status(mesg, FP_ERROR_READING_QUERY);

            return UNPROCESSABLE_MESSAGE;
        }

        if(packet_reader_read(&purd, &tctr, 10) == 10 ) // exact
        {
            /*
             * EDNS (0)
             */
            
            if(tctr.qtype == TYPE_OPT)
            {
                /**
                 * Handle EDNS
                 */

                if((tctr.ttl & NU32(0x00ff0000)) == 0) /* ensure version is 0 */
                {
                    u32 rdlen = ntohs(tctr.rdlen);
                    
#if DNSCORE_HAS_NSID_SUPPORT
                    if(rdlen != 0)
                    {
                        u32 next = purd.offset + rdlen;
                        for(u32 remain = rdlen; remain >= 4; remain -= 4)
                        {
                            u32 opt_type_size;
                            
                            if(ISOK(packet_reader_read_u32(&purd, &opt_type_size))) // read the option-code and the option-length in one operation
                            {
                                if(opt_type_size == NU32(0x00030000)) // check if it's NSID
                                {
                                    // nsid
                                    mesg->_nsid = TRUE;
                                    break;
                                }
                                packet_reader_skip(&purd, ntohl(opt_type_size) & 0xffff);   // skip the data
                            }
                            else
                            {
                                break;
                            }
                        }
                        
                        packet_reader_skip(&purd, next - purd.offset);
                    }
#else
                    packet_reader_skip(&purd, rdlen);
#endif
                    if(tsigname[0] == '\0')
                    {
                        message_set_buffer_size(mesg, MAX(EDNS0_MIN_LENGTH, ntohs(tctr.qclass))); /* our own limit, taken from the config file */
                        mesg->_edns = TRUE;

                        mesg->_rcode_ext = tctr.ttl;
#if DEBUG
                        log_debug("EDNS: udp-size=%d rcode-ext=%08x desc=%04x", message_get_size(mesg), tctr.ttl, rdlen);
#endif
                        continue;
                    }

#if DEBUG
                    log_debug("OPT record is not processable (broken)");
#endif
                    return UNPROCESSABLE_MESSAGE;
                }
                else
                {
                   message_set_status(mesg, FP_EDNS_BAD_VERSION);
                   message_set_size(mesg, MAX(EDNS0_MIN_LENGTH, ntohs(tctr.qclass)));
                   mesg->_edns = TRUE;
                   mesg->_rcode_ext = 0;

#if DEBUG
                    log_debug("OPT record is not processable (not supported)");
#endif

                   return MAKE_DNSMSG_ERROR(FP_EDNS_BAD_VERSION);
                }
            }
#if DNSCORE_HAS_TSIG_SUPPORT
            
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
                    
                    ya_result return_code;
                    
                    if(message_isquery(mesg))
                    {
                        if(FAIL(return_code = tsig_process_query(mesg, &purd, record_offset, tsigname, &tctr)))
                        {
#if DEBUG
                            // this should be reported above
                            log_notice("%r query error from %{sockaddr}", return_code, message_get_sender_sa(mesg));
#endif
                            return return_code;
                        }
                    }
                    else
                    {
                        tsig_item *key = tsig_get(tsigname);
                        
                        if(key != NULL)
                        {
                            if(FAIL(return_code = tsig_process(mesg, &purd, record_offset, key, &tctr)))
                            {
#if DEBUG
                                // this should be reported above
                                log_notice("%r answer error from %{sockaddr}", return_code, message_get_sender_sa(mesg));
#endif
                                return return_code;
                            }
                        }
                        else
                        {
                            log_notice("answer error from %{sockaddr}: TSIG when none expected", message_get_sender_sa(mesg));

                            message_set_status(mesg, FP_TSIG_UNEXPECTED);

                            return MAKE_DNSMSG_ERROR(FP_TSIG_UNEXPECTED);
                        }
                    }

                    break;  /* we know there is no need to loop anymore */
                }
                else
                {
                    /*
                     * Error: TSIG is not the last AR record
                     */

#if DEBUG
                    log_debug("TSIG record is not the last AR");
#endif
                    
                    message_set_status(mesg, FP_TSIG_IS_NOT_LAST);

                    return UNPROCESSABLE_MESSAGE;
                }
            }
#endif
            else
            {
                /* Unhandled AR TYPE */

                log_debug("unhandled AR type %{dnstype}", &tctr.qtype);
                
                message_set_status(mesg, FP_UNEXPECTED_RR_IN_QUERY);                

                return UNPROCESSABLE_MESSAGE;
            }
        }
    } /* While there are AR to process */
    
    message_set_additional_count_ne(mesg, 0);
    message_set_size(mesg, query_end);

    return SUCCESS;
}

/**
 * Handles the OPT and TSIG records of an answer.
 * 
 * @param mesg
 * @param ar_count
 * @return 
 */

static ya_result
message_process_answer_additionals(message_data *mesg, u16 ar_count /* network order */ )
{
    /*
     * @note: I've moved this in the main function (the one calling this one)
     */

    yassert(ar_count != 0 && ar_count == message_get_additional_count_ne(mesg));

    u8 *buffer = message_get_buffer(mesg);

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

    u32 message_size = message_get_size(mesg);

    packet_unpack_reader_data purd;
    purd.packet = buffer;        
    purd.packet_size = message_size;

    if(mesg->_ar_start == NULL)
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

        message_size = purd.offset;

        mesg->_ar_start = &mesg->_buffer[purd.offset];
    }
    else
    {
        purd.offset = message_get_additional_section_ptr(mesg) - mesg->_buffer; // size up to additional sections
    }

    /* We are now at the start of the ar */

    struct type_class_ttl_rdlen tctr;
    u8 tsigname[MAX_DOMAIN_LENGTH];
    
#if DNSCORE_HAS_TSIG_SUPPORT
    u32 record_offset;
#endif

    while(ar_count-- > 0)
    {
#if DNSCORE_HAS_TSIG_SUPPORT
        record_offset = purd.offset;
#endif

        if(FAIL(packet_reader_read_fqdn(&purd, tsigname, sizeof(tsigname))))
        {
            /* oops */
            
            message_set_status(mesg, FP_ERROR_READING_QUERY);

            return UNPROCESSABLE_MESSAGE;
        }

        if(packet_reader_read(&purd, &tctr, 10) == 10 ) // exact
        {
            /*
             * EDNS (0)
             */
            
            if(tctr.qtype == TYPE_OPT)
            {
                /**
                 * Handle EDNS
                 */
                
                if((tctr.ttl & NU32(0x00ff0000)) == 0) /* ensure version is 0 */
                {
                    if(tsigname[0] == '\0')
                    {
                        message_sub_additional_count(mesg, 1);

                        mesg->_edns = TRUE;
                        mesg->_rcode_ext = tctr.ttl;

                        log_debug("EDNS: udp-size=%d rcode-ext=%08x desc=%04x", message_get_buffer_size(mesg), tctr.ttl, ntohs(tctr.rdlen));
                        continue;
                    }
                }
                else
                {
                   mesg->_edns = TRUE;
                   mesg->_rcode_ext = tctr.ttl;
                   
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
#if DNSCORE_HAS_TSIG_SUPPORT
            
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
                    
                    ya_result return_code;
                    
                    if(message_isquery(mesg))
                    {
                        if(FAIL(return_code = tsig_process_query(mesg, &purd, record_offset, tsigname, &tctr)))
                        {
                            log_err("%r query error from %{sockaddr}", return_code, message_get_sender_sa(mesg));

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
                        if(message_has_tsig(mesg))
                        {
                            if(dnsname_equals(tsigname, message_tsig_get_name(mesg)))
                            {                        
                                if(FAIL(return_code = tsig_process_answer(mesg, &purd, record_offset, &tctr)))
                                {
                                    log_err("%r answer error from %{sockaddr}", return_code, message_get_sender_sa(mesg));

                                    return UNPROCESSABLE_MESSAGE;
                                }
                            }
                            else
                            {
                                log_err("TSIG name mismatch from %{sockaddr}", message_get_sender_sa(mesg));
                                
                                return UNPROCESSABLE_MESSAGE;
                            }
                        }
                        else // no tsig
                        {
                            log_err("answer error from %{sockaddr}: TSIG when none expected", message_get_sender_sa(mesg));

                            message_set_status(mesg, FP_TSIG_UNEXPECTED);

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
                    
                    message_set_status(mesg, FP_TSIG_IS_NOT_LAST);

                    return UNPROCESSABLE_MESSAGE;
                }
            }
#endif
            else
            {
                /* Unhandled AR TYPE */
#if DEBUG
                log_debug("skipping AR type %{dnstype}", &tctr.qtype);
#endif
                purd.offset += ntohs(tctr.rdlen);
                
                message_size = purd.offset;
            }
        }
    } /* While there are AR to process */

    message_set_additional_count_ne(mesg, 0);
    message_set_size(mesg, message_size);

    return SUCCESS;
}

#if 0
/**
 * Handles the OPT and TSIG records of an answer.
 *
 * @param mesg
 * @param ar_count
 * @return
 */

static ya_result
message_process_answer_additionals_and_keep(message_data *mesg, u16 ar_count /* network order */ )
{
    /*
     * @note: I've moved this in the main function (the one calling this one)
     */

    yassert(ar_count != 0 && ar_count == message_get_additional_count_ne(mesg));

    u8 *buffer = message_get_buffer(mesg);

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

    u32 message_size = message_get_size(mesg);

    packet_unpack_reader_data purd;
    purd.packet = buffer;
    purd.packet_size = message_size;

    if(mesg->_ar_start == NULL)
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

        message_size = purd.offset;

        mesg->_ar_start = &mesg->_buffer[purd.offset];
    }
    else
    {
        purd.offset = message_get_additional_section_ptr(mesg) - mesg->_buffer; // size up to additional sections
    }

    /* We are now at the start of the ar */

    struct type_class_ttl_rdlen tctr;
    u8 tsigname[MAX_DOMAIN_LENGTH];

#if DNSCORE_HAS_TSIG_SUPPORT
    u32 record_offset;
#endif

    while(ar_count-- > 0)
    {
#if DNSCORE_HAS_TSIG_SUPPORT
        record_offset = purd.offset;
#endif

        if(FAIL(packet_reader_read_fqdn(&purd, tsigname, sizeof(tsigname))))
        {
            /* oops */

            message_set_status(mesg, FP_ERROR_READING_QUERY);

            return UNPROCESSABLE_MESSAGE;
        }

        if(packet_reader_read(&purd, &tctr, 10) == 10 ) // exact
        {
            /*
             * EDNS (0)
             */

            if(tctr.qtype == TYPE_OPT)
            {
                /**
                 * Handle EDNS
                 */

                if((tctr.ttl & NU32(0x00ff0000)) == 0) /* ensure version is 0 */
                {
                    if(tsigname[0] == '\0')
                    {
                        mesg->_edns = TRUE;
                        mesg->_rcode_ext = tctr.ttl;

                        log_debug("EDNS: udp-size=%d rcode-ext=%08x desc=%04x", message_get_buffer_size(mesg), tctr.ttl, ntohs(tctr.rdlen));
                        continue;
                    }
                }
                else
                {
                    message_set_status(mesg, FP_EDNS_BAD_VERSION);
                    message_set_buffer_size(mesg, edns0_maxsize);
                    mesg->_edns = TRUE;
                    mesg->_rcode_ext = 0;

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
#if DNSCORE_HAS_TSIG_SUPPORT

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

                    ya_result return_code;

                    if(message_isquery(mesg))
                    {
                        if(FAIL(return_code = tsig_process_query(mesg, &purd, record_offset, tsigname, &tctr)))
                        {
                            log_err("%r query error from %{sockaddr}", return_code, message_get_sender_sa(mesg));

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
                        if(message_has_tsig(mesg))
                        {
                            if(dnsname_equals(tsigname, message_tsig_get_name(mesg)))
                            {
                                if(FAIL(return_code = tsig_process_answer(mesg, &purd, record_offset, &tctr)))
                                {
                                    log_err("%r answer error from %{sockaddr}", return_code, message_get_sender_sa(mesg));

                                    return UNPROCESSABLE_MESSAGE;
                                }
                            }
                            else
                            {
                                log_err("TSIG name mismatch from %{sockaddr}", message_get_sender_sa(mesg));

                                return UNPROCESSABLE_MESSAGE;
                            }
                        }
                        else // no tsig
                        {
                            log_err("answer error from %{sockaddr}: TSIG when none expected", message_get_sender_sa(mesg));

                            message_set_status(mesg, FP_TSIG_UNEXPECTED);

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

                    message_set_status(mesg, FP_TSIG_IS_NOT_LAST);

                    return UNPROCESSABLE_MESSAGE;
                }
            }
#endif
            else
            {
                /* Unhandled AR TYPE */
#if DEBUG
                log_debug("skipping AR type %{dnstype}", &tctr.qtype);
#endif
                purd.offset += ntohs(tctr.rdlen);

                message_size = purd.offset;
            }
        }
    } /* While there are AR to process */

    message_set_additional_count_ne(mesg, 0);
    message_set_size(mesg, message_size);

    return SUCCESS;
}
#endif

/** \brief Processing DNS packet
 *
 *  @param mesg
 *
 *  @retval OK
 *  @return status of message is written in message_get_status(mesg)
 */

/* Defines a mask and the expected result for the 4 first 16 bits of the header */
#ifdef WORDS_BIGENDIAN
#define MESSAGE_HEADER_MASK     (( (u64) 0 )                        |  \
        ( ((u64) ( QR_BITS | AA_BITS | RA_BITS | TC_BITS )) << 40 ) |  \
        ( ((u64) ( RA_BITS | RCODE_BITS )) << 32 )                  |  \
        ( ((u64) 1LL) << 16 ))

#define MESSAGE_HEADER_RESULT   ( ((u64) 1LL) << 16 )

/* Bind gives "RA" here (seems irrelevant, nonsense, but we need to accept it) */

#define NOTIFY_MESSAGE_HEADER_MASK     (( (u64) 0LL )             |  \
        ( ((u64) ( TC_BITS )) << 40 )                             |  \
        ( ((u64) 1LL) << 16 ))

#define NOTIFY_MESSAGE_HEADER_RESULT   ( ((u64) 1LL) << 16 )
   
#else

#define MESSAGE_HEADER_MASK     (( (u64) 0LL )                      |  \
        ( ((u64) ( QR_BITS | AA_BITS | RA_BITS | TC_BITS )) << 16 ) |  \
        ( ((u64) ( RA_BITS | RCODE_BITS )) << 24 )                  |  \
        ( ((u64) 1LL) << 40 ))

#define MESSAGE_HEADER_RESULT   ( ((u64) 1LL) << 40 )

/* Bind gives "RA" here (seems irrelevant, nonsense, but we need to accept it) */

#define NOTIFY_MESSAGE_HEADER_MASK     (( (u64) 0LL )             |  \
        ( ((u64) ( TC_BITS )) << 16 )                             |  \
        ( ((u64) 1LL) << 40 ))

#define NOTIFY_MESSAGE_HEADER_RESULT   ( ((u64) 1LL) << 40 )

#endif

/* EDF: this takes about 150 cycles [144;152] with peaks at 152 */
   
/**
 * Canonises the query:
 * _ copies the query fqdn lowercase
 * _ copies the query type and class for easy access
 * 
 * (should be renamed to message_query_canonise or something of that effect)
 * 
 * @param mesg
 * @return a pointer to the answer section (or more accurately, just after the class of the (first) query
 */
   
static inline u8*
message_process_copy_fqdn(message_data *mesg)
{
    u8 *src = message_get_query_section_ptr(mesg);
    u8 *dst = &mesg->_canonised_fqdn[0];

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
            const u8 * const limit = dst + len;

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
                message_set_status(mesg, FP_NAME_TOO_LARGE);

                DERROR_MSG("FP_NAME_TOO_LARGE");

                return NULL;
            }
        }
        else
        {
            message_set_status(mesg, ((len & 0xC0)==0xC0)?FP_QNAME_COMPRESSED:FP_NAME_FORMAT_ERROR);

            return NULL;
        }
    }

    /* Get qtype & qclass */
    
    mesg->_query_type  = GET_U16_AT(src[0]); /** @note : NATIVETYPE  */
    mesg->_query_class = GET_U16_AT(src[2]); /** @note : NATIVECLASS */
    
    // the next section starts at &src[4]

    return &src[4];
}

ya_result
message_process_query(message_data *mesg)
{
    u8 *buffer = message_get_buffer(mesg);
    
    /** CHECK DNS HEADER */
    /** Drop dns packet if query is answer or does not have correct header length */

    /*
     * +5 <=> 1 qd record ar least
     */

    u64 *h64 = (u64*)buffer;
    u64 m64 = MESSAGE_HEADER_MASK;
    u64 r64 = MESSAGE_HEADER_RESULT;

    if((message_get_size(mesg) < DNS_HEADER_LENGTH + 5) ||
            ((  *h64 & m64) != r64 ) )
    {
        /** Return if QDCOUNT is not 1
         *
         *  @note Previous test was actually testing if QDCOUNT was > 1
         *        I assumed either 0 or >1 is wrong for us so I used the same trick than for QCCOUNT
         */

        if(MESSAGE_QR(buffer))
        {
            message_set_status(mesg, FP_QR_BIT_SET);
            return INVALID_MESSAGE;
        }

        MESSAGE_FLAGS_AND(buffer, OPCODE_BITS|RD_BITS, 0);

        if(NETWORK_ONE_16 != MESSAGE_QD(buffer))
        {
            if(0 == MESSAGE_QD(buffer))
            {
                DERROR_MSG("FP_QDCOUNT_IS_0");
                message_set_status(mesg, FP_QDCOUNT_IS_0);
                return INVALID_MESSAGE; /* will be dropped */
            }
            else
            {
                DERROR_MSG("FP_QDCOUNT_BIG_1");
                message_set_status(mesg, FP_QDCOUNT_BIG_1);
            }
        }
        else if(MESSAGE_NS(buffer) != 0)
        {
            message_set_status(mesg, FP_NSCOUNT_NOT_0);
        }
        else
        {                
            message_set_status(mesg, FP_PACKET_DROPPED);
        }

        return UNPROCESSABLE_MESSAGE;
    }

    /**
     * @note Past this point, a message could be processable.
     *       It's the right place to reset the message's defaults.
     *
     */

    message_reset_buffer_size(mesg);
    mesg->_ar_start = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
    mesg->_tsig.tsig  = NULL;
#endif
    mesg->_rcode_ext  = 0;
    mesg->_edns       = FALSE;
#if DNSCORE_HAS_NSID_SUPPORT
    mesg->_nsid       = FALSE;
#endif

    u8 *s = message_process_copy_fqdn(mesg);

    if(s == NULL)
    {
        message_set_status(mesg, FP_NAME_FORMAT_ERROR);
        return UNPROCESSABLE_MESSAGE;
    }

    /*
     * Handle the OPT and TSIG records
     */

    {
        ya_result return_code;
        u32 nsar_count;

        if((nsar_count = MESSAGE_NSAR(buffer)) != 0)
        {
            if(FAIL(return_code = message_process_additionals(mesg, s, nsar_count)))
            {
                //message_set_size(mesg, s - buffer);

                return return_code;
            }
        }

        if(message_get_query_type(mesg) != TYPE_IXFR)
        {
            message_set_size(mesg, s - buffer);
        }
    }

    /* cut the trash here */


    /* At this point the TSIG has been computed and removed */
    /* Clear zome bits */
    message_apply_mask(mesg, ~(QR_BITS|TC_BITS|AA_BITS), ~(Z_BITS|AD_BITS|CD_BITS|RA_BITS|RCODE_BITS));
    //MESSAGE_LOFLAGS(buffer) &= ~(Z_BITS|AD_BITS|CD_BITS|RCODE_BITS);

    message_set_status(mesg, FP_MESG_OK);

    return OK;
}

int
message_process(message_data *mesg)
{
    u8 *buffer = message_get_buffer(mesg);
    
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

            if(     (message_get_size(mesg) < DNS_HEADER_LENGTH + 5) ||
                    ((  *h64 & m64) != r64 ) )
            {
                /** Return if QDCOUNT is not 1
                 *
                 *  @note Previous test was actually testing if QDCOUNT was > 1
                 *        I assumed either 0 or >1 is wrong for us so I used the same trick than for QCCOUNT
                 */
                
                if(MESSAGE_QR(buffer))
                {
                    message_set_status(mesg, FP_QR_BIT_SET);
                    return INVALID_MESSAGE;
                }
                
                MESSAGE_FLAGS_AND(buffer, OPCODE_BITS|RD_BITS, 0);

                if(NETWORK_ONE_16 != MESSAGE_QD(buffer))
                {
                    if(0 == MESSAGE_QD(buffer))
                    {
                        DERROR_MSG("FP_QDCOUNT_IS_0");
                        
                        message_set_status(mesg, FP_QDCOUNT_IS_0);
                        
                        return INVALID_MESSAGE; /* will be dropped */
                    }
                    else
                    {
                        message_set_status(mesg, FP_QDCOUNT_BIG_1);

                        DERROR_MSG("FP_QDCOUNT_BIG_1");
                    }
                }
                else if( MESSAGE_NS(buffer) != 0)
                {
                    message_set_status(mesg, FP_NSCOUNT_NOT_0);
                }
                else
                {                
                    message_set_status(mesg, FP_PACKET_DROPPED);
                }

                return UNPROCESSABLE_MESSAGE;
            }


            
            /**
             * @note Past this point, a message could be processable.
             *       It's the right place to reset the message's defaults.
             *
             */

            message_reset_buffer_size(mesg);
            mesg->_ar_start   = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
            mesg->_tsig.tsig  = NULL;
#endif
            mesg->_rcode_ext  = 0;
            mesg->_edns       = FALSE;
#if DNSCORE_HAS_NSID_SUPPORT
            mesg->_nsid       = FALSE;
#endif
            
            u8 *s = message_process_copy_fqdn(mesg);

            if(s == NULL)
            {
                message_set_status(mesg, FP_NAME_FORMAT_ERROR);
                return UNPROCESSABLE_MESSAGE;
            }


            
            /*
             * Handle the OPT and TSIG records
             */

            {
                ya_result return_code;
                u32 nsar_count;

                if((nsar_count = MESSAGE_NSAR(buffer)) != 0)
                {
                    if(FAIL(return_code = message_process_additionals(mesg, s, nsar_count)))
                    {
                        message_set_size(mesg, s - buffer);
                        
                        return return_code;
                    }
                }
                
                if(message_get_query_type(mesg) != TYPE_IXFR)
                {
                    message_set_size(mesg, s - buffer);
                }
            }

            /* At this point the TSIG has been computed and removed */
            /* Clear zome bits */
            message_apply_mask(mesg, ~(QR_BITS|TC_BITS|AA_BITS), ~(Z_BITS|RA_BITS|AD_BITS|CD_BITS|RCODE_BITS));

            message_set_status(mesg, FP_MESG_OK);

            return OK;
        }
        case OPCODE_NOTIFY:
        {
            MESSAGE_LOFLAGS(buffer) &= ~(Z_BITS|AD_BITS|CD_BITS);
            

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
            if(     (message_get_size(mesg) < DNS_HEADER_LENGTH + 5) ||
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
                        message_set_status(mesg, FP_QDCOUNT_IS_0);
                        return INVALID_MESSAGE;
                    }
                    else
                    {
                        message_set_status(mesg, FP_QDCOUNT_BIG_1);

                        DERROR_MSG("FP_QDCOUNT_BIG_1");
                    }
                }
                else
                {
                    message_set_status(mesg, FP_PACKET_DROPPED);
                }

                return UNPROCESSABLE_MESSAGE;
            }



            u8 *s = message_process_copy_fqdn(mesg);

            if(s == NULL)
            {
                message_set_status(mesg, FP_NAME_FORMAT_ERROR);
                return UNPROCESSABLE_MESSAGE;
            }



            /**
             * @note Past this point, a message could be processable.
             *       It's the right place to reset the message's defaults.
             *
             */

            message_reset_buffer_size(mesg);
            mesg->_ar_start  = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
            mesg->_tsig.tsig  = NULL;
#endif
            mesg->_rcode_ext  = 0;
            mesg->_edns       = FALSE;
#if DNSCORE_HAS_NSID_SUPPORT
            mesg->_nsid       = FALSE;
#endif
            /*
             * If there is a TSIG, it is here ...
             */

#if DNSCORE_HAS_TSIG_SUPPORT
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

            message_set_status(mesg, FP_MESG_OK);

            return OK;
        }
        case OPCODE_UPDATE:
        {
            MESSAGE_LOFLAGS(buffer) &= ~(Z_BITS|AD_BITS|CD_BITS|RCODE_BITS);
            

            /*    ------------------------------------------------------------    */

            /** CHECK DNS HEADER */
            /** Drop dns packet if query is answer or does not have correct header length */

            /*
             * +5 <=> 1 qd record ar least
             */

            u64 *h64 = (u64*)buffer;
            u64 m64 = MESSAGE_HEADER_MASK;
            u64 r64 = MESSAGE_HEADER_RESULT;

            if(     (message_get_size(mesg) < DNS_HEADER_LENGTH + 5) ||
                    ((  *h64 & m64) != r64 ) )
            {
                /** Return if QDCOUNT is not 1
                 *
                 *  @note Previous test was actually testing if QDCOUNT was > 1
                 *        I assumed either 0 or >1 is wrong for us so I used the same trick than for QCCOUNT
                 */
                
                if(MESSAGE_QR(buffer))
                {
                    message_set_status(mesg, FP_QR_BIT_SET);
                    return INVALID_MESSAGE;
                }
                
                MESSAGE_FLAGS_AND(buffer, OPCODE_BITS, 0);

                if(NETWORK_ONE_16 != MESSAGE_QD(buffer))
                {
                    if(0 == MESSAGE_QD(buffer))
                    {
                        DERROR_MSG("FP_QDCOUNT_IS_0");
                        message_set_status(mesg, FP_QDCOUNT_IS_0);
                        return INVALID_MESSAGE;
                    }
                    else
                    {
                        DERROR_MSG("FP_QDCOUNT_BIG_1");
                        message_set_status(mesg, FP_QDCOUNT_BIG_1);
                    }

                    return UNPROCESSABLE_MESSAGE;
                }

                message_set_status(mesg, FP_PACKET_DROPPED);

                return UNPROCESSABLE_MESSAGE;
            }



            u8 *s = message_process_copy_fqdn(mesg);

            if(s == NULL)
            {
                message_set_status(mesg, FP_NAME_FORMAT_ERROR);
                return UNPROCESSABLE_MESSAGE;
            }



            /**
             * @note Past this point, a message could be processable.
             *       It's the right place to reset the message's defaults.
             *
             */

            message_reset_buffer_size(mesg);
            mesg->_ar_start = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
            mesg->_tsig.tsig  = NULL;
#endif
            mesg->_rcode_ext  = 0;
            mesg->_edns       = FALSE;
#if DNSCORE_HAS_NSID_SUPPORT
            mesg->_nsid       = FALSE;
#endif
            /*
             * If there is a TSIG, it is here ...
             */
            
#if DNSCORE_HAS_TSIG_SUPPORT
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

            message_apply_mask(mesg, ~(QR_BITS|TC_BITS|AA_BITS), ~(RA_BITS|RCODE_BITS));

            message_set_status(mesg, FP_MESG_OK);
            
            return OK;
        }
#if HAS_CTRL
        case OPCODE_CTRL:
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

            if(     (message_get_size(mesg) < DNS_HEADER_LENGTH + 5) ||
                    ((  *h64 & m64) != r64 ) )
            {
                /** Return if QDCOUNT is not 1
                 *
                 *  @note Previous test was actually testing if QDCOUNT was > 1
                 *        I assumed either 0 or >1 is wrong for us so I used the same trick than for QCCOUNT
                 */
                
                if(MESSAGE_QR(buffer))
                {
                    message_set_status(mesg, FP_QR_BIT_SET);
                    return INVALID_MESSAGE;
                }
                
                MESSAGE_FLAGS_AND(buffer, OPCODE_BITS, 0);

                if(NETWORK_ONE_16 != MESSAGE_QD(buffer))
                {
                    if(0 == MESSAGE_QD(buffer))
                    {
                        DERROR_MSG("FP_QDCOUNT_IS_0");
                        message_set_status(mesg, FP_QDCOUNT_IS_0);
                        return INVALID_MESSAGE;
                    }
                    else
                    {
                        DERROR_MSG("FP_QDCOUNT_BIG_1");
                        message_set_status(mesg, FP_QDCOUNT_BIG_1);
                    }

                    return UNPROCESSABLE_MESSAGE;
                }

                message_set_status(mesg, FP_PACKET_DROPPED);

                return UNPROCESSABLE_MESSAGE;
            }



            u8 *s = message_process_copy_fqdn(mesg);

            if(s == NULL)
            {
                message_set_status(mesg, FP_NAME_FORMAT_ERROR);
                return UNPROCESSABLE_MESSAGE;
            }



            /**
             * @note Past this point, a message could be processable.
             *       It's the right place to reset the message's defaults.
             *
             */

            message_reset_buffer_size(mesg);
            mesg->_ar_start = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
            message_tsig_clear_key(mesg);
#endif
            mesg->_rcode_ext  = 0;
            mesg->_edns       = FALSE;
#if DNSCORE_HAS_NSID_SUPPORT
            mesg->_nsid       = FALSE;
#endif
            /*
             * If there is a TSIG, it is here ...
             */
            
#if DNSCORE_HAS_TSIG_SUPPORT
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

            message_apply_mask(mesg, ~(QR_BITS|TC_BITS|AA_BITS), ~(RA_BITS|RCODE_BITS));

            message_set_status(mesg, FP_MESG_OK);
            
            return OK;
        }
#endif // HAS_CTRL
        default:
        {
            u8 hf = MESSAGE_HIFLAGS(buffer);
            if((hf & QR_BITS) == 0)
            {
                MESSAGE_LOFLAGS(buffer) &= ~(Z_BITS|AD_BITS|CD_BITS|RCODE_BITS);
                MESSAGE_FLAGS_AND(buffer, OPCODE_BITS, 0);

                message_reset_buffer_size(mesg);
                mesg->_ar_start = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
                mesg->_tsig.tsig  = NULL;
#endif
                mesg->_rcode_ext  = 0;
                mesg->_edns       = FALSE;
#if DNSCORE_HAS_NSID_SUPPORT
                mesg->_nsid       = FALSE;
#endif
                message_set_status(mesg, FP_NOT_SUPP_OPC);
                message_set_size(mesg, DNS_HEADER_LENGTH);
                SET_U32_AT(mesg->_buffer[4],0);    /* aligned to 32 bits, so two 32 bits instead of one 64 */
                SET_U32_AT(mesg->_buffer[8],0);

                /* reserved for future use */
                
                return UNPROCESSABLE_MESSAGE;
            }
            else
            {
                message_set_status(mesg, FP_PACKET_DROPPED);
                
                return INVALID_MESSAGE;
            }
        }
    }
}

int
message_process_lenient(message_data *mesg)
{
    if(message_get_size(mesg) < DNS_HEADER_LENGTH)
    {
        return UNPROCESSABLE_MESSAGE;
    }
    /*
    if(message_istruncated(mesg))
    {
        return MESSAGE_TRUNCATED;
    }
    */
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

    message_reset_buffer_size(mesg);
    mesg->_ar_start = NULL;
    mesg->_rcode_ext  = 0;
    mesg->_edns       = FALSE;
#if DNSCORE_HAS_NSID_SUPPORT
    mesg->_nsid       = FALSE;
#endif

    /*
     * Handle the OPT and TSIG records
     */

    {
        ya_result return_code;
        u16 ar_count_ne;

        if((ar_count_ne = message_get_additional_count_ne(mesg)) != 0)
        {
            if(FAIL(return_code = message_process_answer_additionals(mesg, ar_count_ne)))
            {
                return return_code;
            }
        }
#if DNSCORE_HAS_TSIG_SUPPORT
        else
        {
            mesg->_tsig.tsig  = NULL;
            
            /* cut the trash here */
            /*message_set_size(mesg, s - buffer);(*/
        }
#endif
    }
    


    /* At this point the TSIG has been computed and removed */

    //message_set_status(mesg, FP_MESG_OK);
    message_set_status(mesg, (mesg->_buffer[3] & 0xf));

    return SUCCESS;
}

static ya_result
message_answer_verify_additionals(message_data *mesg, packet_unpack_reader_data *purd, int ar_count)
{
    /* We are now at the start of the ar */

    struct type_class_ttl_rdlen *tctr;
#if DNSCORE_HAS_TSIG_SUPPORT
    u32 record_offset;
    u8 fqdn[MAX_DOMAIN_LENGTH];
#endif

    while(ar_count-- > 0)
    {
#if DNSCORE_HAS_TSIG_SUPPORT
        record_offset = purd->offset;
#endif

        if(FAIL(packet_reader_read_fqdn(purd, fqdn, sizeof(fqdn))))
        {
            /* oops */
            
            message_set_status(mesg, FP_ERROR_READING_QUERY);

            return UNPROCESSABLE_MESSAGE;
        }
        
        if(packet_reader_available(purd) < 10)
        {
            message_set_status(mesg, FP_ERROR_READING_QUERY);
            
            return UNPROCESSABLE_MESSAGE;
        }
        
        tctr = (struct type_class_ttl_rdlen*)packet_reader_get_next_u8_ptr_const(purd);
        
        purd->offset += 10;
        
        switch(tctr->qtype)
        {
            /*
             * EDNS (0)
             */
            
            case TYPE_OPT:
            {
                /**
                 * Handle EDNS
                 */
                
                message_sub_additional_count(mesg, 1);
                
                if((tctr->ttl & NU32(0x00ff0000)) == 0) /* ensure version is 0 */
                {
                    if(fqdn[0] == '\0')
                    {
                        message_set_buffer_size(mesg, edns0_maxsize); /* our own limit, taken from the config file */
                        mesg->_edns = TRUE;
                        mesg->_rcode_ext = tctr->ttl;

                        log_debug("EDNS: udp-size=%d rcode-ext=%08x desc=%04x", message_get_size(mesg), tctr->ttl, ntohs(tctr->rdlen));
                        continue;
                    }
                }
                else
                {
                   message_set_status(mesg, FP_EDNS_BAD_VERSION);
                   message_set_buffer_size(mesg, edns0_maxsize);
                   mesg->_edns = TRUE;
                   mesg->_rcode_ext = 0;

                   break;
                }
                
                log_debug("OPT record is not processable (broken or not supported)");

                return UNPROCESSABLE_MESSAGE;
            }
#if DNSCORE_HAS_TSIG_SUPPORT
            
            /*
             * TSIG
             */
            
            case TYPE_TSIG:
            {
                if(ar_count == 0)
                {
                    /*
                     * It looks like a TSIG ...
                     */
                    
                    ya_result return_code;
                    
                    if(message_has_tsig(mesg))
                    {
                        if(dnsname_equals(fqdn, message_tsig_get_name(mesg)))
                        {                        
                            if(FAIL(return_code = tsig_process_answer(mesg, purd, record_offset, tctr)))
                            {
                                log_err("%r answer error from %{sockaddr}", return_code, message_get_sender_sa(mesg));

                                return return_code;
                            }
                        }
                        else
                        {
                            log_err("TSIG name mismatch from %{sockaddr}", message_get_sender_sa(mesg));

                            return UNPROCESSABLE_MESSAGE;
                        }
                    }
                    else // no tsig
                    {
                        log_err("answer error from %{sockaddr}: TSIG when none expected", message_get_sender_sa(mesg));

                        message_set_status(mesg, FP_TSIG_UNEXPECTED);

                        return UNPROCESSABLE_MESSAGE;
                    }

                    return SUCCESS;  /* we know there is no need to loop anymore */
                }
                else
                {
                    /*
                     * Error: TSIG is not the last AR record
                     */

                    log_debug("TSIG record is not the last AR");
                    
                    message_set_status(mesg, FP_TSIG_IS_NOT_LAST);

                    return UNPROCESSABLE_MESSAGE;
                }
            }
#endif
            default:
            {
                /* Unhandled AR TYPE */
#if DEBUG
                log_debug("skipping AR type %{dnstype}", &tctr->qtype);
#endif
                purd->offset += ntohs(tctr->rdlen);
                break;
            }
        }
    } /* While there are AR to process */
    
    return SUCCESS;
}

int
message_answer_verify(message_data *mesg)
{
    if(message_get_size(mesg) < DNS_HEADER_LENGTH)
    {
        return UNPROCESSABLE_MESSAGE;
    }
    
    u8 *after_query_section;
    
    if(message_get_query_count_ne(mesg) != 0)
    {
        after_query_section = message_process_copy_fqdn(mesg); // canonises the query fqdn and fetches its type and class

        if(after_query_section == NULL)
        {
            return UNPROCESSABLE_MESSAGE;
        }
    }
    else
    {
        if(mesg->_tcp_serial == 0) // needed at the beginning of the stream
        {
            return UNPROCESSABLE_MESSAGE;
        }
        
        after_query_section = message_get_query_section_ptr(mesg); // as there is no query section
    }

    /**
     * @note Past this point, a message could be processable.
     *       It's the right place to reset the message's defaults.
     *
     */
    
    u16 ar_count_ne;

    if((ar_count_ne = message_get_additional_count_ne(mesg)) != 0)
    {
        // find the additional section
        
        packet_unpack_reader_data purd;
        purd.packet = message_get_buffer_const(mesg);        
        purd.packet_size = message_get_size(mesg);
        purd.offset = after_query_section - purd.packet;
        
        // skip all records before the additional section

        for(int ar_index = message_get_answer_count(mesg) + message_get_authority_count(mesg); ar_index > 0; --ar_index)
        {
            packet_reader_skip_record(&purd);
        }

        mesg->_ar_start = &mesg->_buffer[purd.offset];
        
        // ar_start is ready

        message_answer_verify_additionals(mesg, &purd,  ntohs(ar_count_ne));
    }
    else
    {    
        mesg->_ar_start = NULL;
        mesg->_rcode_ext  = 0;
        mesg->_edns       = FALSE;
#if DNSCORE_HAS_NSID_SUPPORT
        mesg->_nsid       = FALSE;
#endif
    }

    message_set_status(mesg, FP_MESG_OK);

    return OK;
}


void
message_transform_to_error(message_data *mesg)
{
    if(!mesg->_edns)
    {
        message_set_answer(mesg);
        message_or_rcode(mesg, message_get_status(mesg));

        if(message_get_status(mesg) == RCODE_FORMERR)
        {
            SET_U32_AT(mesg->_buffer[4],0);    /* aligned to 32 bits, so two 32 bits instead of one 64 */
            SET_U32_AT(mesg->_buffer[8],0);
            
            message_set_size(mesg, DNS_HEADER_LENGTH);
        }
        else
        {
        }
    }
    else
    {
        /* 00 0029 0200 EE 00 00000000 */
        
        if(message_get_status(mesg) == RCODE_FORMERR)
        {
            SET_U32_AT(mesg->_buffer[4],0);    /* aligned to 32 bits, so two 32 bits instead of one 64 */
            SET_U32_AT(mesg->_buffer[8],0);
            
            message_set_size(mesg, DNS_HEADER_LENGTH);
        }
        else
        {
            message_set_size(mesg, message_get_additional_section_ptr(mesg) - mesg->_buffer);
        }

        message_set_answer(mesg);
        message_set_rcode(mesg, message_get_status(mesg) & 15);
        
        /* #AR = 1 */
        mesg->_buffer[DNS_HEADER_LENGTH - 1] = 1;    /* AR count was 0, now it is 1 */
        
        /* append opt *//* */
        u8 *buffer = message_get_buffer_limit(mesg);
        buffer[ 0] = 0;
        buffer[ 1] = 0;
        buffer[ 2] = 0x29;        
        buffer[ 3] = edns0_maxsize>>8;
        buffer[ 4] = edns0_maxsize;
        buffer[ 5] = message_get_status(mesg) >> 4; // status is updated here
        buffer[ 6] = mesg->_rcode_ext >> 16;
        buffer[ 7] = mesg->_rcode_ext >> 8;
        buffer[ 8] = mesg->_rcode_ext;

#if DNSCORE_HAS_NSID_SUPPORT
        if(!message_has_nsid(mesg))
        {
            buffer[ 9] = 0;
            buffer[10] = 0;

            buffer += EDNS0_RECORD_SIZE;
        }
        else
        {
            buffer += EDNS0_RECORD_SIZE - 2;
            memcpy(buffer, edns0_rdatasize_nsid_option_wire, edns0_rdatasize_nsid_option_wire_size);
            buffer += edns0_rdatasize_nsid_option_wire_size;
        }
#else
        buffer[ 9] = 0;
        buffer[10] = 0;

        buffer += EDNS0_RECORD_SIZE;
#endif
        message_set_size(mesg, buffer - mesg->_buffer);
    }
}

void
message_make_query(message_data *mesg, u16 id, const u8 *qname, u16 qtype, u16 qclass)
{
#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->_buffer[0], 0x0000000000010000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#else
    SET_U64_AT(mesg->_buffer[0], 0x0000010000000000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#endif
    message_set_id(mesg, id);

    dnsname_canonize(qname, mesg->_canonised_fqdn);

    ya_result qname_len      = dnsname_len(qname);
    u8 *tc                   = message_get_query_section_ptr(mesg);
    memcpy(tc, qname, qname_len);
    tc                      += qname_len;
    SET_U16_AT(tc[0], qtype);
    tc                      += 2;
    SET_U16_AT(tc[0], qclass);
    tc                      += 2;
#if DNSCORE_HAS_TSIG_SUPPORT
    mesg->_tsig.tsig         = NULL;
#endif

    mesg->_ar_start = tc;
    message_reset_buffer_size(mesg);
    message_set_size(mesg, tc - message_get_buffer_const(mesg));
    message_set_status(mesg, FP_MESG_OK);
    mesg->_rcode_ext        = 0;
}

void
message_make_query_ex(message_data *mesg, u16 id, const u8 *qname, u16 qtype, u16 qclass, u16 flags)
{
#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->_buffer[0], 0x0000000000010000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#else
    SET_U64_AT(mesg->_buffer[0], 0x0000010000000000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#endif
    message_set_id(mesg, id);

    dnsname_canonize(qname, mesg->_canonised_fqdn);

    ya_result qname_len      = dnsname_len(qname);
    u8 *tc                   = message_get_query_section_ptr(mesg);
    memcpy(tc, qname, qname_len);
    tc += qname_len;
    SET_U16_AT(tc[0], qtype);
    tc += 2;
    SET_U16_AT(tc[0], qclass);
    tc += 2;
    
    mesg->_ar_start = tc;
    message_set_size(mesg, tc - message_get_buffer_const(mesg));
    mesg->_rcode_ext = 0;
    
    message_set_status(mesg, FP_MESG_OK);
#if DNSCORE_HAS_TSIG_SUPPORT
    message_tsig_clear_key(mesg);
#endif
    
    if(flags != 0)
    {
        message_set_additional_count_ne(mesg, NETWORK_ONE_16);
        
        mesg->_rcode_ext |= MESSAGE_EDNS0_DNSSEC;
        
        u8 *buffer = message_get_buffer_limit(mesg);
        buffer[ 0] = 0;
        buffer[ 1] = 0;                     // TYPE
        buffer[ 2] = 0x29;                  //
        buffer[ 3] = edns0_maxsize >> 8;    // CLASS = SIZE
        buffer[ 4] = edns0_maxsize;         //
        buffer[ 5] = message_get_status(mesg) >> 4;   // extended RCODE & FLAGS
        buffer[ 6] = mesg->_rcode_ext >> 16;
        buffer[ 7] = mesg->_rcode_ext >> 8;
        buffer[ 8] = mesg->_rcode_ext;
        buffer[ 9] = 0;                     // RDATA descriptor
        buffer[10] = 0;
        
        message_increase_size(mesg, 11);
    }
}

void message_make_message(message_data *mesg, u16 id, const u8 *qname, u16 qtype, u16 qclass, packet_writer *uninitialised_packet_writer)
{
    assert(uninitialised_packet_writer != NULL);
    assert(packet_writer_get_offset(uninitialised_packet_writer) <= message_get_buffer_size_max(mesg));
    
#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->_buffer[0], 0x0000000000010000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#else
    SET_U64_AT(mesg->_buffer[0], 0x0000010000000000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#endif
    message_set_id(mesg, id);

    dnsname_canonize(qname, mesg->_canonised_fqdn);
    
    packet_writer_create(uninitialised_packet_writer, message_get_buffer(mesg), DNSPACKET_MAX_LENGTH);

    packet_writer_add_fqdn(uninitialised_packet_writer, qname);
    packet_writer_add_u16(uninitialised_packet_writer, qtype);
    packet_writer_add_u16(uninitialised_packet_writer, qclass);
#if DNSCORE_HAS_TSIG_SUPPORT
    message_tsig_clear_key(mesg);
#endif
       
    message_set_size(mesg, packet_writer_get_offset(uninitialised_packet_writer));
    mesg->_ar_start = message_get_buffer_limit(mesg);
    
    message_reset_buffer_size(mesg);

    message_set_status(mesg, FP_MESG_OK);
}

void
message_make_notify(message_data *mesg, u16 id, const u8 *qname, u16 qtype, u16 qclass)
{
#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->_buffer[0], 0x0000240000010000LL); // notify + AA
    SET_U32_AT(mesg->_buffer[8], 0);
#else
    SET_U64_AT(mesg->_buffer[0], 0x0000010000240000LL); // notify + AA
    SET_U32_AT(mesg->_buffer[8], 0);
#endif
    message_set_id(mesg, id);

    dnsname_canonize(qname, mesg->_canonised_fqdn);

    ya_result qname_len = dnsname_len(qname);
    u8 *tc = message_get_query_section_ptr(mesg);
    memcpy(tc, qname, qname_len);
    tc += qname_len;
    SET_U16_AT(tc[0], qtype);
    tc += 2;
    SET_U16_AT(tc[0], qclass);
    tc += 2;
#if DNSCORE_HAS_TSIG_SUPPORT
    message_tsig_clear_key(mesg);
#endif
    
    message_set_size(mesg, tc - message_get_buffer_const(mesg));
    mesg->_ar_start = tc;
    message_set_status(mesg, FP_MESG_OK);
}

void
message_make_ixfr_query(message_data *mesg, u16 id, const u8 *qname, u32 soa_ttl, u16 soa_rdata_size, const u8 *soa_rdata)
{
    packet_writer pw;
    
#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->_buffer[0], 0x0000000000010000LL);
    SET_U32_AT(mesg->_buffer[8], 0x00010000);
#else
    SET_U64_AT(mesg->_buffer[0], 0x0000010000000000LL);
    SET_U32_AT(mesg->_buffer[8], 0x00000100);
#endif
    
    message_set_id(mesg, id);

    dnsname_canonize(qname, mesg->_canonised_fqdn);

    packet_writer_create(&pw, message_get_buffer(mesg), message_get_buffer_size_max(mesg));

    packet_writer_add_fqdn(&pw, qname);
    packet_writer_add_u16(&pw, TYPE_IXFR);
    packet_writer_add_u16(&pw, CLASS_IN);

    packet_writer_add_fqdn(&pw, qname);
    packet_writer_add_u16(&pw, TYPE_SOA);
    packet_writer_add_u16(&pw, CLASS_IN);
    packet_writer_add_u32(&pw, htonl(soa_ttl));
    packet_writer_add_rdata(&pw, TYPE_SOA, soa_rdata, soa_rdata_size);
    
#if DNSCORE_HAS_TSIG_SUPPORT
    message_tsig_clear_key(mesg);
#endif
    mesg->_ar_start = &mesg->_buffer[packet_writer_get_offset(&pw)];
    message_reset_buffer_size(mesg);
    message_set_size(mesg, packet_writer_get_offset(&pw));
    message_set_status(mesg, FP_MESG_OK);
}

#if DNSCORE_HAS_TSIG_SUPPORT

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
        ZEROMEMORY(&mesg->_tsig, sizeof(message_tsig));

        mesg->_tsig.tsig = key;
        mesg->_tsig.mac_size = mesg->_tsig.tsig->mac_size;

        u64 now = time(NULL);
        mesg->_tsig.timehi = htons((u16)(now >> 32));
        mesg->_tsig.timelo = htonl((u32)now);

        mesg->_tsig.fudge  = htons(300);    /* 5m */

        mesg->_tsig.mac_algorithm = key->mac_algorithm;

        mesg->_tsig.original_id = message_get_id(mesg);
        
        return tsig_sign_answer(mesg);
    }

    return TSIG_BADKEY;
}

ya_result
message_sign_query(message_data *mesg, const tsig_item *key)
{
    if(key != NULL)
    {
        ZEROMEMORY(&mesg->_tsig, sizeof(message_tsig));

        mesg->_tsig.tsig = key;
        mesg->_tsig.mac_size = mesg->_tsig.tsig->mac_size;

        u64 now = time(NULL);
        mesg->_tsig.timehi = htons((u16)(now >> 32));
        mesg->_tsig.timelo = htonl((u32)now);

        mesg->_tsig.fudge  = htons(300);    /* 5m */

        mesg->_tsig.mac_algorithm = key->mac_algorithm;

        mesg->_tsig.original_id = message_get_id(mesg);
        
        // mesg->tsig.error = 0;     zeromem
        // mesg->tsig.other_len = 0; zeromem

        return tsig_sign_query(mesg);
    }

    return TSIG_BADKEY;
}

#endif

void
message_make_error(message_data *mesg, u16 error_code)
{
    MESSAGE_FLAGS_OR(mesg->_buffer, QR_BITS, error_code);
#ifdef WORDS_BIGENDIAN
    SET_U32_AT(mesg->_buffer[4], 0x00010000);
    SET_U32_AT(mesg->_buffer[8], 0x00000000);
#else
    SET_U32_AT(mesg->_buffer[4], 0x00000100);
    SET_U32_AT(mesg->_buffer[8], 0x00000000);
#endif

    message_reset_buffer_size(mesg);
    // + 4 is for TYPE + CLASS 
    message_set_size(mesg, DNS_HEADER_LENGTH + 4 + dnsname_len(message_get_query_section_ptr(mesg)));
    mesg->_ar_start = message_get_buffer_limit(mesg);
    message_set_status(mesg, (finger_print)error_code);
}

void
message_make_signed_error(message_data *mesg, u16 error_code)
{
    message_make_error(mesg, error_code);
    
    if(message_has_tsig(mesg))
    {
        tsig_sign_answer(mesg);
    }
}

ya_result
message_make_error_and_reply_tcp(message_data *mesg, u16 error_code, int tcpfd)
{
    ya_result ret;

    message_make_signed_error(mesg, error_code);

    if(ISOK(ret = message_send_tcp(mesg, tcpfd)))
    {
        //
    }
    else
    {
        tcp_set_abortive_close(tcpfd);
    }

    return ret;
}

ssize_t
message_make_error_and_reply_tcp_with_default_minimum_throughput(message_data *mesg, u16 error_code, int tcpfd)
{
    ssize_t ret;
    message_make_signed_error(mesg, error_code);
    
    ret = message_update_length_send_tcp_with_default_minimum_throughput(mesg, tcpfd);
    
    return ret;
}

/**
 * Creates an answer with an OPT error code
 */

void
message_make_error_ext(message_data *mesg, u32 error_code)
{
    MESSAGE_FLAGS_OR(mesg->_buffer, QR_BITS, error_code & 0x0f);
#ifdef WORDS_BIGENDIAN
    SET_U32_AT(mesg->_buffer[4], 0x00010000);
    SET_U32_AT(mesg->_buffer[8], 0x00000000);
#else
    SET_U32_AT(mesg->_buffer[4], 0x00000100);
    SET_U32_AT(mesg->_buffer[8], 0x00000000);
#endif

    message_reset_buffer_size(mesg);
    // + 4 is for TYPE + CLASS 
    size_t query_section_size = DNS_HEADER_LENGTH + 4 + dnsname_len(message_get_query_section_ptr(mesg));
    mesg->_ar_start = &mesg->_buffer[query_section_size];
    
    // the upper 8 bits of the error code are to be put in OPT

    u8 *edns0 = mesg->_ar_start;
    edns0[0] = 0;                
    SET_U16_AT(edns0[1], TYPE_OPT);
    SET_U16_AT(edns0[3], htons(message_edns0_getmaxsize()));
    SET_U32_AT(edns0[5], (((error_code & 0xff0) << 24) | (message_get_rcode_ext(mesg) & 0x00ffffff)));
    SET_U16_AT(edns0[9], 0);
    message_set_size(mesg, query_section_size + 11);    
    message_set_status(mesg, (finger_print)error_code);
}

ya_result
message_query_tcp(message_data *mesg, const host_address *server)
{
    /* connect the server */
    
    ya_result return_value;
    
    if(ISOK(return_value = message_set_sender_from_host_address(mesg, server)))
    {
        int sockfd;
        
        if((sockfd = socket(message_get_sender_sa(mesg)->sa_family, SOCK_STREAM, 0)) >=0)
        {
            fd_setcloseonexec(sockfd);

            socklen_t sa_len = return_value;
            
            if(connect(sockfd, message_get_sender_sa(mesg), sa_len) == 0)
            {
#if DEBUG
                log_debug("sending %d+2 bytes to %{sockaddr} (tcp)", message_get_size(mesg), message_get_sender(mesg));
                log_memdump_ex(g_system_logger, MSG_DEBUG5, message_get_buffer_const(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_HEXTEXT);
#endif
                if(message_send_tcp(mesg, sockfd) == (ssize_t)message_get_size(mesg) + 2)
                {
                    u16 tcp_len;

                    shutdown(sockfd, SHUT_WR);
                    
                    if(readfully(sockfd, &tcp_len, 2) == 2)
                    {
                        tcp_len = ntohs(tcp_len);
                        
                        if(readfully(sockfd, message_get_buffer(mesg), tcp_len) == tcp_len)
                        {
                            /*
                             * test the answser
                             * test the TSIG if any
                             */
                            
                            message_set_size(mesg, tcp_len);
#if DEBUG
                            log_debug("received %d bytes from %{sockaddr} (tcp)", message_get_size(mesg), message_get_sender(mesg));
                            log_memdump_ex(g_system_logger, MSG_DEBUG5, message_get_buffer_const(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_HEXTEXT);
#endif
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

            shutdown(sockfd, SHUT_RDWR);

            tcp_set_abortive_close(sockfd);

            close_ex(sockfd);
        }
        else
        {
            return_value = ERRNO_ERROR;
        }
    }
    
    return return_value;
}

ya_result
message_query_tcp_ex(message_data *mesg, const host_address *bindto, const host_address *server, message_data *answer)
{
    /* connect the server */
    
    ya_result ret;
    socklen_t sa_len;
    socketaddress sa;

    if((mesg == NULL) || (server == NULL) || (answer == NULL))
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    if(bindto != NULL)
    {
        ret = host_address2sockaddr(bindto, &sa);
        if(FAIL(ret))
        {
            return ret;
        }

        sa_len = (socklen_t)ret;
    }
    
    if(ISOK(ret = message_set_sender_from_host_address(mesg, server)))
    {
        int sockfd;
        
        if((sockfd = socket(message_get_sender_sa(mesg)->sa_family, SOCK_STREAM, 0)) >=0)
        {
            fd_setcloseonexec(sockfd);

            if(bindto != NULL)
            {
                int on = 1;
                if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on))))
                {
                    ret = ERRNO_ERROR;
                    close(sockfd);
                    return ret;
                }

                if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *) &on, sizeof(on))))
                {
                    ret = ERRNO_ERROR;
                    close(sockfd);
                    return ret;
                }

                if(bind(sockfd, &sa.sa, sa_len) < 0)
                {
                    ret = ERRNO_ERROR;
                    close_ex(sockfd);
                    return ret;
                }
            }

            if(connect(sockfd, message_get_sender_sa(mesg), message_get_sender_size(mesg)) == 0)
            {
#if DEBUG
                log_debug("sending %d bytes to %{sockaddr} (tcp)", message_get_size(mesg), message_get_sender(mesg));
                log_memdump_ex(g_system_logger, MSG_DEBUG5, message_get_buffer_const(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_HEXTEXT);
#endif
                if(message_send_tcp(mesg, sockfd) == (ssize_t)message_get_size(mesg) + 2)
                {                    
                    u16 tcp_len;

                    shutdown(sockfd, SHUT_WR);
                    
                    if(readfully(sockfd, &tcp_len, 2) == 2)
                    {
                        tcp_len = ntohs(tcp_len);
                        
                        if(readfully(sockfd, message_get_buffer(answer), tcp_len) == tcp_len)
                        {
                            /*
                             * test the answser
                             * test the TSIG if any
                             */
                            
                            message_set_size(answer, tcp_len);
#if DNSCORE_HAS_TSIG_SUPPORT
                            message_tsig_copy_from(answer, mesg);
#endif
                            message_copy_sender_from(answer, mesg);
#if DEBUG
                            log_debug("received %d bytes from %{sockaddr} (tcp)", message_get_size(answer), message_get_sender_sa(answer));
                            log_memdump_ex(g_system_logger, MSG_DEBUG5, message_get_buffer_const(answer), message_get_size(answer), 16, OSPRINT_DUMP_HEXTEXT);
#endif
                            ret = message_process_lenient(answer);
                        }
                    }                    
                }
            }
            else
            {
                // Linux quirk ...
                
                if(errno != EINPROGRESS)
                {
                    ret = ERRNO_ERROR;
                }
                else
                {
                    ret = MAKE_ERRNO_ERROR(ETIMEDOUT);
                }
            }

            shutdown(sockfd, SHUT_RDWR);

            tcp_set_abortive_close(sockfd);

            close_ex(sockfd);
        }
        else
        {
            ret = ERRNO_ERROR;
        }
    }
    
    return ret;
}

ya_result
message_query_tcp_with_timeout(message_data *mesg, const host_address *address, u8 to_sec)
{
    ya_result ret;

    if((mesg == NULL) || (address == NULL))
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    input_stream is;
    output_stream os;

    if(ISOK(ret = tcp_input_output_stream_connect_host_address(address, &is, &os, to_sec)))
    {
        int sockfd = fd_input_stream_get_filedescriptor(&is);

        tcp_set_sendtimeout(sockfd, to_sec, 0);
        tcp_set_recvtimeout(sockfd, to_sec, 0);

        if(ISOK(ret = message_write_tcp(mesg, &os)))
        {
            output_stream_flush(&os);

            shutdown(sockfd, SHUT_WR);

            u16 id = message_get_id(mesg);
#if DEBUG
            message_debug_trash_buffer(mesg);
#endif
            u16 len;
#if DEBUG
            len = ~0;
#endif
            if(ISOK(ret = input_stream_read_nu16(&is, &len)))
            {
                if (ISOK(ret =  input_stream_read_fully(&is, message_get_buffer(mesg), len)))
                {
                    message_set_size(mesg, ret);
                    
                    if(message_get_id(mesg) != id)
                    {
                        ret = MESSAGE_HAS_WRONG_ID;
                    }
                    else if(!message_isanswer(mesg))
                    {
                        ret = MESSAGE_IS_NOT_AN_ANSWER;
                    }
                    else if(message_get_rcode(mesg) != RCODE_NOERROR)
                    {
                        ret = MAKE_DNSMSG_ERROR(message_get_rcode(mesg));
                    }
                }
                else
                {
                    message_set_size(mesg, 0);
                }
            }
        }

        shutdown(sockfd, SHUT_RDWR);

        tcp_set_abortive_close(sockfd);

        output_stream_close(&os);
        output_stream_close(&is);
    }

    return ret;
}

ya_result
message_query_tcp_with_timeout_ex(message_data *mesg, const host_address *server, message_data *answer, u8 to_sec)
{
    /* connect the server */

    ya_result return_value;

    if(ISOK(return_value = message_set_sender_from_host_address(mesg, server)))
    {
        int sockfd;

        if((sockfd = socket(message_get_sender_sa(mesg)->sa_family, SOCK_STREAM, 0)) >=0)
        {
            fd_setcloseonexec(sockfd);

            socklen_t sa_len = return_value;

            if(connect(sockfd, message_get_sender_sa(mesg), sa_len) == 0)
            {
#if 1 // DEBUG
                log_debug("sending %d bytes to %{sockaddr} (tcp)", message_get_size(mesg), message_get_sender(mesg));
                log_memdump_ex(g_system_logger, MSG_DEBUG5, message_get_buffer_const(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_HEXTEXT);
#endif
                tcp_set_sendtimeout(sockfd, to_sec, 0);
                tcp_set_recvtimeout(sockfd, to_sec, 0);

                ssize_t n = message_send_tcp(mesg, sockfd);

                if(n == (ssize_t)message_get_size(mesg) + 2)
                {
                    u16 tcp_len;

                    shutdown(sockfd, SHUT_WR);

                    n = readfully(sockfd, &tcp_len, 2);

                    if(n == 2)
                    {
                        tcp_len = ntohs(tcp_len);

                        n = readfully(sockfd, message_get_buffer(answer), tcp_len);

                        if(n == tcp_len)
                        {
                            /*
                             * test the answser
                             * test the TSIG if any
                             */

                            message_set_size(answer, tcp_len);
#if DNSCORE_HAS_TSIG_SUPPORT
                            message_tsig_copy_from(answer, mesg);
#endif
                            message_copy_sender_from(answer, mesg);
#if DEBUG
                            log_debug("received %d bytes from %{sockaddr} (tcp)", message_get_size(answer), message_get_sender_sa(answer));
                            log_memdump_ex(g_system_logger, MSG_DEBUG5, message_get_buffer_const(answer), message_get_size(answer), 16, OSPRINT_DUMP_HEXTEXT);
#endif
                            return_value = message_process_lenient(answer);
                        }
                        else
                        {
                            return_value = UNEXPECTED_EOF;
                        }
                    }
                    else
                    {
                        return_value = UNEXPECTED_EOF;
                    }
                }
                else
                {
                    return_value = UNABLE_TO_COMPLETE_FULL_WRITE;
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

            shutdown(sockfd, SHUT_RDWR);

            tcp_set_abortive_close(sockfd);

            close_ex(sockfd);
        }
        else
        {
            return_value = ERRNO_ERROR;
        }
    }

    return return_value;
}

ya_result
message_query_udp(message_data *mesg, const host_address *server)
{
    ya_result                                         return_code = SUCCESS;

    int                                                   seconds = 0;
    int                                                  useconds = 500000;
    
    yassert(mesg != NULL);
    yassert(server != NULL);

    return_code = message_query_udp_with_timeout(mesg, server, seconds, useconds);

    return return_code;
}

ya_result
message_query_udp_with_timeout_and_retries(message_data *mesg, const host_address *server, int seconds, int useconds, u8 retries, u8 flags)
{
    ya_result return_value = SUCCESS;
    random_ctx rndctx = thread_pool_get_random_ctx();
    u16 id;

    for(u8 countdown = retries; countdown > 0; )
    {
        if (flags & MESSAGE_QUERY_UDP_FLAG_RESET_ID)
        {
            id = (u16)random_next(rndctx);
            message_set_id(mesg, id);
        }
        else
        {
            id = message_get_id(mesg);
        }
        
        if(ISOK(return_value = message_query_udp_with_timeout(mesg, server, seconds, useconds)))
        {
            if(message_get_id(mesg) != id)
            {
                return_value = MESSAGE_HAS_WRONG_ID;
            }
            else if(!message_isanswer(mesg))
            {
                return_value = MESSAGE_IS_NOT_AN_ANSWER;
            }
            else if(message_get_rcode(mesg) != RCODE_NOERROR)
            {
                return_value = MAKE_DNSMSG_ERROR(message_get_rcode(mesg));
            }

            break;
        }
        
        if(return_value == MAKE_ERRNO_ERROR(EINTR))
        {
            continue;
        }

        if(return_value != MAKE_ERRNO_ERROR(EAGAIN) || countdown <= 0)
        {
            /*
             * Do not retry for any other kind of error
             */

            break;
        }
        
        countdown--;

        usleep_ex(10000);  /* 10 ms */
        
        /*
        if (flags & CHANGE_NAME_SERVER)
        {
        }
        */
    }

    return return_value;
}

ya_result
message_query_udp_with_timeout(message_data *mesg, const host_address *server, int seconds, int useconds)
{
    yassert(mesg != NULL);
    yassert(server != NULL);
    
    /* connect the server */
    
    ya_result ret;
    
    u16 id;
    bool has_fqdn = FALSE;
    u8 fqdn[MAX_DOMAIN_LENGTH + 1];

    if(ISOK(ret = message_set_sender_from_host_address(mesg, server)))
    {
        int sockfd;
        
        if((sockfd = socket(message_get_sender_sa(mesg)->sa_family, SOCK_DGRAM, 0)) >=0)
        {
            fd_setcloseonexec(sockfd);
            
            tcp_set_recvtimeout(sockfd, seconds, useconds); /* half a second for UDP is a lot ... */

            int send_size = message_get_size(mesg);

            ssize_t n;

            if((n = message_send_udp(mesg, sockfd)) == send_size)
            {
                id = message_get_id(mesg);

                if(message_get_query_count_ne(mesg) != 0)
                {
                    has_fqdn = TRUE;
                    dnsname_copy(fqdn, message_get_buffer_const(mesg) + 12);
                }

                message_data_with_buffer recv_mesg_buff;
                message_data *recv_mesg = message_data_with_buffer_init(&recv_mesg_buff);

                //recv_mesg._tsig.hmac = mesg->_tsig.hmac;

                s64 time_limit = seconds;
                time_limit *= ONE_SECOND_US;
                time_limit += useconds;
                time_limit += timeus();

                ret = SUCCESS;

                while((n = message_recv_udp(recv_mesg, sockfd)) >= 0)
                {
#if DEBUG
                    log_memdump_ex(g_system_logger, MSG_DEBUG5, message_get_buffer_const(recv_mesg), n, 16, OSPRINT_DUMP_HEXTEXT);
#endif
                    // check the id is right

                    if(message_get_id(recv_mesg) == id)
                    {
                        // check that the sender is the one we spoke to

                        if(sockaddr_equals(message_get_sender_sa(mesg), message_get_sender_sa(recv_mesg)))
                        {
                            message_tsig_copy_from(recv_mesg, mesg);

                            if(ISOK(ret  = message_process_lenient(recv_mesg)))
                            {
                                // check the domain is right

                                if(!has_fqdn || dnsname_equals(fqdn, message_get_canonised_fqdn(recv_mesg)))
                                {
                                    // everything checks up

                                    message_copy_sender_from(mesg, recv_mesg);
                                    mesg->_ar_start = &mesg->_buffer[recv_mesg->_ar_start - recv_mesg->_buffer];
                                    mesg->_iovec.iov_len = recv_mesg->_iovec.iov_len;
                                    mesg->_rcode_ext = recv_mesg->_rcode_ext;
                                    mesg->_status = recv_mesg->_status;

                                    if(mesg->_buffer_size < mesg->_iovec.iov_len)
                                    {
                                        mesg->_buffer_size = mesg->_iovec.iov_len;
                                    }

                                    mesg->_query_type = recv_mesg->_query_type;
                                    mesg->_query_class = recv_mesg->_query_class;
                                    mesg->_edns = recv_mesg->_edns;
                                    mesg->_nsid = recv_mesg->_nsid;

                                    if((mesg->_control_buffer_size = recv_mesg->_control_buffer_size) > 0)
                                    {
                                        memcpy(mesg->_msghdr_control_buffer, recv_mesg->_msghdr_control_buffer, recv_mesg->_control_buffer_size);
                                    }

                                    dnsname_copy(mesg->_canonised_fqdn, recv_mesg->_canonised_fqdn);

                                    memcpy(mesg->_buffer, recv_mesg->_buffer, recv_mesg->_iovec.iov_len);

                                    break;
                                }
                                else
                                {
                                    ret = MESSAGE_UNEXPECTED_ANSWER_DOMAIN;
                                }
                            }

                            // ret is set to an error
                        }
                        else
                        {
                            ret = INVALID_MESSAGE;
                        }
                    }
                    else
                    {
                        ret = MESSAGE_HAS_WRONG_ID;
                    }

                    s64 time_now = timeus();

                    if(time_now >= time_limit)
                    {
                        ret = MAKE_ERRNO_ERROR(EAGAIN);
                        break;
                    }

                    s64 time_remaining = time_limit - time_now;

                    tcp_set_recvtimeout(sockfd, time_remaining / 1000000ULL, time_remaining % 1000000ULL); /* half a second for UDP is a lot ... */
                }

                message_finalize(recv_mesg);

                //recv_mesg._tsig.hmac = NULL;

                if((n < 0) && ISOK(ret))
                {
                    ret = ERRNO_ERROR;
                }

                /* timeout */
            }
            else
            {
                ret = (n < 0)?n:ERROR;
            }
            
            close_ex(sockfd);
        }
        else
        {
            ret = ERRNO_ERROR;
        }
    }
   
    return ret;
}

ya_result
message_query(message_data *mesg, const host_address *server)
{
    ya_result ret;
    size_t size;
    u8 header_copy[12];
    
    // keep a copy of the state, in case there is truncation
    
    size = message_get_size(mesg);
    memcpy(header_copy, mesg->_buffer, sizeof(header_copy));
    
    if(ISOK(ret = message_query_udp_with_timeout_and_retries(mesg, server, 1, 0, 3, 0)))
    {
        if(message_istruncated(mesg))
        {
            message_set_size(mesg, size);
            memcpy(mesg->_buffer, header_copy, sizeof(header_copy));
            
            ret = message_query_tcp_with_timeout(mesg, server, 3);
        }
    }

    return ret;
}

ya_result
message_ixfr_query_get_serial(const message_data *mesg, u32 *serial)
{
    packet_unpack_reader_data purd;
    ya_result return_value;
    
    u8 domain_fqdn[MAX_DOMAIN_LENGTH];
    u8 soa_fqdn[MAX_DOMAIN_LENGTH];
    
    packet_reader_init_from_message(&purd, mesg);

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

ya_result
message_query_serial(const u8 *origin, const host_address *server, u32 *serial_out)
{
    yassert(origin != NULL);
    yassert(server != NULL);
    yassert(serial_out != NULL);
    
    /* do an SOA query */
    
    ya_result ret;
    
    random_ctx rndctx = thread_pool_get_random_ctx();
    message_data_with_buffer soa_query_mesg_buff;
    message_data *soa_query_mesg = message_data_with_buffer_init(&soa_query_mesg_buff);

    for(u16 countdown = 5; countdown > 0; )
    {
        u16 id = (u16)random_next(rndctx);

        message_make_query(soa_query_mesg, id, origin, TYPE_SOA, CLASS_IN);

        if(ISOK(ret = message_query_udp(soa_query_mesg, server)))
        {
            const u8 *buffer = message_get_buffer_const(soa_query_mesg);
            
            if(MESSAGE_QR(buffer))
            {
                if(MESSAGE_ID(buffer) == id)
                {
                    if(MESSAGE_RCODE(buffer) == RCODE_NOERROR)
                    {
                        if((MESSAGE_QD(buffer) == NETWORK_ONE_16) && ((MESSAGE_AN(buffer) == NETWORK_ONE_16) || (MESSAGE_NS(buffer) == NETWORK_ONE_16)))
                        {
                            packet_unpack_reader_data pr;
                            packet_reader_init_from_message_at(&pr, soa_query_mesg, DNS_HEADER_LENGTH); // scan-build false positive: if message_query_udp returns no-error, then soa_query_mesg.received is set
                            packet_reader_skip_fqdn(&pr);
                            packet_reader_skip(&pr, 4);

                            u8 tmp[MAX_DOMAIN_LENGTH];

                            /* read and expect an SOA */

                            packet_reader_read_fqdn(&pr, tmp, sizeof(tmp));

                            if(dnsname_equals(tmp, origin))
                            {
                                struct type_class_ttl_rdlen tctr;

                                if(packet_reader_read(&pr, &tctr, 10) == 10) // exact
                                {
                                    if((tctr.qtype == TYPE_SOA) && (tctr.qclass == CLASS_IN))
                                    {
                                        if(ISOK(ret = packet_reader_skip_fqdn(&pr)))
                                        {
                                            if(ISOK(ret = packet_reader_skip_fqdn(&pr)))
                                            {
                                                if(packet_reader_read(&pr, tmp, 4) == 4) // exact
                                                {
                                                    *serial_out = ntohl(GET_U32_AT(tmp[0]));

                                                    return SUCCESS;
                                                }
                                            }
                                        }
                                    }
                                    else
                                    {
                                        ret = MESSAGE_UNEXPECTED_ANSWER_TYPE_CLASS;
                                    }
                                }
                                else
                                {
                                    ret = RCODE_FORMERR;
                                }
                            }
                            else
                            {
                                ret = MESSAGE_UNEXPECTED_ANSWER_DOMAIN;
                            }
                        }
                        else
                        {
                            ret = INVALID_MESSAGE;
                        }
                    }
                    else
                    {
                        ret = MAKE_DNSMSG_ERROR(message_get_rcode(soa_query_mesg));
                    }
                }
                else
                {
                    ret = MESSAGE_HAS_WRONG_ID;
                }
            }
            else
            {
                ret = MESSAGE_IS_NOT_AN_ANSWER;
            }
            
            break;
        }
        
        if(ret == MAKE_ERRNO_ERROR(EINTR))
        {
            continue;
        }

        if(ret != MAKE_ERRNO_ERROR(EAGAIN) || countdown <= 0)
        {
            /*
             * Do not retry for any other kind of error
             */

            break;
        }
        
        countdown--;

        usleep_ex(10000);  /* 10 ms */
    }

    return ret; // fake positive, ret has been initialised
}

#if MESSAGE_PAYLOAD_IS_POINTER

void message_init_ex(message_data* mesg, u32 mesg_size, void *buffer, size_t buffer_size)
{
    ZEROMEMORY(mesg, offsetof(message_data, _msghdr_control_buffer));
    mesg->_msghdr.msg_name = &mesg->_sender;
    mesg->_msghdr.msg_namelen = sizeof(mesg->_sender);
    mesg->_msghdr.msg_iov = &mesg->_iovec;
    mesg->_msghdr.msg_iovlen = 1;
#ifndef WIN32
    mesg->_msghdr.msg_control = NULL;
    mesg->_msghdr.msg_controllen = 0;
#else
    mesg->_msghdr.msg_control.buf = NULL;
    mesg->_msghdr.msg_control.len = 0;
#endif
    mesg->_msghdr.msg_flags = 0;
    //mesg->_msghdr.msg_control = mesg->_msghdr_control_buffer;
    //mesg->_msghdr.msg_controllen = sizeof(mesg->_msghdr_control_buffer);
#if MESSAGE_PAYLOAD_IS_POINTER
    //
#else
    mesg->_iovec.iov_base = mesg->_buffer;
#endif
    mesg->_iovec.iov_len = buffer_size;

#if MESSAGE_PAYLOAD_IS_POINTER
    mesg->_message_data_size = mesg_size;
#endif

    mesg->_control_buffer_size = sizeof(mesg->_msghdr_control_buffer);
    mesg->_buffer_size = buffer_size;
    mesg->_buffer_size_limit = buffer_size;
    mesg->_tsig.hmac = NULL;

#if MESSAGE_PAYLOAD_IS_POINTER
    mesg->_buffer = (u8*)buffer;

    mesg->_iovec.iov_base = mesg->_buffer;
#if DEBUG
    memset(buffer,0x5a, buffer_size);
#endif
#else
#if DEBUG
    memset(&mesg->_buffer,0x5a, mesg->_buffer_size_limit);
#endif
#endif
}

#else // MESSAGE_PAYLOAD_IS_POINTER

void message_init(message_data* mesg)
{
    ZEROMEMORY(mesg, offsetof(message_data, _msghdr_control_buffer));
    mesg->_msghdr.msg_name = &mesg->_sender;
    mesg->_msghdr.msg_namelen = sizeof(mesg->_sender);
    mesg->_msghdr.msg_iov = &mesg->_iovec;
    mesg->_msghdr.msg_iovlen = 1;
    mesg->_msghdr.msg_control = NULL;
    mesg->_msghdr.msg_controllen = 0;
    mesg->_msghdr.msg_flags = 0;
    //mesg->_msghdr.msg_control = mesg->_msghdr_control_buffer;
    //mesg->_msghdr.msg_controllen = sizeof(mesg->_msghdr_control_buffer);
    mesg->_iovec.iov_base = mesg->_buffer;
    mesg->_iovec.iov_len = NETWORK_BUFFER_SIZE;
    mesg->_control_buffer_size = sizeof(mesg->_msghdr_control_buffer);
    mesg->_buffer_size = NETWORK_BUFFER_SIZE;
    mesg->_buffer_size_limit = NETWORK_BUFFER_SIZE;
    mesg->_tsig.hmac = NULL;
#if DEBUG
    memset(&mesg->_buffer,0x5a, mesg->_buffer_size_limit);
#endif
}

#endif

/**
 * If pointer is NULL, the structure and buffer will be allocated together
 * Note that in the current implementation, 8 bytes are reserved for TCP
 */

message_data*
message_new_instance_ex(void *ptr, u32 message_size)        // should be size of edns0 or 64K for TCP
{
    message_data *mesg;
    if(ptr == NULL)
    {
        u8 *tmp;
        size_t message_data_size = ((sizeof(message_data) + 7) & ~7) + message_size;
        MALLOC_OBJECT_ARRAY_OR_DIE(tmp, u8, message_data_size, GENERIC_TAG);
        ptr = &tmp[(sizeof(message_data) + 7) & ~7];
        mesg = (message_data*)tmp;
        message_init_ex(mesg, message_data_size, ptr, message_size);
    }
    else
    {
        MALLOC_OBJECT_OR_DIE(mesg, message_data, MESGDATA_TAG); // legit
        message_init_ex(mesg, sizeof(message_data), ptr, message_size);
    }
    return mesg;
}

message_data*
message_new_instance()
{
    message_data *mesg;
    mesg = message_new_instance_ex(NULL, 65536);
    return mesg;
}

void message_finalize(message_data *mesg)
{
    if(mesg->_tsig.hmac != NULL)
    {
        hmac_free(mesg->_tsig.hmac);
        mesg->_tsig.hmac = NULL;
    }
}

void message_free(message_data *mesg)
{
    if(mesg != NULL)
    {
        message_finalize(mesg);
        free(mesg); // legit
    }
}

/*
 * Does not clone the pool.
 */

message_data*
message_dup(const message_data *mesg)
{
    message_data *clone = message_new_instance_ex(NULL, mesg->_buffer_size_limit + 8);
    if(message_get_additional_section_ptr_const(mesg) != NULL)
    {
        message_set_additional_section_ptr(clone,
                &clone->_buffer[
                message_get_additional_section_ptr_const(mesg) - message_get_buffer_const(mesg)
                ]);
    }
    
    memcpy(&clone->_rcode_ext, &mesg->_rcode_ext,
            offsetof(message_data, _msghdr_control_buffer)
            );
    
    message_copy_sender_from(clone, mesg);
#ifndef WIN32
    memcpy(clone->_msghdr_control_buffer, mesg->_msghdr_control_buffer, mesg->_msghdr.msg_controllen);
#else
    memcpy(clone->_msghdr_control_buffer, mesg->_msghdr_control_buffer, mesg->_msghdr.msg_control.len);
#endif
    
    dnsname_copy(clone->_canonised_fqdn, message_get_canonised_fqdn(mesg));
#if !MESSAGE_PAYLOAD_IS_POINTER
    SET_U16_AT(clone->_buffer_tcp_len[0], GET_U16_AT(mesg->_buffer_tcp_len[0]));
#endif
    memcpy(message_get_buffer(clone), message_get_buffer_const(mesg), message_get_size(mesg));
    message_set_size(clone, message_get_size(mesg));
    
    return clone;
}

void message_log(logger_handle *logger, int level, const message_data *mesg)
{
    ya_result ret;
    int index = 0;
    rdata_desc rrdesc = {0, 0, NULL};
    struct type_class_ttl_rdlen *tctrp;
    u8 rr[32768];
            
    logger_handle_msg(logger,level, "to: %{sockaddr}", message_get_sender_sa(mesg));
    logger_handle_msg(logger,level, "id: %i ", message_get_id(mesg));
    logger_handle_msg(logger,level, "flags: %02x %02x opcode: %s rcode: %s", message_get_flags_hi(mesg), message_get_flags_lo(mesg), dns_message_opcode_get_name(message_get_opcode(mesg) >> OPCODE_SHIFT), dns_message_rcode_get_name(message_get_rcode(mesg)));
    logger_handle_msg(logger,level, "qr: %i, an: %i, ns: %i, ar: %i",
            message_get_query_count(mesg), message_get_answer_count(mesg),
            message_get_authority_count(mesg), message_get_additional_count(mesg));
    packet_unpack_reader_data  pr;
    packet_reader_init_from_message(&pr, mesg);

    /* fqdn + type + class */
    for(u16 qc = message_get_query_count(mesg); qc > 0; --qc)
    {
        if(FAIL(ret = packet_reader_read_zone_record(&pr, rr, sizeof(rr))))
        {
            logger_handle_msg(logger, MSG_ERR, "failed to read zone record: %r", ret);
            return;
        }

        u16 *type_class = (u16*)&rr[dnsname_len(rr)];

        logger_handle_msg(logger,level, "Q%3i: %{dnsname} %{dnstype} %{dnsclass}", index++, rr, &type_class[0], &type_class[1]);
    }

    if((message_get_opcode(mesg) == OPCODE_QUERY) || (message_get_opcode(mesg) == OPCODE_NOTIFY))
    {
        for(int section = 1; section <= 3; ++section)
        {
            index = 0;

            for(u16 sc = message_get_section_count(mesg, section); sc > 0; --sc)
            {
                if(FAIL(ret = packet_reader_read_record(&pr, rr, sizeof(rr))))
                {
                    logger_handle_msg(logger, MSG_ERR, "failed to read zone record: %r", ret);
                    return;
                }

                tctrp = (struct type_class_ttl_rdlen *)&rr[dnsname_len(rr)];
                rrdesc.type = tctrp->qtype;
                rrdesc.len = ntohs(tctrp->rdlen);
                rrdesc.rdata = &((u8*)tctrp)[10];

                logger_handle_msg(logger, level, "%c%3i: %{dnsname} %i %{typerdatadesc}", "QANa"[section], index++, rr, ntohl(tctrp->ttl), &rrdesc);
            }
        }
    }
    else if(message_get_opcode(mesg) == OPCODE_UPDATE)
    {
        for(int section = 1; section <= 3; ++section)
        {
            index = 0;

            for(u16 sc = message_get_section_count(mesg, section); sc > 0; --sc)
            {
                u8 *rdata_buffer;
                s32 rttl;
                u16 rtype;
                u16 rclass;
                u16 rdata_buffer_size;
                u16 rdata_size;

                if(FAIL(ret = packet_reader_read_fqdn(&pr, rr, sizeof(rr))))
                {
                    return;
                }

                rdata_buffer = &rr[ret];
                rdata_buffer_size = sizeof(rr) - ret;

                if(FAIL(ret = packet_reader_read_u16(&pr, &rtype)))
                {
                    logger_handle_msg(logger, MSG_ERR, "failed to read zone record: %r", ret);
                    return;
                }

                if(FAIL(ret = packet_reader_read_u16(&pr, &rclass)))
                {
                    logger_handle_msg(logger, MSG_ERR, "failed to read zone record: %r", ret);
                    return;;
                }

                if(FAIL(ret = packet_reader_read_u32(&pr, (u32*)&rttl)))
                {
                    logger_handle_msg(logger, MSG_ERR, "failed to read zone record: %r", ret);
                    return;;
                }

                rttl = ntohl(rttl);

                if(FAIL(ret = packet_reader_read_u16(&pr, &rdata_size)))
                {
                    logger_handle_msg(logger, MSG_ERR, "failed to read zone record: %r", ret);
                    return;;
                }

                rdata_size = ntohs(rdata_size);

                if(rclass != TYPE_ANY)
                {
                    if(FAIL(ret = packet_reader_read_rdata(&pr, rtype, rdata_size, rdata_buffer, rdata_buffer_size))) // fixed buffer
                    {
                        logger_handle_msg(logger, MSG_ERR, "failed to read zone record: %r", ret);
                        return;
                    }

                    rrdesc.type = rtype;
                    rrdesc.len = rdata_size;
                    rrdesc.rdata = rdata_buffer;

                    logger_handle_msg(logger, level, "%c%3i: %{dnsname} %i %{dnsclass} %{typerdatadesc}", "QANa"[section], index++, rr, rttl, &rclass, &rrdesc);
                }
                else
                {
                    logger_handle_msg(logger, level, "%c%3i: %{dnsname} %i %{dnsclass} %{dnstype}", "QANa"[section], index++, rr, rttl, &rclass, &rtype);
                }
            }
        }
    }
}

ya_result
message_get_ixfr_query_serial(message_data *mesg, u32 *serialp)
{
    packet_unpack_reader_data purd;    
    ya_result ret;
    u16 qtype;
    
    packet_reader_init_from_message(&purd, mesg);

    packet_reader_skip_fqdn(&purd);
    
    if(FAIL(ret = packet_reader_read_u16(&purd, &qtype)))
    {
        return ret;
    }
    
    if(qtype != TYPE_IXFR)
    {
        return ERROR; // not an IXFR
    }
    
    packet_reader_skip(&purd, 2);

    message_set_size(mesg, purd.offset);

    /* Get the queried serial */

    if(FAIL(ret = packet_reader_skip_fqdn(&purd)))
    {
        return ret;
    }
    
    if(FAIL(ret = packet_reader_skip(&purd, 10)))
    {
        return ret;
    }
    
    if(FAIL(ret = packet_reader_skip_fqdn(&purd)))
    {
        return ret;
    }
    
    if(FAIL(ret = packet_reader_skip_fqdn(&purd)))
    {
        return ret;
    }
    
    if(serialp != NULL)
    {
        if(FAIL(ret = packet_reader_read_u32(&purd, serialp)))
        {
            return ret;
        }
        
        *serialp = ntohl(*serialp);
    }
    
    return SUCCESS;
}

#if DNSCORE_HAS_TSIG_SUPPORT
ya_result
message_terminate_then_write(message_data *mesg, output_stream *tcpos, tsig_tcp_message_position pos)
#else
ya_result
message_terminate_then_write(message_data *mesg, output_stream *tcpos, int unused)
#endif
{
    ya_result ret;
    
#if !DNSCORE_HAS_TSIG_SUPPORT
#pragma message("TSIG SUPPORT HAS BEEN DISABLED")
    (void)unused;
#endif
    
    if(message_is_edns0(mesg)) // Dig does a TCP query with EDNS0
    {
        /* 00 00 29 SS SS rr vv 80 00 00 00 */

        u8 *buffer = message_get_buffer_limit(mesg);
        buffer[ 0] = 0;
        buffer[ 1] = 0;
        buffer[ 2] = 0x29;        
        buffer[ 3] = edns0_maxsize >> 8;
        buffer[ 4] = edns0_maxsize;
        buffer[ 5] = message_get_status(mesg) >> 4;
        buffer[ 6] = mesg->_rcode_ext >> 16;
        buffer[ 7] = mesg->_rcode_ext >> 8;
        buffer[ 8] = mesg->_rcode_ext;
        buffer[ 9] = 0;
        buffer[10] = 0;
        
        message_increase_size(mesg, 11);
        
        message_set_additional_count_ne(mesg, NU16(1));
    }
    else
    {
        message_set_additional_count_ne(mesg, 0);
    }

#if DNSCORE_HAS_TSIG_SUPPORT
    if(message_has_tsig(mesg))
    {
        if(FAIL(ret = tsig_sign_tcp_message(mesg, pos)))
        {
            return ret;
        }
    }
#endif

    ret = message_write_tcp(mesg, tcpos);

    return ret;
}

/**
 * Maps records in a message to easily access them afterward.
 * 
 * @param map the message map to initialise
 * @param mesg the message to map
 * @param tight do two passes to use the least amount of memory possible
 * 
 * @return an error code
 */

ya_result
message_map_init(message_map *map, const message_data *mesg)
{
    map->mesg = mesg;
    
    packet_unpack_reader_data purd;
    
    packet_reader_init_from_message(&purd, mesg);
    
    ya_result ret;
    
    u16 qc = message_get_query_count(mesg);
    u16 an = message_get_answer_count(mesg);
    u16 ns = message_get_authority_count(mesg);
    u16 ar = message_get_additional_count(mesg);
    
    int total = qc;
    total += an;
    total += ns;
    total += ar;
        
    ptr_vector_init_ex(&map->records, total);
    
    int i;
    
    for(i = 0; i < qc; ++i)
    {
        ptr_vector_append(&map->records, (void*)packet_reader_get_next_u8_ptr_const(&purd));
        packet_reader_skip_fqdn(&purd);
        if(FAIL(ret = packet_reader_skip(&purd, 4)))
        {
            message_map_finalize(map);
            return ret;
        }
    }
        
    for(; i < total; ++i)
    {
        ptr_vector_append(&map->records, (void*)packet_reader_get_next_u8_ptr_const(&purd));
        
        if(FAIL(ret = packet_reader_skip_record(&purd)))
        {
            message_map_finalize(map);
            return ret;
        }
    }
    
    ret = ptr_vector_size(&map->records);
    
    map->section_base[0] = 0;
    map->section_base[1] = message_get_section_count(map->mesg, 0) + map->section_base[0];
    map->section_base[2] = message_get_section_count(map->mesg, 1) + map->section_base[1];
    map->section_base[3] = message_get_section_count(map->mesg, 2) + map->section_base[2];
    
    return ret;
}

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

ya_result
message_map_get_fqdn(const message_map *map, int index, u8 *fqdn, int fqdn_size)
{
    if((index >= 0) && (index <= ptr_vector_last_index(&map->records)))
    {
        if(dnsname_expand_compressed(message_get_buffer_const(map->mesg), message_get_size(map->mesg),
                ptr_vector_get(&map->records, index), fqdn, fqdn_size) != NULL)
        {
            return SUCCESS;
        }
    }
    
    return ERROR;
}

/**
 * Gets the type class ttl rdata_size of the record at index
 * 
 * @param map
 * @param index
 * @param tctr
 * 
 * @return an error code
 */


ya_result
message_map_get_tctr(const message_map *map, int index, struct type_class_ttl_rdlen *tctr)
{
    if((index >= 0) && (index <= ptr_vector_last_index(&map->records)))
    {
        const u8 *p;
        if((p = dnsname_skip_compressed(message_get_buffer_const(map->mesg), message_get_size(map->mesg),
                ptr_vector_get(&map->records, index))) != NULL)
        {
            if(index >= map->section_base[1])
            {
                if(message_get_buffer_limit_const(map->mesg) - p >= 10)
                {
                    memcpy(tctr, p, 10);

                    return SUCCESS;
                }
            }
            else
            {
                if(message_get_buffer_limit_const(map->mesg) - p >= 4)
                {
                    memcpy(tctr, p, 4);
                    tctr->ttl = 0;
                    tctr->rdlen = 0;

                    return SUCCESS;
                }
            }
        }
    }
    
    return ERROR;
}

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

ya_result
message_map_get_rdata(const message_map *map, int index, u8 *rdata, int rdata_size)
{
    if((index >= (int)map->section_base[1]) && (index <= ptr_vector_last_index(&map->records)))
    {
        const u8 *p;
        if((p = dnsname_skip_compressed(message_get_buffer_const(map->mesg), message_get_size(map->mesg),
                ptr_vector_get(&map->records, index))) != NULL)
        {
            if(message_get_buffer_limit_const(map->mesg) - p >= 10)
            {
                const u8 *rdata_base = rdata;
                size_t d;
                
                u16 rtype = GET_U16_AT_P(p);
                p += 8;
                u16 n = ntohs(GET_U16_AT_P(p));
                p += 2;
                
                if(message_get_buffer_limit_const(map->mesg) - p >= n)
                {   
                    switch(rtype)
                    {
                        /******************************************************************************
                         * The types that requires special handling (dname compression)
                         ******************************************************************************/

                        case TYPE_MX:
                        case TYPE_AFSDB:
                        {
                            if(rdata_size < 3) // minimal expected size
                            {
                                return INVALID_RECORD;
                            }

                            SET_U16_AT_P(rdata, GET_U16_AT_P(p));
                            rdata += 2;
                            rdata_size -= 2;
                            p += 2;
                        }

                        FALLTHROUGH // fall through

                        case TYPE_NS:
                        case TYPE_CNAME:
                        case TYPE_DNAME:
                        case TYPE_PTR:
                        case TYPE_MB:
                        case TYPE_MD:
                        case TYPE_MF:
                        case TYPE_MG:
                        case TYPE_MR:
                        {
                            if((p = dnsname_expand_compressed(message_get_buffer_const(map->mesg), message_get_size(map->mesg),
                                p, rdata, rdata_size)) != NULL)
                            {
                                return p - rdata_base;
                            }

                            return INVALID_RECORD;
                        }
                        case TYPE_SOA:
                        {
                            if((p = dnsname_expand_compressed(message_get_buffer_const(map->mesg), message_get_size(map->mesg),
                                p, rdata, rdata_size)) != NULL)
                            {
                                d = dnsname_len(rdata);
                                rdata += d;
                                rdata_size -= d;

                                if((p = dnsname_expand_compressed(message_get_buffer_const(map->mesg), message_get_size(map->mesg),
                                    p, rdata, rdata_size)) != NULL)
                                {
                                    d = dnsname_len(rdata);

                                    rdata += d;
                                    rdata_size -= d;

                                    if(rdata_size >= 20)
                                    {
                                        memcpy(rdata, p, 20);
                                        return &rdata[20] - rdata_base;
                                    }
                                }
                            }

                            return INVALID_RECORD;
                        }
                        case TYPE_RRSIG:    /* not supposed to be compressed */
                        {
                            if(rdata_size > RRSIG_RDATA_HEADER_LEN)
                            {
                                const u8 *p_base = p;
                                memcpy(rdata, p, RRSIG_RDATA_HEADER_LEN);
                                rdata += RRSIG_RDATA_HEADER_LEN;
                                rdata_size -= RRSIG_RDATA_HEADER_LEN;
                                p += RRSIG_RDATA_HEADER_LEN;

                                if((p = dnsname_expand_compressed(message_get_buffer_const(map->mesg), message_get_size(map->mesg),
                                    p, rdata, rdata_size)) != NULL)
                                {
                                    d = dnsname_len(rdata);
                                    rdata += d;
                                    //rdata_size -= d;
                                    d = p - p_base;
                                    memcpy(rdata, p, d);

                                    return &rdata[d] - rdata_base;
                                }
                            }

                            return INVALID_RECORD;
                        }
                        case TYPE_NSEC: /* not supposed to be compressed */
                        {
                            const u8 *p_base = p;
                            if((p = dnsname_expand_compressed(message_get_buffer_const(map->mesg), message_get_size(map->mesg),
                                p, rdata, rdata_size)) != NULL)
                            {
                                d = dnsname_len(rdata);
                                rdata += d;
                                //rdata_size -= d;
                                d = p - p_base;
                                memcpy(rdata, p, d);

                                return &rdata[d] - rdata_base;
                            }

                            return INVALID_RECORD;
                        }

                        default:
                        {
                            if(rdata_size >= n)
                            {
                                memcpy(rdata, p, n);
                                return n;
                            }

                            return INVALID_RECORD;
                        }
                    } // switch type
                }
            }
        }
    }
        
    return ERROR;
}

/**
 * Gets the type of the record at index
 * 
 * @param map
 * @param index
 * 
 * @return the record type or an error code  
 */

ya_result
message_map_get_type(const message_map *map, int index)
{
    if((index >= 0) && (index <= ptr_vector_last_index(&map->records)))
    {
        const u8 *p;
        if((p = dnsname_skip_compressed(message_get_buffer_const(map->mesg), message_get_size(map->mesg),
                ptr_vector_get(&map->records, index))) != NULL)
        {
            if(message_get_buffer_limit_const(map->mesg) - p >= 2)
            {
                u16 rtype = GET_U16_AT_P(p);
                
                return rtype;
            }
        }
    }
    
    return ERROR;
}

/**
 * 
 * @param map
 * 
 * @return the number of records mapped
 */

int
message_map_record_count(const message_map *map)
{
    int size = ptr_vector_size(&map->records);
    return size;
}

/**
 * Returns the index of the next record with the given type
 * from, and including, a given index.
 *
 * @param map
 * @param index
 * @param type
 * @return 
 */

int
message_map_get_next_record_from(const message_map *map, int index, u16 type)
{
    ya_result ret;
    
    for(;;)
    {
        ret = message_map_get_type(map, index);
        
        if(ret == type)
        {
            return index;
        }
        
        if(FAIL(ret))
        {
            return ret;
        }
        
        ++index;
    }
}

/**
 * Returns the index of the next record with the given type
 * from, and including, a given index in a given section (0 to 3).
 * 
 * @param map
 * @param index
 * @param type
 * @return 
 */

int
message_map_get_next_record_from_section(const message_map *map, int section, int index, u16 type)
{
    if(index < 0)
    {
        return INVALID_ARGUMENT_ERROR;
    }
    
    u16 sc = message_get_section_count(map->mesg, section);
    
    if(index >= sc)
    {
        return INVALID_ARGUMENT_ERROR;
    }
        
    ya_result ret;
    
    do
    {
        ret = message_map_get_type(map, map->section_base[section] + index);
        
        if(ret == type)
        {
            return index;
        }
        
        if(FAIL(ret))
        {
            return ret;
        }
        
        ++index;
    }
    while(index < sc);
    
    return ERROR;
}

/**
 * Releases the memory used by the map
 * 
 * @param map
 */

void
message_map_finalize(message_map *map)
{
    ptr_vector_destroy(&map->records);
}

static int
message_map_reorder_remap_type(int t, int ct)
{
    int r;
    switch(t)
    {
        case TYPE_SOA:        
            r = 0 << 1;
            break;
        case TYPE_NSEC:
            r = 0x7ffe << 1;
            break;
        case TYPE_NSEC3:
            r = 0x7fff << 1;
            break;
        case TYPE_RRSIG:
            r = message_map_reorder_remap_type(ct, 0) + 1;
            break;
        default:
            r = (ntohs(t) + 0x1000) << 1;
            break;
    }
    return r;
}

static int
message_map_reorder_comparator(const void *rra, const void *rrb, void *ctx)
{
    const u8 *pa = (const u8*)rra;
    const u8 *pb = (const u8*)rrb;
    message_map *map = (message_map *)ctx;
    struct type_class_ttl_rdlen tctra;
    struct type_class_ttl_rdlen tctrb;
    u16 ctypea;
    u16 ctypeb;
    u8 fqdna[256];
    u8 fqdnb[256];
    
    if(rra == rrb)
    {
        return 0;
    }
    
    pa = dnsname_expand_compressed(message_get_buffer_const(map->mesg), message_get_size(map->mesg), rra, fqdna, sizeof(fqdna));
    memcpy(&tctra, pa, 10);
    pa += 10;
    if(tctra.qtype == TYPE_RRSIG)
    {
        ctypea = GET_U16_AT_P(pa);
    }
    else
    {
        ctypea = 0;
    }
    
    pa += 10;
    
    pb = dnsname_expand_compressed(message_get_buffer_const(map->mesg), message_get_size(map->mesg), rrb, fqdnb, sizeof(fqdnb));
    memcpy(&tctrb, pb, 10);
    pb += 10;
    if(tctrb.qtype == TYPE_RRSIG)
    {
        ctypeb = GET_U16_AT_P(pb);
    }
    else
    {
        ctypeb = 0;
    }
        
    tctra.rdlen = ntohs(tctra.rdlen);
    tctrb.rdlen = ntohs(tctrb.rdlen);
    int rdata_size_d = tctra.rdlen;
    int rdata_size_min = MIN(tctra.rdlen, tctrb.rdlen);
    rdata_size_d -= tctrb.rdlen;
    int d;
    
    bool n3a = (tctra.qtype == TYPE_NSEC3) || (ctypea == TYPE_NSEC3);
    bool n3b = (tctrb.qtype == TYPE_NSEC3) || (ctypeb == TYPE_NSEC3);
    
    if(n3a)
    {
        if(n3b)
        {
            // both are NSEC3 related: normal sort
        }
        else
        {
            // the NSEC3 one is after the normal one
            return 1;
        }
    }
    else // the first one is not NSEC3 related
    {
        if(n3b)
        {
            // the second one is: it comes after the normal one
            return -1;
        }
        else
        {
            // none are NSEC3 related: normal sort
        }
    }
    
    d = dnsname_compare(fqdna, fqdnb);
    
    if(d == 0)
    {
        // let's avoid lot's of if-then-else

        int ta = message_map_reorder_remap_type(tctra.qtype, ctypea);
        int tb = message_map_reorder_remap_type(tctrb.qtype, ctypeb);

        d = ta - tb;

        if(d == 0)
        {
            d = memcmp(pa, pb, rdata_size_min);

            if(d == 0)
            {
                d = rdata_size_d;
            }
        }
    }
    
    return d;
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

void
message_map_reorder(message_map *map)
{
    // apply message_map_reorder_comparator to sections 1, 2 and 3.
    ptr_vector fakev;
    for(int section = 1; section < 4; ++section)
    {    
        int sc = message_get_section_count(map->mesg, section);
        if(sc > 1)
        {
            fakev.data = &map->records.data[map->section_base[section]];
            fakev.offset = sc - 1;
            fakev.size = fakev.offset + 1;
            ptr_vector_qsort_r(&fakev, message_map_reorder_comparator, map);
        }
    }
}

void
message_map_print(const message_map *map, output_stream *os)
{
    osformat(os, ";; opcode: %s, status: %s, id: %i, flags:",
            dns_message_opcode_get_name(message_get_opcode(map->mesg) >> OPCODE_SHIFT),
            dns_message_rcode_get_name(message_get_rcode(map->mesg)),
            ntohs(message_get_id(map->mesg)));
    
    u8 h = message_get_flags_hi(map->mesg);
    if(h & QR_BITS) output_stream_write(os, "qr ", 3);
    if(h & AA_BITS) output_stream_write(os, "aa ", 3);
    if(h & TC_BITS) output_stream_write(os, "tc ", 3);
    if(h & RD_BITS) output_stream_write(os, "rd ", 3);
    
    u8 l = message_get_flags_hi(map->mesg);
    
    if(l & RA_BITS) output_stream_write(os, "ra ", 3);
    if(l & AD_BITS) output_stream_write(os, "ad ", 3);
    if(l & CD_BITS) output_stream_write(os, "cd ", 3);
    
    osformatln(os, "\n;; SECTION: [%i ,%i, %i, %i]",
            message_get_section_count(map->mesg, 0),
            message_get_section_count(map->mesg, 1),
            message_get_section_count(map->mesg, 2),
            message_get_section_count(map->mesg, 3));
    
    struct type_class_ttl_rdlen tctr;
    u8 tmp[1024];
    
    int i = 0;
    
    for(int section = 0; section < 4; ++section)
    {
        osformatln(os, ";; SECTION %i:", section);
        
        for(int n = message_get_section_count(map->mesg, section); n > 0; --n)
        {
            message_map_get_fqdn(map, i, tmp, sizeof(tmp));
            if(ISOK(message_map_get_tctr(map, i, &tctr)))
            {
                osformat(os, "%{dnsname} %9i %{dnsclass} %{dnstype} ", tmp, ntohl(tctr.ttl), &tctr.qclass, &tctr.qtype);
                
                if(section > 0)
                {
                    int rdata_size = message_map_get_rdata(map, i, tmp, sizeof(tmp));

                    rdata_desc rd = {tctr.qtype, rdata_size, tmp};
                    osformat(os, "%{rdatadesc}", &rd);
                }
                osprintln(os, "");
                
                ++i;
            }
            else
            {
                osformatln(os, "%{dnsname} READ FAILURE\n", tmp);
                break;
            }
        }
        
        osprintln(os, "");
    }
}

s32 message_send_udp_debug(const message_data *mesg, int sockfd)
{
    log_info("message_send_udp(%p, %i) through %{sockaddr}", mesg, sockfd, mesg->_msghdr.msg_name);

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

ssize_t message_send_tcp(const message_data *mesg, int sockfd)
{
    ssize_t ret;
    struct msghdr tcp_msghdr;
    struct iovec tcp_data[2];
    u16 tcp_len = message_get_size_u16(mesg);
    u16 tcp_native_len = htons(tcp_len);

    tcp_data[0].iov_base = &tcp_native_len;
    tcp_data[0].iov_len = 2;
    tcp_data[1].iov_base = mesg->_buffer;
    tcp_data[1].iov_len = tcp_len;
    tcp_msghdr.msg_name = mesg->_msghdr.msg_name;
    tcp_msghdr.msg_namelen = mesg->_msghdr.msg_namelen;
    tcp_msghdr.msg_iov = &tcp_data[0];
    tcp_msghdr.msg_iovlen = 2;
    tcp_msghdr.msg_control = mesg->_msghdr.msg_control;
    tcp_msghdr.msg_controllen = mesg->_msghdr.msg_controllen;
    tcp_msghdr.msg_flags = 0;

    s32 remain = tcp_len + 2;

#if DEBUG
    s32 again = 0;
#endif

    for(;;)
    {
        ret = sendmsg(sockfd, &tcp_msghdr, 0);

        if(ret < 0)
        {
            int err = ERRNO_ERROR;
            if(err == MAKE_ERRNO_ERROR(EINTR))
            {
                continue;
            }

            if(err == MAKE_ERRNO_ERROR(EAGAIN))
            {
#if DEBUG
                ++again;
#endif
                usleep(100);
                continue;
            }

            ret = err;

            break;
        }

        remain -= ret;

        if(remain == 0)
        {
            break;
        }

        while(tcp_msghdr.msg_iovlen > 0)
        {
            if((size_t)ret < tcp_msghdr.msg_iov[0].iov_len)
            {
                u8* p = (u8*)tcp_msghdr.msg_iov[0].iov_base;
                p += ret;
                tcp_msghdr.msg_iov[0].iov_base = p;
                tcp_msghdr.msg_iov[0].iov_len -= (size_t)ret;
                break;
            }
            else
            {
                ret -= (size_t)tcp_msghdr.msg_iov[0].iov_len;

                ++tcp_msghdr.msg_iov;
                --tcp_msghdr.msg_iovlen;

                if(ret == 0)
                {
                    break;
                }
            }
        }
    }

#if DEBUG
    if(again > 0)
    {
        log_debug("message_send_tcp: again=%i", again);
    }
#endif

    return ret;
}

/** @} */
