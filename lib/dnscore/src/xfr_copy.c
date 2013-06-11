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
/** @defgroup ### #######
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include "dnscore/message.h"
#include "dnscore/packet_reader.h"
#include "dnscore/format.h"
#include "dnscore/xfr_copy.h"
#include "dnscore/file_input_stream.h"
#include "dnscore/file_output_stream.h"
#include "dnscore/buffer_output_stream.h"
#include "dnscore/fdtools.h"

/* it depends if host is DARWIN or LINUX */
#ifdef HAVE_SYS_SYSLIMITS_H
#include        <sys/syslimits.h>
#elif HAVE_LINUX_LIMITS_H
#include        <linux/limits.h>
#endif /* HAVE_SYS_SYSLIMITS_H */

#define MODULE_MSG_HANDLE g_system_logger

/**
 * @todo FINISH AND CLEAN THIS
 */

/**
 * Fixes an issue with the dirent not always set as expected.
 *
 * The type can be set to DT_UNKNOWN instead of file or directory.
 * In that case the function will call stats to get the type.
 */

u8
dirent_get_file_type(const char* folder, struct dirent *entry)
{
    u8 d_type;

#ifdef _DIRENT_HAVE_D_TYPE
    d_type = entry->d_type;
#else
    d_type = DT_UNKNOWN;
#endif
    /*
     * If the FS OR the OS does not supports d_type, there is another way:
     */

    if(d_type == DT_UNKNOWN)
    {
        struct stat file_stat;
        
        char d_name[PATH_MAX];
        snprintf(d_name, sizeof(d_name), "%s/%s", folder, entry->d_name);

        while(stat(d_name, &file_stat) < 0)
        {
            int e = errno;

            if(e != EINTR)
            {
                log_err("stat(%s): %r", d_name, ERRNO_ERROR);
                break;
            }
        }

        if(S_ISREG(file_stat.st_mode))
        {
            d_type = DT_REG;
        }
    }

    return d_type;
}

static ya_result
xfr_copy_open_previous(const u8 *origin, const char* folder, u32 end_at_serial, u32 new_end_at_serial, output_stream* target_os)
{
    struct dirent entry;
    struct dirent *result = NULL;
    u32 from;
    u32 to;
    ya_result return_code = ERROR;

    char name[1024];
    char fqdn[MAX_DOMAIN_TEXT_LENGTH + 1];

    /* returns the number of bytes = strlen(x) + 1 */

    s32 fqdn_len = dnsname_to_cstr(fqdn, origin) ;

    DIR* dir = opendir(folder);
    if(dir != NULL)
    {
        for(;;)
        {
            int readdir_ret = readdir_r(dir, &entry, &result);
            
            if(readdir_ret != 0)
            {
                return_code = MAKE_ERRNO_ERROR(readdir_ret);
                
                log_err("readdir_r(%s,,) failed with %i/%r", folder, readdir_ret, return_code);
                
                break;
            }
            
            /* 0 : ok, > 0 : error */

            if(result == NULL)  /* end reached */
            {
                break;
            }

            u8 d_type = dirent_get_file_type(folder, result);

            if(d_type == DT_REG)
            {
                if(memcmp(result->d_name, fqdn, fqdn_len) == 0)
                {
                    const char* serials = &result->d_name[fqdn_len];

                    /*
                     * at serials [ 8+1+8 ] we MUST have a '.'
                     * followed by 'i' 'x' '\0'
                     */

                    if(strlen(serials) == 8 + 1 + 8 + XFR_INCREMENTAL_EXT_STRLEN)
                    {
                        if(strcmp(&serials[8 + 1 + 8], XFR_INCREMENTAL_EXT) == 0)
                        {
                            int converted = sscanf(serials, "%08x-%08x", &from, &to);

                            if(converted == 2)
                            {
                                if(to == end_at_serial)
                                {
                                    snprintf(name, sizeof(name), "%s/%s", folder, result->d_name);

                                    return_code = file_output_stream_open_ex(name, O_WRONLY|O_APPEND, XFR_INCREMENTAL_FILE_MODE, target_os);

                                    if(ISOK(return_code))
                                    {
                                        char new_name[1024];

                                        snformat(new_name, sizeof (new_name), XFR_INCREMENTAL_WIRE_FILE_FORMAT, folder, origin, from, new_end_at_serial);

                                        if(rename(name, new_name) < 0)
                                        {
                                            output_stream_close(target_os);

                                            /** @todo: log */

                                            return_code = ERRNO_ERROR;
                                        }

                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        closedir(dir);
    }

    return return_code;
}

static ya_result
xfr_copy_get_file_path(char *file_path, u32 file_path_len, u16 qtype, const char* data_path, u8 *origin, u32 current_serial, u32 last_serial, bool tmp)
{
    ya_result return_value;
    
    char *tmptxt = (tmp)?".tmp":"";
    
    zassert(file_path != NULL);

    switch(qtype)
    {
        case TYPE_AXFR:
        {
            return_value = snformat(file_path, file_path_len, "%s/%{dnsname}%08x.axfr%s", data_path, origin, last_serial, tmptxt);
            break;
        }
        case TYPE_IXFR:
        {
            return_value = snformat(file_path, file_path_len, "%s/%{dnsname}%08x-%08x.ix%s", data_path, origin, current_serial, last_serial, tmptxt);
            break;
        }
        default:
        {
            struct timeval tv;
            gettimeofday(&tv, NULL);

            return_value = snformat(file_path, file_path_len, "%s/%{dnsname}-%d.%d.xfr%s", data_path, origin, tv.tv_sec, tv.tv_usec, tmptxt);
            break;
        }
    }
    
    return return_value;
}

static ya_result 
xfr_copy_rename_file(char *file_path, u32 file_path_len, u16 qtype, const char* data_path, u8 *origin, u32 current_serial, u32 last_serial, bool tmp)
{
    ya_result return_value;
    char tmp_path[1024];

    u32 tmp_path_len = MAX(sizeof(tmp_path), file_path_len);
    
    if(ISOK(return_value = xfr_copy_get_file_path(tmp_path, tmp_path_len, qtype, data_path, origin, current_serial, last_serial, tmp)))
    {
        if(rename(file_path, tmp_path)>=0)
        {
            strncpy(file_path, tmp_path, file_path_len);
            return_value = SUCCESS;
        }
        else
        {
            return_value = ERRNO_ERROR;
        }
    }

    return return_value;
}

static ya_result
xfr_copy_create_file(output_stream *xfrs, char *file_path, u32 file_path_len, u16 qtype, const char* data_path, u8 *origin, u32 current_serial, u32 last_serial)
{
    ya_result return_value;

    zassert(xfrs != NULL);

    xfr_copy_get_file_path(file_path, file_path_len, qtype, data_path, origin, current_serial, last_serial, TRUE);

    /*
     * We finally can create the file
     */

    if(FAIL(return_value = file_output_stream_create(file_path, 0644, xfrs)))
    {
        return return_value;
    }

    /*
     * Do NOT use buffers yet.
     */

    return (u32)qtype;
}

/**
 * Reads from the (tcp) input stream for an xfr
 * Detects the xfr type
 * Copies into the right file
 *
 * @return error code
 */

#ifdef WORDS_BIGENDIAN
#define AXFR_MESSAGE_HEADER_MASK    (( (u64) 0 )                                    | \
                                     (((u64) (QR_BITS | AA_BITS | TC_BITS )) << 24 )| \
                                     (((u64) ( RA_BITS | RCODE_BITS )) << 16 )      | \
                                     ( (u64) 1LL << 0 ))

#define AXFR_MESSAGE_HEADER_RESULT  (( (u64) (QR_BITS | AA_BITS) << 24 )            | \
                                     ( ((u64) 1LL) << 0 ))

#else
#define AXFR_MESSAGE_HEADER_MASK     (( (u64) 0LL )                                   | \
                                      (((u64) ( QR_BITS | AA_BITS | TC_BITS )) << 16 )| \
                                      (((u64) ( RCODE_BITS )) << 24 )       | \
                                      (((u64) 1LL) << 40 ))

#define AXFR_MESSAGE_HEADER_RESULT   ((((u64) ( QR_BITS | AA_BITS )) << 16 )| \
                                      (((u64) 1LL) << 40 ))

#define AXFR_NEXT_MESSAGE_HEADER_MASK     (( (u64) 0LL )                                   | \
                                      (((u64) ( QR_BITS | AA_BITS | TC_BITS )) << 16 )| \
                                      (((u64) ( RCODE_BITS )) << 24 ))


#define AXFR_NEXT_MESSAGE_HEADER_RESULT   (((u64) ( QR_BITS | AA_BITS )) << 16 )

#endif

static u32
xfr_copy_hash(const u8 *p)
{
    u32 h = 0;
    u32 c;
    u8 s = 0;
    do
    {
        c = toupper(*p++);
        c &= 0x3f;
        h += c << (s & 15);
        h += 97;
        s += 13;
    }
    while(c != 0);
    
    return h;
}

ya_result
xfr_copy_get_data_path(const char *base_data_path, const u8 *origin, char *data_path, u32 data_path_size)
{
    u32 h = xfr_copy_hash(origin);
    
    return snformat(data_path, data_path_size, "%s/%02x/%02x", base_data_path, h & 0xff, (h >> 8) & 0xff);
}

/**
 * 
 * Creates the hashed folders
 * 
 */

ya_result
xfr_copy_make_data_path(const char *base_data_path, const u8 *origin, char *data_path, u32 data_path_size)
{
    u32 h = xfr_copy_hash(origin);
    ya_result return_value;
    
    if(ISOK(return_value = snformat(data_path, data_path_size, "%s/%02x", base_data_path, h & 0xff)))
    {
        mkdir(data_path, 0755);
        
        ya_result rv = return_value;
        
        if(ISOK(return_value = snformat(&data_path[return_value], data_path_size - return_value, "/%02x", (h >> 8) & 0xff)))
        {        
            return_value += rv;
            
            mkdir(data_path, 0755);
        }
    }
    
    return return_value;
}

/**
 * 
 * Downloads an AXFR/IXFR stream and builds (or updates) a journal on disk
 * 
 * @param is the input stream with the AXFR or IXFR, wire format
 * @param flags mostly XFR_ALLOW_AXFR or XFR_ALLOW_IXFR
 * @param origin the domain of the zone
 * @param base_data_path the folder where to put the journal (or journal hash directories and journal)
 * @param current_serial the serial currently available
 * @param loaded_serial a pointer to get the serial available after loading
 * @param message the message that led to this download
 * 
 * @return an error code, TYPE_AXFR, TYPE_IXFR, TYPE_NONE
 */

ya_result
xfr_copy(xfr_copy_args* args)
{
    // input_stream *is, xfr_copy_flags flags, u8 *origin, const char* base_data_path, u32 current_serial, u32 *loaded_serial, message_data *message
    
    input_stream *is = args->is;
    u8 *origin = args->origin;
    message_data *message = args->message;
    
    output_stream xfrs;
    packet_unpack_reader_data reader;
    u8 *buffer;
    u8 *record;
    u8 *ptr;
    const tsig_item *tsig;
    ya_result record_len;
    ya_result return_value;
    u32 origin_len;
    u32 last_serial = 0;
    u32 record_index = 0;
    u16 tcplen;
    u16 qtype;
    u16 qclass;
    u16 ancount;
    u16 xfr_mode;

    u16 old_mac_size;
    
    bool ixfr_mark;
    bool eos;
    bool last_message_had_tsig;

    u8 old_mac[64];

    char data_path[1024];
    char file_path[1024];
    
    args->out_loaded_serial = 0;
    args->out_journal_file_append_offset = 0;
    args->out_journal_file_append_size = 0;
    
    if(FAIL(return_value = xfr_copy_get_data_path(args->base_data_path, origin, data_path, sizeof(data_path))))
    {
        return return_value;
    }
    
    /*
     * Start by reading the first packet, and determine if it's an AXFR or an IXFR (for the name)
     * note: it's read and converted to the host endianness
     */
    
    /* TCP length */

    if(FAIL(return_value = input_stream_read_nu16(is, &tcplen)))
    {
        return return_value;
    }
    
    if(return_value != 2)
    {
        return UNEXPECTED_EOF;
    }
    
    /* if the length is not enough, return the most appropriate error code */

    origin_len = dnsname_len(origin);

    if(tcplen < DNS_HEADER_LENGTH + origin_len + 4)
    {
        return_value = UNEXPECTED_EOF;
        
        if(tcplen >= DNS_HEADER_LENGTH)
        {
            if(ISOK(return_value = input_stream_read_fully(is, (u8*)file_path, DNS_HEADER_LENGTH)))
            {
                return_value = MAKE_DNSMSG_ERROR(MESSAGE_RCODE(file_path));
            }
        }
        
        /* TODO: retry ? */
        return return_value;
    }
    
    /* read the whole message */

    buffer = &message->buffer[0];

    record = &buffer[DNSPACKET_MAX_LENGTH + 1];

    if(FAIL(return_value = input_stream_read_fully(is, buffer, tcplen)))
    {
        return return_value;
    }
    
    message->received = return_value;
    
    /* check the message makes sense */

    u64 *h64 = (u64*)buffer;
    u64 m64 = AXFR_MESSAGE_HEADER_MASK;
    u64 r64 = AXFR_MESSAGE_HEADER_RESULT;

    if(((*h64&m64) != r64) || (MESSAGE_NS(message->buffer) != 0))
    {
        u8 code = MESSAGE_RCODE(message->buffer);

        if(code != 0)
        {
            return_value = MAKE_DNSMSG_ERROR(code);
        }
        else
        {
            return_value = UNPROCESSABLE_MESSAGE;
        }

         return return_value;
    }

    m64 = AXFR_NEXT_MESSAGE_HEADER_MASK;
    r64 = AXFR_NEXT_MESSAGE_HEADER_RESULT;

    packet_reader_init(buffer, tcplen, &reader);
    reader.offset = DNS_HEADER_LENGTH;

    packet_reader_read_fqdn(&reader, record, RDATA_MAX_LENGTH + 1);

    if(!dnsname_equals(record, origin))
    {
        return INVALID_PROTOCOL;
    }

    if(FAIL(return_value = packet_reader_read_u16(&reader, &qtype)))
    {
        return return_value;
    }
    
    if(return_value != 2)
    {
        return UNEXPECTED_EOF;
    }

    /* 
     * check that we are allowed to process this particular kind of transfer
     * note : this does not determine what is REALLY begin transferred
     */
    
    switch(qtype)
    {
        case TYPE_AXFR:
        {
            if((args->flags & XFR_ALLOW_AXFR) == 0)
            {
                return INVALID_PROTOCOL;
            }
            break;
        }
        case TYPE_IXFR:
        {
            if((args->flags & XFR_ALLOW_IXFR) == 0)
            {
                return INVALID_PROTOCOL;
            }
            break;
        }
        default:
        {
            return INVALID_PROTOCOL;
        }
    }

    if(FAIL(return_value = packet_reader_read_u16(&reader, &qclass)))
    {
        return return_value;
    }

    if(qclass != CLASS_IN)
    {
        /** wrong answer */
        return INVALID_PROTOCOL;
    }
    
    /* check for TSIG and verify */

    ancount = ntohs(MESSAGE_AN(buffer));
    
    if((last_message_had_tsig = ((tsig = message->tsig.tsig) != NULL)))
    {
        /* verify the TSIG
         *
         * AR > 0
         * skip ALL the records until the last AR
         * it MUST be a TSIG
         * It's the first TSIG answering to our query
         * verify it
         *
         */

        message->tsig.tsig = NULL;


        old_mac_size = message->tsig.mac_size;
        memcpy(old_mac, message->tsig.mac, old_mac_size);

        if(FAIL(return_value = tsig_message_extract(message)))
        {
            log_debug("xfr_copy: error extracting the signature");

            return return_value;
        }

        if(return_value == 0)
        {
            log_debug("xfr_copy: no signature when one was requested");

            return TSIG_BADSIG; /* no signature, when one was requested, is a bad signature */
        }

        if(message->tsig.tsig != tsig)
        {
            /* This is not the one we started with */

            log_debug("xfr_copy: signature key does not match");

            return TSIG_BADSIG;
        }

        /** @todo check that the tsig in the message matches the one that was sent */

        if(FAIL(return_value = tsig_verify_tcp_first_message(message, old_mac, old_mac_size)))
        {
            return return_value;
        }

        reader.packet_size = message->received;
    }

    log_debug("xfr_copy: expecting %5d answer records", ancount);    

    /*
     * read the SOA (it MUST be the SOA so no need to check for UNSUPPORTED_TYPE)
     */

    if(FAIL(record_len = packet_reader_read_record(&reader, record, RDATA_MAX_LENGTH + 1)))
    {
        return record_len;
    }

    if(!dnsname_equals(record, origin))
    {
        return INVALID_PROTOCOL;
    }

    ptr = &record[origin_len];

    if(GET_U16_AT(*ptr) != TYPE_SOA)
    {
        return INVALID_PROTOCOL;
    }

    ptr += 8; /* type class ttl */
    
    u16 rdata_size = ntohs(GET_U16_AT(*ptr));    
    if(rdata_size < 22)
    {
        return INVALID_PROTOCOL;
    }
    else
    {
        rdata_size -= 16;

        ptr += 2; /* rdata size */

        s32 len = dnsname_len(ptr);
        
        if(len >= rdata_size)
        {
            return INVALID_PROTOCOL;
        }
        rdata_size -= len;
        ptr += len;

        len = dnsname_len(ptr);
        if(len >= rdata_size)
        {
            return INVALID_PROTOCOL;
        }
        rdata_size -= len;
        
        if(rdata_size != 4)
        {
            return INVALID_PROTOCOL;
        }
        
        ptr += len;
    }

    last_serial = ntohl(GET_U32_AT(*ptr));

    if(last_serial == args->current_serial)
    {
        args->out_loaded_serial = args->current_serial;
        args->out_journal_file_append_offset = 0;
        args->out_journal_file_append_size = 0;
                
        return SUCCESS;
    }

    /*
     * We have got the first SOA
     * Next time we find this SOA (second next time for IXFR) the stream, it will be the end of the stream
     */

    /*
     * The stream can be AXFR or IXFR.
     * In order to know WHAT it is I cannot check the query.  I can only know that if the second record is an SOA too.
     */

    xfr_mode = TYPE_ANY;

    ixfr_mark = FALSE;
    
    if(FAIL(return_value = xfr_copy_create_file(&xfrs, file_path, sizeof(file_path), xfr_mode, data_path, origin, args->current_serial, last_serial)))
    {
        return return_value;
    }

    /*
     * Now we can write the SOA
     */

    /*log_debug("xfr_copy: #%5d %{recordwire} (first)", record_index, record);*/

    if(FAIL(return_value = output_stream_write(&xfrs, record, record_len)))
    {
        unlink(file_path);
        
        return return_value;
    }

    ancount--;
    record_index++;

    /*
     * Then we read all records for all packets
     * If we find an SOA ...
     *      AXFR: it has to be the last serial and it is the end of the stream.
     *      IXFR: if it's not the last serial it has to go from step to step
     *            AND once we have reached the "last serial" once, the next hit is the end of the stream.
     */

    eos = FALSE;

    for(;;)
    {
        while(ancount-- > 0)
        {
            if(FAIL(record_len = packet_reader_read_record(&reader, record, RDATA_MAX_LENGTH + 1)))
            {
                if(record_len != UNSUPPORTED_TYPE)
                {
                    eos = TRUE;

                    return_value = record_len;

                    break;
                }

                log_debug("xfr_copy: skipped unsupported record #%d %{recordwire}", record_index, record);

                record_index++;
                continue;
            }

            ptr = record + dnsname_len(record);

            u16 rtype = GET_U16_AT(*ptr);
            
            if(rtype == TYPE_SOA)
            {
                /* handle SOA case */

                if(!dnsname_equals(record, origin))
                {
                    eos = TRUE;

                    return_value = ERROR;

                    break;
                }

                ptr += 2 + 2 + 4 + 2;
                ptr += dnsname_len(ptr);
                ptr += dnsname_len(ptr);
                u32 soa_serial = ntohl(GET_U32_AT(*ptr));
                
                if(xfr_mode == TYPE_ANY)
                {
                    if(record_index == 1)
                    {
                        /*
                         * Rewind
                         */

                        lseek(fd_output_stream_get_filedescriptor(&xfrs), 0, SEEK_SET);
                        
                        xfr_mode = TYPE_IXFR;
                    }
                    else
                    {
                        xfr_mode = TYPE_AXFR;
                    }

                    xfr_copy_rename_file(file_path, sizeof(file_path), xfr_mode, data_path, origin, args->current_serial, last_serial, TRUE);

                    /*
                     * Now we can use buffering.
                     *
                     * Cannot fail
                     */

                    buffer_output_stream_init(&xfrs, &xfrs, 4096);
                }

                if(soa_serial == last_serial)
                {
                    if(xfr_mode == TYPE_AXFR || (xfr_mode == TYPE_IXFR && ixfr_mark))
                    {
                        return_value = SUCCESS;

                        /*
                         * The last record of an AXFR must be written,
                         * the last record of an IXFR must not.
                         */

                        if(xfr_mode == TYPE_AXFR)
                        {
                            /*log_debug("xfr_copy: #%5d %{recordwire} (last)", record_index, record);*/

                            return_value = output_stream_write(&xfrs, record, record_len);
                        }

                        /* done */
                        eos = TRUE;                       

                        break;
                    }

                    /* IXFR needs to find the mark twice */

                    ixfr_mark = TRUE;
                }
            }
            
            switch(rtype)
            {
                case TYPE_IXFR:
                case TYPE_AXFR:
                case TYPE_OPT:
                case TYPE_ANY:
                    return INVALID_PROTOCOL;
                default:
                    break;
            }
            
            /* log_debug("xfr_copy: #%5d %{recordwire}", record_index, record); */

            if(FAIL(return_value = output_stream_write(&xfrs, record, record_len)))
            {
                eos = TRUE;

                break;
            }

            record_index++;
        }

        if(eos)
        {
            break;
        }

        return_value = input_stream_read_nu16(is, &tcplen);

        if(return_value != 2)
        {
            break;
        }

        if(tcplen == 0)
        {
            return_value = UNEXPECTED_EOF;
            break;
        }

        if(FAIL(return_value = input_stream_read_fully(is, buffer, tcplen)))
        {
            break;
        }

        message->received = return_value;


#ifndef NDEBUG
        memset(&buffer[tcplen], 0xff, DNSPACKET_MAX_LENGTH + 1 - tcplen);
#endif

        /*
         * Check the headers
         */

        /*

        message_header *header = (message_header*)buffer;

        if( (header->opcode & fm) != fm || ntohs(header->qdcount) > 1 || header->ancount == 0 || header->nscount != 0 || header->arcount != 0)
        {
            return_value = ERROR;

            break;
        }
        */

        if(((*h64&m64) != r64) || (MESSAGE_NS(message->buffer) != 0))
        {
            u8 code = MESSAGE_RCODE(message->buffer);

            if(code != 0)
            {
                return_value = MAKE_DNSMSG_ERROR(code);
            }
            else
            {
                return_value = UNPROCESSABLE_MESSAGE;
            }
            
            break;
        }

        if((last_message_had_tsig = (tsig != NULL)))
        {
            /* verify the TSIG
             *
             * AR > 0
             * skip ALL the records until the last AR
             * it MUST be a TSIG
             * It's the first TSIG answering to our query
             * verify it
             *
             */

            message->tsig.tsig = NULL;

            if(FAIL(return_value = tsig_message_extract(message)))
            {
                break;
            }
            
            if(return_value == 1)
            {
                if(message->tsig.tsig != tsig)
                {
                    /* This is not the one we started with */

                    log_debug("xfr_copy: signature key does not match");
                    
                    return_value = TSIG_BADSIG;
                    break;
                }
            }

            if(FAIL(return_value = tsig_verify_tcp_next_message(message)))
            {
                break;
            }
        }

        message_header *header = (message_header*)buffer;
        
        ancount = ntohs(header->ancount);

        packet_reader_init(buffer, message->received, &reader);
        reader.offset = DNS_HEADER_LENGTH;

        u16 n = ntohs(header->qdcount);
        
        while(n > 0)
        {
            if(FAIL(return_value = packet_reader_skip_fqdn(&reader)))
            {
                break;
            }

            packet_reader_skip(&reader, 4);

            n--;
        }

        /**
         * @todo: TSIG
         */
    }

    if(tsig != NULL)
    {
        tsig_verify_tcp_last_message(message);
        
        if(!last_message_had_tsig)
        {
            /*
             * The stream didn't end with a TSIG
             * It's bad.
             *
             */

            log_err("xfr_copy: TSIG enabled answer didn't ended with a signed packet");

            return_value = TSIG_BADSIG;
        }
    }

    output_stream_close(&xfrs);

    if(FAIL(return_value))
    {
        unlink(file_path);
    }
    else
    {
        args->out_loaded_serial = last_serial;
        
        if(xfr_mode == TYPE_IXFR)
        {
            /** @TODO : merge IXFR files */
            /* merge */
            /* get the ix file ending with the start of this one */
            /* append the newly created file */
            /* rename */

            /**
             * @todo find an ix file whose name ends with current_serial
             *       if it exists: append the current file to it.
             *       if not: rename the file
             */

            output_stream os;
            if(ISOK(xfr_copy_open_previous(origin, data_path, args->current_serial, last_serial, &os)))
            {
                ya_result return_value;
                char tmp[1024];
                
                /**
                 * open for reading & stream
                 */
                
                args->out_journal_file_append_offset = fd_input_stream_get_size(&os);
                args->out_journal_file_append_size = 0;
                
                /* os is a file stream */

                input_stream is;

                if(ISOK(return_value = file_input_stream_open(file_path, &is)))
                {
                    while((return_value = input_stream_read(&is, (u8*)tmp, sizeof(tmp))) > 0)
                    {
                        args->out_journal_file_append_size += return_value;
                        
                        output_stream_write(&os, (u8*)tmp, return_value);
                    }

                    output_stream_close(&is);

                    unlink(file_path);
                }

                output_stream_close(&os);
            }
            else
            {
                args->out_journal_file_append_offset = 0;
                args->out_journal_file_append_size = filesize(file_path);
            
                xfr_copy_rename_file(file_path, sizeof(file_path), xfr_mode, data_path, origin, args->current_serial, last_serial, FALSE);
            }
        }
        else /* AXFR */
        {
            args->out_journal_file_append_offset = 0;
            args->out_journal_file_append_size = filesize(file_path);
            
            xfr_copy_rename_file(file_path, sizeof(file_path), xfr_mode, data_path, origin, args->current_serial, last_serial, FALSE);
        }

        return_value = (u32)xfr_mode;
    }

    return return_value;
}

ya_result
xfr_delete_axfr(const u8 *origin, const char *folder)
{
    struct dirent entry;
    struct dirent *result;
    u32 serial;
    ya_result return_code = ERROR;

    char fqdn[MAX_DOMAIN_TEXT_LENGTH + 1];

    /* returns the number of bytes = strlen(x) + 1 */

    s32 fqdn_len = dnsname_to_cstr(fqdn, origin) ;

    DIR* dir = opendir(folder);
    
    if(dir != NULL)
    {
        for(;;)
        {
            readdir_r(dir, &entry, &result);

            if(result == NULL)
            {
                break;
            }

            u8 d_type = dirent_get_file_type(folder, result);

            if(d_type == DT_REG)
            {
                if(memcmp(result->d_name, fqdn, fqdn_len) == 0)
                {
                    const char* serials = &result->d_name[fqdn_len];

                    /*
                     * at serials [ 8+1+8 ] we MUST have a '.'
                     * followed by 'i' 'x' '\0'
                     */

                    if(strlen(serials) == 8 + XFR_FULL_EXT_STRLEN)
                    {
                        if(strcmp(&serials[8], XFR_FULL_EXT) == 0)
                        {
                            int converted = sscanf(serials, "%08x", &serial);

                            if(converted == 1)
                            {
                                /* got one */
                                
                                log_debug("deleting AXFR file: %s", result->d_name);
                                
                                if(unlink_ex(folder, result->d_name) < 0)
                                {
                                    log_err("unlink %s/%s: %r", folder, result->d_name, ERRNO_ERROR);
                                }
                            }
                        }
                    }
                }
            }
        }

        closedir(dir);
    }

    return return_code;
}

ya_result
xfr_delete_ix(const u8 *origin, const char *folder)
{
    struct dirent entry;
    struct dirent *result;
    u32 from;
    u32 to;
    ya_result return_code = ERROR;

    char fqdn[MAX_DOMAIN_TEXT_LENGTH + 1];

    /* returns the number of bytes = strlen(x) + 1 */

    s32 fqdn_len = dnsname_to_cstr(fqdn, origin);

    DIR* dir = opendir(folder);
    if(dir != NULL)
    {
        for(;;)
        {
            readdir_r(dir, &entry, &result);

            if(result == NULL)
            {
                break;
            }

            u8 d_type = dirent_get_file_type(folder, result);

            if(d_type == DT_REG)
            {
                if(memcmp(result->d_name, fqdn, fqdn_len) == 0)
                {
                    const char* serials = &result->d_name[fqdn_len];

                    /*
                     * at serials [ 8+1+8 ] we MUST have a '.'
                     * followed by 'i' 'x' '\0'
                     */

                    if(strlen(serials) == 8 + 1 + 8 + XFR_INCREMENTAL_EXT_STRLEN)
                    {
                        if(strcmp(&serials[8 + 1 + 8], XFR_INCREMENTAL_EXT) == 0)
                        {
                            int converted = sscanf(serials, "%08x-%08x", &from, &to);

                            if(converted == 2)
                            {
                                /* got one */
                                
                                log_debug("deleting IX file: %s", result->d_name);
                                
                                if(unlink_ex(folder, result->d_name) < 0)
                                {
                                    log_err("unlink %s/%s: %r", folder, result->d_name, ERRNO_ERROR);
                                }
                            }
                        }
                    }
                }
            }
        }

        closedir(dir);
    }

    return return_code;
}

/** @} */
