/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2020, EURid vzw. All rights reserved.
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

/** @defgroup test
 *  @ingroup test
 *  @brief journal server
 *
 * The journal-server is a minimal DNS TCP server meant to answer to AXFR and IXFR queries.
 * It's meant to be used for testing journal cases.
 *
 */

#include <dnscore/dnscore.h>

#include <dnscore/random.h>
#include <dnscore/message.h>
#include <dnscore/config_settings.h>
#include <dnscore/host_address.h>
#include <dnscore/socket-server.h>
#include <dnscore/thread_pool.h>
#include <dnscore/packet_reader.h>
#include <dnscore/zone_reader_text.h>

#define ZDB_JOURNAL_CODE 1
#include <dnsdb/journal.h>
#include <dnsdb/zdb-zone-path-provider.h>
#include <dnsdb/zdb.h>
#include <dnscore/packet_writer.h>
#include <dnscore/serial.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnsdb/zdb_zone_load.h>
#include <dnscore/parser.h>
#include <dnsdb/zdb-zone-answer-axfr.h>
#include <dnscore/signals.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/logger_channel_stream.h>
#include <dnsdb/journal-cjf-common.h>

#define TCP_BUFFER_SIZE     4096

#define THREAD_POOL_SIZE 32

#undef MODULE_MSG_HANDLE
logger_handle *g_program_logger = LOGGER_HANDLE_SINK;
#define MODULE_MSG_HANDLE g_program_logger

#define ZAIXFRRB_TAG 0x425252465849415a

struct client_parm
{
    socketaddress addr;
    socklen_t addr_size;
    int sockfd;
};

typedef struct client_parm client_parm;

static host_address *server_ip = NULL;
static host_address *slave_ip = NULL;
static journal *jh = NULL;
static struct thread_pool_s *tp = NULL;
static struct thread_pool_s *dtp = NULL;
static struct thread_pool_s *udptp = NULL;
static zdb db;
static int server_sockfd = -1;
static int server_udp_sockfd = -1;

static char journal_directory[PATH_MAX];
static char axfr_directory[PATH_MAX] = "/tmp/journal-server";

static int edns0_maxsize = 4096;

static ya_result
zone_path_provider_callback(const u8* domain_fqdn, char *path_buffer, u32 path_buffer_size, u32 flags)
{
    ya_result ret = SUCCESS;
    ya_result ret2 = SUCCESS;

    if(flags & ZDB_ZONE_PATH_PROVIDER_ZONE_PATH)
    {
        strcpy_ex(path_buffer, journal_directory, path_buffer_size);

        if(flags & ZDB_ZONE_PATH_PROVIDER_MKDIR)
        {
            if(ISOK(ret = mkdir_ex(path_buffer, 0755, 0)))
            {
                ret = strlen(path_buffer);
            }
        }

        return ret;
    }

    if(flags & ZDB_ZONE_PATH_PROVIDER_AXFR_FILE)
    {
        if(ISOK(ret = snformat(path_buffer, path_buffer_size, "%s/%{dnsname}.xfr", axfr_directory, domain_fqdn)))
        {
            if(flags & ZDB_ZONE_PATH_PROVIDER_MKDIR)
            {
                if(FAIL(ret2 = mkdir_ex(path_buffer, 0755, MKDIR_EX_PATH_TO_FILE)))
                {
                    ret = ret2;
                }
            }
        }

        return ret;
    }

    log_info("zone_path_provider_callback(%{dnsname}, %p, %u, %x) returning an error",
             domain_fqdn, path_buffer, path_buffer_size, flags);

    return ERROR;
}

#if ZDB_HAS_TSIG_SUPPORT
static ya_result
tcp_client_xfr_send_message(output_stream *tcpos, packet_writer *pw, message_data *mesg, tsig_tcp_message_position pos)
#else
static ya_result
tcp_client_xfr_send_message(output_stream *tcpos, packet_writer *pw, message_data *mesg)
#endif
{
    ya_result return_code;

    /*
     * Flush and stop
     */

#if 0 // DEBUG
    log_info("client: IXFR: sending message for %{dnsname} to %{sockaddr}", message_get_canonised_fqdn(mesg), message_get_sender(mesg));
#endif

    if(message_is_edns0(mesg)) // Dig does a TCP query with EDNS0
    {
        /* 00 00 29 SS SS rr vv 80 00 00 00 */

        memset(packet_writer_get_next_u8_ptr(pw), 0, EDNS0_RECORD_SIZE);
        packet_writer_forward(pw, 2);
        packet_writer_add_u8(pw, 0x29);
        packet_writer_add_u16(pw, htons(edns0_maxsize));
        packet_writer_add_u32(pw, message_get_rcode_ext(mesg));
        packet_writer_forward(pw, 2);
        message_set_additional_count_ne(mesg, NETWORK_ONE_16);
    }
    else
    {
        message_set_additional_count_ne(mesg, 0);
    }

    message_set_size(mesg, packet_writer_get_offset(pw));

#if ZDB_HAS_TSIG_SUPPORT
    if(message_has_tsig(mesg))
    {
        message_set_additional_section_ptr(mesg, packet_writer_get_next_u8_ptr(pw));

        if(FAIL(return_code = tsig_sign_tcp_message(mesg, pos)))
        {
            log_info("client: IXFR: failed to sign the answer: %r", return_code);

            return return_code;
        }
    }
#endif

    packet_writer_set_offset(pw, message_get_size(mesg));

    if(FAIL(return_code = write_tcp_packet(pw, tcpos)))
    {
        log_info("client: IXFR: error sending IXFR packet to %{sockaddr}: %r", message_get_sender_sa(mesg), return_code);
    }

    return return_code;
}


static ya_result
tcp_client_read_record_from_stream(input_stream *is, u8 *qname, u32 *qname_sizep, struct type_class_ttl_rdlen *tctrlp, u8 *rdata_buffer, u32 *rdata_sizep)
{
    ya_result return_code;

    /* Read the next DNAME from the stored INCREMENTAL */

    if((return_code = input_stream_read_dnsname(is, qname)) <= 0)
    {
        if(return_code < 0)
        {
            log_info("client: IXFR: error reading IXFR qname: %r", return_code);
        }
        else
        {
            log_info("client: IXFR: eof reading IXFR qname: %r", return_code);
        }

        return return_code;
    }

    *qname_sizep = return_code;

    if(return_code > 0)
    {
        /* read the next type+class+ttl+rdatalen from the stored IXFR */

        tctrlp->qtype = 0;
        tctrlp->rdlen = 0;

        if(FAIL(return_code = input_stream_read_fully(is, tctrlp, 10)))
        {
            log_info("client: IXFR: error reading IXFR record: %r", return_code);

            return return_code;
        }

        if(FAIL(return_code = input_stream_read_fully(is, rdata_buffer, ntohs(tctrlp->rdlen))))
        {
            log_info("client: IXFR: error reading IXFR record rdata: %r", return_code);

            return return_code;
        }

        *rdata_sizep = return_code;

        return_code = *qname_sizep + 10 + *rdata_sizep;
    }
    else
    {
        *rdata_sizep = 0;
    }

    return return_code;
}

static void
tcp_client_ixfr(client_parm *parm, message_data *mesg)
{
    log_info("%{sockaddr} tcp_cilent_ixfr begin", &parm->addr);

    ya_result ret;
    int sockfd = parm->sockfd;
    size_t query_size = message_get_size(mesg);
    const u8 *origin = message_get_canonised_fqdn(mesg);
    packet_writer pw;
    input_stream is;

    output_stream tcpos_root;
    output_stream tcpos;
    fd_output_stream_attach(&tcpos_root, sockfd);
    buffer_output_stream_init(&tcpos, &tcpos_root, TCP_BUFFER_SIZE);

    //struct type_class_ttl_rdlen current_soa_tctrl;

    /*
     */

    u8 *rdata_buffer = NULL;
    struct type_class_ttl_rdlen tctrl;
    u32 qname_size;
    u32 rdata_size;

    u16 an_count = 0;

    u32 packet_size_limit = message_get_buffer_size_max(mesg);
    u32 packet_size_trigger = packet_size_limit / 2; // so, ~32KB, also : guarantees that there will be room for SOA & TSIG;
    s32 packet_records_limit = MAX_S32;
    s32 packet_records_countdown = packet_records_limit;

    u32 serial;

    tsig_tcp_message_position pos = TSIG_START;

    u8 fqdn[MAX_DOMAIN_LENGTH];

    if(ISOK(ret = message_get_ixfr_query_serial(mesg, &serial)))
    {
        log_info("client: %{sockaddr}: IXFR from serial %u", &parm->addr, serial);

        journal *jnl = NULL;

        if(ISOK(ret = journal_acquire_from_fqdn_ex(&jnl, message_get_canonised_fqdn(mesg), FALSE)))
        {
            log_info("client: %{sockaddr}: IXFR from serial %u: journal acquired (%i)", &parm->addr, serial, jnl->rc);

            dns_resource_record last_soa_rr;
            dns_resource_record_init(&last_soa_rr);

            if(ISOK(ret = journal_get_last_soa(jnl, &last_soa_rr)))
            {
                dns_resource_record rr;
                dns_resource_record_init(&rr);

                if(ISOK(ret = journal_get_ixfr_stream_at_serial(jnl, serial, &is, &rr)))
                {
                    log_info("client: %{sockaddr}: IXFR from serial %u: journal stream ready {%p}", &parm->addr, serial);

                    message_set_authoritative_answer(mesg);
                    message_set_authority_count_ne(mesg, 0);
                    message_set_additional_count_ne(mesg, 0);

                    packet_unpack_reader_data purd;
                    packet_reader_init_from_message(&purd, mesg);

                    /* Keep only the query */

                    packet_reader_skip_fqdn(&purd);
                    purd.offset += 4;

                    message_set_size(mesg, purd.offset);
                    query_size = message_get_size(mesg);

                    packet_writer_init(&pw, message_get_buffer(mesg), query_size, packet_size_limit - 780);

                    /*
                     * Init
                     *
                     * Write the final SOA (start of the IXFR stream)
                     */

                    packet_writer_add_fqdn(&pw, (const u8*)last_soa_rr.name);
                    packet_writer_add_bytes(&pw, (const u8*)&last_soa_rr.tctr, 8); // not 10 because the next call writes the rdata size before the rdata
                    packet_writer_add_rdata(&pw, TYPE_SOA, last_soa_rr.rdata, last_soa_rr.rdata_size);

                    u32 last_serial;
#if 0
                    u32 prev_serial;
#endif
                    rr_soa_get_serial(last_soa_rr.rdata, last_soa_rr.rdata_size, &last_serial);
#if 0
                    prev_serial = last_serial;
#endif
                    log_info("client: %{sockaddr}: IXFR ends with %{dnsrr}", &parm->addr, &last_soa_rr);

                    an_count = 1 /*2*/;

                    u32 page_record_count = 0;
                    u32 soa_count = 0;

                    bool end_of_stream = FALSE;

                    MALLOC_OR_DIE(u8*, rdata_buffer, RDATA_MAX_LENGTH, ZAIXFRRB_TAG);    /* rdata max size */

                    for(;;)
                    {
                        rdata_size = RDATA_MAX_LENGTH;

                        if(FAIL(ret = tcp_client_read_record_from_stream(&is, fqdn, &qname_size, &tctrl, rdata_buffer, &rdata_size)))
                        {
                            // critical error.

                            log_info("client: IXFR: %{dnsname}: %{sockaddr}: read record #%d failed: %r", origin, message_get_sender_sa(mesg), an_count, ret);
                            break;
                        }

                        // at this point, record_length >= 0
                        // if record_length > 0 then tctrl has been set

                        u32 record_length = ret;

                        if(record_length > 0)
                        {
                            if(tctrl.qtype == TYPE_SOA) // scan-build (7) false positive: the path allegedly leading here lies on an incoherence (record_length <= 0)
                            {
                                ++soa_count;

                                // ensure we didn't go too far
                                u32 soa_serial;
                                rr_soa_get_serial(rdata_buffer, rdata_size, &soa_serial);
                                if(serial_gt(soa_serial, last_serial))
                                {
                                    log_info("client: IXFR: %{dnsname}: %{sockaddr}: cutting at serial %u", origin, message_get_sender_sa(mesg), soa_serial);

                                    record_length = 0; // will be seen as an EOF
                                }
#if 0
                                else if(soa_serial == prev_serial)
                                {
                                    // this is the second time we see this serial: it's done

                                    log_info("client: IXFR: %{dnsname}: %{sockaddr}: read closing serial %u", origin, message_get_sender_sa(mesg), soa_serial);

                                    record_length = 0; // will be seen as an EOF
                                }
#endif
                                else if(dnscore_shuttingdown())
                                {
                                    log_info("client: IXFR: %{dnsname}: %{sockaddr}: shutting down: cutting at serial %u", origin, message_get_sender_sa(mesg), soa_serial);

                                    record_length = 0; // will be seen as an EOF
                                }

                                if((soa_count & 1) == 0)
                                {
                                    //
                                }
                                else
                                {
                                    page_record_count = 0;
                                }
                            }

                            ++page_record_count;
#if 0
// generates a corruption
                            if(page_record_count > 50000)
                            {
                                break;
                            }
#endif
                        }

                        if(record_length == 0)
                        {
    #if DEBUG
                            log_info("client: IXFR: %{dnsname}: %{sockaddr}: end of stream", origin, message_get_sender(mesg));
    #endif

    #if ZDB_HAS_TSIG_SUPPORT
                            if(pos != TSIG_START)
                            {
                                pos = TSIG_END;
                            }
                            else
                            {
                                pos = TSIG_WHOLE;
                            }
    #endif
                            // Last SOA
                            // There is no need to check for remaining space as packet_size_trigger guarantees there is still room
    #if  DEBUG
                            {
                                rdata_desc rr_desc = {TYPE_SOA, last_soa_rr.rdata_size, last_soa_rr.rdata};
                                log_info("client: IXFR: %{dnsname}: closing: %{dnsname} %{typerdatadesc}", origin, origin, &rr_desc);
                            }
    #endif
                            packet_writer_add_fqdn(&pw, (const u8*)last_soa_rr.name);
                            packet_writer_add_bytes(&pw, (const u8*)&last_soa_rr.tctr, 8); /* not 10 ? */
                            packet_writer_add_rdata(&pw, TYPE_SOA, last_soa_rr.rdata, last_soa_rr.rdata_size);

                            ++an_count;

                            end_of_stream = TRUE;
                        }
                        else if(record_length > MAX_U16) // technically possible: a record too big to fit in an update (not likely)
                        {
                            // this is technically possible with an RDATA of 64K
                            log_info("client: IXFR: %{dnsname}: %{sockaddr}: ignoring record of size %u", origin, message_get_sender_sa(mesg), record_length);
                            rdata_desc rr_desc = {tctrl.qtype, rdata_size, rdata_buffer};
                            log_info("client: IXFR: %{dnsname}: %{sockaddr}: record is: %{dnsname} %{typerdatadesc}", origin, message_get_sender_sa(mesg), ret, fqdn, &rr_desc);
                            continue;
                        }

                        // if the record puts us above the trigger, or if there is no more record to read, send the message

                        if((pw.packet_offset + record_length >= packet_size_trigger) || (packet_records_countdown-- <= 0) || end_of_stream)
                        {
                            // flush

                            message_set_answer_count(mesg, an_count);
                            //message_set_size(mesg, packet_writer_get_offset(&pw));

    #if ZDB_HAS_TSIG_SUPPORT
                            if(FAIL(ret = tcp_client_xfr_send_message(&tcpos, &pw, mesg, pos)))
    #else
                                if(FAIL(ret = tcp_client_xfr_send_message(&tcpos, &pw, mesg)))
    #endif
                            {
                                if(ret == MAKE_ERRNO_ERROR(EPIPE))
                                {
                                    log_notice("client: IXFR: %{dnsname}: %{sockaddr}: send message failed: client closed connection", origin, message_get_sender_sa(mesg));
                                }
                                else
                                {
                                    log_notice("client: IXFR: %{dnsname}: %{sockaddr}: send message failed: %r", origin, message_get_sender_sa(mesg), ret);
                                }

                                break;
                            }

    #if ZDB_HAS_TSIG_SUPPORT
                            pos = TSIG_MIDDLE;
    #endif
                            packet_writer_init(&pw, message_get_buffer(mesg), query_size, packet_size_limit - 780);

                            an_count = 0;

                            if(end_of_stream)
                            {
                                break;
                            }

                            packet_records_countdown = packet_records_limit;
                        }

    #if 0 // DEBUG
                        {
                            rdata_desc rr_desc = {tctrl.qtype, rdata_size, rdata_buffer};
                            log_info("client: IXFR: %{dnsname}: sending: %{dnsname} %{typerdatadesc}", origin, fqdn, &rr_desc);
                        }
    #endif

                        packet_writer_add_fqdn(&pw, (const u8*)fqdn);
                        packet_writer_add_bytes(&pw, (const u8*)&tctrl, 8);
                        packet_writer_add_rdata(&pw, tctrl.qtype, rdata_buffer, rdata_size);

                        ++an_count;
                    } // for loop

                    input_stream_close(&is);

                    free(rdata_buffer);
                }
                else
                {
                    log_info("client: %{sockaddr}: %{dnsname}: IXFR from serial %u: could not obtain journal stream: %r", &parm->addr, origin, serial, ret);
                }

                dns_resource_record_finalize(&rr);
            }
            else
            {
                log_info("client: %{sockaddr}: %{dnsname}: IXFR from serial %u: could not obtain last SOA record: %r", &parm->addr, origin, serial, ret);
            }

            dns_resource_record_finalize(&last_soa_rr);

            log_info("client: %{sockaddr}: %{dnsname}: IXFR from serial %u: releasing journal (%i) (%p) (%p)", &parm->addr, origin, serial, jnl->rc, jnl, origin);

            journal_release(jnl);
        }
        else
        {
            log_info("client: %{sockaddr}: %{dnsname}: IXFR from serial %u: could not acquire journal: %r", &parm->addr, origin, serial, ret);
        }
    }
    else
    {
        log_info("client: %{sockaddr}: IXFR could not get stream from serial %u", &parm->addr, serial);
    }

    log_info("%{sockaddr} tcp_cilent_ixfr end", &parm->addr);

    output_stream_flush(&tcpos);

    fd_output_stream_detach(&tcpos_root);
    output_stream_close(&tcpos);

    sleep(8); // just a test
}

static void
notify_slave(message_data *mesg)
{
    journal *jnl;
    ya_result ret;

    if(ISOK(ret = journal_acquire_from_fqdn_ex(&jnl, message_get_canonised_fqdn(mesg), FALSE)))
    {
        log_info("udp: %{sockaddr} %{dnsname} journal acquired (%i)", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg), jnl->rc);

        dns_resource_record last_soa_rr;
        dns_resource_record_init(&last_soa_rr);

        if(ISOK(ret = journal_get_last_soa(jnl, &last_soa_rr)))
        {
            message_data *notify_mesg;
            notify_mesg = message_new_instance();
            message_make_notify(notify_mesg, rand(), message_get_canonised_fqdn(mesg), TYPE_SOA, CLASS_IN);

            //packet_writer pw;
            //packet_writer_init_append_to_message(&pw, notify_mesg);

            // this works but not with tests on the lo device
            //message_copy_sender_from(notify_mesg, mesg);
            //message_set_sender_port(notify_mesg, NU16(53));

            socketaddress sa;
            ya_result  sa_len = host_address2sockaddr(slave_ip, &sa);
            message_copy_sender_from_sa(notify_mesg, &sa.sa, sa_len);

            //message_set_authoritative(notify_mesg);
            //message_set_authority_count_ne(notify_mesg, 0);
            //message_set_additional_count_ne(notify_mesg, 0);
            //packet_writer_add_record(&pw, message_get_canonised_fqdn(mesg), TYPE_SOA, CLASS_IN, 86400, last_soa_rr.rdata, last_soa_rr.rdata_size);
            //message_set_size(notify_mesg, packet_writer_get_offset(&pw));

            log_info("%{sockaddr}: %{dnsname}: sending notification to %{sockaddr}", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg), message_get_sender_sa(notify_mesg));

            while(!dnscore_shuttingdown())
            {
                ssize_t n = message_send_udp(notify_mesg, server_udp_sockfd);
                if(n >= 0)
                {
                    log_info("%{sockaddr}: %{dnsname}: notification sent", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg));
                    break;
                }

                if((errno != EINTR) && (errno != EAGAIN) && (errno != ETIMEDOUT))
                {
                    log_info("%{sockaddr}: %{dnsname}: failed to send notification: %r", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg), ERRNO_ERROR);
                    break;
                }

                sleep(1);

                log_info("%{sockaddr}: %{dnsname}: re-trying to send notification", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg));
            }

            message_free(notify_mesg);
        }
        else
        {
            log_info("%{sockaddr}: could not get last SOA from journal: %r", message_get_sender_sa(mesg), ret);
        }

        log_info("%{sockaddr}: releasing journal (%i)", message_get_sender_sa(mesg), jnl->rc);

        journal_release(jnl);
    }
}

static void
tcp_client_axfr(client_parm *parm, message_data *mesg)
{
    const u8 *origin = message_get_canonised_fqdn(mesg);

    //struct type_class_ttl_rdlen current_soa_tctrl;

    dnsname_vector origin_vector;
    dnsname_to_dnsname_vector(origin, &origin_vector);

    zdb_zone *zone = zdb_acquire_zone_read(&db, &origin_vector);
    if(zone != NULL)
    {
        log_info("client: %{sockaddr}: AXFR %{dnsname}", &parm->addr, origin);
        zdb_zone_answer_axfr(zone, mesg, parm->sockfd, NULL, dtp, 48*1024, 0, TRUE);

        notify_slave(mesg);

        zdb_zone_release(zone);
    }
    else
    {
        log_info("client: %{sockaddr}: AXFR: %{dnsname} zone not loaded", &parm->addr, origin);
    }
}

static void*
tcp_client_thread(void* parm_)
{
    client_parm *parm = (client_parm*)parm_;
    
    // decode the dns message (that must be an IXFR)
    // return the journal from the serial, for one page only
    
    message_data* mesg = message_new_instance();
    ya_result ret;
    
    //u8 buffer[1024];

    log_info("client: %{sockaddr} receiving query", &parm->addr);
    
    if(ISOK(ret = message_recv_tcp(mesg, parm->sockfd)))
    {
        message_copy_sender_from_socket(mesg, parm->sockfd);

        log_info("client: %{sockaddr} processing query", &parm->addr);

        if(ISOK(ret = message_process_query(mesg)))
        {
            u16 qtype = message_get_query_type(mesg);

            log_info("client: %{sockaddr} query type: %{dnstype}", &parm->addr, &qtype);

            switch(qtype)
            {
                case TYPE_AXFR:
                {
                    tcp_client_axfr(parm, mesg);
                    break;
                }
                case TYPE_IXFR:
                {
                    tcp_client_ixfr(parm, mesg);
                    break;
                }
                default:
                {
                    message_make_error_and_reply_tcp_with_default_minimum_throughput(mesg, RCODE_NOTIMP, parm->sockfd);
                    break;
                }
            }
        }
        else
        {
            log_info("client: %{sockaddr} failed to process query: %r", &parm->addr, ret);
        }
    }
    else
    {
        log_info("client: %{sockaddr} failed to receive query: %r", &parm->addr, ret);
    }
    
    message_free(mesg);
    close_ex(parm->sockfd);
    free(parm);
    return NULL;
}

static void*
udp_client_thread(void* parm_)
{
    (void)parm_;

    // decode the dns message (that must be an IXFR)
    // return the journal from the serial, for one page only

    message_data* mesg = message_new_instance();
    zdb_query_ex_answer qea;
    void *pool;
    MALLOC_OBJECT_ARRAY_OR_DIE(pool, u8, MESSAGE_POOL_SIZE, GENERIC_TAG);
    message_set_pool_buffer(mesg, pool, MESSAGE_POOL_SIZE);

    ya_result ret;

    log_info("udp: waiting for query");

    while(!dnscore_shuttingdown())
    {
        if(ISOK(ret = message_recv_udp(mesg, server_udp_sockfd)))
        {
            log_info("udp: %{sockaddr} processing query", message_get_sender_sa(mesg));

            if(message_get_opcode(mesg) == OPCODE_QUERY)
            {
                if(ISOK(ret = message_process_query(mesg)))
                {
                    if(message_isquery(mesg))
                    {
                        log_info("udp: %{sockaddr} %{dnsname} %{dnstype} query", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg));

                        if(message_get_query_type(mesg) != TYPE_SOA)
                        {
                            zdb_query_ex_answer_create(&qea);
#pragma message ("use the other function")
#if 0
                            finger_print fp = zdb_query_ex(&db, mesg, &qea, message_get_pool_buffer(mesg));

                            message_set_status(mesg, fp);

                            if(fp == FP_RCODE_NOERROR)
                            {
                                zdb_query_message_update(mesg, &qea);
                            }
#endif
                            zdb_query_ex_answer_destroy(&qea);
                        }
                        else
                        {
                            // the SOA must be taken from the journal as the zones are never modified

                            journal *jnl;

                            if(ISOK(ret = journal_acquire_from_fqdn_ex(&jnl, message_get_canonised_fqdn(mesg), FALSE)))
                            {
                                log_info("udp: %{sockaddr} %{dnsname} journal acquired (%i)", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg), jnl->rc);

                                dns_resource_record last_soa_rr;
                                dns_resource_record_init(&last_soa_rr);
                                packet_writer pw;

                                if(ISOK(ret = journal_get_last_soa(jnl, &last_soa_rr)))
                                {
                                    message_set_authoritative_answer(mesg);
                                    message_set_authority_count_ne(mesg, 0);
                                    message_set_additional_count_ne(mesg, 0);

                                    packet_unpack_reader_data purd;
                                    packet_reader_init_from_message(&purd, mesg);

                                    /* Keep only the query */

                                    packet_reader_skip_fqdn(&purd);
                                    purd.offset += 4;

                                    message_set_size(mesg, purd.offset);
                                    u16 query_size = message_get_size(mesg);

                                    packet_writer_init(&pw, message_get_buffer(mesg), query_size, 32768 - 780);

                                    /*
                                     * Init
                                     *
                                     * Write the final SOA (start of the IXFR stream)
                                     */

                                    packet_writer_add_fqdn(&pw, (const u8*)last_soa_rr.name);
                                    packet_writer_add_bytes(&pw, (const u8*)&last_soa_rr.tctr, 8); // not 10 because the next call writes the rdata size before the rdata
                                    packet_writer_add_rdata(&pw, TYPE_SOA, last_soa_rr.rdata, last_soa_rr.rdata_size);

                                    u32 last_serial;
                                    rr_soa_get_serial(last_soa_rr.rdata, last_soa_rr.rdata_size, &last_serial);

                                    message_set_answer_count(mesg, 1);
                                    message_set_size(mesg, packet_writer_get_offset(&pw));
                                }
                                else
                                {
                                    log_info("udp: %{sockaddr} %{dnsname}: could not get last SOA from journal", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg));

                                    message_make_error(mesg, RCODE_SERVFAIL);
                                }

                                log_info("udp: %{sockaddr} %{dnsname}: journal (%i)", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg), jnl->rc);

                                journal_release(jnl);
                            }
                            else
                            {
                                log_info("udp: %{sockaddr} %{dnsname}: could not acquire journal", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg));

                                message_make_error(mesg, RCODE_REFUSED);
                            }
                        }
                    }
                    else
                    {
                        log_info("udp: %{sockaddr} %{dnsname}: answer to a query: ignoring", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg));
                        continue;
                    }
                }
                else
                {
                    log_info("udp: query cannot be processed: %r", ret);

                    message_make_error(mesg, RCODE_FORMERR);
                }
            }
            else if(message_get_opcode(mesg) == OPCODE_NOTIFY)
            {
                if(ISOK(ret = message_process_lenient(mesg)))
                {
                    if(message_isanswer(mesg))
                    {
                        log_info("udp: %{sockaddr} %{dnsname}: notification reply", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg));
                    }
                    else
                    {
                        log_info("udp: %{sockaddr} %{dnsname}: notification of zone change: ignoring", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg));
                    }

                    continue;
                }
                else
                {
                    log_info("udp: notification cannot be processed: %r", ret);

                    message_make_error(mesg, RCODE_FORMERR);
                }
            }
            else
            {
                log_info("udp: %{sockaddr} %{dnsname}: operation not supported", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg));

                message_make_error(mesg, RCODE_NOTIMP);
            }

            log_info("udp: sending reply");

            message_send_udp(mesg, server_udp_sockfd);

            message_recv_udp_reset(mesg);
            message_reset_control_size(mesg);

            log_info("udp: waiting for query");
        }
        else
        {
            // log_info("udp: no query received: %r", ret);
        }
    }

    message_free(mesg);

    free(pool);

    return NULL;
}

static ya_result
zone_load(const u8 *origin, const char *file_name)
{
    ya_result ret;
    zone_reader zr;
    struct zdb_zone_load_parms zone_load_parms;

    if(ISOK(ret = zone_reader_text_open(file_name, &zr)))
    {
        if(origin != NULL)
        {
            zone_reader_text_set_origin(&zr, origin);
        }

        log_info("loading zone from '%s'", file_name);
        zdb_zone_load_parms_init(&zone_load_parms, &zr, origin, 0);
        if(ISOK(ret = zdb_zone_load_ex(&zone_load_parms)))
        {
            log_info("%{dnsname}: loaded zone from '%s': %i", zone_load_parms.out_zone->origin, file_name, ret);

            zdb_zone *old_zone = zdb_set_zone(&db, zone_load_parms.out_zone);
            if(old_zone != NULL)
            {
                log_info("%{dnsname}: unloading previous instance of the zone (which is unexpected)", zone_load_parms.out_zone->origin);
                zdb_zone_release(old_zone);
            }

            if(ISOK(ret = journal_acquire_from_fqdn_ex(&jh, zone_load_parms.out_zone->origin, FALSE)))
            {
                u32 serial_from;
                u32 serial_to;

                journal_get_serial_range(jh, &serial_from, &serial_to);
                log_info("%{dnsname}: journal acquired [%u; %u] (%i)", zone_load_parms.out_zone->origin, serial_from, serial_to, jh->rc);
                log_info("%{dnsname}: journal released [%u; %u] (%i)", zone_load_parms.out_zone->origin, serial_from, serial_to, jh->rc);
                journal_release(jh);
            }
            else
            {
                log_info("%{dnsname}: journal not loaded: %r", zone_load_parms.out_zone->origin, ret);
                ret = SUCCESS; // no journal is not actually a problem
            }
        }
        else
        {
            log_info("failed to load zone from '%s': %r", file_name, ret);
        }

        zdb_zone_load_parms_finalize(&zone_load_parms);
    }
    else
    {
        log_info("failed to open the file '%s': %r", file_name, ret);
    }

    return ret;
}

static void help()
{
    log_info("parameters: server-ip slave-ip journal-directory [zone-file list]");
    flushout();
}

static ya_result
network_prepare()
{
    ya_result  ret;

    // prepare to listen to TCP

    struct addrinfo *ai = NULL;

    host_address2addrinfo(server_ip, &ai);

    socket_server_opensocket_s tcp_ctx;
    socket_server_opensocket_s udp_ctx;

    if(FAIL(ret = socket_server_opensocket_init(&tcp_ctx, ai, SOCK_STREAM)))
    {
        return ret;
    }

    if(FAIL(ret = socket_server_opensocket_init(&udp_ctx, ai, SOCK_DGRAM)))
    {
        return ret;
    }

    const int on = 1;

    //socket_server_opensocket_setopt(socket_server_opensocket_s *tcp_ctx, int level, int optname, void* opt, socklen_t optlen)

    if(ai->ai_family == AF_INET6)
    {
        socket_server_opensocket_setopt(&tcp_ctx, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    }

    socket_server_opensocket_setopt(&tcp_ctx, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

#ifdef SO_REUSEPORT
    socket_server_opensocket_setopt(&tcp_ctx, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif

    if(ai->ai_family == AF_INET6)
    {
        socket_server_opensocket_setopt(&udp_ctx, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
        socket_server_opensocket_setopt_ignore_error(&udp_ctx, IPPROTO_IP, DSTADDR_SOCKOPT, &on, sizeof(on));
        socket_server_opensocket_setopt_ignore_error(&udp_ctx, IPPROTO_IPV6, DSTADDR6_SOCKOPT, &on, sizeof(on));
#ifndef WIN32
        socket_server_opensocket_setopt(&udp_ctx, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
#endif
        socket_server_opensocket_setopt(&udp_ctx, IPPROTO_IPV6, DSTADDR_SOCKOPT, &on, sizeof(on));
    }
    else
    {
        socket_server_opensocket_setopt(&udp_ctx, IPPROTO_IP, DSTADDR_SOCKOPT, &on, sizeof(on));
    }

    socket_server_opensocket_setopt(&udp_ctx, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
    socket_server_opensocket_setopt(&udp_ctx, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif

    server_sockfd = socket_server_opensocket_open(&tcp_ctx);

    if(server_sockfd >= 0)
    {
        log_info("socket opened");

        fd_setcloseonexec(server_sockfd);
        fd_setnonblocking(server_sockfd);

        server_udp_sockfd = socket_server_opensocket_open(&udp_ctx);

        if(server_udp_sockfd >= 0)
        {
            log_info("UDP socket opened");

            fd_setcloseonexec(server_udp_sockfd);

            ret = SUCCESS;
            //if(ISOK(ret = fcntl(server_udp_sockfd, F_GETFL, 0)))
            {
                // fcntl(server_udp_sockfd, F_SETFL, ret | O_NONBLOCK);

                tcp_set_recvtimeout(server_udp_sockfd, 1, 0);

                if((udptp = thread_pool_init(THREAD_POOL_SIZE, THREAD_POOL_SIZE * 2)) == NULL)
                {
                    log_info("could not start the UDP thread pool");
                    return EXIT_FAILURE;
                }
            }

            log_info("network has been setup");
        }
        else
        {
            ret = server_udp_sockfd;

            log_info("could not open the UDP socket: %r", ret);
        }
    }
    else
    {
        ret = server_sockfd;

        log_info("could not open the TCP socket: %r", ret);
    }

    return ret;
}

static void
network_loop()
{
    if(ISOK(listen(server_sockfd, 10)))
    {
        log_info("listening to %{hostaddr}", server_ip);

        // wait for connections

        client_parm* parm;
        MALLOC_OBJECT_OR_DIE(parm, client_parm, GENERIC_TAG);
        parm->addr_size = sizeof(parm->addr);

        log_info("accepting connection");

        for(int i = 0; i < THREAD_POOL_SIZE; ++i)
        {
            thread_pool_enqueue_call(udptp, udp_client_thread, parm, NULL, "udpclnt");
        }

        while(!dnscore_shuttingdown())
        {
            int sockfd = accept(server_sockfd, &parm->addr.sa, &parm->addr_size);
            if(sockfd < 0)
            {
                sleep(1);
                continue;
            }

            parm->sockfd = sockfd;

            log_info("connection accepted");

            thread_pool_enqueue_call(tp, tcp_client_thread, parm, NULL, "tcpclnt");

            MALLOC_OBJECT_OR_DIE(parm, client_parm, GENERIC_TAG);
            parm->addr_size = sizeof(parm->addr);

            log_info("accepting connection");
        }

        log_info("program shutting down");

        // every x seconds, send a notify
    }
    else
    {
        ya_result err = ERRNO_ERROR;
        if(err != MAKE_ERRNO_ERROR(EPIPE))
        {
            log_info("failed to listen to %{hostaddr}: %r", server_ip, err);
        }
        else
        {
            log_err("connection to socket server is broken");
        }
    }
}

static void
signal_task_shutdown()
{
    log_info("signal_task_shutdown()");

    if(!dnscore_shuttingdown())
    {
        dnscore_shutdown();
    }

    log_info("signal_task_shutdown(): end");
}

static void
signal_int(u8 signum)
{
    (void)signum;
    signal_task_shutdown();
    signal_handler_stop();
#if DEBUG
    logger_flush();
#endif
}

static void
logger_setup()
{
    output_stream stdout_os;
    fd_output_stream_attach(&stdout_os, dup_ex(1));
    buffer_output_stream_init(&stdout_os, &stdout_os, 65536);

    logger_channel *stdout_channel = logger_channel_alloc();
    logger_channel_stream_open(&stdout_os, FALSE, stdout_channel);
    logger_channel_register("stdout", stdout_channel);

    logger_handle_create("system", &g_system_logger);
    logger_handle_add_channel("system", MSG_ALL_MASK, "stdout");

    logger_handle_create("database", &g_database_logger);
    logger_handle_add_channel("database", MSG_ALL_MASK, "stdout");

    logger_handle_create("program", &g_program_logger);
    logger_handle_add_channel("program", MSG_ALL_MASK, "stdout");
}

int
main(int argc, char *argv[])
{
    ya_result ret;
    
    
    /* initializes the core library */
    dnscore_init();
    zdb_init();
    
    if(argc < 5)
    {
        help();
        return EXIT_FAILURE;
    }

    logger_setup();

    signal_handler_init();

    signal_handler_set(SIGINT, signal_int);

    zdb_create(&db);
    
    static const anytype defaults = {._8u8={CONFIG_HOST_LIST_FLAGS_DEFAULT,1,0,0,0,0,0,0}};
    
    if(FAIL(ret = config_set_host_list(argv[1], &server_ip, defaults)))
    {
        log_info("%s is an invalid ip: %r", argv[1], ret);
        help();
        return EXIT_FAILURE;
    }

    if(server_ip->port == 0)
    {
        server_ip->port = NU16(53);
    }
    
    if(FAIL(ret = config_set_host_list(argv[2], &slave_ip, defaults)))
    {
        log_info("%s is an invalid ip: %r", argv[2], ret);
        help();
        return EXIT_FAILURE;
    }

    if(slave_ip->port == 0)
    {
        slave_ip->port = NU16(53);
    }

    strcpy(journal_directory, argv[3]);
    log_info("journal directory: '%s'", journal_directory);
    // zdb_zone_path_provider_callback *zdb_zone_path_get_provider();
    zdb_zone_path_set_provider(zone_path_provider_callback);

    if((tp = thread_pool_init(THREAD_POOL_SIZE, THREAD_POOL_SIZE * 2)) == NULL)
    {
        log_info("could not start the disk thread pool");
        return EXIT_FAILURE;
    }

    if((dtp = thread_pool_init(THREAD_POOL_SIZE, THREAD_POOL_SIZE * 2)) == NULL)
    {
        log_info("could not start the network thread pool");
        return EXIT_FAILURE;
    }

    if(FAIL(ret = network_prepare()))
    {
        log_info("network setup failed: %r", ret);
        return EXIT_FAILURE;
    }

    for(int i = 4; i < argc; ++i)
    {
        zone_load(NULL, argv[i]);
    }

    network_loop();

    flushout();
    flusherr();
    fflush(NULL);

    zdb_finalize();
    dnscore_finalize();

    return EXIT_SUCCESS;
}
