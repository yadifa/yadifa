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
/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 *----------------------------------------------------------------------------*/



#include <dnscore/logger_handle.h>
#include <dnscore/message.h>

#include <dnslg/dns.h>
#include <dnscore/message_dnsupdate.h>
#include <dnscore/packet_writer.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnsdb/zdb_zone_load_interface.h>
#include <dnszone/zone_file_reader.h>
#include "yazu-config.h"

/*----------------------------------------------------------------------------*/

#define MODULE_MSG_HANDLE g_client_logger
logger_handle *g_client_logger;

extern config_yazu_settings_s g_yazu_main_settings;

/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/






/** @brief Function ...
 *
 *  ...
 *
 *  @param ...
 *
 *  @retval OK
 *  @retval NOK
 */

int
//yazu_run(config_data *config)
yazu_run()
{
    ya_result                                              return_code = OK;
    message_data                                                       mesg;
    u16                                                   id = dns_new_id();

//    message_dnsupdate_data                      *entry = config->dns_update;


//    message_dnsupdate_data_show(config->dns_update);

    printf("yazu\n");
    formatln("qzone: %{dnsname}", g_yazu_main_settings.qzone);
    formatln("qttl: %lu", g_yazu_main_settings.qttl);
    formatln("qclass: %{class}", g_yazu_main_settings.qclass);
//    host_address *server = NULL;
    //   bytearray_output_stream_context os_text_context;
//    output_stream os_text;



    /* create a new stream of g_yazu_main_settings.update
     * then make the stream parseble for a zone file
     * note: normally a zone file starts with a SOA in the APEX, skip that
     *
     * read the string as a resource record and put it in 'entry'
     */
    input_stream is_text;
    char *buffer;
    u32 buffer_size;

    buffer = (char *)g_yazu_main_settings.update;
    buffer_size = (u32)strlen(buffer);

    bytearray_input_stream_init((u8*)buffer, buffer_size, &is_text, TRUE);
    zone_reader zr;


    if(ISOK(return_code = zone_file_reader_parse_stream(&is_text, &zr))) {
        zone_file_reader_ignore_missing_soa(&zr);

        packet_writer pw;
        u16 id = rand();
        u16 up_count = 0;
        message_make_dnsupdate_init(&mesg, id, g_yazu_main_settings.qzone, g_yazu_main_settings.qclass, 512, &pw);

        resource_record entry;
        resource_record_init(&entry);
        while ((return_code = zone_reader_read_record(&zr, &entry)) <= 0)
        {
            if (FAIL(return_code))
            {
                log_debug("zone_reader_read_record: %r", return_code);

                return return_code;
            }

            u8 *rdata = zone_reader_rdata(entry);
            u16 rdata_size = zone_reader_rdata_size(entry);

            packet_writer_add_record(&pw, entry.name, entry.type, entry.class, entry.ttl, rdata, rdata_size);
            up_count++;

            resource_record_resetcontent(&entry); /* "next" */
        }
    }







        return 0;
    packet_writer pw;

    if(g_yazu_main_settings.file == NULL)
    {
        if(g_yazu_main_settings.update == NULL)
        {
            return NOK;
        }

        formatln("update: %s", g_yazu_main_settings.update);
        message_make_dnsupdate_init(&mesg, id, g_yazu_main_settings.qzone, g_yazu_main_settings.qclass, 512, &pw); /** @TODO change me*/



//        message_make_dnsupdate_add_record(&mesg, &pw, entry->zname, entry->ztype, entry->zclass, entry->zttl, entry->zrdata_len, entry->zrdata);

    }
    else
    {
        formatln("file: %s", g_yazu_main_settings.file);

        u16 dnsupdata_class;

    }


 



    

//    message_make_dnsupdate_init(&mesg, id, zzone->ip.dname.dname, entry->zclass, 512, &pw); /** @TODO change me*/

    format("\n\tSEND: %d\n\n", mesg.send_length);
//    dnsupdata_class = entry->zclass;




    return return_code;
}




/*----------------------------------------------------------------------------*/

