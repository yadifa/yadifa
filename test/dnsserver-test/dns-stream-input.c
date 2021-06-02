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

#include <dnscore/format.h>
#include "dns-stream-input.h"

struct dns_stream_input_data_s
{
    u8 *domain;
};

static ya_result
axfr_record_input_data_feed(struct input_stream_input_data_s *input_data)
{
    ya_result ret = SUCCESS;

    for(;;)
    {
        switch(input_data->indexes[0])
        {
            case 0:
            {
                static const u16 apex[] = {TYPE_SOA, TYPE_NS, TYPE_NS, TYPE_MX};
                static const size_t apex_size = sizeof(apex) / sizeof(u16);
                record_input_data_feed_serial_set(1);

                if(input_data->indexes[1] < apex_size)
                {
                    ret = record_input_data_feed(input_data, apex, apex_size, input_domain_get(input_data->input), &input_data->indexes[1]);
                    return ret;
                }

                ++input_data->indexes[0];
                input_data->indexes[1]= 0;
                break;
            }
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            {
                static const u16 delegation[] = {TYPE_NS, TYPE_NS};
                static const size_t delegation_size = sizeof(delegation) / sizeof(u16);

                if(input_data->indexes[1] < delegation_size)
                {

                    char fqdn[256];
                    u8 wire[256];

                    snformat(fqdn, sizeof(fqdn), "subdomain-%i.%{dnsname}", input_data->indexes[0], input_domain_get(input_data->input));
                    cstr_to_dnsname(wire, fqdn);

                    ret = record_input_data_feed(input_data, delegation, delegation_size, wire, &input_data->indexes[1]);
                    return ret;
                }

                ++input_data->indexes[0];
                input_data->indexes[1]= 0;
                break;
            }
            case 7:
            {
                static const u16 end_soa[] = {TYPE_SOA};
                static const size_t end_soa_size = sizeof(end_soa) / sizeof(u16);

                if(input_data->indexes[1] < end_soa_size)
                {
                    ret = record_input_data_feed(input_data, end_soa, end_soa_size, input_domain_get(input_data->input), &input_data->indexes[1]);
                    return ret;
                }

                ++input_data->indexes[0];
                input_data->indexes[1]= 0;
                break;
            }
            default:
            {
                ret = 0;
                return ret;
            }
        }
    }
}

static ya_result
cve_2021_25214_ixfr_record_input_data_feed(struct input_stream_input_data_s *input_data)
{
    ya_result ret = SUCCESS;

    for(;;)
    {
        switch(input_data->indexes[0])
        {
            case 0:
            {
                static const u16 last_soa[] = {TYPE_SOA};
                static const size_t apex_size = sizeof(last_soa) / sizeof(u16);
                record_input_data_feed_serial_set(2);

                ret = record_input_data_feed(input_data, last_soa, apex_size, input_domain_get(input_data->input), &input_data->indexes[1]);

                ++input_data->indexes[0];
                input_data->indexes[1]= 0;

                ++input_data->indexes[0];

                return ret;
            }
            case 1:
            {
                static const u16 remove_soa[] = {TYPE_SOA};
                static const size_t apex_size = sizeof(remove_soa) / sizeof(u16);
                record_input_data_feed_serial_set(1);

                ret = record_input_data_feed(input_data, remove_soa, apex_size, input_domain_get(input_data->input), &input_data->indexes[1]);
                //ret = record_input_data_feed(input_data, remove_soa, apex_size, "\005other", &input_data->indexes[1]);

                ++input_data->indexes[0];
                input_data->indexes[1]= 0;
                return ret;
            }
            case 2:
            {
                static const u16 remove_soa[] = {TYPE_SOA};
                static const size_t apex_size = sizeof(remove_soa) / sizeof(u16);
                record_input_data_feed_serial_set(1);

                ret = record_input_data_feed(input_data, remove_soa, apex_size, "\005other", &input_data->indexes[1]);

                ++input_data->indexes[0];
                input_data->indexes[1]= 0;
                return ret;
            }
            case 3:
            {
                static const u16 remove_records_soa[] = {TYPE_NS, TYPE_MX};
                static const size_t apex_size = sizeof(remove_records_soa) / sizeof(u16);

                ret = record_input_data_feed(input_data, remove_records_soa, apex_size, input_domain_get(input_data->input), &input_data->indexes[1]);

                if(input_data->indexes[1] >= apex_size)
                {
                    ++input_data->indexes[0];
                    input_data->indexes[1]= 0;
                }
                return ret;
            }
            case 4:
            {
                static const u16 add_soa[] = {TYPE_SOA};
                static const size_t apex_size = sizeof(add_soa) / sizeof(u16);
                record_input_data_feed_serial_set(2);

                ret = record_input_data_feed(input_data, add_soa, apex_size, input_domain_get(input_data->input), &input_data->indexes[1]);

                ++input_data->indexes[0];
                input_data->indexes[1]= 0;
                return ret;
            }
            case 5:
            {
                static const u16 add_records_soa[] = {TYPE_NS, TYPE_NS, TYPE_NS, TYPE_MX};
                static const size_t apex_size = sizeof(add_records_soa) / sizeof(u16);

                ret = record_input_data_feed(input_data, add_records_soa, apex_size, input_domain_get(input_data->input), &input_data->indexes[1]);

                if(input_data->indexes[1] >= apex_size)
                {
                    ++input_data->indexes[0];
                    input_data->indexes[1]= 0;
                }
                return ret;
            }
            case 6:
            {
                static const u16 last_soa[] = {TYPE_SOA};
                static const size_t apex_size = sizeof(last_soa) / sizeof(u16);
                record_input_data_feed_serial_set(2);

                ret = record_input_data_feed(input_data, last_soa, apex_size, input_domain_get(input_data->input), &input_data->indexes[1]);

                ++input_data->indexes[0];
                input_data->indexes[1]= 0;
                return ret;
            }
            default:
            {
                ret = 0;
                return ret;
            }
        }
    }
}

static ya_result
ixfr_record_input_data_feed(struct input_stream_input_data_s *input_data)
{
    ya_result ret = SUCCESS;

    for(;;)
    {
        switch(input_data->indexes[0])
        {
            case 0:
            {
                static const u16 last_soa[] = {TYPE_SOA};
                static const size_t apex_size = sizeof(last_soa) / sizeof(u16);
                record_input_data_feed_serial_set(2);

                ret = record_input_data_feed(input_data, last_soa, apex_size, input_domain_get(input_data->input), &input_data->indexes[1]);

                ++input_data->indexes[0];
                input_data->indexes[1]= 0;
                return ret;
            }
            case 1:
            {
                static const u16 remove_soa[] = {TYPE_SOA};
                static const size_t apex_size = sizeof(remove_soa) / sizeof(u16);
                record_input_data_feed_serial_set(1);

                ret = record_input_data_feed(input_data, remove_soa, apex_size, input_domain_get(input_data->input), &input_data->indexes[1]);

                ++input_data->indexes[0];
                input_data->indexes[1]= 0;
                return ret;
            }
            case 2:
            {
                static const u16 remove_records_soa[] = {TYPE_NS, TYPE_MX};
                static const size_t apex_size = sizeof(remove_records_soa) / sizeof(u16);

                ret = record_input_data_feed(input_data, remove_records_soa, apex_size, input_domain_get(input_data->input), &input_data->indexes[1]);

                if(input_data->indexes[1] >= apex_size)
                {
                    ++input_data->indexes[0];
                    input_data->indexes[1]= 0;
                }
                return ret;
            }
            case 3:
            {
                static const u16 add_soa[] = {TYPE_SOA};
                static const size_t apex_size = sizeof(add_soa) / sizeof(u16);
                record_input_data_feed_serial_set(2);

                ret = record_input_data_feed(input_data, add_soa, apex_size, input_domain_get(input_data->input), &input_data->indexes[1]);

                ++input_data->indexes[0];
                input_data->indexes[1]= 0;
                return ret;
            }
            case 4:
            {
                static const u16 add_records_soa[] = {TYPE_NS, TYPE_NS, TYPE_NS, TYPE_MX};
                static const size_t apex_size = sizeof(add_records_soa) / sizeof(u16);

                ret = record_input_data_feed(input_data, add_records_soa, apex_size, input_domain_get(input_data->input), &input_data->indexes[1]);

                if(input_data->indexes[1] >= apex_size)
                {
                    ++input_data->indexes[0];
                    input_data->indexes[1]= 0;
                }
                return ret;
            }
            case 5:
            {
                static const u16 last_soa[] = {TYPE_SOA};
                static const size_t apex_size = sizeof(last_soa) / sizeof(u16);
                record_input_data_feed_serial_set(2);

                ret = record_input_data_feed(input_data, last_soa, apex_size, input_domain_get(input_data->input), &input_data->indexes[1]);

                ++input_data->indexes[0];
                input_data->indexes[1]= 0;
                return ret;
            }
            default:
            {
                ret = 0;
                return ret;
            }
        }
    }
}

static const u8 *dns_stream_input_domain_get(struct input_s *input)
{
    struct dns_stream_input_data_s *data = (struct dns_stream_input_data_s*)input->data;
    return data->domain;
}

static ya_result dns_stream_input_axfr_input_stream_init(struct input_s *input, input_stream *is)
{
    ya_result ret = input_stream_input_init(is, input, axfr_record_input_data_feed);
    return ret;
}

static ya_result dns_stream_input_ixfr_input_stream_init(struct input_s *input, u32 serial_value, input_stream *is)
{
    ya_result ret = input_stream_input_init(is, input, ixfr_record_input_data_feed);
    return ret;
}

static ya_result dns_stream_input_cve_2021_25214_ixfr_input_stream_init(struct input_s *input, u32 serial_value, input_stream *is)
{
    ya_result ret = input_stream_input_init(is, input, cve_2021_25214_ixfr_record_input_data_feed);
    return ret;
}

static ya_result dns_stream_input_finalise(struct input_s *input)
{
    struct dns_stream_input_data_s *data = (struct dns_stream_input_data_s*)input->data;
    dnsname_free(data->domain);
    free(data);
    input->data = NULL;
    return SUCCESS;
}

static input_vtbl_t dns_stream_input_vtbl =
{
    dns_stream_input_domain_get,
    dns_stream_input_axfr_input_stream_init,
    dns_stream_input_ixfr_input_stream_init,
    dns_stream_input_finalise
};

ya_result
dns_stream_input_init(struct input_s *input, const u8 *fqdn)
{
    struct dns_stream_input_data_s *data;
    MALLOC_OBJECT_OR_DIE(data, struct dns_stream_input_data_s, GENERIC_TAG);
    data->domain = dnsname_dup(fqdn);
    input->data = data;
    input->vtbl = &dns_stream_input_vtbl;
}

static input_vtbl_t dns_stream_cve_2021_25214_input_vtbl =
{
    dns_stream_input_domain_get,
    dns_stream_input_axfr_input_stream_init,
    dns_stream_input_cve_2021_25214_ixfr_input_stream_init,
    dns_stream_input_finalise
};

ya_result
dns_stream_cve_2021_25214_input_init(struct input_s *input, const u8 *fqdn)
{
    struct dns_stream_input_data_s *data;
    MALLOC_OBJECT_OR_DIE(data, struct dns_stream_input_data_s, GENERIC_TAG);
    data->domain = dnsname_dup(fqdn);
    input->data = data;
    input->vtbl = &dns_stream_cve_2021_25214_input_vtbl;
}
