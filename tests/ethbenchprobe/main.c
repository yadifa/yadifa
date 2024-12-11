/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 * @defgroup test
 * @ingroup test
 * @brief skeleton file
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * skeleton test program, will not be installed with a "make install"
 *
 * To create a new test based on the skeleton:
 *
 * _ copy the folder
 * _ replace "skeleton" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 * _ add the test to the CMakeLists.txt from the tests directory
 *
 *----------------------------------------------------------------------------*/

#include <ctype.h>

#include <dnscore/dnscore.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/format.h>
#include <dnscore/cmdline.h>
#include <dnscore/config_settings.h>
#include "dnscore/config_cmdline.h"
#include "dnscore/file_output_stream.h"
#include "dnscore/signals.h"

#define PROC_FILE          "/proc/net/dev"
// #define PROC_FILE "/tmp/dev"
#define TX_END_CD          5
#define SAMPLE_SIZE        86400

#define VERSION            "1.0.0"

#define MAIN_SETTINGS_NAME "main"
#define NETWORK_INTERFACE  "eth0"
#define SAMPLING_FILE_NAME "ethbenchprobe.json"
#define DEFAULT_TAG        "sampling"

struct main_settings_s
{
    char    *interface;
    char    *rx_interface;
    char    *tx_interface;
    char    *sampling_file_name;
    char    *tag;
    uint32_t tx_countdown;
    bool     sampling;
};

typedef struct main_settings_s main_settings_t;

static main_settings_t         g_main_settings;

static atomic_bool             signaled = false;

#define CONFIG_TYPE main_settings_t
CONFIG_BEGIN(main_settings_desc)
CONFIG_STRING(interface, NETWORK_INTERFACE)
CONFIG_STRING(rx_interface, NULL)
CONFIG_STRING(tx_interface, NULL)
CONFIG_STRING(sampling_file_name, SAMPLING_FILE_NAME)
CONFIG_STRING(tag, DEFAULT_TAG)
CONFIG_U32(tx_countdown, "5")
CONFIG_BOOL(sampling, "0")
CONFIG_END(main_settings_desc)
#undef CONFIG_TYPE

CMDLINE_BEGIN(main_settings_cmdline)
CMDLINE_SECTION(MAIN_SETTINGS_NAME)
CMDLINE_OPT("interface", 'i', "interface")
CMDLINE_HELP("interface-name", "the interface to monitor (both RX and TX) (" NETWORK_INTERFACE ")")
CMDLINE_OPT("rx", 'r', "rx_interface")
CMDLINE_HELP("RX-interface-name", "the interface to monitor (RX-only) (" NETWORK_INTERFACE ")")
CMDLINE_OPT("tx", 't', "tx_interface")
CMDLINE_HELP("TX-interface-name", "the interface to monitor (TX-only) (" NETWORK_INTERFACE ")")
CMDLINE_BOOL("sampling", 's', "sampling")
CMDLINE_HELP("", "enables sampling")
CMDLINE_OPT("output", 'o', "sampling_file_name")
CMDLINE_HELP("file-name", "the name of the sampling file (" SAMPLING_FILE_NAME ")")
CMDLINE_OPT("countdown", 'c', "tx_countdown")
CMDLINE_HELP("seconds",
             "if set, the program will automatically stop if no transmission happens for that amount of seconds after "
             "the first transmission")
CMDLINE_OPT("tag", 'T', "tag")
CMDLINE_HELP("text", "a tag added in the sampling file (" DEFAULT_TAG ")")

CMDLINE_MSG("", "")
CMDLINE_VERSION_HELP(main_settings_cmdline)
CMDLINE_END(main_settings_cmdline)

struct interface_s
{
    input_stream_t fis;
    char          *buffer;
    size_t         buffer_size;
};

typedef struct interface_s interface_t;

struct interface_metrics_s
{
    uint64_t rx_bytes;
    uint64_t rx_packets;
    uint64_t rx_errs;
    uint64_t rx_drop;
    uint64_t rx_fifo;
    uint64_t rx_frame;
    uint64_t rx_compressed;
    uint64_t rx_multicast;

    uint64_t tx_bytes;
    uint64_t tx_packets;
    uint64_t tx_errs;
    uint64_t tx_drop;
    uint64_t tx_fifo;
    uint64_t tx_colls;
    uint64_t tx_carrier;
    uint64_t tx_compressed;
};

typedef struct interface_metrics_s interface_metrics_t;

struct sample_s
{
    int64_t  ts;
    uint64_t rx_bytes;
    uint64_t rx_packets;
    uint64_t tx_bytes;
    uint64_t tx_packets;
};

typedef struct sample_s sample_t;

static void             signal_handler(uint8_t signum)
{
    (void)signum;
    signaled = true;
    //    puts("Signal!");
}

static ya_result interface_metrics_json_write(output_stream_t *os, const interface_metrics_t *itfm)
{
    ya_result ret = ret = osformat(os,
                                   "{"
                                   "\"rx_bytes\": %lli,"
                                   "\"rx_packets\": %lli,"
                                   "\"rx_errs\": %lli,"
                                   "\"rx_drop\": %lli,"
                                   "\"rx_fifo\": %lli,"
                                   "\"rx_frame\": %lli,"
                                   "\"rx_compressed\": %lli,"
                                   "\"rx_multicast\": %lli,"
                                   "\"tx_bytes\": %lli,"
                                   "\"tx_packets\": %lli,"
                                   "\"tx_errs\": %lli,"
                                   "\"tx_drop\": %lli,"
                                   "\"tx_fifo\": %lli,"
                                   "\"tx_colls\": %lli,"
                                   "\"tx_carrier\": %lli,"
                                   "\"tx_compressed\": %lli"
                                   "}",
                                   itfm->rx_bytes,
                                   itfm->rx_packets,
                                   itfm->rx_errs,
                                   itfm->rx_drop,
                                   itfm->rx_fifo,
                                   itfm->rx_frame,
                                   itfm->rx_compressed,
                                   itfm->rx_multicast,
                                   itfm->tx_bytes,
                                   itfm->tx_packets,
                                   itfm->tx_errs,
                                   itfm->tx_drop,
                                   itfm->tx_fifo,
                                   itfm->tx_colls,
                                   itfm->tx_carrier,
                                   itfm->tx_compressed);
    return ret;
}

static ya_result interface_open(interface_t *intf)
{
    ya_result ret = file_input_stream_open(&intf->fis, PROC_FILE);
    if(ISOK(ret))
    {
        const size_t buffer_size = 65536;
        char        *buffer = (char *)malloc(buffer_size);
        if(buffer != NULL)
        {
            intf->buffer = buffer;
            intf->buffer_size = buffer_size;
            return SUCCESS;
        }

        input_stream_close(&intf->fis);
    }

    input_stream_set_void(&intf->fis);
    intf->buffer = NULL;
    intf->buffer_size = 0;

    return ret;
}

static void interface_close(interface_t *intf)
{
    input_stream_close(&intf->fis);
    free(intf->buffer);

    input_stream_set_void(&intf->fis);
    intf->buffer = NULL;
    intf->buffer_size = 0;
}

ya_result interface_probe(interface_t *intf, const char *ifname, interface_metrics_t *im)
{
    for(;;)
    {
        // read the whole file

        int text_size = input_stream_read(&intf->fis, intf->buffer, intf->buffer_size);

        // reset the file pointer

        fd_input_stream_seek(&intf->fis, 0);

        if(text_size > 0)
        {
            // seek the interface
            char *p = intf->buffer;

            for(;;)
            {
                char *itf_end = strchr(p, ':');
                if(itf_end != NULL)
                {
                    *itf_end = '\0';
                    char *itf_start = itf_end - 1;
                    while(!isspace(*itf_start) && (itf_start > p))
                    {
                        --itf_start;
                    }
                    while(isspace(*itf_start)) // should only happen once
                    {
                        ++itf_start; // doesn't start with an interface so it should be OK
                    }
                    char *line_start = itf_end + 1;
                    char *line_end = strchr(line_start, '\n');
                    if(line_end != NULL)
                    {
                        *line_end = '\0';
                        p = line_end + 1;
                    }
                    else
                    {
                        line_end = &intf->buffer[text_size];
                    }

                    if(strcmp(itf_start, ifname) == 0)
                    {
                        if(sscanf(line_start,
                                  "%" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
                                  &im->rx_bytes,
                                  &im->rx_packets,
                                  &im->rx_errs,
                                  &im->rx_drop,
                                  &im->rx_fifo,
                                  &im->rx_frame,
                                  &im->rx_compressed,
                                  &im->rx_multicast,
                                  &im->tx_bytes,
                                  &im->tx_packets,
                                  &im->tx_errs,
                                  &im->tx_drop,
                                  &im->tx_fifo,
                                  &im->tx_colls,
                                  &im->tx_carrier,
                                  &im->tx_compressed) == 16)
                        {
                            // got the values
                            return 1;
                        }

                        return 0;
                    }
                } // if(itf_end != NULL)
                else
                {
                    return MAKE_ERRNO_ERROR(ENOENT);
                }
            } // for(;;)
        }
        else if(text_size < 0)
        {
            formatln("error reading metrics: %r", text_size);
            return text_size;
        }
        else
        {
            return 0;
        }
    }
}

static ya_result interface_follow(const char *rx_interface, const char *tx_interface, const char *sampling_file, const char *tag, uint64_t tx_countdown)
{
    sample_t  *samples;
    const bool sampling = sampling_file != NULL;

    if(sampling)
    {
        samples = (sample_t *)malloc(sizeof(sample_t) * SAMPLE_SIZE);
    }
    else
    {
        samples = NULL;
    }

    size_t              samples_count = 0;

    int64_t             ts_begin = timeus();
    int64_t             rx_begin = 0; // probed
    int64_t             rx_end = 0;   // probed
    int64_t             tx_begin = 0; // probed
    int64_t             tx_end = 0;   // probed

    interface_t         intf; // common for both interfaces

    interface_metrics_t rx_im_begin; // initial state
    interface_metrics_t tx_im_begin;
    interface_metrics_t rx_im_end; // final state
    interface_metrics_t tx_im_end;

    uint64_t            rx_packets_prev = 0;
    uint64_t            rx_bytes_prev = 0;
    uint64_t            tx_packets_prev = 0;
    uint64_t            tx_bytes_prev = 0;

    ZEROMEMORY(&rx_im_begin, sizeof(interface_metrics_t));
    ZEROMEMORY(&tx_im_begin, sizeof(interface_metrics_t));
    ZEROMEMORY(&rx_im_end, sizeof(interface_metrics_t));
    ZEROMEMORY(&tx_im_end, sizeof(interface_metrics_t));

    interface_open(&intf);

    // get both initial states

    if(interface_probe(&intf, rx_interface, &rx_im_begin) != 1)
    {
        interface_close(&intf);
        return INVALID_STATE_ERROR;
    }

    if(interface_probe(&intf, tx_interface, &tx_im_begin) != 1)
    {
        interface_close(&intf);
        return INVALID_STATE_ERROR;
    }

    uint64_t rx_packets_first = rx_im_begin.rx_packets;
    uint64_t tx_packets_first = tx_im_begin.tx_packets;

    for(;;)
    {
        int64_t now = timeus();

        // keep track of TX, in case transmissions happen before receptions (which would be wrong)

        if(interface_probe(&intf, tx_interface, &tx_im_begin) == 1)
        {
            if((tx_begin == 0) && (tx_im_begin.tx_packets > tx_packets_first))
            {
                tx_begin = now; // first and last TX timestamps
                tx_end = now;
            }
        }

        if(interface_probe(&intf, rx_interface, &rx_im_begin) == 1)
        {
            if(rx_im_begin.rx_packets > rx_packets_first)
            {
                rx_begin = now; // first and last RX timestamps
                rx_end = now;
                break;
            }
        }

        if(signaled)
        {
            exit(EXIT_SUCCESS);
        }

        usleep(10000);
    }

    int64_t  approx_one_sec = 1000000;

    uint64_t rx_packets_last = rx_im_begin.rx_packets;
    uint64_t tx_packets_last = tx_im_begin.tx_packets;

    // keep track of the 4 most important values

    rx_packets_prev = rx_im_begin.rx_packets;
    rx_bytes_prev = rx_im_begin.rx_bytes;
    tx_packets_prev = tx_im_begin.tx_packets;
    tx_bytes_prev = tx_im_begin.tx_bytes;

    uint64_t tx_countdown_current = tx_countdown;

    for(;;)
    {
        int64_t now = timeus();

        if(interface_probe(&intf, rx_interface, &rx_im_end) == 1)
        {
            if(rx_packets_last < rx_im_end.rx_packets)
            {
                rx_end = now;
                rx_packets_last = rx_im_end.rx_packets;
            }
        }

        if(interface_probe(&intf, tx_interface, &tx_im_end) == 1)
        {
            if((tx_begin == 0) && (tx_im_end.tx_packets > tx_packets_first))
            {
                tx_begin = now;
            }

            if(tx_packets_last < tx_im_end.tx_packets)
            {
                tx_end = now;
                tx_packets_last = tx_im_end.tx_packets;
                tx_countdown_current = tx_countdown; // waits for 5 seconds without changes before stopping
            }
            else
            {
                // if the countdown is enabled and there has been at least one transmission

                if((tx_countdown > 0) && (tx_begin != 0))
                {
                    if(--tx_countdown_current <= 0)
                    {
                        break;
                    }
                }
            }

            if(signaled)
            {
                break;
            }

            if(sampling)
            {
                int64_t dt = now - rx_begin;
                int64_t delay = (dt % 1000000) / 2;
                if(delay > 0)
                {
                    approx_one_sec = 1000000 - delay;
                }

                samples[samples_count].ts = dt;
                samples[samples_count].rx_packets = rx_im_end.rx_packets - rx_packets_prev;
                samples[samples_count].rx_bytes = rx_im_end.rx_bytes - rx_bytes_prev;
                samples[samples_count].tx_packets = tx_im_end.tx_packets - tx_packets_prev;
                samples[samples_count].tx_bytes = tx_im_end.tx_bytes - tx_bytes_prev;
                ++samples_count;

                rx_packets_prev = rx_im_end.rx_packets;
                rx_bytes_prev = rx_im_end.rx_bytes;
                tx_packets_prev = tx_im_end.tx_packets;
                tx_bytes_prev = tx_im_end.tx_bytes;
            }
        }
        usleep(approx_one_sec);
    }

    interface_close(&intf);

    formatln("rx-packets: %llu", rx_im_end.rx_packets - rx_im_begin.rx_packets);
    formatln("rx-bytes: %llu", rx_im_end.rx_bytes - rx_im_begin.rx_bytes);
    formatln("tx-packets: %llu", tx_im_end.tx_packets - tx_im_begin.tx_packets);
    formatln("tx-bytes: %llu", tx_im_end.tx_bytes - tx_im_begin.tx_bytes);
    formatln("rx-first-ts: %lli", MAX(rx_begin - ts_begin, 0));
    formatln("tx-first-ts: %lli", MAX(tx_begin - ts_begin, 0));
    formatln("rx-last-ts: %lli", MAX(rx_end - ts_begin, 0));
    formatln("tx-last-ts: %lli", MAX(tx_end - ts_begin, 0));
    flushout();

    if(sampling && (samples_count > 0))
    {
        for(; samples_count > 0; --samples_count)
        {
            if((samples[samples_count].rx_packets > 0) || (samples[samples_count].tx_packets > 0))
            {
                break;
            }
        }

        ya_result       ret;
        output_stream_t os;
        ret = file_output_stream_create(&os, sampling_file, 0640);
        if(ISOK(ret))
        {
            osformat(&os, "{\"tag\": \"%s\", \"rx-interface\": \"%s\", \"tx-interface\": \"%s\", \"samples\": [", tag, rx_interface, tx_interface);
            for(size_t i = 0; i < samples_count; ++i)
            {
                if(i > 0)
                {
                    osprint(&os, ",");
                }

                osformat(&os,
                         "{\"timeStamp\": %lli,\"rx-packets\": %llu,\"rx-bytes\": %llu,\"tx-packets\": "
                         "%llu,\"tx-bytes\": %llu}",
                         samples[i].ts,
                         samples[i].rx_packets,
                         samples[i].rx_bytes,
                         samples[i].tx_packets,
                         samples[i].tx_bytes);
            }
            osprint(&os, "], \"begin-raw\": ");

            interface_metrics_json_write(&os, &rx_im_begin);

            osprint(&os, ", \"end-raw\": ");

            interface_metrics_json_write(&os, &rx_im_end);

            osprint(&os, "}");
            output_stream_close(&os);
        }
        else
        {
            formatln("failed to create '%s': %r", sampling_file, ret);
            return ret;
        }
    }

    return SUCCESS;
}

static void help(const char *name)
{
    formatln("%s [args]\n\n", name);
    cmdline_print_help(main_settings_cmdline, termout);
}

static ya_result main_config(int argc, char *argv[])
{
    config_error_t cfgerr;
    ya_result      ret;

    config_init();

    int priority = 0;

    config_register_struct(MAIN_SETTINGS_NAME, main_settings_desc, &g_main_settings, priority++);

    config_register_cmdline(priority++); // without this line, the help will not work

    struct config_source_s sources[1];

    if(FAIL(ret = config_source_set_commandline(&sources[0], main_settings_cmdline, argc, argv)))
    {
        formatln("command line definition: %r", ret);
        return ret;
    }

    config_error_init(&cfgerr);

    if(FAIL(ret = config_read_from_sources(sources, 1, &cfgerr)))
    {
        formatln("settings: (%s:%i) %s: %r", cfgerr.file, cfgerr.line_number, cfgerr.line, ret);
        flushout();

        config_error_finalise(&cfgerr);

        return ret;
    }

    config_error_finalise(&cfgerr);

    if(g_main_settings.rx_interface == NULL)
    {
        g_main_settings.rx_interface = g_main_settings.interface;
    }

    if(g_main_settings.tx_interface == NULL)
    {
        g_main_settings.tx_interface = g_main_settings.interface;
    }

    if(cmdline_help_get())
    {
        help(argv[0]);
        return SUCCESS;
    }

    if(cmdline_version_get())
    {
        println("Version " VERSION);
        return SUCCESS;
    }

    return 1;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    /* initializes the core library */
    dnscore_init();
    ya_result ret = main_config(argc, argv);

    if(ISOK(ret))
    {
        if(ret == 1)
        {
            signal_handler_init();
            signal_handler_set(SIGTERM, signal_handler);
            signal_handler_set(SIGINT, signal_handler);
            interface_follow(g_main_settings.rx_interface, g_main_settings.tx_interface, g_main_settings.sampling ? g_main_settings.sampling_file_name : NULL, g_main_settings.tag, g_main_settings.tx_countdown);
        }
        else
        {
            // help was printed.
        }
    }
    else
    {
        formatln("main_config returned: %r", ret);
    }

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
