/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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

#include "yatest.h"
#include "yatest_stream.h"
#include "dnscore/network.h"
#include "dnscore/file_output_stream.h"
#include <dnscore/fdtools.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/logger_channel_stream.h>
#include <dnscore/logger_channel_file.h>
#include <dnscore/logger_channel_pipe.h>
#include <dnscore/logger_channel_syslog.h>
#include <dnscore/dnscore.h>
#include <dnscore/logger.h>

#define CHANNEL_OUTPUT_STTREAM_BUFFER_SIZE 0x1000000

static logger_handle_t  *handle = LOGGER_HANDLE_SINK;
static logger_channel_t *channel;
// static logger_channel_t *bad_stream_channel;
static logger_channel_t *file_channel;
static logger_channel_t *bad_file_channel;
static logger_channel_t *bad_file_channel_id;
static logger_channel_t *file_channel_deleted;
static logger_channel_t *pipe_channel;
static logger_channel_t *bad_pipe_channel;
static logger_channel_t *syslog_channel;
static output_stream_t   channel_output_stream;

struct hack_logger_channel_file_s
{
    output_stream_t os;
    char           *file_name;
    int             fd;
    uid_t           uid;
    gid_t           gid;
    uint16_t        mode;
    bool            force_flush;
};

typedef struct hack_logger_channel_file_s hack_logger_channel_file_t;

static const char                        *find_eol_or_eof(const char *text)
{
    char c;
    for(;; ++text)
    {
        c = *text;
        if((c == '\n') || (c == '\0'))
        {
            return text;
        }
    }
}

static bool logger_output_line_matches(const char *logger_line, int logger_line_size, const char *text, int text_size)
{
    // this doesn't work because of one exception in the format
    /*
    // a logger output line starts with:
    static char header_template[] = "####-##-## ##:##:##.###### | ###### | ???????? | handle   ";
    if(logger_line_size < sizeof(header_template) - 1)
    {
        yatest_err("logger_line is not a log line");
        yatest_hexdump_err(logger_line, logger_line + logger_line_size);
        return false;
    }
    logger_line += sizeof(header_template) - 1;
    logger_line_size -= sizeof(header_template) - 1;
    */
    int separator_count = 0;
    while(*logger_line != '\0')
    {
        if(*logger_line == '|')
        {
            ++separator_count;
            if(separator_count == 4)
            {
                break;
            }
        }
        ++logger_line;
        --logger_line_size;
    }

    if(logger_line_size == text_size)
    {
        if(memcmp(logger_line, text, text_size) == 0)
        {
            return true;
        }
    }

    yatest_err("logger_output_line_matches: false");
    yatest_err("got:");
    yatest_hexdump_err(logger_line, logger_line + logger_line_size);
    yatest_err("expected:");
    yatest_hexdump_err(text, text + text_size);
    return false;
}

static int logger_output_matches(const char *logger_output, const char *text)
{
    // split into lines
    for(;;)
    {
        const char *logger_line = logger_output;
        const char *logger_line_limit = find_eol_or_eof(logger_line);
        const char *text_line = text;
        const char *text_line_limit = find_eol_or_eof(text_line);
        if(logger_line_limit == logger_line)
        {
            return text_line_limit == text_line;
        }
        if(!logger_output_line_matches(logger_line, logger_line_limit - logger_line, text_line, text_line_limit - text_line))
        {
            return false;
        }
        if((*logger_line_limit == '\0') || (*text_line_limit == '\0'))
        {
            return (*logger_line_limit == '\0') && (*text_line_limit == '\0');
        }
        logger_output = logger_line_limit + 1;
        text = text_line_limit + 1;
    }
}

static void init()
{
    int ret;
    dnscore_init();
    logger_start();

    signal(SIGPIPE, SIG_IGN);

    logger_handle_create("handle", &handle);
    bytearray_output_stream_init(&channel_output_stream, NULL, CHANNEL_OUTPUT_STTREAM_BUFFER_SIZE);
    output_stream_t os = channel_output_stream;
    channel = logger_channel_alloc();
    logger_channel_stream_open(&os, false, channel);
    logger_channel_register("channel", channel);
    logger_handle_add_channel("handle", MSG_ALL_MASK, "channel");
    /*
        output_stream_t bad_stream;
        fd_output_stream_attach(&bad_stream, -1);
        bad_stream_channel = logger_channel_alloc();
        logger_channel_stream_open(&bad_stream, false, bad_stream_channel);
        logger_channel_register("bad-stream", bad_stream_channel);
        //logger_handle_add_channel("handle", MSG_ALL_MASK, "bad-stream");
    */
    unlink_ex("/tmp", "file-logger-test.log");
    unlink_ex("/tmp", "pipe-logger-test.log");

    file_channel = logger_channel_alloc();
    ret = logger_channel_file_open("/tmp/file-logger-test.log", getuid(), getgid(), 0644, true, file_channel);
    if(FAIL(ret))
    {
        yatest_err("logger_channel_file_open failed with %08x = %s", ret, error_gettext(ret));
        exit(1);
    }
    logger_channel_register("file", file_channel);
    logger_handle_add_channel("handle", MSG_ALL_MASK, "file");

    file_channel_deleted = logger_channel_alloc();
    ret = logger_channel_file_open("/tmp/file-logger-test.log.deleted", getuid(), getgid(), 0644, true, file_channel_deleted);
    if(FAIL(ret))
    {
        yatest_err("logger_channel_file_open failed with %08x = %s (deleted)", ret, error_gettext(ret));
        exit(1);
    }
    logger_channel_register("file-deleted", file_channel_deleted);
    logger_handle_add_channel("handle", MSG_ALL_MASK, "file-deleted");

    bad_file_channel = logger_channel_alloc();
    ret = logger_channel_file_open("/tmp/file-logger-test-to-corrupt.log", getuid(), getgid(), 0644, true, bad_file_channel);
    if(FAIL(ret))
    {
        yatest_err("logger_channel_file_open failed with %08x = %s (bad-file)", ret, error_gettext(ret));
        exit(1);
    }
    logger_channel_register("bad-file", bad_file_channel);
    logger_handle_add_channel("handle", MSG_ALL_MASK, "bad-file");
    logger_channel_file_rename(bad_file_channel, "/dev/no/such/file/will.break");

    bad_file_channel_id = logger_channel_alloc();
    ret = logger_channel_file_open("/tmp/file-logger-test-to-corrupt-id.log", getuid(), getgid(), 0644, true, bad_file_channel_id);
    if(FAIL(ret))
    {
        yatest_err("logger_channel_file_open failed with %08x = %s (bad-file-id)", ret, error_gettext(ret));
        exit(1);
    }
    logger_channel_register("bad-file-id", bad_file_channel_id);
    logger_handle_add_channel("handle", MSG_ALL_MASK, "bad-file-id");
    // @note 20240606 edf -- without hacking into the structure, I can't possibly produce an uid/gid error on demand
    hack_logger_channel_file_t *bad_file_channel_id_data = (hack_logger_channel_file_t *)bad_file_channel_id->data;
    bad_file_channel_id_data->uid = 0;
    bad_file_channel_id_data->gid = 0;

    pipe_channel = logger_channel_alloc();
    ret = logger_channel_pipe_open("|/usr/bin/cat>/tmp/pipe-logger-test.log", true, pipe_channel);
    if(FAIL(ret))
    {
        yatest_err("logger_channel_pipe_open failed with %08x = %s", ret, error_gettext(ret));
        exit(1);
    }
    logger_channel_register("pipe", pipe_channel);
    logger_handle_add_channel("handle", MSG_ALL_MASK, "pipe");

    bad_pipe_channel = logger_channel_alloc();
    ret = logger_channel_pipe_open("|/usr/bin/-cat-no-such-program->/tmp/bad-pipe-logger-test.log", true, bad_pipe_channel);
    if(FAIL(ret))
    {
        yatest_err("logger_channel_pipe_open failed with %08x = %s (bad)", ret, error_gettext(ret));
        exit(1);
    }
    logger_channel_register("bad-pipe", bad_pipe_channel);
    logger_handle_add_channel("handle", MSG_ALL_MASK, "bad-pipe");

    syslog_channel = logger_channel_alloc();
    logger_channel_syslog_open("logger-test", LOG_PID, LOG_USER, syslog_channel);
    logger_channel_register("syslog", syslog_channel);
    logger_handle_add_channel("handle", MSG_ALL_MASK, "syslog");

    logger_handle_exit_level(0);
    logger_handle_exit_level(MSG_CRIT);

    logger_flush();

    logger_set_level(logger_get_level());
    logger_wait_started();

    if(logger_is_self())
    {
        yatest_err("logger_is_self did return true");
        exit(1);
    }

    unlink("/tmp/file-logger-test.log.deleted");
}

static void finalise()
{
    int channel_count = logger_handle_count_channels("handle");
    yatest_log("channel_count=%i", channel_count);
    int usage_count = logger_channel_get_usage_count("channel");
    yatest_log("usage_count=%i", usage_count);
    logger_handle_remove_channel("handle", "syslog");
    logger_channel_unregister("syslog");
    logger_handle_remove_channel("handle", "bad-pipe");
    logger_channel_unregister("bad-pipe");
    logger_handle_remove_channel("handle", "pipe");
    logger_channel_unregister("pipe");
    logger_handle_remove_channel("handle", "file");
    logger_channel_unregister("file");
    logger_handle_remove_channel("handle", "bad-stream");
    logger_channel_unregister("bad-stream");
    // logger_handle_remove_channel("handle", "channel");
    // logger_channel_unregister("channel");
    logger_channel_close_all();
    int usage_count_after_close_all = logger_channel_get_usage_count("channel");
    yatest_log("usage_count_after_close_all=%i", usage_count_after_close_all);
    logger_handle_close("handle");
    logger_stop();
    int channel_count_after_stop = logger_handle_count_channels("handle");
    yatest_log("channel_count_after_stop=%i", channel_count_after_stop);
    dnscore_finalize();
}

static int logger_handle_msg_test()
{
    init();
    for(int level = MSG_DEBUG7; level > MSG_CRIT; --level)
    {
        logger_handle_msg(handle, level, "text-%i", level);
    }
    logger_flush();
    output_stream_write_u8(&channel_output_stream, 0);
    yatest_log("'%s'", bytearray_output_stream_buffer(&channel_output_stream));
    static const char expected_output[] =
        "| 7 | text-14\n"
        "| 6 | text-13\n"
        "| 5 | text-12\n"
        "| 4 | text-11\n"
        "| 3 | text-10\n"
        "| 2 | text-9\n"
        "| 1 | text-8\n"
        "| D | text-7\n"
        "| I | text-6\n"
        "| N | text-5\n"
        "| W | text-4\n"
        "| E | text-3\n";
    if(!logger_output_matches((char *)bytearray_output_stream_buffer(&channel_output_stream), expected_output))
    {
        yatest_err("no match");
        return 1;
    }
    finalise();
    return 0;
}

static int logger_handle_msg_nocull_test()
{
    init();
    for(int level = MSG_DEBUG7; level > MSG_CRIT; --level)
    {
        logger_handle_msg_nocull(handle, level, "text-%i", level);
    }
    logger_flush();
    output_stream_write_u8(&channel_output_stream, 0);
    yatest_log("'%s'", bytearray_output_stream_buffer(&channel_output_stream));
    static const char expected_output[] =
        "| 7 | text-14\n"
        "| 6 | text-13\n"
        "| 5 | text-12\n"
        "| 4 | text-11\n"
        "| 3 | text-10\n"
        "| 2 | text-9\n"
        "| 1 | text-8\n"
        "| D | text-7\n"
        "| I | text-6\n"
        "| N | text-5\n"
        "| W | text-4\n"
        "| E | text-3\n";
    if(!logger_output_matches((char *)bytearray_output_stream_buffer(&channel_output_stream), expected_output))
    {
        yatest_err("no match");
        return 1;
    }
    finalise();
    return 0;
}

static int logger_handle_msg_text_test()
{
    init();
    for(int level = MSG_DEBUG7; level > MSG_CRIT; --level)
    {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "text-%i", level);
        logger_handle_msg_text(handle, level, tmp, strlen(tmp));
    }
    logger_flush();
    output_stream_write_u8(&channel_output_stream, 0);
    yatest_log("'%s'", bytearray_output_stream_buffer(&channel_output_stream));
    static const char expected_output[] =
        "| 7 | text-14\n"
        "| 6 | text-13\n"
        "| 5 | text-12\n"
        "| 4 | text-11\n"
        "| 3 | text-10\n"
        "| 2 | text-9\n"
        "| 1 | text-8\n"
        "| D | text-7\n"
        "| I | text-6\n"
        "| N | text-5\n"
        "| W | text-4\n"
        "| E | text-3\n";
    if(!logger_output_matches((char *)bytearray_output_stream_buffer(&channel_output_stream), expected_output))
    {
        yatest_err("no match");
        return 1;
    }
    finalise();
    return 0;
}

static int logger_handle_msg_text_ext_test()
{
    init();
    for(int level = MSG_DEBUG7; level > MSG_CRIT; --level)
    {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "%i", level);
        static const char prefix[] = " | ###### | ???????? | handle   | X | text-";
        logger_handle_msg_text_ext(handle, level, tmp, strlen(tmp), prefix, sizeof(prefix) - 1, LOGGER_MESSAGE_TIMEMS | LOGGER_MESSAGE_PREFIX);
    }
    logger_flush();
    output_stream_write_u8(&channel_output_stream, 0);
    uint8_t *text_buffer = bytearray_output_stream_buffer(&channel_output_stream);
    yatest_log("'%s'", (char*)text_buffer);
    static const char expected_output[] =
        "| X | text-14\n"
        "| X | text-13\n"
        "| X | text-12\n"
        "| X | text-11\n"
        "| X | text-10\n"
        "| X | text-9\n"
        "| X | text-8\n"
        "| X | text-7\n"
        "| X | text-6\n"
        "| X | text-5\n"
        "| X | text-4\n"
        "| X | text-3\n";
    if(!logger_output_matches((char *)bytearray_output_stream_buffer(&channel_output_stream), expected_output))
    {
        yatest_err("no match");
        return 1;
    }
    finalise();
    return 0;
}

static int logger_handle_try_msg_test()
{
    init();
    for(int level = MSG_DEBUG7; level > MSG_CRIT; --level)
    {
        logger_handle_try_msg(handle, level, "text-%i", level);
    }
    logger_flush();
    output_stream_write_u8(&channel_output_stream, 0);
    yatest_log("'%s'", bytearray_output_stream_buffer(&channel_output_stream));
    static const char expected_output[] =
        "| 7 | text-14\n"
        "| 6 | text-13\n"
        "| 5 | text-12\n"
        "| 4 | text-11\n"
        "| 3 | text-10\n"
        "| 2 | text-9\n"
        "| 1 | text-8\n"
        "| D | text-7\n"
        "| I | text-6\n"
        "| N | text-5\n"
        "| W | text-4\n"
        "| E | text-3\n";
    if(!logger_output_matches((char *)bytearray_output_stream_buffer(&channel_output_stream), expected_output))
    {
        yatest_err("no match");
        return 1;
    }
    finalise();
    return 0;
}

static int logger_handle_try_msg_text_test()
{
    init();
    for(int level = MSG_DEBUG7; level > MSG_CRIT; --level)
    {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "text-%i", level);
        logger_handle_try_msg_text(handle, level, tmp, strlen(tmp));
    }
    logger_flush();
    output_stream_write_u8(&channel_output_stream, 0);
    yatest_log("'%s'", bytearray_output_stream_buffer(&channel_output_stream));
    static const char expected_output[] =
        "| 7 | text-14\n"
        "| 6 | text-13\n"
        "| 5 | text-12\n"
        "| 4 | text-11\n"
        "| 3 | text-10\n"
        "| 2 | text-9\n"
        "| 1 | text-8\n"
        "| D | text-7\n"
        "| I | text-6\n"
        "| N | text-5\n"
        "| W | text-4\n"
        "| E | text-3\n";
    if(!logger_output_matches((char *)bytearray_output_stream_buffer(&channel_output_stream), expected_output))
    {
        yatest_err("no match");
        return 1;
    }
    finalise();
    return 0;
}

static int log_memdump_ex_test()
{
    init();
    log_memdump_set_layout(3, 255);
    log_memdump_ex(handle, MSG_INFO, yatest_lorem_ipsum, sizeof(yatest_lorem_ipsum), 64, OSPRINT_DUMP_BUFFER);
    logger_flush();
    yatest_log("'%s'", bytearray_output_stream_buffer(&channel_output_stream));
    static const char expected_output[] =
        "| I | 0000 | 4c6f7265 6d206970 73756d20 646f6c6f 72207369 7420616d 65742c20 636f6e73 65637465 74757220 "
        "61646970 69736369 6e672065 6c69742c 20736564 20646f20  |  Lorem ipsum dolor sit amet, consectetur adipiscing "
        "elit, sed do \n"
        "| I | 0040 | 65697573 6d6f6420 74656d70 6f722069 6e636964 6964756e 74207574 206c6162 6f726520 65742064 "
        "6f6c6f72 65206d61 676e6120 616c6971 75612e0a 56657374  |  eiusmod tempor incididunt ut labore et dolore magna "
        "aliqua..Vest\n"
        "| I | 0080 | 6962756c 756d2073 65642061 72637520 6e6f6e20 6f64696f 20657569 736d6f64 206c6163 696e6961 "
        "2061742e 0a4d6175 72697320 73697420 616d6574 206d6173  |  ibulum sed arcu non odio euismod lacinia at..Mauris "
        "sit amet mas\n"
        "| I | 00C0 | 73612076 69746165 20746f72 746f7220 636f6e64 696d656e 74756d20 6c616369 6e696120 71756973 "
        "2076656c 2e0a4d61 74746973 20656e69 6d207574 2074656c  |  sa vitae tortor condimentum lacinia quis "
        "vel..Mattis enim ut tel\n"
        "| I | 0100 | 6c757320 656c656d 656e7475 6d207361 67697474 69732076 69746165 20657420 6c656f20 64756973 "
        "2e0a5369 7420616d 65742063 6f6e7365 63746574 75722061  |  lus elementum sagittis vitae et leo duis..Sit amet "
        "consectetur a\n"
        "| I | 0140 | 64697069 7363696e 6720656c 69742075 7420616c 69717561 6d207075 72757320 7369742e 0a4e6973 "
        "6920706f 72746120 6c6f7265 6d206d6f 6c6c6973 20616c69  |  dipiscing elit ut aliquam purus sit..Nisi porta "
        "lorem mollis ali\n"
        "| I | 0180 | 7175616d 2e0a4120 65726174 206e616d 20617420 6c656374 75732075 726e6120 64756973 2e0a436f "
        "6e736571 75617420 69642070 6f727461 206e6962 68207665  |  quam..A erat nam at lectus urna duis..Consequat id "
        "porta nibh ve\n"
        "| I | 01C0 | 6e656e61 74697320 63726173 20736564 2066656c 69732e0a 52697375 73206e75 6c6c616d 20656765 "
        "74206665 6c697320 65676574 206e756e 63206c6f 626f7274  |  nenatis cras sed felis..Risus nullam eget felis "
        "eget nunc lobort\n"
        "| I | 0200 | 6973206d 61747469 7320616c 69717561 6d206661 75636962 75732e0a 00                                "
        "                                                |  is mattis aliquam faucibus...\n";
    if(!logger_output_matches((char *)bytearray_output_stream_buffer(&channel_output_stream), expected_output))
    {
        yatest_err("no match");
        return 1;
    }
    finalise();
    return 0;
}

static int log_memdump_test()
{
    init();
    log_memdump_set_layout(3, 255);
    log_memdump(handle, MSG_INFO, yatest_lorem_ipsum, sizeof(yatest_lorem_ipsum), 64);
    logger_flush();
    yatest_log("'%s'", bytearray_output_stream_buffer(&channel_output_stream));
    static const char expected_output[] =
        "| I | 4c6f7265 6d206970 73756d20 646f6c6f 72207369 7420616d 65742c20 636f6e73 65637465 74757220 61646970 "
        "69736369 6e672065 6c69742c 20736564 20646f20  |  Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed "
        "do \n"
        "| I | 65697573 6d6f6420 74656d70 6f722069 6e636964 6964756e 74207574 206c6162 6f726520 65742064 6f6c6f72 "
        "65206d61 676e6120 616c6971 75612e0a 56657374  |  eiusmod tempor incididunt ut labore et dolore magna "
        "aliqua..Vest\n"
        "| I | 6962756c 756d2073 65642061 72637520 6e6f6e20 6f64696f 20657569 736d6f64 206c6163 696e6961 2061742e "
        "0a4d6175 72697320 73697420 616d6574 206d6173  |  ibulum sed arcu non odio euismod lacinia at..Mauris sit amet "
        "mas\n"
        "| I | 73612076 69746165 20746f72 746f7220 636f6e64 696d656e 74756d20 6c616369 6e696120 71756973 2076656c "
        "2e0a4d61 74746973 20656e69 6d207574 2074656c  |  sa vitae tortor condimentum lacinia quis vel..Mattis enim ut "
        "tel\n"
        "| I | 6c757320 656c656d 656e7475 6d207361 67697474 69732076 69746165 20657420 6c656f20 64756973 2e0a5369 "
        "7420616d 65742063 6f6e7365 63746574 75722061  |  lus elementum sagittis vitae et leo duis..Sit amet "
        "consectetur a\n"
        "| I | 64697069 7363696e 6720656c 69742075 7420616c 69717561 6d207075 72757320 7369742e 0a4e6973 6920706f "
        "72746120 6c6f7265 6d206d6f 6c6c6973 20616c69  |  dipiscing elit ut aliquam purus sit..Nisi porta lorem mollis "
        "ali\n"
        "| I | 7175616d 2e0a4120 65726174 206e616d 20617420 6c656374 75732075 726e6120 64756973 2e0a436f 6e736571 "
        "75617420 69642070 6f727461 206e6962 68207665  |  quam..A erat nam at lectus urna duis..Consequat id porta "
        "nibh ve\n"
        "| I | 6e656e61 74697320 63726173 20736564 2066656c 69732e0a 52697375 73206e75 6c6c616d 20656765 74206665 "
        "6c697320 65676574 206e756e 63206c6f 626f7274  |  nenatis cras sed felis..Risus nullam eget felis eget nunc "
        "lobort\n"
        "| I | 6973206d 61747469 7320616c 69717561 6d206661 75636962 75732e0a 00                                       "
        "                                         |  is mattis aliquam faucibus...\n";
    if(!logger_output_matches((char *)bytearray_output_stream_buffer(&channel_output_stream), expected_output))
    {
        yatest_err("no match");
        return 1;
    }
    finalise();
    return 0;
}

static int log_msghdr_test()
{
    init();
    char            control[4] = {0, 1, 2, 3};
    socketaddress_t ss;
    memset(&ss, 0, sizeof(ss));
    struct iovec  vec;
    struct msghdr hdr;
    ss.sa4.sin_family = AF_INET;
    ss.sa4.sin_port = NU16(53);
    ss.sa4.sin_addr.s_addr = NU32(0x7f000001);
    hdr.msg_controllen = sizeof(control);
    hdr.msg_control = control;
    hdr.msg_flags = 0;
    hdr.msg_iov = &vec;
    hdr.msg_iovlen = 1;
    hdr.msg_name = &ss;
    hdr.msg_namelen = sizeof(struct sockaddr_in);
    vec.iov_base = (void *)yatest_lorem_ipsum;
    vec.iov_len = sizeof(yatest_lorem_ipsum);

    log_memdump_set_layout(3, 255);
    log_msghdr(handle, MSG_INFO, &hdr);
    logger_flush();
    output_stream_write_u8(&channel_output_stream, 0);
    yatest_log("'%s'", bytearray_output_stream_buffer(&channel_output_stream));
    static const char expected_output[] =
        "| I | udp message header:\n"
        "| I | msg_name: 127.0.0.1#53\n"
        "| I | 0000 | 02000035 7f000001 00000000 00000000                                      |  ...5............\n"
        "| I | msg_iov[0]:\n"
        "| I | 0000 | 4c6f7265 6d206970 73756d20 646f6c6f 72207369 7420616d 65742c20 636f6e73  |  Lorem ipsum dolor "
        "sit amet, cons\n"
        "| I | 0020 | 65637465 74757220 61646970 69736369 6e672065 6c69742c 20736564 20646f20  |  ectetur adipiscing "
        "elit, sed do \n"
        "| I | 0040 | 65697573 6d6f6420 74656d70 6f722069 6e636964 6964756e 74207574 206c6162  |  eiusmod tempor "
        "incididunt ut lab\n"
        "| I | 0060 | 6f726520 65742064 6f6c6f72 65206d61 676e6120 616c6971 75612e0a 56657374  |  ore et dolore magna "
        "aliqua..Vest\n"
        "| I | 0080 | 6962756c 756d2073 65642061 72637520 6e6f6e20 6f64696f 20657569 736d6f64  |  ibulum sed arcu non "
        "odio euismod\n"
        "| I | 00A0 | 206c6163 696e6961 2061742e 0a4d6175 72697320 73697420 616d6574 206d6173  |   lacinia at..Mauris "
        "sit amet mas\n"
        "| I | 00C0 | 73612076 69746165 20746f72 746f7220 636f6e64 696d656e 74756d20 6c616369  |  sa vitae tortor "
        "condimentum laci\n"
        "| I | 00E0 | 6e696120 71756973 2076656c 2e0a4d61 74746973 20656e69 6d207574 2074656c  |  nia quis vel..Mattis "
        "enim ut tel\n"
        "| I | 0100 | 6c757320 656c656d 656e7475 6d207361 67697474 69732076 69746165 20657420  |  lus elementum "
        "sagittis vitae et \n"
        "| I | 0120 | 6c656f20 64756973 2e0a5369 7420616d 65742063 6f6e7365 63746574 75722061  |  leo duis..Sit amet "
        "consectetur a\n"
        "| I | 0140 | 64697069 7363696e 6720656c 69742075 7420616c 69717561 6d207075 72757320  |  dipiscing elit ut "
        "aliquam purus \n"
        "| I | 0160 | 7369742e 0a4e6973 6920706f 72746120 6c6f7265 6d206d6f 6c6c6973 20616c69  |  sit..Nisi porta "
        "lorem mollis ali\n"
        "| I | 0180 | 7175616d 2e0a4120 65726174 206e616d 20617420 6c656374 75732075 726e6120  |  quam..A erat nam at "
        "lectus urna \n"
        "| I | 01A0 | 64756973 2e0a436f 6e736571 75617420 69642070 6f727461 206e6962 68207665  |  duis..Consequat id "
        "porta nibh ve\n"
        "| I | 01C0 | 6e656e61 74697320 63726173 20736564 2066656c 69732e0a 52697375 73206e75  |  nenatis cras sed "
        "felis..Risus nu\n"
        "| I | 01E0 | 6c6c616d 20656765 74206665 6c697320 65676574 206e756e 63206c6f 626f7274  |  llam eget felis eget "
        "nunc lobort\n"
        "| I | 0200 | 6973206d 61747469 7320616c 69717561 6d206661 75636962 75732e0a 00        |  is mattis aliquam "
        "faucibus...\n"
        "| I | msg_control:\n"
        "| I | 0000 | 00010203                                                                 |  ....\n"
        "| I | msg_flags: 0\n";
    if(!logger_output_matches((char *)bytearray_output_stream_buffer(&channel_output_stream), expected_output))
    {
        yatest_err("no match");
        return 1;
    }
    finalise();
    return 0;
}

static int big_log_test()
{
    char *message = (char *)yatest_malloc(sizeof(yatest_lorem_ipsum));
    memcpy(message, yatest_lorem_ipsum, sizeof(yatest_lorem_ipsum));
    for(int i = 0; message[i] != '\0'; ++i)
    {
        if(message[i] == '\n')
        {
            message[i] = ' ';
        }
    }
    init();
    for(int i = 0; i < 4096; ++i)
    {
        logger_handle_msg_text(handle, MSG_INFO, message, sizeof(yatest_lorem_ipsum) - 1);
    }
    logger_reopen();
    for(int i = 0; i < 4096; ++i)
    {
        logger_handle_msg_text(handle, MSG_INFO, message, sizeof(yatest_lorem_ipsum) - 1);
    }
    logger_flush();
    logger_sink();
    for(int i = 0; i < 4096; ++i)
    {
        logger_handle_msg_text(handle, MSG_INFO, message, sizeof(yatest_lorem_ipsum) - 1);
    }
    logger_flush();
    finalise();
    return 0;
}

static int ttylog_handle_test()
{
    // ttylog_handle_out
    init();
    log_memdump_set_layout(3, 255);
    ttylog_handle_dbg(handle, "dbg");
    ttylog_handle_out(handle, "out");
    ttylog_handle_notice(handle, "notice");
    ttylog_handle_warn(handle, "warn");
    ttylog_handle_err(handle, "err");
    logger_flush();
    output_stream_write_u8(&channel_output_stream, 0);
    yatest_log("'%s'", bytearray_output_stream_buffer(&channel_output_stream));
    static const char expected_output[] =
        "| D | dbg\n"
        "| I | out\n"
        "| N | notice\n"
        "| W | warn\n"
        "| E | err\n";
    if(!logger_output_matches((char *)bytearray_output_stream_buffer(&channel_output_stream), expected_output))
    {
        yatest_err("no match");
        return 1;
    }
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(logger_handle_msg_test)
YATEST(logger_handle_msg_nocull_test)
YATEST(logger_handle_msg_text_test)
YATEST(logger_handle_msg_text_ext_test)
YATEST(logger_handle_try_msg_test)
YATEST(logger_handle_try_msg_text_test)
YATEST(big_log_test)
YATEST(log_memdump_ex_test)
YATEST(log_memdump_test)
YATEST(log_msghdr_test)
YATEST(ttylog_handle_test)
YATEST_TABLE_END
