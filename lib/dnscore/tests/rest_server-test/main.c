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
#include "dnscore/tcp_io_stream.h"
#include <dnscore/dnscore.h>
#include <dnscore/rest_server.h>
#include <dnscore/parsing.h>
#include <math.h>
#include "glibchooks/glibchooks_controller.h"
#include "glibchooks/filedescriptor.h"
#include "dnscore/rest_client.h"
#include "dnscore/simple_http_server.h"

/*
    host_address_t *listen;
    char *pid_file;
    char *ca;
    char *cert;
    char *key;
    pid_t pid;
    uid_t uid;
    gid_t gid;
    uint32_t worker_count;
    uint32_t queue_size;
    uint16_t default_port;
    bool https;
    bool setup_signals;
*/

static rest_server_network_setup_args_t rest_args;

static void                             hooks_init()
{
    ssize_t ret = glibchooks_controller_init();
    if(ret < 0)
    {
        yatest_log("Unable to setup glibc hook: skipped");
        exit(0);
    }
}

static void init()
{
    int ret;
    dnscore_init();
    memset(&rest_args, 0, sizeof(rest_args));
    rest_args.listen = host_address_new_instance_parse("0.0.0.0");
    rest_args.worker_count = 2;
    rest_args.queue_size = 10;
    rest_args.default_port = 60000;
    rest_args.setup_signals = true;
    ret = rest_server_setup(&rest_args);
    if(FAIL(ret))
    {
        yatest_err("rest_server_setup: %08x", ret);
        exit(1);
    }
    ret = rest_server_start(&rest_args);
    if(FAIL(ret))
    {
        yatest_err("rest_server_start: %08x", ret);
        exit(1);
    }
}

static void finalise()
{
    rest_server_stop(&rest_args);
    dnscore_finalize();
}

static ya_result rest_server_test_rest_query(const char *command, const char *text)
{
    input_stream_t  http_is;
    output_stream_t http_os;
    size_t          query_size;
    ya_result       ret;
    size_t          text_buffer_size = 0x100000;
    char           *text_buffer;
    char            key[64];
    char            value[256];
    yatest_log("sleeping for 5 seconds");
    yatest_sleep(5);
    yatest_log("sleept for 5 seconds");
    text_buffer = malloc(text_buffer_size);
    snprintf(text_buffer,
             text_buffer_size,
             "%s %s HTTP/1.1\r\n"
             "Host: 127.0.0.1:%i\r\n"
             "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 "
             "Safari/537.36\r\n"
             "\r\n",
             command,
             text,
             rest_args.default_port);
    query_size = strlen(text_buffer);
    // open a connection to the server address
    // send the stream
    // read the answer

    ret = tcp_input_output_stream_connect_ex("127.0.0.1", rest_args.default_port, &http_is, &http_os, NULL, 3);

    if(FAIL(ret))
    {
        yatest_err("failed to connect: %08x", ret);
        free(text_buffer);
        return ret;
    }

    output_stream_write_fully(&http_os, text_buffer, query_size);
    output_stream_flush(&http_os);

    // first line

    ret = input_stream_read_line(&http_is, text_buffer, text_buffer_size);
    if(ret <= 0)
    {
        free(text_buffer);
        input_stream_close(&http_is);
        yatest_err("failed to read answer: %08x", ret);
        return ERROR;
    }

    int content_length = 0;

    // header

    yatest_log("----- header begin -----");

    for(;;)
    {
        ret = input_stream_read_line(&http_is, text_buffer, text_buffer_size);
        if(ret <= 0)
        {
            yatest_err("failed to read header: %08x", ret);
            break;
        }

        if(ret <= 2)
        {
            break;
        }

        --ret;
        text_buffer[--ret] = '\0';

        char *p = text_buffer;
        key[0] = '\0';
        value[0] = '\0';

        int32_t key_len = parse_copy_next_word(key, sizeof(key), p);
        p += key_len;
        key[key_len - 1] = '\0';
        p += parse_copy_next_word(value, sizeof(value), p);
        yatest_log("Header: %s = '%s'", key, value);

        if(strcmp(key, "Content-Length") == 0)
        {
            content_length = atoi(value);
        }
    }

    yatest_log("----- header end -----");

    yatest_log("----- message begin -----");
    while(content_length > 0)
    {
        int n = MIN((int)text_buffer_size, content_length);
        ret = input_stream_read_fully(&http_is, text_buffer, n);
        if(FAIL(ret))
        {
            free(text_buffer);
            input_stream_close(&http_is);
            yatest_err("failed to read message");
            return ret;
        }
        output_stream_write_fully(termout, text_buffer, ret);
        flushout();
        content_length -= ret;
    }

    yatest_log("----- message end -----");

    free(text_buffer);

    return SUCCESS;
}

static void simple_text_page(rest_server_context_t *ctx)
{
    int         http_code;
    const char *http_text;

    http_code = 400;
    http_text = "It worked!";

    char   *v_text = "?";
    double  v_double = -1;
    int64_t v_int64 = 0x5a5a5a5a5a5a5a5a;
    int     v_int = 0x5a5a5a5a;
    uint8_t v_u8 = 0xa5;
    bool    v_bool = false;

    if(rest_server_context_arg_get(ctx, &v_text, "s", "text", NULL))
    {
        yatest_log("text=%s", v_text);
        if(strcmp(v_text, "Hello World") != 0)
        {
            yatest_err("text value is wrong");
            exit(1);
        }
    }
    if(rest_server_context_arg_get_double(ctx, &v_double, "f", "double", NULL))
    {
        yatest_log("double=%f", v_double);
        double dt = fabs(v_double - 1.234);
        if(dt > 0.00001)
        {
            yatest_err("double value is wrong");
            exit(1);
        }
    }
    if(rest_server_context_arg_get_int64(ctx, &v_int64, "i64", "int64", NULL))
    {
        yatest_log("int=%i", v_int64);
        if(v_int64 != 9123456789)
        {
            yatest_err("int value is wrong");
            exit(1);
        }
    }
    if(rest_server_context_arg_get_int(ctx, &v_int, "i", "int", NULL))
    {
        yatest_log("int=%i", v_int);
        if(v_int != 1234)
        {
            yatest_err("int value is wrong");
            exit(1);
        }
    }
    if(rest_server_context_arg_get_u8(ctx, &v_u8, "hhi", "u8", NULL))
    {
        yatest_log("u8=%i", v_u8);
        if(v_u8 != 255)
        {
            yatest_err("u8 value is wrong");
            exit(1);
        }
    }
    if(rest_server_context_arg_get_bool(ctx, &v_bool, "b", "bool", NULL))
    {
        yatest_log("bool=%i", v_bool);
        if(!v_bool)
        {
            yatest_err("bool value is wrong");
            exit(1);
        }
    }

    ya_result ret;

    if(ISOK(ret = rest_server_context_arg_get_double_ex(ctx, &v_double, "f", "double", NULL)))
    {
        yatest_log("double=%f", v_double);
        double dt = fabs(v_double - 1.234);
        if(dt > 0.00001)
        {
            yatest_err("double value is wrong");
            exit(1);
        }
    }
    else
    {
        yatest_err("double value is wrong: %08x", ret);
        exit(1);
    }

    if(ISOK(ret = rest_server_context_arg_get_int64_ex(ctx, &v_int64, "i64", "int64", NULL)))
    {
        yatest_log("int64=%" PRIi64, v_int64);
        if(v_int64 != 9123456789)
        {
            yatest_err("int64 value is wrong");
            exit(1);
        }
    }
    else
    {
        yatest_err("int64 value is wrong: %08x", ret);
        exit(1);
    }

    if(ISOK(ret = rest_server_context_arg_get_int_ex(ctx, &v_int, "i", "int", NULL)))
    {
        yatest_log("int=%i", v_int);
        if(v_int != 1234)
        {
            yatest_err("int value is wrong");
            exit(1);
        }
    }
    else
    {
        yatest_err("int value is wrong: %08x", ret);
        exit(1);
    }

    if(ISOK(ret = rest_server_context_arg_get_bool_ex(ctx, &v_bool, "b", "bool", NULL)))
    {
        yatest_log("bool=%i", v_bool);
        if(!v_bool)
        {
            yatest_err("bool value is wrong");
            exit(1);
        }
    }
    else
    {
        yatest_err("bool value is wrong: %08x", ret);
        exit(1);
    }

    // failures

    if(FAIL(ret = rest_server_context_arg_get_double_ex(ctx, &v_double, "text", NULL)))
    {
        yatest_log("text as double rejected");
    }
    else
    {
        yatest_err("double should not have been parsed");
        exit(1);
    }

    if(FAIL(ret = rest_server_context_arg_get_int64_ex(ctx, &v_int64, "text", NULL)))
    {
        yatest_log("text as int64 rejected");
    }
    else
    {
        yatest_err("int64 should not have been parsed");
        exit(1);
    }

    if(FAIL(ret = rest_server_context_arg_get_int_ex(ctx, &v_int, "text", NULL)))
    {
        yatest_log("text as int rejected");
    }
    else
    {
        yatest_err("int should not have been parsed");
        exit(1);
    }

    if(FAIL(ret = rest_server_context_arg_get_bool_ex(ctx, &v_bool, "text", NULL)))
    {
        yatest_log("text as bool rejected");
    }
    else
    {
        yatest_err("bool should not have been parsed");
        exit(1);
    }

    rest_server_write_http_header_and_print(ctx,
                                            http_code,
                                            http_text,
                                            "{"
                                            "\"status\": \"%s\""
                                            "}",
                                            http_text);
}

static bool simple_bin_page_ok = false;

static void simple_bin_page(rest_server_context_t *ctx)
{
    int         http_code;
    const char *http_text;

    http_code = 400;
    http_text = "It worked!";

    char body[64];
    snprintf(body, sizeof(body), "{\"status\": \"%s\"}", http_text);
    int body_len = strlen(body);

    rest_server_write_http_header_and_body(ctx, http_code, http_text, body_len, body);

    simple_bin_page_ok = true;
}

static bool chunked_json_page_ok = false;

static void chunked_json_page(rest_server_context_t *ctx)
{
    output_stream_t *os = &ctx->os;

    http_header_code(os, 200);
    http_header_content_type_application_json(os);
    http_header_transfer_encoding_chunked(os);
    http_header_date_now(os);
    http_header_close(os);

    json_t json = json_object_new_instance();
    json_t data = json_array_new_instance();

    for(int i = 0; i < 256; ++i)
    {
        json_array_add_number(data, i);
    }

    json_object_add(json, (const uint8_t *)"data", data);

    char *answer = json_to_string(json);
    int   answer_size = strlen(answer);

    http_write_chunk(os, answer, answer_size);

    http_write_chunk_close(os);

    free(answer);
    json_delete(json);

    chunked_json_page_ok = true;
}

static bool registry_domain_bin_page_ok = false;

static void registry_domain_bin_page(rest_server_context_t *ctx)
{
    int         http_code;
    const char *http_text;

    http_code = 400;
    http_text = "It worked!";

    char  body[64];
    char *tld;
    char *domain;
    if(rest_server_context_path_arg_get(ctx, &tld, "tld"))
    {
        if(rest_server_context_path_arg_get(ctx, &domain, "domain"))
        {
            snprintf(body, sizeof(body), "{\"status\": \"%s\",\"tld\": \"%s\", \"domain\": \"%s\"}", http_text, tld, domain);
            int body_len = strlen(body);
            rest_server_write_http_header_and_body(ctx, http_code, http_text, body_len, body);
        }
    }
    registry_domain_bin_page_ok = true;
}

static bool health_bin_page_ok = false;

static void health_bin_page(rest_server_context_t *ctx)
{
    int         http_code;
    const char *http_text;

    http_code = 400;
    http_text = "It worked!";

    char body[64];
    snprintf(body, sizeof(body), "{\"health\": \"%s\"}", http_text);
    int body_len = strlen(body);

    rest_server_write_http_header_and_body(ctx, http_code, http_text, body_len, body);

    health_bin_page_ok = true;
}

static bool info_bin_page_ok = false;

static void info_bin_page(rest_server_context_t *ctx)
{
    int         http_code;
    const char *http_text;

    http_code = 400;
    http_text = "It worked!";

    char body[64];
    snprintf(body, sizeof(body), "{\"info\": \"%s\"}", http_text);
    int body_len = strlen(body);

    rest_server_write_http_header_and_body(ctx, http_code, http_text, body_len, body);

    info_bin_page_ok = true;
}

static int simple_page_test()
{
    init();
    rest_server_page_register("hi", simple_text_page);
    rest_server_test_rest_query("GET", "hi?text=Hello%20World&double=1.234&int=1234&u8=255&bool=1&int64=9123456789");
    rest_server_page_register("hi", NULL);
    finalise();
    return 0;
}

static int simple_bin_page_test()
{
    int ret = 0;
    init();
    rest_server_page_register("hi", simple_bin_page);
    rest_server_test_rest_query("GET", "hi?text=Hello%20World&double=1.234&int=1234&u8=255&bool=1&int64=9123456789");
    rest_server_page_register("hi", NULL);
    if(!simple_bin_page_ok)
    {
        ret = 1;
        yatest_err("simple_bin_page_ok is false");
    }
    finalise();
    return ret;
}

static int path_variable_bin_page_test()
{
    int ret = 0;
    init();
    rest_server_page_register("//registry/$tld/domain/$domain", registry_domain_bin_page);
    rest_server_page_register("//service/1.0/health", health_bin_page);
    rest_server_page_register("//service/1.0/info", info_bin_page);
    rest_server_test_rest_query("GET", "/registry/eu/domain/yadifa?text=Hello%20World&double=1.234&int=1234&u8=255&bool=1&int64=9123456789");
    rest_server_test_rest_query("GET", "service/1.0/health");
    rest_server_test_rest_query("GET", "service/1.0/info");
    rest_server_page_register("//registry/$tld/domain/$domain", NULL);
    if(!registry_domain_bin_page_ok)
    {
        ret = 1;
        yatest_err("registry_domain_bin_page_ok is false");
    }
    if(!health_bin_page_ok)
    {
        ret = 1;
        yatest_err("health_bin_page_ok is false");
    }
    if(!info_bin_page_ok)
    {
        ret = 1;
        yatest_err("info_bin_page_ok is false");
    }
    finalise();
    return ret;
}

static int signal_test()
{
    init();
    rest_server_page_register("hi", simple_text_page);
    rest_server_test_rest_query("GET", "hi?text=Hello%20World&double=1.234&int=1234&u8=255&bool=1&int64=9123456789");

    kill(getpid(), SIGINT);
    yatest_sleep(1);
    rest_server_wait(&rest_args);

    rest_server_page_register("hi", NULL);
    finalise();
    return 0;
}

static int request_overflow_test()
{
    init();
    size_t uri_buffer_size = 81000;
    char  *uri = malloc(uri_buffer_size);
    memset(uri, 0, uri_buffer_size);
    strcpy(uri, "hi?aa=bb");
    for(int i = 0; i < 20000; ++i) // should be about 80008
    {
        memcpy(&uri[8 + i * 4], "&a=b", 4);
    }

    rest_server_page_register("hi", simple_bin_page);
    rest_server_test_rest_query("GET", uri);
    rest_server_page_register("hi", NULL);
    finalise();
    return 0;
}

static int invalid_request_test()
{
    init();
    rest_server_page_register("hi", simple_bin_page);
    rest_server_test_rest_query("BROKEN", "hi?text=Hello%20World&double=1.234&int=1234&u8=255&bool=1&int64=9123456789");
    rest_server_page_register("hi", NULL);
    finalise();
    return 0;
}

static int notfound_test()
{
    init();
    rest_server_page_register("hi", simple_bin_page);
    rest_server_test_rest_query("GET", "hello?text=Hello%20World&double=1.234&int=1234&u8=255&bool=1&int64=9123456789");
    rest_server_page_register("hi", NULL);
    finalise();
    return 0;
}

static int setup_test()
{
    int ret;
    dnscore_init();

    ret = rest_server_setup(NULL);
    if(ret != UNEXPECTED_NULL_ARGUMENT_ERROR)
    {
        yatest_err("rest_server_setup expected to return UNEXPECTED_NULL_ARGUMENT_ERROR (null args)");
        return 1;
    }

    memset(&rest_args, 0, sizeof(rest_args));

    ret = rest_server_setup(&rest_args);
    if(ret != UNEXPECTED_NULL_ARGUMENT_ERROR)
    {
        yatest_err("rest_server_setup expected to return UNEXPECTED_NULL_ARGUMENT_ERROR (null listen)");
        return 1;
    }

    rest_args.listen = host_address_new_instance_parse("0.0.0.0");
    rest_args.worker_count = 2;
    rest_args.queue_size = 10;
    rest_args.default_port = 60000;

    rest_args.pid_file = "/tmp/rest_server_test-setup_test.pid";
    unlink(rest_args.pid_file);

    ret = rest_server_setup(&rest_args);
    if(FAIL(ret))
    {
        yatest_err("rest_server_setup: %08x", ret);
        return 1;
    }

    finalise();
    return 0;
}

static int pid_locked_test()
{
    int ret;
    dnscore_init();
    memset(&rest_args, 0, sizeof(rest_args));

    rest_args.listen = host_address_new_instance_parse("0.0.0.0");
    rest_args.worker_count = 2;
    rest_args.queue_size = 10;
    rest_args.default_port = 60000;

    rest_args.pid_file = "/tmp/rest_server_test-setup_test.pid";

    FILE *f = fopen(rest_args.pid_file, "w+");
    fprintf(f, "1\n");
    fclose(f);

    ret = rest_server_setup(&rest_args);
    if(ISOK(ret))
    {
        yatest_err("rest_server_setup: expected to fail, returned %08x", ret);
        return 1;
    }

    finalise();
    return 0;
}

static int wrong_listen_test()
{
    int ret;
    dnscore_init();

    memset(&rest_args, 0, sizeof(rest_args));

    host_address_t ha = {.version = 1};
    rest_args.listen = &ha;
    rest_args.worker_count = 2;
    rest_args.queue_size = 10;
    rest_args.default_port = 60000;

    ret = rest_server_setup(&rest_args);
    if(ISOK(ret))
    {
        yatest_err("rest_server_setup expected to fail, returned %08x", ret);
        return 1;
    }

    finalise();
    return 0;
}

static void socket_error_test_hook(socket_function_args_t *args)
{
    args->mask = 0x1f;
    args->ret = -1;
    args->errno_value = EACCES;
}

static int socket_error_test()
{
    int ret;
    hooks_init();
    dnscore_init();

    glibchooks_set_or_die("socket", socket_error_test_hook);

    memset(&rest_args, 0, sizeof(rest_args));

    rest_args.listen = host_address_new_instance_parse("0.0.0.0");
    rest_args.worker_count = 2;
    rest_args.queue_size = 10;
    rest_args.default_port = 60000;

    ret = rest_server_setup(&rest_args);
    if(ISOK(ret))
    {
        yatest_err("rest_server_setup expected to fail, returned %08x", ret);
        return 1;
    }

    finalise();
    return 0;
}

static int  setsockopt_error_test_hook_level = 0;
static int  setsockopt_error_test_hook_option_name = 0;

static void setsockopt_error_test_hook(setsockopt_function_args_t *args)
{
    if((args->level == setsockopt_error_test_hook_level) && (args->option_name == setsockopt_error_test_hook_option_name))
    {
        args->mask = 0x7f;
        args->ret = -1;
        args->errno_value = EINVAL;
    }
}

static int ipv6only_error_test()
{
    int ret;
    hooks_init();
    dnscore_init();

    setsockopt_error_test_hook_level = IPPROTO_IPV6;
    setsockopt_error_test_hook_option_name = IPV6_V6ONLY;
    glibchooks_set_or_die("setsockopt", setsockopt_error_test_hook);

    memset(&rest_args, 0, sizeof(rest_args));

    rest_args.listen = host_address_new_instance_parse("::1");
    rest_args.worker_count = 2;
    rest_args.queue_size = 10;
    rest_args.default_port = 60000;

    ret = rest_server_setup(&rest_args);
    if(ISOK(ret))
    {
        yatest_err("rest_server_setup expected to fail, returned %08x", ret);
        return 1;
    }

    finalise();
    return 0;
}

static int reuseaddr_error_test()
{
    int ret;
    hooks_init();
    dnscore_init();

    setsockopt_error_test_hook_level = SOL_SOCKET;
    setsockopt_error_test_hook_option_name = SO_REUSEADDR;
    glibchooks_set_or_die("setsockopt", setsockopt_error_test_hook);

    memset(&rest_args, 0, sizeof(rest_args));

    rest_args.listen = host_address_new_instance_parse("0.0.0.0");
    rest_args.worker_count = 2;
    rest_args.queue_size = 10;
    rest_args.default_port = 60000;

    ret = rest_server_setup(&rest_args);
    if(ISOK(ret))
    {
        yatest_err("rest_server_setup expected to fail, returned %08x", ret);
        return 1;
    }

    finalise();
    return 0;
}

static int reuseport_error_test()
{
    int ret;
    hooks_init();
    dnscore_init();

    setsockopt_error_test_hook_level = SOL_SOCKET;
    setsockopt_error_test_hook_option_name = SO_REUSEPORT;
    glibchooks_set_or_die("setsockopt", setsockopt_error_test_hook);

    memset(&rest_args, 0, sizeof(rest_args));

    rest_args.listen = host_address_new_instance_parse("0.0.0.0");
    rest_args.worker_count = 2;
    rest_args.queue_size = 10;
    rest_args.default_port = 60000;

    ret = rest_server_setup(&rest_args);
    if(ISOK(ret))
    {
        yatest_err("rest_server_setup expected to fail, returned %08x", ret);
        return 1;
    }

    finalise();
    return 0;
}

static int  bind_error_test_hook_countdown = 3;

static void bind_error_test_hook(bind_function_args_t *args)
{
    if(--bind_error_test_hook_countdown <= 0)
    {
        args->mask = 0x1f;
        args->ret = -1;
        args->errno_value = EINVAL;
    }
}

static int bind_error_test()
{
    int ret;
    hooks_init();
    dnscore_init();

    glibchooks_set_or_die("bind", bind_error_test_hook);

    memset(&rest_args, 0, sizeof(rest_args));

    rest_args.listen = host_address_new_instance_parse("0.0.0.0");
    rest_args.listen->next = host_address_new_instance_parse("::1");
    rest_args.listen->next->next = host_address_new_instance_parse("127.0.0.254");
    rest_args.worker_count = 2;
    rest_args.queue_size = 10;
    rest_args.default_port = 60000;

    ret = rest_server_setup(&rest_args);
    if(ISOK(ret))
    {
        yatest_err("rest_server_setup expected to fail, returned %08x", ret);
        return 1;
    }

    finalise();
    return 0;
}

static void listen_error_test_hook(listen_function_args_t *args)
{
    args->mask = 0x0f;
    args->ret = -1;
    args->errno_value = EADDRINUSE;
}

static int listen_error_test()
{
    int ret;
    hooks_init();
    dnscore_init();

    glibchooks_set_or_die("listen", listen_error_test_hook);

    memset(&rest_args, 0, sizeof(rest_args));

    rest_args.listen = host_address_new_instance_parse("0.0.0.0");
    rest_args.worker_count = 2;
    rest_args.queue_size = 10;
    rest_args.default_port = 60000;

    ret = rest_server_setup(&rest_args);
    if(ISOK(ret))
    {
        yatest_err("rest_server_setup expected to fail, returned %08x", ret);
        return 1;
    }

    finalise();
    return 0;
}

static bool uri_matches(uri_t *uri, const char *scheme, const char *user, const char *host, const char *port, const char *path, ...)
{
    if(strcmp(uri->scheme_text, scheme) != 0)
    {
        yatest_err("scheme doesn't match: '%s' vs '%s'", uri->scheme_text, scheme);
        return false;
    }
    if(strcmp(uri->user_text, user) != 0)
    {
        yatest_err("user doesn't match: '%s' vs '%s'", uri->user_text, user);
        return false;
    }
    if(strcmp(uri->host_text, host) != 0)
    {
        yatest_err("host doesn't match: '%s' vs '%s'", uri->host_text, host);
        return false;
    }
    if(strcmp(uri->port_text, port) != 0)
    {
        yatest_err("port doesn't match: '%s' vs '%s'", uri->port_text, port);
        return false;
    }
    if(strcmp(uri->path_text, path) != 0)
    {
        yatest_err("path doesn't match: '%s' vs '%s'", uri->path_text, path);
        return false;
    }
    va_list args;
    va_start(args, path);

    for(;;)
    {
        const char *key = va_arg(args, char *);
        if(key == NULL)
        {
            break;
        }
        const char         *value = va_arg(args, char *);
        ptr_treemap_node_t *node = ptr_treemap_find(&uri->args, key);
        if(node == NULL)
        {
            yatest_err("key '%s' not found", key);
            return false;
        }
        if(strcmp(node->value, value) != 0)
        {
            yatest_err("key->value '%s'->'%s' doesn't match '%s'->'%s'", node->key, node->value, key, value);
            return false;
        }
    }

    va_end(args);
    return true;
}

static int uri_test()
{
    ya_result ret;
    dnscore_init();
    uri_t uri;
    //
    ret = uri_init_from_text(&uri, "http://mylogin@myserver:12345/path/to/my/index.html?arg0=0&arg1=Hello World&arg3=");
    if(FAIL(ret))
    {
        yatest_err("uri0 init failed with %08x", ret);
        return 1;
    }
    if(!uri_matches(&uri, "http", "mylogin", "myserver", "12345", "path/to/my/index.html", "arg0", "0", "arg1", "Hello World", "arg3", "", NULL))
    {
        yatest_err("uri0 not parsed correctly");
        return 1;
    }
    uri_finalise(&uri);
    //
    ret = uri_init_from_text(&uri, "http://myserver:12345/path/to/my/index.html?arg0=0&arg1=Hello World&arg3=");
    if(FAIL(ret))
    {
        yatest_err("uri1 init failed with %08x", ret);
        return 1;
    }
    if(!uri_matches(&uri, "http", "", "myserver", "12345", "path/to/my/index.html", "arg0", "0", "arg1", "Hello World", "arg3", "", NULL))
    {
        yatest_err("uri1 not parsed correctly");
        return 1;
    }
    uri_finalise(&uri);
    //
    ret = uri_init_from_text(&uri, "http://myserver/path/to/my/index.html?arg0=0&arg1=Hello World&arg3=");
    if(FAIL(ret))
    {
        yatest_err("uri2 init failed with %08x", ret);
        return 1;
    }
    if(!uri_matches(&uri, "http", "", "myserver", "", "path/to/my/index.html", "arg0", "0", "arg1", "Hello World", "arg3", "", NULL))
    {
        yatest_err("uri2 not parsed correctly");
        return 1;
    }
    uri_finalise(&uri);
    //
    ret = uri_init_from_text(&uri, "http://myserver/?arg0=0&arg1=Hello World&arg3=");
    if(FAIL(ret))
    {
        yatest_err("uri3 init failed with %08x", ret);
        return 1;
    }
    if(!uri_matches(&uri, "http", "", "myserver", "", "", "arg0", "0", "arg1", "Hello World", "arg3", "", NULL))
    {
        yatest_err("uri3 not parsed correctly");
        return 1;
    }
    uri_finalise(&uri);
    //
    ret = uri_init_from_text(&uri, "http://myserver?arg0=0&arg1=Hello World&arg3=");
    if(FAIL(ret))
    {
        yatest_err("uri4 init failed with %08x", ret);
        return 1;
    }
    if(!uri_matches(&uri, "http", "", "myserver", "", "", "arg0", "0", "arg1", "Hello World", "arg3", "", NULL))
    {
        yatest_err("uri4 not parsed correctly");
        return 1;
    }
    uri_finalise(&uri);
    //
    ret = uri_init_from_text(&uri, "http://myserver?");
    if(FAIL(ret))
    {
        yatest_err("uri5 init failed with %08x", ret);
        return 1;
    }
    if(!uri_matches(&uri, "http", "", "myserver", "", "", NULL))
    {
        yatest_err("uri5 not parsed correctly");
        return 1;
    }
    uri_finalise(&uri);
    //
    ret = uri_init_from_text(&uri, "http://myserver");
    if(FAIL(ret))
    {
        yatest_err("uri6 init failed with %08x", ret);
        return 1;
    }
    if(!uri_matches(&uri, "http", "", "myserver", "", "", NULL))
    {
        yatest_err("uri6 not parsed correctly");
        return 1;
    }
    uri_finalise(&uri);
    //
    dnscore_finalize();
    return 0;
}

static int rest_client_success_test()
{
    int ret = 0;
    init();
    rest_server_page_register("hi", simple_bin_page);
    json_t json = NULL;
    ret = rest_query_uri("http://127.0.0.1:60000/hi?arg0=0&arg1=1", &json);
    if(ISOK(ret))
    {
        yatest_log("query successful");
        json_write_to(json, termout);
    }
    else
    {
        yatest_err("query failure: code %08x", ret);
        return 1;
    }
    finalise();
    return ret;
}

static int rest_client_chunk_test()
{
    int ret = 0;
    init();
    rest_server_page_register("chunked", chunked_json_page);
    json_t json = NULL;
    ret = rest_query_uri("http://127.0.0.1:60000/chunked?arg0=0&arg1=1", &json);
    if(ISOK(ret))
    {
        yatest_log("query successful");
        json_write_to(json, termout);
    }
    else
    {
        yatest_err("query failure: code %08x", ret);
        return 1;
    }
    finalise();
    return ret;
}

YATEST_TABLE_BEGIN
YATEST(simple_page_test)
YATEST(path_variable_bin_page_test)
YATEST(simple_bin_page_test)
YATEST(signal_test)
YATEST(request_overflow_test)
YATEST(invalid_request_test)
YATEST(notfound_test)
YATEST(setup_test)
YATEST(pid_locked_test)
YATEST(wrong_listen_test)
YATEST(socket_error_test)
YATEST(ipv6only_error_test)
YATEST(reuseaddr_error_test)
YATEST(reuseport_error_test)
YATEST(bind_error_test)
YATEST(listen_error_test)
YATEST(uri_test)
YATEST(rest_client_success_test)
YATEST(rest_client_chunk_test)
YATEST_TABLE_END
