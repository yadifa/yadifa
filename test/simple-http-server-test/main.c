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

/** @defgroup test
 *  @ingroup test
 *  @brief simple_http_server_test file
 * 
 * simple_http_server_test test program, will not be installed with a "make install"
 * 
 * To create a new test based on the simple_http_server_test:
 * 
 * _ copy the folder
 * _ replace "simple_http_server_test" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 *
 */

#include <dnscore/dnscore.h>
#include <dnscore/simple-http-server.h>
#include <dnscore/json.h>

#define WAIT_US 600000000 // 10 minutes

static ya_result
simple_rest_server_page_writer_simple_test(const struct simple_rest_server_page *page, output_stream *os, const simple_rest_server_page_writer_args *args)
{
    (void)page;
    ya_result answer_size;
    char answer[128];
    
    const char *host = simple_rest_server_page_writer_args_get_header_field(args, "Host");
    
    const char *a = simple_rest_server_page_writer_args_get_uri_arg(args, "a");
    
    if(a != NULL)
    {
        answer_size = snformat(answer, sizeof(answer), "{a='%s'}", a);
    }
    else
    {
        answer_size = snformat(answer, sizeof(answer), "{empty=true}");
    }
    
    http_header_code(os, 200);
    
    if(host != NULL)
    {
        http_header_host(os, host, 9);
    }
    
    http_header_content_type_application_json(os);
    http_header_transfer_encoding_chunked(os);
    http_header_date_now(os);
    http_header_close(os);
    http_write_chunk(os, answer, answer_size);
    http_write_chunk_close(os);
    
    return SUCCESS;
}

static ya_result
simple_rest_server_page_writer_json_test(const struct simple_rest_server_page *page, output_stream *os, const simple_rest_server_page_writer_args *args)
{
    (void)page;
    ya_result answer_size;
    
    const char *host = simple_rest_server_page_writer_args_get_header_field(args, "Host");
    
    const char *a = simple_rest_server_page_writer_args_get_uri_arg(args, "a");
    
    json object = json_object_new_instance();
        
    if(a != NULL)
    {
        a = "undefined";
    }
    
    json_object_add_string(object, "a", a);

    json array = json_array_new_instance();
    {
        json_array_add_number(array, 3.14159265359);
        json_array_add_string(array, "item1");

        json object = json_object_new_instance();
        {
            json_object_add_number(object, "golden-ratio", 1.61803398875);
            json_object_add_number(object, "e", 2.71828182846);
            json_object_add_boolean(object, "true-or-false", TRUE);
            json_object_add_boolean(object, "true-and-false", FALSE);
        }
        json_array_add(array, object);
    }
    json_object_add(object, "array", array);

    
    http_header_code(os, 200);
    
    if(host != NULL)
    {
        http_header_host(os, host, 9);
    }
    
    json_write_to(object, termout);
    
    answer_size = json_size(object);
    
    http_header_content_type_application_json(os);
    http_header_date_now(os);
    //http_header_content_length(os, answer_size);
    http_header_transfer_encoding_chunked(os);
    http_header_close(os);
    http_write_chunk_begin(os, answer_size);
    json_write_to(object, os);
    http_write_chunk_end(os);
    http_write_chunk_close(os);
    
    

    return SUCCESS;
}

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    
    /* initializes the core library */
    dnscore_init();
    
    simple_rest_server srs;
    
    struct addrinfo *addr;
    
    if(FAIL(getaddrinfo("127.0.0.1", "8080", NULL, &addr)))
    {
        formatln("getaddrinfo failed with: %r", ERRNO_ERROR);
        return EXIT_FAILURE;
    }
    
    ya_result ret;
    
    if(ISOK(ret = simple_rest_server_init(&srs, addr)))
    {
        simple_rest_server_page_register(&srs, "simple", simple_rest_server_page_writer_simple_test, NULL);
        simple_rest_server_page_register(&srs, "json", simple_rest_server_page_writer_json_test, NULL);
        
        if(ISOK(ret = simple_rest_server_start(&srs)))
        {
            s64 start = timeus();
            s64 now;

            for(;;)
            {
                now = timeus();
                s64 d = now - start;

                if(d >= WAIT_US)
                {
                    break;
                }

                usleep(WAIT_US - d);
            }

            simple_rest_server_stop(&srs);
        }
        
        simple_rest_server_finalize(&srs);
    }

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
