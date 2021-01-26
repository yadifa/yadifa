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
 *  @brief skeleton file
 * 
 * skeleton test program, will not be installed with a "make install"
 * 
 * To create a new test based on the skeleton:
 * 
 * _ copy the folder
 * _ replace "skeleton" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 *
 */

#include <dnscore/dnscore.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/parser.h>
#include <dnscore/format.h>

static const char * const zfr_string_delimiters = "\"\"''";
static const char * const zfr_multiline_delimiters = "()";
static const char * const zrf_comment_markers = ";";
static const char * const zrf_blank_makers = "\040\t\r";
static const char * const zfr_escape_characters = "\\";

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    /* initializes the core library */
    dnscore_init();

    parser_s parser;
    input_stream is;
    ya_result ret;
    char buffer[1024];

    if(ISOK(ret = file_input_stream_open(&is, "input0.txt")))
    {
        if(ISOK(ret = parser_init(&parser,
                                          zfr_string_delimiters,      // by 2
                                          zfr_multiline_delimiters,   // by 2
                                          zrf_comment_markers,        // by 1
                                          zrf_blank_makers,           // by 1
                                          zfr_escape_characters)))    // by 1
        {
            parser_push_stream(&parser, &is);

            do
            {
                while(ISOK(ret = parser_copy_next_word(&parser, buffer, sizeof(buffer) - 1)))
                {
                    buffer[ret] = '\0';
                    formatln("word=<%s>", buffer);
                    flushout();
                }

                if(ret != PARSER_REACHED_END_OF_LINE)
                {
                    formatln("error %r parsing <%s>", ret, parser_text(&parser));
                    parser_next_characters(&parser);
                }
            }
            while(ret != PARSER_REACHED_END_OF_FILE);
        }
    }

    formatln("return code: %r", ret);

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
