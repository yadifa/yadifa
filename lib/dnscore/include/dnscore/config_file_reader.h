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

#pragma once

#include <dnscore/config_settings.h>
#include <dnscore/input_stream.h>

/**
 * 
 * Parses an input stream for a section/container defined by its config sectiondescriptor.
 * The input stream will be closed by the function.
 * 
 * @param stream_name a name to identify the stream in case of error
 * @param ins the input stream to parse
 * @param csd the descriptor of the section to parse
 * @param cfgerr if not NULL, the error reporting structure to fill in case of error
 * 
 * @return an error code
 */

ya_result config_file_reader_parse_stream(const char* stream_name, input_stream *ins, struct config_section_descriptor_s *csd, config_error_s *cfgerr);

/**
 * 
 * Parses a file for a section/container defined by its config sectiondescriptor.
 * 
 * @param fullpath the file path
 * @param csd the descriptor of the section to parse
 * @param cfgerr if not NULL, the error reporting structure to fill in case of error
 * 
 * @return an error code
 */

ya_result config_file_reader_open(const char* fullpath, struct config_section_descriptor_s *csd, config_error_s *cfgerr);
