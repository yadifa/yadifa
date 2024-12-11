################################################################################
#
# Copyright (c) 2011-2024, EURid vzw. All rights reserved.
# The YADIFA TM software product is provided under the BSD 3-clause license:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#        * Redistributions of source code must retain the above copyright
#          notice, this list of conditions and the following disclaimer.
#        * Redistributions in binary form must reproduce the above copyright
#          notice, this list of conditions and the following disclaimer in the
#          documentation and/or other materials provided with the distribution.
#        * Neither the name of EURid nor the names of its contributors may be
#          used to endorse or promote products derived from this software
#          without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
################################################################################

cmake_minimum_required(VERSION 3.22)

cmake_path(GET CMAKE_CURRENT_SOURCE_DIR FILENAME NAME)
set(SOURCE_FILES main.c)

include_directories(BEFORE
                    "${YATEST_INCLUDE_DIRECTORY}"
                    "${CMAKE_SOURCE_DIR}/lib/dnscore/include"
                    "${CMAKE_BINARY_DIR}/lib/dnscore/include"
                    "${CMAKE_SOURCE_DIR}/lib/dnscore/tests/modules")


add_executable(${NAME} ${SOURCE_FILES})
target_coverage_test(${NAME})
target_link_libraries(${NAME} PUBLIC ${DNSCORELIB_NAME})

add_test(NAME "${NAME}-osformat_test"  COMMAND ${NAME} osformat_test)
add_test(NAME "${NAME}-osprint_wrapped_test"  COMMAND ${NAME} osprint_wrapped_test)
add_test(NAME "${NAME}-debug_osformatln_test"  COMMAND ${NAME} debug_osformatln_test)
add_test(NAME "${NAME}-debug_println_test"  COMMAND ${NAME} debug_println_test)
add_test(NAME "${NAME}-println_test"  COMMAND ${NAME} println_test)
add_test(NAME "${NAME}-print_test"  COMMAND ${NAME} print_test)
add_test(NAME "${NAME}-print_char_test"  COMMAND ${NAME} print_char_test)
add_test(NAME "${NAME}-asformat_test"  COMMAND ${NAME} asformat_test)
add_test(NAME "${NAME}-format_grow_hash_table_test"  COMMAND ${NAME} format_grow_hash_table_test)
add_test(NAME "${NAME}-osprint_base16_test"  COMMAND ${NAME} osprint_base16_test)
add_test(NAME "${NAME}-osprint_u32_test"  COMMAND ${NAME} osprint_u32_test)
add_test(NAME "${NAME}-osprint_u16_test"  COMMAND ${NAME} osprint_u16_test)
add_test(NAME "${NAME}-osprint_u32_hex_test"  COMMAND ${NAME} osprint_u32_hex_test)
add_test(NAME "${NAME}-osprint_quoted_text_escaped_test"  COMMAND ${NAME} osprint_quoted_text_escaped_test)
add_test(NAME "${NAME}-osprint_char_times_test"  COMMAND ${NAME} osprint_char_times_test)
add_test(NAME "${NAME}-snformat_test"  COMMAND ${NAME} snformat_test)
add_test(NAME "${NAME}-asnformat_test"  COMMAND ${NAME} asnformat_test)
add_test(NAME "${NAME}-fformat_test"  COMMAND ${NAME} fformat_test)
add_test(NAME "${NAME}-osprint_rdata_test"  COMMAND ${NAME} osprint_rdata_test)
add_test(NAME "${NAME}-osprint_rdata_escaped_test"  COMMAND ${NAME} osprint_rdata_escaped_test)
add_test(NAME "${NAME}-print_rdata_test"  COMMAND ${NAME} print_rdata_test)
add_test(NAME "${NAME}-osprint_dump_with_base_test"  COMMAND ${NAME} osprint_dump_with_base_test)
add_test(NAME "${NAME}-osprint_dump_with_base_squeezable_test"  COMMAND ${NAME} osprint_dump_with_base_squeezable_test)
add_test(NAME "${NAME}-osprint_question_test"  COMMAND ${NAME} osprint_question_test)
add_test(NAME "${NAME}-print_question_test"  COMMAND ${NAME} print_question_test)

