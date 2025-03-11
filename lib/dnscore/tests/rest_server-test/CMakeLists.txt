################################################################################
#
# Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
                    "${CMAKE_SOURCE_DIR}/lib/dnscore/tests/modules"
                    "${CMAKE_SOURCE_DIR}/lib/glibchooks/include")

add_executable(${NAME} ${SOURCE_FILES})
target_coverage_test(${NAME})
target_link_libraries(${NAME} PUBLIC ${DNSCORELIB_NAME} glibchooksload glibchooksctrl glibchooks)

add_test(NAME "${NAME}-simple_page_test"  COMMAND ${NAME} simple_page_test)
add_test(NAME "${NAME}-path_variable_bin_page_test"  COMMAND ${NAME} path_variable_bin_page_test)
add_test(NAME "${NAME}-simple_bin_page_test"  COMMAND ${NAME} simple_bin_page_test)
add_test(NAME "${NAME}-signal_test"  COMMAND ${NAME} signal_test)
add_test(NAME "${NAME}-request_overflow_test"  COMMAND ${NAME} request_overflow_test)
add_test(NAME "${NAME}-invalid_request_test"  COMMAND ${NAME} invalid_request_test)
add_test(NAME "${NAME}-notfound_test"  COMMAND ${NAME} notfound_test)
add_test(NAME "${NAME}-setup_test"  COMMAND ${NAME} setup_test)
add_test(NAME "${NAME}-pid_locked_test"  COMMAND ${NAME} pid_locked_test)
add_test(NAME "${NAME}-wrong_listen_test"  COMMAND ${NAME} wrong_listen_test)
add_test(NAME "${NAME}-socket_error_test"  COMMAND ${NAME} socket_error_test)
add_test(NAME "${NAME}-ipv6only_error_test"  COMMAND ${NAME} ipv6only_error_test)
add_test(NAME "${NAME}-reuseaddr_error_test"  COMMAND ${NAME} reuseaddr_error_test)
add_test(NAME "${NAME}-reuseport_error_test"  COMMAND ${NAME} reuseport_error_test)
add_test(NAME "${NAME}-bind_error_test"  COMMAND ${NAME} bind_error_test)
add_test(NAME "${NAME}-listen_error_test"  COMMAND ${NAME} listen_error_test)
add_test(NAME "${NAME}-uri_test"  COMMAND ${NAME} uri_test)
add_test(NAME "${NAME}-rest_client_success_test"  COMMAND ${NAME} rest_client_success_test)
add_test(NAME "${NAME}-rest_client_chunk_test"  COMMAND ${NAME} rest_client_chunk_test)
