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
                    "${CMAKE_SOURCE_DIR}/lib/dnscore/tests/modules")


add_executable(${NAME} ${SOURCE_FILES})
target_coverage_test(${NAME})
target_link_libraries(${NAME} PUBLIC ${DNSCORELIB_NAME})

add_test(NAME "${NAME}-digest32h_test"  COMMAND ${NAME} digest32h_test)
add_test(NAME "${NAME}-dnsname_test"  COMMAND ${NAME} dnsname_test)
add_test(NAME "${NAME}-dnsnamevector_test"  COMMAND ${NAME} dnsnamevector_test)
add_test(NAME "${NAME}-dnsnamestack_test"  COMMAND ${NAME} dnsnamestack_test)
add_test(NAME "${NAME}-dnslabel_test"  COMMAND ${NAME} dnslabel_test)
add_test(NAME "${NAME}-dnsclass_test"  COMMAND ${NAME} dnsclass_test)
add_test(NAME "${NAME}-dnstype_test"  COMMAND ${NAME} dnstype_test)
add_test(NAME "${NAME}-sockaddr_test"  COMMAND ${NAME} sockaddr_test)
add_test(NAME "${NAME}-sockaddrip_test"  COMMAND ${NAME} sockaddrip_test)
add_test(NAME "${NAME}-hostaddr_test"  COMMAND ${NAME} hostaddr_test)
add_test(NAME "${NAME}-hostaddrip_test"  COMMAND ${NAME} hostaddrip_test)
add_test(NAME "${NAME}-hostaddrlist_test"  COMMAND ${NAME} hostaddrlist_test)
add_test(NAME "${NAME}-rdatadesc_test"  COMMAND ${NAME} rdatadesc_test)
add_test(NAME "${NAME}-typerdatadesc_test"  COMMAND ${NAME} typerdatadesc_test)
add_test(NAME "${NAME}-recordwire_test"  COMMAND ${NAME} recordwire_test)
add_test(NAME "${NAME}-dnsrr_test"  COMMAND ${NAME} dnsrr_test)
add_test(NAME "${NAME}-dnszrr_test"  COMMAND ${NAME} dnszrr_test)
