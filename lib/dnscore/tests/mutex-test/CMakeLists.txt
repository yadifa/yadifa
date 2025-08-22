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

add_test(NAME "${NAME}-exclusion2_test"  COMMAND ${NAME} exclusion2_test)
add_test(NAME "${NAME}-exclusion4_test"  COMMAND ${NAME} exclusion4_test)
add_test(NAME "${NAME}-exclusion8_test"  COMMAND ${NAME} exclusion8_test)
add_test(NAME "${NAME}-exclusion_recursive2_test"  COMMAND ${NAME} exclusion_recursive2_test)
add_test(NAME "${NAME}-exclusion_recursive4_test"  COMMAND ${NAME} exclusion_recursive4_test)
add_test(NAME "${NAME}-exclusion_recursive8_test"  COMMAND ${NAME} exclusion_recursive8_test)
add_test(NAME "${NAME}-exclusion_group2_test"  COMMAND ${NAME} exclusion_group2_test)
add_test(NAME "${NAME}-exclusion_group4_test"  COMMAND ${NAME} exclusion_group4_test)
add_test(NAME "${NAME}-exclusion_group8_test"  COMMAND ${NAME} exclusion_group8_test)
add_test(NAME "${NAME}-exclusion_shared_mutex2_test"  COMMAND ${NAME} exclusion_shared_mutex2_test)
add_test(NAME "${NAME}-exclusion_shared_mutex4_test"  COMMAND ${NAME} exclusion_shared_mutex4_test)
add_test(NAME "${NAME}-exclusion_shared_mutex8_test"  COMMAND ${NAME} exclusion_shared_mutex8_test)
add_test(NAME "${NAME}-exclusion_shared_mutex_try2_test"  COMMAND ${NAME} exclusion_shared_mutex_try2_test)
add_test(NAME "${NAME}-exclusion_shared_mutex_recursive2_test"  COMMAND ${NAME} exclusion_shared_mutex_recursive2_test)
add_test(NAME "${NAME}-exclusion_shared_mutex_recursive4_test"  COMMAND ${NAME} exclusion_shared_mutex_recursive4_test)
add_test(NAME "${NAME}-exclusion_shared_mutex_recursive8_test"  COMMAND ${NAME} exclusion_shared_mutex_recursive8_test)
add_test(NAME "${NAME}-shared_group_mutex_transferlock_test"  COMMAND ${NAME} shared_group_mutex_transferlock_test)
add_test(NAME "${NAME}-speed_test"  COMMAND ${NAME} speed_test)
add_test(NAME "${NAME}-mutex_debug_test"  COMMAND ${NAME} mutex_debug_test)
add_test(NAME "${NAME}-mutex_futex_test"  COMMAND ${NAME} mutex_futex_test)
add_test(NAME "${NAME}-mutex_semaphore_test"  COMMAND ${NAME} mutex_semaphore_test)
add_test(NAME "${NAME}-mutex_semaphore_shared_mem_test"  COMMAND ${NAME} mutex_semaphore_shared_mem_test)
