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

add_test(NAME "${NAME}-time_epoch_as_rfc5322_test"  COMMAND ${NAME} time_epoch_as_rfc5322_test)
add_test(NAME "${NAME}-time_gm_internal_test"  COMMAND ${NAME} time_gm_internal_test)
add_test(NAME "${NAME}-timeus_test"  COMMAND ${NAME} timeus_test)
add_test(NAME "${NAME}-timeus_and_s_test"  COMMAND ${NAME} timeus_and_s_test)
add_test(NAME "${NAME}-timems_test"  COMMAND ${NAME} timems_test)
add_test(NAME "${NAME}-timems_new_test"  COMMAND ${NAME} timems_new_test)
add_test(NAME "${NAME}-usleep_ex_test"  COMMAND ${NAME} usleep_ex_test)
add_test(NAME "${NAME}-usleep_until_test"  COMMAND ${NAME} usleep_until_test)
add_test(NAME "${NAME}-mkgmtime_test"  COMMAND ${NAME} mkgmtime_test)
add_test(NAME "${NAME}-time_days_in_month_test"  COMMAND ${NAME} time_days_in_month_test)
add_test(NAME "${NAME}-time_first_day_of_month_test"  COMMAND ${NAME} time_first_day_of_month_test)
add_test(NAME "${NAME}-timeus_from_smarttime_ex_test"  COMMAND ${NAME} timeus_from_smarttime_ex_test)
add_test(NAME "${NAME}-timeus_with_offset_test"  COMMAND ${NAME} timeus_with_offset_test)
