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

# include(${CMAKE_SOURCE_DIR}/cmake/FindYADIFA.cmake)

get_filename_component(AUTO_NAME ${CMAKE_CURRENT_SOURCE_DIR} NAME)

message("Building test: ${AUTO_NAME}")

project(${AUTO_NAME} LANGUAGES C)

# FindYADIFA(DNSCORE DNSDB SEARCH_PATHS ../../lib/dnscore ../../lib/dnsdb)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_COMMON_FLAGS}")

include_directories(${YADIFA_INCLUDE_DIRS})

include_directories("${CMAKE_SOURCE_DIR}/lib/dnscore/include")
include_directories("${CMAKE_BINARY_DIR}/lib/dnscore/include")

include_directories("${CMAKE_SOURCE_DIR}/lib/dnsdb/include")
include_directories("${CMAKE_BINARY_DIR}/lib/dnsdb/include")

add_executable(${PROJECT_NAME} main.c)

target_link_libraries(${PROJECT_NAME} PUBLIC ${DNSCORELIB_NAME})

# If another lib is needed, but add in this order
#
# target_link_libraries(${PROJECT_NAME} ${DNSDBLIB_NAME} ${DNSCORELIB_NAME})

