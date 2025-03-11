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

project(dnslg LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(LIBRARY_SO_VERSION                       10.0.0)
set(LIBRARY_SO_MAJOR                             10)

set(PACKAGE "dnslg")

kvstatus("building" "${PACKAGE}")

add_definitions(-DDNSLG_BUILD)

################################################################################
#
#       SOURCES
#
################################################################################

set(LIBRARY_SOURCE_PATH "src")
set(LIBRARY_HEADER_PATH "include/dnslg")
set(LIBRARY_CONFIG_FILE "dnslg_config.h")
set(LIBRARY_FEATURES_FILE "dnslg_config_features.h")
set(LIBRARY_FEATURES_PREFIX "DNSLG_")

set(LIBRARY_SOURCES
    ${LIBRARY_SOURCE_PATH}/config_load.c
    ${LIBRARY_SOURCE_PATH}/config_resolver.c
    ${LIBRARY_SOURCE_PATH}/dns.c
    ${LIBRARY_SOURCE_PATH}/resolv_conf.c
    ${LIBRARY_SOURCE_PATH}/resolv.c
)

set(LIBRARY_HEADERS
    ${LIBRARY_HEADER_PATH}/config_load.h
    ${LIBRARY_HEADER_PATH}/config_resolver.h
    ${LIBRARY_HEADER_PATH}/dns.h
    ${LIBRARY_HEADER_PATH}/resolv_conf.h
    ${LIBRARY_HEADER_PATH}/resolv.h
)

# add itself as search path
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/include")
include_directories("${CMAKE_CURRENT_BINARY_DIR}/include")

################################################################################
#
# Config & features
#
################################################################################

kvstatus("creating" "${LIBRARY_HEADER_PATH}/${LIBRARY_CONFIG_FILE}")
configure_file("${LIBRARY_CONFIG_FILE}.cmake.in" "${LIBRARY_HEADER_PATH}/${LIBRARY_CONFIG_FILE}")

kvstatus("creating" "${LIBRARY_FEATURES_FILE}")
prefixes_configure_file("${CMAKE_CURRENT_BINARY_DIR}/${LIBRARY_HEADER_PATH}/${LIBRARY_CONFIG_FILE}" "${CMAKE_CURRENT_BINARY_DIR}/${LIBRARY_HEADER_PATH}/${LIBRARY_FEATURES_FILE}" "${LIBRARY_FEATURES_PREFIX}")
set(LIBRARY_HEADERS ${LIBRARY_HEADERS} "${CMAKE_CURRENT_BINARY_DIR}/${LIBRARY_HEADER_PATH}/${LIBRARY_FEATURES_FILE}")

################################################################################
#
# Dependencies
#
################################################################################

include_directories("${CMAKE_SOURCE_DIR}/lib/dnscore/include")
include_directories("${CMAKE_BINARY_DIR}/lib/dnscore/include")

set(DNSLG_LIBRARIES_DEPS ${DNSCORELIB_NAME})

kvstatus("DNSLG_LIBRARIES_DEPS" "${DNSLG_LIBRARIES_DEPS}")

################################################################################
#
# Targets
#
################################################################################

if(BUILD_SHARED_LIBS)
    kvstatus("dnslg build" "shared")
    add_library(dnslg SHARED             ${LIBRARY_SOURCES} ${LIBRARY_HEADERS})
    link_directories("${CMAKE_INSTALL_PREFIX}/lib")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_COMMON_FLAGS} ${C_LIBRARY_FLAGS}")
    set_target_properties(dnslg PROPERTIES SOVERSION ${LIBRARY_SO_VERSION})
    set_target_properties(dnslg PROPERTIES VERSION ${LIBRARY_SO_MAJOR})
    target_link_libraries(dnslg ${DNSLG_LIBRARIES_DEPS})
endif()

if(BUILD_STATIC_LIBS)
    kvstatus("dnslg build" "static")
    add_library(dnslg-static STATIC ${LIBRARY_SOURCES} ${LIBRARY_HEADERS})
    set_target_properties(dnslg-static PROPERTIES OUTPUT_NAME dnslg)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_COMMON_FLAGS} ${C_LIBRARY_FLAGS}")

    link_directories("${CMAKE_INSTALL_PREFIX}/lib")
    target_link_libraries(dnslg-static ${DNSLG_LIBRARIES_DEPS})
endif()


kvstatus("making ${PACKAGE}" "done")

################################################################################
#
# Installation
#
################################################################################

if(BUILD_SHARED_LIBS)
    kvstatus("install" "${PACKAGE} shared libray")
    install(TARGETS dnslg LIBRARY DESTINATION "${CMAKE_INSTALL_FULL_LIBDIR}")
    set(DNSLGLIB_NAME "dnslg" CACHE STRING "dnslg library name" FORCE)
endif()

if(BUILD_STATIC_LIBS)
    kvstatus("install" "${PACKAGE} static library")
    install(TARGETS dnslg-static LIBRARY DESTINATION "${CMAKE_INSTALL_FULL_LIBDIR}")
    set(DNSLGLIB_NAME "dnslg-static" CACHE STRING "dnslg library name" FORCE)
endif()

install(FILES ${LIBRARY_HEADERS} DESTINATION "${CMAKE_INSTALL_FULL_INCLUDEDIR}/dnslg")
