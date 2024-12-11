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

project(yadifa LANGUAGES C)


################################################################################
#
#       GLOBAL SETTINGS
#
################################################################################

set(PACKAGE "yadifa")

message(STATUS "start making                      : yadifa")

option_has(CTRL "command line control module" true)
option_has(CRAFT "command line craft module (DO NOT RELEASE)" false)
option_has(YADIG "command line query module" true)
option_has(ZONESIGN "command line zone signing module" true)
option_has(KEYGEN "command line key generation module" true)

################################################################################
#
#       SOURCES
#
################################################################################

set(YADIFA_SOURCES
    main.c
    query_result.c
)

set(YADIFA_HEADERS
    main.h
    client_error.h
    common_config.h
    query_result.h
)

set(YADIFA_SOURCES
   ${YADIFA_SOURCES}
   common.c
   module.c
   ya_conf.c
)

set(YADIFA_HEADERS
    ${YADIFA_HEADERS}
    common.h
    module.h
    ya_conf.h
)

if(HAS_ZONESIGN)
    message("yadifa zonesign command")

    set(YADIFA_SOURCES
            ${YADIFA_SOURCES}
            module/zonesign.c
            )

    set(YADIFA_HEADERS
            ${YADIFA_HEADERS}
            module/zonesign.h
            )
endif()

kvstatus("HAS_ZONESIGN" "${HAS_ZONESIGN}")

if(HAS_KEYGEN)
    message("yadifa keygen command")

    set(YADIFA_SOURCES
            ${YADIFA_SOURCES}
            module/keygen.c
            )

    set(YADIFA_HEADERS
            ${YADIFA_HEADERS}
            module/keygen.h
            )
endif()

kvstatus("HAS_KEYGEN" "${HAS_KEYGEN}")

if(HAS_CTRL)
    message("yadifa ctrl command")

    set(YADIFA_SOURCES
        ${YADIFA_SOURCES}
        module/ctrl.c
    )

    set(YADIFA_HEADERS
        ${YADIFA_HEADERS}
        module/ctrl.h
    )
endif()

kvstatus("HAS_CTRL" "${HAS_CTRL}")

if(HAS_CRAFT)
    message("yadifa craft command")

    set(YADIFA_SOURCES
            ${YADIFA_SOURCES}
            module/craft.c
            )

    set(YADIFA_HEADERS
            ${YADIFA_HEADERS}
            module/craft.h
            )
endif()

kvstatus("HAS_CRAFT" "${HAS_CRAFT}")

if(HAS_YADIG)
    message("yadifa yadig command")

    set(YADIFA_SOURCES
        ${YADIFA_SOURCES}
        module/yadig.c
    )

    set(YADIFA_HEADERS
        ${YADIFA_HEADERS}
        module/yadig.h
    )
endif()

kvstatus("HAS_YADIG" "${HAS_YADIG}")

if(HAS_DNS_CONFIG_CHECKER)
    set(YADIFA_SOURCES
        ${YADIFA_SOURCES}
        module/dns_config_checker.c
    )

    set(YADIFA_HEADERS
        ${YADIFA_HEADERS}
        module/dns_config_checker.h
    )
endif()

kvstatus("HAS_DNS_CONFIG_CHECKER" "${HAS_DNS_CONFIG_CHECKER}")

if(HAS_DNSSEC_TOOL)
    message("yadifa dnssec command")

    set(YADIFA_SOURCES
        ${YADIFA_SOURCES}
        module/dnssec_tool.c
    )

    set(YADIFA_HEADERS
        ${YADIFA_HEADERS}
        module/dnssec_tool.h
    )
endif()
kvstatus("HAS_DNSSEC_TOOL" "${HAS_DNSSEC_TOOL}")

kvstatus("HAS_DNSQ" "${HAS_DNSQ}")

if(HAS_EXPERIMENTAL)
    set(YADIFA_SOURCES
        ${YADIFA_SOURCES}
        dnssec_test.c
    )

    set(YADIFA_HEADERS
        ${YADIFA_HEADERS}
        dnssec_test.h
    )
endif()
kvstatus("HAS_EXPERIMENTAL" "${HAS_EXPERIMENTAL}")

configure_file(client_config.h.cmake.in client_config.h)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

################################################################################
#
#       SEARCH EXTERNAL LIBRARIES
#
################################################################################

# yadifa needs:
#   - dnscore
#   - dnsdb
#   - dnszone
#   - dnslg
#
# maybe:
#   - dnstcl
#

# add headers of yadifad libraries in the search path
include_directories("${CMAKE_SOURCE_DIR}/lib/dnscore/include")
include_directories("${CMAKE_BINARY_DIR}/lib/dnscore/include")
include_directories("${CMAKE_SOURCE_DIR}/lib/dnsdb/include")
include_directories("${CMAKE_BINARY_DIR}/lib/dnsdb/include")
include_directories("${CMAKE_SOURCE_DIR}/lib/dnslg/include")
include_directories("${CMAKE_BINARY_DIR}/lib/dnslg/include")

if(HAS_TCL)
    include_directories("${CMAKE_SOURCE_DIR}/lib/dnstcl/include")
    include_directories("${CMAKE_BINARY_DIR}/lib/dnstcl/include")
else()
#
endif()

buildinfo_file("${CMAKE_BINARY_DIR}/lib/dnsdb/include/buildinfo.h")

kvstatus("HAS_TCL IN YADIFA" "${HAS_TCL}\n")
if(HAS_TCL)
    # if 'Tcl' found
    find_package(Tcl REQUIRED)
    include_directories("${CMAKE_SOURCE_DIR}/lib/dnstcl/include")

    set(YADIFA_LIBRARIES_DEPS ${YADIFA_LIBRARIES} dnstcl  ${TCL_LIB})
else()
    set(YADIFA_LIBRARIES_DEPS ${YADIFA_LIBRARIES})
endif()

# this is only to check the include path if there are some issues
# no need to add libcrypto and libssl in the linking this is done with dnscore
# find_package(Openssl REQUIRED)

################################################################################
#
#       BUILD
#
################################################################################

add_executable(yadifa ${YADIFA_SOURCES} ${YADIFA_HEADERS})

# link it with other libraries
#     - from YADIFA 'dnscore'
#     - from YADIFA 'db'
#     - from YADIFA 'dnslg'
#     - from YADIFA 'dnstcl' (maybe)

target_link_libraries(yadifa PUBLIC ${DNSLGLIB_NAME} ${DNSDBLIB_NAME} ${DNSCORELIB_NAME})

message(STATUS "making yadifa done\n")

################################################################################
#
#       INSTALLS
#
################################################################################

kvmessage("install" "yadifa")
install(TARGETS yadifa RUNTIME DESTINATION "${CMAKE_INSTALL_FULL_BINDIR}")

