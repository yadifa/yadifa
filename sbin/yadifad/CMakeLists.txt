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

project(yadifad LANGUAGES C)

set(PACKAGE "yadifad")

kvstatus("building" "${PACKAGE}")

################################################################################
#
#       SOURCES
#
################################################################################

set(YADIFAD_SOURCES
    yadifad.c
    axfr.c
    config_main.c
    config_zone.c
    confs.c
    database_service_zone_desc_load.c
    database_service_zone_desc_unload.c
    database_service_zone_download.c
    database_service_zone_freeze.c
    database_service_zone_load.c
    database_service_zone_mount.c
    database_service_zone_store.c
    database_service_zone_unfreeze.c
    database_service_zone_unload.c
    database_service_zone_unmount.c
    database_service.c
    database.c
    ixfr.c
    log_query.c
    log_statistics.c
    notify.c
    poll_util.c
    process_class_ch.c
    server.c
    server_context.c
    server_dns_tcp.c
    server_dns_tls.c
    server_rndc.c
    server_process_message_common.c
    server_process_message_tcp.c
    server_process_message_udp.c
    signals.c
    zone.c
)
if(WIN32)
message("Windows variant")
set(YADIFAD_SOURCES ${YADIFAD_SOURCES}
    server_sm.c
)
elseif(APPLE)
message("OSX variant")
set(YADIFAD_SOURCES ${YADIFAD_SOURCES}
    server_sm.c
    server_rw.c
)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "OpenBSD")
message("OpenBSD")
set(YADIFAD_SOURCES ${YADIFAD_SOURCES}
    server_sm.c
    server_rw.c
)
else()
message("UNIX variant")
set(YADIFAD_SOURCES ${YADIFAD_SOURCES}
    server_rw.c
    server_sm.c
    server_mm.c
)
endif()
set(YADIFAD_HEADERS
    yadifad.h
    axfr.h
    config_error.h
    confs.h
    database_service_zone_desc_load.h
    database_service_zone_desc_unload.h
    database_service_zone_download.h
    database_service_zone_freeze.h
    database_service_zone_load.h
    database_service_zone_mount.h
    database_service_zone_store.h
    database_service_zone_unfreeze.h
    database_service_zone_unload.h
    database_service_zone_unmount.h
    database_service.h
    database.h
    dnssec_policy.h
    ixfr.h
    log_query.h
    log_statistics.h
    notify.h
    poll_util.h
    process_class_ch.h
    server.h
    server_context.h
    server_dns_tcp.h
    server_dns_tls.h
    server_rndc.h
    server_error.h
    server_process_message_common.h
    signals.h
    zone.h
    zone_desc.h
    zone_source.h
)
if(WIN32)
elseif(APPLE)
set(YADIFAD_SOURCES ${YADIFAD_SOURCES}
    server_rw.h
    server_sm.h
)
else()
set(YADIFAD_SOURCES ${YADIFAD_SOURCES}
    server_rw.h
    server_mm.h
    server_sm.h
)
endif()

kvstatus("HAS_NSID_SUPPORT" "${HAS_NSID_SUPPORT}")

if(HAS_NSID_SUPPORT)
    set(YADIFAD_SOURCES
        ${YADIFAD_SOURCES}
        config_nsid.c
    )
endif()
kvstatus("HAS_TCL" "${HAS_TCL}")

if(HAS_TCL)
    set(YADIFAD_SOURCES
    	${YADIFAD_SOURCES}
    		server_shell.c
    )
    set(YADIFAD_HEADERS
    		${YADIFAD_HEADERS}
    		server_shell.h
    )
endif()

kvstatus("HAS_CTRL" "${HAS_CTRL}")

if(HAS_CTRL)
    set(YADIFAD_SOURCES
        ${YADIFAD_SOURCES}
        config_control.c
        config_rndc.c
        ctrl.c
        ctrl_query.c
        ctrl_zone.c
    )

    set(YADIFAD_HEADERS
        ${YADIFAD_HEADERS}
        ctrl.h
        ctrl_query.h
        ctrl_zone.h
    )

    if(HAS_EXPERIMENTAL)
        set(YADIFAD_SOURCES
            ${YADIFAD_SOURCES}
            ctrl_notify.c
            ctrl_query_axfr.c
            ctrl_query_message.c
            ctrl_update.c
        )

        set(YADIFAD_HEADERS
            ${YADIFAD_HEADERS}
            ctrl_notify.h
            ctrl_query_axfr.h
            ctrl_query_message.h
            ctrl_update.h
        )
    endif()
endif()

kvstatus("HAS_EXPERIMENTAL" "${HAS_EXPERIMENTAL}")
kvstatus("HAS_ACL_SUPPORT" "${HAS_ACL_SUPPORT}")

kvstatus("HAS_RRL_SUPPORT" "${HAS_RRL_SUPPORT}")

if(HAS_RRL_SUPPORT)
    set(YADIFAD_SOURCES
        ${YADIFAD_SOURCES}
        rrl.c
    )

    set(YADIFAD_HEADERS
        ${YADIFAD_HEADERS}
        rrl.h
    )
endif()


kvstatus("HAS_DYNUPDATE_SUPPORT" "${HAS_DYNUPDATE_SUPPORT}")
if(HAS_DYNUPDATE_SUPPORT)
    set(YADIFAD_SOURCES
        ${YADIFAD_SOURCES}
        dynupdate_query_service.c
    )

    set(YADIFAD_HEADERS
        ${YADIFAD_HEADERS}
        dynupdate_query_service.h
    )
endif()

if(HAS_DNSSEC_SUPPORT)
    kvstatus("HAS_RRSIG_MANAGEMENT_SUPPORT" "${HAS_RRSIG_MANAGEMENT_SUPPORT}")
    if(HAS_RRSIG_MANAGEMENT_SUPPORT)
        set(YADIFAD_SOURCES
            ${YADIFAD_SOURCES}
    			config_denial.c
                config_dnssec_policy.c
                config_key_roll.c
                config_key_roll_parser.c
                config_key_suite.c
                config_key_template.c
    			database_service_zone_resignature.c
                zone_signature_date_next.c
                zone_signature_date_prev.c
                zone_signature_policy.c
        )

        set(YADIFAD_HEADERS
            ${YADIFAD_HEADERS}
    			database_service_zone_resignature.h
    			config_dnssec_policy.h
    			config_key_roll_parser.h
    			zone_signature_policy.h
        )
    endif()
endif()

kvstatus("HAS_EVENT_DYNAMIC_MODULE" "${HAS_EVENT_DYNAMIC_MODULE}")
if(HAS_EVENT_DYNAMIC_MODULE)
    set(YADIFAD_SOURCES ${YADIFAD_SOURCES}
        dynamic_module_handler.c
    )
    set(YADIFAD_SOURCES ${YADIFAD_SOURCES}
        dynamic_module_handler.h
        dynamic_module_interface.h
    )
endif()

kvstatus("HAS_DYNCONF_SUPPORT" "${HAS_DYNCONF_SUPPORT}")
if(HAS_DYNCONF_SUPPORT)
    set(YADIFAD_SOURCES
        ${YADIFAD_SOURCES}
        dynconf.c
    )

    set(YADIFAD_HEADERS
        ${YADIFAD_HEADERS}
        dynconf.h
    )
endif()

configure_file(server_config.h.cmake.in server_config.h)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

################################################################################
#
#       SEARCH EXTERNAL LIBRARIES
#
################################################################################

# yadifad needs:
#   - dnscore
#   - dnsdb
#
# maybe:
#   - dnstcl
#

# add headers of yadifad libraries in the search path
include_directories("${CMAKE_SOURCE_DIR}/lib/dnscore/include")
include_directories("${CMAKE_BINARY_DIR}/lib/dnscore/include")

include_directories("${CMAKE_SOURCE_DIR}/lib/dnsdb/include")
include_directories("${CMAKE_BINARY_DIR}/lib/dnsdb/include")

#set(YADIFA_LIBRARIES
#LINK_PUBLIC dnscore
#		LINK_PRIVATE dnsdb)

buildinfo_file("${CMAKE_BINARY_DIR}/lib/dnsdb/include/buildinfo.h")

kvstatus("HAS_TCL IN YADIFAD" "${HAS_TCL}\n")
if(HAS_TCL)

    # if 'Tcl' found
    find_package(Tcl REQUIRED)
    include_directories("${CMAKE_SOURCE_DIR}/lib/dnstcl/include")

    set(YADIFAD_LIBRARIES_DEPS ${TCL_LIB})

    set(YADIFAD_SOURCES
        ${YADIFAD_SOURCES}
        server-shell.c
    )

    set(YADIFAD_HEADERS
        ${YADIFAD_HEADERS}
        server-shell.h
    )
else()
    #
endif()

# this is only to check the include path if there are some issues
# no need to add libcrypto and libssl in the linking this is done with dnscore
# find_package(Openssl REQUIRED)

################################################################################
#
# Target
#
################################################################################

add_library(yadifad-lib STATIC ${YADIFAD_SOURCES} ${YADIFAD_HEADERS})

# link it with other libraries
#     - from YADIFA 'dnscore'
#     - from YADIFA 'db'
#     - from YADIFA 'dnszone'
#     - from YADIFA 'dnstcl' (maybe)

# Set it up globally
#
#if(APPLE)
#    set(CMAKE_MACOSX_RPATH 1)
#endif()
#set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_COMMON_FLAGS}")

link_directories("${CMAKE_INSTALL_PREFIX}/lib")

target_link_libraries(yadifad-lib PUBLIC ${DNSDBLIB_NAME} ${DNSCORELIB_NAME})

add_executable(yadifad main.c)
target_link_libraries(yadifad PUBLIC yadifad-lib)

kvstatus("built" "${PACKAGE}")

################################################################################
#
# Installation
#
################################################################################

install(TARGETS yadifad RUNTIME DESTINATION "${CMAKE_INSTALL_FULL_SBINDIR}")
