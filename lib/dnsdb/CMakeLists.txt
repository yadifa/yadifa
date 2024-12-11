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
project(dnsdb LANGUAGES C)

include(${CMAKE_SOURCE_DIR}/cmake/EURidToolbox.cmake)

set(CMAKE_C_STANDARD 11)
set(LIBRARY_SO_VERSION 10.0.0)
set(LIBRARY_SO_MAJOR 10)

set(PACKAGE "dnsdb")

kvstatus("building" "${PACKAGE}")

add_definitions(-DDNSDB_BUILD)

################################################################################
#
#       SOURCES
#
################################################################################

set(LIBRARY_SOURCE_PATH "src")
set(LIBRARY_HEADER_PATH "include/dnsdb")
set(LIBRARY_CONFIG_FILE "dnsdb_config.h")
set(LIBRARY_FEATURES_FILE "zdb_config_features.h")
set(LIBRARY_FEATURES_PREFIX "ZDB_")

set(LIBRARY_SOURCES
        ${LIBRARY_SOURCE_PATH}/avl.c
        ${LIBRARY_SOURCE_PATH}/dictionary.c
        ${LIBRARY_SOURCE_PATH}/dictionary_btree.c
        ${LIBRARY_SOURCE_PATH}/dictionary_htbt.c
        ${LIBRARY_SOURCE_PATH}/htable.c
        ${LIBRARY_SOURCE_PATH}/htbt.c
		${LIBRARY_SOURCE_PATH}/journal_cjf.c
        ${LIBRARY_SOURCE_PATH}/journal_cjf_idxt.c
        ${LIBRARY_SOURCE_PATH}/journal_cjf_page_cache.c
        ${LIBRARY_SOURCE_PATH}/journal_cjf_page_output_stream.c
        ${LIBRARY_SOURCE_PATH}/journal_cjf_page.c
		${LIBRARY_SOURCE_PATH}/journal_cjf_ro.c
        ${LIBRARY_SOURCE_PATH}/journal.c
        ${LIBRARY_SOURCE_PATH}/journal_ix.c
        ${LIBRARY_SOURCE_PATH}/journal_jnl.c
        ${LIBRARY_SOURCE_PATH}/xfr_copy.c

		${LIBRARY_SOURCE_PATH}/zdb_zone_resource_record.c
		${LIBRARY_SOURCE_PATH}/zdb_zone_resource_record_set.c
		${LIBRARY_SOURCE_PATH}/zdb_zone_resource_record_sets.c
		${LIBRARY_SOURCE_PATH}/zdb_zone_resource_record_sets_collection.c

        ${LIBRARY_SOURCE_PATH}/zdb_zone_answer_axfr.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_answer_ixfr.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_arc.c
		#${LIBRARY_SOURCE_PATH}/zdb_zone_diff.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_dnssec.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_find.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_garbage.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_journal.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_lock.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_lock_monitor.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_path_provider.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_reader_filter.c
        ${LIBRARY_SOURCE_PATH}/zdb.c
        ${LIBRARY_SOURCE_PATH}/zdb_cache.c
        ${LIBRARY_SOURCE_PATH}/zdb_error.c
        ${LIBRARY_SOURCE_PATH}/zdb_icmtl.c
		${LIBRARY_SOURCE_PATH}/zdb_query_to_wire.c
		${LIBRARY_SOURCE_PATH}/zdb_query_to_wire_append.c
		${LIBRARY_SOURCE_PATH}/zdb_query_to_wire_append_nsec.c
		${LIBRARY_SOURCE_PATH}/zdb_query_to_wire_append_nsec3.c
		${LIBRARY_SOURCE_PATH}/zdb_query_to_wire_append_soa.c
		${LIBRARY_SOURCE_PATH}/zdb_query_to_wire_append_type_rrsigs.c
		${LIBRARY_SOURCE_PATH}/zdb_record.c
        ${LIBRARY_SOURCE_PATH}/zdb_rr_label.c
        ${LIBRARY_SOURCE_PATH}/zdb_sanitize.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_axfr_input_stream.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_label.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_label_iterator.c
		${LIBRARY_SOURCE_PATH}/zdb_zone_label_iterator_ex.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_load.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_process.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_store_axfr.c
		${LIBRARY_SOURCE_PATH}/zdb_zone_store_czf.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_write_text.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_write_unbound.c
)

set(LIBRARY_HEADERS
        ${LIBRARY_HEADER_PATH}/avl.h
        ${LIBRARY_HEADER_PATH}/btree.h
        ${LIBRARY_HEADER_PATH}/dictionary.h
        ${LIBRARY_HEADER_PATH}/dictionary_node.h
        ${LIBRARY_HEADER_PATH}/dnsrdata.h
        ${LIBRARY_HEADER_PATH}/dnssec.h
        ${LIBRARY_HEADER_PATH}/dnssec_config.h
        ${LIBRARY_HEADER_PATH}/dnssec_keystore.h
        ${LIBRARY_HEADER_PATH}/htable.h
        ${LIBRARY_HEADER_PATH}/htbt.h
        ${LIBRARY_HEADER_PATH}/journal_cjf.h
        ${LIBRARY_HEADER_PATH}/journal_cjf_common.h
        ${LIBRARY_HEADER_PATH}/journal_cjf_idxt.h
        ${LIBRARY_HEADER_PATH}/journal_cjf_page.h
        ${LIBRARY_HEADER_PATH}/journal_cjf_page_cache.h
        ${LIBRARY_HEADER_PATH}/journal_cjf_page_output_stream.h
        ${LIBRARY_HEADER_PATH}/journal.h
        ${LIBRARY_HEADER_PATH}/journal_ix.h
        ${LIBRARY_HEADER_PATH}/journal_jnl.h
        ${LIBRARY_HEADER_PATH}/chain_replay.h
        ${LIBRARY_HEADER_PATH}/nsec.h
        ${LIBRARY_HEADER_PATH}/nsec_chain_replay.h
        ${LIBRARY_HEADER_PATH}/nsec3.h
        ${LIBRARY_HEADER_PATH}/nsec3_collection.h
        ${LIBRARY_HEADER_PATH}/nsec3_chain_replay.h
        ${LIBRARY_HEADER_PATH}/nsec3_item.h
        ${LIBRARY_HEADER_PATH}/nsec3_load.h
        ${LIBRARY_HEADER_PATH}/nsec3_owner.h
        ${LIBRARY_HEADER_PATH}/nsec3_types.h
        ${LIBRARY_HEADER_PATH}/nsec3_zone.h
        ${LIBRARY_HEADER_PATH}/nsec_collection.h
        ${LIBRARY_HEADER_PATH}/nsec_common.h
        ${LIBRARY_HEADER_PATH}/rrsig.h
        ${LIBRARY_HEADER_PATH}/xfr_copy.h
        ${LIBRARY_HEADER_PATH}/zdb.h
        ${LIBRARY_HEADER_PATH}/zdb_config.h
        ${LIBRARY_HEADER_PATH}/zdb_error.h
        ${LIBRARY_HEADER_PATH}/zdb_icmtl.h
		${LIBRARY_HEADER_PATH}/zdb_query_to_wire.h
		${LIBRARY_HEADER_PATH}/zdb_query_to_wire_append.h
		${LIBRARY_HEADER_PATH}/zdb_query_to_wire_append_nsec.h
		${LIBRARY_HEADER_PATH}/zdb_query_to_wire_append_nsec3.h
		${LIBRARY_HEADER_PATH}/zdb_query_to_wire_append_soa.h
		${LIBRARY_HEADER_PATH}/zdb_query_to_wire_append_type_rrsigs.h
		${LIBRARY_HEADER_PATH}/zdb_query_to_wire_context.h
        ${LIBRARY_HEADER_PATH}/zdb_record.h
        ${LIBRARY_HEADER_PATH}/zdb_rr_label.h
        ${LIBRARY_HEADER_PATH}/zdb_sanitize.h
		${LIBRARY_HEADER_PATH}/zdb_ttlrdata.h
        ${LIBRARY_HEADER_PATH}/zdb_types.h
        ${LIBRARY_HEADER_PATH}/zdb_cache.h
        ${LIBRARY_HEADER_PATH}/zdb_zone.h
        ${LIBRARY_HEADER_PATH}/zdb_lock.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_arc.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_dnssec.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_find.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_garbage.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_journal.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_lock.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_lock_monitor.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_answer_axfr.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_answer_ixfr.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_maintenance.h
        ${LIBRARY_HEADER_PATH}/zdb_packed_ttlrdata.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_axfr_input_stream.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_label.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_label_iterator.h
		${LIBRARY_HEADER_PATH}/zdb_zone_label_iterator_ex.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_load.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_path_provider.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_process.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_reader_filter.h
		${LIBRARY_HEADER_PATH}/zdb_zone_resource_record.h
		${LIBRARY_HEADER_PATH}/zdb_zone_resource_record_set.h
		${LIBRARY_HEADER_PATH}/zdb_zone_resource_record_sets.h
        ${LIBRARY_HEADER_PATH}/zdb_zone_write.h
        ${LIBRARY_HEADER_PATH}/nsec3_forall_label.h
)


kvstatus("HAS_DYNUPDATE_SUPPORT" "${HAS_DYNUPDATE_SUPPORT}")
if(HAS_DYNUPDATE_SUPPORT)
    set(LIBRARY_SOURCES
        ${LIBRARY_SOURCES}
        ${LIBRARY_SOURCE_PATH}/dynupdate_check_prerequisites.c
        ${LIBRARY_SOURCE_PATH}/dynupdate_diff.c
        ${LIBRARY_SOURCE_PATH}/dynupdate_diff_nochain.c
        ${LIBRARY_SOURCE_PATH}/dynupdate_diff_nsec.c
        ${LIBRARY_SOURCE_PATH}/dynupdate_diff_nsec3.c
		${LIBRARY_SOURCE_PATH}/dynupdate_message.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_maintenance.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_maintenance_rrsig.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_maintenance_nsec.c
        ${LIBRARY_SOURCE_PATH}/zdb_zone_maintenance_nsec3.c
	)
    set(LIBRARY_HEADERS
        ${LIBRARY_HEADERS}
	    ${LIBRARY_HEADER_PATH}/dynupdate.h
	    ${LIBRARY_HEADER_PATH}/dynupdate_diff.h
		${LIBRARY_HEADER_PATH}/dynupdate_message.h
    )
endif()

kvstatus("HAS_DNSSEC_SUPPORT" "${HAS_DNSSEC_SUPPORT}")
if(HAS_DNSSEC_SUPPORT)
		set(LIBRARY_SOURCES
        ${LIBRARY_SOURCES}
        ${LIBRARY_SOURCE_PATH}/dnssec.c
        ${LIBRARY_SOURCE_PATH}/dnssec_keystore.c
        ${LIBRARY_SOURCE_PATH}/nsec_common.c
        ${LIBRARY_SOURCE_PATH}/rrsig.c
        ${LIBRARY_SOURCE_PATH}/zdb_packed_ttlrdata.c
    )
endif()

kvstatus("HAS_NSEC3_SUPPORT" "${HAS_NSEC3_SUPPORT}")
if(HAS_NSEC3_SUPPORT)
		set(LIBRARY_SOURCES
        ${LIBRARY_SOURCES}
        ${LIBRARY_SOURCE_PATH}/nsec3.c
        ${LIBRARY_SOURCE_PATH}/nsec3_collection.c
        ${LIBRARY_SOURCE_PATH}/nsec3_item.c
        ${LIBRARY_SOURCE_PATH}/nsec3_chain_replay.c
        ${LIBRARY_SOURCE_PATH}/nsec3_load.c
        ${LIBRARY_SOURCE_PATH}/nsec3_owner.c
        ${LIBRARY_SOURCE_PATH}/nsec3_zone.c
        ${LIBRARY_SOURCE_PATH}/nsec3_forall_label.c
    )

		set(LIBRARY_HEADERS
        ${LIBRARY_HEADERS}
#        ${LIBRARY_HEADER_PATH}/nsec3.h
#        ${LIBRARY_HEADER_PATH}/nsec3_collection.h
#        ${LIBRARY_HEADER_PATH}/nsec3_hash.h
#        ${LIBRARY_HEADER_PATH}/nsec3_item.h
#        ${LIBRARY_HEADER_PATH}/nsec3_load.h
#        ${LIBRARY_HEADER_PATH}/nsec3_owner.h
#        ${LIBRARY_HEADER_PATH}/nsec3_types.h
#        ${LIBRARY_HEADER_PATH}/nsec3_zone.h
    )
endif()

if(HAS_NSEC_SUPPORT)
		set(LIBRARY_SOURCES
        ${LIBRARY_SOURCES}
        ${LIBRARY_SOURCE_PATH}/nsec.c
		${LIBRARY_SOURCE_PATH}/nsec_chain_replay.c
        ${LIBRARY_SOURCE_PATH}/nsec_collection.c
    )

		set(LIBRARY_HEADERS
        ${LIBRARY_HEADERS}
#        ${LIBRARY_HEADER_PATH}/nsec.h
#        ${LIBRARY_HEADER_PATH}/nsec_collection.h
#        ${LIBRARY_HEADER_PATH}/nsec_common.h
    )
endif()

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

# dnscore headers

include_directories("${CMAKE_SOURCE_DIR}/lib/dnscore/include")
include_directories("${CMAKE_BINARY_DIR}/lib/dnscore/include")

# this is only to check the include path if there are some issues
# no need to add libcrypto and libssl in the linking this is done with dnscore
# find_package(Openssl REQUIRED)

set(DNSDB_LIBRARIES_DEPS ${DNSCORELIB_NAME})

kvstatus("DNSDB_LIBRARIES_DEPS" "${DNSDB_LIBRARIES_DEPS}")

################################################################################
#
# Targets
#
################################################################################

add_library(dnsdb-objects OBJECT ${LIBRARY_SOURCES} ${LIBRARY_HEADERS})
kvmessage("CMAKE_C_FLAGS" "${CMAKE_C_FLAGS}")

if(BUILD_SHARED_LIBS)
	kvstatus("${PACKAGE} build" "shared")
	add_library(dnsdb SHARED $<TARGET_OBJECTS:dnsdb-objects> ${LIBRARY_HEADERS})
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_COMMON_FLAGS} ${C_LIBRARY_FLAGS}")
	kvmessage("CMAKE_C_FLAGS" "${CMAKE_C_FLAGS}")
    set_target_properties(dnsdb PROPERTIES SOVERSION ${LIBRARY_SO_VERSION})
    set_target_properties(dnsdb PROPERTIES VERSION ${LIBRARY_SO_MAJOR})

	# link it with other libraries
	#     - from YADIFA 'dnscore'
	target_link_libraries(dnsdb ${DNSDB_LIBRARIES_DEPS})
endif()

if(BUILD_STATIC_LIBS)
	kvstatus("${PACKAGE} build" "static")
	add_library(dnsdb-static STATIC $<TARGET_OBJECTS:dnsdb-objects> ${LIBRARY_HEADERS})
	set_target_properties(dnsdb-static PROPERTIES OUTPUT_NAME dnsdb)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_COMMON_FLAGS} ${C_LIBRARY_FLAGS}")
	kvmessage("CMAKE_C_FLAGS" "${CMAKE_C_FLAGS}")

	link_directories("${CMAKE_INSTALL_PREFIX}/lib")
	target_link_libraries(dnsdb-static ${DNSDB_LIBRARIES_DEPS})
endif()

kvstatus("making ${PACKAGE}" "done")

################################################################################
#
# Installation
#
################################################################################

if(BUILD_SHARED_LIBS)
	kvstatus("install" "${PACKAGE} shared libray")
	install(TARGETS dnsdb LIBRARY DESTINATION "${CMAKE_INSTALL_FULL_LIBDIR}")
	set(DNSDBLIB_NAME "dnsdb" CACHE STRING "dnsdb library name" FORCE)
endif()

if(BUILD_STATIC_LIBS)
	kvstatus("install" "${PACKAGE} static library")
	install(TARGETS dnsdb-static LIBRARY DESTINATION "${CMAKE_INSTALL_FULL_LIBDIR}")
	set(DNSDBLIB_NAME "dnsdb-static" CACHE STRING "dnsdb library name" FORCE)
endif()

install(FILES ${LIBRARY_HEADERS} DESTINATION "${CMAKE_INSTALL_FULL_INCLUDEDIR}/dnsdb")
