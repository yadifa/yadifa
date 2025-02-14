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
include(${CMAKE_SOURCE_DIR}/cmake/EURidToolbox.cmake)

project(dnscore LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(LIBRARY_SO_VERSION                       10.0.0)
set(LIBRARY_SO_MAJOR                             10)

set(PACKAGE "dnscore")

kvstatus("building" "${PACKAGE}")

add_definitions(-DDNSCORE_BUILD)

################################################################################
#
#       SOURCES
#
################################################################################

set(LIBRARY_SOURCE_PATH "src")
set(LIBRARY_HEADER_PATH "include/dnscore")
set(LIBRARY_CONFIG_FILE "dnscore_config.h")
set(LIBRARY_FEATURES_FILE "dnscore_config_features.h")
set(LIBRARY_FEATURES_PREFIX "DNSCORE_")

set(LIBRARY_SOURCES
    ${LIBRARY_SOURCE_PATH}/acl.c
    ${LIBRARY_SOURCE_PATH}/acl_config.c
    ${LIBRARY_SOURCE_PATH}/alarm.c
    #${LIBRARY_SOURCE_PATH}/allocator.c
    ${LIBRARY_SOURCE_PATH}/async.c
    ${LIBRARY_SOURCE_PATH}/base16.c
    ${LIBRARY_SOURCE_PATH}/base32.c
    ${LIBRARY_SOURCE_PATH}/base32hex.c
    ${LIBRARY_SOURCE_PATH}/base64.c
    ${LIBRARY_SOURCE_PATH}/basic_priority_queue.c
    ${LIBRARY_SOURCE_PATH}/buffer_input_stream.c
    ${LIBRARY_SOURCE_PATH}/buffer_output_stream.c
    ${LIBRARY_SOURCE_PATH}/buffered_file.c
    ${LIBRARY_SOURCE_PATH}/bytearray_input_stream.c
    ${LIBRARY_SOURCE_PATH}/bytearray_output_stream.c
    ${LIBRARY_SOURCE_PATH}/bytezarray_output_stream.c
    ${LIBRARY_SOURCE_PATH}/cache.c
    ${LIBRARY_SOURCE_PATH}/checked_output_stream.c
    ${LIBRARY_SOURCE_PATH}/circular_file.c
    ${LIBRARY_SOURCE_PATH}/clone_input_output_stream.c
    ${LIBRARY_SOURCE_PATH}/cmdline.c
    ${LIBRARY_SOURCE_PATH}/concat_input_stream.c
    ${LIBRARY_SOURCE_PATH}/config_cmdline.c
    ${LIBRARY_SOURCE_PATH}/config_file_reader.c
    ${LIBRARY_SOURCE_PATH}/config_key.c
    ${LIBRARY_SOURCE_PATH}/config_logger.c
    ${LIBRARY_SOURCE_PATH}/config_settings.c
    ${LIBRARY_SOURCE_PATH}/config_struct.c
    ${LIBRARY_SOURCE_PATH}/counter_output_stream.c
    ${LIBRARY_SOURCE_PATH}/crypto.c
    ${LIBRARY_SOURCE_PATH}/crc32.c
    ${LIBRARY_SOURCE_PATH}/debug.c
    ${LIBRARY_SOURCE_PATH}/debug_bench.c
    ${LIBRARY_SOURCE_PATH}/debug_bfd.c
    ${LIBRARY_SOURCE_PATH}/debug_malloc.c
    ${LIBRARY_SOURCE_PATH}/debug_mmap.c
    ${LIBRARY_SOURCE_PATH}/debug_stacktrace.c
    ${LIBRARY_SOURCE_PATH}/digest_rawdata.c
    ${LIBRARY_SOURCE_PATH}/dns_udp.c
    ${LIBRARY_SOURCE_PATH}/dns_message_verify_rrsig.c
    ${LIBRARY_SOURCE_PATH}/dns_message_writer_dig.c
    ${LIBRARY_SOURCE_PATH}/dns_message_writer_json.c
    ${LIBRARY_SOURCE_PATH}/dns_message_writer_easyparse.c
    ${LIBRARY_SOURCE_PATH}/dns_resource_record.c
    ${LIBRARY_SOURCE_PATH}/dnscore.c
    ${LIBRARY_SOURCE_PATH}/dnscore_extension.c
    ${LIBRARY_SOURCE_PATH}/dnsformat.c
    ${LIBRARY_SOURCE_PATH}/dnskey.c
    ${LIBRARY_SOURCE_PATH}/dnskey_keyring.c
    ${LIBRARY_SOURCE_PATH}/dnskey_eddsa.c
    ${LIBRARY_SOURCE_PATH}/dnskey_signature.c
    ${LIBRARY_SOURCE_PATH}/dnsname.c
    ${LIBRARY_SOURCE_PATH}/empty_input_stream.c
    ${LIBRARY_SOURCE_PATH}/error_state.c
    ${LIBRARY_SOURCE_PATH}/fdtools.c
    ${LIBRARY_SOURCE_PATH}/file_input_stream.c
    ${LIBRARY_SOURCE_PATH}/file_mtime_set.c
    ${LIBRARY_SOURCE_PATH}/file_output_stream.c
    ${LIBRARY_SOURCE_PATH}/file_pool.c
    ${LIBRARY_SOURCE_PATH}/filesystem_file.c
    ${LIBRARY_SOURCE_PATH}/format.c
    ${LIBRARY_SOURCE_PATH}/hash.c
    ${LIBRARY_SOURCE_PATH}/hash_table_values.c
    ${LIBRARY_SOURCE_PATH}/host_address.c
    #${LIBRARY_SOURCE_PATH}/hsdllist.c
    ${LIBRARY_SOURCE_PATH}/http_chunk_output_stream.c
    ${LIBRARY_SOURCE_PATH}/identity.c
    ${LIBRARY_SOURCE_PATH}/initialise_state.c
    ${LIBRARY_SOURCE_PATH}/input_stream.c
    #${LIBRARY_SOURCE_PATH}/ipc.c
    ${LIBRARY_SOURCE_PATH}/json.c
    ${LIBRARY_SOURCE_PATH}/limited_input_stream.c
    ${LIBRARY_SOURCE_PATH}/limiter.c
    ${LIBRARY_SOURCE_PATH}/list_dl.c
    ${LIBRARY_SOURCE_PATH}/list_dl_nodata.c
    ${LIBRARY_SOURCE_PATH}/list_sl.c
    ${LIBRARY_SOURCE_PATH}/list_sl_debug.c
    ${LIBRARY_SOURCE_PATH}/logger_output_stream.c
    ${LIBRARY_SOURCE_PATH}/logger.c
    ${LIBRARY_SOURCE_PATH}/logger_channel_file.c
    ${LIBRARY_SOURCE_PATH}/logger_channel_stream.c
    ${LIBRARY_SOURCE_PATH}/logger_channel_syslog.c
    ${LIBRARY_SOURCE_PATH}/logger_handle.c
    ${LIBRARY_SOURCE_PATH}/mapped_file.c
    ${LIBRARY_SOURCE_PATH}/dns_message.c
    ${LIBRARY_SOURCE_PATH}/dns_message_writer.c
    ${LIBRARY_SOURCE_PATH}/dns_message_update.c
    ${LIBRARY_SOURCE_PATH}/mt_output_stream.c
    ${LIBRARY_SOURCE_PATH}/mutex.c
    ${LIBRARY_SOURCE_PATH}/mutex_contention_monitor.c
    ${LIBRARY_SOURCE_PATH}/mutex_debug.c
    ${LIBRARY_SOURCE_PATH}/mutex_futex.c
    ${LIBRARY_SOURCE_PATH}/mutex_group.c
    ${LIBRARY_SOURCE_PATH}/mutex_mutex.c
    ${LIBRARY_SOURCE_PATH}/mutex_shared_group.c
    ${LIBRARY_SOURCE_PATH}/network.c
    #${LIBRARY_SOURCE_PATH}/name.c
    ${LIBRARY_SOURCE_PATH}/nsec3_hash.c
    ${LIBRARY_SOURCE_PATH}/output_stream.c
    ${LIBRARY_SOURCE_PATH}/pace.c
    ${LIBRARY_SOURCE_PATH}/dns_packet_reader.c
    ${LIBRARY_SOURCE_PATH}/dns_packet_writer.c
    ${LIBRARY_SOURCE_PATH}/parser.c
    ${LIBRARY_SOURCE_PATH}/parsing.c
    ${LIBRARY_SOURCE_PATH}/pcg_basic.c
    ${LIBRARY_SOURCE_PATH}/permut.c
    ${LIBRARY_SOURCE_PATH}/process.c
    ${LIBRARY_SOURCE_PATH}/pid.c
    ${LIBRARY_SOURCE_PATH}/pipe_stream.c
    ${LIBRARY_SOURCE_PATH}/pool.c
    ${LIBRARY_SOURCE_PATH}/ptr_treeset.c
    ${LIBRARY_SOURCE_PATH}/ptr_treeset_debug.c
    ${LIBRARY_SOURCE_PATH}/ptr_treemap.c
    ${LIBRARY_SOURCE_PATH}/ptr_treemap_debug.c
    ${LIBRARY_SOURCE_PATH}/ptr_vector.c
    ${LIBRARY_SOURCE_PATH}/pushback_input_stream.c
    ${LIBRARY_SOURCE_PATH}/queue_sl.c
    ${LIBRARY_SOURCE_PATH}/random.c
    ${LIBRARY_SOURCE_PATH}/rest_client.c
    ${LIBRARY_SOURCE_PATH}/rest_server.c
    ${LIBRARY_SOURCE_PATH}/rewind_input_stream.c
    ${LIBRARY_SOURCE_PATH}/rfc.c
    ${LIBRARY_SOURCE_PATH}/rndc.c
    ${LIBRARY_SOURCE_PATH}/serial.c
    ${LIBRARY_SOURCE_PATH}/server_setup.c
    ${LIBRARY_SOURCE_PATH}/service.c
    ${LIBRARY_SOURCE_PATH}/shared_heap.c
    ${LIBRARY_SOURCE_PATH}/shared_circular_buffer.c
    ${LIBRARY_SOURCE_PATH}/shared_heap_bytearray_output_stream.c
    ${LIBRARY_SOURCE_PATH}/signals.c
    ${LIBRARY_SOURCE_PATH}/simple_http_server.c
    ${LIBRARY_SOURCE_PATH}/socket_server.c
    ${LIBRARY_SOURCE_PATH}/ssl_input_output_stream.c
    ${LIBRARY_SOURCE_PATH}/string_set.c
    ${LIBRARY_SOURCE_PATH}/sys_error.c
    ${LIBRARY_SOURCE_PATH}/sys_get_cpu_count.c
    ${LIBRARY_SOURCE_PATH}/tcp_io_stream.c
    ${LIBRARY_SOURCE_PATH}/tcp_manager2.c
    ${LIBRARY_SOURCE_PATH}/tcp_manager_channel_ssl_context.c
    ${LIBRARY_SOURCE_PATH}/thread_pool.c
    ${LIBRARY_SOURCE_PATH}/thread.c
    ${LIBRARY_SOURCE_PATH}/thread_setaffinity_macos.c
    ${LIBRARY_SOURCE_PATH}/thread_tag.c
    ${LIBRARY_SOURCE_PATH}/threaded_qsl_cw.c
    ${LIBRARY_SOURCE_PATH}/threaded_dll_cw.c
    ${LIBRARY_SOURCE_PATH}/threaded_nbrb.c
    ${LIBRARY_SOURCE_PATH}/threaded_queue_slg.c
    ${LIBRARY_SOURCE_PATH}/threaded_ringbuffer_cw.c
    ${LIBRARY_SOURCE_PATH}/timeformat.c
    ${LIBRARY_SOURCE_PATH}/timems.c
    ${LIBRARY_SOURCE_PATH}/tools.c
    ${LIBRARY_SOURCE_PATH}/typebitmap.c
    ${LIBRARY_SOURCE_PATH}/u32_treeset.c
    ${LIBRARY_SOURCE_PATH}/u64_treeset.c
    ${LIBRARY_SOURCE_PATH}/u64_treeset_debug.c
    ${LIBRARY_SOURCE_PATH}/u32_treemap.c
    ${LIBRARY_SOURCE_PATH}/u64_treemap.c
    ${LIBRARY_SOURCE_PATH}/uri.c
    ${LIBRARY_SOURCE_PATH}/utf8.c
    ${LIBRARY_SOURCE_PATH}/xfr_input_stream.c
    ${LIBRARY_SOURCE_PATH}/zalloc.c
    ${LIBRARY_SOURCE_PATH}/zone_reader_axfr.c
    ${LIBRARY_SOURCE_PATH}/zone_reader_text.c
)

if(NOT WIN32)
    if(OPENSSL_VERSION_MAJOR LESS 3)
        message("using libssl < 3.0 API")
        set(LIBRARY_SOURCES ${LIBRARY_SOURCES}
            #${LIBRARY_SOURCE_PATH}/dnskey_dsa.c
            ${LIBRARY_SOURCE_PATH}/dnskey_ecdsa.c
            ${LIBRARY_SOURCE_PATH}/dnskey_rsa.c
            ${LIBRARY_SOURCE_PATH}/digest_sha1.c
            ${LIBRARY_SOURCE_PATH}/digest_sha256.c
            ${LIBRARY_SOURCE_PATH}/digest_sha384.c
            ${LIBRARY_SOURCE_PATH}/digest_sha512.c
            ${LIBRARY_SOURCE_PATH}/hmac_openssl.c)
    else()
        message("using libssl >= 3.0 API")
        set(LIBRARY_SOURCES ${LIBRARY_SOURCES}
            ${LIBRARY_SOURCE_PATH}/dnskey_evp.c
            #${LIBRARY_SOURCE_PATH}/dnskey_evp_dsa.c
            ${LIBRARY_SOURCE_PATH}/dnskey_evp_ecdsa.c
            ${LIBRARY_SOURCE_PATH}/dnskey_evp_rsa.c
            ${LIBRARY_SOURCE_PATH}/digest_evp.c
            ${LIBRARY_SOURCE_PATH}/hmac_evp.c)
    endif()
    set(LIBRARY_SOURCES ${LIBRARY_SOURCES} ${LIBRARY_SOURCE_PATH}/digest_md5_internal.c)
else()
    message("using libssl >= 3.0 API")
    set(LIBRARY_SOURCES ${LIBRARY_SOURCES}
        ${LIBRARY_SOURCE_PATH}/dnskey_evp.c
        #${LIBRARY_SOURCE_PATH}/dnskey_evp_dsa.c
        ${LIBRARY_SOURCE_PATH}/dnskey_evp_ecdsa.c
        ${LIBRARY_SOURCE_PATH}/dnskey_evp_rsa.c
        ${LIBRARY_SOURCE_PATH}/digest_evp.c
        ${LIBRARY_SOURCE_PATH}/hmac_evp.c)
endif()

set(LIBRARY_HEADERS
    ${LIBRARY_HEADER_PATH}/acl.h
    ${LIBRARY_HEADER_PATH}/acl_config.h
    ${LIBRARY_HEADER_PATH}/alarm.h
    #${LIBRARY_HEADER_PATH}/allocator.h
    ${LIBRARY_HEADER_PATH}/async.h
    ${LIBRARY_HEADER_PATH}/avl.c.inc
    ${LIBRARY_HEADER_PATH}/avl.h.inc
    ${LIBRARY_HEADER_PATH}/base16.h
    ${LIBRARY_HEADER_PATH}/base32.h
    ${LIBRARY_HEADER_PATH}/base32hex.h
    ${LIBRARY_HEADER_PATH}/base64.h
    ${LIBRARY_HEADER_PATH}/basic_priority_queue.h
    ${LIBRARY_HEADER_PATH}/buffer_input_stream.h
    ${LIBRARY_HEADER_PATH}/buffer_output_stream.h
    ${LIBRARY_HEADER_PATH}/buffered_file.h
    ${LIBRARY_HEADER_PATH}/bytearray_input_stream.h
    ${LIBRARY_HEADER_PATH}/bytearray_output_stream.h
    ${LIBRARY_HEADER_PATH}/bytezarray_output_stream.h
    ${LIBRARY_HEADER_PATH}/cache.h
    ${LIBRARY_HEADER_PATH}/checked_output_stream.h
    ${LIBRARY_HEADER_PATH}/circular_file.h
    ${LIBRARY_HEADER_PATH}/clone_input_output_stream.h
    ${LIBRARY_HEADER_PATH}/cmdline.h
    ${LIBRARY_HEADER_PATH}/concat_input_stream.h
    ${LIBRARY_HEADER_PATH}/config_cmdline.h
    ${LIBRARY_HEADER_PATH}/config_file_reader.h
    ${LIBRARY_HEADER_PATH}/config_settings.h
    ${LIBRARY_HEADER_PATH}/counter_output_stream.h
    ${LIBRARY_HEADER_PATH}/crypto.h
    ${LIBRARY_HEADER_PATH}/crc32.h
    ${LIBRARY_HEADER_PATH}/ctrl_rfc.h
    ${LIBRARY_HEADER_PATH}/debug.h
    ${LIBRARY_HEADER_PATH}/debug_config.h
    ${LIBRARY_HEADER_PATH}/digest.h
    ${LIBRARY_HEADER_PATH}/dns_udp.h
    ${LIBRARY_HEADER_PATH}/dns_message.h
    ${LIBRARY_HEADER_PATH}/dns_message_verify_rrsig.h
    ${LIBRARY_HEADER_PATH}/dns_message_writer.h
    ${LIBRARY_HEADER_PATH}/dns_resource_record.h
    ${LIBRARY_HEADER_PATH}/dnscore.h
    ${LIBRARY_HEADER_PATH}/dnscore_extension.h
    ${LIBRARY_HEADER_PATH}/dnscore_release_date.h
    ${LIBRARY_HEADER_PATH}/dnsformat.h
    ${LIBRARY_HEADER_PATH}/dnskey.h
    ${LIBRARY_HEADER_PATH}/dnskey_keyring.h
    ${LIBRARY_HEADER_PATH}/dnskey_dsa.h
    ${LIBRARY_HEADER_PATH}/dnskey_ecdsa.h
    ${LIBRARY_HEADER_PATH}/dnskey_eddsa.h
    ${LIBRARY_HEADER_PATH}/dnskey_rsa.h
    ${LIBRARY_HEADER_PATH}/dnskey_signature.h
    ${LIBRARY_HEADER_PATH}/dnsname.h
    ${LIBRARY_HEADER_PATH}/dnsname_set.h
    ${LIBRARY_HEADER_PATH}/dnssec_errors.h
    ${LIBRARY_HEADER_PATH}/empty_input_stream.h
    ${LIBRARY_HEADER_PATH}/error_state.h
    ${LIBRARY_HEADER_PATH}/fdtools.h
    ${LIBRARY_HEADER_PATH}/file.h
    ${LIBRARY_HEADER_PATH}/file_input_stream.h
    ${LIBRARY_HEADER_PATH}/file_mtime_set.h
    ${LIBRARY_HEADER_PATH}/file_output_stream.h
    ${LIBRARY_HEADER_PATH}/file_pool.h
    ${LIBRARY_HEADER_PATH}/filesystem_file.h
    ${LIBRARY_HEADER_PATH}/fingerprint.h
    ${LIBRARY_HEADER_PATH}/format.h
    ${LIBRARY_HEADER_PATH}/hash.h
    ${LIBRARY_HEADER_PATH}/hmac.h
    ${LIBRARY_HEADER_PATH}/host_address.h
    #${LIBRARY_HEADER_PATH}/hsdllist.h
    ${LIBRARY_HEADER_PATH}/http_chunk_output_stream.h
    ${LIBRARY_HEADER_PATH}/identity.h
    ${LIBRARY_HEADER_PATH}/initialise_state.h
    ${LIBRARY_HEADER_PATH}/input_stream.h
    ${LIBRARY_HEADER_PATH}/io_stream.h
    ${LIBRARY_HEADER_PATH}/json.h
    ${LIBRARY_HEADER_PATH}/json_type.h
    ${LIBRARY_HEADER_PATH}/limited_input_stream.h
    ${LIBRARY_HEADER_PATH}/limiter.h
    ${LIBRARY_HEADER_PATH}/list_dl.h
    ${LIBRARY_HEADER_PATH}/list_dl_nodata.h
    ${LIBRARY_HEADER_PATH}/list_sl.h
    ${LIBRARY_HEADER_PATH}/list_sl_debug.h
    ${LIBRARY_HEADER_PATH}/logger.h
    ${LIBRARY_HEADER_PATH}/logger_channel_file.h
    ${LIBRARY_HEADER_PATH}/logger_channel_stream.h
    ${LIBRARY_HEADER_PATH}/logger_channel_syslog.h
    ${LIBRARY_HEADER_PATH}/logger_handle.h
    ${LIBRARY_HEADER_PATH}/logger_output_stream.h
    ${LIBRARY_HEADER_PATH}/mapped_file.h
    ${LIBRARY_HEADER_PATH}/dns_message_update.h
    ${LIBRARY_HEADER_PATH}/dns_message_opt.h
    ${LIBRARY_HEADER_PATH}/mt_output_stream.h
    ${LIBRARY_HEADER_PATH}/mutex.h
    ${LIBRARY_HEADER_PATH}/mutex_contention_monitor.h
    ${LIBRARY_HEADER_PATH}/mutex_debug.h
    ${LIBRARY_HEADER_PATH}/mutex_defines.h
    ${LIBRARY_HEADER_PATH}/mutex_futex.h
    ${LIBRARY_HEADER_PATH}/mutex_group.h
    ${LIBRARY_HEADER_PATH}/mutex_logger.h
    ${LIBRARY_HEADER_PATH}/mutex_mutex.h
    ${LIBRARY_HEADER_PATH}/mutex_semaphore.h
    ${LIBRARY_HEADER_PATH}/mutex_shared_group.h
    ${LIBRARY_HEADER_PATH}/mutex_spinlock.h
    ${LIBRARY_HEADER_PATH}/network.h
    ${LIBRARY_HEADER_PATH}/nsec3_hash.h
    ${LIBRARY_HEADER_PATH}/openssl.h
    ${LIBRARY_HEADER_PATH}/output_stream.h
    ${LIBRARY_HEADER_PATH}/pace.h
    ${LIBRARY_HEADER_PATH}/dns_packet_reader.h
    ${LIBRARY_HEADER_PATH}/dns_packet_writer.h
    ${LIBRARY_HEADER_PATH}/parser.h
    ${LIBRARY_HEADER_PATH}/parsing.h
    ${LIBRARY_HEADER_PATH}/pcg_basic.h
    ${LIBRARY_HEADER_PATH}/permut.h
    ${LIBRARY_HEADER_PATH}/pid.h
    ${LIBRARY_HEADER_PATH}/pipe_stream.h
    ${LIBRARY_HEADER_PATH}/pool.h
    ${LIBRARY_HEADER_PATH}/print_stream.h
    ${LIBRARY_HEADER_PATH}/process.h
    ${LIBRARY_HEADER_PATH}/ptr_set.h
    ${LIBRARY_HEADER_PATH}/ptr_set_debug.h
    ${LIBRARY_HEADER_PATH}/ptr_treemap.h
    ${LIBRARY_HEADER_PATH}/ptr_treemap_debug.h
    ${LIBRARY_HEADER_PATH}/ptr_treeset.h
    ${LIBRARY_HEADER_PATH}/ptr_treeset_debug.h
    ${LIBRARY_HEADER_PATH}/ptr_vector.h
    ${LIBRARY_HEADER_PATH}/pushback_input_stream.h
    ${LIBRARY_HEADER_PATH}/queue_sl.h
    ${LIBRARY_HEADER_PATH}/random.h
    ${LIBRARY_HEADER_PATH}/rest_client.h
    ${LIBRARY_HEADER_PATH}/rest_server.h
    ${LIBRARY_HEADER_PATH}/rewind_input_stream.h
    ${LIBRARY_HEADER_PATH}/rfc.h
    ${LIBRARY_HEADER_PATH}/rndc.h
    ${LIBRARY_HEADER_PATH}/serial.h
    ${LIBRARY_HEADER_PATH}/server_setup.h
    ${LIBRARY_HEADER_PATH}/service.h
    ${LIBRARY_HEADER_PATH}/shared_heap.h
    ${LIBRARY_HEADER_PATH}/shared_circular_buffer.h
    ${LIBRARY_HEADER_PATH}/shared_heap_bytearray_output_stream.h
    ${LIBRARY_HEADER_PATH}/signals.h
    ${LIBRARY_HEADER_PATH}/simple_http_server.h
    ${LIBRARY_HEADER_PATH}/smp_int.h
    ${LIBRARY_HEADER_PATH}/socket_server.h
    ${LIBRARY_HEADER_PATH}/ssl_input_output_stream.h
    ${LIBRARY_HEADER_PATH}/string_set.h
    ${LIBRARY_HEADER_PATH}/sys_error.h
    ${LIBRARY_HEADER_PATH}/sys_get_cpu_count.h
    ${LIBRARY_HEADER_PATH}/sys_types.h
    ${LIBRARY_HEADER_PATH}/tcp_io_stream.h
#    ${LIBRARY_HEADER_PATH}/tcp_manager.h
    ${LIBRARY_HEADER_PATH}/tcp_manager2.h
#    ${LIBRARY_HEADER_PATH}/tcp_manager_epoll.h
#    ${LIBRARY_HEADER_PATH}/tcp_manager_host_context.h
#    ${LIBRARY_HEADER_PATH}/tcp_manager_socket_context.h
#    ${LIBRARY_HEADER_PATH}/tcp_manager_types.h
#    ${LIBRARY_HEADER_PATH}/tcp_server.h
    ${LIBRARY_HEADER_PATH}/thread_pool.h
    ${LIBRARY_HEADER_PATH}/thread.h
    ${LIBRARY_HEADER_PATH}/threaded_qsl_cw.h
    ${LIBRARY_HEADER_PATH}/threaded_dll_cw.h
    ${LIBRARY_HEADER_PATH}/threaded_nbrb.h
    ${LIBRARY_HEADER_PATH}/threaded_queue.h
    ${LIBRARY_HEADER_PATH}/threaded_queue_slg.h
    ${LIBRARY_HEADER_PATH}/threaded_ringbuffer_cw.h
#    ${LIBRARY_HEADER_PATH}/threaded_dynamic_fifo.h
#    ${LIBRARY_HEADER_PATH}/threaded_dynamic_stack.h
    ${LIBRARY_HEADER_PATH}/timeformat.h
    ${LIBRARY_HEADER_PATH}/timems.h
    ${LIBRARY_HEADER_PATH}/tools.h
    ${LIBRARY_HEADER_PATH}/typebitmap.h
    ${LIBRARY_HEADER_PATH}/u32_set.h
    ${LIBRARY_HEADER_PATH}/u32_treeset.h
    ${LIBRARY_HEADER_PATH}/u64_treeset.h
    ${LIBRARY_HEADER_PATH}/u64_set_debug.h
    ${LIBRARY_HEADER_PATH}/u32_treemap.h
    ${LIBRARY_HEADER_PATH}/u64_treemap.h
    ${LIBRARY_HEADER_PATH}/u64_treeset.h
    ${LIBRARY_HEADER_PATH}/u64_treeset_debug.h
    ${LIBRARY_HEADER_PATH}/uri.h
    ${LIBRARY_HEADER_PATH}/utf8.h
    ${LIBRARY_HEADER_PATH}/xfr_input_stream.h
    ${LIBRARY_HEADER_PATH}/zalloc.h
    ${LIBRARY_HEADER_PATH}/zone_reader.h
    ${LIBRARY_HEADER_PATH}/zone_reader_axfr.h
    ${LIBRARY_HEADER_PATH}/zone_reader_text.h
    ${LIBRARY_HEADER_PATH}/zonefile_reader.h
)

if(UNIX)
set(LIBRARY_SOURCES ${LIBRARY_SOURCES}
    ${LIBRARY_SOURCE_PATH}/chroot.c
    ${LIBRARY_SOURCE_PATH}/logger_channel_pipe.c
    ${LIBRARY_SOURCE_PATH}/popen_output_stream.c
)
set(LIBRARY_HEADERS ${LIBRARY_HEADERS}
    ${LIBRARY_HEADER_PATH}/chroot.h
    ${LIBRARY_HEADER_PATH}/logger_channel_pipe.h
    ${LIBRARY_HEADER_PATH}/popen_output_stream.h
)
endif()

if(WIN32)
set(LIBRARY_HEADERS ${LIBRARY_HEADERS}
    ${LIBRARY_HEADER_PATH}/system_service.h
)

set(LIBRARY_SOURCES ${LIBRARY_SOURCES}
    ${LIBRARY_SOURCE_PATH}/system_service.c
    ${CMAKE_SOURCE_DIR}/platforms/win32/src/errno.c
    ${CMAKE_SOURCE_DIR}/platforms/win32/src/pthread.c
    ${CMAKE_SOURCE_DIR}/platforms/win32/src/dirent.c
    ${CMAKE_SOURCE_DIR}/platforms/win32/src/sys/mman.c
    ${CMAKE_SOURCE_DIR}/platforms/win32/src/sys/socket.c
    ${CMAKE_SOURCE_DIR}/platforms/win32/src/fork.c
)
endif()

message(STATUS "add osx_clock_gettime.c")
if(CMAKE_HOST_SYSTEM_NAME MATCHES "Darwin")
    set(LIBRARY_SOURCES
        ${LIBRARY_SOURCES}
        ${LIBRARY_SOURCE_PATH}/osx_clock_gettime.c
    )
    message(STATUS "add osx_clock_gettime.h")
    set(LIBRARY_HEADERS
        ${LIBRARY_HEADERS}
        ${LIBRARY_HEADER_PATH}/osx_clock_gettime.h
    )
endif()

kvstatus("HAS_TSIG_SUPPORT" "${HAS_TSIG_SUPPORT}")
if(HAS_TSIG_SUPPORT)
    set(LIBRARY_SOURCES
        ${LIBRARY_SOURCES}
        ${LIBRARY_SOURCE_PATH}/tsig.c
        ${LIBRARY_SOURCE_PATH}/tsig_algorithms.c
    )
    set(LIBRARY_HEADERS
        ${LIBRARY_HEADERS}
        ${LIBRARY_HEADER_PATH}/tsig.h
    )
endif()

kvstatus("HAS_NSID_SUPPORT" "${HAS_NSID_SUPPORT}")
if(HAS_NSID_SUPPORT)
    set(LIBRARY_SOURCES
        ${LIBRARY_SOURCES}
        ${LIBRARY_SOURCE_PATH}/nsid.c
    )
    set(LIBRARY_HEADERS
        ${LIBRARY_HEADERS}
        ${LIBRARY_HEADER_PATH}/nsid.h
    )
endif()

kvstatus("HAS_RDTSC" "${HAS_RDTSC}")
if(HAS_RDTSC)
    set(LIBRARY_SOURCES
        ${LIBRARY_SOURCES}
        ${LIBRARY_SOURCE_PATH}/rdtsc.c
    )
    set(LIBRARY_HEADERS
        ${LIBRARY_HEADERS}
        ${LIBRARY_HEADER_PATH}/rdtsc.h
    )
endif()

if(${HAS_OQS_SUPPORT})
    set(LIBRARY_SOURCES ${LIBRARY_SOURCES}
            ${LIBRARY_SOURCE_PATH}/dnskey_postquantumsafe.c)
    set(LIBRARY_HEADERS ${LIBRARY_HEADERS}
            ${LIBRARY_HEADER_PATH}/dnskey_postquantumsafe.h)
endif()

kvstatus("HAS_EXPERIMENTAL" "${HAS_EXPERIMENTAL}")
if(HAS_EXPERIMENTAL)
    set(LIBRARY_SOURCES
        ${LIBRARY_SOURCES}
        ${LIBRARY_SOURCE_PATH}/charon.c
        ${LIBRARY_SOURCE_PATH}/message_print_format_json.c
        ${LIBRARY_SOURCE_PATH}/message_print_format_multiline.c
        ${LIBRARY_SOURCE_PATH}/message_print_format_parse.c
        ${LIBRARY_SOURCE_PATH}/message_print_format_short.c
        ${LIBRARY_SOURCE_PATH}/message_print_format_wire.c
        ${LIBRARY_SOURCE_PATH}/message_print_format_wire_ext.c
        ${LIBRARY_SOURCE_PATH}/message_print_format_xml.c
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
#  Dependencies
#
################################################################################

set(DNSCORE_LIBRARIES_DEPS "")

if(WIN32)
set(DNSCORE_LIBRARIES_DEPS ${DNSCORE_LIBRARIES_DEPS} ws2_32.lib)
set(DNSCORE_LIBRARIES_DEPS ${DNSCORE_LIBRARIES_DEPS} Advapi32.lib)
endif()

if(UNIX)
# find pthread otherwise quit
find_library(PTHREAD_LIB
    NAMES
        pthread
    PATHS
        /usr/local/ /usr/
    PATH_SUFFIXES
        lib
)

if(NOT PTHREAD_LIB EQUAL "PTHREAD_LIB-NOTFOUND")
    kvstatus("pthread" "${PTHREAD_LIB}")
    set(DNSCORE_LIBRARIES_DEPS ${DNSCORE_LIBRARIES_DEPS} "${PTHREAD_LIB}")
else()
    kvfatal("pthread" "not found")
endif()

if(BFD_DEBUG)
    # find bfd otherwise quit
    find_library(BFD_LIB
            NAMES
            bfd
            PATHS
            /usr/local/ /usr/
            PATH_SUFFIXES
            lib
            )

    if(NOT BFD_LIB EQUAL "BFD_LIB-NOTFOUND")
        kvstatus("bfd" "${BFD_LIB}")
        set(DNSCORE_LIBRARIES_DEPS ${DNSCORE_LIBRARIES_DEPS} ${BFD_LIB})
    else()
        kvfatal("bfd" "not found")
    endif()
endif()

endif() # UNIX

if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    kvstatus("FreeBSD" "execinfo")
    set(DNSCORE_LIBRARIES_DEPS ${DNSCORE_LIBRARIES_DEPS} execinfo)
endif()

kvstatus("DNSCORE_LIBRARIES_DEPS" "${DNSCORE_LIBRARIES_DEPS}")

################################################################################
#
# Targets
#
################################################################################

#set(HASH_TABLE_MAP_GENERATOR_SOURCES src/hash_table_map_generator.c src/hash_table_values.c)
#add_executable(hash_table_map_generator ${HASH_TABLE_MAP_GENERATOR_SOURCES})

add_library(dnscore-objects OBJECT ${LIBRARY_SOURCES} ${LIBRARY_HEADERS})

if(BUILD_SHARED_LIBS)
    kvstatus("${PACKAGE} build" "shared")
    add_library(dnscore SHARED $<TARGET_OBJECTS:dnscore-objects> ${LIBRARY_HEADERS})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_COMMON_FLAGS} ${C_LIBRARY_FLAGS}")
    target_compile_options(dnscore PRIVATE ${CMAKE_C_FLAGS} ${C_COMMON_FLAGS} ${C_LIBRARY_FLAGS})
    kvmessage("CMAKE_C_FLAGS" "${CMAKE_C_FLAGS}")
    set_target_properties(dnscore PROPERTIES SOVERSION ${LIBRARY_SO_VERSION})
    set_target_properties(dnscore PROPERTIES VERSION ${LIBRARY_SO_MAJOR})

    message(STATUS "will link with '${OPENSSL_LIB}'")
    target_link_libraries(dnscore "${OPENSSL_LIB}")
    message(STATUS "will use headers from '${OPENSSL_HEADERS}'")
    target_include_directories(dnscore PUBLIC ${OPENSSL_HEADERS})
    message(STATUS "will link with '${CRYPTO_LIB}'")
    target_link_libraries(dnscore "${CRYPTO_LIB}")

    if(${HAS_OQS_SUPPORT})
        message(STATUS "will link with '${OPENQUANTUMSAFE_LIB}'")
        message(STATUS "will use headers from '${OPENQUANTUMSAFE_HEADERS}'")
        target_link_libraries(dnscore "${OPENQUANTUMSAFE_LIB}")
        target_include_directories(dnscore PUBLIC "${OPENQUANTUMSAFE_HEADERS}")
    endif()

    if(WIN32)
        target_link_libraries(dnscore "Iphlpapi")
    endif()

    link_directories("${CMAKE_INSTALL_PREFIX}/lib")
    target_link_libraries(dnscore ${DNSCORE_LIBRARIES_DEPS})
endif()

if(BUILD_STATIC_LIBS)
    kvstatus("${PACKAGE} build" "static")
    add_library(dnscore-static STATIC $<TARGET_OBJECTS:dnscore-objects> ${LIBRARY_HEADERS})
    set_target_properties(dnscore-static PROPERTIES OUTPUT_NAME dnscore)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_COMMON_FLAGS}")
    kvmessage("CMAKE_C_FLAGS" "${CMAKE_C_FLAGS}")

    message(STATUS "will link with '${OPENSSL_LIB}'")
    target_link_libraries(dnscore-static "${OPENSSL_LIB}")
    message(STATUS "will link with '${CRYPTO_LIB}'")
    target_link_libraries(dnscore-static "${CRYPTO_LIB}")

    if(${HAS_OQS_SUPPORT})
        message(STATUS "will link with '${OPENQUANTUMSAFE_LIB}'")
        message(STATUS "will use headers from '${OPENQUANTUMSAFE_HEADERS}'")
        target_link_libraries(dnscore-static "${OPENQUANTUMSAFE_LIB}")
        target_include_directories(dnscore-static PUBLIC "${OPENQUANTUMSAFE_HEADERS}")
    endif()

    if(WIN32)
        target_link_libraries(dnscore-static "Iphlpapi")
    endif()

    link_directories("${CMAKE_INSTALL_PREFIX}/lib")
    target_link_libraries(dnscore-static ${DNSCORE_LIBRARIES_DEPS})
endif()

kvstatus("built" "${PACKAGE}")

################################################################################
#
# Installation
#
################################################################################

if(BUILD_SHARED_LIBS)
    kvstatus("install" "${PACKAGE} shared libray")
    install(TARGETS dnscore LIBRARY DESTINATION "${CMAKE_INSTALL_FULL_LIBDIR}")
    set(DNSCORELIB_NAME "dnscore" CACHE STRING "dnscore library name" FORCE)
endif()

if(BUILD_STATIC_LIBS)
    kvstatus("install" "${PACKAGE} static library")
    install(TARGETS dnscore-static LIBRARY DESTINATION "${CMAKE_INSTALL_FULL_LIBDIR}")
    set(DNSCORELIB_NAME "dnscore-static" CACHE STRING "dnscore library name" FORCE)
endif()

install(FILES ${LIBRARY_HEADERS} DESTINATION "${CMAKE_INSTALL_FULL_INCLUDEDIR}/dnscore")

################################################################################
#
# Tests
#
################################################################################

#
# Note: do NOT sort these lines. There is a hierarchy here.
#

add_subdirectory(tests/dnscore-test)
add_subdirectory(tests/fdtools-test)
add_subdirectory(tests/skeleton-test)
add_subdirectory(tests/acl-test)
add_subdirectory(tests/alarm-test) # slow
add_subdirectory(tests/basexx-test)
add_subdirectory(tests/buffer_input_stream-test)
add_subdirectory(tests/bytearray_input_stream-test)
add_subdirectory(tests/concat_input_stream-test)
add_subdirectory(tests/empty_input_stream-test)
add_subdirectory(tests/file_input_stream-test)
add_subdirectory(tests/input_stream-test)
add_subdirectory(tests/limited_input_stream-test)
add_subdirectory(tests/rewind_input_stream-test)
add_subdirectory(tests/pushback_input_stream-test) # slow
add_subdirectory(tests/xfr_input_stream-test) # slow
add_subdirectory(tests/bytearray_output_stream-test)
add_subdirectory(tests/bytezarray_output_stream-test)
add_subdirectory(tests/buffer_output_stream-test)
add_subdirectory(tests/checked_output_stream-test)
add_subdirectory(tests/counter_output_stream-test)
add_subdirectory(tests/file_output_stream-test)
add_subdirectory(tests/http_chunk_output_stream-test)
add_subdirectory(tests/output_stream-test)
add_subdirectory(tests/popen_output_stream-test)
add_subdirectory(tests/async-test)
add_subdirectory(tests/basic_priority_queue-test)
add_subdirectory(tests/filesystem_file-test)
add_subdirectory(tests/mapped_file-test)
add_subdirectory(tests/buffered_file-test)
add_subdirectory(tests/chroot-test)
add_subdirectory(tests/config-test)
add_subdirectory(tests/config_key-test)
add_subdirectory(tests/config_logger-test)
add_subdirectory(tests/crypto-test)
add_subdirectory(tests/digest-test)
add_subdirectory(tests/dns_message-test)
add_subdirectory(tests/dns_resource_record-test)
add_subdirectory(tests/dnscore_extension-test)
add_subdirectory(tests/dnsformat-test)
add_subdirectory(tests/dnskey-test)
add_subdirectory(tests/dnsname-test)
add_subdirectory(tests/error_state-test) # slow
add_subdirectory(tests/file_pool-test)
add_subdirectory(tests/format-test)
add_subdirectory(tests/hash-test)
add_subdirectory(tests/hmac_evp-test)
add_subdirectory(tests/host_address-test)
add_subdirectory(tests/json-test)
add_subdirectory(tests/list_dl-test)
add_subdirectory(tests/list_sl-test)
add_subdirectory(tests/list_dl_nodata-test)
add_subdirectory(tests/list_sl_debug-test)
add_subdirectory(tests/logger-test)
add_subdirectory(tests/message_dnsupdate-test)
add_subdirectory(tests/mt_output_stream-test)
add_subdirectory(tests/mutex-test) # slow
add_subdirectory(tests/network-test)
add_subdirectory(tests/nsec3_hash-test)
add_subdirectory(tests/pace-test) # slow
add_subdirectory(tests/dns_packet_reader-test)
add_subdirectory(tests/dns_packet_writer-test)
add_subdirectory(tests/parsing-test)
add_subdirectory(tests/parser-test)
add_subdirectory(tests/pid-test)
add_subdirectory(tests/pipe_steam-test)
add_subdirectory(tests/pool-test)
add_subdirectory(tests/process-test)
add_subdirectory(tests/ptr_treeset-test)
add_subdirectory(tests/ptr_treeset_debug-test)
add_subdirectory(tests/ptr_treemap-test)
add_subdirectory(tests/ptr_treemap_debug-test)
add_subdirectory(tests/ptr_vector-test)
add_subdirectory(tests/random-test)
add_subdirectory(tests/rfc-test)
add_subdirectory(tests/serial-test)
add_subdirectory(tests/service-test)
add_subdirectory(tests/shared_heap-test)
add_subdirectory(tests/shared_circular_buffer-test)
add_subdirectory(tests/signal-test)
add_subdirectory(tests/sys_get_cpu_count-test)
add_subdirectory(tests/thread-test)
add_subdirectory(tests/u64_treemap-test)
add_subdirectory(tests/threaded_dll_cw-test)
add_subdirectory(tests/threaded_qsl_cw-test)
add_subdirectory(tests/threaded_slg-test)
add_subdirectory(tests/threaded_ringbuffer_cw-test)
add_subdirectory(tests/timeformat-test)
add_subdirectory(tests/timems-test)
add_subdirectory(tests/tools-test)
add_subdirectory(tests/tsig-test)
add_subdirectory(tests/typebitmap-test)
add_subdirectory(tests/utf8-test)
add_subdirectory(tests/zalloc-test)
add_subdirectory(tests/zone_reader_text-test)
add_subdirectory(tests/zone_reader_axfr-test)
add_subdirectory(tests/uri-test)
add_subdirectory(tests/rest_server-test)
add_subdirectory(tests/cache-test)
add_subdirectory(tests/crc32-test)
