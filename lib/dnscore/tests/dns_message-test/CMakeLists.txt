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

add_test(NAME "${NAME}-header_test"  COMMAND ${NAME} header_test)
add_test(NAME "${NAME}-buffer_test"  COMMAND ${NAME} buffer_test)
add_test(NAME "${NAME}-features_test"  COMMAND ${NAME} features_test)
add_test(NAME "${NAME}-edns0_test"  COMMAND ${NAME} edns0_test)
add_test(NAME "${NAME}-tsig_test"  COMMAND ${NAME} tsig_test)
add_test(NAME "${NAME}-opt_test"  COMMAND ${NAME} opt_test)
add_test(NAME "${NAME}-network_dns_message_send_recv_tcp_test"  COMMAND ${NAME} network_dns_message_send_recv_tcp_test)
add_test(NAME "${NAME}-network_dns_message_query_tcp_test"  COMMAND ${NAME} network_dns_message_query_tcp_test)
add_test(NAME "${NAME}-network_dns_message_query_tcp_timeout_test"  COMMAND ${NAME} network_dns_message_query_tcp_timeout_test)
add_test(NAME "${NAME}-network_dns_message_query_tcp_ex_test"  COMMAND ${NAME} network_dns_message_query_tcp_ex_test)
add_test(NAME "${NAME}-network_dns_message_query_tcp_ex_bindto_test"  COMMAND ${NAME} network_dns_message_query_tcp_ex_bindto_test)
add_test(NAME "${NAME}-network_dns_message_query_tcp_timeout_ex_test"  COMMAND ${NAME} network_dns_message_query_tcp_timeout_ex_test)
add_test(NAME "${NAME}-network_dns_message_write_read_tcp_test"  COMMAND ${NAME} network_dns_message_write_read_tcp_test)
add_test(NAME "${NAME}-network_dns_message_send_recv_tcp_min_throughput_test"  COMMAND ${NAME} network_dns_message_send_recv_tcp_min_throughput_test)
add_test(NAME "${NAME}-network_dns_message_send_recv_tcp_default_min_throughput_test"  COMMAND ${NAME} network_dns_message_send_recv_tcp_default_min_throughput_test)
add_test(NAME "${NAME}-network_dns_message_make_error_and_reply_tcp_test"  COMMAND ${NAME} network_dns_message_make_error_and_reply_tcp_test)
add_test(NAME "${NAME}-network_dns_message_make_error_and_reply_tcp_with_default_minimum_throughput_test"  COMMAND ${NAME} network_dns_message_make_error_and_reply_tcp_with_default_minimum_throughput_test)
add_test(NAME "${NAME}-network_dns_message_send_recv_udp_test"  COMMAND ${NAME} network_dns_message_send_recv_udp_test)
add_test(NAME "${NAME}-network_dns_message_send_debug_recv_udp_test"  COMMAND ${NAME} network_dns_message_send_debug_recv_udp_test)
add_test(NAME "${NAME}-network_dns_message_query_udp_test"  COMMAND ${NAME} network_dns_message_query_udp_test)
add_test(NAME "${NAME}-network_dns_message_query_udp_with_timeout_and_retries_test"  COMMAND ${NAME} network_dns_message_query_udp_with_timeout_and_retries_test)
add_test(NAME "${NAME}-network_dns_message_query_test"  COMMAND ${NAME} network_dns_message_query_test)
add_test(NAME "${NAME}-network_dns_message_query_but_truncated_test"  COMMAND ${NAME} network_dns_message_query_but_truncated_test)
add_test(NAME "${NAME}-network_dns_message_query_serial_test"  COMMAND ${NAME} network_dns_message_query_serial_test)
add_test(NAME "${NAME}-network_dns_message_ixfr_query_get_serial_test"  COMMAND ${NAME} network_dns_message_ixfr_query_get_serial_test)
add_test(NAME "${NAME}-network_dns_message_dup_test"  COMMAND ${NAME} network_dns_message_dup_test)
add_test(NAME "${NAME}-dns_message_with_buffer"  COMMAND ${NAME} dns_message_with_buffer)
add_test(NAME "${NAME}-dns_message_map_test"  COMMAND ${NAME} dns_message_map_test)
add_test(NAME "${NAME}-dns_message_process_over_query_test"  COMMAND ${NAME} dns_message_process_over_query_test)
add_test(NAME "${NAME}-dns_message_process_over_notify_test"  COMMAND ${NAME} dns_message_process_over_notify_test)
add_test(NAME "${NAME}-dns_message_process_over_update_test"  COMMAND ${NAME} dns_message_process_over_update_test)
add_test(NAME "${NAME}-dns_message_process_over_ctrl_test"  COMMAND ${NAME} dns_message_process_over_ctrl_test)
add_test(NAME "${NAME}-dns_message_process_over_iquery_test"  COMMAND ${NAME} dns_message_process_over_iquery_test)
add_test(NAME "${NAME}-dns_message_process_lenient_over_query_test"  COMMAND ${NAME} dns_message_process_lenient_over_query_test)
add_test(NAME "${NAME}-dns_message_process_lenient_over_notify_test"  COMMAND ${NAME} dns_message_process_lenient_over_notify_test)
add_test(NAME "${NAME}-dns_message_process_lenient_over_update_test"  COMMAND ${NAME} dns_message_process_lenient_over_update_test)
add_test(NAME "${NAME}-dns_message_process_lenient_over_ctrl_test"  COMMAND ${NAME} dns_message_process_lenient_over_ctrl_test)
add_test(NAME "${NAME}-dns_message_process_query_over_query_test"  COMMAND ${NAME} dns_message_process_query_over_query_test)
add_test(NAME "${NAME}-dns_message_transform_to_error_test"  COMMAND ${NAME} dns_message_transform_to_error_test)
add_test(NAME "${NAME}-dns_message_make_error_test"  COMMAND ${NAME} dns_message_make_error_test)
add_test(NAME "${NAME}-dns_message_make_signed_error_test"  COMMAND ${NAME} dns_message_make_signed_error_test)
add_test(NAME "${NAME}-dns_message_make_message_test"  COMMAND ${NAME} dns_message_make_message_test)
add_test(NAME "${NAME}-dns_message_make_ixfr_query_test"  COMMAND ${NAME} dns_message_make_ixfr_query_test)
add_test(NAME "${NAME}-dns_message_sign_query_by_name_test"  COMMAND ${NAME} dns_message_sign_query_by_name_test)
add_test(NAME "${NAME}-dns_message_sign_query_by_name_with_epoch_and_fudge_test"  COMMAND ${NAME} dns_message_sign_query_by_name_with_epoch_and_fudge_test)
add_test(NAME "${NAME}-dns_message_cookie_test"  COMMAND ${NAME} dns_message_cookie_test)
add_test(NAME "${NAME}-dns_message_set_sender_port_test"  COMMAND ${NAME} dns_message_set_sender_port_test)
add_test(NAME "${NAME}-dns_message_get_sender_address_ptr_test"  COMMAND ${NAME} dns_message_get_sender_address_ptr_test)
add_test(NAME "${NAME}-dns_message_get_sender_address_size_test"  COMMAND ${NAME} dns_message_get_sender_address_size_test)
add_test(NAME "${NAME}-dns_message_get_sender_sa_family_size_test"  COMMAND ${NAME} dns_message_get_sender_sa_family_size_test)
add_test(NAME "${NAME}-dns_message_verify_rrsig_test"  COMMAND ${NAME} dns_message_verify_rrsig_test)
add_test(NAME "${NAME}-dns_message_verify_rrsig_wrong_message_test"  COMMAND ${NAME} dns_message_verify_rrsig_wrong_message_test)
