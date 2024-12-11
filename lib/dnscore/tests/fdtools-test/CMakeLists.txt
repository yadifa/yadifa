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
                    "${CMAKE_SOURCE_DIR}/lib/dnscore/tests/modules"
                    "${CMAKE_SOURCE_DIR}/lib/glibchooks/include")

add_executable(${NAME} ${SOURCE_FILES})
target_coverage_test(${NAME})
target_link_libraries(${NAME} PUBLIC ${DNSCORELIB_NAME} glibchooksload glibchooksctrl glibchooks)

add_test(NAME "${NAME}-success_test"  COMMAND ${NAME} success_test)
add_test(NAME "${NAME}-readfully_test"  COMMAND ${NAME} readfully_test)
add_test(NAME "${NAME}-readfully_error_short_read_test"  COMMAND ${NAME} readfully_error_short_read_test)
add_test(NAME "${NAME}-readfully_error_zero_read_test"  COMMAND ${NAME} readfully_error_zero_read_test)
add_test(NAME "${NAME}-readfully_limited_test"  COMMAND ${NAME} readfully_limited_test)
add_test(NAME "${NAME}-readfully_limited_slow_test"  COMMAND ${NAME} readfully_limited_slow_test)
add_test(NAME "${NAME}-readfully_limited_error_short_read_test"  COMMAND ${NAME} readfully_limited_error_short_read_test)
add_test(NAME "${NAME}-readfully_limited_error_zero_read_test"  COMMAND ${NAME} readfully_limited_error_zero_read_test)
add_test(NAME "${NAME}-readfully_limited_ex_test"  COMMAND ${NAME} readfully_limited_ex_test)
add_test(NAME "${NAME}-readfully_limited_ex_slow_test"  COMMAND ${NAME} readfully_limited_ex_slow_test)
add_test(NAME "${NAME}-readfully_limited_ex_error_short_read_test"  COMMAND ${NAME} readfully_limited_ex_error_short_read_test)
add_test(NAME "${NAME}-readfully_limited_ex_error_zero_read_test"  COMMAND ${NAME} readfully_limited_ex_error_zero_read_test)
add_test(NAME "${NAME}-writefully_test"  COMMAND ${NAME} writefully_test)
add_test(NAME "${NAME}-writefully_limited_test"  COMMAND ${NAME} writefully_limited_test)
add_test(NAME "${NAME}-writefully_limited_slow_test"  COMMAND ${NAME} writefully_limited_slow_test)
add_test(NAME "${NAME}-sendfully_limited_test"  COMMAND ${NAME} sendfully_limited_test)
add_test(NAME "${NAME}-sendfully_limited_slow_test"  COMMAND ${NAME} sendfully_limited_slow_test)
add_test(NAME "${NAME}-recvfully_limited_ex_test"  COMMAND ${NAME} recvfully_limited_ex_test)
add_test(NAME "${NAME}-recvfully_limited_ex_slow_test"  COMMAND ${NAME} recvfully_limited_ex_slow_test)
add_test(NAME "${NAME}-readtextline_test"  COMMAND ${NAME} readtextline_test)
add_test(NAME "${NAME}-unlink_ex_test"  COMMAND ${NAME} unlink_ex_test)
add_test(NAME "${NAME}-file_get_absolute_path_test"  COMMAND ${NAME} file_get_absolute_path_test)
add_test(NAME "${NAME}-file_get_absolute_parent_directory_test"  COMMAND ${NAME} file_get_absolute_parent_directory_test)
add_test(NAME "${NAME}-open_ex_test"  COMMAND ${NAME} open_ex_test)
add_test(NAME "${NAME}-open_create_ex_test"  COMMAND ${NAME} open_create_ex_test)
add_test(NAME "${NAME}-open_create_ex_nolog_test"  COMMAND ${NAME} open_create_ex_nolog_test)
add_test(NAME "${NAME}-close_ex_test"  COMMAND ${NAME} close_ex_test)
add_test(NAME "${NAME}-socketclose_ex_test"  COMMAND ${NAME} socketclose_ex_test)
add_test(NAME "${NAME}-close_ex_nolog_test"  COMMAND ${NAME} close_ex_nolog_test)
add_test(NAME "${NAME}-fsync_ex_test"  COMMAND ${NAME} fsync_ex_test)
add_test(NAME "${NAME}-fdatasync_ex_test"  COMMAND ${NAME} fdatasync_ex_test)
add_test(NAME "${NAME}-dup_ex_test"  COMMAND ${NAME} dup_ex_test)
add_test(NAME "${NAME}-dup2_ex_test"  COMMAND ${NAME} dup2_ex_test)
add_test(NAME "${NAME}-truncate_ex_test"  COMMAND ${NAME} truncate_ex_test)
add_test(NAME "${NAME}-ftruncate_ex_test"  COMMAND ${NAME} ftruncate_ex_test)
add_test(NAME "${NAME}-fd_getsockettype_test"  COMMAND ${NAME} fd_getsockettype_test)
add_test(NAME "${NAME}-filesize_test"  COMMAND ${NAME} filesize_test)
add_test(NAME "${NAME}-file_exists_test"  COMMAND ${NAME} file_exists_test)
add_test(NAME "${NAME}-file_is_link_test"  COMMAND ${NAME} file_is_link_test)
add_test(NAME "${NAME}-file_is_directory_test"  COMMAND ${NAME} file_is_directory_test)
add_test(NAME "${NAME}-file_mtime_test"  COMMAND ${NAME} file_mtime_test)
add_test(NAME "${NAME}-fd_mtime_test"  COMMAND ${NAME} fd_mtime_test)
add_test(NAME "${NAME}-mkdir_ex_test"  COMMAND ${NAME} mkdir_ex_test)
add_test(NAME "${NAME}-fd_setcloseonexec_test"  COMMAND ${NAME} fd_setcloseonexec_test)
add_test(NAME "${NAME}-fd_setnonblocking_test"  COMMAND ${NAME} fd_setnonblocking_test)
add_test(NAME "${NAME}-fd_setblocking_test"  COMMAND ${NAME} fd_setblocking_test)
add_test(NAME "${NAME}-dirent_get_file_type_test"  COMMAND ${NAME} dirent_get_file_type_test)
add_test(NAME "${NAME}-readdir_forall_test"  COMMAND ${NAME} readdir_forall_test)
add_test(NAME "${NAME}-access_check_test"  COMMAND ${NAME} access_check_test)
add_test(NAME "${NAME}-mkstemp_test"  COMMAND ${NAME} mkstemp_test)
add_test(NAME "${NAME}-rmdir_ex_test"  COMMAND ${NAME} rmdir_ex_test)
