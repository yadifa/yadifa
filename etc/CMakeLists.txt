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

################################################################################
#
#       INSTALLS
#
################################################################################

set(YADIFAD_CONF "yadifad.conf")
set(YADIFAD_CONF_EXAMPLE "${CMAKE_CURRENT_SOURCE_DIR}/${YADIFAD_CONF}.example")

set(YADIFA_CONF "yadifa.conf")
set(YADIFA_CONF_EXAMPLE "${CMAKE_CURRENT_SOURCE_DIR}/${YADIFA_CONF}.example")

set(KEYS_CONF "keys.conf")
set(KEYS_CONF_EXAMPLE "${CMAKE_CURRENT_SOURCE_DIR}/${KEYS_CONF}.example")

set(YADIFAD_INIT "yadifad.init")
set(YADIFAD_INIT_EXAMPLE "${CMAKE_CURRENT_SOURCE_DIR}/${YADIFAD_INIT}.example")
set(YADIFAD_SERVICE "yadifad.service")
set(YADIFAD_SERVICE_EXAMPLE "${CMAKE_CURRENT_SOURCE_DIR}/${YADIFAD_SERVICE}.example")

set(YADIFA "yadifa")
set(YADIFA_BASH_COMPLETION "${CMAKE_CURRENT_SOURCE_DIR}/${YADIFA}.bash_completion")
set(YADIFA_BASH_COMPLETION_GENERATED "${CMAKE_CURRENT_BINARY_DIR}/${YADIFA}.bash_completion")

set(YADIFAD "yadifad")
set(YADIFAD_BASH_COMPLETION "${CMAKE_CURRENT_SOURCE_DIR}/${YADIFAD}.bash_completion")
set(YADIFAD_BASH_COMPLETION_GENERATED "${CMAKE_CURRENT_BINARY_DIR}/${YADIFAD}.bash_completion")

set(YAKEYROLLD "yakeyrolld")
set(YAKEYROLLD_CONF "${YAKEYROLLD}.conf")
set(YAKEYROLLD_CONF_EXAMPLE "${CMAKE_CURRENT_SOURCE_DIR}/${YAKEYROLLD_CONF}.example")

set(BASH_COMPLETION_DIRECTOR "/etc/bash_completion.d/")

# note: LENGTH must be a multiple of 4
string(RANDOM LENGTH 24 ALPHABET "ABASH_COMPLETION_DIRECTORYDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" RNDBASE64)

# YADIFAD_CONF
message("Generating ${CMAKE_CURRENT_BINARY_DIR}/${YADIFAD_CONF} from ${YADIFAD_CONF_EXAMPLE}")
file(STRINGS "${YADIFAD_CONF_EXAMPLE}" YADIFAD_CONF_EXAMPLE_CONTENT)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${YADIFAD_CONF}" "")
foreach(SOURCE_LINE IN LISTS YADIFAD_CONF_EXAMPLE_CONTENT)
    string(REGEX REPLACE "(.*)/var/(.*)" "XXXMATCHXXX1${LOCALSTATEDIR}/XXXMATCHXXX2" TARGET_LINE "${SOURCE_LINE}")
    string(REPLACE "XXXMATCHXXX1" "${CMAKE_MATCH_1}" TARGET_LINE "${TARGET_LINE}")
    string(REPLACE "XXXMATCHXXX2" "${CMAKE_MATCH_2}" TARGET_LINE "${TARGET_LINE}")
    file(APPEND "${CMAKE_CURRENT_BINARY_DIR}/${YADIFAD_CONF}" "${TARGET_LINE}\n")
endforeach()

# YAKEYROLLD_CONF
message("Generating ${CMAKE_CURRENT_BINARY_DIR}/${YAKEYROLLD_CONF} from ${YAKEYROLLD_CONF_EXAMPLE}")
file(STRINGS "${YAKEYROLLD_CONF_EXAMPLE}" YAKEYROLLD_CONF_EXAMPLE_CONTENT)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${YAKEYROLLD_CONF}" "")
foreach(SOURCE_LINE IN LISTS YAKEYROLLD_CONF_EXAMPLE_CONTENT)
    string(REGEX REPLACE "(.*)/var/(.*)" "XXXMATCHXXX1${LOCALSTATEDIR}/XXXMATCHXXX2" TARGET_LINE "${SOURCE_LINE}")
    string(REPLACE "XXXMATCHXXX1" "${CMAKE_MATCH_1}" TARGET_LINE "${TARGET_LINE}")
    string(REPLACE "XXXMATCHXXX2" "${CMAKE_MATCH_2}" TARGET_LINE "${TARGET_LINE}")
    file(APPEND "${CMAKE_CURRENT_BINARY_DIR}/${YAKEYROLLD_CONF}" "${TARGET_LINE}\n")
endforeach()

# YADIFA_CONF
configure_file("${YADIFA_CONF_EXAMPLE}" "${CMAKE_CURRENT_BINARY_DIR}/${YADIFA_CONF}" COPYONLY)

# KEYS_CONF
message("Generating ${CMAKE_CURRENT_BINARY_DIR}/${KEYS_CONF} from ${KEYS_CONF_EXAMPLE}")
file(STRINGS "${KEYS_CONF_EXAMPLE}" KEYS_CONF_EXAMPLE_CONTENT)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${KEYS_CONF}" "")
foreach(SOURCE_LINE IN LISTS KEYS_CONF_EXAMPLE_CONTENT)
    string(REPLACE "ChangeThisKey" "${RNDBASE64}" TARGET_LINE "${SOURCE_LINE}")
    file(APPEND "${CMAKE_CURRENT_BINARY_DIR}/${KEYS_CONF}" "${TARGET_LINE}\n")
endforeach()

# YADIFAD_INIT
message("Generating ${CMAKE_CURRENT_BINARY_DIR}/${YADIFAD_INIT} from ${YADIFAD_INIT_EXAMPLE}")
file(STRINGS "${YADIFAD_INIT_EXAMPLE}" YADIFAD_INIT_EXAMPLE_CONTENT)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${YADIFAD_INIT}" "")
foreach(SOURCE_LINE IN LISTS YADIFAD_INIT_EXAMPLE_CONTENT)
    string(REGEX REPLACE "^PREFIX=.*" "PREFIX=${PREFIX}" TARGET_LINE "${SOURCE_LINE}")
    file(APPEND "${CMAKE_CURRENT_BINARY_DIR}/${YADIFAD_INIT}" "${TARGET_LINE}\n")
endforeach()

# YADIFAD_SERVICE
message("Generating ${CMAKE_CURRENT_BINARY_DIR}/${YADIFAD_SERVICE} from ${YADIFAD_SERVICE_EXAMPLE}")
file(STRINGS "${YADIFAD_SERVICE_EXAMPLE}" YADIFAD_SERVICE_EXAMPLE_CONTENT)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${YADIFAD_SERVICE}" "")
foreach(SOURCE_LINE IN LISTS YADIFAD_SERVICE_EXAMPLE_CONTENT)
    string(REGEX REPLACE "/usr/sbin" "${SBINDIR}" TARGET_LINE "${SOURCE_LINE}")
    string(REGEX REPLACE "/etc/yadifa" "${SYSCONFDIR}" TARGET_LINE "${TARGET_LINE}")
    string(REGEX REPLACE "/var" "${LOCALSTATE}" TARGET_LINE "${TARGET_LINE}")
    file(APPEND "${CMAKE_CURRENT_BINARY_DIR}/${YADIFAD_SERVICE}" "${TARGET_LINE}\n")
endforeach()

# YC
configure_file("${YADIFA_BASH_COMPLETION}" "${YADIFA_BASH_COMPLETION_GENERATED}" COPYONLY)

# YD
configure_file("${YADIFAD_BASH_COMPLETION}" "${YADIFAD_BASH_COMPLETION_GENERATED}" COPYONLY)

# The reason this overwrites already existing files is that these generated files are newer than the existing ones
#
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${YADIFAD_CONF}" DESTINATION "${CMAKE_INSTALL_FULL_DOCDIR}" COMPONENT etc)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${KEYS_CONF}" DESTINATION "${CMAKE_INSTALL_FULL_DOCDIR}" COMPONENT etc)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${YADIFA_CONF}" DESTINATION "${CMAKE_INSTALL_FULL_DOCDIR}" COMPONENT etc)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${YAKEYROLLD_CONF}" DESTINATION "${CMAKE_INSTALL_FULL_DOCDIR}" COMPONENT etc)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${YADIFAD_INIT}" DESTINATION "${CMAKE_INSTALL_FULL_DOCDIR}" COMPONENT etc)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${YADIFAD_SERVICE}" DESTINATION "${CMAKE_INSTALL_FULL_DOCDIR}" COMPONENT etc)

install(FILES "${YADIFA_BASH_COMPLETION_GENERATED}" DESTINATION "${CMAKE_INSTALL_FULL_DOCDIR}" COMPONENT etc)
install(FILES "${YADIFAD_BASH_COMPLETION_GENERATED}" DESTINATION "${CMAKE_INSTALL_FULL_DOCDIR}" COMPONENT etc)

install(FILES
        "yadifad-primary.conf.example"
        "yadifad-secondary.conf.example"
        "yadifad.init.debian"
        "yadifad.init.rhel"
        "yadifad.logrotate"
        "yadifad.service.arch"
        "yadifad.service.debian"
        "yadifad.service.rhel"
        "yakeyrolld.conf.example"
        DESTINATION "${CMAKE_INSTALL_FULL_DOCDIR}" COMPONENT etc)

install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR})
install(CODE
        "
        #file(TOUCH \"${CMAKE_INSTALL_FULL_SYSCONFDIR}/yadifa.conf\")
        file(TOUCH \"${CMAKE_INSTALL_FULL_SYSCONFDIR}/yadifad.conf\")
        file(TOUCH \"${CMAKE_INSTALL_FULL_SYSCONFDIR}/yakeyrolld.conf\")
        ")
