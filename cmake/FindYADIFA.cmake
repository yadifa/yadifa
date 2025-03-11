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

function(FindYADIFAHandleLib NAME LIBNAME HEADERNAME LIST)
    #message("NAME=${NAME} LIBNAME=${LIBNAME} HEADERNAME=${HEADERNAME} LIST=${LIST}")

    set(${NAME}_FOUND false PARENT_SCOPE)

    find_library(${NAME}_LIB
            NAMES           ${LIBNAME}
            PATHS           ${LIST}
            PATH_SUFFIXES   lib
            )

    if(NOT ${${NAME}_LIB} STREQUAL "${NAME}_LIB-NOTFOUND")
        set(${NAME}_LIB ${${NAME}_LIB} PARENT_SCOPE)
        set(YADIFA_LIBRARIES ${YADIFA_LIBRARIES} ${${NAME}_LIB} PARENT_SCOPE)
        message("${LIBNAME} library: ${${NAME}_LIB}")
    else()
        message(FATAL_ERROR "${LIBNAME} library: not found")
    endif()

    unset(${NAME}_INCLUDE_DIR CACHE)
    find_path(${NAME}_INCLUDE_DIR
            NAMES ${HEADERNAME}
            PATHS ${LIST}
            PATH_SUFFIXES include
            )

    if(NOT ${${NAME}_INCLUDE_DIR} STREQUAL "${NAME}_INCLUDE_DIR-NOTFOUND")
        set(${NAME}_INCLUDE_DIR ${${NAME}_INCLUDE_DIR} PARENT_SCOPE)
        set(YADIFA_INCLUDE_DIRS ${YADIFA_INCLUDE_DIRS} ${${NAME}_INCLUDE_DIR} PARENT_SCOPE)
        message("${LIBNAME} headers: ${${NAME}_INCLUDE_DIR}")

        set(${NAME}_FOUND true PARENT_SCOPE)

    else()
        message(FATAL_ERROR "${LIBNAME} headers: not found (${HEADERNAME})")
        return()
    endif()
endfunction()

function(FindYADIFA)
    set(YADIFA_OPTIONS DNSCORE DNSDB DNSTCL DNSLG)
    set(YADIFA_PATHS SEARCH_PATHS)
    cmake_parse_arguments(YADIFA "${YADIFA_OPTIONS}" "" "${YADIFA_PATHS}" ${ARGN})

    #message("YADIFA_DNSCORE=${YADIFA_DNSCORE}")
    #message("YADIFA_DNSDB=${YADIFA_DNSDB}")
    #message("YADIFA_DNSTCL=${YADIFA_DNSTCL}")
    #message("YADIFA_DNSLG=${YADIFA_DNSLG}")
    #message("YADIFA_SEARCH_PATHS=${YADIFA_SEARCH_PATHS}")
    #
    set(YADIFA_LIBRARIES "" PARENT_SCOPE)
    set(YADIFA_INCLUDE_DIRS "" PARENT_SCOPE)

    if(YADIFA_DNSCORE)
        FindYADIFAHandleLib(DNSCORE dnscore dnscore/dnscore.h "${YADIFA_SEARCH_PATHS}")
        message("DNSCORE_LIB=${DNSCORE_LIB} DNSCORE_INCLUDE_DIR=${DNSCORE_INCLUDE_DIR}")
    endif()

    if(YADIFA_DNSDB)
        FindYADIFAHandleLib(DNSDB dnsdb dnsdb/zdb.h "${YADIFA_SEARCH_PATHS}")
        message("DNSDB_LIB=${DNSDB_LIB} DNSDB_INCLUDE_DIR=${DNSDB_INCLUDE_DIR}")
    endif()

    if(YADIFA_DNSTCL)
        FindYADIFAHandleLib(DNSTCL dnstcl dnstcl/dnstcl.h "${YADIFA_SEARCH_PATHS}")
        message("DNSTCL_LIB=${DNSTCL_LIB} DNSTCL_INCLUDE_DIR=${DNSTCL_INCLUDE_DIR}")
    endif()

    if(YADIFA_DNSLG)
        FindYADIFAHandleLib(DNSLG dnslg dnslg/dns.h "${YADIFA_SEARCH_PATHS}")
        message("DNSLG_LIB=${DNSLG_LIB} DNSLG_INCLUDE_DIR=${DNSLG_INCLUDE_DIR}")
    endif()

    list(REMOVE_DUPLICATES YADIFA_INCLUDE_DIRS)

    #message("YADIFA_LIBRARIES=${YADIFA_LIBRARIES}")
    #message("YADIFA_INCLUDE_DIRS=${YADIFA_INCLUDE_DIRS}")
    #message("YADIFA_INCLUDE_DIRS_LIST=${YADIFA_INCLUDE_DIRS_LIST}")

    set(YADIFA_LIBRARIES "${YADIFA_LIBRARIES}" PARENT_SCOPE)
    set(YADIFA_INCLUDE_DIRS "${YADIFA_INCLUDE_DIRS}" PARENT_SCOPE)
endfunction()

