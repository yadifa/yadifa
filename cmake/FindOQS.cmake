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

kvstatus("OpenQuantumSafe" "find library libOQS")
kvstatus("CMAKE_SIZEOF_VOID_P" ${CMAKE_SIZEOF_VOID_P})
if(${CMAKE_SIZEOF_VOID_P} STREQUAL "8")
    set(OPENQUANTUMSAFE_ADDITIONAL_LIBRARY_HINT "lib64")
else()
    set(OPENQUANTUMSAFE_ADDITIONAL_LIBRARY_HINT "lib32")
endif()

set(OPENQUANTUMSAFE_ADDITIONAL_PATH "")

kvstatus("OpenQuantumSafe" "additional path: ${OPENQUANTUMSAFE_ADDITIONAL_PATH}")

set(OPENQUANTUMSAFE_FIND_PATH "not set")
set(OPENQUANTUMSAFE_FIND_PATH_SUFFIXES "not set")
set(OPENQUANTUMSAFE_FIND_CRYPTO "not set")
set(OPENQUANTUMSAFE_FIND_SSL "not set")
set(OPENQUANTUMSAFE_FIND_NODEFAULT 0)

set(OPENQUANTUMSAFE_FIND_PATH "${OPENQUANTUMSAFE_ADDITIONAL_PATH} /usr/local/openssl/ /usr/local/ /usr/")
set(OPENQUANTUMSAFE_FIND_PATH_SUFFIXES lib ${OPENQUANTUMSAFE_ADDITIONAL_LIBRARY_HINT})
set(OPENQUANTUMSAFE_FIND_OQS "oqs")

if(OPENQUANTUMSAFE_DIRECTORY)
    kvmessage("OpenQuantumSafe" "directory set to ${OPENQUANTUMSAFE_DIRECTORY}")
    set(OPENQUANTUMSAFE_FIND_PATH ${OPENQUANTUMSAFE_DIRECTORY})
    set(OPENQUANTUMSAFE_FIND_NODEFAULT 1)
else()
    kvmessage("OpenQuantumSafe" "directory not set")
endif()

    # detect

if(${OPENQUANTUMSAFE_FIND_NODEFAULT} EQUAL 0)
    kvmessage("OpenQuantumSafe" "find ${OPENQUANTUMSAFE_FIND_OQS} in ${OPENQUANTUMSAFE_FIND_PATH} / ${OPENQUANTUMSAFE_FIND_PATH_SUFFIXES} and default paths")
    find_library(OPENQUANTUMSAFE_LIB
            NAMES
            ${OPENQUANTUMSAFE_FIND_OQS}
            PATHS
            ${OPENQUANTUMSAFE_FIND_PATH}
            PATH_SUFFIXES
            ${OPENQUANTUMSAFE_FIND_PATH_SUFFIXES}
            )

    unset(OPENQUANTUMSAFE_HEADERS CACHE)

    find_path(OPENQUANTUMSAFE_HEADERS
            NAMES
            oqs/oqs.h
            PATHS
            ${OPENQUANTUMSAFE_FIND_PATH}
            PATH_SUFFIXES
            include
            )
else()
    kvmessage("OpenQuantumSafe" "find ${OPENQUANTUMSAFE_FIND_SSL} in ${OPENQUANTUMSAFE_FIND_PATH} / ${OPENQUANTUMSAFE_FIND_PATH_SUFFIXES}")
    find_library(OPENQUANTUMSAFE_LIB
            NAMES
            ${OPENQUANTUMSAFE_FIND_OQS}
            PATHS
            ${OPENQUANTUMSAFE_FIND_PATH}
            PATH_SUFFIXES
            ${OPENQUANTUMSAFE_FIND_PATH_SUFFIXES}
    )

    unset(OPENQUANTUMSAFE_HEADERS CACHE)

    find_path(OPENQUANTUMSAFE_HEADERS
            NAMES
            oqs/oqs.h
            PATHS
            ${OPENQUANTUMSAFE_FIND_PATH}
            PATH_SUFFIXES
            include
            NO_DEFAULT_PATH
            NO_SYSTEM_ENVIRONMENT_PATH
            )
endif()

if(OPENQUANTUMSAFE_HEADERS)
    kvstatus("OpenQuantumSafe headers" "${OPENQUANTUMSAFE_HEADERS}")
    include_directories(${OPENQUANTUMSAFE_HEADERS})

    if(OPENQUANTUMSAFE_LIB)
        kvstatus("OpenQuantumSafe found" "${OPENQUANTUMSAFE_LIB}")
        set(DNSCORE_LIBRARIES_DEPS ${DNSCORE_LIBRARIES_DEPS} ${OPENQUANTUMSAFE_LIB})
    else()
        kvstatus("OpenQuantumSafe" "library not found")
    endif()
else()
    kvstatus("OpenQuantumSafe headers" "headers not found")
endif()
