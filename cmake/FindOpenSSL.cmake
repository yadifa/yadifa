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

kvstatus("find package" "Openssl")
kvstatus("CMAKE_SIZEOF_VOID_P" ${CMAKE_SIZEOF_VOID_P})
if(${CMAKE_SIZEOF_VOID_P} STREQUAL "8")
    set(OPENSSL_ADDITIONAL_LIBRARY_HINT "lib64")
else()
    set(OPENSSL_ADDITIONAL_LIBRARY_HINT "lib32")
endif()

set(OPENSSL_ADDITIONAL_PATH "")

# @20151002 gve --  this is specially for 'el capitan' until a solution has been found, problem finding openssl include files
if(CMAKE_HOST_SYSTEM_NAME MATCHES "Darwin")
        
        message(STATUS "Host System Version              : ${CMAKE_HOST_SYSTEM_VERSION}")
        if("${CMAKE_HOST_SYSTEM_VERSION}" GREATER 6)
                message(STATUS "note: MacOS X version is 10.7 or higher")
                add_definitions(-Wno-deprecated)
        endif()

        if("${CMAKE_HOST_SYSTEM_VERSION}" GREATER 20)
                message(STATUS "note: MacOS 11 version is 'Big Sur'")
                #
                # @TODO 20201201 gve -- ld can not find -lSystem, adding directory does not work
                #
#                include_directories("/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/System.framework")
        elseif("${CMAKE_HOST_SYSTEM_VERSION}" GREATER 19)
                message(STATUS "note: MacOS X version is 'Catalina'")
        elseif("${CMAKE_HOST_SYSTEM_VERSION}" GREATER 17)
                message(STATUS "note: MacOS X version is 'High Sierra'")
        elseif("${CMAKE_HOST_SYSTEM_VERSION}" GREATER 14)
                message(STATUS "note: MacOS X version is 'El capitan'")
                include_directories("/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-migrator/sdk/MacOSX.sdk/usr/include/")
        endif()

	#set(OPENSSL_ADDITIONAL_PATH "/usr/local/Cellar/openssl@1.1/1.1.1g")
	set(OPENSSL_ADDITIONAL_PATH "/opt/homebrew/Cellar/openssl\@3/3.4.0")

endif()

kvstatus("Openssl additional path" "${OPENSSL_ADDITIONAL_PATH}")

set(OPENSSL_FIND_PATH "not set")
set(OPENSSL_FIND_PATH_SUFFIXES "not set")
set(OPENSSL_FIND_CRYPTO "not set")
set(OPENSSL_FIND_SSL "not set")
set(OPENSSL_FIND_NODEFAULT 0)

if(APPLE)
    kvmessage("Crypto" "Darwin")
    set(OPENSSL_FIND_PATH "${OPENSSL_ADDITIONAL_PATH} /usr/local/openssl/ /usr/local/ /usr/ /opt/homebrew/")
    set(OPENSSL_FIND_PATH_SUFFIXES "lib")
    set(OPENSSL_FIND_CRYPTO "crypto")
    set(OPENSSL_FIND_SSL "ssl")
    # also: NO_DEFAULT_PATH NO_SYSTEM_ENVIRONMENT_PATH
    set(OPENSSL_FIND_NODEFAULT 1)
elseif(UNIX)
    kvmessage("Crypto" "Unix")
    set(OPENSSL_FIND_PATH "${OPENSSL_ADDITIONAL_PATH} /usr/local/openssl/ /usr/local/ /usr/")
    set(OPENSSL_FIND_PATH_SUFFIXES lib ${OPENSSL_ADDITIONAL_LIBRARY_HINT})
    set(OPENSSL_FIND_CRYPTO "crypto")
    set(OPENSSL_FIND_SSL "ssl")
elseif(WIN32)
    kvmessage("Crypto" "WIN32")
    set(OPENSSL_FIND_PATH ${OPENSSL_ADDITIONAL_PATH} "C:/Program Files/OpenSSL")
    set(OPENSSL_FIND_PATH_SUFFIXES "lib")
    set(OPENSSL_FIND_CRYPTO "libcrypto.lib")
    set(OPENSSL_FIND_SSL "libssl.lib")
else()
    message(FATAL_ERROR "System is not supported")
endif()

if(OPENSSL_DIRECTORY)
    kvmessage("SSL" "OpenSSL directory set to ${OPENSSL_DIRECTORY}")
    set(OPENSSL_FIND_PATH ${OPENSSL_DIRECTORY})
    set(OPENSSL_FIND_NODEFAULT 1)
else()
    kvmessage("SSL" "OpenSSL directory not set")
endif()

    # detect

if(${OPENSSL_FIND_NODEFAULT} EQUAL 0)
    kvmessage("SSL" "find ${OPENSSL_FIND_CRYPTO} in ${OPENSSL_FIND_PATH} / ${OPENSSL_FIND_PATH_SUFFIXES} and default paths")
    find_library(CRYPTO_LIB
            NAMES
            ${OPENSSL_FIND_CRYPTO}
            PATHS
            ${OPENSSL_FIND_PATH}
            PATH_SUFFIXES
            ${OPENSSL_FIND_PATH_SUFFIXES}
            )
    kvmessage("SSL" "find ${OPENSSL_FIND_SSL} in ${OPENSSL_FIND_PATH} / ${OPENSSL_FIND_PATH_SUFFIXES} and default paths")
    find_library(OPENSSL_LIB
            NAMES
            ${OPENSSL_FIND_SSL}
            PATHS
            ${OPENSSL_FIND_PATH}
            PATH_SUFFIXES
            ${OPENSSL_FIND_PATH_SUFFIXES}
            )

    unset(OPENSSL_HEADERS CACHE)

    find_path(OPENSSL_HEADERS
            NAMES
            openssl/engine.h
            PATHS
            ${OPENSSL_FIND_PATH}
            PATH_SUFFIXES
            include
            )

else()
    kvmessage("SSL" "find ${OPENSSL_FIND_CRYPTO} in ${OPENSSL_FIND_PATH} / ${OPENSSL_FIND_PATH_SUFFIXES}")
    find_library(CRYPTO_LIB
            NAMES
            ${OPENSSL_FIND_CRYPTO}
            PATHS
            ${OPENSSL_FIND_PATH}
            PATH_SUFFIXES
            ${OPENSSL_FIND_PATH_SUFFIXES}
            NO_DEFAULT_PATH
            NO_SYSTEM_ENVIRONMENT_PATH
            )
    kvmessage("SSL" "find ${OPENSSL_FIND_SSL} in ${OPENSSL_FIND_PATH} / ${OPENSSL_FIND_PATH_SUFFIXES}")
    find_library(OPENSSL_LIB
            NAMES
            ${OPENSSL_FIND_SSL}
            PATHS
            ${OPENSSL_FIND_PATH}
            PATH_SUFFIXES
            ${OPENSSL_FIND_PATH_SUFFIXES}
            NO_DEFAULT_PATH
            NO_SYSTEM_ENVIRONMENT_PATH
            )

    unset(OPENSSL_HEADERS CACHE)
    find_path(OPENSSL_HEADERS
            NAMES
            openssl/engine.h
            PATHS
            ${OPENSSL_FIND_PATH}
            PATH_SUFFIXES
            include
            NO_DEFAULT_PATH
            NO_SYSTEM_ENVIRONMENT_PATH
            )
endif()

if(CRYPTO_LIB)
    kvstatus("crypto found" "${CRYPTO_LIB}")
    set(DNSCORE_LIBRARIES_DEPS ${DNSCORE_LIBRARIES_DEPS} ${CRYPTO_LIB})
else()
    kvfatal("crypto" "not found")
endif()

if(OPENSSL_HEADERS)
    kvstatus("openssl headers" "${OPENSSL_HEADERS}")
    include_directories(${OPENSSL_HEADERS})
else()
    kvstatus("openssl headers" "not found")
endif()

if(OPENSSL_LIB)
    kvstatus("openssl found" "${OPENSSL_LIB}")
    set(DNSCORE_LIBRARIES_DEPS ${DNSCORE_LIBRARIES_DEPS} ${OPENSSL_LIB})
else()
    kvfatal("openssl" "not found")
endif()

########################################################################################################################

set(LIBRESSL_DETECTION_PROGRAM_SOURCE "#include <openssl/ssl.h>
int main()
{
#if LIBRESSL_VERSION_NUMBER
    printf(\"libressl\")%SEMICOLON%
#else
    printf(\"openssl\")%SEMICOLON%
#endif
    return 0%SEMICOLON%
}
")

set(LIBRESSL_DETECTION_PROGRAM_RESULT "?")
set(LIBRESSL_DETECTION_PROGRAM_OUTPUT "?")

get_filename_component(OPENSSL_LIB_PATH "${OPENSSL_LIB}" DIRECTORY)

compile_and_run(SOURCE "${LIBRESSL_DETECTION_PROGRAM_SOURCE}"
        RESULT_VARIABLE LIBRESSL_DETECTION_PROGRAM_RESULT
        OUTPUT_VARIABLE LIBRESSL_DETECTION_PROGRAM_OUTPUT
        CFLAGS -I ${OPENSSL_HEADERS}
        LDFLAGS -Wl,-rpath=${OPENSSL_LIB_PATH} ${OPENSSL_LIB} ${CRYPTO_LIB})

kvmessage("libressl-version result" "${LIBRESSL_DETECTION_PROGRAM_RESULT}")
kvmessage("libressl-version output" "${LIBRESSL_DETECTION_PROGRAM_OUTPUT}")

if("${LIBRESSL_DETECTION_PROGRAM_OUTPUT}" STREQUAL "libressl")
    set(HAS_LIBRESSL_MODE 1 CACHE BOOL "libressl replaces openssl on this build" FORCE)
    kvmessage("SSL mode" "libreSSL")
else()
    set(HAS_LIBRESSL_MODE 0 CACHE BOOL "genuine openssl on this build" FORCE)
    kvmessage("SSL mode" "openSSL")
endif()

########################################################################################################################

set(OPENSSL_VERSION_PROGRAM_SOURCE "#include <stdio.h>
unsigned int OPENSSL_version_major(void)%SEMICOLON%
unsigned int OPENSSL_version_minor(void)%SEMICOLON%
unsigned int OPENSSL_version_patch(void)%SEMICOLON%
int main()
{
   printf(\"%i.%i.%i%LF%\", OPENSSL_version_major(), OPENSSL_version_minor(), OPENSSL_version_patch())%SEMICOLON%
   return 0%SEMICOLON%
}
")

set(OPENSSL_VERSION_PROGRAM_RESULT "?")
set(OPENSSL_VERSION_PROGRAM_OUTPUT "?")

get_filename_component(OPENSSL_LIB_PATH "${OPENSSL_LIB}" DIRECTORY)

compile_and_run(SOURCE "${OPENSSL_VERSION_PROGRAM_SOURCE}"
        RESULT_VARIABLE OPENSSL_VERSION_PROGRAM_RESULT
        OUTPUT_VARIABLE OPENSSL_VERSION_PROGRAM_OUTPUT
        CFLAGS -I ${OPENSSL_HEADERS}
        LDFLAGS -Wl,-rpath=${OPENSSL_LIB_PATH} ${OPENSSL_LIB} ${CRYPTO_LIB})

kvmessage("openssl-version result" "${OPENSSL_VERSION_PROGRAM_RESULT}")
kvmessage("openssl-version output" "${OPENSSL_VERSION_PROGRAM_OUTPUT}")
if(${OPENSSL_VERSION_PROGRAM_RESULT} EQUAL 0)
    string(REGEX MATCH "^([0-9]+)" OPENSSL_VERSION_MAJOR "${OPENSSL_VERSION_PROGRAM_OUTPUT}")
    kvmessage("openssl-version major" "${OPENSSL_VERSION_MAJOR}")
else()
    set(OPENSSL_VERSION_MAJOR 1)
    kvmessage("openssl-version major" "${OPENSSL_VERSION_MAJOR}")
endif()

set(OPENSSL_VERSION_MAJOR "${OPENSSL_VERSION_MAJOR}" CACHE STRING "The detected version of libssl" FORCE)

# find pthread otherwise quit
find_library(PTHREAD_LIB
        NAMES
        pthread
        PATHS
        /usr/local/ /usr/
        PATH_SUFFIXES
        lib
        )

