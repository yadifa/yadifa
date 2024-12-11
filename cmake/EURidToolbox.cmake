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

include(CheckIncludeFile)
include(TestBigEndian)
include(CheckSymbolExists)

function(StoreBooleanToCache VARNAME VARTEXT HELP)
    if(${${VARNAME}})
        set(${VARNAME} ON CACHE BOOL ${HELP})
        message("${VARTEXT}: yes")
    else()
        set(${VARNAME} OFF CACHE BOOL ${HELP})
        message("${VARTEXT}: no")
    endif()
endfunction()

function(StoreNotBooleanToCache VARNAME VARTEXT HELP)
    if(${${VARNAME}})
        set(${VARNAME} OFF CACHE BOOL ${HELP})
        message("${VARTEXT}: no")
    else()
        set(${VARNAME} ON CACHE BOOL ${HELP})
        message("${VARTEXT}: yes")
    endif()
endfunction()

# try_compile prints all the output, so we need our own

function(try_c_compile_silently SOURCE_CODE OUT_VAR_NAME)
    #message(STATUS "try_c_compile_silently ${SOURCE_CODE}")
    set(TRY_COMPILE_SILENTLY_FILE "${CMAKE_CURRENT_BINARY_DIR}/try_c_compile_silently.c")
    file(WRITE ${TRY_COMPILE_SILENTLY_FILE} "${SOURCE_CODE}")
    set(TRY_COMPILE_SILENTLY_COMMAND "${CMAKE_C_COMPILER}")
    set(TRY_COMPILE_SILENTLY_TARGET_ARG "-o")
    set(TRY_COMPILE_SILENTLY_TARGET_FILE "${CMAKE_CURRENT_BINARY_DIR}/try_c_compile_silently")
    #message(STATUS "try_c_compile_silently for ${OUT_VAR_NAME} using '${TRY_COMPILE_SILENTLY_COMMAND} ${CMAKE_C_FLAGS} ${TRY_COMPILE_SILENTLY_FILE} ${TRY_COMPILE_SILENTLY_TARGET_ARG} ${TRY_COMPILE_SILENTLY_TARGET_FILE}'")
    execute_process(
            COMMAND ${TRY_COMPILE_SILENTLY_COMMAND} ${CMAKE_C_FLAGS} ${TRY_COMPILE_SILENTLY_FILE} ${TRY_COMPILE_SILENTLY_TARGET_ARG} ${TRY_COMPILE_SILENTLY_TARGET_FILE}
            RESULT_VARIABLE TRY_COMPILE_SILENTLY_RESULT
            OUTPUT_QUIET
            ERROR_QUIET
            )
    #message("TRY_COMPILE_SILENTLY_RESULT ${TRY_COMPILE_SILENTLY_RESULT}")
    if(${TRY_COMPILE_SILENTLY_RESULT} EQUAL 0)
        set(${OUT_VAR_NAME} 1 PARENT_SCOPE)
    else()
        set(${OUT_VAR_NAME} 0 PARENT_SCOPE)
    endif()
    file(REMOVE ${TRY_COMPILE_SILENTLY_TARGET_FILE})
    file(REMOVE ${TRY_COMPILE_SILENTLY_FILE})
endfunction()

function(try_c_compile_and_run_silently SOURCE_CODE OUT_VAR_NAME)
    if(LINUX)
        message(STATUS "try_c_compile_and_run_silently ${SOURCE_CODE} in ${CMAKE_CURRENT_BINARY_DIR}")
        set(TRY_COMPILE_AND_RUN_SILENTLY_FILE "${CMAKE_CURRENT_BINARY_DIR}/try_c_compile_and_run_silently.c")
        file(WRITE ${TRY_COMPILE_AND_RUN_SILENTLY_FILE} "${SOURCE_CODE}")
        set(TRY_COMPILE_AND_RUN_SILENTLY_COMMAND "${CMAKE_C_COMPILER}")
        set(TRY_COMPILE_AND_RUN_SILENTLY_TARGET_ARG "-o")
        set(TRY_COMPILE_AND_RUN_SILENTLY_TARGET_FILE "${CMAKE_CURRENT_BINARY_DIR}/try_c_compile_and_run_silently")
        message(STATUS "try_c_compile_and_run_silently for ${OUT_VAR_NAME} using '\"${TRY_COMPILE_AND_RUN_SILENTLY_COMMAND}\" ${CMAKE_C_FLAGS} ${TRY_COMPILE_AND_RUN_SILENTLY_FILE} ${TRY_COMPILE_AND_RUN_SILENTLY_TARGET_ARG} ${TRY_COMPILE_AND_RUN_SILENTLY_TARGET_FILE}'")
        execute_process(
                COMMAND "${TRY_COMPILE_AND_RUN_SILENTLY_COMMAND}" ${CMAKE_C_FLAGS} ${TRY_COMPILE_AND_RUN_SILENTLY_FILE} ${TRY_COMPILE_AND_RUN_SILENTLY_TARGET_ARG} ${TRY_COMPILE_AND_RUN_SILENTLY_TARGET_FILE}
                RESULT_VARIABLE TRY_COMPILE_AND_RUN_SILENTLY_COMPILE_RESULT
                #OUTPUT_QUIET
                #ERROR_QUIET
        )
        message("TRY_COMPILE_AND_RUN_SILENTLY_COMPILE_RESULT compile: ${TRY_COMPILE_AND_RUN_SILENTLY_COMPILE_RESULT}")
        if(TRY_COMPILE_AND_RUN_SILENTLY_COMPILE_RESULT EQUAL 0)
            execute_process(
                    COMMAND ${TRY_COMPILE_AND_RUN_SILENTLY_TARGET_FILE}
                    RESULT_VARIABLE TRY_COMPILE_AND_RUN_SILENTLY_RESULT
                    OUTPUT_QUIET
                    ERROR_QUIET
            )
            #message("TRY_COMPILE_AND_RUN_SILENTLY_RESULT run: ${TRY_COMPILE_AND_RUN_SILENTLY_RESULT}")

            set(${OUT_VAR_NAME} ${TRY_COMPILE_AND_RUN_SILENTLY_RESULT})
            set(${OUT_VAR_NAME} ${TRY_COMPILE_AND_RUN_SILENTLY_RESULT} PARENT_SCOPE)
        else()
            set(${OUT_VAR_NAME} "FAILURE-TO-COMPILE")
            set(${OUT_VAR_NAME} "FAILURE-TO-COMPILE" PARENT_SCOPE)
        endif()

        file(REMOVE ${TRY_COMPILE_AND_RUN_SILENTLY_TARGET_FILE})
        file(REMOVE ${TRY_COMPILE_AND_RUN_SILENTLY_FILE})

        #message("TRY_COMPILE_AND_RUN_SILENTLY_RESULT returning: OUT_VAR_NAME=${OUT_VAR_NAME}=${${OUT_VAR_NAME}}")
    else()
        set(${OUT_VAR_NAME} 0)
    endif() # LINUX    
endfunction()

#
# Given cmake insists on splitting on ; no matter what, the source can use %SEMICOLON% %CR% and %LF%
#

macro(compile_and_run)
    message("compile_and_run(${ARGN})")
    set(parameters SOURCE RESULT_VARIABLE OUTPUT_VARIABLE ERROR_VARIABLE)
    set(multiparameters CFLAGS LDFLAGS)
    cmake_parse_arguments(COMPILE_AND_RUN "" "${parameters}" "${multiparameters}" ${ARGN})

    if(NOT COMPILE_AND_RUN_SOURCE)
        kvfatal("compile_and_run" "source not defined")
    endif()

    string(REPLACE "%SEMICOLON%" "\\\;" COMPILE_AND_RUN_SOURCE ${COMPILE_AND_RUN_SOURCE})
    string(REPLACE "%CR%" "\\r" COMPILE_AND_RUN_SOURCE ${COMPILE_AND_RUN_SOURCE})
    string(REPLACE "%LF%" "\\n" COMPILE_AND_RUN_SOURCE ${COMPILE_AND_RUN_SOURCE})

    message(STATUS "compile_and_run SOURCE='${COMPILE_AND_RUN_SOURCE}' RESULT_VAR=${COMPILE_AND_RUN_RESULT_VARIABLE} OUTPUT_VAR=${COMPILE_AND_RUN_OUTPUT_VARIABLE} CFLAGS=${COMPILE_AND_RUN_CFLAGS} LDFLAGS=${COMPILE_AND_RUN_LDFLAGS}")
    string(SHA256 COMPILE_AND_RUN_SUFFIX "${COMPILE_AND_RUN_SOURCE}")

    set(COMPILE_AND_RUN_TARGET_FILE "${CMAKE_CURRENT_BINARY_DIR}/compile_and_run_${COMPILE_AND_RUN_SUFFIX}")
    set(COMPILE_AND_RUN_FILE "${COMPILE_AND_RUN_TARGET_FILE}.c")

    file(WRITE ${COMPILE_AND_RUN_FILE} "${COMPILE_AND_RUN_SOURCE}")
    set(COMPILE_AND_RUN_COMMAND "${CMAKE_C_COMPILER}")
    set(COMPILE_AND_RUN_TARGET_ARG "-o")

    message(STATUS "compile_and_run cmd='${COMPILE_AND_RUN_COMMAND}' cflags='${COMPILE_AND_RUN_CFLAGS}' file='${COMPILE_AND_RUN_FILE}' target_arg='${COMPILE_AND_RUN_TARGET_ARG}' target_file='${COMPILE_AND_RUN_TARGET_FILE}' ldflags='${COMPILE_AND_RUN_LDFLAGS}'")
    message(STATUS "compile_and_run ${COMPILE_AND_RUN_COMMAND} ${COMPILE_AND_RUN_CFLAGS} ${COMPILE_AND_RUN_FILE} ${COMPILE_AND_RUN_TARGET_ARG} ${COMPILE_AND_RUN_TARGET_FILE} ${COMPILE_AND_RUN_LDFLAGS}")

    execute_process(COMMAND "${COMPILE_AND_RUN_COMMAND}" ${COMPILE_AND_RUN_CFLAGS} ${COMPILE_AND_RUN_FILE} ${COMPILE_AND_RUN_TARGET_ARG} ${COMPILE_AND_RUN_TARGET_FILE} ${COMPILE_AND_RUN_LDFLAGS}
            RESULT_VARIABLE ${COMPILE_AND_RUN_RESULT_VARIABLE}
            OUTPUT_VARIABLE ${COMPILE_AND_RUN_OUTPUT_VARIABLE})

    message("compile_and_run compile: ${${COMPILE_AND_RUN_RESULT_VARIABLE}}")

    if(${COMPILE_AND_RUN_RESULT_VARIABLE} EQUAL 0)
        execute_process(
                COMMAND ${COMPILE_AND_RUN_TARGET_FILE}
                RESULT_VARIABLE ${COMPILE_AND_RUN_RESULT_VARIABLE}
                OUTPUT_VARIABLE ${COMPILE_AND_RUN_OUTPUT_VARIABLE}
#                ERROR_VARIABLE ${COMPILE_AND_RUN_ERROR_VARIABLE}
                ERROR_QUIET
        )
        message("compile_and_run result: ${${COMPILE_AND_RUN_RESULT_VARIABLE}}")
        message("compile_and_run output: ${${COMPILE_AND_RUN_OUTPUT_VARIABLE}}")
    else()
        message("compile_and_run compilation failed")
    endif()

    #file(REMOVE ${COMPILE_AND_RUN_TARGET_FILE})
    #file(REMOVE ${COMPILE_AND_RUN_FILE})
endmacro()

# sockaddr_in sometimes has a sin_len field, sometimes has not

function(check_sockaddr_sin_len_field)
    set(CHECKSOCKADDRSINLENFIELD_SOURCE "")

    check_include_file(stdlib.h HAVE_STDLIB_H)
    if(${HAVE_STDLIB_H})
        set(CHECKSOCKADDRSINLENFIELD_SOURCE "${CHECKSOCKADDRSINLENFIELD_SOURCE}#include <stdlib.h>
")
    endif()
    check_include_file(sys/types.h HAVE_SYS_TYPES_H)
    if(${HAVE_SYS_TYPES_H})
        set(CHECKSOCKADDRSINLENFIELD_SOURCE "${CHECKSOCKADDRSINLENFIELD_SOURCE}#include <sys/types.h>
")
    endif()
    check_include_file(netinet/in.h HAVE_NETINET_IN_H)
    if(${HAVE_NETINET_IN_H})
        set(CHECKSOCKADDRSINLENFIELD_SOURCE "${CHECKSOCKADDRSINLENFIELD_SOURCE}#include <netinet/in.h>
")
    endif()
    check_include_file(netinet6/in6.h HAVE_NETINET6_IN6_H)
    if(${HAVE_NETINET6_IN6_H})
        set(CHECKSOCKADDRSINLENFIELD_SOURCE "${CHECKSOCKADDRSINLENFIELD_SOURCE}#include <netinet6/in6.h>
")
    endif()

    set(CHECKSOCKADDRSINLENFIELD_SOURCE "${CHECKSOCKADDRSINLENFIELD_SOURCE}int main(int argc, char** argv)
{
    struct sockaddr_in sa\;
    sa.sin_len = sizeof(struct sockaddr_in)\;
}
")

    try_c_compile_silently(${CHECKSOCKADDRSINLENFIELD_SOURCE} HAS_SOCKADDR_IN_SIN_LEN)

    set(HAS_SOCKADDR_IN_SIN_LEN ${HAS_SOCKADDR_IN_SIN_LEN} PARENT_SCOPE)

    StoreBooleanToCache(HAS_SOCKADDR_IN_SIN_LEN "Checked if struct sockaddr_in has sin_len field" "struct sockaddr_in has sin_len field")

    #file(WRITE check_sockaddr_sin_len_field.c ${CHECKSOCKADDRSINLENFIELD_SOURCE})
    #try_compile(HAS_SOCKADDR_IN_SIN_LEN ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/check_sockaddr_sin_len_field.c OUTPUT_VARIABLE HAS_SOCKADDR_IN_SIN_LEN_LOG OUTPUT_QUIET)
    #FILE(DELETE check_sockaddr_sin_len_field.c)
endfunction()

function(check_sockaddr_sin6_len_field)
    set(CHECKSOCKADDRSINLENFIELD_SOURCE "")

    check_include_file(stdlib.h HAVE_STDLIB_H)
    if(${HAVE_STDLIB_H})
        set(CHECKSOCKADDRSINLENFIELD_SOURCE "${CHECKSOCKADDRSINLENFIELD_SOURCE}#include <stdlib.h>
")
    endif()
    check_include_file(sys/types.h HAVE_SYS_TYPES_H)
    if(${HAVE_SYS_TYPES_H})
        set(CHECKSOCKADDRSINLENFIELD_SOURCE "${CHECKSOCKADDRSINLENFIELD_SOURCE}#include <sys/types.h>
")
    endif()
    check_include_file(netinet/in.h HAVE_NETINET_IN_H)
    if(${HAVE_NETINET_IN_H})
        set(CHECKSOCKADDRSINLENFIELD_SOURCE "${CHECKSOCKADDRSINLENFIELD_SOURCE}#include <netinet/in.h>
")
    endif()
    check_include_file(netinet6/in6.h HAVE_NETINET6_IN6_H)
    if(${HAVE_NETINET6_IN6_H})
        set(CHECKSOCKADDRSINLENFIELD_SOURCE "${CHECKSOCKADDRSINLENFIELD_SOURCE}#include <netinet6/in6.h>
")
    endif()

    set(CHECKSOCKADDRSINLENFIELD_SOURCE "${CHECKSOCKADDRSINLENFIELD_SOURCE}int main(int argc, char** argv)
{
    struct sockaddr_in6 sa6\;
    sa6.sin6_len = sizeof(struct sockaddr_in6)\;
}
")

    try_c_compile_silently(${CHECKSOCKADDRSINLENFIELD_SOURCE} HAS_SOCKADDR_IN6_SIN6_LEN)

    set(HAS_SOCKADDR_IN6_SIN6_LEN ${HAS_SOCKADDR_IN6_SIN6_LEN} PARENT_SCOPE)

    StoreBooleanToCache(HAS_SOCKADDR_IN6_SIN6_LEN "Checked if struct sockaddr_in6 has sin6_len field" "struct sockaddr_in6 has sin6_len field")

    #file(WRITE check_sockaddr_sin_len_field.c ${CHECKSOCKADDRSINLENFIELD_SOURCE})
    #try_compile(HAS_SOCKADDR_IN6_SIN6_LEN ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/check_sockaddr_sin_len_field.c OUTPUT_VARIABLE HAS_SOCKADDR_IN_SIN_LEN_LOG OUTPUT_QUIET)
    #FILE(DELETE check_sockaddr_sin_len_field.c)
endfunction()

# gcc has an attribute to suppress fallthrough warnings

function(check_gcc_fallthrough_support)
    set(CHECKGCCFALLTHROUGH_SOURCE "int main(int argc, char* argv[])\
{\
        switch(argc)\
        {\
                case 0:\
                        __attribute__ ((fallthrough));\
                default:\
                        break;\
        }\
        return 0;\
}")

    try_c_compile_silently(${CHECKGCCFALLTHROUGH_SOURCE} HAS_GCCFALLTHROUGH)

    set(HAS_GCCFALLTHROUGH ${HAS_GCCFALLTHROUGH} PARENT_SCOPE)

    StoreBooleanToCache(HAS_GCCFALLTHROUGH "Checked if the compiler supports GCC fallthrough attribute" "GCC fallthrough attribute")
endfunction()

# clang has an attribute to suppress fallthrough warnings

function(check_clang_fallthrough_support)
    set(CHECKCLANGFALLTHROUGH_SOURCE "int main(int argc, char* argv[])\
{\
        switch(argc)\
        {\
                case 0:\
                        [[fallthrough]];\
                default:\
                        break;\
        }\
        return 0;\
}")

    try_c_compile_silently(${CHECKCLANGFALLTHROUGH_SOURCE} HAS_CLANGFALLTHROUGH)

    set(HAS_CLANGFALLTHROUGH ${HAS_CLANGFALLTHROUGH} PARENT_SCOPE)

    StoreBooleanToCache(HAS_CLANGFALLTHROUGH "Checked if the compiler supports CLANG fallthrough attribute" "CLANG fallthrough attribute")
endfunction()

function(check_memalign_issues)
    set(CHECK_MEMALIGN_ISSUES_SOURCE "
#include<stdlib.h>

int main(int argc, char** argv)
{
        char* p = (char*)malloc(8)\;
        p++\;
        int* intp= (int*)p\;
        *intp=1\;
        return 0\;
}")

    try_c_compile_silently(${CHECK_MEMALIGN_ISSUES_SOURCE} HAS_MEMALIGN_ISSUES)

    StoreNotBooleanToCache(HAS_MEMALIGN_ISSUES "Checked if the system has issue writing on unaligned memory" "cannot write on unaligned memory")
endfunction()

function(check_gnu_source)
    set(CHECK_GNU_SOURCE "
#include <features.h>
#ifdef __GLIBC__
int main()
{
return 0;
}
#else
__GLIBC__ not defined
#endif
")
    try_c_compile_silently(${CHECK_GNU_SOURCE} HAS_GNU_SOURCE)

    StoreNotBooleanToCache(HAS_GNU_SOURCE "Checked if the system is using glibc" "glibc isn't the C library used")
endfunction()

function(check_self)
    set(CHECK_SELF_RETURN_0_SOURCE "
int main(int argc, char** argv)
{
        return 0\;
}")
    try_c_compile_and_run_silently(${CHECK_SELF_RETURN_0_SOURCE} CHECK_SELF_RETURN_0)
    if(NOT ${CHECK_SELF_RETURN_0} EQUAL 0)
        message(FATAL_ERROR "check_self: CHECK_SELF_RETURN_0 returned '${CHECK_SELF_RETURN_0}' instead of '0'")
    endif()
    #message(STATUS "Should return 0: ${CHECK_SELF_RETURN_0}")
    set(CHECK_SELF_RETURN_1_SOURCE "
int main(int argc, char** argv)
{
        return 1\;
}")
    try_c_compile_and_run_silently(${CHECK_SELF_RETURN_1_SOURCE} CHECK_SELF_RETURN_1)
    if(NOT ${CHECK_SELF_RETURN_1} EQUAL 1)
        message(FATAL_ERROR "check_self: CHECK_SELF_RETURN_1 returned '${CHECK_SELF_RETURN_1}' instead of '1'")
    endif()
    #message(STATUS "Should return 1: ${CHECK_SELF_RETURN_1}")
    set(CHECK_SELF_CRASH_SOURCE "
int main(int argc, char** argv)
{
        char *p = 0\;
        for(int i = 0\; i < 0x7fffffffLL\;++i)
        {
            p[i] = i\;
        }
        return 0\;
}")
    try_c_compile_and_run_silently(${CHECK_SELF_CRASH_SOURCE} CHECK_SELF_CRASH)
    if("${CHECK_SELF_CRASH}" EQUAL 0)
        message(FATAL_ERROR "check_self: CHECK_SELF_CRASH returned '${CHECK_SELF_CRASH}' instead of crashing")
    endif()
    #message(STATUS "Should return an error: ${CHECK_SELF_CRASH}")
endfunction()


function(check_pthread_setname_np)
    #message(STATUS CMAKE_REQUIRED_DEFINITIONS=${CMAKE_REQUIRED_DEFINITIONS})
    set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE=1)
    set(CMAKE_REQUIRED_LIBRARIES "-lpthread")
    check_symbol_exists(pthread_setname_np "pthread.h" HAS_PTHREAD_SETNAME_NP)
    #message("Checked presence of function pthread_setname_np: ${HAS_PTHREAD_SETNAME_NP}")
    if(NOT HAS_PTHREAD_SETNAME_NP)
        set(CHECK_PTHREAD_SETNAME_NP_SOURCE "
#define _GNU_SOURCE 1
#include <pthread.h>
int main(int argc, char** argv)
{
    pthread_setname_np(pthread_self(), \"self\")\;
    return 0\;
}")
        try_c_compile_silently(${CHECK_PTHREAD_SETNAME_NP_SOURCE} HAS_PTHREAD_SETNAME_NP)
        set(HAS_PTHREAD_SETNAME_NP ${HAS_PTHREAD_SETNAME_NP} PARENT_SCOPE)
    endif()

    StoreBooleanToCache(HAS_PTHREAD_SETNAME_NP "Checked presence of function pthread_setname_np" "pthread_setname_np available")
endfunction()

function(check_pthread_setaffinity_np)
    #message(STATUS CMAKE_REQUIRED_DEFINITIONS=${CMAKE_REQUIRED_DEFINITIONS})
    set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE=1)
    set(CMAKE_REQUIRED_LIBRARIES "-lpthread")
    check_symbol_exists(pthread_setaffinity_np "pthread.h" HAS_PTHREAD_SETAFFINITY_NP)
    #message("Checked presence of function pthread_setaffinity_np: ${HAS_PTHREAD_SETAFFINITY_NP}")
    if(NOT HAS_PTHREAD_SETAFFINITY_NP)
        set(CHECK_PTHREAD_SETAFFINITY_NP_SOURCE "
#define _GNU_SOURCE 1
#include <pthread.h>
int main(int argc, char** argv)
{
    pthread_setaffinity_np(pthread_self(), 0, 0)\; // does not need to run
    return 0\;
}")
        try_c_compile_silently(${CHECK_PTHREAD_SETAFFINITY_NP_SOURCE} HAS_PTHREAD_SETAFFINITY_NP)
        set(HAS_PTHREAD_SETAFFINITY_NP ${HAS_PTHREAD_SETAFFINITY_NP} PARENT_SCOPE)
    endif()
    StoreBooleanToCache(HAS_PTHREAD_SETAFFINITY_NP "Checked presence of function pthread_setaffinity_np" "pthread_setaffinity_np available")
endfunction()

function(check_pthread_spin_init)
    #message(STATUS CMAKE_REQUIRED_DEFINITIONS=${CMAKE_REQUIRED_DEFINITIONS})
    set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE=1)
    set(CMAKE_REQUIRED_LIBRARIES "-lpthread")
    check_symbol_exists(pthread_spin_init "pthread.h" HAS_PTHREAD_SPIN_INIT)
    #message("Checked presence of function pthread_spin_init: ${HAS_PTHREAD_SPIN_INIT}")
    if(NOT HAS_PTHREAD_SPIN_INIT)
        set(CHECK_PTHREAD_SPIN_INIT_SOURCE "
#define _GNU_SOURCE 1
#include <pthread.h>
int main(int argc, char** argv)
{
    pthread_spin_init(pthread_self(), \"self\")\;
    return 0\;
}")
        try_c_compile_silently(${CHECK_PTHREAD_SPIN_INIT_SOURCE} HAS_PTHREAD_SPIN_INIT)
        set(HAS_PTHREAD_SPIN_INIT ${HAS_PTHREAD_SPIN_INIT} PARENT_SCOPE)
        message("Checked presence of function pthread_spin_init more thoroughly: ${HAS_PTHREAD_SPIN_INIT}")
    endif()
    StoreBooleanToCache(HAS_PTHREAD_SPIN_INIT "Checked presence of function pthread_spin_init" "pthread_spin_init available")
endfunction()

function(check_mremap)
    set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE=1)
    check_symbol_exists(mremap "sys/mman.h" HAS_MREMAP)
    #message("Checked presence of function mremap: ${HAS_MREMAP}")
    if(NOT HAS_MREMAP)
        set(CHECK_MREMAP_SOURCE "
#define _GNU_SOURCE 1
#include <sys/mman.h>
int main(int argc, char** argv)
{
    mremap(0,0,0,0)\;
    return 0\;
}")
        try_c_compile_silently(${CHECK_MREMAP_SOURCE} HAS_MREMAP)
        set(HAS_MREMAP ${HAS_MREMAP} PARENT_SCOPE)
    endif()

    StoreBooleanToCache(HAS_MREMAP "Checked presence of function mremap" "mremap available")
endfunction()

function(check_timegm)
    set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE=1)
    check_symbol_exists(timegm "time.h" HAS_TIMEGM)
    #message("Checked presence of function timegm: ${HAS_TIMEGM}")
    if(NOT HAS_TIMEGM)
        set(CHECK_TIMEGM_SOURCE "
#define _GNU_SOURCE 1
#include <time.h>
int main(int argc, char** argv)
{
    struct tm t\;
    timegm(&t)\;
    return 0\;
}")
        try_c_compile_silently(${CHECK_TIMEGM_SOURCE} HAS_TIMEGM)
        set(HAS_TIMEGM ${HAS_TIMEGM} PARENT_SCOPE)
    endif()
    StoreBooleanToCache(HAS_TIMEGM "Checked presence of function timegm" "timegm available")
endfunction()

function(check_gettid)
    set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE=1)
    check_symbol_exists(gettid "sys/types.h" HAVE_GETTID)
    #message("Checked presence of function timegm: ${HAS_TIMEGM}")
    if(NOT HAVE_GETTID)
        set(CHECK_GETTID_SOURCE "
#define _GNU_SOURCE 1
#include <unistd.h>
#include <sys/types.h>
int main(int argc, char** argv)
{
    pid_t pid = gettid()\;
    return 0\;
}")
        try_c_compile_silently(${CHECK_GETTID_SOURCE} HAVE_GETTID)
        set(HAVE_GETTID ${HAVE_GETTID} PARENT_SCOPE)
    endif()
    StoreBooleanToCache(HAVE_GETTID "Checked presence of function gettid" "gettid available")
endfunction()

function(check_endianness)
    test_big_endian(BIG_ENDIAN_RESULT)

    if(BIG_ENDIAN_RESULT)
        message("Checked for endianness: big endian")
        set(HAS_BIG_ENDIAN 1 PARENT_SCOPE)
        set(HAS_LITTLE_ENDIAN 0 PARENT_SCOPE)
        set(HAS_BIG_ENDIAN ON CACHE BOOL "big endian")
        set(HAS_LITTLE_ENDIAN OFF CACHE BOOL "little endian")
    else()
        message("Checked for endianness: little endian")
        set(HAS_BIG_ENDIAN 0 PARENT_SCOPE)
        set(HAS_LITTLE_ENDIAN 1 PARENT_SCOPE)
        set(HAS_BIG_ENDIAN OFF CACHE BOOL "big endian")
        set(HAS_LITTLE_ENDIAN ON CACHE BOOL "little endian")
    endif()
endfunction()

function(set_has BASENAME)
    set(HAS_${BASENAME} ${BASENAME} PARENT_SCOPE)
endfunction()

function(set_have BASENAME)
    set(HAS_${BASENAME} ${BASENAME} PARENT_SCOPE)
endfunction()

macro(option_has BASENAME TEXT DEFAULT)
    option(${BASENAME} ${TEXT} ${DEFAULT})
    if(${BASENAME})
        set(HAS_${BASENAME} 1)
    else()
        set(HAS_${BASENAME} 0)
    endif()
endmacro()

macro(option_have BASENAME TEXT DEFAULT)
    option(${BASENAME} ${TEXT} ${DEFAULT})
    if(${BASENAME})
        set(HAVE_${BASENAME} 1)
    else()
        set(HAVE_${BASENAME} 0)
    endif()
endmacro()

macro(option_has_support BASENAME TEXT DEFAULT)
    option(${BASENAME} ${TEXT} ${DEFAULT})
    if(${BASENAME})
        set(HAS_${BASENAME}_SUPPORT 1)
    else()
        set(HAS_${BASENAME}_SUPPORT 0)
    endif()
endmacro()

macro(option_have_support BASENAME TEXT DEFAULT)
    option(${BASENAME} ${TEXT} ${DEFAULT})
    if(${BASENAME})
        set(HAVE_${BASENAME}_SUPPORT 1)
    else()
        set(HAVE_${BASENAME}_SUPPORT 0)
    endif()
endmacro()

macro(option_set BASENAME TEXT DEFAULT)
    option(${BASENAME} ${TEXT} ${DEFAULT})
    if(${BASENAME})
        set(${BASENAME} 1)
    else()
        set(${BASENAME} 0)
    endif()
endmacro()

macro(option_path BASENAME TEXT DEFAULT)
    set(${BASENAME} ${DEFAULT} CACHE PATH ${TEXT})
endmacro()

function(prefixes_configure_file SOURCE TARGET PREFIX)
    message("prefixes_configure_file ${SOURCE} into ${TARGET} with ${PREFIX}")
    FILE(STRINGS "${SOURCE}" SOURCE_CONTENT)
    FILE(WRITE "${TARGET}" "#pragma once\n// Generated file\n")
    foreach(SOURCE_LINE ${SOURCE_CONTENT})
        string(REGEX REPLACE "#define[ \t]+PACKAGE" "#define ${PREFIX}PACKAGE" TARGET_LINE ${SOURCE_LINE})

        string(REGEX REPLACE "#define[ \t]+VERSION" "#define ${PREFIX}VERSION" TARGET_LINE ${TARGET_LINE})

        string(REGEX REPLACE "#define[ \t]+HAS_" "#define ${PREFIX}HAS_" TARGET_LINE ${TARGET_LINE})
        string(REGEX REPLACE "[ \t]+ON$" " 1" TARGET_LINE ${TARGET_LINE})

        string(REGEX REPLACE "#if[ \t]+HAS_" "#if ${PREFIX}HAS_" TARGET_LINE ${TARGET_LINE})
        string(REGEX REPLACE "[ \t]+ON$" " 1" TARGET_LINE ${TARGET_LINE})

        string(REGEX REPLACE "#define[ \t]+HAVE_" "#define ${PREFIX}HAVE_" TARGET_LINE ${TARGET_LINE})
        string(REGEX REPLACE "[ \t]+ON$" " 1" TARGET_LINE ${TARGET_LINE})

        string(REGEX REPLACE "#if[ \t]+HAVE_" "#if ${PREFIX}HAVE_" TARGET_LINE ${TARGET_LINE})
        string(REGEX REPLACE "[ \t]+ON$" " 1" TARGET_LINE ${TARGET_LINE})

        string(REGEX REPLACE "^.*#undef[ \t]+HAS_([A-Za-z0-9_]+).*" "#define ${PREFIX}HAS_XXXMATCHXXX 0" TARGET_LINE ${TARGET_LINE})
        string(REPLACE "XXXMATCHXXX" "${CMAKE_MATCH_1}" TARGET_LINE ${TARGET_LINE})

        string(REGEX REPLACE "^.*#undef[ \t]+HAVE_([A-Za-z0-9_]+).*" "#define ${PREFIX}HAVE_XXXMATCHXXX 0" TARGET_LINE ${TARGET_LINE})
        string(REPLACE "XXXMATCHXXX" "${CMAKE_MATCH_1}" TARGET_LINE ${TARGET_LINE})

        file(APPEND "${TARGET}" "${TARGET_LINE}\n")
    endforeach()
endfunction()

function(buildinfo_file PATH)
    FILE(WRITE "${PATH}" "#pragma once\n// build info not supported with this build type\n#define BUILD_OPTIONS \"\"\n")
endfunction()

set(KV_SPACES_CONST "                                                                ")

set(KVMESSAGE_PREFIX "    ")
set(KVMESSAGE_KEYWIDTH 34)
set(KVMESSAGE_SEPARATOR ": ")

function(kvmessage KEY VALUE)
    string(APPEND KEY ${KV_SPACES_CONST})
    string(SUBSTRING ${KEY} 0 ${KVMESSAGE_KEYWIDTH} KEY)
    message(${KVMESSAGE_PREFIX} ${KEY} ${KVMESSAGE_SEPARATOR} ${VALUE})
endfunction()

set(KVSTATUS_PREFIX "")
set(KVSTATUS_KEYWIDTH 34)
set(KVSTATUS_SEPARATOR ": ")

function(kvstatus KEY VALUE)
    string(APPEND KEY ${KV_SPACES_CONST})
    string(SUBSTRING ${KEY} 0 ${KVSTATUS_KEYWIDTH} KEY)
    message(STATUS ${KVSTATUS_PREFIX} ${KEY} ${KVSTATUS_SEPARATOR} ${VALUE})
endfunction()

####################################################################################################
# If you are here, and something broke, check that you haven't given "-DPREFIX:PATH=XXXX" to cmake #
####################################################################################################

function(kvfatal KEY VALUE)
    string(APPEND KEY ${KV_SPACES_CONST})
    string(SUBSTRING ${KEY} 0 ${KVSTATUS_KEYWIDTH} KEY)
    message(FATAL_ERROR ${KVSTATUS_PREFIX} ${KEY} ${KVSTATUS_SEPARATOR} ${VALUE})
endfunction()

function(read_version DEFAULT_VALUE)
    #message("fetching version")
    set(VERSION_TEXT "")
    file(READ ${CMAKE_SOURCE_DIR}/VERSION VERSION_TEXT)
    string(STRIP ${VERSION_TEXT} VERSION_TEXT)
    string(LENGTH ${VERSION_TEXT} VERSION_TEXT_LENGTH)
    if(VERSION_TEXT_LENGTH EQUAL 0)
        set(VERSION_TEXT ${DEFAULT_VALUE} PARENT_SCOPE)
        #message("fetching version failed: ${VERSION_TEXT}")
    else()
        set(VERSION_TEXT ${VERSION_TEXT} PARENT_SCOPE)
        #message("fetching version succeeded: ${VERSION_TEXT}")
    endif()
endfunction()

function(check_gethostbyname)
    check_symbol_exists(gethostbyname "netdb.h" HAS_GETHOSTBYNAME)
    if(HAS_GETHOSTBYNAME)
        message("Checked presence of function gethostbyname: no additional library required")
        set(LINK_WITH_GETHOSTBYNAME_LIBRARY "")
    else()
        set(CMAKE_REQUIRED_LIBRARIES nsl)
        check_symbol_exists(gethostbyname "netdb.h" HAS_GETHOSTBYNAME)
        if(HAS_GETHOSTBYNAME)
            set(LINK_WITH_GETHOSTBYNAME_LIBRARY "-lnsl")
            message("Checked presence of function gethostbyname: nsl library required")
        else()
            message(FATAL_ERROR "check_gethostbyname: could not find function gethostbyname")
        endif()
    endif()
endfunction()

enable_testing()

# Gives an option for coverage

option_set(COVERAGE "Enables coverage" OFF)

if(${COVERAGE})
    kvmessage("CTEST_COVERAGE_COMMAND" "${CTEST_COVERAGE_COMMAND}")
    kvmessage("CTEST_COVERAGE_EXTRA_FLAGS" "${CTEST_COVERAGE_EXTRA_FLAGS}")
    kvmessage("COVERAGE_COMMAND" "${COVERAGE_COMMAND}")
    kvmessage("COVERAGE_EXTRA_FLAGS" "${COVERAGE_EXTRA_FLAGS}")
    if(CMAKE_C_COMPILER_ID MATCHES "GNU")
        message("GNU compiler coverage")
    elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
        message("LLVM compiler coverage")

        set(LLVM_COVERAGE_WRAPPER "${CMAKE_BINARY_DIR}/llvm-cov-gcov")
        if(NOT EXISTS ${LLVM_COVERAGE_WRAPPER})
            message("Creating ${LLVM_COVERAGE_WRAPPER}")
            file(WRITE  ${LLVM_COVERAGE_WRAPPER} "#!/bin/sh\n")
            file(APPEND ${LLVM_COVERAGE_WRAPPER} "/usr/bin/llvm-cov gcov $*\n")
            file(CHMOD ${LLVM_COVERAGE_WRAPPER} PERMISSIONS OWNER_EXECUTE OWNER_READ)
        else()
            message("Using ${LLVM_COVERAGE_WRAPPER}")
        endif()

        set(COVERAGE_COMMAND ${LLVM_COVERAGE_WRAPPER})
    else()
        message("No supported compiler coverage")
    endif()
endif()

macro(target_coverage)
    if(${COVERAGE})
        if(CMAKE_C_COMPILER_ID MATCHES "GNU")
            message("GNU compiler coverage")
            target_compile_options(${ARGV0} PRIVATE -g --coverage)
            target_link_options(${ARGV0} PUBLIC --coverage)
        elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
            message("LLVM compiler coverage")
            target_compile_options(${ARGV0} PRIVATE -g --coverage)
            target_link_options(${ARGV0} PUBLIC --coverage)
        else()
            message("unsupported compiler ${CMAKE_C_COMPILER_ID}: no coverage")
        endif()
    else()

    endif()
endmacro()

macro(target_coverage_test)
    if(${COVERAGE})
        if(CMAKE_C_COMPILER_ID MATCHES "GNU")
            message("GNU compiler coverage")
            target_link_options(${ARGV0} PUBLIC --coverage)
        elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
            message("LLVM compiler coverage")
            target_link_options(${ARGV0} PUBLIC --coverage)
        else()
            message("unsupported compiler ${CMAKE_C_COMPILER_ID}: no coverage")
        endif()
    else()

    endif()
endmacro()
