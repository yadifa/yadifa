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

include(${CMAKE_SOURCE_DIR}/cmake/CheckCHeaders.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/CheckCompilerFlags.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/EURidToolbox.cmake)

read_version("3.0.3")

project(yadifa VERSION ${VERSION_TEXT} LANGUAGES C)

kvstatus("YADIFA version" "${VERSION_TEXT}")

if(WIN32)
set(BUILD_SHARED_LIBS OFF)
set(BUILD_STATIC_LIBS ON)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /STACK:8388608")
add_definitions(-DMICROSOFT_WINDOWS_WINBASE_H_DEFINE_INTERLOCKED_CPLUSPLUS_OVERLOADS=0)
endif()

set(IGNORE_GNU_INSTALL_DIRS false CACHE BOOL "Ignore the rules of setting-up the installation paths")

if(NOT IGNORE_GNU_INSTALL_DIRS)
include(GNUInstallDirs)
endif()

set(CMAKE_C_STANDARD 11)
#set(CMAKE_C_STANDARD 23)

check_atomic_load()

include(${CMAKE_SOURCE_DIR}/cmake/FindOpenSSL.cmake)

set(CMAKE_VERBOSE_MAKEFILE ON)

check_self()
check_headers_files()
check_sockaddr_sin_len_field()
check_sockaddr_sin6_len_field()
check_c_compiler_flags()
check_memalign_issues()
if(UNIX)
check_gnu_source()
check_pthread_setname_np()
check_pthread_setaffinity_np()
check_pthread_spin_init()
check_gettid()
endif()
check_mremap()
check_timegm()
check_endianness()

# If we relase the cmake build, we cannot force the prefix to one of our owns.
#
#
# you must clear CMakeCache if you want to change this

#if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
#    set(CMAKE_INSTALL_PREFIX
#        "/registry/${PROJECT_NAME}-${PROJECT_VERSION}" CACHE PATH "${PROJECT_NAME} install prefix" FORCE
#    )
#endif()

################################################################################
#
#	PARAMETERS THAT CAN BE CHANGED
#
################################################################################

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

include(CTest) # must be included after EURidToolbox.cmake

set(YATEST_INCLUDE_DIRECTORY "${CMAKE_SOURCE_DIR}/tests")

# settings from subdirectories - START

set(PACKAGE "yadifa")
set(PACKAGE_VERSION "3.0.3")
set(VERSION "3.0.3")
set(PACKAGE_STRING "${PACKAGE} ${PACKAGE_VERSION}")
set(PACKAGE_BUGREPORT "bugreport@yadifa.eu")

set(CPACK_SOURCE_PACKAGE_FILE_NAME ${PACKAGE}-${PACKAGE_VERSION})
set(CPACK_SOURCE_IGNORE_FILES \.git.*;\.idea)
set(CPACK_SOURCE_GENERATOR "TGZ")

# please do not change these options
option_has(FILEPOOL_CACHE "DEVS: enable the user-level cache for the file pools" OFF)
option_has(DNSQ "DEVS: enable the code related to that project" OFF)
option_has_support(DROPALL "DEVS: Enable this test feature" OFF)
option_has_support(DYNCONF "DEVS: enable dynamic configuration" OFF)
option_has(EXPERIMENTAL "DEVS: Enable various experimental code" OFF)
option_has_support(MIRROR "DEVS: Enable this test feature" OFF)
option_has_support(NSEC "DEVS: enable NSEC support" ON)
option_has_support(NSEC3 "DEVS: enable NSEC3 support" ON)
option_has(RDTSC "DEVS: enable RDTSC usage for profiling" OFF)

set(NETWORK_INTERFACES_MAX 256)

mark_as_advanced(
        DNSQ
        DROPALL
        DYNCONF
        EXPERIMENTAL
        MIRROR
        NSEC
        NSEC3
        RDTSC
        )

option_has(DEBUG "Enable #if DEBUG code" OFF)

option_has_support(PRIMARY "Enable DNS primary code" ON)
option_has_support(DNSSEC "Enable DNSSEC support" ON)
option_has(CTRL "Enable remote control" ON)
option_has_support(NSID "Enable NSID support" ON)

option_has_support(ACL "Enable ACL support" ON)
option_has_support(RRL "Enable RRL support" ON)
option_has_support(TSIG "Enable TSIG support" ON)
option_has_support(DYNUPDATE "Enable dynamic update support" ON)
option_has_support(RRSIG_MANAGEMENT "Enable RRSIG verification and generation for zones" ON)
option_has_support(ZALLOC "Enable internal memory allocation support" ON)
option_has_support(ZALLOC_STATISTICS "Enable internal memory allocation statistics" OFF)
option_has_support(ZALLOC_DEBUG "Enable internal memory allocation debugging" OFF)
option_has_support(MMAP_DEBUG "Enable mmap debugging" OFF)
option_has_support(MALLOC_DEBUG "Enable heap memory allocation debugging" OFF)
option_has_support(LIBC_MALLOC_DEBUG "Enable libc malloc monitors" OFF)
option_has_support(BFD_DEBUG "Enable bfd debuging (symbol tables)" OFF)
option_has(QUERY_US_DEBUG "Measure query time in us" OFF)
option_has_support(MUTEX_DEBUG "Enable mutex debugging (insanely heavy)" OFF)
option_has_support(LOCK_DEBUG "Enable zone lock debugging (insanely heavy)" OFF)
option_has_support(TRACK_ZONES_DEBUG "Enable tracking of the instanciated zones for detecting potential leaks. Relatively cheap with a small (<100) amount of zones." OFF)
option_has(LOG_THREAD_ID "Enable a new column in the logs with an alphanumeric id consistent in the lowest 32 bits of the thread id sending the line" OFF)
option_has(LOG_THREAD_TAG "Enable a column with a 8 letters human-readable tag identifying a thread in each log line" ON)
option_has(LOG_PID "Enable a column with the pid in each line of log" ON)
option_has(FULL_ASCII7 "Enable acceptance of ASCII7 characters in DNS names (not recommended)" OFF)
option_has_support(ECDSA "Enable Elliptic Curve (ECDSA) support" ON)
if(NOT CMAKE_HOST_SYSTEM_NAME MATCHES "OpenBSD")
    option_has_support(EDDSA "Enable Edwards Curve (EDDSA) support" ON)
endif()
option(OPENSSL_DIRECTORY "Sets the installation directory of OPENSSL (default: autodetects)" "")

option_has_support(NON_AA_AXFR "Enable lenient acceptance of AXFR answer from primary that do not have AA bit set (Microsoft DNS)" OFF)
option_has(SYSTEMD_RESOLVED_AVOIDANCE "If set, yadifad will set do-not-listen to \"127.0.0.53 port 53\" by default (otherwise the list is empty)" OFF)
option_has(EVENT_DYNAMIC_MODULE "Enable Adds support for dynamically loaded module that gets events from yadifad and is allowed to fetch some information from the daemon (EXPERIMENTAL)" OFF)
option_has(TCL "Enable TCL support" OFF)
option_has(BUILD_TIMESTAMP "Set to ON to disable the build timestamp" OFF)
option_has(TCP_MANAGER "If set, the TCP manager will be enabled and used to handle TCP quotas" ON) # do NOT turn off
option_has(LOGGING_DISABLED "If set, the logging macros are no-operations. This is useful for coverage." OFF)
option_has_support(DNS_OVER_TLS "If set, yadifad will support DNS over TLS (experimental)" ON)
option_has_support(OQS "If set, yadifad will support experimental post-quantum-safe algorithms" OFF)

option_path(OPENSSL_DIRECTORY "Set to the path of openssl" "")

option_has(GCC_HARDENED "Adds build options for GCC" OFF)

# some 'has_XXX' for YADIFA binary

#option_has(YADIFA              "controler for 'yadifad'"           ON) # HAS_CTRL is already defined
option_has(DNSSEC_TOOL         "replacement of BIND dnssec-tools"  ON)
option_has(DNS_CONFIG_CHECKER  "checks YADIFA config"             OFF)
option_has(YADIG               "replacement of BIND dig"           ON)

# still experimental stuff
# this is stuff needed when we have a WHOIS plugin
option_has(WHOIS               "for WHOIS plugin"                 OFF)
# this is stuff needed when we have a DNSQ plugin
option_has(DNSQ                "for DNSQ plugin"                  OFF)

option_set(TOOLS "Enable the tools" ON)

option_set(BUILD_SHARED_LIBS "Build shared libraries" ON)
option_set(BUILD_STATIC_LIBS "Build static libraries" OFF)
option_set(WITH_COVERAGE "Build with -fprofile-arcs and -ftest-coverage" OFF)

option_set(TIME64 "Build with _TIME_BITS=64" OFF)

kvstatus("OQS support" "${HAS_OQS_SUPPORT}")
if(${HAS_OQS_SUPPORT})
    include(${CMAKE_SOURCE_DIR}/cmake/FindOQS.cmake)
endif()

kvstatus("shared-build" "${BUILD_SHARED_LIBS}")
kvstatus("static-build" "${BUILD_STATIC_LIBS}")

#
# settings from subdirectories - END

# libraries can be compiled STATIC or SHARED

set(IS_DARWIN_OS                                 0)


if(NOT DEBUG)
    set(COMPILE_FOR_RELEASE                      1)
else()
    # you need to choose one of them, you can not switch on all of them
    # at the same time
    set(COMPILE_FOR_DEBUG                        1)
    set(COMPILE_FOR_PROFILE                      0)
endif()

set(CMAKE_HOST_UNIX                              1)

################################################################################
#
#       COLORIZE
#
################################################################################

if(NOT WIN32)
    message(STATUS "COLORIZE OUTPUT")
    string(ASCII 27 Esc)
    set(ColorReset  "${Esc}[m")
    set(ColorBold   "${Esc}[1m")
    set(Red         "${Esc}[31m")
    set(Green       "${Esc}[32m")
    set(Yellow      "${Esc}[33m")
    set(Blue        "${Esc}[34m")
    set(Magenta     "${Esc}[35m")
    set(Cyan        "${Esc}[36m")
    set(White       "${Esc}[37m")
    set(BoldRed     "${Esc}[1;31m")
    set(BoldGreen   "${Esc}[1;32m")
    set(BoldYellow  "${Esc}[1;33m")
    set(BoldBlue    "${Esc}[1;34m")
    set(BoldMagenta "${Esc}[1;35m")
    set(BoldCyan    "${Esc}[1;36m")
    set(BoldWhite   "${Esc}[1;37m")
endif()

###############################################################################
###############################################################################
##                                                                           ##
## DO NOT USE "PREFIX" AS FOR AUTOCONF/AUTOMAKE                              ##
##                                                                           ##
## DON'T : option(PREFIX "the installation prefix" ${CMAKE_INSTALL_PREFIX})  ##
##                                                                           ##
###############################################################################
###############################################################################

# Update back the options for GNUInstallDirs

if(IGNORE_GNU_INSTALL_DIRS)
set(CMAKE_INSTALL_FULL_SYSCONFDIR "${CMAKE_INSTALL_PREFIX}/etc" CACHE PATH "<prefix>/etc")
set(CMAKE_INSTALL_FULL_BINDIR "${CMAKE_INSTALL_PREFIX}/bin"  CACHE PATH "<prefix>/bin")
set(CMAKE_INSTALL_FULL_SBINDIR "${CMAKE_INSTALL_PREFIX}/sbin"  CACHE PATH "<prefix>/sbin")
set(CMAKE_INSTALL_FULL_LIBEXEC "${CMAKE_INSTALL_PREFIX}/libexec"  CACHE PATH "<prefix>/libexec")
set(CMAKE_INSTALL_FULL_LIBDIR "${CMAKE_INSTALL_PREFIX}/lib"  CACHE PATH "<prefix>/lib")
set(CMAKE_INSTALL_FULL_INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include"  CACHE PATH "<prefix>/include")
set(CMAKE_INSTALL_FULL_LOCALSTATEDIR "${CMAKE_INSTALL_PREFIX}/var"  CACHE PATH "<prefix>/var")
set(CMAKE_INSTALL_FULL_RUNSTATEDIR "${CMAKE_INSTALL_PREFIX}/var/run"  CACHE PATH "<prefix>/var/run")
set(CMAKE_INSTALL_FULL_DATAROOTDIR "${CMAKE_INSTALL_PREFIX}/share"  CACHE PATH "<prefix>/share")
set(CMAKE_INSTALL_FULL_DATADIR "${CMAKE_INSTALL_FULL_DATAROOTDIR}" CACHE PATH "<datarootdir>")
set(CMAKE_INSTALL_FULL_LOCALEDIR "${CMAKE_INSTALL_PREFIX}/share/locale" CACHE PATH "<prefix>/share/locale")
set(CMAKE_INSTALL_FULL_LOGDIR "${CMAKE_INSTALL_PREFIX}/var/log" CACHE PATH "<prefix>/var/log")
set(CMAKE_INSTALL_FULL_MANDIR "${CMAKE_INSTALL_FULL_DATAROOTDIR}/man" CACHE PATH "<datarootdir>/man")
set(CMAKE_INSTALL_FULL_DOCDIR "${CMAKE_INSTALL_FULL_DATAROOTDIR}/doc/yadifa" CACHE PATH "<datarootdir>/doc/yadifa")
else()
endif()

################################################################################
#
#       DEFINITIONS
#
################################################################################

# common defines
set(ENV{PREFIX} ${CMAKE_INSTALL_PREFIX})
add_definitions(-DPREFIX="${CMAKE_INSTALL_PREFIX}")
# Conflicts with WIN32
#set(DATADIR "${PREFIX}/share/" CACHE PATH "read-only architecture-independent data")
add_definitions(-DSYSCONFDIR="${CMAKE_INSTALL_FULL_SYSCONFDIR}")
add_definitions(-DLOCALSTATEDIR="${CMAKE_INSTALL_FULL_LOCALSTATEDIR}")
add_definitions(-DRUNSTATEDIR="${CMAKE_INSTALL_FULL_RUNSTATEDIR}")
add_definitions(-DDATAROOTDIR="${CMAKE_INSTALL_FULL_DATAROOTDIR}")
add_definitions(-DDATADIR="${CMAKE_INSTALL_FULL_DATADIR}")
add_definitions(-DLOCALEDIR="${CMAKE_INSTALL_FULL_LOCALEDIR}")
add_definitions(-DLOGDIR="${CMAKE_INSTALL_FULL_LOGDIR}")

set(TCLDIR "${PREFIX}/tcl/" CACHE PATH "...")
add_definitions(-DTCLDIR="${TCLDIR}")

kvstatus("PREFIX" ${CMAKE_INSTALL_PREFIX})
kvstatus("SYSCONFDIR" "${CMAKE_INSTALL_FULL_SYSCONFDIR}")
kvstatus("LOCALSTATEDIR" "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}")
kvstatus("RUNSTATEDIR" "${CMAKE_INSTALL_FULL_RUNSTATEDIR}")
kvstatus("DATAROOTDIR" "${CMAKE_INSTALL_FULL_DATAROOTDIR}")
kvstatus("DATADIR" "${CMAKE_INSTALL_FULL_DATADIR}")
kvstatus("LOCALEDIR" "${CMAKE_INSTALL_FULL_LOCALEDIR}")
kvstatus("LOGDIR" "${CMAKE_INSTALL_FULL_LOGDIR}")

add_compile_options(-fPIC)

if(${GCC_HARDENED})
    message("Hardened build")
    add_compile_options(-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -fstack-protector-strong -fstack-clash-protection -Wformat -Werror=format-security -fcf-protection -Wall -Wextra)
endif()

################################################################################
#
#       CMake C flags
#
################################################################################

if(COMPILE_FOR_RELEASE)
    kvstatus("compilations for" "release")

    add_definitions(-DCMR=1)
    add_definitions(-DNDEBUG=1)
else()
    if(COMPILE_FOR_DEBUG)
        kvstatus("compilations for" "debug")

        add_definitions(-DCMD=1)
        add_definitions(-DDEBUG=1)
    else()
        if(COMPILE_FOR_PROFILE)
            kvstatus("compilations for" "profiling")

            add_definitions(-DCMP=1)
            add_definitions(-DNDEBUG=1)
        endif()
    endif()
endif()

if(UNIX)
message(STATUS "UNIX build")

check_c_compiler_flag(-Wstringop-truncation C_HAS_WSTRINGOP_TRUNCATION)
check_c_compiler_flag(-Wno-unknown-pragmas C_HAS_WNO_UNKNOWN_PRAGMAS)
check_c_compiler_flag(-Werror=missing-field-initializers C_HAS_WERROR_MISSING_FIELD_INITIALIZERS)

add_compile_options(-D_FILE_OFFSET_BITS=64)
add_compile_options(-D_THREAD_SAFE)
add_compile_options(-Wall)
add_compile_options(-Wextra)
add_compile_options(-Wno-strict-prototypes)
add_compile_options(-Wno-address-of-packed-member)
add_compile_options(-fno-strict-aliasing)
if(TIME64)
add_compile_options(-D_TIME_BITS=64)
endif()

if(WITH_COVERAGE)
kvstatus("coverage" "enabled")
add_compile_options(-fprofile-arcs -ftest-coverage -fprofile-update=atomic)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    add_link_options(-lgcov)
endif()
add_link_options(--coverage)
else()
kvstatus("coverage" "disabled")
endif()

if(HAS_BFD_DEBUG_SUPPORT)
add_compile_options(-rdynamic)
endif()

if(C_HAS_WERROR_MISSING_FIELD_INITIALIZER)
add_compile_options(-Werror=missing-field-initializers)
endif()

if(C_HAS_WSTRINGOP_TRUNCATION)
add_compile_options(-Wstringop-truncation)
endif()

if(C_HAS_WNO_UNKNOWN_PRAGMAS)
add_compile_options(-Wno-unknown-pragmas)
endif()

add_compile_options(-fno-ident)
add_compile_options(-mtune=native)

elseif(WIN32)
message(STATUS "WIN32 build")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_CRT_NONSTDC_NO_DEPRECATE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG=0")
include_directories("${CMAKE_SOURCE_DIR}/platforms/win32/include")
endif()

if(APPLE)
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__APPLE_USE_RFC_2292=1")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__APPLE_USE_RFC_3542=1")
endif()

if(UNIX)
set(TMP_CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
check_symbol_exists(sendmmsg sys/socket.h HAVE_SENDMMSG)
set(CMAKE_C_FLAGS ${TMP_CMAKE_C_FLAGS})

if(CMAKE_HOST_SYSTEM_NAME MATCHES "Darwin")
    message(STATUS "no -lrt")
elseif(CMAKE_HOST_SYSTEM_NAME MATCHES "OpenBSD")
    message(STATUS "no -lrt")
else()
    #set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lrt")
endif()
elseif(WIN32)
endif()

################################################################################
#
#       CMake linker flags
#
################################################################################

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,stack-size=8388608")


#message\(STATUS\s+\"\s+([A-Za-z0-9-_ ]+[A-Za-z0-9-_])\s+:\s+(.*)"\)

#if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
#   # using Clang
#   kvstatus("compiler" "${CMAKE_HOST_SYSTEM_NAME}")
#else()
#   # using GCC
#else()
#   # using Intel C++
#else()
#   # using Visual Studio C++
#endif()

kvstatus("compiler used" "${CMAKE_C_COMPILER_ID}")

configure_file(cmake/config.h.cmake.in config.h)

message(STATUS "summary config.h written")

################################################################################
#
#       FUNCTIONS
#
################################################################################

# will add another CMakeLists.txt file
if(APPLE)
    set(CMAKE_MACOSX_RPATH 1)
endif()

set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib" ".")

################################################################################
#
#       BUILD
#
################################################################################

kvstatus("start making" "${PROJECT_NAME} project\n")

# add cmake files of libraries
add_subdirectory(lib/dnscore)
add_subdirectory(lib/dnsdb)
add_subdirectory(lib/dnslg)
add_subdirectory(lib/glibchooks)

if(HAS_TCL)
    #add_definitions(-DHAS_TCL)
    add_subdirectory(lib/dnstcl)
endif()

# add cmake files of binaries
add_subdirectory(sbin/yadifad)
add_subdirectory(bin/yadifa)
add_subdirectory(sbin/yakeyrolld)

# add etc directories with its files
add_subdirectory(etc)
add_subdirectory(doc)

add_subdirectory(tests)

add_subdirectory(var)

file(COPY ${CMAKE_SOURCE_DIR}/yadifa.supp DESTINATION ${CMAKE_BINARY_DIR}/valgrind)

# done
message(STATUS "making ${PROJECT_NAME} project done\n")

include(CPack)
