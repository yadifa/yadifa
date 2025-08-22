dnl ----------------------------------------------------------------------------
dnl
dnl Copyright (c) 2011-2025, EURid vzw. All rights reserved.
dnl The YADIFA TM software product is provided under the BSD 3-clause license:
dnl
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted provided that the following conditions
dnl are met:
dnl
dnl        * Redistributions of source code must retain the above copyright
dnl          notice, this list of conditions and the following disclaimer.
dnl        * Redistributions in binary form must reproduce the above copyright
dnl          notice, this list of conditions and the following disclaimer in the
dnl          documentation and/or other materials provided with the distribution.
dnl        * Neither the name of EURid nor the names of its contributors may be
dnl          used to endorse or promote products derived from this software
dnl          without specific prior written permission.
dnl
dnl THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
dnl AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
dnl IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
dnl ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
dnl LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
dnl CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
dnl SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
dnl INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
dnl CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
dnl ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
dnl POSSIBILITY OF SUCH DAMAGE.
dnl
dnl ----------------------------------------------------------------------------

configure_base_path="$0/"

dnl Do NOT change this block of comments
dnl ====================================
dnl YADIFA VERSION 2.7.0 DATE 2024-05-14
dnl ====================================

AC_PREREQ([2.69])
AC_REVISION([$Revision$])
define(YADIFA_VERSION, [m4_esyscmd(printf "%s-%s" $(cat "${configure_base_path}VERSION") 11709)])

AC_INIT([yadifa],YADIFA_VERSION,[info@yadifa.eu])

echo
echo
echo "YADIFA BUNDLE START"
echo "-------------------"
echo
echo $0

AC_CANONICAL_TARGET

m4_include([m4/eurid.m4])
m4_include([m4/yadifa.m4])

AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror tar-pax])

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_MACRO_DIR([m4])

AM_PROG_AR

# automake version < 1.14
# AM_PROG_CC_C_O

LT_INIT([disable-shared])

AC_DARWIN_LIBTOOL
dnl obsolete: AC_PROG_LIBTOOL

AC_DEFUN([SYSCONF], [/$prefix/PACKAGE/PACKAGE.conf])

AC_CANONICAL_BUILD

dnl Checks for libraries.

AC_CHECK_LIB([c], [printf])
AC_SEARCH_LIBS([pthread_create],[pthread],,[exit 1])
AC_SEARCH_LIBS([clock_gettime],[rt],,[exit 1])

dnl Checks for header files.

dnl obsolete: AC_HEADER_STDC

AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h stdio.h string.h sys/time.h syslog.h unistd.h stdatomic.h])

# Check for Darwin or Linux
AC_CHECK_HEADERS([linux/limits.h sys/syslimits.h i386/limits.h ppc/limits.h])

# Check for Darwin or Linux
AC_CHECK_HEADERS([sys/types.h i386/types.h])

AC_CHECK_HEADERS([sys/socket.h])

dnl Checks for typedefs, structures, and compiler characteristics.

AC_C_CONST
AC_C_BIGENDIAN
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_TM

dnl AC_PROG_RANLIB

AC_CHECK_TYPES(uint8_t)
AC_CHECK_TYPES(int8_t) 
AC_CHECK_TYPES(uint16_t)
AC_CHECK_TYPES(int16_t) 
AC_CHECK_TYPES(uint32_t)
AC_CHECK_TYPES(int32_t) 
AC_CHECK_TYPES(uint64_t)
AC_CHECK_TYPES(int64_t) 
AC_CHECK_TYPES(long long)
AC_CHECK_TYPES(u_char)


AC_CHECK_FUNCS([bzero memset select socket atexit clock_gettime dup2 fdatasync ftruncate getcwd gethostname getpagesize gettimeofday inet_ntoa localtime_r memchr memmove memset mkdir mkfifo munmap select socket strcasecmp strchr strdup strerror strncasecmp strrchr strtol timegm])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADER_STDBOOL
AC_CHECK_TYPES([ptrdiff_t])
AC_C_INLINE
AC_C_RESTRICT
AC_FUNC_CHOWN
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_PROG_CXX
AC_STRUCT_TIMEZONE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_OFF_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_FUNC_SELECT_ARGTYPES
dnl obsolete: AC_TYPE_SIGNAL
AC_FUNC_STAT

AC_SYS_LARGEFILE

AC_COMPILER_CHECK
AC_PTHREAD_SPINLOCK_CHECK
AC_PTHREAD_SETNAME_NP_CHECK
AC_PTHREAD_SETAFFINITY_NP_CHECK
AC_GETTID_CHECK
AC_TIMEGM_CHECK
AC_MREMAP_CHECK
AC_ATOMIC_LOAD_CHECK

echo "mmsg results:"
echo "have_sendmmsg='$have_sendmmsg'"
echo "have_recvmmsg='$have_recvmmsg'"
echo "-------"

AC_CHECK_FUNC(sendmmsg, [
    have_sendmmsg=true
    AC_DEFINE_UNQUOTED([HAVE_SENDMMSG], [1], [Has sendmmsg system call])
    ], [
    have_sendmmsg=false
    AC_DEFINE_UNQUOTED([HAVE_SENDMMSG], [0], [Has sendmmsg system call])
    ])
AC_CHECK_FUNC(recvmmsg, [
    have_recvmmsg=true
    AC_DEFINE_UNQUOTED([HAVE_RECVMMSG], [1], [Has recvmmsg system call])
    ], [
    have_recvmmsg=false
    AC_DEFINE_UNQUOTED([HAVE_RECVMMSG], [0], [Has recvmmsg system call])
    ])


AM_CONDITIONAL(HAVE_SENDMMSG, [test x$have_sendmmsg = xtrue])
AM_CONDITIONAL(HAVE_RECVMMSG, [test x$have_recvmmsg = xtrue])
AC_SUBST(HAVE_SENDMMSG)
AC_SUBST(HAVE_RECVMMSG)

AC_YADIFA_ENABLE_SSL
AC_YADIFA_ADD_SSL
AC_YADIFA_FEATURES
AC_YADIFA_ADD_LIBS
AC_CHECK_LTO
AC_YADIFA_FEATURES

AC_EURID_SUMMARY

AC_CONFIG_FILES([
Makefile
etc/Makefile
doc/Makefile
var/Makefile

lib/dnscore/Makefile
lib/dnsdb/Makefile
lib/dnslg/Makefile

sbin/yadifad/Makefile

])

AC_HAS_WITHOUT(tests, TESTS, [various internal test programs],,
[
AC_CONFIG_FILES([
tests/circular-file-test/Makefile
tests/cjf-scan/Makefile
tests/cmdline-test/Makefile
tests/collection-test/Makefile
tests/daemonised-logger-test/Makefile
tests/dns-message-test/Makefile
tests/dnssec-test/Makefile
tests/dsfromkey-test/Makefile
tests/ethbenchprobe/Makefile
tests/file-test/Makefile
tests/freebsd12-test/Makefile
tests/hmac-test/Makefile
tests/ipc-test/Makefile
tests/journal-fusion/Makefile
tests/journal-from-ixfr/Makefile
tests/journal-speed-test/Makefile
tests/keygen-test/Makefile
tests/limiter-test/Makefile
tests/message-test/Makefile
tests/network-interfaces-forall-test/Makefile
tests/notify-test/Makefile
tests/nsec3-answer/Makefile
tests/nsec3-hash/Makefile
tests/pid-file-test/Makefile
tests/protocol-test/Makefile
tests/query-hammer-test/Makefile
tests/rndc-test/Makefile
tests/rrsig-test/Makefile
tests/shared-circular-buffer-test/Makefile
tests/shared-heap-test/Makefile
tests/simple-http-server-test/Makefile
tests/stream-test/Makefile
tests/threaded-queue/Makefile
tests/udp-echo-test/Makefile
tests/update-test/Makefile
tests/zone-save-test/Makefile
])
],[])

AC_CONFIG_FILES([
    bin/yadifa/Makefile
    ])

AC_CONFIG_FILES([
    sbin/yakeyrolld/Makefile
    ])

AC_HAS_WITHOUT(tools, TOOLS, [provided DNS-related tools],,,,)

AC_OUTPUT

dnl AC_YADIFA_SUMMARY

make features

echo
echo
echo "YADIFA BUNDLE DONE"
echo "------------------"
echo
echo

