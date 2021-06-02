dnl ############################################################################
dnl
dnl Copyright (c) 2011-2021, EURid vzw. All rights reserved.
dnl The YADIFA TM software product is provided under the BSD 3-clause license:
dnl
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted provided that the following conditions
dnl are met:
dnl
dnl        * Redistributions of source code must retain the above copyright
dnl          notice, this list of conditions and the following disclaimer.
dnl        * Redistributions in binary form must reproduce the above copyright
dnl          notice, this list of conditions and the following disclaimer in
dnl          the documentation and/or other materials provided with the
dnl          distribution.
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
dnl CONTRACT, STRICT LIABILITY,OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
dnl ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
dnl POSSIBILITY OF SUCH DAMAGE.
dnl
dnl ############################################################################        
        
configure_base_path="$0/"

AC_PREREQ(2.61)
AC_REVISION([$Revision: 10135 $])
AC_INIT([yadifa],m4_esyscmd(
    [
        svn info 2> /dev/null |
        grep 'Last Changed Rev: ' |
        sed -re 's/.*: (.*)/Revision: \1 $/' -e 's/^/$/' >> revision.txt ;
        echo $(cat "${configure_base_path}VERSION")-$(grep -r \$Revision: revision.txt configure.ac Makefile.am sbin/* lib/*/* bin/* doc/* etc/* |
        sed -e 's/^.*\$Revision: *//' -e 's/\$.*//' -e 's/ *//' |
        sort -n |
        /usr/bin/tail -1 |
        tr -d '\n') |
        tr -d '\n'
    ]),[info@yadifa.eu])

echo
echo
echo "YADIFA BUNDLE START"
echo "-------------------"
echo
echo $0


m4_include([m4/eurid.m4])
m4_include([m4/yadifa.m4])

AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror tar-pax])

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_MACRO_DIR([m4])

AM_PROG_AR

# automake version < 1.14
AM_PROG_CC_C_O

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

AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h sys/time.h syslog.h unistd.h stdatomic.h])

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
test/circular-file-test/Makefile
test/cjf-scan/Makefile
test/cmdline-test/Makefile
test/collection-test/Makefile
test/daemonised-logger-test/Makefile
test/dnskey-test/Makefile
test/dnsname-test/Makefile
test/dnssec-test/Makefile
test/dnsserver-test/Makefile
test/dsfromkey-test/Makefile
test/filepool-test/Makefile
test/file-test/Makefile
test/freebsd12-test/Makefile
test/ipc-test/Makefile
test/journal-fusion/Makefile
test/journal-from-ixfr/Makefile
test/journal-speed-test/Makefile
test/keygen-test/Makefile
test/limiter-test/Makefile
test/logger-test/Makefile
test/message-test/Makefile
test/mutex-test/Makefile
test/notify-test/Makefile
test/network-interfaces-forall-test/Makefile
test/nsec3-answer/Makefile
test/nsec3-hash/Makefile
test/openssl111a-ecdsa-test/Makefile
test/openssl111a-eddsa-test/Makefile
test/parser-test/Makefile
test/protocol-test/Makefile
test/query-hammer-test/Makefile
test/rrsig-test/Makefile
test/shared-circular-buffer-test/Makefile
test/shared-heap-test/Makefile
test/simple-http-server-test/Makefile
test/skeleton/Makefile
test/stream-test/Makefile
test/threaded-queue/Makefile
test/update-test/Makefile
test/xfr/Makefile
test/zone-save-test/Makefile
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

