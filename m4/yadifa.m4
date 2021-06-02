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
        
AC_DEFUN([AC_CHECK_ENABLE_RRL], [

AC_HAS_DISABLE(rrl,RRL_SUPPORT,[DNS Response Rate Limiter])
 
])

dnl SSL DNSCORE DNSDB (all defaulted to FALSE)

requires_tcl=0
requires_ssl=0
requires_dnscore=0
requires_dnsdb=0
requires_dnslg=0
requires_dnstcl=0

AC_DEFUN([AC_YADIFA_ENABLE_TCL], [
	requires_tcl=1
])

AC_DEFUN([AC_YADIFA_ENABLE_SSL], [
	requires_ssl=1
])

AC_DEFUN([AC_YADIFA_ENABLE_DNSCORE], [
	requires_dnscore=1
])

AC_DEFUN([AC_YADIFA_ENABLE_DNSDB], [
	requires_dnsdb=1
    requires_dnscore=1
])

AC_DEFUN([AC_YADIFA_ENABLE_DNSLG], [
	requires_dnslg=1
	requires_dnscore=1
])

AC_DEFUN([AC_YADIFA_ENABLE_DNSTCL], [
	requires_dnstcl=1
	requires_dnsdb=1
	requires_dnslg=1
	requires_dnscore=1
])

AC_DEFUN([AC_YADIFA_ADD_SSL], [
    SSLDEPS=""
    echo "Finding the SSL dependencies"
    AC_SEARCH_LIBS([deflate],[z])

    echo "SSLDEPS=${SSLDEPS}"

	AC_MSG_CHECKING(if SSL is available)

    ac_check_lib_ssl=0

    AC_ARG_WITH(openssl_lib, AS_HELP_STRING([--with-openssl-lib=DIR], [the openssl library from directory DIR]),
        [
            AC_MSG_RESULT([yes])
            LDFLAGS="-L$with_openssl_lib $SSLDEPS $LDFLAGS"
			echo "LDFLAGS=${LDFLAGS}"
            ac_check_lib_ssl=1
        ])

    AC_ARG_WITH(openssl_include, AS_HELP_STRING([--with-openssl-include=DIR], [the openssl headers from directory DIR]),
        [
            AC_MSG_RESULT([yes])
            CFLAGS="-I$with_openssl_include $CFLAGS $CFLAGS3264"
			echo "CFLAGS=${LDFLAGS}"
            ac_check_lib_ssl=1
        ])


	AC_ARG_WITH(openssl, AS_HELP_STRING([--with-openssl=DIR], [the openssl from directory DIR]),
		[
			echo "yes"

			OPENSSL="${withval}"
			CFLAGS="-I$with_openssl/include $CFLAGS $CFLAGS3264"
			LDFLAGS="-L$with_openssl/lib $SSLDEPS $LDFLAGS"
			echo "CFLAGS=$CFLAGS"
			echo "LDFLAGS=$LDFLAGS"
            ac_check_lib_ssl=1
		],
		[
			echo "no"
			CFLAGS="$CFLAGS $CFLAGS3264"
            LDFLAGS="$SSLDEPS $LDFLAGS"
			echo "CFLAGS=${CFLAGS}"
			echo "LDFLAGS=${LDFLAGS}"
            ac_check_lib_ssl=1
		])

    if [[ $ac_check_lib_ssl -eq 1 ]]
    then
dnl    	AC_CHECK_LIB([crypto], [RSA_new],,,[$SSLDEPS])
dnl		AC_CHECK_LIB([ssl], [SSL_library_init],,[exit],[$SSLDEPS])
        AC_SEARCH_LIBS([RSA_new],[crypto],,[exit 1],)
        AC_SEARCH_LIBS([SSL_library_init],[ssl],,[
            AC_SEARCH_LIBS([OPENSSL_init_ssl],[ssl],,[exit 1])
            ])
        AC_DEFINE_UNQUOTED(HAS_OPENSSL, [1], [linked with an OpenSSL compatible API])
    else
        AC_DEFINE_UNQUOTED(HAS_OPENSSL, [0], [not linked with an OpenSSL compatible API])
    fi

	AC_SUBST(OPENSSL)
])


AC_DEFUN([AC_YADIFA_ADD_LIBS], [

LDDYN="-Wl,-Bdynamic"
LDSTAT="-Wl,-Bstatic"

echo -n "checking if -Bstatic & -Bdynamic are supported ... "
$CC -Wl,-Bstatic 2>&1|grep Bstatic > /dev/null
if [[ $? -eq 0 ]]
then
	echo "not supported"
	LDDYN=""
	LDSTAT=""
else
	echo "supported"
fi

LIBS="$LDDYN $LIBS"

AC_SEARCH_LIBS([gethostbyname],[nsl],,[exit 1])
AC_SEARCH_LIBS([socket],[socket],,[exit 1])
AC_SEARCH_LIBS([dlopen],[dl],,[exit 1])
AC_SEARCH_LIBS([pthread_self],[pthread],,[exit 1])
dnl AC_GETHOSTBYNAME_CHECK

if [[ $requires_tcl -eq 1 ]]
then
	echo "TCL is required by this setup ..."

    if [[ "$tcl_version" = "" ]]
    then
        echo "tcl_version empty, expected something like 'tcl8.x'"
        exit 1
    fi

    CFLAGS="$CFLAGS -DWITHTCLINCLUDED"
    if [[ ! "${tcl_includedir}" = "/usr/include" ]] && [[ ! "${tcl_includedir}" = "" ]]
    then
    	CFLAGS="$CFLAGS -I${tcl_includedir}"
    fi

    if [[ ! "${tcl_libdir}" = "/usr/lib" ]] && [[ ! "${tcl_libdir}" = "/lib" ]] && [[ ! "${tcl_libdir}" = "" ]]
    then
    	LDFLAGS="-L${tcl_libdir} $LDFLAGS"
    fi

    echo "searching for library '$tcl_version' in the system"

	AC_SEARCH_LIBS(Tcl_Main, [${tcl_version}], ,[echo "could not find ${tcl_version} :: tcl_includedir=${tcl_includedir} :: tcl_libdir=${tcl_libdir}"; exit 1])
fi

dnl SSL

if [[ $requires_ssl -eq 1 ]]
then
	echo "SSL is required by this setup ..."
    
    AC_YADIFA_ADD_SSL

else
	echo "SSL is not required by this setup"
fi

dnl DNSCORE

if [[ $requires_dnscore -eq 1 ]]
then
AC_SEARCH_LIBS([clock_gettime],[rt])
AC_MSG_CHECKING(for the DNS Core library)

		if [[ ! -d ${srcdir}/../../lib/dnscore ]]
		then
			AC_CHECK_LIB([dnscore], [dnscore_init],,[exit],[$LDSTAT -ldnscore $LDDYN -lssl])
		else
			CFLAGS="-I${srcdir}/../../lib/dnscore/include $CFLAGS"
			LDFLAGS="-L../../lib/dnscore/.libs $LDFLAGS"
			LDFLAGS="$LDFLAGS $LDSTAT -ldnscore $LDDYN"
		fi
AC_SUBST(DNSCORE)

fi

dnl DNSDB

if [[ $requires_dnsdb -eq 1 ]]
then

AC_MSG_CHECKING(for the DNS Database library)

		if [[ ! -d ${srcdir}/../../lib/dnsdb ]]
		then
			AC_CHECK_LIB([dnsdb], [zdb_init],,[exit],[$LDSTAT -ldnscore $LDDYN -lssl])
		else
			echo "embedded"

			CFLAGS="-I${srcdir}/../../lib/dnsdb/include $CFLAGS"
			LDFLAGS="-L../../lib/dnsdb/.libs $LDFLAGS"

			LDFLAGS="$LDFLAGS $LDSTAT -ldnsdb $LDDYN"
		fi
AC_SUBST(DNSDB)

fi

dnl DNSLG

if [[ $requires_dnslg -eq 1 ]]
then

AC_MSG_CHECKING(for the DNS Looking Glass library)
		
		if [[ ! -d ${srcdir}/../../lib/dnslg ]]
		then
        	AC_CHECK_LIB([dnslg], [dnslg_init],,[exit],[$LDSTAT -ldnscore $LDDYN ])
        else
            CFLAGS="-I${srcdir}/../../lib/dnslg/include $CFLAGS"
            LDFLAGS="-L../../lib/dnslg/.libs $LDFLAGS"

            LDFLAGS="$LDFLAGS $LDSTAT -ldnslg $LDDYN"	
		fi
AC_SUBST(DNSLG)

fi

LDFLAGS="$LDFLAGS $LDDYN"
LIBS="$LDDYN $LIBS"

])

dnl Features

AC_DEFUN([AC_YADIFA_FEATURES], [

AC_CHECK_ENABLE_RRL

dnl MASTER
dnl ==========================================================================

dnl NOTE: Putting the empty optional text (,,) is mandatory

AC_HAS_DISABLE(master,MASTER_SUPPORT,[DNS master],,

    AC_YADIFA_ENABLE_SSL
    ,
    enable_dynupdate='no'
    enable_rrsig_management='no')

dnl CTRL module
dnl ==========================================================================

AC_HAS_DISABLE(ctrl,CTRL,[yadifa ctrl remote control tool])

dnl ZONESIGN
dnl ==========================================================================

AC_HAS_ENABLE(zonesign,ZONESIGN,[yadifa zonesign tool])

dnl KEYGEN
dnl ==========================================================================

AC_HAS_ENABLE(keygen,KEYGEN,[yadifa keygen tool])

dnl NSID
dnl ==========================================================================

AC_HAS_DISABLE(nsid,NSID_SUPPORT,[NSID support])

dnl ACL
dnl ==========================================================================

dnl AC_HAS_DISABLE(acl,ACL_SUPPORT,[ACL support],,
dnl    AC_YADIFA_ENABLE_SSL
dnl    ,
dnl    enable_tsig='no'
dnl    )
AC_FORCE_ENABLE(acl,ACL_SUPPORT)
AC_YADIFA_ENABLE_SSL

dnl TSIG
dnl ==========================================================================

dnl AC_HAS_DISABLE(tsig,TSIG_SUPPORT,[TSIG support],,
dnl     AC_YADIFA_ENABLE_SSL
dnl     ,
dnl     )
AC_FORCE_ENABLE(tsig,TSIG_SUPPORT)
AC_YADIFA_ENABLE_SSL

dnl DYNUPDATE
dnl ==========================================================================

AC_HAS_DISABLE(dynupdate,DYNUPDATE_SUPPORT,[dynamic update support])

dnl RRSIG_MANAGEMENT
dnl ==========================================================================

AC_HAS_DISABLE(rrsig_management,RRSIG_MANAGEMENT_SUPPORT,[RRSIG verification and generation for zones],,
    AC_YADIFA_ENABLE_SSL
    ,
    )

AM_CONDITIONAL([HAS_DNSSEC_SUPPORT], [true])
AC_DEFINE_UNQUOTED([HAS_DNSSEC_SUPPORT], [1], [MUST be enabled if either NSEC3 or NSEC are enabled])
AC_SUBST(ZDB_HAS_DNSSEC_SUPPORT)
AC_YADIFA_ENABLE_SSL

AM_CONDITIONAL(HAS_NSEC_SUPPORT,[true])
AC_DEFINE_UNQUOTED([HAS_NSEC_SUPPORT], [1], [NSEC enabled])
AC_SUBST(HAS_NSEC_SUPPORT)

AM_CONDITIONAL(HAS_NSEC3_SUPPORT,[true])
AC_DEFINE_UNQUOTED([HAS_NSEC3_SUPPORT], [1], [NSEC3 enabled])
AC_SUBST(HAS_NSEC3_SUPPORT)

dnl ZALLOC
dnl ==========================================================================

AC_HAS_DISABLE(zalloc,ZALLOC_SUPPORT,[zalloc memory system])

dnl ZALLOC STATISTICS
dnl =================

AC_HAS_ENABLE(zalloc_statistics,ZALLOC_STATISTICS_SUPPORT,[zalloc statistics support])

dnl ZALLOC DEBUG
dnl ============

AC_HAS_ENABLE(zalloc_debug,ZALLOC_DEBUG_SUPPORT,[zalloc debug support for yadifa objects])

dnl MALLOC DEBUG
dnl ============

AC_HAS_ENABLE(malloc_debug,MALLOC_DEBUG_SUPPORT,[malloc debug support for yadifa objects])

dnl LIBC MALLOC DEBUG
dnl ============

AC_HAS_ENABLE(libc_malloc_debug,LIBC_MALLOC_DEBUG_SUPPORT,[libc malloc debug support monitors program-wide allocations])

dnl BFD STACKTRACE DEBUG
dnl ====================

AC_HAS_ENABLE(bfd_debug,BFD_DEBUG_SUPPORT,[bfd debug support])

case "$enable_bfd_debug" in
    yes)
        AC_SEARCH_LIBS([dlinfo],[dl],[],[echo no dl],)
        AC_SEARCH_LIBS([sha1_init_ctx],[iberty],[],[echo iberty],)
        AC_SEARCH_LIBS([bfd_init],[bfd],[],[echo no bfd;exit 1],)
        ;;
    no|*)
        ;;
esac

dnl MUTEX STACKTRACE DEBUG
dnl ======================

AC_HAS_ENABLE(mutex_debug,MUTEX_DEBUG_SUPPORT,[mutex debug support])

dnl ZONE MUTEX DEBUG
dnl ================
AC_HAS_ENABLE(lock_debug,LOCK_DEBUG_SUPPORT,[zone lock debug support])

dnl FILEPOOL CACHE
dnl ================
AC_HAS_ENABLE(filepool_cache,FILEPOOL_CACHE,[file pool uses cache (dev)])

dnl INSTANCIATED ZONES DEBUG
dnl ========================

AC_HAS_ENABLE(track_zones_debug,TRACK_ZONES_DEBUG_SUPPORT,[tracking of the instanciated zones for detecting potential leaks.  Relatively cheap with a small (<100) amount of zones.])

dnl LOG THREAD ID
dnl =============

AC_HAS_ENABLE(log_thread_id,LOG_THREAD_ID,[a column with an alphanumeric id consistent in the lowest 32 bits of a thread id in each log line])

dnl LOG THREAD TAG
dnl ==============

AC_HAS_DISABLE(log_thread_tag,LOG_THREAD_TAG,[a column with a 8 letters human-readable tag identifying a thread in each log line])

dnl LOG PID
dnl =======

AC_HAS_DISABLE(log_pid,LOG_PID,[a column with the pid in each line of log])

dnl ASCII 7
dnl =======

AC_HAS_ENABLE(full_ascii7,FULL_ASCII7,[acceptance of ASCII7 characters in DNS names (not recommended)])

dnl ECDSA
dnl =====
AC_HAS_DISABLE(ecdsa,ECDSA_SUPPORT,[Elliptic Curve (ECDSA) support (ie: the available OpenSSL does not support it)])

dnl SYSTEMD-RESOLVED
dnl ================

AC_HAS_ENABLE(systemd_resolved_avoidance, SYSTEMD_RESOLVED_AVOIDANCE, [to set do-not-listen to "127.0.0.53 port 53" by default (otherwise the list is empty by default)])

dnl NON-AA AXFR (non-AA AXFR as sent by MS DNS)
dnl ==========================================================================

AC_HAS_ENABLE(non_aa_axfr_support,NON_AA_AXFR_SUPPORT,[defaults axfr-strict-authority to no. Lenient acceptance of AXFR answer from master that do not have AA bit by default (Microsoft DNS)])

dnl TCP MANAGER
dnl ==========================================================================

AC_HAS_ENABLE(tcp_manager,TCP_MANAGER,[Enables the TCP manager])

dnl STRDUP
dnl ==========================================================================

dnl include strdup

AC_MSG_CHECKING(if has strdup)
AM_CONDITIONAL([HAS_STRDUP], [false])

cat > strdup_test.c <<_ACEOF
#include<stdlib.h>
#include<string.h>

int main(int argc, char** argv)
{
	char* p = strdup("test");
	return 0;
}
_ACEOF
${CC} ${CFLAGS} strdup_test.c -o strdup_test
if [[ $? -eq 0 ]]; then
	has_strdup=1;
	echo "yes"
else
	echo "no"
fi
rm -f strdup_test strdup_test.c
AM_CONDITIONAL([HAS_STRDUP], [test $has_strdup = yes])

dnl EVENT DYNAMIC MODULE
dnl ==========================================================================

AC_HAS_ENABLE(event_dynamic_module,EVENT_DYNAMIC_MODULE,[Adds support for dynamically loaded module that gets events from yadifad and is allowed to fetch some information])

dnl logdir
dnl ==========================================================================

AC_HAS_WITH(logdir, LOGDIR, [the log file directory set to this], [where to put the log files],
logdir="$withval"
with_logdir="$logdir"
,
logdir=${localstatedir}/log/yadifa
with_logdir="$logdir"
)

AC_SUBST(logdir)

echo "LOGDIR=$logdir"

AC_SOCKADDR_SA_LEN_CHECK
AC_SOCKADDR_IN_SIN_LEN_CHECK
AC_SOCKADDR_IN6_SIN6_LEN_CHECK

])

dnl NOTIMESTAMP
dnl ==========================================================================

AC_HAS_DISABLE(build_timestamp,BUILD_TIMESTAMP,[Disable timestamps in the build])

dnl close_ex file-descriptor double-close protection (debug)
dnl ==========================================================================
AC_HAS_ENABLE(fd_close_debug, CLOSE_EX_REF, [close_ex(fd) to change the value of fd to detect double-closes issues (debug)])

AC_HAS_DISABLE(yadifa,YADIFA,[controller for yadifad],[building with controller])
AC_HAS_DISABLE(dnssec_tools,DNSSEC_TOOLS,[DNSSEC module for yadifa],[enable DNSSEC module for yadifa])

AC_DEFUN([AC_YADIFA_SUMMARY], [

if [[ "$disable_acl" = "yes" ]]; then enable_acl="no"; else enable_acl="yes";fi
if [[ "$disable_tsig" = "yes" ]]; then enable_tsig="no"; else enable_tsig="yes";fi

echo
echo SUMMARY
echo _____________________
echo
echo CC ................ : $CC
echo LD ................ : $LD
echo AR ................ : $AR
echo CFLAGS ............ : $CFLAGS
echo CXXFLAGS .......... : $CXXFLAGS
echo CPPFLAGS .......... : $CPPFLAGS
echo LDFLAGS ........... : $LDFLAGS
echo LIBS .............. : $LIBS
echo
echo ZALLOC ............ : $enable_zalloc
echo ZALLOC STATISTICS . : $enable_zalloc_statistics
echo ZALLOC DEBUG ...... : $enable_zalloc_debug
echo ACL ............... : $enable_acl
echo TSIG .............. : $enable_tsig
echo MASTER ............ : $enable_master
echo DYNUPDATE ......... : $enable_dynupdate
echo RRSIG MANAGEMENT .. : $enable_rrsig_management
echo CTRL .............. : $enable_ctrl
echo NSEC .............. : $enable_nsec
echo NSEC3 ............. : $enable_nsec3
echo RRL ............... : $enable_rrl
echo
echo TCL ............... : $with_tcl
if [[ "$with_tcl" = "yes" ]]; then 
echo TCL used ............................ : $tcl_version
echo TCL library ......................... : $tcl_libdir
echo "TCL includes ........................ : $tcl_includedir"
fi
echo

])

