dnl ############################################################################
dnl 
dnl Copyright (c) 2011, EURid. All rights reserved.
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

dnl CTRL class

AC_DEFUN([AC_CHECK_ENABLE_CTRL], [

AM_CONDITIONAL([HAS_CTRL], [false])

])

dnl SSL DNSCORE DNSDB DNSZONE (all defaulted to FALSE)

requires_ssl=0
requires_dnscore=0
requires_dnsdb=0
requires_dnszone=0

AC_DEFUN([AC_YADIFA_ENABLE_SSL], [
	requires_ssl=1
])

AC_DEFUN([AC_YADIFA_ENABLE_DNSCORE], [
	requires_dnscore=1
])

AC_DEFUN([AC_YADIFA_ENABLE_DNSDB], [
	requires_dnsdb=1
])

AC_DEFUN([AC_YADIFA_ENABLE_DNSZONE], [
	requires_dnszone=1
])

AC_DEFUN([AC_YADIFA_ADD_LIBS], [

LDDYN="-Wl,-Bdynamic"
LDSTAT="-Wl,-Bstatic"

echo -n "checking if -Bstatic & -Bdynamic are supported ... "
$CC -Wl,-Bstatic 2>&1|grep Bstatic > /dev/null
if [[ $? -eq 0 ]]
then
	echo "not supported";
	LDDYN=""
	LDSTAT=""
else
	echo "supported";
fi

LIBS="$LDDYN $LIBS"

dnl SSL

SSLDEPS=""
AC_CHECK_LIB([socket], [socket],[SSLDEPS="$SSLDEPS -lsocket"],[echo no socket],)
AC_CHECK_LIB([dl], [dlinfo],[SSLDEPS="$SSLDEPS -ldl"],[echo no dl],)
echo "SSLDEPS=${SSLDEPS}"

if [[ $requires_ssl -eq 1 ]]
then

	echo "SSL is required by this setup ..."

	AC_MSG_CHECKING(if SSL is available)
	AC_ARG_WITH(openssl, AS_HELP_STRING([--with-openssl=DIR], [Use the openssl from directory DIR]),
		[
			echo "yes"

			OPENSSL="${withval}"
			CPPFLAGS="-I$with_openssl/include $CPPFLAGS $CFLAGS3264"
			LDFLAGS="-L$with_openssl/lib $SSLDEPS $LDFLAGS"
			echo "CPPFLAGS=${CPPFLAGS}"
			echo "LDFLAGS=${LDFLAGS}"


			AC_CHECK_LIB([crypto], [RSA_new],,,[$SSLDEPS])
			AC_CHECK_LIB([ssl], [SSL_library_init],,[exit],[$SSLDEPS])
		],
		[
			echo "no"
			CPPFLAGS="$CPPFLAGS $CFLAGS3264"
            LDFLAGS="$SSLDEPS $LDFLAGS"
			echo "CPPFLAGS=${CPPFLAGS}"
			echo "LDFLAGS=${LDFLAGS}"

			AC_CHECK_LIB([crypto], [RSA_new],,,[$SSLDEPS])
			AC_CHECK_LIB([ssl], [SSL_library_init],,[exit],[$SSLDEPS])
		])
	AC_SUBST(OPENSSL)

else
	echo "SSL is not required by this setup"
	CPPFLAGS="$CPPFLAGS $CFLAGS3264"
	AC_CHECK_LIB([socket], [socket],,,)
fi


dnl DNSZONE

if [[ $requires_dnszone -eq 1 ]]
then

AC_MSG_CHECKING(for the DNS Zone library)
AC_ARG_WITH(dnszone, AS_HELP_STRING([--with-dnszone=DIR], [Use the dnszone from directory DIR/lib (devs only)]),
    [
		CPPFLAGS="-I$with_dnszone/include $CPPFLAGS"
        LDFLAGS="-L$with_dnszone/lib $LDFLAGS";
        AC_CHECK_LIB([dnszone], [dnszone_init],,[exit],[$LDSTAT -ldnsdb -ldnscore $LDDYN -lssl])
    ],
    [
		
		if [[ ! -d ${srcdir}/../../lib/dnszone ]]
		then
        	AC_CHECK_LIB([dnszone], [dnszone_init],,[exit],[$LDSTAT -ldnsdb -ldnscore $LDDYN -lssl])
        else
            CPPFLAGS="-I${srcdir}/../../lib/dnszone/include $CPPFLAGS"
            LDFLAGS="-L../../lib/dnszone/.libs $LDFLAGS"

            LDFLAGS="$LDFLAGS $LDSTAT -ldnszone $LDDYN"	
		fi
    ])
AC_SUBST(DNSZONE)

fi

dnl DNSDB

if [[ $requires_dnsdb -eq 1 ]]
then

AC_MSG_CHECKING(for the DNS Database library)
AC_ARG_WITH(dnsdb, AS_HELP_STRING([--with-dnsdb=DIR], [Use the dnsdb from directory DIR/lib (devs only)]),
	[
		CPPFLAGS="-I$with_dnsdb/include $CPPFLAGS"
		LDFLAGS="-L$with_dnsdb/lib $LDFLAGS";
		AC_CHECK_LIB([dnsdb], [zdb_init],,[exit],[$LDSTAT -ldnscore $LDDYN -lssl])
	],
	[

		if [[ ! -d ${srcdir}/../../lib/dnsdb ]]
		then
			AC_CHECK_LIB([dnsdb], [zdb_init],,[exit],[$LDSTAT -ldnscore $LDDYN -lssl])
		else
			echo "embedded"

			CPPFLAGS="-I${srcdir}/../../lib/dnsdb/include $CPPFLAGS"
			LDFLAGS="-L../../lib/dnsdb/.libs $LDFLAGS"

			LDFLAGS="$LDFLAGS $LDSTAT -ldnsdb $LDDYN"
		fi
	])
AC_SUBST(DNSDB)

fi

dnl DNSCORE

if [[ $requires_dnscore -eq 1 ]]
then
AC_MSG_CHECKING(for the DNS Core library)
AC_ARG_WITH(dnscore, AS_HELP_STRING([--with-dnscore=DIR], [Use the dnscore from directory DIR/lib (devs only)]),
	[
		CPPFLAGS="-I$with_dnscore/include $CPPFLAGS"
		LDFLAGS="-L$with_dnscore/lib $LDFLAGS";
		AC_CHECK_LIB([dnscore], [dnscore_init],,[exit],[$LDSTAT -ldnscore $LDDYN -lssl])
	],
	[

		if [[ ! -d ${srcdir}/../../lib/dnscore ]]
		then
			AC_CHECK_LIB([dnscore], [dnscore_init],,[exit],[$LDSTAT -ldnscore $LDDYN -lssl])
		else
			CPPFLAGS="-I${srcdir}/../../lib/dnscore/include $CPPFLAGS"
			LDFLAGS="-L../../lib/dnscore/.libs $LDFLAGS"

			LDFLAGS="$LDFLAGS $LDSTAT -ldnscore $LDDYN"
		fi
	])
AC_SUBST(DNSCORE)

fi

LDFLAGS="$LDFLAGS $LDDYN"
LIBS="$LDDYN $LIBS"

])

dnl Features

AC_DEFUN([AC_YADIFA_FEATURES], [

dnl CTRL class

AM_CONDITIONAL([HAS_CTRL], [false])

dnl Less memory usage (Z-alloc uses smaller chunks when he gets new buffers, of course it's slower)

AM_CONDITIONAL([HAS_TINY_FOOTPRINT], [false])
AC_MSG_CHECKING(if tiny footprint has been required )
AC_ARG_ENABLE(tiny_footprint, AS_HELP_STRING([--enable-tiny-footprint], [Uses less memory at once]), [enable_tiny_footprint=yes], [enable_tiny_footprint=no])
AC_MSG_RESULT($enable_tiny_footprint)
case "$enable_tiny_footprint" in
    yes)
        AC_DEFINE_UNQUOTED([HAS_TINY_FOOTPRINT], [1], [Define this to use less memory])
        AM_CONDITIONAL([HAS_TINY_FOOTPRINT], [true])
        ;;
    *)
        ;;
esac
AM_CONDITIONAL([HAS_TINY_FOOTPRINT], [test $enable_tiny_footprint = yes])

dnl ACL

AM_CONDITIONAL(HAS_ACL_SUPPORT, [true])
AC_DEFINE_UNQUOTED([HAS_ACL_SUPPORT], [1], [Enable ACL support])

dnl TSIG

AM_CONDITIONAL(HAS_TSIG_SUPPORT, [true])
AC_DEFINE_UNQUOTED([HAS_TSIG_SUPPORT], [1], [Enable TSIG support])

dnl NSEC3

AM_CONDITIONAL([HAS_DNSSEC_SUPPORT], [false])

dnl AC_MSG_CHECKING(if NSEC3 has been disabled)
enable_nsec3=yes

case "$enable_nsec3" in
	yes)
		AC_DEFINE_UNQUOTED([HAS_NSEC3_SUPPORT], [1], [Set this to 1 to enable NSEC3 support])
		AM_CONDITIONAL([HAS_DNSSEC_SUPPORT], [true])
		AC_DEFINE_UNQUOTED([HAS_DNSSEC_SUPPORT], [1], [MUST be enabled if either NSEC3 or NSEC are enabled])
		AC_YADIFA_ENABLE_SSL
		;;
	no|*)
		;;
esac
AM_CONDITIONAL([HAS_NSEC3_SUPPORT], [test $enable_nsec3 = yes])

dnl NSEC

dnl AC_MSG_CHECKING(if NSEC has been disabled)
enable_nsec=yes
case "$enable_nsec" in
	yes)
		AC_DEFINE_UNQUOTED([HAS_NSEC_SUPPORT], [1], [Set this to 1 to enable NSEC support])
		AM_CONDITIONAL([HAS_DNSSEC_SUPPORT], [true])
		AC_DEFINE_UNQUOTED([HAS_DNSSEC_SUPPORT], [1], [MUST be enabled if either NSEC3 or NSEC are enabled])
		AC_YADIFA_ENABLE_SSL
		;;
	no|*)
		;;
esac
AM_CONDITIONAL([HAS_NSEC_SUPPORT], [test $enable_nsec = yes])

AM_CONDITIONAL([TCLCOMMANDS], [false])

dnl MIRROR debug 

AM_CONDITIONAL([HAS_MIRROR_SUPPORT], [false])

dnl DROPALL debug 

AM_CONDITIONAL([HAS_DROPALL_SUPPORT], [false])

dnl send messages instead of sendto

AC_MSG_CHECKING(if MESSAGES has been enabled)
AC_ARG_ENABLE(messages, AS_HELP_STRING([--enable-messages], [Use messages instead of send. Needed if you have many IPs aliased on the same interface.]),
		[], [enable_messages=no])
AC_MSG_RESULT($enable_messages)
case "$enable_messages" in
	yes)
		AC_DEFINE_UNQUOTED([HAS_MESSAGES_SUPPORT], [1], [Use messages instead of send. Needed if you have many IPs aliased on the same interface.])
		;;
	no|*)
		;;
esac
AM_CONDITIONAL([HAS_MESSAGES_SUPPORT], [test $enable_messages = yes])

AC_SOCKADDR_SA_LEN_CHECK
AC_FADDRESS_SANITIZER_CHECK
AC_FNO_OMIT_FRAME_POINTER_CHECK

])

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
echo CPPFLAGS .......... : $CPPFLAGS
echo LDFLAGS ........... : $LDFLAGS
echo LIBS .............. : $LIBS
echo
echo ACL ............... : $enable_acl
echo CTRL .............. : $enable_ctrl
echo NSEC .............. : $enable_nsec
echo NSEC3 ............. : $enable_nsec3
echo TSIG .............. : $enable_tsig
echo
echo TCL ............... : $enable_tcl
echo

])

