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
dnl
dnl       SVN Program:
dnl               $URL: http://trac.s.of.be.eurid.eu:80/svn/sysdevel/projects/yadifa/trunk/bin/yadifa/configure.ac $
dnl
dnl       Last Update:
dnl               $Date: 2012-03-27 16:56:49 +0200 (Tue, 27 Mar 2012) $
dnl               $Revision: 1868 $
dnl
dnl       Purpose:
dnl              common yadifa m4 macros
dnl
dnl ############################################################################

dnl CTRL class

AC_DEFUN([AC_CHECK_ENABLE_CTRL], [

AM_CONDITIONAL([HAS_CTRL], [false])
AC_MSG_CHECKING(if ctrl has been enabled )
AC_ARG_ENABLE(ctrl, AS_HELP_STRING([--enable-ctrl], [Enables remote control]), [enable_ctrl=yes], [enable_ctrl=no])
AC_MSG_RESULT($enable_ctrl)
case "$enable_ctrl" in
    yes)
        AC_DEFINE_UNQUOTED([HAS_CTRL], [1], [Define this to enable the remote control])
        AM_CONDITIONAL([HAS_CTRL], [true])
        ;;
    *)
        ;;
esac
AM_CONDITIONAL([HAS_CTRL], [test $enable_ctrl = yes])

])

dnl DYNAMIC_PROVISIONING

AC_DEFUN([AC_CHECK_ENABLE_DYNAMIC_PROVISIONING], [

AM_CONDITIONAL([HAS_DYNAMIC_PROVISIONING], [false])
AC_MSG_CHECKING(if dynamic provisioning has been enabled )
AC_ARG_ENABLE(dynamic-provisioning, AS_HELP_STRING([--enable-dynamic-provisioning], [Enables dynamic-provisioning]), [enable_dynamic_provisioning=yes], [enable_dynamic_provisioning=no])
AC_MSG_RESULT($enable_dynamic_provisioning)
case "$enable_dynamic_provisioning" in
    yes)
        AC_DEFINE_UNQUOTED([HAS_DYNAMIC_PROVISIONING], [1], [Define this to enable dynamic provisioning])
        AM_CONDITIONAL([HAS_DYNAMIC_PROVISIONING], [true])
        ;;
    *)
        ;;
esac
AM_CONDITIONAL([HAS_DYNAMIC_PROVISIONING], [test $enable_dynamic_provisioning = yes])
AM_CONDITIONAL([HAS_CTRL], [true])

])

dnl DNS_RRL

AC_DEFUN([AC_CHECK_ENABLE_RRL], [

AM_CONDITIONAL([HAS_RRL_SUPPORT], [false])
AC_MSG_CHECKING(if DNS Response Rate Limiting has been enabled )
AC_ARG_ENABLE(rrl, AS_HELP_STRING([--enable-rrl], [Enables DNS RRL]), [enable_rrl=yes], [enable_rrl=no])
AC_MSG_RESULT($enable_rrl)
case "$enable_rrl" in
    yes)
        AC_DEFINE_UNQUOTED([HAS_RRL_SUPPORT], [1], [Define this to enable DNS RRL])
        AM_CONDITIONAL([HAS_RRL_SUPPORT], [true])
        ;;
    *)
        ;;
esac
AM_CONDITIONAL([HAS_RRL_SUPPORT], [test $enable_rrl = yes])

])

dnl SSL DNSCORE DNSDB DNSZONE (all defaulted to FALSE)

requires_ssl=1
requires_dnscore=0
requires_dnsdb=0
requires_dnszone=0
requires_dnslg=0

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

AC_DEFUN([AC_YADIFA_ENABLE_DNSLG], [
	requires_dnslg=1
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

if [[ $requires_ssl -eq 1 ]]
then
	echo "SSL is required by this setup ..."
    
    SSLDEPS=""
    echo "Finding the SSL dependencies"
    AC_CHECK_LIB([socket], [socket],[SSLDEPS="$SSLDEPS -lsocket"],[echo no socket],)
    AC_CHECK_LIB([dl], [dlinfo],[SSLDEPS="$SSLDEPS -ldl"],[echo no dl],)
    AC_CHECK_LIB([z], [deflate],[SSLDEPS="$SSLDEPS -lz"],[echo no z],)

    echo "SSLDEPS=${SSLDEPS}"

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


dnl DNSLG

if [[ $requires_dnslg -eq 1 ]]
then

AC_MSG_CHECKING(for the DNS Looking Glass library)
AC_ARG_WITH(dnslg, AS_HELP_STRING([--with-dnslg=DIR], [Use the dnslg from directory DIR/lib (devs only)]),
    [
		CPPFLAGS="-I$with_dnslg/include $CPPFLAGS"
        LDFLAGS="-L$with_dnszone/lib $LDFLAGS";
        AC_CHECK_LIB([dnslg], [dnslg_init],,[exit],[$LDSTAT -ldnscore $LDDYN -lssl])
    ],
    [
		
		if [[ ! -d ${srcdir}/../../lib/dnslg ]]
		then
        	AC_CHECK_LIB([dnslg], [dnslg_init],,[exit],[$LDSTAT -ldnscore $LDDYN ])
        else
            CPPFLAGS="-I${srcdir}/../../lib/dnslg/include $CPPFLAGS"
            LDFLAGS="-L../../lib/dnslg/.libs $LDFLAGS"

            LDFLAGS="$LDFLAGS $LDSTAT -ldnslg $LDDYN"	
		fi
    ])
AC_SUBST(DNSLG)

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

AC_CHECK_ENABLE_DYNAMIC_PROVISIONING
AC_CHECK_ENABLE_RRL

dnl SENDMSG / SENDTO : send messages with sendmsg instead of sendto
dnl ==========================================================================

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


dnl MASTER
dnl ==========================================================================

AM_CONDITIONAL(HAS_MASTER_SUPPORT, [true])
AC_MSG_CHECKING(if MASTER has been disabled)
AC_ARG_ENABLE(master, AS_HELP_STRING([--disable-master], [Disable MASTER support (devs only)]), [disable_master=yes], [disable_master=no])
AC_MSG_RESULT($disable_master)
case "$disable_master" in
	yes)
		AC_DEFINE_UNQUOTED([HAS_MASTER_SUPPORT], [0], [Do not support MASTER (devs only)])
		AM_CONDITIONAL([HAS_MASTER_SUPPORT], [false])
        enable_dynupdate='no'
        disable_dynupdate='yes'
        enable_rrsig_management='no'
        disable_rrsig_management='yes'
		;;
	no|*)
		AC_DEFINE_UNQUOTED([HAS_MASTER_SUPPORT], [1], [Enable MASTER support])
        AM_CONDITIONAL([HAS_MASTER_SUPPORT], [true])
		AC_YADIFA_ENABLE_SSL
        ;;
esac
AM_CONDITIONAL([HAS_MASTER_SUPPORT], [test $disable_master = no])

dnl CTRL class
dnl ==========================================================================

AM_CONDITIONAL([HAS_CTRL], [false])
AC_MSG_CHECKING(if ctrl has been enabled )
AC_ARG_ENABLE(ctrl, AS_HELP_STRING([--enable-ctrl], [Enables remote control (devs only)]), [enable_ctrl=yes], [enable_ctrl=no])
AC_MSG_RESULT($enable_ctrl)
case "$enable_ctrl" in
    yes)
        AC_DEFINE_UNQUOTED([HAS_CTRL], [1], [Define this to enable the remote control (devs only)])
        AM_CONDITIONAL([HAS_CTRL], [true])
        ;;
    *)
        ;;
esac
AM_CONDITIONAL([HAS_CTRL], [test $enable_ctrl = yes])

dnl NSID
dnl ==========================================================================

AM_CONDITIONAL([HAS_NSID_SUPPORT], [false])
AC_MSG_CHECKING(if NSID has been enabled )
AC_ARG_ENABLE(nsid, AS_HELP_STRING([--enable-nsid], [Enable NSID support]), [enable_nsid=yes], [enable_nsid=no])
AC_MSG_RESULT($enable_nsid)
case "$enable_nsid" in
    yes)
        AC_DEFINE_UNQUOTED([HAS_NSID_SUPPORT], [1], [Define this to enable NSID support])
        AM_CONDITIONAL([HAS_NSID_SUPPORT], [true])
        ;;
    *)
        ;;
esac
AM_CONDITIONAL([HAS_NSID_SUPPORT], [test $enable_nsid = yes])

dnl DYNUPDATE
dnl ==========================================================================

AM_CONDITIONAL(HAS_DYNUPDATE_SUPPORT, [true])
AC_MSG_CHECKING(if DYNUPDATE has been disabled)
AC_ARG_ENABLE(dynupdate, AS_HELP_STRING([--disable-dynupdate], [Disable dynamic update support (devs only)]), [disable_dynupdate=yes], [disable_dynupdate=no])
AC_MSG_RESULT($disable_dynupdate)
case "$disable_dynupdate" in
	yes)
		AC_DEFINE_UNQUOTED([HAS_DYNUPDATE_SUPPORT], [0], [Do not support dynamic update (devs only)])
		AM_CONDITIONAL([HAS_DYNUPDATE_SUPPORT], [false])
		;;
	no|*)
		AC_DEFINE_UNQUOTED([HAS_DYNUPDATE_SUPPORT], [1], [Enable dynamic update support])
        AM_CONDITIONAL([HAS_DYNUPDATE_SUPPORT], [true])
        ;;
esac
AM_CONDITIONAL([HAS_DYNUPDATE_SUPPORT], [test $disable_dynupdate = no])

dnl RRSIG_MANAGEMENT
dnl ==========================================================================

AM_CONDITIONAL(HAS_RRSIG_MANAGEMENT_SUPPORT, [true])
AC_MSG_CHECKING(if RRSIG_MANAGEMENT has been disabled)
AC_ARG_ENABLE(rrsig_management, AS_HELP_STRING([--disable-rrsig-management], [Disable RRSIG verification and generation for zones]), [disable_rrsig_management=yes], [disable_rrsig_management=no])
AC_MSG_RESULT($disable_rrsig_management)
case "$disable_rrsig_management" in
	yes)
		AC_DEFINE_UNQUOTED([HAS_RRSIG_MANAGEMENT_SUPPORT], [0], [Do not verify nor generate RRSIG for zones])
		AM_CONDITIONAL([HAS_RRSIG_MANAGEMENT_SUPPORT], [false])
		;;
	no|*)
		AC_DEFINE_UNQUOTED([HAS_RRSIG_MANAGEMENT_SUPPORT], [1], [Do verify and/or generate RRSIG for zones])
        AM_CONDITIONAL([HAS_RRSIG_MANAGEMENT_SUPPORT], [true])
		AC_YADIFA_ENABLE_SSL
        ;;
esac
AM_CONDITIONAL([HAS_RRSIG_MANAGEMENT_SUPPORT], [test $disable_rrsig_management = no])


AM_CONDITIONAL([HAS_ACL_SUPPORT], [true])
AC_DEFINE(HAS_ACL_SUPPORT, 1, [always on])
AM_CONDITIONAL([HAS_TSIG_SUPPORT], [true])
AC_DEFINE(HAS_TSIG_SUPPORT, 1, [always on])
AM_CONDITIONAL([HAS_DNSSEC_SUPPORT], [true])
AC_DEFINE(HAS_DNSSEC_SUPPORT, 1, [always on])
AM_CONDITIONAL([HAS_NSEC3_SUPPORT], [true])
AC_DEFINE(HAS_NSEC3_SUPPORT, 1, [always on])
AM_CONDITIONAL([HAS_NSEC_SUPPORT], [true])
AC_DEFINE(HAS_NSEC_SUPPORT, 1, [always on])
AM_CONDITIONAL([TCLCOMMANDS], [false])
AM_CONDITIONAL([HAS_MIRROR_SUPPORT], [false])
AM_CONDITIONAL([HAS_DROPALL_SUPPORT], [false])

AC_SOCKADDR_SA_LEN_CHECK
AC_FADDRESS_SANITIZER_CHECK
AC_FNO_OMIT_FRAME_POINTER_CHECK
AC_FCATCH_UNDEFINED_BEHAVIOR_CHECK

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
echo MASTER ............ : $enable_master
echo DYNUPDATE ......... : $enable_dynupdate
echo RRSIG MANAGEMENT .. : $enable_rrsig_management
echo CTRL .............. : $enable_ctrl
echo RRL ............... : $enable_rrl
echo

])

