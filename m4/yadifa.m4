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


dnl ####################################################
dnl
dnl AC_HAS_ENABLE(low-case --enable-*, up-case HAS_*, text, config.h text,ifyes,ifno)
dnl
dnl This macro creates a parameter with
dnl _ a shell-variable-name that will be used for --enable-VARIABLENAME
dnl     '_' of the variable name will be replaced by a '-' in the command
dnl
dnl _ SOMETHINGSOMETHING that will be transformed into a HAS_SOMETHINGSOMETHING define (both C & Makefile)
dnl
dnl _ A text to be put next to the --enable-this line in the --help
dnl
dnl _ An optional text to be put in the config.h output file.  If not set or empty, the --help text is used
dnl
dnl _ A block to execute if the option is enabled (--enable-this)
dnl
dnl _ A block to execute if the option is disabled (--disable-this or not set)
dnl
dnl ####################################################

AC_DEFUN([AC_HAS_ENABLE], [
#
# AC_HAS_ENABLE $1
#
AM_CONDITIONAL(HAS_$2, [false])
# CHECKING
AC_MSG_CHECKING(if [$2] has been enabled)
# ARG ENABLE
AC_ARG_ENABLE([$1], AS_HELP_STRING([--enable-[translit($1,[_],[-])]], [Enable $3]))
dnl # MSG RESULT
dnl AC_MSG_RESULT($enable_[$1])
dnl echo "enabled: '$enable_[$1]'"
# CASE
case "y$enable_[$1]" in
	yyes)
# DEFINE Y
		AC_DEFINE_UNQUOTED([HAS_$2], [1], ifelse($4,,[$3 enabled.],$4))
# CONDITIONAL Y
		AM_CONDITIONAL([HAS_$2], [true])
        enable_[$1]="yes"
        AC_MSG_RESULT([yes])
# IF YES
        $5
# ENDIF
		;;
	yno|y|*)
# DEFINE N
		AC_DEFINE_UNQUOTED([HAS_$2], [0], ifelse($4,,[$3 disabled.],$4))
# CONDITIONAL N
        AM_CONDITIONAL([HAS_$2], [false])
        enable_[$1]="no"
        AC_MSG_RESULT([no])
# IF NO
        $6
# ENDIF
        ;;
esac
dnl # CONDITIONAL
dnl AM_CONDITIONAL([HAS_$2], [test y$enable_[$1] = yyes])
# SUBST
AC_SUBST(HAS_$2)
# AC_HAS_ENABLE $1 DONE
])

dnl ####################################################
dnl
dnl AC_HAS_DISABLE(low-case --disable-*, up-case HAS_*, text, config.h text,ifyes,ifno)
dnl
dnl This macro creates a parameter with
dnl _ a shell-variable-name that will be used for --disable-VARIABLENAME
dnl     '_' of the variable name will be replaced by a '-' in the command
dnl
dnl _ SOMETHINGSOMETHING that will be transformed into a HAS_SOMETHINGSOMETHING define (both C & Makefile)
dnl
dnl _ A text to be put next to the --disable-this line in the --help
dnl
dnl _ An optional text to be put in the config.h output file.  If not set or empty, the --help text is used
dnl
dnl _ A block to execute if the option is enabled (--enable-this or not set)
dnl
dnl _ A block to execute if the option is disabled (--disable-this)
dnl
dnl ####################################################

AC_DEFUN([AC_HAS_DISABLE], [
#
# AC_HAS_DISABLE $1
#
AM_CONDITIONAL(HAS_$2, [true])
# CHECKING
AC_MSG_CHECKING(if [$2] has been disabled)
# ARG ENABLE
AC_ARG_ENABLE([$1], AS_HELP_STRING([--disable-[translit($1,[_],[-])]],[Disable $3]))
# MSG RESULT
dnl echo "enabled: '$enable_[$1]'"
# CASE
case "y$enable_[$1]" in
	yyes|y)
# DEFINE Y
		AC_DEFINE_UNQUOTED([HAS_$2], [1], ifelse($4,,[$3 enabled.],$4))
# CONDITIONAL Y
		AM_CONDITIONAL([HAS_$2], [true])
        enable_[$1]=yes
        AC_MSG_RESULT([no])
# IF YES
        $5
# ENDIF
		;;
	yno|*)
# DEFINE N
		AC_DEFINE_UNQUOTED([HAS_$2], [0], ifelse($4,,[$3 disabled.],$4))
# CONDITIONAL N
        AM_CONDITIONAL([HAS_$2], [false])
        enable_[$1]=no
        AC_MSG_RESULT([yes])
# IF NO
        $6
# ENDIF
        ;;
esac
dnl # CONDITIONAL
dnl AM_CONDITIONAL([HAS_$2], [test y$enable_[$1] = yyes])
# SUBST
AC_SUBST(HAS_$2)
# AC_HAS_DISABLE $1 DONE
])

dnl ####################################################
dnl
dnl AC_HAS_WITH(low-case --with-*, up-case HAS_*, text, config.h text,ifyes,ifno)
dnl
dnl This macro creates a parameter with
dnl _ a shell-variable-name that will be used for --with-VARIABLENAME
dnl     '_' of the variable name will be replaced by a '-' in the command
dnl
dnl _ SOMETHINGSOMETHING that will be transformed into a HAS_SOMETHINGSOMETHING define (both C & Makefile)
dnl
dnl _ A text to be put next to the --with-this line in the --help
dnl
dnl _ An optional text to be put in the config.h output file.  If not set or empty, the --help text is used
dnl
dnl _ A block to execute if the option is withd (--with-this)
dnl
dnl _ A block to execute if the option is withoutd (--without-this or not set)
dnl
dnl ####################################################

AC_DEFUN([AC_HAS_WITH], [
#
# AC_HAS_WITH $1
#
AM_CONDITIONAL(HAS_$2, [false])
# CHECKING
AC_MSG_CHECKING(if [$1] has been given)
# ARG WITH
AC_ARG_WITH([$1], AS_HELP_STRING([--with-[translit($1,[_],[-])]], [build $3]),
[
# DEFINE Y
		AC_DEFINE_UNQUOTED([HAS_$2], [1], ifelse($4,,[build $3.],$4))
# CONDITIONAL Y
		AM_CONDITIONAL([HAS_$2], [true])
        AC_DEFINE_UNQUOTED([HAS_WITH_$2], "$with_[$1]" // $withval, ifelse($4,,[build $3.],$4))
        with_[$1]="yes"
        AC_MSG_RESULT([yes])
# IF YES
        $5
# ENDIF
]
,
[
# DEFINE N
		AC_DEFINE_UNQUOTED([HAS_$2], [0], ifelse($4,,[don't build $3.],$4))
# CONDITIONAL N
        AM_CONDITIONAL([HAS_$2], [false])
        with_[$1]="no"
        AC_MSG_RESULT([no])
# IF NO
        $6
# ENDIF
])
# SUBST
AC_SUBST(HAS_$2)
# AC_HAS_WITH $1 DONE
])

dnl ####################################################
dnl
dnl AC_HAS_WITHOUT(low-case --without-*, up-case HAS_*, text, config.h text,ifyes,ifno)
dnl
dnl This macro creates a parameter with
dnl _ a shell-variable-name that will be used for --without-VARIABLENAME
dnl     '_' of the variable name will be replaced by a '-' in the command
dnl
dnl _ SOMETHINGSOMETHING that will be transformed into a HAS_SOMETHINGSOMETHING define (both C & Makefile)
dnl
dnl _ A text to be put next to the --without-this line in the --help
dnl
dnl _ An optional text to be put in the config.h output file.  If not set or empty, the --help text is used
dnl
dnl _ A block to execute if the option is withd (--with-this or not set)
dnl
dnl _ A block to execute if the option is withoutd (--without-this)
dnl
dnl ####################################################

AC_DEFUN([AC_HAS_WITHOUT], [
#
# AC_HAS_WITHOUT $1
#
AM_CONDITIONAL(HAS_$2, [true])
# CHECKING
AC_MSG_CHECKING(if [$1] has to be build)
# ARG WITH
AC_ARG_WITH([$1], AS_HELP_STRING([--without-[translit($1,[_],[-])]],[build $3]))

# MSG RESULT
case "y$with_[$1]" in
    yyes|y)
# DEFINE Y
		AC_DEFINE_UNQUOTED([HAS_$2], [1], ifelse($4,,[build $3.],$4))
# CONDITIONAL Y
		AM_CONDITIONAL([HAS_$2], [true])
        with_[$1]=yes
        AC_MSG_RESULT([yes])
# IF YES
        $5
# ENDIF
        ;;

    yno|*)
# DEFINE N
		AC_DEFINE_UNQUOTED([HAS_$2], [0], ifelse($4,,[don't build $3.],$4))
# CONDITIONAL N
        AM_CONDITIONAL([HAS_$2], [false])
        with_[$1]=no
        AC_MSG_RESULT([no])
# IF NO
        $6
# ENDIF
        ;;
esac

# SUBST
AC_SUBST(HAS_$2)
# AC_HAS_WITHOUT $1 DONE
])

dnl dnl ####################################################
dnl dnl
dnl dnl COMPILER SUPPORT
dnl dnl
dnl dnl ####################################################
dnl 
dnl AC_DEFUN([AC_COMPILER_SUPPORTS], [
dnl #
dnl # AC_COMPILER_SUPPORTS $1
dnl #
dnl # CHECKING
dnl AC_MSG_CHECKING(if compiler supports [$1])
dnl cat > test-gcc-$2.c <<_ACEOF
dnl #include <stdlib.h>
dnl int main(int argc,char** argv)
dnl {
dnl     (void)argc;
dnl     (void)argv;
dnl     puts("Hello World!");
dnl     return 0;
dnl }
dnl _ACEOF
dnl ${CC} $1 test-gcc-$2.c -o test-gcc-$2
dnl if [[ $? -ne 0]]
dnl then
dnl     AM_CONDITIONAL(HAS_CC_$2, [false])
dnl     AC_MSG_RESULT([no])
dnl else
dnl     AM_CONDITIONAL(HAS_CC_$2, [true])
dnl     AC_MSG_RESULT([yes])
dnl fi
dnl AC_SUBST(HAS_CC_$2)
dnl rm -f test-gcc-$2.c
dnl 
dnl ])
dnl
dnl dnl ####################################################

dnl CTRL class
dnl

AC_DEFUN([AC_CHECK_ENABLE_CTRL], [

AC_HAS_ENABLE(ctrl,CTRL,[remote control])

])

dnl DNS_RRL

AC_DEFUN([AC_CHECK_ENABLE_RRL], [

AC_HAS_DISABLE(rrl,RRL_SUPPORT,[DNS Response Rate Limiter])
 
])

dnl SSL DNSCORE DNSDB DNSZONE (all defaulted to FALSE)

requires_ssl=0
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
    requires_dnscore=1
])

AC_DEFUN([AC_YADIFA_ENABLE_DNSZONE], [
	requires_dnszone=1
	requires_dnsdb=1
    requires_dnscore=1
])

AC_DEFUN([AC_YADIFA_ENABLE_DNSLG], [
	requires_dnslg=1
    requires_dnscore=1
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

AC_SEARCH_LIBS([gethostbyname],[nsl],,[exit 1])
AC_SEARCH_LIBS([socket],[socket],,[exit 1])
AC_SEARCH_LIBS([dlopen],[dl],,[exit 1])
dnl AC_GETHOSTBYNAME_CHECK

dnl SSL

if [[ $requires_ssl -eq 1 ]]
then
	echo "SSL is required by this setup ..."
    
    SSLDEPS=""
    echo "Finding the SSL dependencies"
    AC_SEARCH_LIBS([deflate],[z])

    echo "SSLDEPS=${SSLDEPS}"

	AC_MSG_CHECKING(if SSL is available)

    ac_check_lib_ssl=0

    AC_ARG_WITH(openssl_lib, AS_HELP_STRING([--with-openssl-lib=DIR], [Use the openssl library from directory DIR]),
        [
            AC_MSG_RESULT([yes])
            LDFLAGS="-L$with_openssl_lib $SSLDEPS $LDFLAGS"
			echo "LDFLAGS=${LDFLAGS}"
            ac_check_lib_ssl=1
        ])

    AC_ARG_WITH(openssl_include, AS_HELP_STRING([--with-openssl-include=DIR], [Use the openssl headers from directory DIR]),
        [
            AC_MSG_RESULT([yes])
            CFLAGS="-I$with_openssl_include $CFLAGS $CFLAGS3264"
			echo "CFLAGS=${LDFLAGS}"
            ac_check_lib_ssl=1
        ])


	AC_ARG_WITH(openssl, AS_HELP_STRING([--with-openssl=DIR], [Use the openssl from directory DIR]),
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
        AC_SEARCH_LIBS([SSL_library_init],[ssl],,[exit 1])
    fi

	AC_SUBST(OPENSSL)

else
	echo "SSL is not required by this setup"
fi

dnl DNSCORE

if [[ $requires_dnscore -eq 1 ]]
then
AC_SEARCH_LIBS([clock_gettime],[rt])
AC_MSG_CHECKING(for the DNS Core library)
AC_ARG_WITH(dnscore, AS_HELP_STRING([--with-dnscore=DIR], [Use the dnscore from directory DIR/lib (devs only)]),
	[
		CFLAGS="-I$with_dnscore/include $CFLAGS"
		LDFLAGS="-L$with_dnscore/lib $LDFLAGS";
		AC_CHECK_LIB([dnscore], [dnscore_init],,[exit],[$LDSTAT -ldnscore $LDDYN -lssl])
	],
	[

		if [[ ! -d ${srcdir}/../../lib/dnscore ]]
		then
			AC_CHECK_LIB([dnscore], [dnscore_init],,[exit],[$LDSTAT -ldnscore $LDDYN -lssl])
		else
			CFLAGS="-I${srcdir}/../../lib/dnscore/include $CFLAGS"
			LDFLAGS="-L../../lib/dnscore/.libs $LDFLAGS"
			LDFLAGS="$LDFLAGS $LDSTAT -ldnscore $LDDYN"
		fi
	])
AC_SUBST(DNSCORE)

fi

dnl DNSDB

if [[ $requires_dnsdb -eq 1 ]]
then

AC_MSG_CHECKING(for the DNS Database library)
AC_ARG_WITH(dnsdb, AS_HELP_STRING([--with-dnsdb=DIR], [Use the dnsdb from directory DIR/lib (devs only)]),
	[
		CFLAGS="-I$with_dnsdb/include $CFLAGS"
		LDFLAGS="-L$with_dnsdb/lib $LDFLAGS";
		AC_CHECK_LIB([dnsdb], [zdb_init],,[exit],[$LDSTAT -ldnscore $LDDYN -lssl])
	],
	[

		if [[ ! -d ${srcdir}/../../lib/dnsdb ]]
		then
			AC_CHECK_LIB([dnsdb], [zdb_init],,[exit],[$LDSTAT -ldnscore $LDDYN -lssl])
		else
			echo "embedded"

			CFLAGS="-I${srcdir}/../../lib/dnsdb/include $CFLAGS"
			LDFLAGS="-L../../lib/dnsdb/.libs $LDFLAGS"

			LDFLAGS="$LDFLAGS $LDSTAT -ldnsdb $LDDYN"
		fi
	])
AC_SUBST(DNSDB)

fi

dnl DNSZONE

if [[ $requires_dnszone -eq 1 ]]
then

AC_MSG_CHECKING(for the DNS Zone library)
AC_ARG_WITH(dnszone, AS_HELP_STRING([--with-dnszone=DIR], [Use the dnszone from directory DIR/lib (devs only)]),
    [
		CFLAGS="-I$with_dnszone/include $CFLAGS"
        LDFLAGS="-L$with_dnszone/lib $LDFLAGS";
        AC_CHECK_LIB([dnszone], [dnszone_init],,[exit],[$LDSTAT -ldnsdb -ldnscore $LDDYN -lssl])
    ],
    [
		
		if [[ ! -d ${srcdir}/../../lib/dnszone ]]
		then
        	AC_CHECK_LIB([dnszone], [dnszone_init],,[exit],[$LDSTAT -ldnsdb -ldnscore $LDDYN -lssl])
        else
            CFLAGS="-I${srcdir}/../../lib/dnszone/include $CFLAGS"
            LDFLAGS="-L../../lib/dnszone/.libs $LDFLAGS"

            LDFLAGS="$LDFLAGS $LDSTAT -ldnszone $LDDYN"	
		fi
    ])
AC_SUBST(DNSZONE)

fi

dnl DNSLG

if [[ $requires_dnslg -eq 1 ]]
then

AC_MSG_CHECKING(for the DNS Looking Glass library)
AC_ARG_WITH(dnslg, AS_HELP_STRING([--with-dnslg=DIR], [Use the dnslg from directory DIR/lib (devs only)]),
    [
		CFLAGS="-I$with_dnslg/include $CFLAGS"
        LDFLAGS="-L$with_dnszone/lib $LDFLAGS";
        AC_CHECK_LIB([dnslg], [dnslg_init],,[exit],[$LDSTAT -ldnscore $LDDYN -lssl])
    ],
    [
		
		if [[ ! -d ${srcdir}/../../lib/dnslg ]]
		then
        	AC_CHECK_LIB([dnslg], [dnslg_init],,[exit],[$LDSTAT -ldnscore $LDDYN ])
        else
            CFLAGS="-I${srcdir}/../../lib/dnslg/include $CFLAGS"
            LDFLAGS="-L../../lib/dnslg/.libs $LDFLAGS"

            LDFLAGS="$LDFLAGS $LDSTAT -ldnslg $LDDYN"	
		fi
    ])
AC_SUBST(DNSLG)

fi

LDFLAGS="$LDFLAGS $LDDYN"
LIBS="$LDDYN $LIBS"

])

dnl Features

AC_DEFUN([AC_YADIFA_FEATURES], [

AC_CHECK_ENABLE_RRL

dnl SENDMSG / SENDTO : send messages with sendmsg instead of sendto
dnl ==========================================================================

AC_HAS_ENABLE(messages,MESSAGES_SUPPORT,[use messages instead of send (needed if you use more than one IP aliased on the same network interface)])

dnl MASTER
dnl ==========================================================================

dnl NOTE: Putting the empty optional text (,,) is mandatory

AC_HAS_DISABLE(master,MASTER_SUPPORT,[DNS master],,

    AC_YADIFA_ENABLE_SSL
    ,
    enable_dynupdate='no'
    enable_rrsig_management='no')

dnl CTRL class
dnl ==========================================================================

AC_HAS_ENABLE(ctrl,CTRL,[remote control])

dnl NSID
dnl ==========================================================================

AC_HAS_DISABLE(nsid,NSID_SUPPORT,[NSID support])

dnl DYNUPDATE
dnl ==========================================================================

AC_HAS_DISABLE(dynupdate,DYNUPDATE_SUPPORT,[dynamic update support])

dnl RRSIG_MANAGEMENT
dnl ==========================================================================

AC_HAS_DISABLE(rrsig_management,RRSIG_MANAGEMENT_SUPPORT,[RRSIG verification and generation for zones],,
    AC_YADIFA_ENABLE_SSL
    ,
    )


AC_HAS_WITH(logdir, LOGDIR, [sets the directory where to put the log files], [where to put the log files],
logdir="$withval"
,
logdir=${localstatedir}/log/yadifa
)
AC_SUBST(logdir)

AM_CONDITIONAL([HAS_ACL_SUPPORT], [true])
AC_DEFINE_UNQUOTED([HAS_ACL_SUPPORT], [1], [always on])
AM_CONDITIONAL([HAS_TSIG_SUPPORT], [true])
AC_DEFINE_UNQUOTED([HAS_TSIG_SUPPORT], [1], [always on])
AM_CONDITIONAL([HAS_DNSSEC_SUPPORT], [true])
AC_DEFINE_UNQUOTED([HAS_DNSSEC_SUPPORT], [1], [always on])
AM_CONDITIONAL([HAS_NSEC3_SUPPORT], [true])
AC_DEFINE_UNQUOTED([HAS_NSEC3_SUPPORT], [1], [always on])
AM_CONDITIONAL([HAS_NSEC_SUPPORT], [true])
AC_DEFINE_UNQUOTED([HAS_NSEC_SUPPORT], [1], [always on])
AM_CONDITIONAL([HAS_MIRROR_SUPPORT], [false])
AC_DEFINE_UNQUOTED([HAS_MIRROR_SUPPORT], [0], [always off])

AC_SOCKADDR_SA_LEN_CHECK
AC_SOCKADDR_IN_SIN_LEN_CHECK
AC_SOCKADDR_IN6_SIN6_LEN_CHECK

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
echo TCL ............... : $enable_tcl
echo

])

