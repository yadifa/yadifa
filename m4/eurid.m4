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

dnl Assume it is true

cpu_intel_compatible=1
icc_enabled=no

dnl handles Darwin libtoolize -> glibtoolize

AC_DEFUN([AC_DARWIN_LIBTOOL], [

case "$(uname -s)" in
    Darwin)
        echo "OSX libtool workaroung"

        alias libtoolize="glibtoolize"
        alias libtool="glibtool"

        is_darwin_os=1
        is_bsd_family=1
        ;;
    FreeBSD)
        is_darwin_os=0
        is_bsd_family=1
        ;;
    *)
        is_darwin_os=0
        is_bsd_family=0
        ;;
esac

if [[ $is_darwin_os -ne 0 ]]
then
    AM_CONDITIONAL([IS_DARWIN_OS], [true])
else
    AM_CONDITIONAL([IS_DARWIN_OS], [false])
fi

if [[ $is_bsd_family -ne 0 ]]
then
    AM_CONDITIONAL([IS_BSD_FAMILY], [true])
else
    AM_CONDITIONAL([IS_BSD_FAMILY], [false])
fi

])


dnl Architecture

AC_DEFUN([AC_CPU_CHECK], [

AC_DEFINE_UNQUOTED([DEFAULT_ASSUMED_CPU_COUNT], [2], [number of harware core if the auto-detect fails])

cpu_intel_compatible=1

AM_CONDITIONAL([HAS_CPU_NIAGARA], [false])
AM_CONDITIONAL([HAS_CPU_AMDINTEL], [false])

echo -n "checking for the cpu options ... "
CPU_UNKNOWN=1

CFLAGS3264=
case "$(uname -i 2>/dev/null)" in
	SUNW,SPARC-Enterprise-T1000)
		AC_DEFINE_UNQUOTED([HAS_CPU_NIAGARA], [1], [T1000 has a Niagara cpu])
		AM_CONDITIONAL([HAS_CPU_NIAGARA], [true])
		echo "UtrasparcT1"
		CFLAGS3264=-m64
		CPU_UNKNOWN=0
		cpu_intel_compatible=0
		;;
	*)
		;;
esac

case "$(uname -m)" in
	x86_64)
		AC_DEFINE_UNQUOTED([HAS_CPU_AMDINTEL], [1], [i386, Athlon, Opteron, Core2, i3, i5, i7, ...])
		AM_CONDITIONAL([HAS_CPU_AMDINTEL], [true])
		echo "AMD/Intel"
		CFLAGS3264=-m64
		CPU_UNKNOWN=0
		cpu_intel_compatible=1
		;;
	*)
		;;
esac

case "${CPU_UNKNOWN}" in
	1)
		echo "generic"
		;;
	0)
		;;
esac

dnl Forced 32/64 bits architecture
echo -n "checking if force 32 bits is enabled ... "
AM_CONDITIONAL([FORCE32BITS], [false])
AC_ARG_ENABLE(force32bits, AS_HELP_STRING([--enable-force32bits], [Forces a 32 bits binary compilation]), [enable_force32bits=yes], [enable_force32bits=no])
AC_MSG_RESULT($enable_force32bits)
case "$enable_force32bits" in
    yes)
        CFLAGS3264=-m32
        AM_CONDITIONAL([FORCE32BITS], [test $enable_force32bits = yes])
        ;;
    *)
        ;;
esac

echo -n "checking if force 64 bits is enabled ... "
AM_CONDITIONAL([FORCE64BITS], [false])
AC_ARG_ENABLE(force64bits, AS_HELP_STRING([--enable-force64bits], [Forces a 64 bits binary compilation]), [enable_force64bits=yes], [enable_force64bits=no])
AC_MSG_RESULT($enable_force64bits)
case "$enable_force64bits" in
    yes)
        CFLAGS3264=-m64
        AM_CONDITIONAL([FORCE64BITS], [test $enable_force64bits = yes])

	if [[ "$enable_force32" = "yes" ]]
	then
		echo "cannot do both --enable-force32bits and --enable-force64bits at the same time"
		exit 1
	fi

        ;;
    *)
        ;;
esac

])

dnl Compiler

AC_DEFUN([AC_COMPILER_CHECK], [

CFLAGS=

CCVER=$($CC --version|head -1|sed 's/.* \([[0-9]]*\)\.\([[0-9]]*\).*/\1.\2/')
if [[ "$CCVER" = "" ]]
then
	CCVER='0.0'
fi

CCNAME=$($CC --version|head -1|sed -e 's/.*clang.*/clang/' -e 's/.*gcc.*/gcc/' -e 's/.*icc.*/icc/'|tr A-Z a-z)

if [[ "$CCNAME" = "" ]]
then
	CCNAME="unknown"
fi

CCMAJOR=$(echo $CCVER | sed 's/\./ /g' | awk '{ print @S|@1}')
CCMINOR=$(echo $CCVER | sed 's/\./ /g' | awk '{ print @S|@2}')

if [[ "$CCMAJOR" = "" ]]
then
	CCMAJOR=0
fi

if [[ "$CCMINOR" = "" ]]
then
	CCMINOR=0
fi

if [[ "$CCNAME" = "gcc" ]]
then
	CCOPTIMISATIONFLAGS=-O3

	if [[ $CCMAJOR -lt 4 ]]
	then
		CCOPTIMISATIONFLAGS=-O0

		echo "WARNING: GCC < 4.0 has optimisations issues with YADIFA."
		sleep 1

	elif [[ $CCMAJOR -eq 4 ]]
	then
		if [[ $CCMINOR -lt 6 ]]
		then
			CCOPTIMISATIONFLAGS=-O0

			echo "WARNING: GCC before 4.6 have optimisation issues with YADIFA."
			sleep 1

		elif [[ $CCMINOR -eq 6 ]]
		then
			CCOPTIMISATIONFLAGS=-O2
		else
			# hopefully after 4.6 the issue is fixed ...
			CCOPTIMISATIONFLAGS=-O3
		fi
	fi

        AM_CONDITIONAL([USES_ICC], [false])
        AM_CONDITIONAL([USES_GCC], [true])
        AM_CONDITIONAL([USES_CLANG], [false])
        AM_CONDITIONAL([USES_UNKNOWN], [false])

elif [[ "$CCNAME" = "icc" ]]
then
	echo "ICC"

	CCOPTIMISATIONFLAGS=-O3

        AM_CONDITIONAL([USES_ICC], [true])
        AM_CONDITIONAL([USES_GCC], [false])
        AM_CONDITIONAL([USES_CLANG], [false])
        AM_CONDITIONAL([USES_UNKNOWN], [false])

	AR=xiar

elif [[ "$CCNAME" = "clang" ]]
then
	echo "CLANG"

	CCOPTIMISATIONFLAGS=-O3
	
        AM_CONDITIONAL([USES_ICC], [false])
        AM_CONDITIONAL([USES_GCC], [false])
        AM_CONDITIONAL([USES_CLANG], [true])
        AM_CONDITIONAL([USES_UNKNOWN], [false])
else
	echo "unsupported compiler"

	CCNAME=$CC

	CCOPTIMISATIONFLAGS=-O2
	
	AM_CONDITIONAL([USES_ICC], [false])
        AM_CONDITIONAL([USES_GCC], [false])
        AM_CONDITIONAL([USES_CLANG], [false])	
        AM_CONDITIONAL([USES_UNKNOWN], [true])
fi

echo "detected compiler is $CCNAME $CCMAJOR $CCMINOR"

AC_SUBST(CCOPTIMISATIONFLAGS, $CCOPTIMISATIONFLAGS)

if [[ $cpu_intel_compatible -eq 0 ]]
then
	if [[ $icc_enabled -ne 0 ]]
	then
		echo "ERROR: cannot enable ICC with CPU other than x86 or amd64"
		exit 1
	fi
fi

])

dnl Memory aligment issues (T1000)

AC_DEFUN([AC_MEMALIGN_CHECK], [

echo -n "checking if memory accesses must be size-aligned ... "
AM_CONDITIONAL([HAS_MEMALIGN_ISSUES], [false])
cat > memalign_issues_test.c <<_ACEOF
#include<stdlib.h>

int main(int argc, char** argv)
{
	char* p = (char*)malloc(8);
	p++;
	int* intp= (int*)p;
	*intp=1;
	return 0;
}
_ACEOF
${CC} ${CFLAGS} memalign_issues_test.c -o memalign_issues_test
has_memalign_issues=0
./memalign_issues_test > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
	has_memalign_issues=1;
	echo "yes"
else
	echo "no"
fi
rm -f memalign_issues_test memalign_issues_test.c
AM_CONDITIONAL([HAS_MEMALIGN_ISSUES], [test $has_memalign_issues])
AC_DEFINE_UNQUOTED([HAS_MEMALIGN_ISSUES], [$has_memalign_issues], [Define this to enable slow but safe memory accesses])

])

dnl clang -faddress-sanitizer support
AC_DEFUN([AC_FADDRESS_SANITIZER_CHECK], [
echo -n "checking if ${CC} supports -faddress-sanitizer ... "
AM_CONDITIONAL([HAS_FADDRESS_SANITIZER], [false])
cat > address_sanitizer_test.c <<_ACEOF
#include<stdlib.h>
int main(int argc, char** argv)
{
	argc=argc;
	argv=argv;
        return 0;
}
_ACEOF
has_faddress_sanitizer=0
${CC} -faddress-sanitizer address_sanitizer_test.c -o address_sanitizer_test > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
	has_faddress_sanitizer=1
	echo yes
	AM_CONDITIONAL([HAS_FADDRESS_SANITIZER], [true])
else
	echo no
	AM_CONDITIONAL([HAS_FADDRESS_SANITIZER], [false])
fi
rm -f address_sanitizer_test.c address_sanitizer_test
])

dnl clang -fno-omit-frame-pointer support
AC_DEFUN([AC_FNO_OMIT_FRAME_POINTER_CHECK], [
echo -n "checking if ${CC} supports -fno-omit-frame-pointer ... "
AM_CONDITIONAL([HAS_FNO_OMIT_FRAME_POINTER], [false])
cat > fno-omit-frame-pointer_test.c <<_ACEOF
#include<stdlib.h>
int main(int argc, char** argv)
{
        argc=argc;
        argv=argv;
        return 0;
}
_ACEOF
has_fno_omit_frame_pointer=0
${CC} -fno-omit-frame-pointer fno-omit-frame-pointer_test.c -o fno-omit-frame-pointer_test > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
        has_fno_omit_frame_pointer=1
        echo yes
	AM_CONDITIONAL([HAS_FNO_OMIT_FRAME_POINTER], [true])
else
        echo no
	AM_CONDITIONAL([HAS_FNO_OMIT_FRAME_POINTER], [false])
fi
rm -f fno-omit-frame-pointer_test.c fno-omit-frame-pointer_test
])

dnl pthread spinlock support

AC_DEFUN([AC_PTHREAD_SPINLOCK_CHECK], [

echo -n "checking for pthread_spin_init ... "

AC_TRY_LINK([#include<pthread.h>],[pthread_spinlock_t lock; pthread_spin_init(&lock, 0);],[AC_DEFINE_UNQUOTED([HAS_PTHREAD_SPINLOCK], [1], [The system supports spinlocks]) echo yes],[echo no]);

])


dnl LTO

AC_DEFUN([AC_CHECK_LTO], [

AC_MSG_CHECKING(if LTO has been enabled)
AC_ARG_ENABLE(lto, AS_HELP_STRING([--enable-lto], [Enable LTO support, requires gold linker]), [enable_lto=yes], [enable_lto=no])
AC_MSG_RESULT($enable_lto)
case "$enable_lto" in
    yes)

	type -p gold

	if [[ $? -ne 0 ]]
	then
		echo "WARNING: 'gold' not found"
		sleep 1
	fi

	if [[ ! "$LD" = "" ]]
	then
		$LD -v |grep -i gold > /dev/null 2>&1

		if [[ $? -ne 0 ]]
		then
			echo
			echo "WARNING: LTO enabled but LD ($LD) is not gold."
			echo
			sleep 1
		fi
	else
		echo "LD not defined"
	fi
	
	AM_CONDITIONAL(HAS_LTO_SUPPORT, [true])
        ;;
    no|*)
	AM_CONDITIONAL(HAS_LTO_SUPPORT, [false])
        ;;
esac

])

AC_DEFUN([AC_SOCKADDR_SA_LEN_CHECK],
[
dnl Check for sa_len field
echo -n "checking if sockaddr has a sa_len field ... "
cat > sockaddr_sa_len.c <<_ACEOF
#include<sys/types.h>
#include<sys/socket.h>
int main(int argc, char* argv[])
{
    struct sockaddr sa;
    sa.sa_len = 4;
}
_ACEOF
has_sockaddr_sa_len=0
${CC} ${CFLAGS} sockaddr_sa_len.c > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
    has_sockaddr_sa_len=1;
    echo "yes"
else
    echo "no"
fi
rm -f sockaddr_sa_len.c sockaddr_sa_len
AM_CONDITIONAL([HAS_SOCKADDR_SA_LEN], [test $has_sockaddr_sa_len = yes])
AC_DEFINE_UNQUOTED([HAS_SOCKADDR_SA_LEN], [$has_sockaddr_sa_len], [The sockaddr struct has an sa_len field])
])

AC_DEFUN([AC_EURID_SUMMARY], [

cat <<EOF
	CC		:	$CC
	CPP		:	$CPP
	LD		:	$LD
	AR		:	$AR

	CFLAGS		:	$CFLAGS
	CPPFLAGS	:	$CPPFLAGS
	LDFLAGS		:	$LDFLAGS

	MEMALIGN ISSUES	:	$has_memalign_issues
	32/64		:	$CFLAGS3264
	LTO		:	$enable_lto
EOF
])

