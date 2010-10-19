dnl Boilerplate
AC_INIT([ipset], [5.0], [kadlec@blackhole.kfki.hu])
AC_CANONICAL_SYSTEM
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

dnl Shortcut: Linux supported alone
case $target in
*-*-linux*) ;;
*) AC_MSG_ERROR([Linux systems supported exclusively!]);;
esac

dnl Additional arguments
dnl Kernel build directory or source tree
AC_ARG_WITH([kbuild],
            AS_HELP_STRING([--with-kbuild=PATH],
                           [Path to kernel build directory]),
            [KBUILDDIR="$withval";])
AC_ARG_WITH([ksource],
            AS_HELP_STRING([--with-ksource=PATH],
                           [Path to kernel source directory]),
            [KSOURCEDIR="$withval";])
AM_CONDITIONAL(WITH_KBUILDDIR, test "$KBUILDDIR" != "")
AC_SUBST(KBUILDDIR)

dnl Sigh: check kernel version dependencies
if test "$KBUILDDIR" != ""
then
	kbuilddir="$KBUILDDIR"
else
	kbuilddir="/lib/modules/`uname -r`/build"
fi

if test -n "$KSOURCEDIR"; then
	ksourcedir="$KSOURCEDIR"
else
	ksourcedir="/lib/modules/$(uname -r)/source"
fi

if test ! -e "$kbuilddir/.config"
then
	AC_MSG_ERROR([The kernel build directory $kbuilddir is not configured])
fi

AC_PROG_GREP

if test "X`$GREP '^CONFIG_IP6_NF_IPTABLES=' $kbuilddir/.config`" = "X"
then
	AC_MSG_ERROR([The kernel build directory $kbuilddir is not configured with IP6_NF_IPTABLES support (ip6tables)])
fi

dnl Check kernel dependencies: nfnetlink.h
NFNL_CB_CONST="`./check_const $ksourcedir/include/linux/netfilter/nfnetlink.h`"
AC_SUBST(NFNL_CB_CONST)

dnl Check kernel dependencies: netlink.h
NETLINK_DUMP_CONST="`./check_const $ksourcedir/include/linux/netlink.h`"
AC_SUBST(NETLINK_DUMP_CONST)

dnl Maximal number of sets supported by the kernel, default 256
AC_ARG_WITH([maxsets],
	    AS_HELP_STRING([--with-maxsets=256],
	    		   [Maximal numer of sets supported by the kernel]),
	    [MAXSETS="$withval";])
AM_CONDITIONAL(WITH_MAXSETS, test "$MAXSETS" != "")
AC_SUBST(MAXSETS)

dnl Verbose compiling
AC_ARG_ENABLE([verbose],
	      AS_HELP_STRING([--enable-verbose],
	                     [Enable verbose mode at compiling/linking.]),
	      [case "${enableval}" in
	       yes)	enable_verbose=yes ;;
	       no)	enable_verbose=no ;;
	       *) AC_MSG_ERROR([bad value ${enableval} for --enable-verbose]) ;;
	       esac], [enable_verbose=no])
	      
AM_CONDITIONAL([ENABLE_VERBOSE], [test "x$enable_verbose" = xyes])

dnl Enable debugging
AC_ARG_ENABLE([debug],
	      AS_HELP_STRING([--enable-debug],
	                     [Enable compiling with debug support.]),
	      [case "${enableval}" in
	       yes)	enable_verbose=yes ;;
	       no)	enable_verbose=no ;;
	       *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
	       esac], [enable_debug=no])
	      
AM_CONDITIONAL([ENABLE_DEBUG], [test "x$enable_debug" = xyes])

dnl Disable extra warn flags
AC_ARG_ENABLE([extra-flags],
	      AS_HELP_STRING([--disable-extra-flags],
	      		     [Disable extra compiler warning flags.]),
	      [case "${enableval}" in
	       yes)	extra_flags=yes ;;
	       no)	extra_flags=no ;;
	       *) AC_MSG_ERROR([bad value ${enableval} for --disable-extra-flags]) ;;
	       esac], [extra_flags=yes])
	      
AM_CONDITIONAL([DISABLE_EXTRA_FLAGS], [test "x$extra_flags" = xno])

dnl Checks for programs
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PROG_LN_S

dnl Checks for libraries
AC_CHECK_LIB([mnl], [mnl_socket_open])
if test x"${ac_cv_lib_mnl_mnl_socket_open}" = xno; then
  AC_MSG_ERROR(libmnl not found)
fi

dnl Checks for header files

dnl Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_TYPES([union nf_inet_addr],,,[#include <linux/types.h>
#include <netinet/in.h>
#include <linux/netfilter.h>])
dnl Checks for library functions.

dnl Generate output
AC_CONFIG_FILES([Makefile lib/Makefile src/Makefile])
AC_OUTPUT
