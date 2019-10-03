dnl l1sign - Implementation of the Lamport one-time signature scheme
dnl Copyright (c) 2019  Janik Rabe <l1sign@janikrabe.com>
dnl
dnl This program is free software: you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation, either version 3 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program.  If not, see <https://www.gnu.org/licenses/>.

AC_INIT([l1sign],
        [0.0.0],
        [l1sign@janikrabe.com],,
        [https://janikrabe.com/projects/l1sign/])
AM_INIT_AUTOMAKE([foreign])

AC_DEFINE(PACKAGE_AUTHOR, ["Janik Rabe"], [author])

warn_CFLAGS=""

enableval=""
AC_ARG_ENABLE(warnings,
[  --enable-warnings       enable additional compiler warnings])
if test "$enableval" = "yes"; then
	warn_CFLAGS="-Wall -Wextra -pedantic"
fi

NEED_LIBGCRYPT_API=1
NEED_LIBGCRYPT_VERSION=1.8.0

AC_DEFINE_UNQUOTED(NEED_LIBGCRYPT_VERSION,
                   "$NEED_LIBGCRYPT_VERSION",
                   [Minimum version of libgcrypt])

AM_PATH_LIBGCRYPT("$NEED_LIBGCRYPT_API:$NEED_LIBGCRYPT_VERSION",, [
	AC_MSG_ERROR([\
$PACKAGE_NAME requires libgcrypt version $NEED_LIBGCRYPT_VERSION \
(API version $NEED_LIBGCRYPT_API) or later.])
])

AC_PROG_CC

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_SUBST([warn_CFLAGS])

AC_OUTPUT
