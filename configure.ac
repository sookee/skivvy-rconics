# /*-----------------------------------------------------------------.
# | Copyright (C) 2011 SooKee oasookee@gmail.com               |
# '------------------------------------------------------------------'
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
# 
# http://www.gnu.org/licenses/gpl-2.0.html
# 
# '-----------------------------------------------------------------*/

AC_INIT([skivvy],[0.1],[oasookee@gmail.com],[skivvy])
AC_CONFIG_SRCDIR([src/test.cpp])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.10 foreign])
#AM_SILENT_RULES([yes])

AM_PROG_LIBTOOL
AC_PROG_CXX
AC_PROG_INSTALL

AC_LANG(C++)
AC_MSG_CHECKING(if $CXX supports C++11)

#CXXFLAGS="$CXXFLAGS -std=gnu++11"
#AC_COMPILE_IFELSE(AC_LANG_PROGRAM([],[for(int i: {0})]),[cpp11=yes],[cpp11=no])
#AC_MSG_RESULT($cpp11)
#if test "$cpp11" = "no"; then
#	AC_MSG_ERROR([C++11 support is required.])
#fi


AC_CONFIG_MACRO_DIR([m4])

AC_LANG_CPLUSPLUS
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
