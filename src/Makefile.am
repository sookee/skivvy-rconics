# /*-----------------------------------------------------------------.
# | Copyright (C) 2012 SooKee oasookee@googlemail.com                |
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

plugin_includedir = $(prefix)/include/skivvy-rconics
plugin_librarydir = $(datadir)/skivvy/plugins
plugin_manualsdir = $(datadir)/skivvy

DEF_FLAGS = \
	-D _GLIBCXX_USE_NANOSLEEP \
	-D _GLIBCXX_USE_SCHED_YIELD \
	-D STAMP=\"$(shell date +%Y%m%d-%H%M%S)\" \
	-D DEV=\"$(shell git diff --quiet || echo -dev)\" \
	-D COMMITS=\"$(shell printf %04d \"$(git log --after={yesterday} --pretty=oneline|wc -l)\")\" \
	-D REVISION=\"$(shell git log -n 1 --pretty=format:%h|tr [:lower:] [:upper:])\" \
	-D DEFAULT_PLUGIN_DIR=\"$(plugindir)\"

GEN_FLAGS = -Wl,-E -Wfatal-errors -Wall -Wextra -Winit-self -ansi -pedantic -pipe -pthread \
	-I$(top_srcdir)/src/include
	
AM_CXXFLAGS = $(GEN_FLAGS) $(DEF_FLAGS) -std=gnu++11

BOTLIBS = -ldl
# -Wl,-E is required for programs that load plugin's
BOTFLAGS = -Wl,-E

plugin_include_HEADERS = \
	$(srcdir)/include/skivvy-rconics/plugin-rconics.h \
	$(srcdir)/include/skivvy-rconics/plugin-rconics-rcon.h

plugin_library_LTLIBRARIES =  \
	skivvy-plugin-rconics.la

# IrcBot plugins
skivvy_plugin_rconics_la_SOURCES = plugin-rconics.cpp plugin-rconics-rcon.cpp
skivvy_plugin_rconics_la_LDFLAGS = -module

plugin_manuals_DATA = $(top_srcdir)/docs/rconics-manual.text

extra_DIST = $(top_srcdir)/docs/rconics-manual.text
