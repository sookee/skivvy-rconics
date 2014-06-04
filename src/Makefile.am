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

plugin_includedir = $(includedir)/skivvy
plugin_librarydir = $(libdir)/skivvy
plugin_manualsdir = $(mandir)/skivvy

INC_SOOKEE = -I$(prefix)/include
LIB_SOOKEE = -L$(prefix)/lib/sookee -lsookee

INC_SKIVVY = -I$(prefix)/include
LIB_SKIVVY = -L$(prefix)/lib/skivvy -lskivvy

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
	
AM_CPPFLAGS = $(INC_SOOKEE) $(INC_SKIVVY)
AM_CXXFLAGS = $(GEN_FLAGS) $(DEF_FLAGS) -std=gnu++11

# -Wl,-E is required for programs that load plugin's
PLUGIN_FLAGS = -Wl,-E

plugin_include_HEADERS = \
	$(srcdir)/include/skivvy/plugin-rconics.h \
	$(srcdir)/include/skivvy/plugin-rconics-rcon.h

plugin_library_LTLIBRARIES =  \
	skivvy-plugin-rconics.la

# IrcBot plugins
skivvy_plugin_rconics_la_SOURCES = plugin-rconics.cpp plugin-rconics-rcon.cpp
skivvy_plugin_rconics_la_LDFLAGS = -module -avoid-version $(PLUGIN_FLAGS)
skivvy_plugin_rconics_la_LIBADD =  $(LIB_SOOKEE) $(LIB_SKIVVY) -L.libs

plugin_manuals_DATA = $(top_srcdir)/docs/rconics-manual.text

extra_DIST = $(top_srcdir)/docs/rconics-manual.text

install-data-hook: $(plugin_library_LTLIBRARIES)
	for m in $(plugin_library_LTLIBRARIES); do \
		base=`echo $$m | sed 's/\..*//'`; \
		rm -f $(plugin_librarydir)/$$base.la; \
	done
