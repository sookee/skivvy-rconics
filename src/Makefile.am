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
