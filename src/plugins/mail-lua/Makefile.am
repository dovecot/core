AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-lua \
	$(LUA_CFLAGS)

NOPLUGIN_LDFLAGS =

module_LTLIBRARIES = \
	lib01_mail_lua_plugin.la

lib01_mail_lua_plugin_la_LDFLAGS = -module -avoid-version $(LUA_LIBS)
lib01_mail_lua_plugin_la_LIBADD = \
	../../lib-lua/libdovecot-lua.la \
	$(LIBDOVECOT)
lib01_mail_lua_plugin_la_SOURCES = \
	mail-lua-plugin.c \
	mail-storage-lua.c

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = \
	mail-lua-plugin.h \
	mail-storage-lua.h

test_programs =

check-local:
	for bin in $(test_programs); do \
	  if ! env $(test_options) $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

noinst_PROGRAMS = $(test_programs)
