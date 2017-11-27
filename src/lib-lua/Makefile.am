noinst_LTLIBRARIES = libdovecot-lua.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	$(LUA_CFLAGS)

libdovecot_lua_la_SOURCES = \
	dlua-script.c \
	dlua-dovecot.c \
	dlua-compat.c
libdovecot_lua_la_DEPENDENCIES = ../lib-dovecot/libdovecot.la $(LUA_LIBS)
libdovecot_lua_la_LIBADD = ../lib-dovecot/libdovecot.la $(LUA_LIBS)

headers = \
	dlua-script.h \
	dlua-script-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = test-lua

noinst_PROGRAMS = $(test_programs)

test_libs =\
 libdovecot-lua.la \
 ../lib-dovecot/libdovecot.la

test_lua_SOURCES = test-lua.c
test_lua_CFLAGS = $(AM_CPPFLAGS) $(BINARY_CFLAGS)
test_lua_LDFLAGS = $(BINARY_LDFLAGS)
test_lua_LDADD = $(test_libs)
test_lua_DEPENDENCIES = $(test_libs)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
