AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-http \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-master \
	$(LUA_CFLAGS)

pkglib_LTLIBRARIES = libdovecot-lua.la
libdovecot_lua_la_SOURCES = \
	dlua-script.c \
	dlua-pushstring.c \
	dlua-error.c \
	dlua-dovecot.c \
	dlua-dovecot-http.c \
	dlua-compat.c \
	dlua-resume.c \
	dlua-table.c \
	dlua-thread.c

test_programs = test-lua

LIBDICT_LUA=
if DLUA_WITH_YIELDS
LIBDICT_LUA += \
	../lib-dict/libdict_lua.la \
	../lib-dns/libdns_lua.la
test_programs += \
	test-dict-lua \
	test-dns-lua
endif

# Note: the only things this lib should depend on are libdovecot and lua.
libdovecot_lua_la_DEPENDENCIES = \
	../lib-dovecot/libdovecot.la \
	$(LIBDICT_LUA)
libdovecot_lua_la_LIBADD = \
	../lib-dovecot/libdovecot.la \
	$(LIBDICT_LUA) \
	$(LUA_LIBS)
libdovecot_lua_la_LDFLAGS = -export-dynamic

headers = \
	dlua-compat.h \
	dlua-script.h \
	dlua-script-private.h \
	dlua-wrapper.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

noinst_PROGRAMS = $(test_programs)

test_libs =\
 libdovecot-lua.la \
 ../lib-dovecot/libdovecot.la

test_lua_SOURCES = test-lua.c
test_lua_CFLAGS = $(AM_CPPFLAGS) $(BINARY_CFLAGS)
test_lua_LDFLAGS = $(BINARY_LDFLAGS)
test_lua_LDADD = $(test_libs) $(LUA_LIBS)
test_lua_DEPENDENCIES = $(test_libs)

test_dict_lua_SOURCES = test-dict-lua.c
test_dict_lua_LDADD = $(test_libs) $(LUA_LIBS)
test_dict_lua_DEPENDENCIES = $(test_libs)

test_dns_lua_SOURCES = test-dns-lua.c
test_dns_lua_LDADD = $(test_libs) $(LUA_LIBS)
test_dns_lua_DEPENDENCIES = $(test_libs)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
