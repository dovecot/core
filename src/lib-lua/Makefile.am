AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-doveadm \
	-I$(top_srcdir)/src/lib-dns-client \
	-I$(top_srcdir)/src/lib-http \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-var-expand \
	$(LUA_CFLAGS)

noinst_LTLIBRARIES = libdlua.la
libdlua_la_SOURCES = \
	dlua-script.c \
	dlua-pushstring.c \
	dlua-error.c \
	dlua-dovecot.c \
	dlua-dovecot-http.c \
	dlua-compat.c \
	dlua-resume.c \
	dlua-table.c \
	dlua-thread.c

test_programs = test-lua test-lua-http-client

WITH_YIELDS_LUA=
if DLUA_WITH_YIELDS
WITH_YIELDS_LUA += \
	../lib-doveadm/libdoveadm_client_lua.la \
	../lib-dict/libdict_lua.la \
	../lib-dns-client/libdns_lua.la
test_programs += \
	test-dict-lua \
	test-dns-lua
endif

libdlua_la_LIBADD = $(WITH_YIELDS_LUA) $(LUA_LIBS)
libdlua_la_DEPENDENCIES = $(WITH_YIELDS_LUA)

pkglib_LTLIBRARIES = libdovecot-lua.la
libdovecot_lua_la_SOURCES =
# Note: the only things this lib should depend on are libdovecot and lua.
libdovecot_lua_la_DEPENDENCIES = \
	libdlua.la \
	$(LIBDOVECOT_DEPS)
libdovecot_lua_la_LIBADD = \
	libdlua.la \
	$(LIBDOVECOT)
libdovecot_lua_la_LDFLAGS = -export-dynamic

headers = \
	dlua-compat.h \
	dlua-script.h \
	dlua-script-private.h \
	dlua-wrapper.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

EXTRA_DIST = \
	test-lua-http-client.lua

noinst_PROGRAMS = $(test_programs)

test_libs_ssl = ../lib-ssl-iostream/libssl_iostream_openssl.la

test_lua_SOURCES = test-lua.c
test_lua_CFLAGS = $(AM_CPPFLAGS) $(BINARY_CFLAGS)
test_lua_LDFLAGS = $(BINARY_LDFLAGS)
test_lua_LDADD = libdlua.la $(LIBDOVECOT) $(LUA_LIBS)
test_lua_DEPENDENCIES = libdlua.la $(LIBDOVECOT_DEPS)

test_dict_lua_SOURCES = test-dict-lua.c
test_dict_lua_LDADD = libdlua.la $(LIBDOVECOT) $(LUA_LIBS)
test_dict_lua_DEPENDENCIES = libdlua.la $(LIBDOVECOT_DEPS)

test_dns_lua_SOURCES = test-dns-lua.c
test_dns_lua_LDADD = libdlua.la $(LIBDOVECOT) $(LUA_LIBS)
test_dns_lua_DEPENDENCIES = libdlua.la $(LIBDOVECOT_DEPS)

test_lua_http_client_SOURCES = test-lua-http-client.c
test_lua_http_client_LDADD = libdlua.la $(LIBDOVECOT) $(test_libs_ssl) $(LUA_LIBS)
test_lua_http_client_DEPENDENCIES = libdlua.la $(LIBDOVECOT_DEPS)
test_lua_http_client_CFLAGS = \
	$(AM_CPPFLAGS) \
	$(DOVECOT_BINARY_CFLAGS) \
	-DTEST_LUA_SCRIPT_DIR=\"$(abs_top_srcdir)/src/lib-lua\"

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
