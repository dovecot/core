noinst_LTLIBRARIES = libdns.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

libdns_la_SOURCES = \
	dns-lookup.c \
	dns-util.c

headers = \
	dns-lookup.h \
	dns-util.h

test_programs = \
	test-dns-lookup \
	test-dns-util

noinst_PROGRAMS = $(test_programs)

test_libs = \
	libdns.la  \
	../lib-test/libtest.la \
	../lib/liblib.la

test_dns_util_SOURCES = test-dns-util.c
test_dns_util_LDADD = $(test_libs)

test_dns_lookup_SOURCES = test-dns-lookup.c
test_dns_lookup_LDADD = $(test_libs)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done


pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

# Internally, the dns methods yield via lua_yieldk() as implemented in Lua
# 5.3 and newer.
if DLUA_WITH_YIELDS
noinst_LTLIBRARIES += libdns_lua.la

libdns_lua_la_SOURCES = \
	dns-lua.c
libdns_lua_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(LUA_CFLAGS) \
	-I$(top_srcdir)/src/lib-lua
libdns_lua_la_LIBADD =
libdns_lua_la_DEPENDENCIES = \
	libdns.la

headers += \
	dns-lua.h
endif
