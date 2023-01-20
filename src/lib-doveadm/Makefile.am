noinst_LTLIBRARIES = libdoveadm.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth-client \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-ssl-iostream

libdoveadm_la_SOURCES = \
	doveadm-client.c \
	doveadm-protocol.c

headers = \
	doveadm-client.h \
	doveadm-protocol.h

# Internally, the methods yield via lua_yieldk() as implemented in Lua
# 5.3 and newer.
if DLUA_WITH_YIELDS
noinst_LTLIBRARIES += libdoveadm_client_lua.la

libdoveadm_client_lua_la_SOURCES = \
	doveadm-client-lua.c
libdoveadm_client_lua_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(LUA_CFLAGS) \
	-I$(top_srcdir)/src/lib-lua
libdoveadm_client_lua_la_LIBADD =
libdoveadm_client_lua_la_DEPENDENCIES = \
	libdoveadm.la

headers += \
	doveadm-client-lua.h
endif

pkginc_libdir = $(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
