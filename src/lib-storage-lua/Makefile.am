AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-var-expand \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	$(LUA_CFLAGS) \
	-I$(top_srcdir)/src/lib-lua

pkglib_LTLIBRARIES = libdovecot-storage-lua.la
libdovecot_storage_lua_la_SOURCES = \
	mail-lua.c \
	mail-user-lua.c \
	mail-storage-lua.c \
	mailbox-lua.c \
	mailbox-attribute-lua.c
libdovecot_storage_lua_la_LIBADD = \
	../lib-dovecot-storage/libdovecot-storage.la \
	../lib-lua/libdovecot-lua.la
libdovecot_storage_lua_la_DEPENDENCIES = \
	../lib-dovecot-storage/libdovecot-storage.la \
	../lib-lua/libdovecot-lua.la
libdovecot_storage_lua_la_LDFLAGS = -export-dynamic

headers = \
	mail-storage-lua.h \
	mail-storage-lua-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
