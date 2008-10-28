noinst_LIBRARIES = libstorage_shared.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-DPKG_RUNDIR=\""$(rundir)"\"

libstorage_shared_a_SOURCES = \
	shared-list.c \
	shared-storage.c

headers = \
	shared-storage.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-storage/index/shared
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
