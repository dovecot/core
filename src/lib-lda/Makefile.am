noinst_LIBRARIES = liblda.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage

liblda_a_SOURCES = \
	lda-settings.c \
	duplicate.c \
	mail-deliver.c \
	mail-send.c \
	smtp-client.c

headers = \
	lda-settings.h \
	duplicate.h \
	mail-deliver.h \
	mail-send.h \
	smtp-client.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
