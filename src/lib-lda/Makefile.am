noinst_LIBRARIES = liblda.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage

liblda_a_SOURCES = \
	duplicate.c \
	lda-settings.c \
	lmtp-client.c \
	mail-deliver.c \
	mail-send.c \
	smtp-client.c

headers = \
	duplicate.h \
	lda-settings.h \
	lmtp-client.h \
	mail-deliver.h \
	mail-send.h \
	smtp-client.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
