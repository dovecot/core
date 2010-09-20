noinst_LTLIBRARIES = liblda.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage

liblda_la_SOURCES = \
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

deps=../lib-storage/libdovecot-storage.la ../lib-dovecot/libdovecot.la

pkglib_LTLIBRARIES = libdovecot-lda.la
libdovecot_lda_la_SOURCES = 
libdovecot_lda_la_LIBADD = liblda.la $(deps)
libdovecot_lda_la_DEPENDENCIES = liblda.la $(deps)
libdovecot_lda_la_LDFLAGS = -export-dynamic
