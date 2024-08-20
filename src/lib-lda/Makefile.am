noinst_LTLIBRARIES = liblda.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-smtp \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-smtp \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-var-expand

liblda_la_SOURCES = \
	lda-settings.c \
	mail-deliver.c \
	mail-send.c

headers = \
	lda-settings.h \
	mail-deliver.h \
	mail-send.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

pkglib_LTLIBRARIES = libdovecot-lda.la
libdovecot_lda_la_SOURCES =
libdovecot_lda_la_LIBADD = liblda.la $(LIBDOVECOT_STORAGE) $(LIBDOVECOT)
libdovecot_lda_la_DEPENDENCIES = liblda.la $(LIBDOVECOT_STORAGE_DEPS) $(LIBDOVECOT_DEPS)
libdovecot_lda_la_LDFLAGS = -export-dynamic


