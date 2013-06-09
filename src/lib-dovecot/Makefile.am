# when adding libraries, update LIBDOVECOT also in configure.in
libs = \
	../lib-master/libmaster.la \
	../lib-fs/libfs.la \
	../lib-settings/libsettings.la \
	../lib-http/libhttp.la \
	../lib-dict/libdict.la \
	../lib-imap/libimap.la \
	../lib-mail/libmail.la \
	../lib-sasl/libsasl.la \
	../lib-auth/libauth.la \
	../lib-dns/libdns.la \
	../lib-charset/libcharset.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-test/libtest.la \
	../lib/liblib.la

pkglib_LTLIBRARIES = libdovecot.la

libdovecot_la_SOURCES = 

libdovecot_la_LIBADD = \
	$(libs) \
	$(MODULE_LIBS) \
	$(LTLIBICONV)

libdovecot_la_DEPENDENCIES = $(libs)
libdovecot_la_LDFLAGS = -export-dynamic
