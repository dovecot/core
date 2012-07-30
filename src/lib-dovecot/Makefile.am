libs = \
	../lib-settings/libsettings.la \
	../lib-dict/libdict.la \
	../lib-imap/libimap.la \
	../lib-mail/libmail.la \
	../lib-auth/libauth.la \
	../lib-dns/libdns.la \
	../lib-fs/libfs.la \
	../lib-charset/libcharset.la \
	../lib-master/libmaster.la \
	../lib/liblib.la

ssl_libs = \
	../lib-master/libmaster_ssl.la \
	../lib-ssl-iostream/libssl_iostream.la

pkglib_LTLIBRARIES = libdovecot.la libdovecot-ssl.la

libdovecot_la_SOURCES = 
libdovecot_ssl_la_SOURCES = 

libdovecot_la_LIBADD = \
	$(libs) \
	$(MODULE_LIBS) \
	$(LTLIBICONV)

libdovecot_ssl_la_LIBADD = \
	$(ssl_libs) \
	$(SSL_LIBS)

libdovecot_la_DEPENDENCIES = $(libs)
libdovecot_ssl_la_DEPENDENCIES = $(ssl_libs)

libdovecot_la_LDFLAGS = -export-dynamic
libdovecot_ssl_la_LDFLAGS = -export-dynamic
