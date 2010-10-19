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

pkglib_LTLIBRARIES = libdovecot.la

libdovecot_la_SOURCES = 

libdovecot_la_LIBADD = \
	$(libs) \
	$(MODULE_LIBS) \
	$(LTLIBICONV)

libdovecot_la_DEPENDENCIES = $(libs)

libdovecot_la_LDFLAGS = -export-dynamic
