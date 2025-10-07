pkglib_LTLIBRARIES = libdovecot.la libdovecot-gssapi.la

libdovecot_la_SOURCES =

libdovecot_la_LIBADD = \
	$(LIBDOVECOT_LA_LIBS) \
	$(MODULE_LIBS) \
	$(LIBPCRE_LIBS) \
	$(RELRO_LDFLAGS)

libdovecot_la_DEPENDENCIES = $(LIBDOVECOT_LA_LIBS)
libdovecot_la_LDFLAGS = -export-dynamic

if HAVE_GSSAPI
libdovecot_gssapi_la_CPPFLAGS = $(AM_CPPFLAGS) $(KRB5_CFLAGS)
libdovecot_gssapi_la_SOURCES =
libdovecot_gssapi_la_LIBADD = \
	$(top_builddir)/src/lib-sasl/libsasl-gssapi.la \
	$(top_builddir)/src/lib-auth/libauth-gssapi.la \
	$(MODULE_LIBS) \
	$(KRB5_LIBS) \
	$(RELRO_LDFLAGS)
libdovecot_gssapi_la_DEPENDENCIES = \
	$(top_builddir)/src/lib-sasl/libsasl-gssapi.la \
	$(top_builddir)/src/lib-auth/libauth-gssapi.la
libdovecot_gssapi_la_LDFLAGS = -export-dynamic
endif
