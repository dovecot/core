pkglib_LTLIBRARIES = libdovecot-gssapi.la

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
