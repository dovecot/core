pkglib_LTLIBRARIES = libdovecot.la

libdovecot_la_SOURCES =

libdovecot_la_LIBADD = \
	$(LIBDOVECOT_LA_LIBS) \
	$(MODULE_LIBS) \
	$(ZLIB_LIBS_STATIC) \
	$(ZLIB_LIBS) \
	$(LIBPCRE_LIBS_STATIC) \
	$(LIBPCRE_LIBS) \
	$(RELRO_LDFLAGS)

libdovecot_la_DEPENDENCIES = $(LIBDOVECOT_LA_LIBS)
libdovecot_la_LDFLAGS = -export-dynamic
