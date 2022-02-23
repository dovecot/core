AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-http \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-doveadm \
	-I$(top_srcdir)/src/doveadm \
	-I$(top_srcdir)/src/plugins/fts \
	$(XAPIAN_CXXFLAGS)

AM_CXXFLAGS = \
	$(XAPIAN_CXXFLAGS)

lib21_fts_flatcurve_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib21_fts_flatcurve_plugin.la

if DOVECOT_PLUGIN_DEPS
fts_plugin_dep = ../fts/lib20_fts_plugin.la
endif

lib21_fts_flatcurve_plugin_la_LIBADD = \
	$(fts_plugin_dep) \
	$(XAPIAN_LIBS)

lib21_fts_flatcurve_plugin_la_SOURCES = \
	fts-flatcurve-plugin.c \
	fts-backend-flatcurve.c \
	fts-backend-flatcurve-xapian.cc

noinst_HEADERS = \
	doveadm-dump-flatcurve.h \
	fts-flatcurve-plugin.h \
	fts-backend-flatcurve.h \
	fts-backend-flatcurve-xapian.h

libdoveadm_fts_flatcurve_plugin_la_SOURCES = \
	doveadm-dump-flatcurve.c \
	doveadm-fts-flatcurve.c
libdoveadm_fts_flatcurve_plugin_la_LIBADD = $(LIBDOVECOT)
libdoveadm_fts_flatcurve_plugin_la_DEPENDENCIES = $(LIBDOVECOT_DEPS)
libdoveadm_fts_flatcurve_plugin_la_LDFLAGS = -module -avoid-version

doveadm_moduledir = $(moduledir)/doveadm
doveadm_module_LTLIBRARIES = \
	libdoveadm_fts_flatcurve_plugin.la