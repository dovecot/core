if BUILD_DOCS
DOCS = doc
endif

SUBDIRS = \
	src \
	$(DOCS)

confdir = $(sysconfdir)
conf_DATA = dovecot-example.conf

EXTRA_DIST = \
	COPYING.LGPL \
	COPYING.MIT \
	$(conf_DATA)

if INSTALL_HEADERS
  pkginclude_HEADERS = config.h
  pkglib_DATA = dovecot-config
else
  noinst_HEADERS = $(headers)
  noinst_DATA = dovecot-config
endif

dovecot-config: dovecot-config.in Makefile
	cat dovecot-config.in | sed \
	-e "s|^moduledir=|moduledir=$(moduledir)|" \
	-e "s|^dovecot_incdir=|dovecot_incdir=$(pkgincludedir)|" > dovecot-config

CLEANFILES = $(noinst_DATA)

