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
	ChangeLog \
	$(conf_DATA)

datafiles = \
	dovecot-config

if INSTALL_HEADERS
  pkginclude_HEADERS = config.h
  pkglib_DATA = $(datafiles)
else
  noinst_DATA = $(datafiles)
endif

if MAINTAINER_MODE
ChangeLog: .hg/dirstate
	hg log --style=changelog > ChangeLog
endif

dovecot-config: dovecot-config.in Makefile
	cat dovecot-config.in | sed \
	-e "s|^moduledir=|moduledir=$(moduledir)|" \
	-e "s|^dovecot_incdir=|dovecot_incdir=$(pkgincludedir)|" > dovecot-config

CLEANFILES = $(datafiles)

