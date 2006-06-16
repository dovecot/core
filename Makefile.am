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

noinst_DATA = dovecot-config

dovecot-config: dovecot-config.in
	cat dovecot-config.in|sed "s|moduledir=|moduledir=$(moduledir)|" > dovecot-config

CLEANFILES = $(noinst_DATA)

