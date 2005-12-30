if BUILD_DOCS
DOCS = doc
endif

SUBDIRS = \
	src \
	$(DOCS)

confdir = $(sysconfdir)
conf_DATA = dovecot-example.conf

EXTRA_DIST = \
	dovecot.spec \
	dovecot.spec.in \
	COPYING.LGPL \
	COPYING.MIT \
	$(conf_DATA)
