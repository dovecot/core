SUBDIRS = conf.d

exampledir = $(docdir)/example-config
example_DATA = \
	dovecot.conf \
	dovecot-db.conf \
	dovecot-dict-sql.conf \
	dovecot-ldap.conf \
	dovecot-sql.conf

EXTRA_DIST = \
	$(example_DATA)

install-data-local:
	$(mkdir_p) $(DESTDIR)/$(sysconfdir)/dovecot
