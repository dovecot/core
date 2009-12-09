SUBDIRS = conf.d

dovecotconfdir = $(sysconfdir)/dovecot
dovecotconf_DATA = README

README: README.in Makefile
	cat README.in | sed "s|@exampledir@|$(exampledir)|" > README

exampledir = $(docdir)/example-config
example_DATA = \
	dovecot.conf \
	dovecot-db.conf.ext \
	dovecot-dict-sql.conf.ext \
	dovecot-ldap.conf.ext \
	dovecot-sql.conf.ext

EXTRA_DIST = \
	$(example_DATA)

install-data-local:
	$(mkdir_p) $(DESTDIR)/$(sysconfdir)/dovecot
