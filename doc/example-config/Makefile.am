SUBDIRS = conf.d

pkgsysconfdir = $(sysconfdir)/dovecot
nodist_pkgsysconf_DATA = README
# nodist_ prefix just doesn't seem to work, so rm it directly:
dist-hook:
	rm -f $(distdir)/README

README: README.in Makefile
	$(AM_V_GEN)cat $(srcdir)/README.in | sed "s|@exampledir@|$(exampledir)|" > README

exampledir = $(docdir)/example-config
example_DATA = \
	dovecot.conf \
	dovecot-dict-auth.conf.ext \
	dovecot-dict-sql.conf.ext \
	dovecot-ldap.conf.ext \
	dovecot-oauth2.conf.ext \
	dovecot-sql.conf.ext

EXTRA_DIST = \
	$(example_DATA) \
	README.in

install-data-local:
	$(mkdir_p) $(DESTDIR)/$(pkgsysconfdir)

CLEANFILES = README
