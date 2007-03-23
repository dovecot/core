docdir = $(datadir)/doc/dovecot

confdir = $(sysconfdir)
conf_DATA = \
	dovecot-ldap-example.conf \
	dovecot-sql-example.conf

doc_DATA = \
	USE-WIKI-INSTEAD \
	auth-protocol.txt \
	securecoding.txt \
	variables.txt

EXTRA_DIST = \
	mkcert.sh \
	dovecot-openssl.cnf \
	$(doc_DATA) \
	$(conf_DATA)
