SUBDIRS = wiki

confdir = $(sysconfdir)
conf_DATA = \
	dovecot-ldap-example.conf \
	dovecot-sql-example.conf

doc_DATA = \
	auth-protocol.txt \
	documentation.txt \
	securecoding.txt

EXTRA_DIST = \
	mkcert.sh \
	dovecot-openssl.cnf \
	$(doc_DATA) \
	$(conf_DATA)
