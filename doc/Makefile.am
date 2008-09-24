SUBDIRS = wiki

confdir = $(sysconfdir)
conf_DATA = \
	dovecot-db-example.conf \
	dovecot-dict-sql-example.conf \
	dovecot-ldap-example.conf \
	dovecot-sql-example.conf

doc_DATA = \
	auth-protocol.txt \
	documentation.txt \
	securecoding.txt

EXTRA_DIST = \
	mkcert.sh \
	dovecot-openssl.cnf \
	solr-schema.xml \
	$(doc_DATA) \
	$(conf_DATA)
