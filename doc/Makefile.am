if BUILD_DOCS
DOCDIRS = wiki example-config
endif

SUBDIRS = man $(DOCDIRS)

docfiles = \
	auth-protocol.txt \
	documentation.txt \
	securecoding.txt \
	thread-refs.txt

if BUILD_DOCS
doc_DATA = $(docfiles)
endif

EXTRA_DIST = \
	dovecot-initd.sh \
	mkcert.sh \
	dovecot-openssl.cnf \
	solr-schema.xml \
	$(docfiles)
