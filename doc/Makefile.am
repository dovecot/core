if BUILD_DOCS
DOCDIRS = wiki example-config
endif

SUBDIRS = man $(DOCDIRS)

docfiles = \
	documentation.txt \
	securecoding.txt \
	thread-refs.txt \
	mkcert.sh \
	dovecot-openssl.cnf \
	solr-schema.xml \
	solr-schema-7.7.0.xml \
	solr-config-7.7.0.xml

if BUILD_DOCS
doc_DATA = $(docfiles)
endif

EXTRA_DIST = \
	dovecot-initd.sh \
	$(docfiles)
