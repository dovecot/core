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
	solr-schema.xml

if BUILD_DOCS
doc_DATA = $(docfiles)
endif

EXTRA_DIST = \
	dovecot-initd.sh \
	$(docfiles)
