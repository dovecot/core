SUBDIRS = . example-config man
DOCDIRS = example-config

docfiles = \
	thread-refs.txt \
	mkcert.sh \
	dovecot-openssl.cnf \
	solr-schema-7.7.0.xml \
	solr-config-7.7.0.xml \
	solr-config-9.xml \
	solr-schema-9.xml \
	index.html

MAN_URL=https://$(DOVECOT_ASSET_URL)/$(DOVECOT_ASSET_VERSION)/core.txz

AM_V_Q = $(am__v_Q_$(V))
am__v_Q_ = $(am__v_Q_$(AM_DEFAULT_VERBOSITY))
am__v_Q_0 = -q
am__v_Q_1 =

stamp-man:
	$(AM_V_at)$(WGET) -nv -O- $(MAN_URL) | xz -d | $(am__untar) && \
		touch stamp-man || rm -f stamp-man

all-local: stamp-man

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(docdir); \
	for dir in $(DOCDIRS); do \
	  cp -fpR $$dir $(DESTDIR)$(docdir); \
	done

uninstall-local:
	-for dir in $(DOCDIRS); do \
	  rm -rf $(DESTDIR)$(docdir)/$$dir; \
	done

doc_DATA = $(docfiles)

EXTRA_DIST = \
	dovecot-initd.sh \
	stamp-man \
	$(docfiles)

distclean-local:
	-rm -f stamp-man
