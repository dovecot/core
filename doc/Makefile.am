extra_dist_extra =

SUBDIRS = . example-config
DOCDIRS = example-config

docfiles = \
	thread-refs.txt \
	mkcert.sh \
	dovecot-openssl.cnf \
	solr-schema-7.7.0.xml \
	solr-config-7.7.0.xml \
	solr-config-9.xml \
	solr-schema-9.xml

DOCS_URL=https://$(DOVECOT_ASSET_URL)/$(DOVECOT_ASSET_VERSION)/docs.txz
MAN_URL=https://$(DOVECOT_ASSET_URL)/$(DOVECOT_ASSET_VERSION)/core.txz

AM_V_Q = $(am__v_Q_$(V))
am__v_Q_ = $(am__v_Q_$(AM_DEFAULT_VERBOSITY))
am__v_Q_0 = -q
am__v_Q_1 =

if INSTALL_DOCS
SUBDIRS += man
DOCDIRS += html
endif

extra_dist_extra += html stamp-html stamp-man
BUILT_SOURCES = stamp-html stamp-man

stamp-html:
	$(AM_V_at)$(WGET) -nv -O- $(DOCS_URL) | xz -d | $(am__untar) && \
		touch stamp-html || rm -f stamp-html

stamp-man:
	$(AM_V_at)$(WGET) -nv -O- $(MAN_URL) | xz -d | $(am__untar) && \
		touch stamp-man || rm -f stamp-man

all-local: html

html-local: stamp-html stamp-man

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
	$(extra_dist_extra) \
	$(docfiles)

distclean-local:
	-if test "$(extra_dist_extra)" != ""; then \
		rm -rf $(extra_dist_extra); \
	fi
