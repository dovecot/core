extra_dist_extra =

SUBDIRS = . example-config
DOCDIRS = example-config

docfiles = \
	thread-refs.txt \
	mkcert.sh \
	dovecot-openssl.cnf \
	solr-schema.xml \
	solr-schema-7.7.0.xml \
	solr-config-7.7.0.xml

DOCS_URL=https://doc.dovecot.org/assets/3.0/docs.txz
MAN_URL=https://doc.dovecot.org/assets/3.0/man.txz

AM_V_Q = $(am__v_Q_$(V))
am__v_Q_ = $(am__v_Q_$(AM_DEFAULT_VERBOSITY))
am__v_Q_0 = -q
am__v_Q_1 =

if INSTALL_DOCS
SUBDIRS += man
DOCDIRS += html
endif

extra_dist_extra += html

html-dl:
	$(AM_V_at)$(WGET) -nv -O- $(DOCS_URL) | xz -d | $(am__untar)

man-dl:
	$(AM_V_at)$(WGET) -nv -O- $(MAN_URL) | xz -d | $(am__untar)

all-local: html

html-local:
	$(AM_V_at)if [ ! -e html/index.html ]; then \
		$(MAKE) html-dl; \
	fi
	$(AM_V_at)if [ ! -e man/dovecot.1 ]; then \
		$(MAKE) man-dl; \
	fi

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(docdir); \
	for dir in $(DOCDIRS); do \
	  cp -nrf $$dir $(DESTDIR)$(docdir); \
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
