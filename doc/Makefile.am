extra_dist_extra =

SUBDIRS = . man example-config
DOCDIRS = example-config

docfiles = \
	thread-refs.txt \
	mkcert.sh \
	dovecot-openssl.cnf \
	solr-schema.xml \
	solr-schema-7.7.0.xml \
	solr-config-7.7.0.xml

AM_V_Q = $(am__v_Q_$(V))
am__v_Q_ = $(am__v_Q_$(AM_DEFAULT_VERBOSITY))
am__v_Q_0 = -q
am__v_Q_1 =

if INSTALL_DOCS
if HAVE_VENV
extra_dist_extra += html
documentation_sources = documentation-main

# extracting the documentation tarball from github yields the
# "documentation-main" directory
$(documentation_sources)/requirements.txt:
	$(AM_V_GEN)wget $(AM_V_Q) -O - \
		https://github.com/dovecot/documentation/archive/refs/heads/main.tar.gz | \
	  gunzip | $(am__untar)

venv: $(documentation_sources)/requirements.txt
	$(AM_V_GEN)$(PYTHON) -m venv venv && \
		venv/bin/pip $(AM_V_Q) install wheel && \
		venv/bin/pip $(AM_V_Q) install -r "$(documentation_sources)/requirements.txt"

html: venv
	$(AM_V_GEN)venv/bin/python -msphinx $(AM_V_Q) -b html $(documentation_sources)/source html

else # if HAVE_VENV

html:
	if [ ! -e html/index.html ]; then echo "Building html documentation needs python installed"; fi

endif # if HAVE_VENV

# hack to build pages only if they're missing
all-local:
	if [ ! -e html/index.html ]; then $(MAKE) html; fi

# explicit hook for make dist
# remove all the build artifacts before packaging
dist-hook: html
	-rm -rf $(distdir)/html/.buildinfo
	-rm -rf $(distdir)/html/.doctrees
	-rm -rf $(distdir)/html/_sources
	-rm -rf $(distdir)/html/objects.inv

install-data-local:
	if [ ! -e html/index.html ]; then $(MAKE) html; fi
	cp -nrf html "$(DESTDIR)$(docdir)"

uninstall-local:
	-rm -rf "$(DESTDIR)$(docdir)/html"

clean-local:
	-rm -rf venv
	-rm -rf $(documentation_sources)

distclean-local: clean-local
	-rm -rf html

maintainer-clean: distclean-local

endif # if INSTALL_DOCS

doc_DATA = $(docfiles)

EXTRA_DIST = \
	dovecot-initd.sh \
	$(extra_dist_extra) \
	$(docfiles)
