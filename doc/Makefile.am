extra_dist_extra =

SUBDIRS = . man example-config
DOCDIRS = example-config
BUILT_SOURCES = html mans

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
extra_dist_extra += html man
documentation_sources = $(top_srcdir)/doc/documentation-main

.NOTPARALLEL: html mans

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

prep-mans:
	-$(AM_V_at)$(MAKE) -C $(documentation_sources)/source/man \
	  V=$(V) pkgsysconfdir=$(sysconfdir) \
	  rundir=$(rundir) \
	  pkglibexecdir=$(pkglibexecdir) \
	  AM_DEFAULT_VERBOSITY=$(AM_DEFAULT_VERBOSITY)

mans: venv prep-mans
	$(AM_V_GEN)test -f man/dovecot.1 || venv/bin/python -msphinx $(AM_V_Q) \
	  -b man $(documentation_sources)/source man

html: venv prep-mans
	$(AM_V_GEN)test -f html/index.html || venv/bin/python -msphinx $(AM_V_Q) \
	  -b html $(documentation_sources)/source html

else # if HAVE_VENV

html:
	if [ ! -e html/index.html ]; then \
	  echo "Building html documentation needs python installed"; \
	fi

mans:
	if [ ! -e man/dovecot.1 ]; then \
	  echo "Building manpages needs python installed"; \
	fi

endif # if HAVE_VENV

# explicit hook for make dist
# remove all the build artifacts before packaging
# NB: this is ran too late to build anything here.
dist-hook:
	-rm -rf $(distdir)/html/.buildinfo
	-rm -rf $(distdir)/html/.doctrees
	-rm -rf $(distdir)/html/_sources
	-rm -rf $(distdir)/html/objects.inv
	-rm -rf $(distdir)/man/.doctrees

clean-local:
	-rm -rf venv
	-rm -rf $(documentation_sources)

rebuild:
	-rm -rf html
	$(MAKE) -C man $@

distclean-local: clean-local rebuild

maintainer-clean: distclean-local

endif # if INSTALL_DOCS

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
