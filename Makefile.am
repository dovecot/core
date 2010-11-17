aclocaldir = $(datadir)/aclocal

SUBDIRS = \
	. \
	src \
	doc

dist_pkginclude_HEADERS = \
	dovecot-version.h

EXTRA_DIST = \
	COPYING.LGPL \
	COPYING.MIT \
	ChangeLog \
	is-tagged.py \
	run-test.sh \
	update-version.sh \
	$(conf_DATA)

datafiles = \
	dovecot-config

nodist_pkginclude_HEADERS = config.h
pkglib_DATA = $(datafiles)

if MAINTAINER_MODE
ChangeLog: .hg/dirstate
	hg log -r tip:fef8259e7277 --style=changelog > ChangeLog
endif

aclocal_DATA = dovecot.m4

dovecot-version.h: noop
	$(SHELL) $(top_srcdir)/update-version.sh $(top_srcdir) $(top_builddir)

noop:

dovecot-config: dovecot-config.in Makefile
	old=`pwd` && cd $(top_builddir) && abs_builddir=`pwd` && cd $$old && \
	cd $(top_srcdir) && abs_srcdir=`pwd` && cd $$old && \
	cat dovecot-config.in | sed \
	-e "s|\$$(top_builddir)|$$abs_builddir|g" \
	-e "s|\$$(incdir)|$$abs_srcdir|g" \
	-e "s|\$$(LIBICONV)|$(LIBICONV)|g" \
	-e "s|^\(dovecot_pkgincludedir\)=|\1=$(pkgincludedir)|" \
	-e "s|^\(dovecot_pkglibdir\)=|\1=$(pkglibdir)|" \
	-e "s|^\(dovecot_pkglibexecdir\)=|\1=$(libexecdir)/dovecot|" \
	-e "s|^\(dovecot_docdir\)=|\1=$(docdir)|" \
	-e "s|^\(dovecot_moduledir\)=|\1=$(moduledir)|" \
	> dovecot-config

if HAVE_SYSTEMD
%.service: %.service.in
	$(AM_V_GEN)sed -e 's,@sbindir\@,$(sbindir),g' $< > $@

systemdsystemunit_DATA = \
        dovecot.socket \
        dovecot.service
else
EXTRA_DIST += dovecot.socket dovecot.service.in
endif

install-exec-hook:
	rm $(DESTDIR)$(pkglibdir)/dovecot-config && \
	grep -v '^LIBDOVECOT_.*_INCLUDE' dovecot-config | \
	grep -v '^LIBDOVECOT.*_DEPS' | sed \
	-e "s|^\(LIBDOVECOT\)=.*$$|\1='-L$(pkglibdir) -ldovecot'|" \
	-e "s|^\(LIBDOVECOT_LOGIN\)=.*$$|\1=-ldovecot-login|" \
	-e "s|^\(LIBDOVECOT_SQL\)=.*$$|\1=-ldovecot-sql|" \
	-e "s|^\(LIBDOVECOT_LDA\)=.*$$|\1=-ldovecot-lda|" \
	-e "s|^\(LIBDOVECOT_STORAGE\)=.*$$|\1=-ldovecot-storage|" \
	-e "s|^\(LIBDOVECOT_INCLUDE\)=.*$$|\1=-I$(pkgincludedir)|" \
	> $(DESTDIR)$(pkglibdir)/dovecot-config

CLEANFILES = $(datafiles)
if HAVE_SYSTEMD
CLEANFILES += $systedmsystemunit_DATA
endif

DISTCLEANFILES = $(top_builddir)/dovecot-version.h

distcheck-hook:
	if which scan-build > /dev/null; then \
	  cd $(distdir)/_build; \
	  scan-build -o scan-reports ../configure --with-ldap=auto --with-pgsql=auto --with-mysql=auto --with-sqlite=auto --with-solr=auto --with-gssapi=auto --with-libwrap=auto; \
	  rm -rf scan-reports; \
	  scan-build -o scan-reports make 2>&1 || exit 1; \
	  if ! rmdir scan-reports 2>/dev/null; then \
	    exit 1; \
	  fi; \
	  cd ../..; rm -rf $(distdir)/_build/*; \
	fi
