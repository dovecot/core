aclocaldir = $(datadir)/aclocal
ACLOCAL_AMFLAGS = -I m4

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
	README \
	README.md \
	INSTALL \
	INSTALL.md \
	update-version.sh \
	run-test-valgrind.supp \
	$(conf_DATA)

noinst_DATA = dovecot-config

nodist_pkginclude_HEADERS = config.h

README: README.md
	$(PANDOC) -f markdown_github -t plain -o $@ $<

INSTALL: INSTALL.md
	$(PANDOC) -f markdown_github -t plain -o $@ $<

ChangeLog:
	git log --name-status --pretty="format:%ai %aN <%aE> (%h)%n%n%w(80,4,4)%s%n%n%b" 5d5c4f2bfb812c767084c0338dae692db476da10^.. > ChangeLog || rm -f ChangeLog

aclocal_DATA = m4/dovecot.m4

dovecot-version.h: noop
	$(SHELL) $(top_srcdir)/update-version.sh $(top_srcdir) $(top_builddir)

noop:

dovecot-config: dovecot-config.in Makefile
	old=`pwd` && cd $(top_builddir) && abs_builddir=`pwd` && cd $$old && \
	cd $(top_srcdir) && abs_srcdir=`pwd` && cd $$old && \
	(echo "DOVECOT_INSTALLED=no"; cat dovecot-config.in | sed \
	-e "s|\$$(top_builddir)|$$abs_builddir|g" \
	-e "s|\$$(incdir)|$$abs_srcdir|g" \
	-e "s|\$$(LIBICONV)|$(LIBICONV)|g" \
	-e "s|\$$(MODULE_LIBS)|$(MODULE_LIBS)|g" \
	-e "s|^\(dovecot_pkgincludedir\)=|\1=$(pkgincludedir)|" \
	-e "s|^\(dovecot_pkglibdir\)=|\1=$(pkglibdir)|" \
	-e "s|^\(dovecot_pkglibexecdir\)=|\1=$(libexecdir)/dovecot|" \
	-e "s|^\(dovecot_docdir\)=|\1=$(docdir)|" \
	-e "s|^\(dovecot_moduledir\)=|\1=$(moduledir)|" \
	-e "s|^\(dovecot_statedir\)=|\1=$(statedir)|" \
	) > dovecot-config

if HAVE_SYSTEMD
%.service: %.service.in
	$(AM_V_GEN)sed -e 's,@sbindir\@,$(sbindir),g' -e 's,@bindir\@,$(bindir),g' -e 's,@rundir\@,$(rundir),g' $< > $@

systemdsystemunit_DATA = \
        dovecot.socket \
        dovecot.service
else
EXTRA_DIST += dovecot.socket dovecot.service.in
endif

install-exec-hook:
	$(mkdir_p) $(DESTDIR)$(pkglibdir); \
	grep -v '^LIBDOVECOT_.*_INCLUDE' dovecot-config | \
	grep -v '^LIBDOVECOT.*_DEPS' | sed \
	-e "s|^\(DOVECOT_INSTALLED\)=.*$$|\1=yes|" \
	-e "s|^\(LIBDOVECOT\)=.*$$|\1='-L$(pkglibdir) -ldovecot'|" \
	-e "s|^\(LIBDOVECOT_LOGIN\)=.*$$|\1='-ldovecot-login $(SSL_LIBS)'|" \
	-e "s|^\(LIBDOVECOT_SQL\)=.*$$|\1=-ldovecot-sql|" \
	-e "s|^\(LIBDOVECOT_COMPRESS\)=.*$$|\1=-ldovecot-compression|" \
	-e "s|^\(LIBDOVECOT_DSYNC\)=.*$$|\1=-ldovecot-dsync|" \
	-e "s|^\(LIBDOVECOT_LDA\)=.*$$|\1=-ldovecot-lda|" \
	-e "s|^\(LIBDOVECOT_LIBFTS\)=.*$$|\1=-ldovecot-fts|" \
	-e "s|^\(LIBDOVECOT_STORAGE\)=.*$$|\1='-ldovecot-storage $(LINKED_STORAGE_LDADD)'|" \
	-e "s|^\(LIBDOVECOT_INCLUDE\)=.*$$|\1=-I$(pkgincludedir)|" \
	> $(DESTDIR)$(pkglibdir)/dovecot-config

uninstall-hook:
	rm $(DESTDIR)$(pkglibdir)/dovecot-config

if HAVE_SYSTEMD
CLEANFILES = $(systemdsystemunit_DATA)
endif

DISTCLEANFILES = \
	$(top_builddir)/dovecot-version.h \
	$(top_builddir)/dovecot-config \
	$(top_builddir)/run-test.sh

distcheck-hook:
	if which scan-build > /dev/null; then \
	  cd $(distdir)/_build; \
	  scan-build -o scan-reports ../configure --with-ldap=auto --with-pgsql=auto --with-mysql=auto --with-sqlite=auto --with-solr=auto --with-gssapi=auto --with-libwrap=auto; \
	  rm -rf scan-reports; \
	  scan-build -o scan-reports make 2>&1 || exit 1; \
	  if ! rmdir scan-reports 2>/dev/null; then \
	    exit 1; \
	  fi; \
	  make distclean; \
	fi
