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
	README.md \
	INSTALL.md \
	update-version.sh \
	run-test-valgrind.supp \
	dovecot.service.in \
	dovecot.socket \
	version \
	$(conf_DATA)

noinst_DATA = dovecot-config

nodist_pkginclude_HEADERS = config.h

version:
	$(AM_V_GEN)$(top_srcdir)/build-aux/git-version-gen > $@

aclocal_DATA = m4/dovecot.m4

dovecot-version.h: noop
	$(AM_V_GEN)$(SHELL) $(top_srcdir)/update-version.sh $(top_srcdir) $(top_builddir)

noop:

dovecot-config: dovecot-config.in Makefile
	$(AM_V_GEN)old=`pwd` && cd $(top_builddir) && abs_builddir=`pwd` && cd $$old && \
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

%.service: %.service.in
	$(AM_V_GEN)sed -e 's,@sbindir\@,$(sbindir),g' \
	-e 's,@bindir\@,$(bindir),g' \
	-e 's,@rundir\@,$(rundir),g' \
	-e 's,@systemdservicetype\@,$(systemdservicetype),g' \
	$< > $@

if WANT_SYSTEMD
systemdsystemunit_DATA = \
        dovecot.socket \
        dovecot.service
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
	-e "s|^\(LIBDOVECOT_LUA\)=.*$$|\1=-ldovecot-lua|" \
	-e "s|^\(LIBDOVECOT_STORAGE\)=.*$$|\1='-ldovecot-storage $(LINKED_STORAGE_LDADD)'|" \
	-e "s|^\(LIBDOVECOT_INCLUDE\)=.*$$|\1=-I$(pkgincludedir)|" \
	> $(DESTDIR)$(pkglibdir)/dovecot-config

uninstall-hook:
	rm $(DESTDIR)$(pkglibdir)/dovecot-config

if WANT_SYSTEMD
CLEANFILES = dovecot.service
endif

DISTCLEANFILES = \
	$(top_builddir)/dovecot-version.h \
	$(top_builddir)/dovecot-config \
	$(top_builddir)/run-test.sh

distcheck-hook:
	if which scan-build > /dev/null; then \
	  cd $(distdir)/_build; \
	  scan-build -o scan-reports ../configure --with-ldap=auto --with-pgsql=auto --with-mysql=auto --with-sqlite=auto --with-solr=auto --with-cassandra=auto --with-lua=auto --with-gssapi=auto --with-libwrap=auto --enable-static-checker; \
	  rm -rf scan-reports; \
	  scan-build -o scan-reports make 2>&1 || exit 1; \
	  if ! rmdir scan-reports 2>/dev/null; then \
	    exit 1; \
	  fi; \
	  make distclean; \
	fi
