aclocaldir = $(datadir)/aclocal

if BUILD_DOCS
DOCS = doc
endif

SUBDIRS = \
	. \
	src \
	$(DOCS)

dist_pkginclude_HEADERS = \
	dovecot-version.h

EXTRA_DIST = \
	COPYING.LGPL \
	COPYING.MIT \
	ChangeLog \
	is-tagged.py \
	update-version.sh \
	$(conf_DATA)

datafiles = \
	dovecot-config

if INSTALL_HEADERS
  nodist_pkginclude_HEADERS = config.h
  pkglib_DATA = $(datafiles)
else
  noinst_DATA = $(datafiles)
endif

if MAINTAINER_MODE
ChangeLog: .hg/dirstate
	hg log --style=changelog > ChangeLog
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

if INSTALL_HEADERS
install-exec-hook:
	rm $(DESTDIR)$(pkglibdir)/dovecot-config && \
	grep -v '^LIBDOVECOT_.*_INCLUDE' dovecot-config | \
	grep -v '^LIBDOVECOT.*_DEPS' | sed \
	-e "s|^\(LIBDOVECOT\)=.*$$|\1='-L$(pkglibdir) -ldovecot'|" \
	-e "s|^\(LIBDOVECOT_LOGIN\)=.*$$|\1=-ldovecot-login|" \
	-e "s|^\(LIBDOVECOT_SQL\)=.*$$|\1=-ldovecot-sql|" \
	-e "s|^\(LIBDOVECOT_STORAGE\)=.*$$|\1=-ldovecot-storage|" \
	-e "s|^\(LIBDOVECOT_INCLUDE\)=.*$$|\1=-I$(pkgincludedir)|" \
	> $(DESTDIR)$(pkglibdir)/dovecot-config
else
install-exec-hook:
endif

CLEANFILES = $(datafiles)

DISTCLEANFILES = $(top_builddir)/dovecot-version.h
