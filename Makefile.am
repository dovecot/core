if BUILD_DOCS
DOCS = doc
endif

SUBDIRS = \
	src \
	$(DOCS)

EXTRA_DIST = \
	COPYING.LGPL \
	COPYING.MIT \
	ChangeLog \
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

dovecot-config: dovecot-config.in Makefile
	old=`pwd` && cd $(top_builddir) && abs_builddir=`pwd` && cd $$old && \
	cd $(top_srcdir) && abs_srcdir=`pwd` && cd $$old && \
	cat dovecot-config.in | sed \
	-e "s|\$$(top_builddir)|$$abs_builddir|g" \
	-e "s|\$$(incdir)|$$abs_srcdir|g" \
	-e "s|\$$(LIBICONV)|$(LIBICONV)|g" \
	-e "s|^\(DOVECOT_MODULEDIR\)=|\1=$(moduledir)|" \
	-e "s|^\(DOVECOT_PKGINCLUDEDIR\)=|\1=$(pkgincludedir)|" \
	-e "s|^\(DOVECOT_PKGLIBDIR\)=|\1=$(pkglibdir)|" \
	-e "s|^\(DOVECOT_PKGLIBEXECDIR\)=|\1=$(libexecdir)/dovecot|" \
	-e "s|^\(DOVECOT_DOCDIR\)=|\1=$(docdir)|" \
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
endif

CLEANFILES = $(datafiles)
