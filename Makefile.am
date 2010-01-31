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
	-e "s|^moduledir=|moduledir=$(moduledir)|" \
	-e "s|^dovecot_pkgincludedir=|dovecot_pkgincludedir=$(pkgincludedir)|" \
	-e "s|^dovecot_pkglibdir=|dovecot_pkglibdir=$(pkglibdir)|" \
	-e "s|^dovecot_pkglibexecdir=|dovecot_pkglibexecdir=$(pkglibexecdir)|" \
	-e "s|^dovecot_docdir=|dovecot_docdir=$(docdir)|" \
	> dovecot-config

if INSTALL_HEADERS
install-exec-hook:
	rm $(DESTDIR)$(pkglibdir)/dovecot-config && sed \
	-e "s|^LIBDOVECOT=.*$$|LIBDOVECOT=$(pkglibdir)/libdovecot.la|" \
	-e "s|^LIBDOVECOT_LOGIN=.*$$|LIBDOVECOT_LOGIN=$(pkglibdir)/libdovecot-login.la|" \
	-e "s|^LIBDOVECOT_SQL=.*$$|LIBDOVECOT_SQL=$(pkglibdir)/libdovecot-sql.la|" \
	-e "s|^LIBDOVECOT_STORAGE=.*$$|LIBDOVECOT_STORAGE=$(pkglibdir)/libdovecot-storage.la|" \
	-e "s|^\(LIBDOVECOT_INCLUDE\)=.*$$|\1=-I$(pkgincludedir)|" \
	-e "s|^\(LIBDOVECOT_.*_INCLUDE\)=.*$$|\1=|" \
	< dovecot-config > $(DESTDIR)$(pkglibdir)/dovecot-config
endif

CLEANFILES = $(datafiles)
