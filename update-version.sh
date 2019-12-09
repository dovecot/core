#!/bin/sh

SRCDIR="${1:-`pwd`}"
BUILDDIR="${2:-`pwd`}"
VERSION_H="dovecot-version.h"
VERSION_HT="dovecot-version.h.tmp"
DOVECOT_BUILD_INFO=${DOVECOT_BUILD_INFO:-DOVECOT_VERSION_FULL}

abspath()
{ #$1 the path
  #$2 1 -> SRCDIR || 2 -> BUILDDIR
	old=`pwd`
	cd "${1}"
	if [ ${2} -eq 1 ]; then
		SRCDIR=`pwd`
	else
		BUILDDIR=`pwd`
	fi
	cd "$old"
}

abspath "${SRCDIR}" 1
abspath "${BUILDDIR}" 2

# when using a different BUILDDIR just copy from SRCDIR, if there is no .git
if [ "${BUILDDIR}" != "${SRCDIR}" ]; then
	if [ ! -d "${SRCDIR}/.git" ]  && [ -f "${SRCDIR}/${VERSION_H}" ]; then
		cmp -s "${SRCDIR}/${VERSION_H}" "${BUILDDIR}/${VERSION_H}"
		if [ $? -ne 0 ]; then
			cp "${SRCDIR}/${VERSION_H}" "${BUILDDIR}/${VERSION_H}"
			exit 0
		fi
	fi
fi

# Don't generate dovecot-version.h if the source tree has no .git dir but
# a dovecot-version.h. This may be the result of a release/nightly tarball.
[ ! -d "${SRCDIR}/.git" ] && [ -f "${BUILDDIR}/${VERSION_H}" ] && exit 0

# Lets generate the dovecot-version.h
[ -f "${BUILDDIR}/${VERSION_HT}" ] && rm -f "${BUILDDIR}/${VERSION_HT}"
if true; then
	GITID=`git --git-dir ${SRCDIR}/.git rev-parse --short HEAD`
	cat > "${BUILDDIR}/${VERSION_HT}" <<EOF
#ifndef DOVECOT_VERSION_H
#define DOVECOT_VERSION_H

#define DOVECOT_REVISION "${GITID}"
#define DOVECOT_VERSION_FULL VERSION" ("DOVECOT_REVISION")"
#define DOVECOT_BUILD_INFO ${DOVECOT_BUILD_INFO}

#endif /* DOVECOT_VERSION_H */
EOF
else
	cat > "${BUILDDIR}/${VERSION_HT}" <<EOF
#ifndef DOVECOT_VERSION_H
#define DOVECOT_VERSION_H

#define DOVECOT_VERSION_FULL VERSION
#define DOVECOT_BUILD_INFO ${DOVECOT_BUILD_INFO}

#endif /* DOVECOT_VERSION_H */
EOF
fi

cmp -s "${BUILDDIR}/${VERSION_H}" "${BUILDDIR}/${VERSION_HT}" && \
	rm -f "${BUILDDIR}/${VERSION_HT}" || \
	mv -f "${BUILDDIR}/${VERSION_HT}" "${BUILDDIR}/${VERSION_H}"
