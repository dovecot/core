#!/bin/sh

SRCDIR="${1:-`pwd`}"
BUILDDIR="${2:-`pwd`}"
VERSION_H="dovecot-version.h"
VERSION_HT="dovecot-version.h.tmp"

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

# when using a different BUILDDIR just copy from SRCDIR, if there is no .hg
if [ "${BUILDDIR}" != "${SRCDIR}" ]; then
	if [ ! -d "${SRCDIR}/.hg" ]  && [ -f "${SRCDIR}/${VERSION_H}" ]; then
		cmp -s "${SRCDIR}/${VERSION_H}" "${BUILDDIR}/${VERSION_H}"
		if [ $? -ne 0 ]; then
			cp "${SRCDIR}/${VERSION_H}" "${BUILDDIR}/${VERSION_H}"
			exit 0
		fi
	fi
fi

# Don't generate dovecot-version.h if the source tree has no .hg dir but
# a dovecot-version.h. This may be the result of a release/nightly tarball.
[ ! -d "${SRCDIR}/.hg" ] && [ -f "${BUILDDIR}/${VERSION_H}" ] && exit 0

# Lets generate the dovecot-version.h
[ -f "${BUILDDIR}/${VERSION_HT}" ] && rm -f "${BUILDDIR}/${VERSION_HT}"
python "${SRCDIR}/is-tagged.py" "${SRCDIR}"
if [ $? = 1 ]; then
	# older hg doesn't recognize option -i
	#HGID=`hg -R ${SRCDIR} id -i 2>/dev/null`
	HGID=`hg -R ${SRCDIR} id 2>/dev/null | awk '{print $1}'`
	cat > "${BUILDDIR}/${VERSION_HT}" <<EOF
#ifndef DOVECOT_VERSION_H
#define DOVECOT_VERSION_H

#define DOVECOT_VERSION_FULL VERSION" (${HGID})"

#endif /* DOVECOT_VERSION_H */
EOF
else
	cat > "${BUILDDIR}/${VERSION_HT}" <<EOF
#ifndef DOVECOT_VERSION_H
#define DOVECOT_VERSION_H

#define DOVECOT_VERSION_FULL VERSION

#endif /* DOVECOT_VERSION_H */
EOF
fi

cmp -s "${BUILDDIR}/${VERSION_H}" "${BUILDDIR}/${VERSION_HT}" && \
	rm -f "${BUILDDIR}/${VERSION_HT}" || \
	mv "${BUILDDIR}/${VERSION_HT}" "${BUILDDIR}/${VERSION_H}"
