#!/bin/sh

SRCDIR="${1:-`pwd`}"
RUNDIR="${2:-/usr/local/var/run/dovecot}"
PKGSYSCONFDIR="${3:-/usr/local/etc/dovecot}"

sed -e "/^@INCLUDE:global-options@$/{
		r ${SRCDIR}/global-options.inc
		d
	}" \
	-e "/^@INCLUDE:global-options-formatter@$/{
		r ${SRCDIR}/global-options-formatter.inc
		d
	}" \
	-e "/^@INCLUDE:option-A@$/{
		r ${SRCDIR}/option-A.inc
		d
	}" \
	-e "/^@INCLUDE:option-S-socket@$/{
		r ${SRCDIR}/option-S-socket.inc
		d
	}" \
	-e "/^@INCLUDE:option-u-user@$/{
		r ${SRCDIR}/option-u-user.inc
		d
	}" \
	-e "/^@INCLUDE:reporting-bugs@$/{
		r ${SRCDIR}/reporting-bugs.inc
		d
	}" | sed -e "s|@pkgsysconfdir@|${PKGSYSCONFDIR}|" -e "s|@rundir@|${RUNDIR}|"

