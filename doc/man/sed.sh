#!/bin/sh

SRCDIR="${1:-`pwd`}"
RUNDIR="${2:-/usr/local/var/run/dovecot}"
SYSCONFDIR="${3:-/usr/local/etc}"

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
	-e "/^@INCLUDE:option-u-user@$/{
		r ${SRCDIR}/option-u-user.inc
		d
	}" \
	-e "/^@INCLUDE:reporting-bugs@$/{
		r ${SRCDIR}/reporting-bugs.inc
		d
	}" | sed -e "s|@sysconfdir@|${SYSCONFDIR}|" -e "s|@rundir@|${RUNDIR}|"

