#!/bin/bash
set -x 
USERID=$(stat -c %u .)
GROUPID=$(stat -c %g .)
HOME=$(cd ..;pwd)
groupadd -g $GROUPID rpmgrp
useradd -u $USERID -g $GROUPID -M rpmuser
SUDO () {
    perl -e 'use POSIX qw(setuid setgid); setgid('${GROUPID}');setuid('${USERID}'); exec @ARGV' -- "$@"
}
SUDO rpmbuild -v -ba ./SPECS/dovecot.spec
