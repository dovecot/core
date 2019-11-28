#!/bin/bash
set -x 
USERID=$(stat -c %u .)
GROUPID=$(stat -c %g .)
HOME=$(cd ..;pwd)
groupadd -g $GROUPID rpmgrp
useradd -u $USERID -g $GROUPID -M rpmuser
# yum install libpq-devel lz4-devel libsodium-devel libexttextcat-devel libstemmer-devel
#yum install postgresql-devel
SUDO () {
    perl -e 'use POSIX qw(setuid setgid); setgid('${GROUPID}');setuid('${USERID}'); exec @ARGV' -- "$@"
}
SUDO rpmbuild -v -ba ./SOURCES/dovecot.spec
