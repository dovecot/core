HOWTO Build RPMS
==========================
Author: Tobi Oetiker 
Date:   19.09.2019, Version 1

Rebase the source
=================

git fetch upstream
git rebase upstream/release-2.3.8

Build RPMS
==========

./autogen.sh
./configure
make dist
cp dovecot-2.3.8.tar.gz rpmbuild/SOURCES
cd rpmbuild
docker-compose run rpmbuild


The rpms are in the folders RPMS and SRPMS
