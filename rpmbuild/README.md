HOWTO Build RPMS
==========================
Author: Tobi Oetiker 
Date:   19.09.2019, Version 1

Rebase the source
=================

git fetch upstream
git rebase upstream/release-2.3.8

git diff 2.3.8 > dovecot-2.3.8-hin-2.3.x.patch

Build RPMS
==========

# update rpmbuild/SOURCES from https://src.fedoraproject.org/rpms/dovecot/tree/master
# manually first and adapt dovecot.spec file
mv dovecot_2.3.8-hin-patch_2.3.8.patch rpmbuild/SOURCES

cd rpmbuild
docker-compose run rpmbuild


The rpms are in the folders RPMS and SRPMS
