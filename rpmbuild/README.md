HOWTO Build RPMS
==========================
Author: Tobias Oetiker and Fritz Zaucker
Date:   2019-12-03, Version 2


# Rebase the source
VERSION=2.3.8
RELEASE=op1

git fetch upstream
git checkout master
git branch -b hin-patch-${VERSION}
git rebase upstream/release-${VERSION}

# make any additional changes to the source

# Create patch
git diff ${VERSION} > dovecot-${VERSION}.hin-${VERSION}-${RELEASE}.patch
git add

# Build RPMS
cd rpmbuild
make

# The generated rpm files are below the RPMS folder
