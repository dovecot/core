#!/bin/sh

# If you've non-standard directories, set these
#ACLOCAL_DIR=
#GETTEXT_DIR=

if test "$ACLOCAL_DIR" != ""; then
  ACLOCAL="aclocal -I $ACLOCAL_DIR"
  export ACLOCAL
fi

for dir in $GETTEXT_DIR /usr/share/gettext; do
  if test -f $dir/config.rpath; then
    /bin/cp -f $dir/config.rpath .
    break
  fi
done

if test ! -f doc/wiki/Authentication.txt; then
  cd doc
  wget http://www.dovecot.org/tmp/wiki-export.tar.gz
  tar xzf wiki-export.tar.gz
  mv wiki-export/*.txt wiki/
  rm -rf wiki-export wiki-export.tar.gz
  cd ..
fi

cd doc/wiki
cp -f Makefile.am.in Makefile.am
echo *.txt | sed 's, , \\/	,g' | tr '/' '\n' >> Makefile.am
cd ../..

if test ! -f ChangeLog; then
  # automake dies unless this exists. It's generated in Makefile
  touch -t `date +%m%d`0000 ChangeLog
fi

autoreconf -i
