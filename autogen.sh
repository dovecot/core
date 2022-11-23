#!/bin/sh

# If you've non-standard directories, set these
#GETTEXT_DIR=

if ! test -f build-aux/config.rpath; then
  for dir in $GETTEXT_DIR /usr/share/gettext /usr/local/share/gettext; do
    if test -f $dir/config.rpath; then
      /bin/cp -f $dir/config.rpath build-aux/
      break
    fi
  done
fi

autoreconf -i
