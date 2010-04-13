#!/bin/sh

trap "rm -f test.out.$$" 0 1 2 3 15

if valgrind --version | grep '^valgrind-3.[012]'; then
  # RHEL 5.4 still has Valgrind v3.2
  valgrind -q --log-file-exactly=test.out.$$ $*
else
  # v3.3+
  valgrind -q --log-file=test.out.$$ $*
fi
if [ -s test.out.$$ ]; then
  cat test.out.$$
  exit 1
fi
