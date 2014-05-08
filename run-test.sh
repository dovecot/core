#!/bin/sh

trap "rm -f test.out.$$" 0 1 2 3 15
supp_path="`dirname $0`/run-test-valgrind.supp"
if [ -r "$supp_path" ]; then
  valgrind -q --suppressions="$supp_path" --log-file=test.out.$$ $*
else
  valgrind -q --log-file=test.out.$$ $*
fi
ret=$?
if [ -s test.out.$$ ]; then
  cat test.out.$$
  exit 1
fi
exit $ret
