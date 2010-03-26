#!/bin/sh

trap "rm -f test.out.$$" 0 1 2 3 15

valgrind -q --log-file=test.out.$$ $*
if [ -s test.out.$$ ]; then
  cat test.out.$$
  exit 1
fi
