#!/bin/sh
#
# Copyright (c) 2019 Dovecot authors, see the included COPYING file */
#
# This script is intended to be called by the script service and to be
# connected to a socket using a service configuration like this:
# 	executable = script -p /path/to/health-check.sh
#
# This simple example merely answers "PONG\n" if the input is "PING\n". It
# stops waiting for input after $timeout which causes the process to die
# which causes the script module to close the socket. Inputs and outputs
# can be written to STDIN and STDOUT, they are duplicated file-descriptors
# if called from the script service.

timeout=10

# timeout the read via trap for POSIX shell compatibility
trap "exit 0" QUIT
trap 'kill $timeout_pid 2>/dev/null' EXIT INT TERM

{
	sleep $timeout
	kill -3 $$ 2>/dev/null
} &
timeout_pid=$!

read -r input
exit_code=$?

cleaned_input=$(echo ${input} | sed "s/[^a-zA-Z0-9]//g")

if [ ${exit_code} -eq 0 ] && [ "${cleaned_input}" = "PING" ];then
	echo "PONG"
fi
# always exit successful
exit 0
