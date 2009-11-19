#!/bin/sh
### BEGIN INIT INFO
# Provides:          dovecot
# Required-Start:    $local_fs $syslog
# Required-Stop:     $local_fs $syslog
# Should-Start:      $time
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Dovecot init script
# Description:       Init script for dovecot services
### END INIT INFO

# Example /etc/init.d/dovecot script. Change DAEMON if necessary.
# License is public domain.

DAEMON=/usr/local/sbin/dovecot

test -x $DAEMON || exit 1
set -e

base_dir=`$DAEMON -a|grep '^base_dir = '|sed 's/^base_dir = //'`
pidfile=$base_dir/master.pid

if test -f $pidfile; then
  running=yes
else
  running=no
fi

case "$1" in
  start)
    echo -n "Starting Dovecot"
    $DAEMON
    echo "."
    ;;
  stop)
    if test $running = yes; then
      echo "Stopping Dovecot"
      kill `cat $pidfile`
      echo "."
    else
      echo "Dovecot is already stopped."
    fi
    ;;
  reload)
    if test $running = yes; then
      echo -n "Reloading Dovecot configuration"
      kill -HUP `cat $pidfile`
      echo "."
    else
      echo "Dovecot isn't running."
    fi
    ;;
  restart|force-reload)
    echo -n "Restarting Dovecot"
    if test $running = yes; then
      kill `cat $pidfile`
      sleep 1
    fi
    $DAEMON
    echo "."
    ;;
  *)
    echo "Usage: /etc/init.d/dovecot {start|stop|reload|restart|force-reload}" >&2
    exit 1
    ;;
esac

exit 0
