#!/bin/sh

director_count=3

echo "Add to /etc/hosts:"

hosts=""
dirs=""
i=0
while [ $i != $director_count ]; do
  i=`expr $i + 1`
  dirs="$dirs 127.0.1.$i"
  echo "director	127.0.1.$i"
  cat > dovecot-director$i.conf <<EOF
listen = 127.0.1.$i
base_dir = /var/run/dovecot$i

!include dovecot-director-common.conf.inc
EOF
done

cat > dovecot-director-common.conf.inc <<EOF
log_path = /var/log/dovecot.log
info_log_path = /var/log/dovecot-access.log
director_servers =$dirs
director_mail_servers = 127.0.0.1-127.0.0.255

ssl = no
service director {
  executable = director -D -t 9091
  user = root
  unix_listener login/director {
    mode = 0666
  }
  fifo_listener login/proxy-notify {
    mode = 0666   
  }
  inet_listener {
    port = 9090
  }
}
service imap-login {
  executable = imap-login -D director
  service_count = 0
}

passdb {
  driver = static
  args = proxy=y nopassword=y port=14300
}
EOF

cat > dovecot-test.conf <<EOF
protocols = imap
ssl = no

log_path = /var/log/dovecot.log
info_log_path = /var/log/dovecot-access.log

service imap-login {
  inet_listener imap {
    port = 0
  }
}
service director-test {
  executable = director-test /var/run/dovecot1/director-admin
  process_limit = 1

  inet_listener {
    port = 14300
  }
  inet_listener {
    port = 9091
  }
}

passdb {
  driver = static
  args = nopassword=y
}
EOF

echo
echo "Start up dovecot instances:"
echo
echo 'for conf in dovecot*.conf; do dovecot -c $conf; done'
echo
echo "Start testing:"
echo
echo "imaptest host=director user=test%d.%d - select=0 no_tracking"
