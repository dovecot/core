#!/bin/sh

# Generates a self-signed certificate.

OPENSSL=${OPENSSL-openssl}
SSLDIR=${SSLDIR-/etc/ssl}
OPENSSLCONFIG=${OPENSSLCONFIG-dovecot-openssl.cnf}

CERTFILE=$SSLDIR/certs/imapd.pem
KEYFILE=$SSLDIR/private/imapd.pem

if [ ! -d $SSLDIR/certs ]; then
  echo $SSLDIR/certs directory doesn't exist
fi

if [ ! -d $SSLDIR/private ]; then
  echo $SSLDIR/private directory doesn't exist
fi

if [ -f $CERTFILE ]; then
  echo "$CERTFILE already exists, won't overwrite"
  exit 1
fi

if [ -f $KEYFILE ]; then
  echo "$KEYFILE already exists, won't overwrite"
  exit 1
fi

$OPENSSL req -new -x509 -nodes -config $OPENSSLCONFIG -out $CERTFILE -keyout $KEYFILE || exit 2
chmod 0600 $KEYFILE
echo 
$OPENSSL x509 -subject -fingerprint -noout -in $CERTFILE || exit 2
