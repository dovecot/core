Build Instructions
==================

For most people, the usual:

```
./autogen.sh
./configure
make
sudo make install
```

is enough. This installs Dovecot under /usr/local.

If you have installed some libraries into locations which require special include or library paths, you can give them in CPPFLAGS and LDFLAGS environment variables. For example:

`CPPFLAGS=-I/opt/openssl/include LDFLAGS=-L/opt/openssl/lib ./configure`

See `./configure --help` for a list of all available configure options.
See [http://wiki2.dovecot.org/CompilingSource](http://wiki2.dovecot.org/CompilingSource) for more information.

Running
=======

Start with the example configuration:

```
cp -r /usr/local/share/doc/dovecot/example-config/* /usr/local/etc/dovecot/
```

Read through, and make needed modifications.

Once everything is configured, start Dovecot by running "dovecot" binary.

See Wiki for more information about configuration. If you're in a hurry, go at least through [http://wiki2.dovecot.org/QuickConfiguration](http://wiki2.dovecot.org/QuickConfiguration)

SSL/TLS
=======

Dovecot used to support both GNUTLS and OpenSSL libraries, but nowadays only the OpenSSL code is working.
