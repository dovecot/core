Build Instructions
==================

For most people, the usual:

```
./configure
make
sudo make install
```

is enough. This installs Dovecot under /usr/local.
When building from git, you need to run `./autogen.sh` first.

If you have installed some libraries into locations which require special include or library paths, you can give them in CPPFLAGS and LDFLAGS environment variables. For example:

`CPPFLAGS=-I/opt/openssl/include LDFLAGS=-L/opt/openssl/lib ./configure`

See `./configure --help` for a list of all available configure options.
See [Compiling Dovecot From Sources](https://doc.dovecot.org/installation_guide/dovecot_community_repositories/compiling_source/) for more information.

Running
=======

Start with the example configuration:

```
cp -r /usr/local/share/doc/dovecot/example-config/* /usr/local/etc/dovecot/
```

Read through, and make needed modifications.

Once everything is configured, start Dovecot by running "dovecot" binary.

See the [Online documentation](https://doc.dovecot.org/configuration_manual/) for more information about configuration. If you're in a hurry, go at least through [Quick Configuration](https://doc.dovecot.org/configuration_manual/quick_configuration/).

SSL/TLS
=======

Dovecot used to support both GNUTLS and OpenSSL libraries, but nowadays only the OpenSSL code is working.
