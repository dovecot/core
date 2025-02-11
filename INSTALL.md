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
See [Installation](https://doc.dovecot.org/latest/installation/installation.html) for more information.

Running
=======

Start with the minimal configuration installed in `/usr/local/etc/dovecot/`.

Read through, and make needed modifications.

Once everything is configured, start Dovecot by running "dovecot" binary.

See the [Online configuration documentation](https://doc.dovecot.org/latest/core/config/overview.html) for more information.

If you're in a hurry, go at least through [Quick Configuration](https://doc.dovecot.org/latest/core/config/guides/quick.html).

SSL/TLS
=======

Dovecot supports [OpenSSL](https://openssl-library.org/) for SSL/TLS
functionality.
