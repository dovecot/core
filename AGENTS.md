# AGENTS

This document describes the minimum environment required on build / CI agents to compile `dovecot-core` and run the unit tests. It assumes a POSIX-like system with a reasonably recent toolchain.

---

## 1. Required software on agents

### 1.1 Toolchain and build tools

Agents must have:

- C compiler (GCC or Clang)
- `make`
- Autotools:
  - `autoconf`
  - `automake`
  - `libtool`
- `pkg-config`
- `flex`
- `bison`
- `git`
- `wget`
- Scripting tools:
  - `perl`
  - `python3`

When building from **git**, `autoreconf -vif` is used to bootstrap the autotools build system.

### 1.2 Core libraries

At minimum, agents should provide development headers and libraries for:

- OpenSSL
- `zlib`
- PCRE2 (32-bit wide)

### 1.3 Recommended libraries for broader test coverage

Many unit tests exercise optional functionality; for full coverage, agents should have dev packages for:

- SQL backends:
  - SQLite
  - PostgreSQL
  - MySQL/MariaDB
- Authentication / identity:
  - PAM
  - LDAP
  - SASL (for libldap)
- System integration:
  - systemd (libsystemd)
  - libcap
- Compression / storage:
  - bzip2
  - LZ4
  - LZMA / xz
- Misc:
  - ICU
  - libsodium
  - libunwind

### 1.4 Example package sets

#### Debian / Ubuntu

```sh
apt-get update
apt-get install -y \
  build-essential \
  autoconf automake libtool pkg-config \
  flex bison \
  git wget \
  perl python3 \
  libssl-dev zlib1g-dev \
  libpcre2-32-0 \
  libpcre2-dev \
  libsqlite3-dev libmysqlclient-dev libpq-dev \
  libldap2-dev libpam0g-dev libsasl2-dev \
  libsystemd-dev libcap-dev \
  libicu-dev libcurl4-openssl-dev libunwind-dev \
  liblz4-dev liblzma-dev libsodium-dev
```

#### RHEL / CentOS / Fedora

```sh
dnf install -y \
  gcc gcc-c++ make \
  autoconf automake libtool pkgconfig \
  flex bison \
  git wget \
  perl python3 \
  openssl-devel zlib-devel \
  pcre2-utf32 \
  pcre2-devel \
  sqlite-devel mariadb-connector-c-devel postgresql-devel \
  openldap-devel pam-devel cyrus-sasl-devel \
  systemd-devel libcap-devel \
  libicu-devel libcurl-devel libunwind-devel \
  lz4-devel xz-devel libsodium-devel
```

---

## 2. Building dovecot-core

Standard sequence:

```sh
./configure
make
sudo make install
```

When building from **git**, run:

```sh
autoreconf -vif
./configure
make -j$(nproc)
```

To enable common features, use

```sh
autoreconf -vif
./configure --with-pgsql --with-ldap --with-notify=inotify --with-lzma=auto --with-zlib --with-bzlib --with-lz4=auto --with-sql=plugin --with-sqlite --enable-maintainer-mode --with-cassandra --with-mysql --with-ldap=plugin --with-lua=plugin --with-solr
make -j$(nproc)
```

NOTE: --enable-maintainer-mode allows rebuilding automake changes after Makefile.am changes in various directories.

To see various available options, use

```sh
./configure --help
```

For non‑standard dependency paths:

```sh
CPPFLAGS="-I/opt/openssl/include" \
LDFLAGS="-L/opt/openssl/lib" \
./configure
```

---

## 3. Running unit tests

### 3.1 Full test suite

```sh
make check
```

Automake test rules discover built `test_programs` and execute each through the `RUN_TEST` wrapper.

### 3.2 Per‑component tests

```sh
make -C src/lib check
make -C src/lib-mail check
make -C src/lib-regex check
make -C src/lib-storage check
```

### 3.3 Valgrind / RUN_TEST wrapper behavior

- If `valgrind` is installed, tests run under valgrind using a generated `run-test.sh` helper script.
- If `valgrind` is **not** installed, or `NOVALGRIND=1` environment variable is set, tests run normally.
- Because tests use `$(LIBTOOL) execute`, agents must install `libtool`.

To disable valgrind usage on agents, ensure `NOVALGRIND=1` environment variable
is set when running make check.

---

## 4. Creating commits

- **Keep commits atomic.** Each commit should contain only the changes directly related to what the message describes—no unrelated fixes or mixed refactoring.
- **Use imperative form in commit titles.** Example: *“Add foo to bar”*, not *“Added”* or *“Adds”*.
- **Prefix the commit title with the affected component.**
  Examples:
  - `configure: Add libpcre2 detection`
  - `lib-test: Add new test helper`
- **Provide meaningful commit messages.** The body should explain *what* changed and *why*. Include details about new options, behaviors, or implications.
- **For bug fixes**, describe the problem, symptoms (including crashes or assertion failures if applicable), and, when known, reference the commit that introduced the issue.
- **One purpose per commit.** Avoid mixing multiple unrelated changes into a single commit.

## 5. Notes for maintainers

- Keep this document up to date when adding dependencies or new test modules.
- Examples are intentionally minimal; adjust package lists per your CI baseline.

