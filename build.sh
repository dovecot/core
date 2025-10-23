BUILD_DIRECTORY="${BUILD_DIRECTORY:-/opt/r7-mailserver/mdaserver}"
VERSION="${VERSION:-2.4.1-patch1}"

#Пакеты компилятора и зависимости
apt-get update -y && apt-get install -y gettext-base gettext openssh-client ca-certificates pkg-config wget apt-utils git coreutils ed

apt-get install -y \
  build-essential make autoconf automake libtool bison flex autotools-dev \
  libssl-dev libldap2-dev libbz2-dev zlib1g-dev liblz4-dev libzstd-dev libcap-dev libsodium-dev libunwind-dev libwrap0-dev libkrb5-dev libpq-dev libsqlite3-dev libexpat1-dev \
  liblua5.3-dev libxapian-dev libstemmer-dev libsasl2-dev libicu-dev krb5-multidev libdb-dev libcurl4-gnutls-dev libexpat-dev libexttextcat-dev default-libmysqlclient-dev \
  libpcre3-dev libcdb-dev liblzma-dev liblmdb-dev libunbound-dev libmagic-dev

#Переменная окружения:
CFLAGS="$CFLAGS -ffile-prefix-map=$PWD=." LDFLAGS="$LDFLAGS" CXXFLAGS="$CFLAGS -ffile-prefix-map=$PWD=. "

# Создание директории назначения
mkdir -p $BUILD_DIRECTORY

#Чистка предыдущей установки, если такая была
make distclean || true

#Сборка Ядра:

## Automake
./autogen.sh

## Конфигурирование пакетов
./configure --with-ldap=plugin --with-sql=plugin --with-lua=plugin --with-pgsql --with-mysql --with-sqlite --with-gssapi=plugin --with-solr --with-flatcurve --with-icu --with-lz4 --with-zstd --with-bzlib --with-stemmer --with-textcat --with-libcap --enable-experimental-mail-utf8 --with-retpoline=thunk --disable-static \
--prefix=$BUILD_DIRECTORY \
--exec-prefix=$BUILD_DIRECTORY

#Компоновка
make -j V=0

# Сборка
make install-strip

# Добавление необходимых пользователей
  useradd --system dovecot
  useradd --system dovenull
  useradd --system vmail
  mkdir -p "$BUILD_DIRECTORY/ssl"
  openssl genrsa -out "$BUILD_DIRECTORY/ssl/private.key" 2048
  openssl req -new -x509 -key "$BUILD_DIRECTORY/ssl/private.key" -out "$BUILD_DIRECTORY/ssl/certificate.crt" -days 365 -subj "/C=RU/ST=Moscow/L=Moscow/O=Company/CN=localhost"
  chmod 600 "$BUILD_DIRECTORY/ssl/private.key"
  chmod 644 "$BUILD_DIRECTORY/ssl/certificate.crt"
  sed -i "s|cert_file = /etc/ssl/dovecot-build-cert.pem|cert_file = $BUILD_DIRECTORY/ssl/certificate.crt|" $BUILD_DIRECTORY/etc/dovecot/dovecot.conf
  sed -i "s|key_file = /etc/ssl/dovecot-build-key.pem|key_file = $BUILD_DIRECTORY/ssl/private.key|" $BUILD_DIRECTORY/etc/dovecot/dovecot.conf

echo "Запустить собранный dovecot? (Y/n) [n]: "
read -t 5 -n 1 -r response
if [[ $response =~ ^[Yy]$ ]]; then
  $BUILD_DIRECTORY/sbin/dovecot -c $BUILD_DIRECTORY/etc/dovecot/dovecot.conf -F
fi