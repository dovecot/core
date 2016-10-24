AC_DEFUN([DOVECOT_SSL], [
  have_ssl=no
  build_dcrypt_openssl=no
  
  if test $want_openssl != no && test $have_ssl = no; then
    if test "$PKG_CONFIG" != "" && $PKG_CONFIG --exists openssl 2>/dev/null; then
      PKG_CHECK_MODULES(SSL, openssl)
      CFLAGS="$CFLAGS $SSL_CFLAGS"
      have_openssl=yes
    else
      # openssl 0.9.8 wants -ldl and it's required if there's only .a lib
      AC_CHECK_LIB(ssl, SSL_read, [
        AC_CHECK_HEADERS(openssl/ssl.h openssl/err.h, [
          SSL_LIBS="-lssl -lcrypto $DLLIB"
          AC_SUBST(SSL_LIBS)
  	have_openssl=yes
        ], [
  	if test $want_openssl = yes; then
  	  AC_ERROR([Can't build with OpenSSL: openssl/ssl.h or openssl/err.h not found])
  	fi
        ])
      ], [
        if test $want_openssl = yes; then
          AC_ERROR([Can't build with OpenSSL: libssl not found])
        fi
      ], -lcrypto $DLLIB)
    fi
    if test "$have_openssl" = "yes"; then
      AC_DEFINE(HAVE_OPENSSL,, [Build with OpenSSL support])
      have_ssl="yes (OpenSSL)"
  
      AC_CHECK_LIB(ssl, SSL_get_current_compression, [
        AC_DEFINE(HAVE_SSL_COMPRESSION,, [Build with OpenSSL compression])
      ],, $SSL_LIBS)
      AC_CHECK_LIB(ssl, SSL_get_servername, [
        AC_DEFINE(HAVE_SSL_GET_SERVERNAME,, [Build with TLS hostname support])
      ],, $SSL_LIBS)
      AC_CHECK_LIB(ssl, SSL_COMP_free_compression_methods, [
        AC_DEFINE(HAVE_SSL_COMP_FREE_COMPRESSION_METHODS,, [Build with SSL_COMP_free_compression_methods() support])
      ],, $SSL_LIBS)
      AC_CHECK_LIB(ssl, [EVP_PKEY_CTX_new_id],
        [build_dcrypt_openssl="yes"],
        AC_MSG_WARN([No ECC support in OpenSSL - not enabling dcrypt]),
      $SSL_LIBS)
    fi
  fi
  AM_CONDITIONAL(BUILD_OPENSSL, test "$have_openssl" = "yes")
  AM_CONDITIONAL(BUILD_DCRYPT_OPENSSL, test "$build_dcrypt_openssl" = "yes")

  if test $want_gnutls != no && test $have_ssl = no; then
    AC_CHECK_LIB(gnutls, gnutls_global_init, [
      AC_CHECK_HEADER(gnutls/gnutls.h, [
        AC_DEFINE(HAVE_GNUTLS,, [Build with GNUTLS support])
        SSL_LIBS="-lgnutls -lgcrypt"
        AC_SUBST(SSL_LIBS)
        have_ssl="yes (GNUTLS)"
        have_gnutls=yes
      ], [
        if test $want_gnutls = yes; then
  	AC_ERROR([Can't build with GNUTLS: gnutls/gnutls.h not found])
        fi
      ])
    ], [
      if test $want_gnutls = yes; then
        AC_ERROR([Can't build with GNUTLS: libgnutls not found])
      fi
    ], -lgcrypt)
  fi
  
  if test "$have_ssl" != "no"; then
  	AC_DEFINE(HAVE_SSL,, [Build with SSL/TLS support])
  fi
])
