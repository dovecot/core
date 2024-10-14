dnl DOVECOT_CHECK_SSL_FUNC(function)
AC_DEFUN([DOVECOT_CHECK_SSL_FUNC], [
   AC_CHECK_DECL([$1], AC_DEFINE(HAVE_$1,, [Define if you have $1]),,
[[#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/core.h>
#endif
#include <openssl/objects.h>
#include <openssl/err.h>
]])
])

AC_DEFUN([DOVECOT_SSL], [
  build_dcrypt_openssl=no
  have_openssl=no

  dnl libressl pkg pretends to be openssl 1.0.0, so we can't check 1.0.2 here
  dnl so we check for 1.0.0 first, then after this check, we check that the
  dnl lib we found actually is 1.0.2 or later.

  PKG_CHECK_EXISTS([openssl], [
     PKG_CHECK_MODULES(SSL, [openssl >= 1.0.0])
  ], [
    AC_CHECK_LIB(ssl, SSL_read, [
      AC_CHECK_HEADERS(openssl/ssl.h openssl/err.h, [
        SSL_LIBS="-lssl -lcrypto $DLLIB"
        AC_SUBST(SSL_LIBS)
        have_openssl=yes
    ], AC_MSG_ERROR(cannot build with OpenSSL: openssl/ssl.h or openssl/err.h not found))])
    AS_IF([test $have_openssl != yes], [
      AC_MSG_ERROR(cannot build with OpenSSL: libssl not found)
    ])
  ])

  AC_MSG_CHECKING([if OpenSSL version is 1.0.2 or better])

  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <openssl/opensslv.h>
      #if OPENSSL_VERSION_NUMBER < 0x10002000L
      #error "fail-compile"
      #endif]], [[ return 0; ]])],
    [ssl_version_ge_102=true], [ssl_version_ge_102=false])
  AC_MSG_RESULT([$ssl_version_ge_102])

  AS_IF([test $ssl_version_ge_102 != true], [
    AC_MSG_ERROR([OpenSSL v1.0.2 or better required to build Dovecot])
  ])

  AC_MSG_CHECKING([if OpenSSL version is 3.0.0 or better])

  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <openssl/opensslv.h>
      #if OPENSSL_VERSION_NUMBER < 0x30000000L
      #error "fail-compile"
      #endif]], [[ return 0; ]])],
    [ssl_version_ge_300=true], [ssl_version_ge_300=false])
  AC_MSG_RESULT([$ssl_version_ge_300])

  AS_IF([test $ssl_version_ge_300 = true], [
    SSL_CFLAGS="$SSL_CFLAGS -DOPENSSL_NO_DEPRECATED -DOPENSSL_API_COMPAT=30000 -DDOVECOT_USE_OPENSSL3"
    dcrypt_openssl_ver=3
    AC_DEFINE([HAVE_OPENSSL3],,1)
  ], [
    SSL_CFLAGS="$SSL_CFLAGS -DOPENSSL_NO_DEPRECATED -DOPENSSL_API_COMPAT=0x1000200L"
  ])

  old_CFLAGS="$CFLAGS"
  CFLAGS="$old_CFLAGS $SSL_CFLAGS"

  dnl * New style mem functions? Should be in v1.1+
  AC_CACHE_CHECK([whether CRYPTO_set_mem_functions has new style parameters],i_cv_have_ssl_new_mem_funcs,[
    old_LIBS=$LIBS
    LIBS="$LIBS -lssl"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
      #include <openssl/ssl.h>
        int CRYPTO_set_mem_functions(
              void *(*m) (size_t, const char *, int),
              void *(*r) (void *, size_t, const char *, int),
              void (*f) (void *, const char *, int));
    ]], [[
    ]])],[
      i_cv_have_ssl_new_mem_funcs=yes
    ],[
      i_cv_have_ssl_new_mem_funcs=no
    ])
    LIBS=$old_LIBS
  ])
  AS_IF([test $i_cv_have_ssl_new_mem_funcs = yes], [
    AC_DEFINE(HAVE_SSL_NEW_MEM_FUNCS,, [Define if CRYPTO_set_mem_functions has new style parameters])
  ])

  DOVECOT_CHECK_SSL_FUNC([ECDSA_SIG_get0])
  DOVECOT_CHECK_SSL_FUNC([ECDSA_SIG_set0])
  DOVECOT_CHECK_SSL_FUNC([EC_GROUP_order_bits])
  DOVECOT_CHECK_SSL_FUNC([ERR_get_error_all])
  DOVECOT_CHECK_SSL_FUNC([ERR_get_error_line_data])
  DOVECOT_CHECK_SSL_FUNC([ERR_remove_state])
  DOVECOT_CHECK_SSL_FUNC([ERR_remove_thread_state])
  DOVECOT_CHECK_SSL_FUNC([EVP_MAC_CTX_new])
  DOVECOT_CHECK_SSL_FUNC([EVP_MD_CTX_new])
  DOVECOT_CHECK_SSL_FUNC([EVP_PKEY_get_raw_private_key])
  DOVECOT_CHECK_SSL_FUNC([EVP_PKEY_get0_RSA])
  DOVECOT_CHECK_SSL_FUNC([EVP_PKEY_get0_EC_KEY])
  DOVECOT_CHECK_SSL_FUNC([EVP_PKEY_get0_DH])
  DOVECOT_CHECK_SSL_FUNC([EVP_PKEY_set1_encoded_public_key])
  DOVECOT_CHECK_SSL_FUNC([HMAC_CTX_init])
  DOVECOT_CHECK_SSL_FUNC([HMAC_CTX_new])
  DOVECOT_CHECK_SSL_FUNC([OBJ_cleanup])
  DOVECOT_CHECK_SSL_FUNC([OBJ_length])
  DOVECOT_CHECK_SSL_FUNC([OPENSSL_cleanup])
  DOVECOT_CHECK_SSL_FUNC([OPENSSL_init_ssl])
  DOVECOT_CHECK_SSL_FUNC([OPENSSL_thread_stop])
  DOVECOT_CHECK_SSL_FUNC([OSSL_PROVIDER_try_load])
  DOVECOT_CHECK_SSL_FUNC([PEM_read_bio_Parameters])
  DOVECOT_CHECK_SSL_FUNC([RSA_set0_crt_params])
  DOVECOT_CHECK_SSL_FUNC([RSA_set0_factors])
  DOVECOT_CHECK_SSL_FUNC([RSA_set0_key])
  DOVECOT_CHECK_SSL_FUNC([SSL_CIPHER_get_kx_nid])
  DOVECOT_CHECK_SSL_FUNC([SSL_clear_options])
  DOVECOT_CHECK_SSL_FUNC([SSL_client_hello_get0_ciphers])
  DOVECOT_CHECK_SSL_FUNC([SSL_CTX_set0_tmp_dh_pkey])
  DOVECOT_CHECK_SSL_FUNC([SSL_CTX_set_ciphersuites])
  DOVECOT_CHECK_SSL_FUNC([SSL_CTX_set_current_cert])
  DOVECOT_CHECK_SSL_FUNC([SSL_CTX_set_ecdh_auto])
  DOVECOT_CHECK_SSL_FUNC([SSL_CTX_set_min_proto_version])
  DOVECOT_CHECK_SSL_FUNC([SSL_CTX_set_tmp_dh_callback])
  DOVECOT_CHECK_SSL_FUNC([SSL_CTX_set_tmp_rsa_callback])
  DOVECOT_CHECK_SSL_FUNC([SSL_get1_peer_certificate])
  DOVECOT_CHECK_SSL_FUNC([SSL_load_error_strings])

  CFLAGS="$old_CFLAGS"
])
