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

  dnl * SSL_clear_options introduced in openssl 0.9.8m but may be backported to
  dnl * older versions in "enterprise" OS releases; originally implemented as a
  dnl * macro but as a function in more recent openssl versions
  AC_CACHE_CHECK([whether SSL_clear_options exists],i_cv_have_ssl_clear_options,[
    old_LIBS=$LIBS
    LIBS="$LIBS -lssl"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
      #include <openssl/ssl.h>
    ]], [[
      SSL *ssl;
      long options;
      SSL_clear_options(ssl, options);
    ]])], [
      i_cv_have_ssl_clear_options=yes
    ],[
      i_cv_have_ssl_clear_options=no
    ])
    LIBS=$old_LIBS
  ])
  AS_IF([test $i_cv_have_ssl_clear_options = yes], [
    AC_DEFINE(HAVE_SSL_CLEAR_OPTIONS,, [Define if you have SSL_clear_options])
  ])

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

  dnl * SSL_CTX_set_min_proto_version is also a macro so AC_CHECK_LIB fails here.
  AC_CACHE_CHECK([whether SSL_CTX_set_min_proto_version exists],i_cv_have_ssl_ctx_set_min_proto_version,[
    old_LIBS=$LIBS
    LIBS="$LIBS -lssl"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
      #include <openssl/ssl.h>
    ]], [[
      SSL_CTX_set_min_proto_version((void*)0, 0);
    ]])],[
      i_cv_have_ssl_ctx_set_min_proto_version=yes
    ],[
      i_cv_have_ssl_ctx_set_min_proto_version=no
    ])
    LIBS=$old_LIBS
  ])
  AS_IF([test $i_cv_have_ssl_ctx_set_min_proto_version = yes], [
    AC_DEFINE(HAVE_SSL_CTX_SET_MIN_PROTO_VERSION,, [Define if you have SSL_CTX_set_min_proto_version])
  ])

  dnl * SSL_CTX_set_current_cert is also a macro so AC_CHECK_LIB fails here.
  AC_CACHE_CHECK([whether SSL_CTX_set_current_cert exists],i_cv_have_ssl_ctx_set_current_cert,[
    old_LIBS=$LIBS
    LIBS="$LIBS -lssl"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
      #include <openssl/ssl.h>
    ]], [[
      SSL_CTX_set_current_cert((void*)0, 0);
    ]])],[
      i_cv_have_ssl_ctx_set_current_cert=yes
    ],[
      i_cv_have_ssl_ctx_set_current_cert=no
    ])
    LIBS=$old_LIBS
  ])
  AS_IF([test $i_cv_have_ssl_ctx_set_current_cert = yes], [
    AC_DEFINE(HAVE_SSL_CTX_SET_CURRENT_CERT,, [Define if you have SSL_CTX_set_current_cert])
  ])


  AC_CHECK_LIB(ssl, SSL_CIPHER_get_kx_nid, [
    AC_DEFINE(HAVE_SSL_CIPHER_get_kx_nid,, [Define if you have SSL_CIPHER_get_kx_nid])
  ],, $SSL_LIBS)

  AC_CHECK_LIB(ssl, ERR_remove_thread_state, [
    AC_DEFINE(HAVE_OPENSSL_ERR_REMOVE_THREAD_STATE,, [Define if you have ERR_remove_thread_state])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, OPENSSL_thread_stop, [
    AC_DEFINE(HAVE_OPENSSL_AUTO_THREAD_DEINIT,, [Define if OpenSSL performs thread cleanup automatically])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, OPENSSL_cleanup, [
    AC_DEFINE(HAVE_OPENSSL_CLEANUP,, [OpenSSL supports OPENSSL_cleanup()])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, ASN1_STRING_get0_data, [
    AC_DEFINE(HAVE_ASN1_STRING_GET0_DATA,, [Build with ASN1_STRING_get0_data() support])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, HMAC_CTX_new, [
    AC_DEFINE(HAVE_HMAC_CTX_NEW,, [Build with HMAC_CTX_new() support])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, EVP_MD_CTX_new, [
    AC_DEFINE(HAVE_EVP_MD_CTX_NEW,, [Build with EVP_MD_CTX_new() support])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, OBJ_length, [
    AC_DEFINE(HAVE_OBJ_LENGTH,, [Build with OBJ_length() support])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, EVP_PKEY_get0_RSA, [
    AC_DEFINE(HAVE_EVP_PKEY_get0,, [Build with EVP_PKEY_get0_*() support])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, SSL_CTX_set_ciphersuites, [
    AC_DEFINE(HAVE_SSL_CTX_SET_CIPHERSUITES,, [Build with SSL_CTX_set_ciphersuites() support])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, BN_secure_new, [
    AC_DEFINE(HAVE_BN_SECURE_NEW,, [Build with BN_secure_new support])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, RSA_set0_key, [
    AC_DEFINE(HAVE_RSA_SET0_KEY,, [Build with RSA_set0_key support])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, RSA_set0_factors, [
    AC_DEFINE(HAVE_RSA_SET0_FACTORS,, [Build with RSA_set0_factors support])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, RSA_set0_crt_params, [
    AC_DEFINE(HAVE_RSA_SET0_CRT_PARAMS,, [Build with RSA_set0_crt_params support])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, ECDSA_SIG_get0, [
    AC_DEFINE(HAVE_ECDSA_SIG_GET0,, [Build with ECDSA_SIG_get0 support])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, ECDSA_SIG_set0, [
    AC_DEFINE(HAVE_ECDSA_SIG_SET0,, [Build with ECDSA_SIG_set0 support])
  ],, $SSL_LIBS)
  AC_CHECK_LIB(ssl, EC_GROUP_order_bits, [
    AC_DEFINE(HAVE_EC_GROUP_order_bits,, [Build with EC_GROUP_order_bits support])
  ],, $SSL_LIBS)
])
