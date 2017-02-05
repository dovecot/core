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
  
      AC_MSG_CHECKING([if OpenSSL version is 1.0.2 or better])

      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
	#include <openssl/opensslv.h>
	#if OPENSSL_VERSION_NUMBER < 0x10002000L
	#error "fail-compile"
	#endif]], [[ return 0; ]])], [ssl_version_ge_102=true], [ssl_version_ge_102=false])
      AC_MSG_RESULT([$ssl_version_ge_102])

      # SSL_clear_options introduced in openssl 0.9.8m but may be backported to
      # older versions in "enterprise" OS releases; originally implemented as a
      # macro but as a function in more recent openssl versions
      AC_CACHE_CHECK([whether SSL_clear_options exists],i_cv_have_ssl_clear_options,[
        old_LIBS=$LIBS
        LIBS="$LIBS -lssl"
        AC_TRY_LINK([
          #include <openssl/ssl.h>
        ], [
          SSL *ssl;
          long options;
          SSL_clear_options(ssl, options);
        ], [
          i_cv_have_ssl_clear_options=yes
        ], [
          i_cv_have_ssl_clear_options=no
        ])
        LIBS=$old_LIBS
      ])
      if test $i_cv_have_ssl_clear_options = yes; then
        AC_DEFINE(HAVE_SSL_CLEAR_OPTIONS,, [Define if you have SSL_clear_options])
      fi

      # New style mem functions? Should be in v1.1+
      AC_CACHE_CHECK([whether CRYPTO_set_mem_functions has new style parameters],i_cv_have_ssl_new_mem_funcs,[
        old_LIBS=$LIBS
        LIBS="$LIBS -lssl"
        AC_TRY_LINK([
          #include <openssl/ssl.h>
	  int CRYPTO_set_mem_functions(
		  void *(*m) (size_t, const char *, int),
		  void *(*r) (void *, size_t, const char *, int),
		  void (*f) (void *, const char *, int));
        ], [
        ], [
          i_cv_have_ssl_new_mem_funcs=yes
        ], [
          i_cv_have_ssl_new_mem_funcs=no
        ])
        LIBS=$old_LIBS
      ])
      if test $i_cv_have_ssl_new_mem_funcs = yes; then
        AC_DEFINE(HAVE_SSL_NEW_MEM_FUNCS,, [Define if CRYPTO_set_mem_functions has new style parameters])
      fi

      # SSL_CTX_set1_curves_list is a macro so plain AC_CHECK_LIB fails here.
      AC_CACHE_CHECK([whether SSL_CTX_set1_curves_list exists],i_cv_have_ssl_ctx_set1_curves_list,[
        old_LIBS=$LIBS
        LIBS="$LIBS -lssl"
        AC_TRY_LINK([
          #include <openssl/ssl.h>
        ], [
          SSL_CTX_set1_curves_list((void*)0, "");
        ], [
          i_cv_have_ssl_ctx_set1_curves_list=yes
        ], [
          i_cv_have_ssl_ctx_set1_curves_list=no
        ])
        LIBS=$old_LIBS
      ])
      if test $i_cv_have_ssl_ctx_set1_curves_list = yes; then
        AC_DEFINE(HAVE_SSL_CTX_SET1_CURVES_LIST,, [Define if you have SSL_CTX_set1_curves_list])
      fi

      AC_CHECK_LIB(ssl, ERR_remove_thread_state, [
        AC_DEFINE(HAVE_OPENSSL_ERR_REMOVE_THREAD_STATE,, [Define if you have ERR_remove_thread_state])
      ],, $SSL_LIBS)
      AC_CHECK_LIB(ssl, OPENSSL_thread_stop, [
        AC_DEFINE(HAVE_OPENSSL_AUTO_THREAD_DEINIT,, [Define if OpenSSL performs thread cleanup automatically])
      ],, $SSL_LIBS)
      AC_CHECK_LIB(ssl, OPENSSL_cleanup, [
        AC_DEFINE(HAVE_OPENSSL_CLEANUP,, [OpenSSL supports OPENSSL_cleanup()])
      ],, $SSL_LIBS)
      AC_CHECK_LIB(ssl, SSL_get_current_compression, [
        AC_DEFINE(HAVE_SSL_COMPRESSION,, [Build with OpenSSL compression])
      ],, $SSL_LIBS)
      AC_CHECK_LIB(ssl, SSL_get_servername, [
        AC_DEFINE(HAVE_SSL_GET_SERVERNAME,, [Build with TLS hostname support])
      ],, $SSL_LIBS)
      AC_CHECK_LIB(ssl, SSL_COMP_free_compression_methods, [
        AC_DEFINE(HAVE_SSL_COMP_FREE_COMPRESSION_METHODS,, [Build with SSL_COMP_free_compression_methods() support])
      ],, $SSL_LIBS)
      AC_CHECK_LIB(ssl, RSA_generate_key_ex, [
        AC_DEFINE(HAVE_RSA_GENERATE_KEY_EX,, [Build with RSA_generate_key_ex() support])
      ],, $SSL_LIBS)
      AC_CHECK_LIB(ssl, ASN1_STRING_get0_data, [
        AC_DEFINE(HAVE_ASN1_STRING_GET0_DATA,, [Build with ASN1_STRING_get0_data() support])
      ],, $SSL_LIBS)
      AC_CHECK_LIB(ssl, [EVP_PKEY_CTX_new_id], [have_evp_pkey_ctx_new_id="yes"],, $SSL_LIBS)
      AC_CHECK_LIB(ssl, [EC_KEY_new], [have_ec_key_new="yes"],, $SSL_LIBS)
      if test "$have_evp_pkey_ctx_new_id" = "yes" && test "$have_ec_key_new" = "yes"; then
        build_dcrypt_openssl="yes"
      else
        AC_MSG_WARN([No ECC support in OpenSSL - not enabling dcrypt])
      fi
    fi
  fi
  AM_CONDITIONAL(BUILD_OPENSSL, test "$have_openssl" = "yes")
  AM_CONDITIONAL(BUILD_DCRYPT_OPENSSL, test "$build_dcrypt_openssl" = "yes")
  AM_CONDITIONAL([SSL_VERSION_GE_102], [test x$ssl_version_ge_102 = xtrue])

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
