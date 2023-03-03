AC_DEFUN([DOVECOT_WANT_GSSAPI], [
  have_gssapi=no
  AS_IF([test $want_gssapi != no], [
    AC_CHECK_PROG(KRB5CONFIG, krb5-config, krb5-config, missing)
    AS_IF([test $KRB5CONFIG != missing], [
      KRB5_LIBS="`$KRB5CONFIG --libs`"
      KRB5_CFLAGS=`$KRB5CONFIG --cflags`
      AS_IF([! $KRB5CONFIG --version gssapi 2>/dev/null >/dev/null], [
        # krb5-config doesn't support gssapi.
        AC_CHECK_LIB(gss, gss_acquire_cred, [
          # Solaris
          KRB5_LIBS="$KRB5_LIBS -lgss"
        ], [
          # failed
          KRB5_LIBS=
        ], $KRB5_LIBS)
      ], [
        KRB5_LIBS="$KRB5_LIBS `$KRB5CONFIG --libs gssapi`"
        KRB5_CFLAGS="$KRB5_CFLAGS `$KRB5CONFIG --cflags gssapi`"
      ])
      AS_IF([test "$KRB5_LIBS" != ""], [
        AC_SUBST(KRB5_LIBS)
        AC_SUBST(KRB5_CFLAGS)

        # Although krb5-config exists, all systems still don't
        # have gssapi.h
        old_CFLAGS=$CFLAGS
        CFLAGS="$CFLAGS $KRB5_CFLAGS"
        AC_CHECK_HEADER([gssapi/gssapi.h], [
          AC_DEFINE(HAVE_GSSAPI_GSSAPI_H,, [GSSAPI headers in gssapi/gssapi.h])
          have_gssapi=yes
        ])
        AC_CHECK_HEADER([gssapi.h], [
          AC_DEFINE(HAVE_GSSAPI_H,, [GSSAPI headers in gssapi.h])
          have_gssapi=yes
        ])
        AS_IF([test $have_gssapi != no], [
          AS_IF([test $want_gssapi = plugin], [
            have_gssapi=plugin
          ])
          AC_DEFINE(HAVE_GSSAPI,, [Build with GSSAPI support])
          AC_CHECK_HEADERS(gssapi/gssapi_ext.h gssapi_krb5.h gssapi/gssapi_krb5.h)

          # MIT has a #define for Heimdal acceptor_identity, but it's way too
          # difficult to test for it..
          old_LIBS=$LIBS
          LIBS="$LIBS $KRB5_LIBS"
          AC_CHECK_FUNCS(gsskrb5_register_acceptor_identity krb5_gss_register_acceptor_identity)
          AC_CHECK_FUNCS(krb5_free_context)

          # does the kerberos library support SPNEGO?
          AC_CACHE_CHECK([whether GSSAPI supports SPNEGO],i_cv_gssapi_spnego,[
            AC_RUN_IFELSE([AC_LANG_PROGRAM([[
              #ifdef HAVE_GSSAPI_H
              #  include <gssapi.h>
              #else
              #  include <gssapi/gssapi.h>
              #endif
              #include <krb5.h>
              #include <string.h>
              ]], [[
                OM_uint32 minor_status;
                gss_OID_set mech_set;
                unsigned char spnego_oid[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };
                unsigned int i;

                gss_indicate_mechs(&minor_status, &mech_set);
                for (i = 0; i < mech_set->count; i++) {
            if (mech_set->elements[i].length == 6 &&
                memcmp(mech_set->elements[i].elements,
                 spnego_oid, 6) == 0)
                  return 0;
                }
                return 1;
            ]])],[
              i_cv_gssapi_spnego=yes
            ], [
              i_cv_gssapi_spnego=no
            ],[])
          ])
          AS_IF([test "$i_cv_gssapi_spnego" = "yes"], [
            AC_DEFINE(HAVE_GSSAPI_SPNEGO,, [GSSAPI supports SPNEGO])
          ])
          LIBS=$old_LIBS

          AS_IF([test $want_gssapi != plugin], [
            AUTH_LIBS="$AUTH_LIBS $KRB5_LIBS"
            AUTH_CFLAGS="$AUTH_CFLAGS $KRB5_CFLAGS"
            AC_DEFINE(BUILTIN_GSSAPI,, [GSSAPI support is built in])
          ], [
            have_gssapi_plugin=yes
          ])
        ], [
          AS_IF([test $want_gssapi != auto], [
            AC_MSG_ERROR(Can't build with GSSAPI support: gssapi.h not found)
          ])
        ])
        CFLAGS=$old_CFLAGS
      ])
    ], [
      AS_IF([test $want_gssapi != auto], [
        AC_MSG_ERROR(Can't build with GSSAPI support: krb5-config not found)
      ])
    ])
  ])
  AM_CONDITIONAL(GSSAPI_PLUGIN, test "$have_gssapi_plugin" = "yes")
])
