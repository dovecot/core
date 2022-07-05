AC_DEFUN([DOVECOT_WANT_LDAP], [
  have_ldap=no

  AS_IF([test "$want_ldap" != "no"], [
    PKG_CHECK_MODULES([LDAP], [ldap], [have_ldap=yes], [have_ldap=no])

    dnl obsolete check for library, remove as soon all supported
    dnl platforms have proper pkg-check files
    AS_IF([test "$have_ldap" = "no"], [
      AC_CHECK_LIB(ldap, ldap_init, [
        have_ldap=yes

        LDAP_LIBS="-lldap"
        AC_CHECK_LIB(ldap, ber_free, [
          # do nothing, default is to add -lldap to LIBS
          :
        ], [
          AC_CHECK_LIB(lber, ber_free, [
            LDAP_LIBS="$LDAP_LIBS -llber"
          ],, $LDAP_LIBS)
        ], $LDAP_LIBS)
        AC_SUBST(LDAP_LIBS)
      ],, $LDAP_LIBS)
    ])

    AS_IF([test "$want_ldap" = "yes" && test "$have_ldap" = "no"], [
      AC_MSG_ERROR([cannot build with LDAP support: ldap library not found])
    ])
  ])

  AS_IF([test "$have_ldap" != "no"], [
    userdb="$userdb ldap"
    passdb="$passdb ldap"

    AS_IF([test "$want_ldap" = "plugin"], [
      have_ldap_plugin=yes
      userdb="$userdb (plugin)"
      passdb="$passdb (plugin)"
    ], [
      AUTH_LIBS="$AUTH_LIBS $LDAP_LIBS"
      DICT_LIBS="$DICT_LIBS $LDAP_LIBS"
      AC_DEFINE(BUILTIN_LDAP,, [LDAP support is built in])
    ])

    AC_DEFINE(LDAP_DEPRECATED, [1], [
      Functions like ldap_bind() have been deprecated in OpenLDAP 2.3
      This define enables them until the code here can be refactored
    ])

    AC_CHECK_LIB(ldap, ldap_initialize, [
      AC_DEFINE(LDAP_HAVE_INITIALIZE,, [Define if you have ldap_initialize])
    ],, $LDAP_LIBS)
    AC_CHECK_LIB(ldap, ldap_start_tls_s, [
      AC_DEFINE(LDAP_HAVE_START_TLS_S,, [Define if you have ldap_start_tls_s])
    ],, $LDAP_LIBS)
    AC_DEFINE(USERDB_LDAP,, [Build with LDAP support])
    AC_DEFINE(PASSDB_LDAP,, [Build with LDAP support])
    AC_CHECK_HEADERS(sasl.h sasl/sasl.h)
  ], [
    not_passdb="$not_passdb ldap"
    not_userdb="$not_userdb ldap"
  ])

  AM_CONDITIONAL(LDAP_PLUGIN, test "$have_ldap_plugin" = "yes")
  AM_CONDITIONAL(HAVE_LDAP, test "$want_ldap" != "no")
])
