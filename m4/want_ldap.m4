AC_DEFUN([DOVECOT_WANT_LDAP], [
  have_ldap=no

  AS_IF([test "$want_ldap" != "no"], [
    PKG_CHECK_MODULES([LDAP], [ldap >= 2.4], [have_ldap=yes], [have_ldap=no])

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

    AC_CHECK_LIB(ldap, ldap_initialize, :, [
      AC_MSG_ERROR([
        cannot build with LDAP support: function ldap_initialize() not found
        (OpenLDAP >= 2.4 required)
      ])
    ], $LDAP_LIBS)

    AC_DEFINE(HAVE_LDAP,, [Build with LDAP support])
    AC_CHECK_HEADERS(sasl.h sasl/sasl.h)
  ], [
    not_passdb="$not_passdb ldap"
    not_userdb="$not_userdb ldap"
  ])

  AM_CONDITIONAL(LDAP_PLUGIN, test "$have_ldap_plugin" = "yes")
  AM_CONDITIONAL(HAVE_LDAP, test "$want_ldap" != "no")
])
