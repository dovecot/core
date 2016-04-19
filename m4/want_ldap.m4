AC_DEFUN([DOVECOT_WANT_LDAP], [
  have_ldap=no
  if test $want_ldap != no; then
          AC_CHECK_LIB(ldap, ldap_init, [
                  AC_CHECK_HEADER(ldap.h, [
                          AC_CHECK_LIB(ldap, ldap_initialize, [
                                  AC_DEFINE(LDAP_HAVE_INITIALIZE,, [Define if you have ldap_initialize])
                          ])
                          AC_CHECK_LIB(ldap, ldap_start_tls_s, [
                                  AC_DEFINE(LDAP_HAVE_START_TLS_S,, [Define if you have ldap_start_tls_s])
                          ])
                          LDAP_LIBS="-lldap"
                          AC_CHECK_LIB(ldap, ber_free, [
                            # do nothing, default is to add -lldap to LIBS
                            :
                          ], [
                            AC_CHECK_LIB(lber, ber_free, [
                              LDAP_LIBS="$LDAP_LIBS -llber"
                            ])
                          ])
                          AC_SUBST(LDAP_LIBS)
                          if test $want_ldap != plugin; then
                                  AUTH_LIBS="$AUTH_LIBS $LDAP_LIBS"
                                  AC_DEFINE(BUILTIN_LDAP,, [LDAP support is built in])
                          fi
  
                          AC_DEFINE(USERDB_LDAP,, [Build with LDAP support])
                          AC_DEFINE(PASSDB_LDAP,, [Build with LDAP support])
                          AC_CHECK_HEADERS(sasl.h sasl/sasl.h)
                          have_ldap=yes
                  ], [
                    if test $want_ldap != auto; then
                      AC_ERROR([Can't build with LDAP support: ldap.h not found])
                    fi
                  ])
          ], [
            if test $want_ldap != auto; then
              AC_ERROR([Can't build with LDAP support: libldap not found])
            fi
          ])
  fi
  
  if test $have_ldap = no; then
    not_passdb="$not_passdb ldap"
    not_userdb="$not_userdb ldap"
  else
    userdb="$userdb ldap"
    passdb="$passdb ldap"
    if test $want_ldap = plugin; then
      have_ldap_plugin=yes
      userdb="$userdb (plugin)"
      passdb="$passdb (plugin)"
    fi
  fi
  AM_CONDITIONAL(LDAP_PLUGIN, test "$have_ldap_plugin" = "yes")
  AM_CONDITIONAL(HAVE_LDAP, test "$want_ldap" = "yes")
])
