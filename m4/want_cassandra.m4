AC_DEFUN([DOVECOT_WANT_CASSANDRA], [
  have_cassandra=no

  AS_IF([test "$want_cassandra" != "no"], [
    PKG_CHECK_MODULES([CASSANDRA], [cassandra], [have_cassandra=yes], [
      have_cassandra=no

      AS_IF([test "$want_cassandra" = "yes"], [
        AC_MSG_ERROR([cannot build with Cassandra support: cassandra library not found])
      ])
    ])
  ])

  AS_IF([test "$want_cassandra" != "no"], [
    found_sql_drivers="$found_sql_drivers cassandra"
    AC_DEFINE(HAVE_CASSANDRA,, [Build with Cassandra support])

    AC_CHECK_LIB(cassandra, cass_cluster_set_constant_speculative_execution_policy, [
      AC_DEFINE(HAVE_CASSANDRA_SPECULATIVE_POLICY, 1, [
        Cassandra supports speculative execution policy
      ])
    ],, $CASSANDRA_LIBS)

    AC_CHECK_LIB(cassandra, cass_cluster_set_use_hostname_resolution, [
      AC_DEFINE(HAVE_CASS_CLUSTER_SET_USE_HOSTNAME_RESOLUTION,, [
        Build with cass_cluster_set_use_hostname_resolution() support
      ])
    ],, $CASSANDRA_LIBS)

    AC_CHECK_DECLS([CASS_SSL_VERIFY_PEER_IDENTITY_DNS], [], [], [[
      #include <cassandra.h>
    ]])
  ])
])
