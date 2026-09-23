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

    AC_CHECK_LIB(cassandra, cass_cluster_set_application_name, [
      AC_DEFINE(HAVE_CASSANDRA_APPLICATION_NAME, 1, [
        Cassandra supports setting application name and version
      ])
    ],, $CASSANDRA_LIBS)

    AC_CHECK_LIB(cassandra, cass_cluster_set_client_id, [
      AC_DEFINE(HAVE_CASSANDRA_CLIENT_ID, 1, [
        Cassandra supports setting client ID
      ])
    ],, $CASSANDRA_LIBS)

    AC_CHECK_LIB(cassandra, cass_cluster_set_local_address, [
      AC_DEFINE(HAVE_CASSANDRA_LOCAL_ADDRESS, 1, [
        Cassandra supports setting local address
      ])
    ],, $CASSANDRA_LIBS)

    AC_CHECK_LIB(cassandra, cass_cluster_set_token_aware_routing_shuffle_replicas, [
      AC_DEFINE(HAVE_CASSANDRA_SHUFFLE_REPLICAS, 1, [
        Cassandra supports disabling token-aware replica shuffling
      ])
    ],, $CASSANDRA_LIBS)

    AC_CHECK_LIB(cassandra, cass_cluster_set_exponential_reconnect, [
      AC_DEFINE(HAVE_CASSANDRA_RECONNECT_POLICY, 1, [
        Cassandra supports configuring reconnection policy
      ])
    ],, $CASSANDRA_LIBS)
  ])
])
