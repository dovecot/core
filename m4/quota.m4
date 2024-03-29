AC_DEFUN([DOVECOT_RPCGEN], [
  RPCGEN=${RPCGEN-rpcgen}
  AS_IF([! $RPCGEN -c /dev/null >/dev/null], [
    RPCGEN=
  ])
  AC_SUBST(RPCGEN)
  
  have_rquota=no
  AS_IF([test -f /usr/include/rpcsvc/rquota.x && test -n "$RPCGEN"], [
    PKG_CHECK_MODULES(LIBTIRPC, libtirpc, [
      have_rquota=yes
      QUOTA_LIBS="$QUOTA_LIBS \$(LIBTIRPC_LIBS)"
    ], [
      AC_CHECK_HEADER([rpc/rpc.h], [
        have_rquota=yes
      ])
    ])
  ])
  AS_IF([test "$have_rquota" = yes], [
    AC_DEFINE(HAVE_RQUOTA,, [Define if you wish to retrieve quota of NFS mounted mailboxes])
  ])
  AM_CONDITIONAL(HAVE_RQUOTA, test "$have_rquota" = "yes")
])

AC_DEFUN([DOVECOT_QUOTA], [
  AC_SEARCH_LIBS(quota_open, quota, [
    AC_DEFINE(HAVE_QUOTA_OPEN,, [Define if you have quota_open()])
    QUOTA_LIBS="$QUOTA_LIBS -lquota"
  ])
  AC_SUBST(QUOTA_LIBS)
])
