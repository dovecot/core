AC_DEFUN([DOVECOT_RPCGEN], [
  RPCGEN=${RPCGEN-rpcgen}
  if ! $RPCGEN -c /dev/null > /dev/null; then
    RPCGEN=
  fi
  AC_SUBST(RPCGEN)
  
  have_rquota=no
  if test -f /usr/include/rpcsvc/rquota.x && test -n "$RPCGEN"; then
    AC_CHECK_HEADER([rpc/rpc.h], [
      AC_DEFINE(HAVE_RQUOTA,, [Define if you wish to retrieve quota of NFS mounted mailboxes])
      have_rquota=yes
    ])
  fi
  AM_CONDITIONAL(HAVE_RQUOTA, test "$have_rquota" = "yes")
])

AC_DEFUN([DOVECOT_QUOTA], [
  AC_SEARCH_LIBS(quota_open, quota, [
    AC_DEFINE(HAVE_QUOTA_OPEN,, [Define if you have quota_open()])
    QUOTA_LIBS="-lquota"
  ])
  AC_SUBST(QUOTA_LIBS)
])
