AC_DEFUN([DOVECOT_NOTIFY], [
  have_notify=none
  
  AS_IF([test "$notify" = "" || test "$notify" = "inotify"], [
    dnl * inotify?
    AC_MSG_CHECKING([whether we can use inotify])
    AS_IF([test "$ac_cv_func_inotify_init" = yes], [
      have_notify=inotify
      notify=inotify
      AC_MSG_RESULT("yes")
      AC_DEFINE(IOLOOP_NOTIFY_INOTIFY,, [Use Linux inotify])
    ], [
      AC_MSG_RESULT("no")
      AS_IF([test "$notify" = "inotify"], [
        AC_MSG_ERROR([inotify requested but not available])
        notify=""
      ])
    ])
  ])
  
  AS_IF([(test "$notify" = "" && test "$ioloop" = kqueue) || test "$notify" = "kqueue"], [
    dnl * BSD kqueue() notify
    AC_MSG_CHECKING([whether we can use BSD kqueue() notify])
    AS_IF([test "$ac_cv_func_kqueue" = yes && test "$ac_cv_func_kevent" = yes], [
      have_notify=kqueue
      notify=kqueue
      AC_MSG_RESULT("yes")
      AC_DEFINE(IOLOOP_NOTIFY_KQUEUE,, [Use BSD kqueue directory changes notification])
    ], [
      AC_MSG_RESULT("no")
      AS_IF([test "$notify" = "kqueue"], [
        AC_MSG_ERROR([kqueue notify requested but kqueue() is not available])
        notify=""
      ])
    ])
  ])
  
  AS_IF([test "$have_notify" = "none"], [
    AC_DEFINE(IOLOOP_NOTIFY_NONE,, [No special notify support])
  ])
])
