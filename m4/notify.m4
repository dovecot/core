AC_DEFUN([DOVECOT_NOTIFY], [
  have_notify=none
  
  if test "$notify" = "" || test "$notify" = "inotify" ; then
    dnl * inotify?
    AC_MSG_CHECKING([whether we can use inotify])
    if test "$ac_cv_func_inotify_init" = yes; then
      have_notify=inotify
      notify=inotify
      AC_MSG_RESULT("yes")
      AC_DEFINE(IOLOOP_NOTIFY_INOTIFY,, [Use Linux inotify])
    else
      AC_MSG_RESULT("no")
      if test "$notify" = "inotify"; then
        AC_MSG_ERROR([inotify requested but not available])
        notify=""
      fi
    fi
  fi
  
  if (test "$notify" = "" && test "$ioloop" = kqueue) || test "$notify" = "kqueue"; then
    dnl * BSD kqueue() notify
    AC_MSG_CHECKING([whether we can use BSD kqueue() notify])
    if test "$ac_cv_func_kqueue" = yes && test "$ac_cv_func_kevent" = yes ; then
      have_notify=kqueue
      notify=kqueue
      AC_MSG_RESULT("yes")
      AC_DEFINE(IOLOOP_NOTIFY_KQUEUE,, [Use BSD kqueue directory changes notificaton])
    else 
      AC_MSG_RESULT("no")
      if test "$notify" = "kqueue" ; then
        AC_MSG_ERROR([kqueue notify requested but kqueue() is not available])
        notify=""
      fi
    fi
  fi
  
  if test "$have_notify" = "none"; then
    AC_DEFINE(IOLOOP_NOTIFY_NONE,, [No special notify support])
  fi
]) 
