dnl * I/O loop function
AC_DEFUN([DOVECOT_IOLOOP], [
  have_ioloop=no
  
  AS_IF([test "$ioloop" = "best" || test "$ioloop" = "epoll"], [
    AC_CACHE_CHECK([whether we can use epoll],i_cv_epoll_works,[
      AC_RUN_IFELSE([AC_LANG_PROGRAM([[
        #include <sys/epoll.h>
      ]], [[
        return epoll_create(5) < 1;
      ]])],[
        i_cv_epoll_works=yes
      ], [
        i_cv_epoll_works=no
      ],[])
    ])
    AS_IF([test $i_cv_epoll_works = yes], [
      AC_DEFINE(IOLOOP_EPOLL,, [Implement I/O loop with Linux 2.6 epoll()])
      have_ioloop=yes
      ioloop=epoll
    ], [
      AS_IF([test "$ioloop" = "epoll"], [
        AC_MSG_ERROR([epoll ioloop requested but epoll_create() is not available])
      ])
    ])
  ])
  
  AS_IF([test "$ioloop" = "best" || test "$ioloop" = "kqueue"], [
      AS_IF([test "$ac_cv_func_kqueue" = yes && test "$ac_cv_func_kevent" = yes], [
        AC_DEFINE(IOLOOP_KQUEUE,, [Implement I/O loop with BSD kqueue()])
        ioloop=kqueue
        have_ioloop=yes
      ], [test "$ioloop" = "kqueue"], [
        AC_MSG_ERROR([kqueue ioloop requested but kqueue() is not available])
      ])
  ])
  
  AS_IF([test "$ioloop" = "best" || test "$ioloop" = "poll"], [
    AC_CHECK_FUNC(poll, [
      AC_DEFINE(IOLOOP_POLL,, [Implement I/O loop with poll()])
      ioloop=poll
      have_ioloop=yes
    ], [
      AS_IF([test "$ioloop" = "poll"], [
        AC_MSG_ERROR([pool ioloop requested but poll() is not available])
      ])
     ])
  ])
  
  AS_IF([test "$have_ioloop" = "no"], [
    AC_DEFINE(IOLOOP_SELECT,, [Implement I/O loop with select()])
    ioloop="select"
  ])
])
