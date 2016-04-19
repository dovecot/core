dnl * I/O loop function
AC_DEFUN([DOVECOT_IOLOOP], [
  have_ioloop=no
  
  if test "$ioloop" = "best" || test "$ioloop" = "epoll"; then
    AC_CACHE_CHECK([whether we can use epoll],i_cv_epoll_works,[
      AC_TRY_RUN([
        #include <sys/epoll.h>
    
        int main()
        {
  	return epoll_create(5) < 1;
        }
      ], [
        i_cv_epoll_works=yes
      ], [
        i_cv_epoll_works=no
      ])
    ])
    if test $i_cv_epoll_works = yes; then
      AC_DEFINE(IOLOOP_EPOLL,, [Implement I/O loop with Linux 2.6 epoll()])
      have_ioloop=yes
      ioloop=epoll
    else
      if test "$ioloop" = "epoll" ; then
        AC_MSG_ERROR([epoll ioloop requested but epoll_create() is not available])
      fi
    fi
  fi
  
  if test "$ioloop" = "best" || test "$ioloop" = "kqueue"; then
      if test "$ac_cv_func_kqueue" = yes && test "$ac_cv_func_kevent" = yes; then
        AC_DEFINE(IOLOOP_KQUEUE,, [Implement I/O loop with BSD kqueue()])
        ioloop=kqueue
        have_ioloop=yes
      elif test "$ioloop" = "kqueue"; then
        AC_MSG_ERROR([kqueue ioloop requested but kqueue() is not available])
      fi
  fi
  
  if test "$ioloop" = "best" || test "$ioloop" = "poll"; then
    AC_CHECK_FUNC(poll, [
      AC_DEFINE(IOLOOP_POLL,, [Implement I/O loop with poll()])
      ioloop=poll
      have_ioloop=yes
    ])
  fi
  
  if test "$have_ioloop" = "no"; then
    AC_DEFINE(IOLOOP_SELECT,, [Implement I/O loop with select()])
    ioloop="select"
  fi
]) 
