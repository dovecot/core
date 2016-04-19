dnl * Compatible sendfile()
AC_DEFUN([DOVECOT_SENDFILE], [
  AC_CHECK_LIB(sendfile, sendfile, [
    LIBS="$LIBS -lsendfile"
    AC_DEFINE(HAVE_SOLARIS_SENDFILE,, [Define if you have Solaris-compatible sendfile()])
  ], [
    dnl * Linux compatible sendfile() - don't check if Solaris one was found.
    dnl * This seems to pass with Solaris for some reason..
    AC_CACHE_CHECK([Linux compatible sendfile()],i_cv_have_linux_sendfile,[
      AC_TRY_LINK([
        #undef _FILE_OFFSET_BITS
        #include <sys/types.h>
        #include <sys/socket.h>
        #include <sys/sendfile.h>
      ], [
        sendfile(0, 0, (void *) 0, 0);
      ], [
        i_cv_have_linux_sendfile=yes
      ], [
        i_cv_have_linux_sendfile=no
      ])
    ])
    if test $i_cv_have_linux_sendfile = yes; then
      AC_DEFINE(HAVE_LINUX_SENDFILE,, [Define if you have Linux-compatible sendfile()])
    fi
  
    dnl * FreeBSD compatible sendfile()
    AC_CACHE_CHECK([FreeBSD compatible sendfile()],i_cv_have_freebsd_sendfile,[
      AC_TRY_LINK([
        #include <sys/types.h>
        #include <sys/socket.h>
        #include <sys/uio.h>
      ], [
        struct sf_hdtr hdtr;
        sendfile(0, 0, 0, 0, &hdtr, (void *) 0, 0);
      ], [
        i_cv_have_freebsd_sendfile=yes
      ], [
        i_cv_have_freebsd_sendfile=no
      ])
    ])
    if test $i_cv_have_freebsd_sendfile = yes; then
      AC_DEFINE(HAVE_FREEBSD_SENDFILE,, [Define if you have FreeBSD-compatible sendfile()])
    fi
  ])
])
