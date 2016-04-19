dnl * see if fd passing works
AC_DEFUN([DOVECOT_FD_PASSING], [
  AC_CACHE_CHECK([whether fd passing works],i_cv_fd_passing,[
    for i in 1 2; do
      old_cflags="$CFLAGS"
      CFLAGS="$CFLAGS -I$srcdir/src/lib $srcdir/src/lib/fdpass.c"
      if test $i = 2; then
        CFLAGS="$CFLAGS -DBUGGY_CMSG_MACROS"
      fi
    
      AC_TRY_RUN([
        #include <sys/types.h>
        #include <sys/socket.h>
        #include <sys/wait.h>
        #include <sys/stat.h>
        #include <unistd.h>
        #include <fcntl.h>
        #include "fdpass.h"
        
        int nopen(void)
        {
  	      int i, n;
  	      struct stat sb;
  	      for (i = n = 0; i < 256; i++)
  		  if (fstat(i, &sb) == 0) n++;
  	      return n;
        }
        int main(void)
        {
  	      int fd[2], send_fd, recv_fd, status, n1, n2;
  	      struct stat st, st2;
  	      char data;
        
  	      send_fd = creat("conftest.fdpass", 0600);
  	      if (send_fd == -1) return 2;
  	      unlink("conftest.fdpass");
  	      if (fstat(send_fd, &st) < 0) return 2;
  	      if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) return 2;
  	      n1 = nopen();
        
  	      switch (fork()) {
  	      case -1:
  		      return 2;
  	      case 0:
  		      alarm(1);
  		      if (fd_send(fd[0], send_fd, &data, 1) != 1) return 2;
  		      return 0;
  	      default:
  		      alarm(2);
  		      if (wait(&status) == -1)
  			return 2;
  		      if (status != 0)
  			return status;
  		      if (fd_read(fd[1], &data, 1, &recv_fd) != 1) return 1;
  		      if (fstat(recv_fd, &st2) < 0) return 2;
  		      /* nopen check is for making sure that only a single fd
  		         was received */
  		      n2 = nopen();
  		      return st.st_ino == st2.st_ino && n2 == n1 + 1 ? 0 : 1;
  	      }
        }
      ], [
        CFLAGS=$old_cflags
        if test $i = 2; then
  	i_cv_fd_passing=buggy_cmsg_macros
        else
          i_cv_fd_passing=yes
        fi
        break
      ], [
        dnl no, try with BUGGY_CMSG_MACROS
        CFLAGS=$old_cflags
        i_cv_fd_passing=no
      ])
    done
  ]);
  
  case "$host_os" in
  darwin[[1-9]].*)
  	if test "$i_cv_fd_passing" = "yes"; then
  		i_cv_fd_passing=buggy_cmsg_macros
  	fi
  	;;
  esac
  
  if test $i_cv_fd_passing = buggy_cmsg_macros; then
    AC_DEFINE(BUGGY_CMSG_MACROS,, [Define if you have buggy CMSG macros])
  fi
  if test $i_cv_fd_passing = no; then
    AC_ERROR([fd passing is required for Dovecot to work])
  fi
])
