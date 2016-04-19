dnl **
dnl ** AIX mntctl
dnl **

AC_DEFUN([DOVECOT_MNTCTL], [
  if test $ac_cv_header_sys_vmount_h = yes; then
    AC_MSG_CHECKING([for reasonable mntctl buffer size])
    AC_RUN_IFELSE([AC_LANG_SOURCE([[
      #include <stdio.h>
      #include <stdlib.h>
      #include <sys/vmount.h>
      int main() {
        int size,count; char *m;
        FILE *f=fopen("conftestval", "w");
        if (!f) exit(1);
        if ((count=mntctl(MCTL_QUERY,sizeof(size),&size))!=0 || !(m=malloc(size)) ||
            (count=mntctl(MCTL_QUERY,size,m))<=0) exit(1);
          fprintf(f, "%d\n",(size * (count + 5))/count & ~1); /* 5 mounts more */
          exit(0);
      }
    ]])],[
      size=`cat conftestval`
      rm -f conftestval
      AC_DEFINE_UNQUOTED(STATIC_MTAB_SIZE,$size, [reasonable mntctl buffer size])
      AC_MSG_RESULT($size)
    ],[
      AC_MSG_RESULT(default)
    ])
  fi
])
