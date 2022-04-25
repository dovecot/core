dnl * Check if statvfs() can be used to find out block device for files
AC_DEFUN([DOVECOT_FILE_BLOCKDEV], [
  AC_CACHE_CHECK([if statvfs.f_mntfromname exists],i_cv_have_statvfs_f_mntfromname,[
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <sys/types.h>
      #include <sys/statvfs.h>
    ]], [[
      struct statvfs buf;
      char *p = buf.f_mntfromname;

      statvfs(".", &buf);
    ]])], [
      i_cv_have_statvfs_f_mntfromname=yes
    ], [
      i_cv_have_statvfs_f_mntfromname=no
    ])
  ])
  AS_IF([test $i_cv_have_statvfs_f_mntfromname = yes], [
    AC_DEFINE(HAVE_STATVFS_MNTFROMNAME,, [Define if you have statvfs.f_mntfromname])
  ])

  dnl * Check if statfs() can be used to find out block device for files
  AC_CACHE_CHECK([if statfs.f_mntfromname exists],i_cv_have_statfs_f_mntfromname,[
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <sys/param.h>
      #include <sys/mount.h>
    ]], [[
      struct statfs buf;
      char *p = buf.f_mntfromname;

      statfs(".", &buf);
    ]])], [
      i_cv_have_statfs_f_mntfromname=yes
    ], [
      i_cv_have_statfs_f_mntfromname=no
    ])
  ])
  AS_IF([test $i_cv_have_statfs_f_mntfromname = yes], [
    AC_DEFINE(HAVE_STATFS_MNTFROMNAME,, [Define if you have statfs.f_mntfromname])
  ])
])
