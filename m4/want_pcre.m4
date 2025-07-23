AC_DEFUN([DOVECOT_WANT_PCRE], [
  have_pcre=no

  AS_IF([test "$want_pcre" != "no"], [
    PKG_CHECK_MODULES([LIBPCRE], [libpcre2-32], [have_pcre=yes], [
      have_pcre=no

      AS_IF([test "$want_pcre" = "yes"], [
        AC_MSG_ERROR(cannot build with pcre support: pcre library (libpcre2-32) not found)
      ])
    ])
  ])

  AS_IF([test "$have_pcre" != "no"], [
    AC_DEFINE(HAVE_LIBPCRE,, [Define if you have libpcre2 backed regular expressions])
  ])

  AM_CONDITIONAL(BUILD_LIBREGEX, test "$have_pcre" = "yes")
])
