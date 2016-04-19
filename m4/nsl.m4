AC_DEFUN([DOVECOT_NSL], [
  AC_SEARCH_LIBS([inet_aton], [resolv])
  AC_SEARCH_LIBS([gethostbyname], [nsl])
  AC_SEARCH_LIBS([socket], [socket])
  AC_SEARCH_LIBS([gethostent], [nsl])
])
