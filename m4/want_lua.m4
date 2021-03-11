AC_DEFUN([DOVECOT_WANT_LUA],[
  AC_ARG_WITH([lua],
    [AS_HELP_STRING([--with-lua=yes|plugin], [build Lua Bindings])],
    [with_lua=$withval],
    [with_lua=no]
  )

  AC_MSG_CHECKING([whether we will be linking in Lua])
  AS_IF([test "x$with_lua" = "xplugin"], [
     with_lua_plugin=yes
     with_lua=yes
  ])
  AC_MSG_RESULT([$with_lua])

  AS_IF([test "x$with_lua" != "xno"], [
    AS_IF([test -n "$LUA_CFLAGS" -o -n "$LUA_LIBS"], [
      with_lua=yes
    ], [
      for LUAPC in lua5.3 lua-5.3 lua53 lua5.1 lua-5.1 lua51 lua; do
         PKG_CHECK_MODULES([LUA], [$LUAPC >= 5.1 $LUAPC != 5.2] , [
           with_lua=yes
         ], [LUAPC=""]) # otherwise pkg_check will fail
         if test "x$LUA_LIBS" != "x"; then break; fi
       done
    ])
  ])

  AS_IF([test "x$with_lua" = "xyes"], [
    AC_MSG_CHECKING([for chosen LUA])
    AC_DEFINE([HAVE_LUA], [1], [Define to 1 if you have lua])
    AS_IF([test "x$LUAPC" != "x"], [
      AC_MSG_RESULT([$LUAPC])
    ],[
      AC_MSG_RESULT([specified via LUA_CFLAGS and LUA_LIBS])
    ])
  ])

  AS_IF([test "x$with_lua" = "xyes"],
    AS_IF([test "x$with_lua_plugin" != "xyes"],
     AC_DEFINE([BUILTIN_LUA],, [Lua support is builtin])
   )
   dnl Check if various lua functions are present
   old_CFLAGS="$CFLAGS"
   CFLAGS="$CFLAGS $LUA_CFLAGS"
   old_LIBS="$LIBS"
   LIBS="$LIBS $LUA_LIBS"

   AC_CHECK_FUNCS([luaL_setfuncs])
   AC_CHECK_FUNCS([luaL_setmetatable])
   AC_CHECK_FUNCS([lua_isinteger])
   AC_CHECK_FUNCS([lua_tointegerx])

   CFLAGS="$old_CFLAGS"
   LIBS="$old_LIBS"
  )
])
