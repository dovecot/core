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

  AS_IF([test "x$with_lua" != "xno"],
    [for LUAPC in lua5.3 lua-5.3 lua53 lua5.2 lua-5.2 lua52 lua5.1 lua-5.1 lua51 lua; do
       PKG_CHECK_MODULES([LUA], $LUAPC >= 5.1, [
         AC_DEFINE([HAVE_LUA], [1], [Define to 1 if you have lua])
         with_lua=yes
       ], [LUAPC=""]) # otherwise pkg_check will fail
       if test "x$LUA_LIBS" != "x"; then break; fi
     done
  ])

  AS_IF([test "x$with_lua" = "xyes"], [
    AC_MSG_CHECKING([for chosen LUA])
    AS_IF([test "x$LUAPC" = "x"], [
        AC_MSG_ERROR([cannot find lua])
      ],[
        AC_MSG_RESULT([$LUAPC])
      ])
  ])

  AS_IF([test "x$with_lua" = "xyes"],
    AS_IF([test "x$with_lua_plugin" != "xyes"],
     AC_DEFINE([BUILTIN_LUA],, [Lua support is builtin])
   )
  )
])
