AC_DEFUN([DOVECOT_WANT_LUA_PLUGIN],[
  AC_ARG_WITH([lua-plugin],
    [AS_HELP_STRING([--with-lua-plugin], [build Lua as plugin @<:@default=no@:>@])],
    [with_lua_plugin=$withval],
    [with_lua_plugin=no]
  )
  AM_CONDITIONAL([AUTH_LUA_PLUGIN], [test "x$with_lua_plugin" = "xyes"])
])

AC_DEFUN([DOVECOT_WANT_LUAJIT],[
  AS_IF([test "$xwith_luajit" = "xplugin"], [with_lua_plugin=yes], [])
  AC_MSG_CHECKING([whether we will be linking in LuaJIT])
  AC_ARG_WITH([luajit],
    [AS_HELP_STRING([--with-luajit], [build LuaJIT bindings @<:@default=auto@:>@])],
    [with_luajit=$withval],
    [with_luajit=no]
  )
  AC_MSG_RESULT([$with_luajit])

  AS_IF([test "x$with_luajit" != "xno"], [
    LUAJITPC="$with_luajit"
    PKG_CHECK_MODULES([LUA], [luajit],
      [AC_DEFINE([HAVE_LUA], [1], [Define to 1 if you have LuaJIT])],
      [LUAJITPC=""]
    )
    AS_IF([test "x$LUAJITPC" = "x"], [
      AC_MSG_ERROR([LuaJIT not found])]
    )
  ])

  AS_IF([test "x$with_luajit" = "xyes"],
    AS_IF([test "x$with_lua_plugin" != "xyes"],
     AC_DEFINE([BUILTIN_LUA],, [Lua support is builtin])
   )
  )
])

AC_DEFUN([DOVECOT_WANT_LUA],[
  AS_IF([test "$xwith_lua" = "xplugin"], [with_lua_plugin=yes], [])
  AC_MSG_CHECKING([whether we will be linking in Lua])
  AC_ARG_WITH([lua],
    [AS_HELP_STRING([--with-lua], [build Lua Bindings @<:@default=auto@:>@])],
    [with_lua=$withval],
    [with_lua=auto]
  )
  AC_MSG_RESULT([$with_lua])

  AS_IF([test "x$with_lua" != "xno"],[
    AS_IF([test "x$with_lua" = "xyes" -o "x$with_lua" = "xauto"],
      [for LUAPC in lua5.3 lua-5.3 lua53 lua5.2 lua-5.2 lua52 lua5.1 lua-5.1 lua51 lua; do
         PKG_CHECK_MODULES([LUA], $LUAPC >= 5.1, [
           AC_DEFINE([HAVE_LUA], [1], [Define to 1 if you have lua])
           with_lua=yes
         ], [LUAPC=""]) # otherwise pkg_check will fail
         if test "x$LUA_LIBS" != "x"; then break; fi
       done
      ],
      [LUAPC="$with_lua"
        PKG_CHECK_MODULES([LUA], $LUAPC >= 5.1, [
          AC_DEFINE([HAVE_LUA], [1], [Define to 1 if you have lua])
          with_lua=yes
        ])
    ])
    AC_MSG_CHECKING([for chosen LUA])
    AS_IF([test "x$LUAPC" = "x"], [
      AS_IF([test "x$with_lua" = "xyes"],
        [AC_MSG_ERROR([cannot find lua])],
        [AC_MSG_RESULT([not found])]
      )],[
        AC_MSG_RESULT([$LUAPC])
      ])
    ])

  AS_IF([test "x$with_lua" = "xyes"],
    AS_IF([test "x$with_lua_plugin" != "xyes"],
     AC_DEFINE([BUILTIN_LUA],, [Lua support is builtin])
   )
  )
])
