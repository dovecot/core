dnl * gcc specific options
AC_DEFUN([DOVECOT_CFLAGS],[
  if test "x$ac_cv_c_compiler_gnu" = "xyes"; then
        # -Wcast-qual -Wcast-align -Wconversion -Wunreachable-code # too many warnings
        # -Wstrict-prototypes -Wredundant-decls # may give warnings in some systems
        # -Wmissing-format-attribute -Wmissing-noreturn -Wwrite-strings # a couple of warnings
        CFLAGS="$CFLAGS -Wall -W -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wformat=2 -Wbad-function-cast"

        if test "$have_clang" = "yes"; then
          AC_TRY_COMPILE([
          #if __clang_major__ > 3 || (__clang_major__ == 3 && __clang_minor__ >= 3)
          #  error new clang
          #endif
          ],,,[
            # clang 3.3+ unfortunately this gives warnings with hash.h
            CFLAGS="$CFLAGS -Wno-duplicate-decl-specifier"
          ])
        else
          # This is simply to avoid warning when building strftime() wrappers..
          CFLAGS="$CFLAGS -fno-builtin-strftime"
        fi

        AC_TRY_COMPILE([
        #if __GNUC__ < 4
        #  error old gcc
        #endif
        ],,[
          # gcc4
          CFLAGS="$CFLAGS -Wstrict-aliasing=2"
        ])

        # Use std=gnu99 if we have new enough gcc
        old_cflags=$CFLAGS
        CFLAGS="-std=gnu99"
        AC_TRY_COMPILE([
        ],, [
          CFLAGS="$CFLAGS $old_cflags"
        ], [
          CFLAGS="$old_cflags"
        ])

  fi
  if test "$have_clang" = "yes"; then
    # clang specific options
    if test "$want_devel_checks" = "yes"; then
      # FIXME: enable once md[45], sha[12] can be compiled without
      #CFLAGS="$CFLAGS -fsanitize=integer,undefined -ftrapv"
      :
    fi
  fi
])
