AC_DEFUN([AC_TYPEOF], [
  dnl * first check if we can get the size with redefining typedefs

  order="$2"
  AS_IF([test "$2" = ""], [
    order="int long long-long"
  ])

  result=""
  visible="unknown"
  AC_MSG_CHECKING([type of $1])
  AC_CACHE_VAL(i_cv_typeof_$1,[
  AS_IF([test "$ac_cv_c_compiler_gnu" = "yes"], [
    dnl * try with printf() + -Werror
    old_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS -Werror"

    for type in $order; do
      case "$type" in
        int)
          fmt="%d"
          ;;
        unsigned-int)
          fmt="%u"
          ;;
        long)
          fmt="%ld"
          ;;
        unsigned-long)
          fmt="%lu"
          ;;
        long-long)
          fmt="%lld"
          ;;
        unsigned-long-long)
          fmt="%llu"
          ;;
        *)
          fmt=""
          ;;
      esac

      AS_IF([test "$fmt" != ""], [
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
          #include <sys/types.h>
          #include <stdio.h>
        ]], [[
          printf("$fmt", ($1)0);
        ]])],[
          AS_IF([test "$result" != ""], [
            dnl * warning check isn't working
            result=""
            visible="unknown"
            break
          ])
          result="`echo $type|sed 's/-/ /g'`"
          visible="$result"
        ],[])
      ])
    done
    CFLAGS="$old_CFLAGS"
  ])

  AS_IF([test "$result" = ""], [
    for type in $order; do
      type="`echo $type|sed 's/-/ /g'`"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <sys/types.h>
        typedef $type $1;
      ]], [[]])],[
        AS_IF([test "$result" != ""], [
          dnl * compiler allows redefining to anything
          result=""
          visible="unknown"
          break
        ])
        result="$type"
        visible="$type"
      ],[])
    done
  ])

  AS_IF([test "$result" = ""], [
    dnl * check with sizes

    dnl * older autoconfs don't include sys/types.h, so do it manually
    AC_RUN_IFELSE([AC_LANG_PROGRAM([[
      #include <stdio.h>
      #include <sys/types.h>
      ]], [[
        FILE *f=fopen("conftestval", "w");
        if (!f) exit(1);
        fprintf(f, "%d\n", sizeof($1));
        exit(0);
    ]])],[
      size=`cat conftestval`
      rm -f conftestval

      for type in $order; do
        actype="ac_cv_sizeof_`echo $type|sed 's/-/_/g'`"
        AS_IF([test "$size" = "`eval echo \\$$actype`"], [
          result="`echo $type|sed 's/-/ /g'`"
          visible="`expr $size \* 8`bit (using $result)"
          break
        ])
      done
      AS_IF([test "$result" = ""], [
        result=unknown
        visible="`expr $size \* 8`bit (unknown type)"
      ])
    ],[],[])
  ])
  i_cv_typeof_$1=$result/$visible
  dnl * AC_CACHE_VAL
  ])

  typeof_$1=`echo $i_cv_typeof_$1 | sed s,/.*$,,`
  visible=`echo $i_cv_typeof_$1 | sed s,^.*/,,`
  AC_MSG_RESULT($visible)
])

