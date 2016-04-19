AC_DEFUN([AC_TYPEOF], [
  dnl * first check if we can get the size with redefining typedefs

  order="$2"
  if test "$2" = ""; then
    order="int long long-long"
  fi

  result=""
  visible="unknown"
  AC_MSG_CHECKING([type of $1])
  AC_CACHE_VAL(i_cv_typeof_$1,[
  if test "x$ac_cv_c_compiler_gnu" = "xyes"; then
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

      if test "$fmt" != ""; then
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
	  #include <sys/types.h>
	  #include <stdio.h>
	]], [[
	  printf("$fmt", ($1)0);
	]])],[
	  if test "$result" != ""; then
	    dnl * warning check isn't working
	    result=""
	    visible="unknown"
	    break
	  fi
	  result="`echo $type|sed 's/-/ /g'`"
	  visible="$result"
	],[])
      fi
    done
    CFLAGS="$old_CFLAGS"
  fi

  if test "$result" = ""; then
    for type in $order; do
      type="`echo $type|sed 's/-/ /g'`"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
	#include <sys/types.h>
	typedef $type $1;
      ]], [[]])],[
	if test "$result" != ""; then
	  dnl * compiler allows redefining to anything
	  result=""
	  visible="unknown"
	  break
	fi
	result="$type"
	visible="$type"
      ],[])
    done
  fi

  if test "$result" = ""; then
    dnl * check with sizes

    dnl * older autoconfs don't include sys/types.h, so do it manually
    AC_RUN_IFELSE([AC_LANG_SOURCE([[
      #include <stdio.h>
      #include <sys/types.h>
      int main() {
	FILE *f=fopen("conftestval", "w");
	if (!f) exit(1);
	fprintf(f, "%d\n", sizeof($1));
	exit(0);
      }
    ]])],[
      size=`cat conftestval`
      rm -f conftestval

      for type in $order; do
        actype="ac_cv_sizeof_`echo $type|sed 's/-/_/g'`"
        if test "$size" = "`eval echo \\$$actype`"; then
	  result="`echo $type|sed 's/-/ /g'`"
	  visible="`expr $size \* 8`bit (using $result)"
	  break
	fi
      done
      if test "$result" = ""; then
        result=unknown
	visible="`expr $size \* 8`bit (unknown type)"
      fi
    ],[],[])
  fi
  i_cv_typeof_$1=$result/$visible
  ])

  typeof_$1=`echo $i_cv_typeof_$1 | sed s,/.*$,,`
  visible=`echo $i_cv_typeof_$1 | sed s,^.*/,,`
  AC_MSG_RESULT($visible)
])

