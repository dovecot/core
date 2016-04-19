dnl * how large time_t values does gmtime() accept?
AC_DEFUN([DOVECOT_GMTIME_MAX], [
  AC_CACHE_CHECK([how large time_t values gmtime() accepts],i_cv_gmtime_max_time_t,[
    AC_RUN_IFELSE([AC_LANG_SOURCE([[
      #include <stdio.h>
      #include <time.h>
      int main() {
        FILE *f;
        int bits;
    
        for (bits = 1; bits < sizeof(time_t)*8; bits++) {
  	time_t t = ((time_t)1 << bits) - 1;
  	if (gmtime(&t) == NULL) {
  	  bits--;
  	  break;
  	}
        }
        if (bits > 40) {
  	/* Solaris 9 breaks after 55 bits. Perhaps other systems break earlier.
  	   Let's just do the same as Cyrus folks and limit it to 40 bits. */
  	bits = 40;
        }
    
        f = fopen("conftest.temp", "w");
        if (f == NULL) {
  	perror("fopen()");
  	return 1;
        }
        fprintf(f, "%d", bits);
        fclose(f);
        return 0;
      }
    ]])],[
      i_cv_gmtime_max_time_t=`cat conftest.temp`
      rm -f conftest.temp
    ], [
      printf "check failed, assuming "
      i_cv_gmtime_max_time_t=31
    ],[])
  ])
  AC_DEFINE_UNQUOTED(TIME_T_MAX_BITS, $i_cv_gmtime_max_time_t, [max. time_t bits gmtime() can handle])
])
