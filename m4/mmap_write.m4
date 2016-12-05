dnl * If mmap() plays nicely with write()
AC_DEFUN([DOVECOT_MMAP_WRITE], [
  AC_CACHE_CHECK([whether shared mmaps get updated by write()s],i_cv_mmap_plays_with_write,[
    AC_TRY_RUN([
      #include <stdio.h>
      #include <sys/types.h>
      #include <sys/stat.h>
      #include <unistd.h>
      #include <fcntl.h>
      #include <sys/mman.h>
      #include <string.h>
      int main() {
        /* return 0 if we're signed */
        int f = open("conftest.mmap", O_RDWR|O_CREAT|O_TRUNC, 0600);
        void *mem;
        if (f == -1) {
          perror("open()");
          return 1;
        }
        unlink("conftest.mmap");
    
        write(f, "1", 2);
        mem = mmap(NULL, 2, PROT_READ|PROT_WRITE, MAP_SHARED, f, 0);
        if (mem == MAP_FAILED) {
          perror("mmap()");
          return 1;
        }
        strcpy(mem, "2");
        msync(mem, 2, MS_SYNC);
        lseek(f, 0, SEEK_SET);
        write(f, "3", 2);
      
        return strcmp(mem, "3") == 0 ? 0 : 1;
      }
    ], [
      i_cv_mmap_plays_with_write=yes
    ], [
      i_cv_mmap_plays_with_write=no
    ])
  ])
  if test $i_cv_mmap_plays_with_write = no; then
    AC_DEFINE(MMAP_CONFLICTS_WRITE,, [Define if shared mmaps don't get updated by write()s])
  fi
])
