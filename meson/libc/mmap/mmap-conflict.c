#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
@0@

int main(void) {
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
