#define _XOPEN_SOURCE 600

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(void) {
#if defined(__GLIBC__) && (__GLIBC__ < 2 || __GLIBC_MINOR__ < 7)
  /* glibc < 2.7 has a broken posix_fallocate(); treat as unavailable. */
  return 1;
#endif

  int fd = creat("conftest.temp", 0600);
  int ret;

  if (fd == -1) {
    perror("creat()");
    return 2;
  }

  /* posix_fallocate() returns 0 on success or a positive errno on failure. */
  ret = posix_fallocate(fd, 1024, 1024) != 0 ? 1 : 0;
  unlink("conftest.temp");

  return ret;
}
