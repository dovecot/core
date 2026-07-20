#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "fdpass.h"

static int nopen(void) {
  int i, n;
  struct stat sb;
  for (i = n = 0; i < 256; i++) {
      if (fstat(i, &sb) == 0) n++;
  }
  return n;
}

int main(void) {
  int fd[2], send_fd, recv_fd, status, n1, n2;
  struct stat st, st2;
  char data;

  send_fd = creat("conftest.fdpass", 0600);
  if (send_fd == -1) {
	  return 2;
  }

  unlink("conftest.fdpass");

  if (fstat(send_fd, &st) < 0) {
	  return 2;
  }

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
	  return 2;
  }

  n1 = nopen();

  switch (fork()) {
  case -1:
          return 2;
  case 0:
          alarm(1);
          if (fd_send(fd[0], send_fd, &data, 1) != 1) return 2;
          return 0;
  default:
          alarm(2);
          if (wait(&status) == -1)
            return 2;
          if (status != 0)
            return status;
          if (fd_read(fd[1], &data, 1, &recv_fd) != 1) return 1;
          if (fstat(recv_fd, &st2) < 0) return 2;
          /* nopen check is for making sure that only a single fd
             was received */
          n2 = nopen();
          return st.st_ino == st2.st_ino && n2 == n1 + 1 ? 0 : 1;
  }
}
