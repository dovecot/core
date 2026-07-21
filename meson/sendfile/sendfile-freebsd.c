#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

int main(void) {
  struct sf_hdtr hdtr;
  sendfile(0, 0, 0, 0, &hdtr, (void *) 0, 0);
  return 0;
}
