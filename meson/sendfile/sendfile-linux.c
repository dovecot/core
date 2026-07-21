#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>

int main(void) {
  sendfile(0, 0, (void *) 0, 0);
  return 0;
}
