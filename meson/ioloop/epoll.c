#include <sys/epoll.h>

int main(void) {
  return epoll_create(5) < 1;
}
