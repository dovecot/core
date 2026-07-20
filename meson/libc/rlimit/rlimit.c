#include <sys/types.h>
@0@

int main(void) {
  struct rlimit r;
  getrlimit(@1@, &r);
  return 0;
}
