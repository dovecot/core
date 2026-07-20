#include <sys/prctl.h>

int main(void) {
  prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
  return 0;
}
