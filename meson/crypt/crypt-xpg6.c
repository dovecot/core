#define _XOPEN_SOURCE 4
#define _XOPEN_SOURCE_EXTENDED 1
#define _XOPEN_VERSION 4
#define _DEFAULT_SOURCE
#define _XPG4_2
#define _XPG6
#include <unistd.h>

int main(void) {
  crypt("a", "b");
  return 0;
}
