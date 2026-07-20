#include <time.h>
#define ISUNSIGNED(type) ((type)0 - 1 > 0)

int main(void) {
  if (ISUNSIGNED(time_t) == ISUNSIGNED(@0@) &&
      sizeof(time_t) == sizeof(@0@))
        return 0;
  return 1;
}
