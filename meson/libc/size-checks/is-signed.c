#include <sys/types.h>

#define ISUNSIGNED(type) ((type)0 - 1 > 0)

/* ISUNSIGNED() is a constant expression, so the array size settles this at compile
   time. Fails to compile unless @0@ is signed. */
int main(void) {
  int check[ISUNSIGNED(@0@) ? -1 : 1];
  (void)check;
  return 0;
}
