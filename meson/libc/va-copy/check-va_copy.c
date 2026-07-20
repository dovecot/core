#include <stdarg.h>
#include <stdlib.h>

void f(int i, ...);

void f (int i, ...) {
  va_list args1, args2;
  va_start (args1, i);
  @0@ (args2, args1);
  if (va_arg (args2, int) != 42 || va_arg (args1, int) != 42)
    exit (1);
  va_end (args1); va_end (args2);
}

int main(void) {
  f (0, 42);
  return 0;
}
