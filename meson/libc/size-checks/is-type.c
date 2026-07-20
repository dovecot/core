#include <sys/types.h>

/* Fails to compile unless @0@ is exactly @1@. _Generic matches the unqualified type, so
   this tells 'long' apart from 'long long' even where the two have the same width. */
int main(void) {
  int check[_Generic((@0@)0, @1@: 1, default: -1)];
  (void)check;
  return 0;
}
