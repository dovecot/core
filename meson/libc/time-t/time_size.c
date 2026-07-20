#include <stdio.h>
#include <time.h>

int main(void) {
  int bits;

  for (bits = 1; bits < sizeof(time_t)*8; bits++) {
    time_t t = ((time_t)1 << bits) - 1;
    if (gmtime(&t) == NULL) {
      bits--;
      break;
    }
  }

  if (bits > 40) {
    /* Solaris 9 breaks after 55 bits. Perhaps other systems break earlier.  Let's just do
       the same as Cyrus folks and limit it to 40 bits. */
     bits = 40;
  }

#ifdef TIME_T_SIGNED
  if (bits == 32) {
    /* Signed 32-bit time_t is the same as unsigned 31-bit time_t */
    bits = 31;
  }
#endif

  printf("%d", bits);
  return 0;
}
