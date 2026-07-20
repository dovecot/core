#define __USE_GNU
@0@

int main(void) {
  mremap(0, 0, 0, MREMAP_MAYMOVE);
  return 0;
}
