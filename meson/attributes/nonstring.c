/* Compilers that don't have the attribute warn instead of failing, so this needs
   -Werror. */
const unsigned char foo[4] __attribute__((nonstring)) = "1234";

int main(void) { return foo[0] == '1' ? 0 : 1; }
