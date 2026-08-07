/* gcc has supported the string form of no_sanitize only since gcc 8; older versions warn
   that the attribute is ignored, which -Werror turns into a failure. */
__attribute__((no_sanitize("undefined"))) static int f(void) { return 0; }

int main(void) { return f(); }
