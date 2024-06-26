#ifndef PUNYCODE_H
#define PUNYCODE_H

/* Parse input as a punycode-encoded string and append it to
   output. Returns 0 on success and -1 on failure. */
int punycode_decode(const char *input, size_t len, string_t *output);

#endif
