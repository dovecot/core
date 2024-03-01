#ifndef PUNYCODE_H
#define PUNYCODE_H

/* Parse input as a punycode-encoded string and return the
   corresponding UTF8 string if the input is valid. If the input isn't
   punycode-encoded or contains an encoding error, return the input. */
string_t *punycode_decode(string_t *input);

#endif
