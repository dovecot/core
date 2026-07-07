#ifndef IDNA_PUNYCODE_H
#define IDNA_PUNYCODE_H

/* Parse input as a punycode-encoded string and append it to
   output. Returns 0 on success and -1 on failure. */
int idna_punycode_decode(const unsigned char *in, size_t in_len,
			 string_t *output);

#endif
