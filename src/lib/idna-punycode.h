#ifndef IDNA_PUNYCODE_H
#define IDNA_PUNYCODE_H

/* Encode the provided 32-bit Unicode input and write encoded result to the
   provided 32-bit buffer. Returns number of code points in output on success
   and -1 on failure. */
ssize_t idna_punycode_encode(const uint32_t *in, size_t in_len,
			     uint32_t *out, size_t out_max);

/* Parse input as a punycode-encoded string and append it to
   output. Returns 0 on success and -1 on failure. */
int idna_punycode_decode_utf8(const unsigned char *in, size_t in_len,
			      string_t *output);
/* Parse input as a punycode-encoded 32-bit string and write the decoded result
   to the provided 32bit buffer. Returns number code points in result on success
   and -1 on failure. */
ssize_t idna_punycode_decode(const uint32_t *in, size_t in_len,
			     uint32_t *out, size_t out_max);

#endif
