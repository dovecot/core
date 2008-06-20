#ifndef HEX_DEC_H
#define HEX_DEC_H

#define DEC2HEX(hexstr, str) \
	dec2hex(hexstr, str, sizeof(hexstr))

/* Decimal -> hex string translation. The result isn't NUL-terminated. */
void dec2hex(unsigned char *hexstr, uintmax_t dec, unsigned int hexstr_size);
/* Parses hex string and returns its decimal value, or 0 in case of errors */
uintmax_t hex2dec(const unsigned char *data, unsigned int len) ATTR_PURE;

#endif
