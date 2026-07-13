#ifndef HEX_DEC_H
#define HEX_DEC_H

enum hex_allowed_case {
	/* Allow lowercase 'a'..'f' */
	HEX_ALLOWED_CASE_LOWER	= BIT(0),
	/* Allow uppercase 'A'..'F' */
	HEX_ALLOWED_CASE_UPPER	= BIT(1),
};

#define HEX_ALLOWED_CASE_BOTH (HEX_ALLOWED_CASE_LOWER|HEX_ALLOWED_CASE_UPPER)

#define DEC2HEX(hexstr, str) \
	dec2hex(hexstr, str, sizeof(hexstr))

/* Decimal -> hex string translation. The result isn't NUL-terminated. */
void dec2hex(unsigned char *hexstr, uintmax_t dec, unsigned int hexstr_size);

/* Parses hex string, returns 0 if succeeded and -1 if failed */
int hex2dec_case(const unsigned char *data, unsigned int len,
		 enum hex_allowed_case allowed_case, uintmax_t *value_r);

/* Parses hex string and returns its decimal value, or 0 in case of errors */
static inline uintmax_t hex2dec(const unsigned char *data, unsigned int len)
{
	uintmax_t value;
	return hex2dec_case(data, len, HEX_ALLOWED_CASE_BOTH, &value) < 0 ?
	       0 : value;
}

#endif
