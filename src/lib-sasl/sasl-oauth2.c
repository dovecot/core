/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"

#include "sasl-oauth2.h"

static const unsigned char key_mask = BIT(0);
static const unsigned char value_mask = BIT(1);

static const unsigned char char_lookup[256] = {
	0,  0,  0,  0,  0,  0,  0,  0,  0,  2,  2,  0,  0,  2,  0,  0, // 00
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 20
	2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, // 20
	2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, // 30
	2,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3, // 40
	3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  2,  2,  2,  2,  2, // 50
	2,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3, // 60
	3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  2,  2,  2,  2,  0, // 70

	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 80
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 90
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // a0
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // b0
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // c0
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // d0
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // e0
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // f0
};


int sasl_oauth2_kvpair_parse(const unsigned char *data, size_t size,
			     const char **key_r, const char **value_r,
			     const unsigned char **end_r,
			     const char **error_r)
{
	const unsigned char *p = data, *pend = data + size, *poffset;

	i_assert(p < pend);

	/* RFC 7628, Section 3.1:

	   kvsep          = %x01
	   key            = 1*(ALPHA)
	   value          = *(VCHAR / SP / HTAB / CR / LF )
	   kvpair         = key "=" value kvsep
	 */

	/* key            = 1*(ALPHA) */
	poffset = p;
	while (p < pend && (char_lookup[*p] & key_mask) != 0x00)
		p++;

	/* "=" */
	if (p == pend) {
		*error_r = "Missing value";
		return -1;
	}
	if (*p != '=') {
		*error_r = "Invalid character in key";
		return -1;
	}
	if (p == poffset) {
		*error_r = "Empty key name";
		return -1;
	}
	*key_r = t_strdup_until(poffset, p);
	p++;

	/* value          = *(VCHAR / SP / HTAB / CR / LF ) */
	poffset = p;
	while (p < pend && (char_lookup[*p] & value_mask) != 0x00)
		p++;

	if (p == pend) {
		*error_r = "Missing separator (0x01)";
		return -1;
	}
	if (*p != 0x01) {
		*error_r = "Invalid character in value";
		return -1;
	}
	*value_r = t_strdup_until(poffset, p);
	p++;

	*end_r = p;
	return 0;
}
