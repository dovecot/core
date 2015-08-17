#ifndef FTS_COMMON_H
#define FTS_COMMON_H

/* Some might consider 0x02BB an apostrophe also. */
#define IS_NONASCII_APOSTROPHE(c) \
	((c) == 0x2019 || (c) == 0xFF07)
#define IS_APOSTROPHE(c) \
	((c) == 0x0027 || IS_NONASCII_APOSTROPHE(c))

#endif
