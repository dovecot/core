/* Copyright (c) 2003-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-index-private.h"

#if WORDS_BIGENDIAN
/* FIXME: Unfortunately these functions were originally written to use
   endian-specific code and we can't avoid that without breaking backwards
   compatibility. When we do break it, just select one of these. */
uint32_t mail_index_uint32_to_offset(uint32_t offset)
{
	i_assert(offset < 0x40000000);
	i_assert((offset & 3) == 0);

	offset >>= 2;
	return  0x00000080 | ((offset & 0x0000007f)) |
		0x00008000 | ((offset & 0x00003f80) >> 7 << 8) |
		0x00800000 | ((offset & 0x001fc000) >> 14 << 16) |
		0x80000000 | ((offset & 0x0fe00000) >> 21 << 24);
}

uint32_t mail_index_offset_to_uint32(uint32_t offset)
{
	if ((offset & 0x80808080) != 0x80808080)
		return 0;

	return  (((offset & 0x0000007f)) |
		 ((offset & 0x00007f00) >> 8 << 7) |
		 ((offset & 0x007f0000) >> 16 << 14) |
		 ((offset & 0x7f000000) >> 24 << 21)) << 2;
}
#else
uint32_t mail_index_uint32_to_offset(uint32_t offset)
{
	i_assert(offset < 0x40000000);
	i_assert((offset & 3) == 0);

	offset >>= 2;
	return  0x80000000 | ((offset & 0x0000007f) << 24) |
		0x00800000 | ((offset & 0x00003f80) >> 7 << 16) |
		0x00008000 | ((offset & 0x001fc000) >> 14 << 8) |
		0x00000080 | ((offset & 0x0fe00000) >> 21);
}

uint32_t mail_index_offset_to_uint32(uint32_t offset)
{
	if ((offset & 0x80808080) != 0x80808080)
		return 0;

	return  (((offset & 0x0000007f) << 21) |
		 ((offset & 0x00007f00) >> 8 << 14) |
		 ((offset & 0x007f0000) >> 16 << 7) |
		 ((offset & 0x7f000000) >> 24)) << 2;
}
#endif

void mail_index_pack_num(uint8_t **p, uint32_t num)
{
	/* number continues as long as the highest bit is set */
	while (num >= 0x80) {
		**p = (num & 0x7f) | 0x80;
		*p += 1;
		num >>= 7;
	}

	**p = num;
	*p += 1;
}

int mail_index_unpack_num(const uint8_t **p, const uint8_t *end,
			  uint32_t *num_r)
{
	const uint8_t *c = *p;
	uint32_t value = 0;
	unsigned int bits = 0;

	for (;;) {
		if (unlikely(c == end)) {
			/* we should never see EOF */
			*num_r = 0;
			return -1;
		}

		value |= (*c & 0x7f) << bits;
		if (*c < 0x80)
			break;

		bits += 7;
		c++;
	}

	if (unlikely(bits >= 32)) {
		/* broken input */
		*p = end;
		*num_r = 0;
		return -1;
	}

	*p = c + 1;
	*num_r = value;
	return 0;
}
