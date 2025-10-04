/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "crc32.h"
#include <zlib.h>

uint32_t crc32_data(const void *data, size_t size)
{
	return crc32_data_more(CRC32_INIT, data, size);
}

uint32_t crc32_data_more(uint32_t crc, const void *data, size_t size)
{
	const unsigned char *p = data;
	uLong zcrc;

	if (crc == CRC32_INIT) {
		/* Start new CRC calculation. */
		zcrc = crc32_z(0L, Z_NULL, 0);
	} else {
		zcrc = crc;
	}

	return (uint32_t)crc32_z(zcrc, p, size);
}
