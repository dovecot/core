/* Copyright (c) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "hex-binary.h"

const char *binary_to_hex(const unsigned char *data, size_t size)
{
	char *buf, *p;
	size_t i;
	int value;

	/* @UNSAFE */

	buf = p = t_malloc(size * 2 + 1);
	for (i = 0; i < size; i++) {
		value = data[i] >> 4;
		*p++ = value < 10 ? value + '0' : value - 10 + 'a';

		value = data[i] & 0x0f;
		*p++ = value < 10 ? value + '0' : value - 10 + 'a';
	}

	*p = '\0';
	return buf;
}

int hex_to_binary(const char *data, buffer_t *dest)
{
	int value;

	while (*data != '\0') {
		if (*data >= '0' && *data <= '9')
			value = (*data - '0') << 4;
		else if (*data >= 'a' && *data <= 'f')
			value = (*data - 'a' + 10) << 4;
		else if (*data >= 'A' && *data <= 'F')
			value = (*data - 'A' + 10) << 4;
		else
			return -1;

		data++;
		if (*data >= '0' && *data <= '9')
			value |= *data - '0';
		else if (*data >= 'a' && *data <= 'f')
			value |= *data - 'a' + 10;
		else if (*data >= 'A' && *data <= 'F')
			value |= *data - 'A' + 10;
		else
			return -1;

		if (buffer_append_c(dest, value) != 1)
			return 0;
		data++;
	}

	return 1;
}
