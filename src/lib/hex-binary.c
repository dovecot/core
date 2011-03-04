/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hex-binary.h"

static void
binary_to_hex_case(unsigned char *dest, const unsigned char *data,
		   size_t size, bool ucase)
{
	unsigned char *p;
	char base_char;
	size_t i;
	int value;

	/* @UNSAFE */
	base_char = ucase ? 'A' : 'a';

	p = dest;
	for (i = 0; i < size; i++) {
		value = data[i] >> 4;
		*p++ = value < 10 ? value + '0' : value - 10 + base_char;

		value = data[i] & 0x0f;
		*p++ = value < 10 ? value + '0' : value - 10 + base_char;
	}
}

const char *binary_to_hex(const unsigned char *data, size_t size)
{
	unsigned char *dest = t_malloc(size * 2 + 1);

	binary_to_hex_case(dest, data, size, FALSE);
	dest[size*2] = '\0';
	return (char *)dest;
}

const char *binary_to_hex_ucase(const unsigned char *data, size_t size)
{
	unsigned char *dest = t_malloc(size * 2 + 1);

	binary_to_hex_case(dest, data, size, TRUE);
	dest[size*2] = '\0';
	return (char *)dest;
}

void binary_to_hex_append(string_t *dest, const unsigned char *data,
			  size_t size)
{
	unsigned char *buf;

	buf = buffer_append_space_unsafe(dest, size * 2);
	binary_to_hex_case(buf, data, size, FALSE);
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

		buffer_append_c(dest, value);
		data++;
	}

	return 0;
}
