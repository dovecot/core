/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "buffer.h"
#include "str.h"
#include "hex-binary.h"

static void test_binary_to_hex(void)
{
	static unsigned char input[] = { 0xff, 0x00, 0x01, 0xb3 };
	static char *output_lcase = "ff0001b3";
	static char *output_ucase = "FF0001B3";
	string_t *str;

	test_begin("binary to hex");
	test_assert(strcmp(binary_to_hex(input, sizeof(input)), output_lcase) == 0);
	test_end();

	test_begin("binary to hex ucase");
	test_assert(strcmp(binary_to_hex_ucase(input, sizeof(input)), output_ucase) == 0);
	test_end();

	test_begin("binary to hex ucase");
	str = t_str_new(32);
	str_append_c(str, '<');
	binary_to_hex_append(str, input, sizeof(input));
	str_append_c(str, '>');
	test_assert(strcmp(str_c(str), t_strconcat("<", output_lcase, ">", NULL)) == 0);
	test_end();
}

static void test_hex_to_binary(void)
{
	static const char *ok_input = "0001fEFf";
	static unsigned char ok_output[] = { 0x00, 0x01, 0xfe, 0xff };
	static const char *error_input[] = {
		"00 01",
		"0x01",
		"0g"
	};
	buffer_t *buf = buffer_create_dynamic(pool_datastack_create(), 10);
	unsigned int i;

	test_begin("hex to binary");
	test_assert(hex_to_binary("", buf) == 0);
	test_assert(buf->used == 0);

	test_assert(hex_to_binary(ok_input, buf) == 0);
	test_assert(buf->used == N_ELEMENTS(ok_output));
	test_assert(memcmp(buf->data, ok_output, buf->used) == 0);

	for (i = 0; i < N_ELEMENTS(error_input); i++)
		test_assert(hex_to_binary(error_input[i], buf) == -1);
	test_end();
}

void test_hex_binary(void)
{
	test_binary_to_hex();
	test_hex_to_binary();
}
