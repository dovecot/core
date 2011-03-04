/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "base64.h"
#include "buffer.h"
#include "str.h"
#include "message-header-encode.h"
#include "test-common.h"

static bool verify_q(const char *str, unsigned int i, bool starts_with_a)
{
	unsigned int line_start = i, char_count = 0;

	if (strncmp(str+i, "\n\t", 2) == 0) {
		i += 2;
		line_start = i - 1;
	}

	for (;;) {
		if (strncmp(str+i, "=?utf-8?q?", 10) != 0)
			return FALSE;
		i += 10;

		if (starts_with_a) {
			if (str[i] != 'a')
				return FALSE;
			starts_with_a = FALSE;
			i++;
		}
		while (strncmp(str+i, "?=", 2) != 0) {
			if (strncmp(str+i, "=C3=A4", 6) != 0)
				return FALSE;
			i += 6;
			char_count++;
		}
		i += 2;
		if (i - line_start > 76)
			return FALSE;

		if (str[i] == '\0')
			break;
		if (strncmp(str+i, "\n\t", 2) != 0)
			return FALSE;
		i += 2;
		line_start = i - 1;
	}
	return char_count == 40;
}

static void test_message_header_encode_q(void)
{
	string_t *input = t_str_new(100);
	string_t *str = t_str_new(512);
	unsigned int i, j, skip;

	test_begin("message header encode q");

	str_append_c(input, 'a');
	for (i = 0; i < 40; i++)
		str_append(input, "ä");
	for (i = 0; i < 80; i++) {
		for (skip = 0; skip < 2; skip++) {
			str_truncate(str, 0);
			for (j = 1; j < i; j++)
				str_append_c(str, 'X');
			if (i != 0)
				str_append_c(str, ' ');

			message_header_encode_q(str_data(input) + skip,
						str_len(input) - skip, str);
			test_assert(verify_q(str_c(str), i, !skip));
		}
	}
	test_end();
}

static bool verify_b(const char *str, unsigned int i, bool starts_with_a)
{
	unsigned int line_start = i, start, j, char_count = 0;
	char bufdata[1000];
	buffer_t buf;

	buffer_create_data(&buf, bufdata, sizeof(bufdata));
	if (strncmp(str+i, "\n\t", 2) == 0) {
		i += 2;
		line_start = i - 1;
	}

	for (;;) {
		if (strncmp(str+i, "=?utf-8?b?", 10) != 0)
			return FALSE;
		i += 10;

		start = i;
		for (; str[i] != '?'; i++) {
			if (str[i] == '\0')
				return FALSE;
		}
		buffer_set_used_size(&buf, 0);
		if (base64_decode(str+start, i-start, NULL, &buf) < 0)
			return FALSE;
		i++;

		if (!starts_with_a)
			j = 0;
		else {
			if (bufdata[0] != 'a')
				return FALSE;
			starts_with_a = FALSE;
			j = 1;
		}
		for (; j < buf.used; j += 2) {
			if (bufdata[j] != '\xc3' || bufdata[j+1] != '\xa4')
				return FALSE;
			char_count++;
		}
		if (j != buf.used)
			return FALSE;

		if (str[i++] != '=')
			return FALSE;

		if (i - line_start > 76)
			return FALSE;

		if (str[i] == '\0')
			break;
		if (strncmp(str+i, "\n\t", 2) != 0)
			return FALSE;
		i += 2;
		line_start = i - 1;
	}
	return char_count == 40;
}

static void test_message_header_encode_b(void)
{
	string_t *input = t_str_new(100);
	string_t *str = t_str_new(512);
	unsigned int i, j, skip;

	test_begin("message header encode b");

	str_append_c(input, 'a');
	for (i = 0; i < 40; i++)
		str_append(input, "ä");
	for (i = 0; i < 80; i++) {
		for (skip = 0; skip < 2; skip++) {
			str_truncate(str, 0);
			for (j = 1; j < i; j++)
				str_append_c(str, 'X');
			if (i != 0)
				str_append_c(str, ' ');

			message_header_encode_b(str_data(input) + skip,
						str_len(input) - skip, str);
			test_assert(verify_b(str_c(str), i, !skip));
		}
	}
	test_end();
}

static void test_message_header_encode(void)
{
	const char *data[] = {
		"a b", "a b",
		"a bcäde f", "a =?utf-8?q?bc=C3=A4de?= f",
		"a ää ä b", "a =?utf-8?b?w6TDpCDDpA==?= b",
		"ä a ä", "=?utf-8?q?=C3=A4_a_=C3=A4?=",
		"ää a ä", "=?utf-8?b?w6TDpCBhIMOk?=",
	};                          
	string_t *str = t_str_new(128);
	unsigned int i;

	test_begin("message header encode");
	for (i = 0; i < N_ELEMENTS(data); i += 2) {
		str_truncate(str, 0);
		message_header_encode(data[i], str);
		test_assert(strcmp(str_c(str), data[i+1]) == 0);
	}
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_message_header_encode_q,
		test_message_header_encode_b,
		test_message_header_encode,
		NULL
	};
	return test_run(test_functions);
}
