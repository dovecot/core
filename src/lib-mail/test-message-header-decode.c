/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "charset-utf8.h"
#include "message-header-decode.h"
#include "test-common.h"

bool charset_is_utf8(const char *charset ATTR_UNUSED) { return TRUE; }

int charset_to_utf8_begin(const char *charset ATTR_UNUSED,
			  enum charset_flags flags ATTR_UNUSED,
			  struct charset_translation **t_r ATTR_UNUSED) { return 0; }
void charset_to_utf8_end(struct charset_translation **t ATTR_UNUSED) {}

enum charset_result
charset_to_utf8(struct charset_translation *t ATTR_UNUSED,
		const unsigned char *src, size_t *src_size, buffer_t *dest)
{
	buffer_append(dest, src, *src_size);
	return CHARSET_RET_OK;
}

static void test_message_header_decode(void)
{
	static const char *data[] = {
		"a =?utf-8?q?=c3=a4?= b", "a ä b",
		"a =?utf-8?q?=c3=a4?= b", "a ä b",
		"a =?utf-8?q?=c3=a4?=\t\t\r\n =?utf-8?q?=c3=a4?= b", "a ää b",
		"a =?utf-8?q?=c3=a4?=  x  =?utf-8?q?=c3=a4?= b", "a ä  x  ä b",
		"a =?utf-8?b?w6TDpCDDpA==?= b", "a ää ä b",
		"=?utf-8?b?w6Qgw6Q=?=", "ä ä",
	};
	string_t *dest;
	unsigned int i;

	test_begin("message header decode");

	dest = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(data); i += 2) {
		str_truncate(dest, 0);
		test_assert(message_header_decode_utf8((const unsigned char *)data[i],
						       strlen(data[i]),
						       dest, FALSE));
		test_assert(strcmp(str_c(dest), data[i+1]) == 0);
	}
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_message_header_decode,
		NULL
	};
	return test_run(test_functions);
}
