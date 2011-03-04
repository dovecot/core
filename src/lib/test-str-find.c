/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str-find.h"

static const char *str_find_text = "xababcd";

static bool test_str_find_substring(const char *key, int expected_pos)
{
	const unsigned char *text = (const unsigned char *)str_find_text;
	const unsigned int text_len = strlen(str_find_text);
	struct str_find_context *ctx;
	unsigned int i, j, pos, max, offset;
	bool ret;

	ctx = str_find_init(pool_datastack_create(), key);
	/* divide text into every possible block combination and test that
	   it matches */
	max = 1 << (text_len-1);
	for (i = 0; i < max; i++) {
		str_find_reset(ctx);
		pos = 0; offset = 0; ret = FALSE;
		for (j = 0; j < text_len; j++) {
			if ((i & (1 << j)) != 0) {
				if (str_find_more(ctx, text+pos, j-pos+1)) {
					ret = TRUE;
					break;
				}
				offset += j-pos + 1;
				pos = j + 1;
			}
		}
		if (pos != text_len && !ret) {
			if (str_find_more(ctx, text+pos, j-pos))
				ret = TRUE;
		}
		if (expected_pos < 0) {
			if (ret)
				return FALSE;
		} else {
			if (!ret)
				return FALSE;

			pos = str_find_get_match_end_pos(ctx) +
				offset - strlen(key);
			if ((int)pos != expected_pos)
				return FALSE;
		}
	}
	return TRUE;
}

struct str_find_input {
	const char *str;
	int pos;
};

void test_str_find(void)
{
	static const char *fail_input[] = {
		"xabc",
		"xabd",
		"abd"
	};
	unsigned int idx, len;
	const char *key, *p;
	unsigned int i;
	bool success = TRUE;

	for (idx = 0; idx < strlen(str_find_text); idx++) {
		for (len = strlen(str_find_text)-idx; len > 0; len--) {
			/* we'll get a search key for all substrings of text */
			T_BEGIN {
				key = t_strndup(str_find_text + idx, len);
				p = strstr(str_find_text, key);
				success = test_str_find_substring(key, p - str_find_text);
			} T_END;
			if (!success)
				break;
		}
	}
	for (i = 0; i < N_ELEMENTS(fail_input) && success; i++)
		success = test_str_find_substring(fail_input[i], -1);
	test_out("str_find()", success);
}
