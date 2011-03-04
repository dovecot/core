/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "hash-format.h"

struct hash_format_test {
	const char *input;
	const char *output;
};

void test_hash_format(void)
{
	static const char *fail_input[] = {
		"%",
		"%A{sha1}",
		"%{sha1",
		"%{sha1:8",
		"%{sha1:8a}",
		"%{sha1:0}",
		"%{sha1:168}",
		NULL
	};
	static struct hash_format_test tests[] = {
		{ "%{sha1}", "8843d7f92416211de9ebb963ff4ce28125932878" },
		{ "*%{sha1}*", "*8843d7f92416211de9ebb963ff4ce28125932878*" },
		{ "*%{sha1:8}*", "*88*" },
		{ "%{sha1:152}", "8843d7f92416211de9ebb963ff4ce281259328" },
		{ "%X{size}", "6" },
		{ "%{sha256:80}", "c3ab8ff13720e8ad9047" },
		{ "%{sha512:80}", "0a50261ebd1a390fed2b" },
		{ "%{md4}", "547aefd231dcbaac398625718336f143" },
		{ "%{md5}", "3858f62230ac3c915f300c664312c63f" },
		{ "%{sha256:80}-%X{size}", "c3ab8ff13720e8ad9047-6" }
	};
	struct hash_format *format;
	string_t *str = t_str_new(128);
	const char *error;
	unsigned int i;

	test_begin("hash_format");
	for (i = 0; fail_input[i] != NULL; i++)
		test_assert(hash_format_init(fail_input[i], &format, &error) < 0);

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert(hash_format_init(tests[i].input, &format, &error) == 0);
		hash_format_loop(format, "foo", 3);
		hash_format_loop(format, "bar", 3);
		str_truncate(str, 0);
		hash_format_deinit(&format, str);
		test_assert(strcmp(str_c(str), tests[i].output) == 0);
	}
	test_end();
}
