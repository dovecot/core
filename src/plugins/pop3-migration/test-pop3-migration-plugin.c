/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "sha1.h"
#include "hex-binary.h"
#include "istream.h"
#include "test-common.h"
#include "pop3-migration-plugin.h"

static void test_pop3_migration_get_hdr_sha1(void)
{
	struct {
		const char *input;
		const char *sha1;
		bool have_eoh;
	} tests[] = {
		{ "", "da39a3ee5e6b4b0d3255bfef95601890afd80709", FALSE },
		{ "\n", "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc", TRUE },
		{ "a: \r\n", "a3871371f2d468493005286282ae10549dab2c57", FALSE },
		{ "a: b\r\n", "44ef6a20971148dd54a161f79814e22e2d098ddb", FALSE },
		{ "a: b \r\n", "44ef6a20971148dd54a161f79814e22e2d098ddb", FALSE },
		{ "a: b  \r\n", "44ef6a20971148dd54a161f79814e22e2d098ddb", FALSE },
		{ "a: b     \r\n", "44ef6a20971148dd54a161f79814e22e2d098ddb", FALSE },
		{ "a: b\r\n\r\n", "938b96404495cced816e3a4f6031734eab4e71b3", TRUE },
		{ "a: b\r\n\r\r\n", "44ef6a20971148dd54a161f79814e22e2d098ddb", FALSE },
		{ "a: b\r\n\r\r\nc: d\r\n\r\n", "44ef6a20971148dd54a161f79814e22e2d098ddb", TRUE },
		{ "a: b\r\n \r\n", "44ef6a20971148dd54a161f79814e22e2d098ddb", FALSE },
		{ "a: b\r\n  \r\n", "44ef6a20971148dd54a161f79814e22e2d098ddb", FALSE },
		{ "a: b\r\n\t\r\n", "44ef6a20971148dd54a161f79814e22e2d098ddb", FALSE },
		{ "a: b\t\t\t\t\r\n", "44ef6a20971148dd54a161f79814e22e2d098ddb", FALSE },
	};
	struct istream *input;
	unsigned char digest[SHA1_RESULTLEN];
	unsigned int i;
	bool have_eoh;

	test_begin("pop3 migration get hdr sha1");

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		input = i_stream_create_from_data(tests[i].input,
						  strlen(tests[i].input));
		test_assert_idx(pop3_migration_get_hdr_sha1(1, input, digest, &have_eoh) == 0, i);
		test_assert_idx(strcasecmp(binary_to_hex(digest, sizeof(digest)), tests[i].sha1) == 0, i);
		test_assert_idx(tests[i].have_eoh == have_eoh, i);
		i_stream_unref(&input);
	}

	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_pop3_migration_get_hdr_sha1,
		NULL
	};
	return test_run(test_functions);
}
