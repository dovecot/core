/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "str-sanitize.h"
#include "test-common.h"
#include "smtp-address.h"

/* 
 * Valid mailbox parse tests
 */

struct valid_mailbox_parse_test {
	const char *input, *output;
	enum smtp_address_parse_flags flags;

	struct smtp_address address;
};

static const struct valid_mailbox_parse_test
valid_mailbox_parse_tests[] = {
	{
		.input = "",
		.flags = SMTP_ADDRESS_PARSE_FLAG_ALLOW_EMPTY,
		.address = { .localpart = NULL, .domain = NULL },
	},
	{
		.input = "user",
		.flags = SMTP_ADDRESS_PARSE_FLAG_ALLOW_LOCALPART,
		.address = { .localpart = "user", .domain = NULL },
	},
	{
		.input = "user@domain.tld",
		.address = { .localpart = "user", .domain = "domain.tld" },
	},
	{
		.input = "1234567890@domain.tld",
		.address = {
			.localpart = "1234567890",
			.domain = "domain.tld" },
	},
	{
		.input = "_______@domain.tld",
		.address = {
			.localpart = "_______",
			.domain = "domain.tld" },
	},
	{
		.input = "firstname.lastname@domain.tld",
		.address = {
			.localpart = "firstname.lastname",
			.domain = "domain.tld" },
	},
	{
		.input = "firstname+lastname@domain.tld",
		.address = {
			.localpart = "firstname+lastname",
			.domain = "domain.tld" },
	},
	{
		.input = "firstname-lastname@domain.tld",
		.address = {
			.localpart = "firstname-lastname",
			.domain = "domain.tld" },
	},
	{
		.input = "\"user\"@domain.tld",
		.address = { .localpart = "user", .domain = "domain.tld" },
		.output = "user@domain.tld"
	},
	{
		.input = "\"user@frop\"@domain.tld",
		.address = { .localpart = "user@frop", .domain = "domain.tld" },
		.output = "\"user@frop\"@domain.tld"
	},
	{
		.input = "user@127.0.0.1",
		.address = { .localpart = "user", .domain = "127.0.0.1" },
	},
	{
		.input = "user@[127.0.0.1]",
		.address = { .localpart = "user", .domain = "[127.0.0.1]" },
	},
	{
		.input = "user@[IPv6:::1]",
		.address = { .localpart = "user", .domain = "[IPv6:::1]" },
	},
	{
		.input = "user@[IPv6:::127.0.0.1]",
		.address = { .localpart = "user", .domain = "[IPv6:::127.0.0.1]" },
	/* Japanese deviations */
	},
	{
		.input = "email@-example.com",
		.address = { .localpart = "email", .domain = "-example.com" },
	},
	{
		.input = ".email@example.com",
		.output = "\".email\"@example.com",
		.address = { .localpart = ".email", .domain = "example.com" },
	},
	{
		.input = "email.@example.com",
		.output = "\"email.\"@example.com",
		.address = { .localpart = "email.", .domain = "example.com" },
	},
	{
		.input = "email..email@example.com",
		.output = "\"email..email\"@example.com",
		.address = { .localpart = "email..email", .domain = "example.com" },
	},
	{
		.input = "Abc..123@example.com",
		.output = "\"Abc..123\"@example.com",
		.address = { .localpart = "Abc..123", .domain = "example.com" },
	},
	{
		.input = "Abc..@example.com",
		.output = "\"Abc..\"@example.com",
		.address = { .localpart = "Abc..", .domain = "example.com" },
	},
};

unsigned int valid_mailbox_parse_test_count =
	N_ELEMENTS(valid_mailbox_parse_tests);

static void
test_smtp_mailbox_equal(const struct smtp_address *test,
			const struct smtp_address *parsed)
{
	if (parsed->localpart == NULL) {
		test_out("address->localpart = (null)",
			 (parsed->localpart == test->localpart));
	} else {
		test_out(t_strdup_printf("address->localpart = \"%s\"",
					 parsed->localpart),
			 null_strcmp(parsed->localpart, test->localpart) == 0);
	}
	if (parsed->domain == NULL) {
		test_out(t_strdup_printf("address->domain = (null)"),
			 (parsed->domain == test->domain));
	} else {
		test_out(t_strdup_printf("address->domain = \"%s\"",
					 parsed->domain),
			 null_strcmp(parsed->domain, test->domain) == 0);
	}
}

static void test_smtp_mailbox_parse_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_mailbox_parse_test_count; i++) T_BEGIN {
		const struct valid_mailbox_parse_test *test;
		struct smtp_address *address;
		const char *error = NULL, *output, *encoded;
		int ret;

		test = &valid_mailbox_parse_tests[i];
		ret = smtp_address_parse_mailbox(pool_datastack_create(),
						 test->input, test->flags,
						 &address, &error);

		test_begin(t_strdup_printf("smtp mailbox valid [%d]", i));
		test_out_reason(t_strdup_printf("parse(\"%s\")", test->input),
				ret == 0, error);

		if (!test_has_failed()) {
			test_smtp_mailbox_equal(&test->address, address);

			encoded = smtp_address_encode(address);
			output = (test->output == NULL ?
				  test->input : test->output);
			test_out(t_strdup_printf("encode() = \"%s\"", encoded),
				 strcmp(encoded, output) == 0);
		}
		test_end();
	} T_END;
}

/*
 * Valid path parse tests
 */

struct valid_path_parse_test {
	const char *input, *output;
	enum smtp_address_parse_flags flags;

	struct smtp_address address;
};

static const struct valid_path_parse_test
valid_path_parse_tests[] = {
	{
		.input = "<>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_ALLOW_EMPTY,
		.address = { .localpart = NULL, .domain = NULL }
	},
	{
		.input = "<user>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_ALLOW_LOCALPART,
		.address = { .localpart = "user", .domain = NULL }
	},
	{
		.input = "<user@domain.tld>",
		.address = { .localpart = "user", .domain = "domain.tld" }
	},
	{
		.input = "<@otherdomain.tld,@yetanotherdomain.tld:user@domain.tld>",
		.address = { .localpart = "user", .domain = "domain.tld" },
		.output = "<user@domain.tld>"
	},
	{
		.input = "user@domain.tld",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL,
		.address = { .localpart = "user", .domain = "domain.tld" },
		.output = "<user@domain.tld>"
	},
	/* Raw */
	{
		.input = "<>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_ALLOW_EMPTY |
			 SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW,
		.address = { .localpart = NULL, .domain = NULL, .raw = NULL }
	},
	{
		.input = "<user>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_ALLOW_LOCALPART |
			 SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW,
		.address = { .localpart = "user", .domain = NULL,
			     .raw = "user" }
	},
	{
		.input = "<user@domain.tld>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW,
		.address = { .localpart = "user", .domain = "domain.tld",
			     .raw = "user@domain.tld" }
	},
	{
		.input = "<@otherdomain.tld,@yetanotherdomain.tld:user@domain.tld>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW,
		.address = { .localpart = "user", .domain = "domain.tld",
			     .raw = "@otherdomain.tld,@yetanotherdomain.tld:"
				    "user@domain.tld" },
		.output = "<user@domain.tld>"
	},
	{
		.input = "user@domain.tld",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL |
			 SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW,
		.address = { .localpart = "user", .domain = "domain.tld",
			     .raw = "user@domain.tld"},
		.output = "<user@domain.tld>"
	},
	/* Broken */
	{
		.input = "<>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_ALLOW_EMPTY |
			 SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN,
		.address = { .localpart = NULL, .domain = NULL, .raw = NULL }
	},
	{
		.input = "<user>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_ALLOW_LOCALPART |
			 SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN,
		.address = { .localpart = "user", .domain = NULL,
			     .raw = "user" }
	},
	{
		.input = "<user@domain.tld>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN,
		.address = { .localpart = "user", .domain = "domain.tld",
			     .raw = "user@domain.tld" }
	},
	{
		.input = "<@otherdomain.tld,@yetanotherdomain.tld:user@domain.tld>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN,
		.address = { .localpart = "user", .domain = "domain.tld",
			     .raw = "@otherdomain.tld,@yetanotherdomain.tld:"
				    "user@domain.tld" },
		.output = "<user@domain.tld>"
	},
	{
		.input = "user@domain.tld",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL |
			 SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN,
		.address = { .localpart = "user", .domain = "domain.tld",
			     .raw = "user@domain.tld"},
		.output = "<user@domain.tld>"
	},
	{
		.input = "u\"ser",
		.flags = SMTP_ADDRESS_PARSE_FLAG_ALLOW_LOCALPART |
			 SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN,
		.address = { .localpart = NULL, .domain = NULL,
			     .raw = "u\"ser" },
		.output = "<>",
	},
	{
		.input = "user\"@domain.tld",
		.flags = SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN,
		.address = { .localpart = NULL, .domain = NULL,
			     .raw = "user\"@domain.tld" },
		.output = "<>",
	},
	{
		.input = "<u\"ser>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_ALLOW_LOCALPART |
			 SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN,
		.address = { .localpart = NULL, .domain = NULL,
			     .raw = "u\"ser" },
		.output = "<>",
	},
	{
		.input = "<user\"@domain.tld>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN,
		.address = { .localpart = NULL, .domain = NULL,
			     .raw = "user\"@domain.tld" },
		.output = "<>",
	},
	{
		.input = "bla$die%bla@die&bla",
		.flags = SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN,
		.address = { .localpart = NULL, .domain = NULL,
			     .raw = "bla$die%bla@die&bla" },
		.output = "<>",
	},
	{
		.input = "/@)$@)BLAARGH!@#$$",
		.flags = SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN,
		.address = { .localpart = NULL, .domain = NULL,
			     .raw = "/@)$@)BLAARGH!@#$$" },
		.output = "<>",
	},
	{
		.input = "</@)$@)BLAARGH!@#$$>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN,
		.address = { .localpart = NULL, .domain = NULL,
			     .raw = "/@)$@)BLAARGH!@#$$" },
		.output = "<>",
	},
	{
		.input = "/@)$@)BLAARGH!@#$$",
		.flags = SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN  |
			 SMTP_ADDRESS_PARSE_FLAG_ALLOW_BAD_LOCALPART |
			 SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL,
		.address = { .localpart = NULL, .domain = NULL,
			     .raw = "/@)$@)BLAARGH!@#$$" },
		.output = "<>",
	},
	{
		.input = "</@)$@)BLAARGH!@#$$>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN |
			 SMTP_ADDRESS_PARSE_FLAG_ALLOW_BAD_LOCALPART |
			 SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL,
		.address = { .localpart = NULL, .domain = NULL,
			     .raw = "/@)$@)BLAARGH!@#$$" },
		.output = "<>",
	},
	{
		.input = "f\xc3\xb6\xc3\xa4@\xc3\xb6\xc3\xa4",
		.flags = SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN |
			 SMTP_ADDRESS_PARSE_FLAG_ALLOW_BAD_LOCALPART |
			 SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL,
		.address = { .localpart = NULL, .domain = NULL,
			     .raw = "f\xc3\xb6\xc3\xa4@\xc3\xb6\xc3\xa4" },
		.output = "<>",
	},
	{
		.input = "<f\xc3\xb6\xc3\xa4@\xc3\xb6\xc3\xa4>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW |
			 SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN |
			 SMTP_ADDRESS_PARSE_FLAG_ALLOW_BAD_LOCALPART |
			 SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL,
		.address = { .localpart = NULL, .domain = NULL,
			     .raw = "f\xc3\xb6\xc3\xa4@\xc3\xb6\xc3\xa4" },
		.output = "<>",
	},
};

unsigned int valid_path_parse_test_count =
	N_ELEMENTS(valid_path_parse_tests);

static void
test_smtp_path_equal(const struct smtp_address *test,
		     const struct smtp_address *parsed)
{
	if (smtp_address_isnull(parsed) || smtp_address_isnull(test)) {
		test_out("address = <>",
			 (smtp_address_isnull(parsed) &&
			  smtp_address_isnull(test)));
	} else {
		test_out(t_strdup_printf("address->localpart = \"%s\"",
					 parsed->localpart),
			 null_strcmp(parsed->localpart, test->localpart) == 0);
	}
	if (smtp_address_isnull(parsed)) {
		/* nothing */
	} else if (parsed->domain == NULL) {
		test_out("address->domain = (null)",
			 (parsed->domain == test->domain));
	} else {
		test_out(t_strdup_printf("address->domain = \"%s\"",
					 parsed->domain),
			 null_strcmp(parsed->domain, test->domain) == 0);
	}
	if (parsed == NULL) {
		test_out_quiet(t_strdup_printf("address = (null)"),
			       (test->raw == NULL));
	} else if (parsed->raw == NULL) {
		test_out_quiet(t_strdup_printf("address->raw = (null)"),
			       (parsed->raw == test->raw));
	} else {
		test_out_quiet(t_strdup_printf("address->raw = \"%s\"",
					 parsed->raw),
			       null_strcmp(parsed->raw, test->raw) == 0);
	}
}

static void test_smtp_path_parse_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_path_parse_test_count; i++) T_BEGIN {
		const struct valid_path_parse_test *test;
		bool ignore_broken;
		struct smtp_address *address;
		const char *error = NULL, *output, *encoded;
		int ret;

		test = &valid_path_parse_tests[i];
		ignore_broken = HAS_ALL_BITS(
			test->flags, SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN);
		ret = smtp_address_parse_path(pool_datastack_create(),
					      test->input, test->flags,
					      &address, &error);

		test_begin(t_strdup_printf("smtp path valid [%d]", i));
		test_out_reason(t_strdup_printf("parse(\"%s\")", test->input),
				(ret == 0 || ignore_broken), error);

		if (!test_has_failed()) {
			test_smtp_path_equal(&test->address, address);

			encoded = smtp_address_encode_path(address);
			output = (test->output == NULL ?
				  test->input : test->output);
			test_out(t_strdup_printf("encode() = \"%s\"", encoded),
				 strcmp(encoded, output) == 0);
		}
		test_end();
	} T_END;
}

/*
 * Valid username parse tests
 */

struct valid_username_parse_test {
	const char *input, *output;

	struct smtp_address address;
};

static const struct valid_username_parse_test
valid_username_parse_tests[] = {
	{
		.input = "user",
		.address = {
			.localpart = "user",
			.domain = NULL },
	},
	{
		.input = "user@domain.tld",
		.address = {
			.localpart = "user",
			.domain = "domain.tld" },
	},
	{
		.input = "user@domain.tld",
		.address = {
			.localpart = "user",
			.domain = "domain.tld" },
	},
	{
		.input = "1234567890@domain.tld",
		.address = {
			.localpart = "1234567890",
			.domain = "domain.tld" },
	},
	{
		.input = "_______@domain.tld",
		.address = {
			.localpart = "_______",
			.domain = "domain.tld" },
	},
	{
		.input = "firstname.lastname@domain.tld",
		.address = {
			.localpart = "firstname.lastname",
			.domain = "domain.tld" },
	},
	{
		.input = "firstname+lastname@domain.tld",
		.address = {
			.localpart = "firstname+lastname",
			.domain = "domain.tld" },
	},
	{
		.input = "firstname-lastname@domain.tld",
		.address = {
			.localpart = "firstname-lastname",
			.domain = "domain.tld" },
	},
	{
		.input = "\"user\"@domain.tld",
		.address = { .localpart = "user", .domain = "domain.tld" },
		.output = "user@domain.tld"
	},
	{
		.input = "\"user@frop\"@domain.tld",
		.address = { .localpart = "user@frop", .domain = "domain.tld" },
		.output = "\"user@frop\"@domain.tld"
	},
	{
		.input = "user@frop@domain.tld",
		.address = { .localpart = "user@frop", .domain = "domain.tld" },
		.output = "\"user@frop\"@domain.tld"
	},
	{
		.input = "user frop@domain.tld",
		.address = { .localpart = "user frop", .domain = "domain.tld" },
		.output = "\"user frop\"@domain.tld"
	},
	{
		.input = "user\"frop@domain.tld",
		.address = { .localpart = "user\"frop", .domain = "domain.tld" },
		.output = "\"user\\\"frop\"@domain.tld"
	},
	{
		.input = "user\\frop@domain.tld",
		.address = { .localpart = "user\\frop", .domain = "domain.tld" },
		.output = "\"user\\\\frop\"@domain.tld"
	},
	{
		.input = "user@127.0.0.1",
		.address = { .localpart = "user", .domain = "127.0.0.1" },
	},
	{
		.input = "user@[127.0.0.1]",
		.address = { .localpart = "user", .domain = "[127.0.0.1]" },
	},
	{
		.input = "user@[IPv6:::1]",
		.address = { .localpart = "user", .domain = "[IPv6:::1]" },
	},
	{
		.input = "user@[IPv6:::127.0.0.1]",
		.address = { .localpart = "user", .domain = "[IPv6:::127.0.0.1]" },
	},
};

unsigned int valid_username_parse_test_count =
	N_ELEMENTS(valid_username_parse_tests);

static void test_smtp_username_parse_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_username_parse_test_count; i++) T_BEGIN {
		const struct valid_username_parse_test *test;
		struct smtp_address *address;
		const char *error = NULL, *output, *encoded;
		int ret;

		test = &valid_username_parse_tests[i];
		ret = smtp_address_parse_username(pool_datastack_create(),
						  test->input,
						  &address, &error);

		test_begin(t_strdup_printf("smtp username valid [%d]", i));
		test_out_reason(t_strdup_printf("parse(\"%s\")", test->input),
				ret == 0, error);

		if (!test_has_failed()) {
			test_smtp_path_equal(&test->address, address);

			encoded = smtp_address_encode(address);
			output = (test->output == NULL ?
				  test->input : test->output);
			test_out(t_strdup_printf("encode() = \"%s\"", encoded),
				 strcmp(encoded, output) == 0);
		}
		test_end();
	} T_END;
}

/*
 * Invalid mailbox parse tests
 */

struct invalid_mailbox_parse_test {
	const char *input;
	enum smtp_address_parse_flags flags;
};

static const struct invalid_mailbox_parse_test
invalid_mailbox_parse_tests[] = {
	{
		.input = "",
	},
	{
		.input = "user",
	},
	{
		.input = "\"user@domain.tld",
	},
	{
		.input = "us\"er@domain.tld",
	},
	{
		.input = "user@frop@domain.tld",
	},
	{
		.input = "user@.tld",
	},
	{
		.input = "user@a$.tld",
	},
	{
		.input = "user@a..tld",
	},
	{
		.input = "user@[]",
	},
	{
		.input = "user@[",
	},
	{
		.input = "user@[AA]",
	},
	{
		.input = "user@[AA",
	},
	{
		.input = "user@[127.0.0]",
	},
	{
		.input = "user@[256.256.256.256]",
	},
	{
		.input = "user@[127.0.0.1",
	},
	{
		.input = "user@[::1]",
	},
	{
		.input = "user@[IPv6:flierp]",
	},
	{
		.input = "user@[IPv6:aa:bb::cc::dd]",
	},
	{
		.input = "user@[IPv6::1]",
	},
	{
		.input = "user@[IPv6:::1",
	},
	{
		.input = "user@[Gen:]",
	},
	{
		.input = "user@[Gen:Hopsa",
	},
	{
		.input = "user@[Gen-:Hopsa]",
	},
	{
		.input = "#@%^%#$@#$@#.com",
	},
	{
		.input = "@example.com",
	},
	{
		.input = "Eric Mail <email@example.com>",
	},
	{
		.input = "email.example.com",
	},
	{
		.input = "email@example@example.com",
	},
	{
		.input = "あいうえお@example.com",
	},
	{
		.input = "email@example.com (Eric Mail)",
	},
	{
		.input = "email@example..com",
#if 0 /* These deviations are allowed (maybe implement strict mode) */
	},
	{
		.input = "email@-example.com",
	},
	{
		.input = ".email@example.com",
	},
	{
		.input = "email.@example.com",
	},
	{
		.input = "email..email@example.com",
	},
	{
		.input = "Abc..123@example.com"
#endif
	},
};

unsigned int invalid_mailbox_parse_test_count =
	N_ELEMENTS(invalid_mailbox_parse_tests);

static void test_smtp_mailbox_parse_invalid(void)
{
	unsigned int i;

	for (i = 0; i < invalid_mailbox_parse_test_count; i++) T_BEGIN {
		const struct invalid_mailbox_parse_test *test;
		struct smtp_address *address;
		const char *error = NULL;
		int ret;

		test = &invalid_mailbox_parse_tests[i];
		ret = smtp_address_parse_mailbox(pool_datastack_create(),
						 test->input, test->flags,
						 &address, &error);

		test_begin(t_strdup_printf("smtp mailbox invalid [%d]", i));
		test_out_reason(t_strdup_printf("parse(\"%s\")", test->input),
				ret < 0, error);
		test_end();
	} T_END;
}

/*
 * Invalid path parse tests
 */

struct invalid_path_parse_test {
	const char *input;
	enum smtp_address_parse_flags flags;
};

static const struct invalid_path_parse_test
invalid_path_parse_tests[] = {
	{
		.input = "",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "\"user@domain.tld",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "us\"er@domain.tld",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@frop@domain.tld",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@.tld",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@a$.tld",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@a..tld",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[]",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[AA]",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[AA",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[127.0.0]",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[256.256.256.256]",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[127.0.0.1",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[::1]",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[IPv6:flierp]",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[IPv6:aa:bb::cc::dd]",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[IPv6::1]",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[IPv6:::1",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[Gen:]",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[Gen:Hopsa",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "user@[Gen-:Hopsa]",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "#@%^%#$@#$@#.com",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "@example.com",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "Eric Mail <email@example.com>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "email.example.com",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "email@example@example.com",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "あいうえお@example.com",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "email@example.com (Eric Mail)",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "email@example..com",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "@otherdomain.tld,@yetanotherdomain.tld:user@domain.tld",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "<>",
	},
	{
		.input = "<user>",
	},
	{
		.input = "<\"user@domain.tld>",
	},
	{
		.input = "<us\"er@domain.tld>",
	},
	{
		.input = "<user@frop@domain.tld>",
	},
	{
		.input = "<user@.tld>",
	},
	{
		.input = "<user@a$.tld>",
	},
	{
		.input = "<user@a..tld>",
	},
	{
		.input = "<user@[]>",
	},
	{
		.input = "<user@[>",
	},
	{
		.input = "<user@[AA]>",
	},
	{
		.input = "<user@[AA>",
	},
	{
		.input = "<user@[127.0.0]>",
	},
	{
		.input = "<user@[256.256.256.256]>",
	},
	{
		.input = "<user@[127.0.0.1>",
	},
	{
		.input = "<user@[::1]>",
	},
	{
		.input = "<user@[IPv6:flierp]>",
	},
	{
		.input = "<user@[IPv6:aa:bb::cc::dd]>",
	},
	{
		.input = "<user@[IPv6::1]>",
	},
	{
		.input = "<user@[IPv6:::1>",
	},
	{
		.input = "<user@[Gen:]>",
	},
	{
		.input = "<user@[Gen:Hopsa>",
	},
	{
		.input = "<user@[Gen-:Hopsa]>",
	},
	{
		.input = "<#@%^%#$@#$@#.com>",
	},
	{
		.input = "<@example.com>",
	},
	{
		.input = "Eric Mail <email@example.com>",
	},
	{
		.input = "<email.example.com>",
	},
	{
		.input = "<email@example@example.com>",
	},
	{
		.input = "<あいうえお@example.com>",
	},
	{
		.input = "<email@example.com> (Eric Mail)",
	},
	{
		.input = "<email@example..com>",
	},
	{
		.input = "<email@example.com",
	},
	{
		.input = "email@example.com>",
	},
	{
		.input = "email@example.com>",
		.flags = SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL
	},
	{
		.input = "<",
		.flags = SMTP_ADDRESS_PARSE_FLAG_ALLOW_EMPTY,
	},
	{
		.input = "<user",
		.flags = SMTP_ADDRESS_PARSE_FLAG_ALLOW_LOCALPART,
	},
	{
		.input = "<@otherdomain.tld,@yetanotherdomain.tld.user@domain.tld>",
	},
	{
		.input = "<@###domain.tld,@yetanotherdomain.tld.user@domain.tld>",
	},
};

unsigned int invalid_path_parse_test_count =
	N_ELEMENTS(invalid_path_parse_tests);

static void test_smtp_path_parse_invalid(void)
{
	unsigned int i;

	for (i = 0; i < invalid_path_parse_test_count; i++) T_BEGIN {
		const struct invalid_path_parse_test *test;
		struct smtp_address *address;
		const char *error = NULL;
		int ret;

		test = &invalid_path_parse_tests[i];
		ret = smtp_address_parse_path(pool_datastack_create(),
					      test->input, test->flags,
					      &address, &error);

		test_begin(t_strdup_printf("smtp path invalid [%d]", i));
		test_out_reason(t_strdup_printf("parse(\"%s\")", test->input),
				ret < 0, error);
		test_end();
	} T_END;
}

/*
 * Invalid username parse tests
 */

struct invalid_username_parse_test {
	const char *input;
	enum smtp_address_parse_flags flags;
};

static const struct invalid_username_parse_test
invalid_username_parse_tests[] = {
	{
		.input = "frop@$%^$%^.tld",
	},
	{
		.input = "fr\top@domain.tld",
	}
};

unsigned int invalid_username_parse_test_count =
	N_ELEMENTS(invalid_username_parse_tests);

static void test_smtp_username_parse_invalid(void)
{
	unsigned int i;

	for (i = 0; i < invalid_username_parse_test_count; i++) T_BEGIN {
		const struct invalid_username_parse_test *test;
		struct smtp_address *address;
		const char *error = NULL;
		int ret;

		test = &invalid_username_parse_tests[i];
		ret = smtp_address_parse_username(pool_datastack_create(),
						  test->input,
						  &address, &error);

		test_begin(t_strdup_printf("smtp username invalid [%d]", i));
		test_out_reason(t_strdup_printf("parse(\"%s\")", test->input),
				ret < 0, error);
		test_end();
	} T_END;
}

/*
 * Address detail parsing
 */

struct address_detail_parse_test {
	const char *delimiters;
	const char *address;
	const char *username;
	const char *detail;
	char delim;
};

static const struct address_detail_parse_test
address_detail_parse_tests[] = {
	{ "", "test", "test", "", '\0' },
	{ "", "test+address", "test+address", "", '\0' },
	{ "", "\"test:address\"", "test:address", "", '\0' },
	{ "", "\"test-address:another+delim\"", "test-address:another+delim",
	  "", '\0' },
	{ "", "test@domain", "test@domain", "", '\0' },
	{ "", "test+address@domain", "test+address@domain", "", '\0' },
	{ "", "\"test:address\"@domain", "test:address@domain", "", '\0' },
	{ "", "\"test-address:another+delim\"@domain",
	  "test-address:another+delim@domain", "", '\0' },

	{ "+-:", "test", "test", "", '\0' },
	{ "+-:", "test+address", "test", "address", '+' },
	{ "+-:", "\"test:address\"", "test", "address", ':' },
	{ "+-:", "\"test-address:another+delim\"",
	  "test", "address:another+delim", '-' },
	{ "+-:", "test@domain", "test@domain", "", '\0' },
	{ "+-:", "test+address@domain", "test@domain", "address", '+' },
	{ "+-:", "\"test:address\"@domain", "test@domain", "address", ':' },
	{ "+-:", "\"test-address:another+delim\"@domain", "test@domain",
	  "address:another+delim", '-' },
};

unsigned int addresss_detail_parse_test_count =
	N_ELEMENTS(address_detail_parse_tests);

static void test_smtp_address_detail_parse(void)
{
	unsigned int i;


	for (i = 0; i < N_ELEMENTS(address_detail_parse_tests); i++) T_BEGIN {
		const struct address_detail_parse_test *test =
			&address_detail_parse_tests[i];
		struct smtp_address *address;
		const char *username, *detail, *error;
		char delim;
		int ret;

		test_begin(t_strdup_printf(
			"smtp address detail parsing [%d]", i));

		ret = smtp_address_parse_path(
			pool_datastack_create(), test->address,
			SMTP_ADDRESS_PARSE_FLAG_ALLOW_LOCALPART |
			SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL,
			&address, &error);
		test_out_reason("address parse", ret == 0, error);

		if (!test_has_failed()) {
			smtp_address_detail_parse_temp(test->delimiters,
						       address, &username,
						       &delim, &detail);
			test_assert(strcmp(username, test->username) == 0);
			test_assert(strcmp(detail, test->detail) == 0);
			test_assert(delim == test->delim);
		}

		test_end();
	} T_END;
}

/*
 * Skip address tests
 */

struct any_address_parse_test {
	const char *input;
	const char *address;
	size_t pos;
	int ret;
};

static const struct any_address_parse_test
any_address_parse_tests[] = {
	{
		.input = "",
		.address = "",
		.pos = 0,
		.ret = 0,
	},
	{
		.input = " ",
		.address = "",
		.pos = 0,
		.ret = 0,
	},
	{
		.input = "frop@example.com",
		.address = "frop@example.com",
		.pos = 16,
		.ret = 0,
	},
	{
		.input = "frop@example.com ",
		.address = "frop@example.com",
		.pos = 16,
		.ret = 0,
	},
	{
		.input = "<frop@example.com>",
		.address = "frop@example.com",
		.pos = 18,
		.ret = 0,
	},
	{
		.input = "<frop@example.com> ",
		.address = "frop@example.com",
		.pos = 18,
		.ret = 0,
	},
	{
		.input = "<frop@example.com",
		.pos = 0,
		.ret = -1,
	},
	{
		.input = "<frop@example.com ",
		.pos = 0,
		.ret = -1,
	},
	{
		.input = "fr\"op@example.com",
		.address = "fr\"op@example.com",
		.pos = 17,
		.ret = 0,
	},
	{
		.input = "fr\"op@example.com ",
		.address = "fr\"op@example.com",
		.pos = 17,
		.ret = 0,
	},
	{
		.input = "fr<op@example.com",
		.address = "fr<op@example.com",
		.pos = 17,
		.ret = 0,
	},
	{
		.input = "fr<op@example.com ",
		.address = "fr<op@example.com",
		.pos = 17,
		.ret = 0,
	},
	{
		.input = "\"frop\"@example.com",
		.address = "\"frop\"@example.com",
		.pos = 18,
		.ret = 0,
	},
	{
		.input = "\"frop\"@example.com ",
		.address = "\"frop\"@example.com",
		.pos = 18,
		.ret = 0,
	},
	{
		.input = "\"frop\\\"@example.com",
		.pos = 0,
		.ret = -1,
	},
	{
		.input = "\"frop\\\"@example.com ",
		.pos = 0,
		.ret = -1,
	},
	{
		.input = "<\"fr>op\"@example.com>",
		.address = "\"fr>op\"@example.com",
		.pos = 21,
		.ret = 0,
	},
	{
		.input = "<\"fr>op\"@example.com> ",
		.address = "\"fr>op\"@example.com",
		.pos = 21,
		.ret = 0,
	},
	{
		.input = "<\"fr>op\"@example.com",
		.pos = 0,
		.ret = -1,
	},
	{
		.input = "<\"fr>op\"@example.com ",
		.pos = 0,
		.ret = -1,
	},
	{
		.input = "<\"frop\">",
		.address = "\"frop\"",
		.pos = 8,
		.ret = 0,
	},
	{
		.input = "<\"frop\"> ",
		.address = "\"frop\"",
		.pos = 8,
		.ret = 0,
	},
	{
		.input = "<\"frop\"",
		.pos = 0,
		.ret = -1,
	},
	{
		.input = "<\"frop\" ",
		.pos = 0,
		.ret = -1,
	},
	{
		.input = "\"frop\\\" ",
		.pos = 0,
		.ret = -1,
	},
	{
		.input = "\"frop\\\"",
		.pos = 0,
		.ret = -1,
	},
};

unsigned int any_address_parse_tests_count =
	N_ELEMENTS(any_address_parse_tests);

static void test_smtp_parse_any_address(void)
{
	unsigned int i;

	for (i = 0; i < any_address_parse_tests_count; i++) T_BEGIN {
		const struct any_address_parse_test *test;
		const char *address = NULL, *pos = NULL;
		int ret;

		test = &any_address_parse_tests[i];
		ret = smtp_address_parse_any(test->input, &address, &pos);

		test_begin(t_strdup_printf("smtp parse any [%d]", i));
		test_out_quiet(t_strdup_printf("parse(\"%s\")",
					       str_sanitize(test->input, 256)),
			       (ret == test->ret) &&
			       ((size_t)(pos - test->input) == test->pos) &&
			       (null_strcmp(test->address, address ) == 0));
		test_end();
	} T_END;
}

/*
 * Tests
 */

int main(void)
{
	static void (*test_functions[])(void) = {
		test_smtp_mailbox_parse_valid,
		test_smtp_path_parse_valid,
		test_smtp_username_parse_valid,
		test_smtp_mailbox_parse_invalid,
		test_smtp_path_parse_invalid,
		test_smtp_username_parse_invalid,
		test_smtp_address_detail_parse,
		test_smtp_parse_any_address,
		NULL
	};
	return test_run(test_functions);
}
