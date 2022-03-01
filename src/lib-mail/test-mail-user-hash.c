/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "mail-user-hash.h"
#include "test-common.h"

#include "md5.h"

static void test_mail_user_hash(void)
{
	struct test_case {
		const char *username;
		const char *format;
		unsigned int hash;
	} test_cases[] = {
		{
			.username = "",
			.format = "",
			.hash = 3558706393,
		},
		{
			.username = "testuser",
			.format = "",
			.hash = 3558706393,
		},
		{
			.username = "",
			.format = "%u",
			.hash = 3558706393,
		},
		{
			.username = "@",
			.format = "%u",
			.hash = 1368314517,
		},
		{
			.username = "",
			.format = "%n@%d",
			.hash = 1368314517,
		},
		{
			.username = "",
			.format = "%n",
			.hash = 3558706393,
		},
		{
			.username = "",
			.format = "%d",
			.hash = 3558706393,
		},
		{
			.username = "testuser",
			.format = "%u",
			.hash = 1570531526,
		},
		{
			.username = "testuser",
			.format = "%n",
			.hash = 1570531526,
		},
		{
			.username = "testuser",
			.format = "%d",
			.hash = 3558706393,
		},
		{
			.username = "@domain",
			.format = "%u",
			.hash = 3749630072,
		},
		{
			.username = "@domain",
			.format = "%n@%d",
			.hash = 3749630072,
		},
		{
			.username = "@domain",
			.format = "%n",
			.hash = 3558706393,
		},
		{
			.username = "@domain",
			.format = "%d",
			.hash = 2908717800,
		},
		{
			.username = "testuser@domain",
			.format = "%u",
			.hash = 3813799143,
		},
		{
			.username = "testuser@domain",
			.format = "%n@%d",
			.hash = 3813799143,
		},
		{
			.username = "testuser@domain",
			.format = "%n",
			.hash = 1570531526,
		},
		{
			.username = "testuser@domain",
			.format = "%d",
			.hash = 2908717800,
		},
                {
                        .username = "test@user@domain",
                        .format = "%u",
                        .hash = 2029259821,
                },
		{
			.username = "test@user@domain",
			.format = "%n@%d",
			.hash = 2029259821,
		},
                {
                        .username = "test@user@domain",
                        .format = "%n",
                        .hash = 160394189,
                },
                {
                        .username = "test@user@domain",
                        .format = "%d",
                        .hash = 1841230927,
                }
	};

	test_begin("mail_user_hash");

	for (size_t i = 0; i < N_ELEMENTS(test_cases); i++) {
		const struct test_case *tc = &test_cases[i];
		const char *error = NULL;
		unsigned int hash;
		test_assert_idx(mail_user_hash(tc->username, tc->format, &hash,
					       &error), i);
		test_assert_idx(error == NULL, i);
		test_assert_idx(hash == tc->hash, i);
	}

	test_end();
}

static void test_mail_user_hash_errors(void)
{
	test_begin("mail_user_hash_errors");

	struct test_case {
		const char *username;
		const char *format;
		unsigned int hash;
		const char *error;
	} test_cases[] = {
		{
			.username = "testuser@domain",
			.format = "%{invalid}",
			.hash = 1466562296,
			.error = "Unknown variable '%invalid'",
		},
	};

	for (size_t i = 0; i < N_ELEMENTS(test_cases); i++) {
		const struct test_case *tc = &test_cases[i];
		const char *error = NULL;
		unsigned int hash = 0;
		test_assert_idx(mail_user_hash(tc->username, tc->format, &hash,
					       &error) == FALSE, i);
		test_assert_idx(tc->hash == hash, i);
		test_assert_strcmp_idx(tc->error, error, i);
		test_assert_idx(tc->hash == hash, i);
	}

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_user_hash,
		test_mail_user_hash_errors,
		NULL
	};
	return test_run(test_functions);
}
