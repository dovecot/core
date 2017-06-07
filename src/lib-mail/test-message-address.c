/* Copyright (c) 2007-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "message-address.h"
#include "test-common.h"

static bool cmp_addr(const struct message_address *a1,
		     const struct message_address *a2)
{
	return null_strcmp(a1->name, a2->name) == 0 &&
		null_strcmp(a1->route, a2->route) == 0 &&
		null_strcmp(a1->mailbox, a2->mailbox) == 0 &&
		null_strcmp(a1->domain, a2->domain) == 0 &&
		a1->invalid_syntax == a2->invalid_syntax;
}

static void test_message_address(void)
{
	static const struct test {
		const char *input;
		const char *wanted_output;
		struct message_address addr;
	} tests[] = {
		{ "user@domain", "<user@domain>",
		  { NULL, NULL, NULL, "user", "domain", FALSE } },
		{ "<user@domain>", NULL,
		  { NULL, NULL, NULL, "user", "domain", FALSE } },
		{ "foo bar <user@domain>", "\"foo bar\" <user@domain>",
		  { NULL, "foo bar", NULL, "user", "domain", FALSE } },
		{ "\"foo bar\" <user@domain>", NULL,
		  { NULL, "foo bar", NULL, "user", "domain", FALSE } },
		{ "\"foo: <a@b>;,\" <user@domain>", NULL,
		  { NULL, "foo: <a@b>;,", NULL, "user", "domain", FALSE } },
		{ "<@route:user@domain>", NULL,
		  { NULL, NULL, "@route", "user", "domain", FALSE } },
		{ "<@route@route2:user@domain>", "<@route,@route2:user@domain>",
		  { NULL, NULL, "@route,@route2", "user", "domain", FALSE } },
		{ "hello <@route ,@route2:user@domain>", "hello <@route,@route2:user@domain>",
		  { NULL, "hello", "@route,@route2", "user", "domain", FALSE } },
		{ "hello", "hello",
		  { NULL, "hello", NULL, "", "", TRUE } },
		{ "user (hello)", "hello <user>",
		  { NULL, "hello", NULL, "user", "", TRUE } },
		{ "hello <user>", "hello <user>",
		  { NULL, "hello", NULL, "user", "", TRUE } },
		{ "@domain", "<@domain>",
		  { NULL, NULL, NULL, "", "domain", TRUE } },
	};
	static struct message_address group_prefix = {
		NULL, NULL, NULL, "group", NULL, FALSE
	};
	static struct message_address group_suffix = {
		NULL, NULL, NULL, NULL, NULL, FALSE
	};
	struct message_address *addr;
	string_t *str, *group;
	const char *wanted_string;
	unsigned int i;

	test_begin("message address parsing");
	str = t_str_new(128);
	group = t_str_new(256);
	str_append(group, "group: ");

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const struct test *test = &tests[i];

		addr = message_address_parse(pool_datastack_create(),
					     (const unsigned char *)test->input,
					     strlen(test->input), UINT_MAX, FALSE);
		test_assert_idx(addr != NULL && addr->next == NULL &&
				cmp_addr(addr, &test->addr), i);

		str_truncate(str, 0);
		message_address_write(str, addr);
		wanted_string = test->wanted_output != NULL ?
			test->wanted_output : test->input;
		test_assert_idx(strcmp(str_c(str), wanted_string) == 0, i);
		if (!test->addr.invalid_syntax) {
			if (i != 0) {
				if ((i % 2) == 0)
					str_append(group, ",");
				else
					str_append(group, " , \n ");
			}
			str_append(group, test->input);
		}
	}
	str_append_c(group, ';');
	test_end();

	test_begin("message address parsing with groups");
	addr = message_address_parse(pool_datastack_create(), str_data(group),
				     str_len(group), UINT_MAX, FALSE);
	test_assert(addr != NULL && cmp_addr(addr, &group_prefix));
	addr = addr->next;
	for (i = 0; i < N_ELEMENTS(tests) && addr != NULL; i++) {
		const struct test *test = &tests[i];

		if (test->addr.invalid_syntax)
			continue;
		test_assert(cmp_addr(addr, &test->addr));
		addr = addr->next;
	}
	test_assert(addr != NULL && addr->next == NULL &&
		    cmp_addr(addr, &group_suffix));
	test_end();

	test_begin("message address parsing with empty group");
	str_truncate(group, 0);
	str_append(group, "group:;");
	addr = message_address_parse(pool_datastack_create(), str_data(group),
				     str_len(group), UINT_MAX, FALSE);
	str_truncate(str, 0);
	message_address_write(str, addr);
	test_assert(addr != NULL && cmp_addr(addr, &group_prefix));
	addr = addr->next;
	test_assert(addr != NULL && addr->next == NULL &&
		    cmp_addr(addr, &group_suffix));
	test_assert(strcmp(str_c(str), "group:;") == 0);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_address,
		NULL
	};
	return test_run(test_functions);
}
