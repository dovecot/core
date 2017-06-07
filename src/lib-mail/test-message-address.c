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

static const struct message_address *test_parse_address(const char *input)
{
	/* duplicate the input (without trailing NUL) so valgrind notices
	   if there's any out-of-bounds access */
	size_t input_len = strlen(input);
	unsigned char *input_dup = i_malloc(input_len);
	memcpy(input_dup, input, input_len);
	const struct message_address *addr =
		message_address_parse(pool_datastack_create(),
				      input_dup, input_len, UINT_MAX, FALSE);
	i_free(input_dup);
	return addr;
}

static void test_message_address(void)
{
	static const struct test {
		const char *input;
		const char *wanted_output;
		struct message_address addr;
	} tests[] = {
		/* user@domain -> <user@domain> */
		{ "user@domain", "<user@domain>",
		  { NULL, NULL, NULL, "user", "domain", FALSE } },
		{ "\"user\"@domain", "<user@domain>",
		  { NULL, NULL, NULL, "user", "domain", FALSE } },
		{ "\"user name\"@domain", "<\"user name\"@domain>",
		  { NULL, NULL, NULL, "user name", "domain", FALSE } },
		{ "\"user@na\\\\me\"@domain", "<\"user@na\\\\me\"@domain>",
		  { NULL, NULL, NULL, "user@na\\me", "domain", FALSE } },
		{ "\"user\\\"name\"@domain", "<\"user\\\"name\"@domain>",
		  { NULL, NULL, NULL, "user\"name", "domain", FALSE } },
		{ "\"\"@domain", "<\"\"@domain>",
		  { NULL, NULL, NULL, "", "domain", FALSE } },
		{ "@domain", "<\"\"@domain>",
		  { NULL, NULL, NULL, "", "domain", TRUE } },

		/* <user@domain> -> <user@domain> */
		{ "<user@domain>", NULL,
		  { NULL, NULL, NULL, "user", "domain", FALSE } },
		{ "<\"user\"@domain>", "<user@domain>",
		  { NULL, NULL, NULL, "user", "domain", FALSE } },
		{ "<\"user name\"@domain>", NULL,
		  { NULL, NULL, NULL, "user name", "domain", FALSE } },
		{ "<\"user@na\\\\me\"@domain>", NULL,
		  { NULL, NULL, NULL, "user@na\\me", "domain", FALSE } },
		{ "<\"user\\\"name\"@domain>", NULL,
		  { NULL, NULL, NULL, "user\"name", "domain", FALSE } },
		{ "<\"\"@domain>", NULL,
		  { NULL, NULL, NULL, "", "domain", FALSE } },
		{ "<@route>", "<@route:\"\">",
		  { NULL, NULL, "@route", "", "", TRUE } },

		/* user@domain (Display Name) -> "Display Name" <user@domain> */
		{ "user@domain (DisplayName)", "DisplayName <user@domain>",
		  { NULL, "DisplayName", NULL, "user", "domain", FALSE } },
		{ "user@domain (Display Name)", "\"Display Name\" <user@domain>",
		  { NULL, "Display Name", NULL, "user", "domain", FALSE } },
		{ "user@domain (Display\"Name)", "\"Display\\\"Name\" <user@domain>",
		  { NULL, "Display\"Name", NULL, "user", "domain", FALSE } },
		{ "user (Display Name)", "\"Display Name\" <user>",
		  { NULL, "Display Name", NULL, "user", "", TRUE } },
		{ "@domain (Display Name)", "\"Display Name\" <\"\"@domain>",
		  { NULL, "Display Name", NULL, "", "domain", TRUE } },

		/* Display Name <user@domain> -> "Display Name" <user@domain> */
		{ "DisplayName <user@domain>", NULL,
		  { NULL, "DisplayName", NULL, "user", "domain", FALSE } },
		{ "Display Name <user@domain>", "\"Display Name\" <user@domain>",
		  { NULL, "Display Name", NULL, "user", "domain", FALSE } },
		{ "\"Display Name\" <user@domain>", NULL,
		  { NULL, "Display Name", NULL, "user", "domain", FALSE } },
		{ "\"Display\\\"Name\" <user@domain>", NULL,
		  { NULL, "Display\"Name", NULL, "user", "domain", FALSE } },
		{ "Display Name <user>", "\"Display Name\" <user>",
		  { NULL, "Display Name", NULL, "user", "", TRUE } },

		/* <@route:user@domain> -> <@route:user@domain> */
		{ "<@route:user@domain>", NULL,
		  { NULL, NULL, "@route", "user", "domain", FALSE } },
		{ "<@route,@route2:user@domain>", NULL,
		  { NULL, NULL, "@route,@route2", "user", "domain", FALSE } },
		{ "<@route@route2:user@domain>", "<@route,@route2:user@domain>",
		  { NULL, NULL, "@route,@route2", "user", "domain", FALSE } },
		{ "<@route@route2:user>", "<@route,@route2:user>",
		  { NULL, NULL, "@route,@route2", "user", "", TRUE } },
		{ "<@route@route2:\"\"@domain>", "<@route,@route2:\"\"@domain>",
		  { NULL, NULL, "@route,@route2", "", "domain", FALSE } },

		/* Display Name <@route:user@domain> ->
		   "Display Name" <@route:user@domain> */
		{ "Display Name <@route:user@domain>", "\"Display Name\" <@route:user@domain>",
		  { NULL, "Display Name", "@route", "user", "domain", FALSE } },
		{ "Display Name <@route,@route2:user@domain>", "\"Display Name\" <@route,@route2:user@domain>",
		  { NULL, "Display Name", "@route,@route2", "user", "domain", FALSE } },
		{ "Display Name <@route@route2:user@domain>", "\"Display Name\" <@route,@route2:user@domain>",
		  { NULL, "Display Name", "@route,@route2", "user", "domain", FALSE } },
		{ "Display Name <@route@route2:user>", "\"Display Name\" <@route,@route2:user>",
		  { NULL, "Display Name", "@route,@route2", "user", "", TRUE } },
		{ "Display Name <@route@route2:\"\"@domain>", "\"Display Name\" <@route,@route2:\"\"@domain>",
		  { NULL, "Display Name", "@route,@route2", "", "domain", FALSE } },

		/* other tests: */
		{ "\"foo: <a@b>;,\" <user@domain>", NULL,
		  { NULL, "foo: <a@b>;,", NULL, "user", "domain", FALSE } },
	};
	static struct message_address group_prefix = {
		NULL, NULL, NULL, "group", NULL, FALSE
	};
	static struct message_address group_suffix = {
		NULL, NULL, NULL, NULL, NULL, FALSE
	};
	const struct message_address *addr;
	string_t *str, *group;
	const char *wanted_string;
	unsigned int i;

	test_begin("message address parsing");
	str = t_str_new(128);
	group = t_str_new(256);
	str_append(group, "group: ");

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const struct test *test = &tests[i];

		addr = test_parse_address(test->input);
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
	addr = test_parse_address(str_c(group));
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
	addr = test_parse_address(str_c(group));
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
