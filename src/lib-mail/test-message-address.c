/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "message-address.h"
#include "test-common.h"

enum test_message_address {
	TEST_MESSAGE_ADDRESS_FLAG_SKIP_LIST = BIT(0),
};

static bool cmp_addr(const struct message_address *a1,
		     const struct message_address *a2)
{
	return null_strcmp(a1->name, a2->name) == 0 &&
		null_strcmp(a1->route, a2->route) == 0 &&
		null_strcmp(a1->mailbox, a2->mailbox) == 0 &&
		null_strcmp(a1->domain, a2->domain) == 0 &&
		a1->invalid_syntax == a2->invalid_syntax;
}

static const struct message_address *
test_parse_address(const char *input, bool fill_missing)
{
	/* duplicate the input (without trailing NUL) so valgrind notices
	   if there's any out-of-bounds access */
	size_t input_len = strlen(input);
	unsigned char *input_dup = i_memdup(input, input_len);
	const struct message_address *addr =
		message_address_parse(pool_datastack_create(),
				      input_dup, input_len, UINT_MAX, fill_missing);
	i_free(input_dup);
	return addr;
}

static void test_message_address(void)
{
	static const struct test {
		const char *input;
		const char *wanted_output;
		const char *wanted_filled_output;
		struct message_address addr;
		struct message_address filled_addr;
		enum test_message_address flags;
	} tests[] = {
		/* user@domain -> <user@domain> */
		{ "user@domain", "<user@domain>", NULL,
		  { NULL, NULL, NULL, "user", "domain", FALSE },
		  { NULL, NULL, NULL, "user", "domain", FALSE }, 0 },
		{ "\"user\"@domain", "<user@domain>", NULL,
		  { NULL, NULL, NULL, "user", "domain", FALSE },
		  { NULL, NULL, NULL, "user", "domain", FALSE }, 0 },
		{ "\"user name\"@domain", "<\"user name\"@domain>", NULL,
		  { NULL, NULL, NULL, "user name", "domain", FALSE },
		  { NULL, NULL, NULL, "user name", "domain", FALSE }, 0 },
		{ "\"user@na\\\\me\"@domain", "<\"user@na\\\\me\"@domain>", NULL,
		  { NULL, NULL, NULL, "user@na\\me", "domain", FALSE },
		  { NULL, NULL, NULL, "user@na\\me", "domain", FALSE }, 0 },
		{ "\"user\\\"name\"@domain", "<\"user\\\"name\"@domain>", NULL,
		  { NULL, NULL, NULL, "user\"name", "domain", FALSE },
		  { NULL, NULL, NULL, "user\"name", "domain", FALSE }, 0 },
		{ "\"\"@domain", "<\"\"@domain>", NULL,
		  { NULL, NULL, NULL, "", "domain", FALSE },
		  { NULL, NULL, NULL, "", "domain", FALSE }, 0 },
		{ "user", "<user>", "<user@MISSING_DOMAIN>",
		  { NULL, NULL, NULL, "user", "", TRUE },
		  { NULL, NULL, NULL, "user", "MISSING_DOMAIN", TRUE }, 0 },
		{ "@domain", "<\"\"@domain>", "<MISSING_MAILBOX@domain>",
		  { NULL, NULL, NULL, "", "domain", TRUE },
		  { NULL, NULL, NULL, "MISSING_MAILBOX", "domain", TRUE }, 0 },

		/* Display Name -> Display Name */
		{ "Display Name", "\"Display Name\"", "\"Display Name\" <MISSING_MAILBOX@MISSING_DOMAIN>",
		  { NULL, "Display Name", NULL, "", "", TRUE },
		  { NULL, "Display Name", NULL, "MISSING_MAILBOX", "MISSING_DOMAIN", TRUE }, 0 },
		{ "\"Display Name\"", "\"Display Name\"", "\"Display Name\" <MISSING_MAILBOX@MISSING_DOMAIN>",
		  { NULL, "Display Name", NULL, "", "", TRUE },
		  { NULL, "Display Name", NULL, "MISSING_MAILBOX", "MISSING_DOMAIN", TRUE }, 0 },
		{ "Display \"Name\"", "\"Display Name\"", "\"Display Name\" <MISSING_MAILBOX@MISSING_DOMAIN>",
		  { NULL, "Display Name", NULL, "", "", TRUE },
		  { NULL, "Display Name", NULL, "MISSING_MAILBOX", "MISSING_DOMAIN", TRUE }, 0 },
		{ "\"Display\" \"Name\"", "\"Display Name\"", "\"Display Name\" <MISSING_MAILBOX@MISSING_DOMAIN>",
		  { NULL, "Display Name", NULL, "", "", TRUE },
		  { NULL, "Display Name", NULL, "MISSING_MAILBOX", "MISSING_DOMAIN", TRUE }, 0 },
		{ "\"\"", "", "<MISSING_MAILBOX@MISSING_DOMAIN>",
		  { NULL, "", NULL, "", "", TRUE },
		  { NULL, "", NULL, "MISSING_MAILBOX", "MISSING_DOMAIN", TRUE }, 0 },

		/* <user@domain> -> <user@domain> */
		{ "<user@domain>", NULL, NULL,
		  { NULL, NULL, NULL, "user", "domain", FALSE },
		  { NULL, NULL, NULL, "user", "domain", FALSE }, 0 },
		{ "<\"user\"@domain>", "<user@domain>", NULL,
		  { NULL, NULL, NULL, "user", "domain", FALSE },
		  { NULL, NULL, NULL, "user", "domain", FALSE }, 0 },
		{ "<\"user name\"@domain>", NULL, NULL,
		  { NULL, NULL, NULL, "user name", "domain", FALSE },
		  { NULL, NULL, NULL, "user name", "domain", FALSE }, 0 },
		{ "<\"user@na\\\\me\"@domain>", NULL, NULL,
		  { NULL, NULL, NULL, "user@na\\me", "domain", FALSE },
		  { NULL, NULL, NULL, "user@na\\me", "domain", FALSE }, 0 },
		{ "<\"user\\\"name\"@domain>", NULL, NULL,
		  { NULL, NULL, NULL, "user\"name", "domain", FALSE },
		  { NULL, NULL, NULL, "user\"name", "domain", FALSE }, 0 },
		{ "<\"\"@domain>", NULL, NULL,
		  { NULL, NULL, NULL, "", "domain", FALSE },
		  { NULL, NULL, NULL, "", "domain", FALSE }, 0 },
		{ "<user>", NULL, "<user@MISSING_DOMAIN>",
		  { NULL, NULL, NULL, "user", "", TRUE },
		  { NULL, NULL, NULL, "user", "MISSING_DOMAIN", TRUE }, 0 },
		{ "<@route>", "<@route:\"\">", "<INVALID_ROUTE:MISSING_MAILBOX@MISSING_DOMAIN>",
		  { NULL, NULL, "@route", "", "", TRUE },
		  { NULL, NULL, "INVALID_ROUTE", "MISSING_MAILBOX", "MISSING_DOMAIN", TRUE }, 0 },

		/* user@domain (Display Name) -> "Display Name" <user@domain> */
		{ "user@domain (DisplayName)", "DisplayName <user@domain>", NULL,
		  { NULL, "DisplayName", NULL, "user", "domain", FALSE },
		  { NULL, "DisplayName", NULL, "user", "domain", FALSE }, 0 },
		{ "user@domain (Display Name)", "\"Display Name\" <user@domain>", NULL,
		  { NULL, "Display Name", NULL, "user", "domain", FALSE },
		  { NULL, "Display Name", NULL, "user", "domain", FALSE }, 0 },
		{ "user@domain (Display\"Name)", "\"Display\\\"Name\" <user@domain>", NULL,
		  { NULL, "Display\"Name", NULL, "user", "domain", FALSE },
		  { NULL, "Display\"Name", NULL, "user", "domain", FALSE }, 0 },
		{ "user (Display Name)", "\"Display Name\" <user>", "\"Display Name\" <user@MISSING_DOMAIN>",
		  { NULL, "Display Name", NULL, "user", "", TRUE },
		  { NULL, "Display Name", NULL, "user", "MISSING_DOMAIN", TRUE }, 0 },
		{ "@domain (Display Name)", "\"Display Name\" <\"\"@domain>", "\"Display Name\" <MISSING_MAILBOX@domain>",
		  { NULL, "Display Name", NULL, "", "domain", TRUE },
		  { NULL, "Display Name", NULL, "MISSING_MAILBOX", "domain", TRUE }, 0 },
		{ "user@domain ()", "<user@domain>", NULL,
		  { NULL, NULL, NULL, "user", "domain", FALSE },
		  { NULL, NULL, NULL, "user", "domain", FALSE }, 0 },

		/* Display Name <user@domain> -> "Display Name" <user@domain> */
		{ "DisplayName <user@domain>", NULL, NULL,
		  { NULL, "DisplayName", NULL, "user", "domain", FALSE },
		  { NULL, "DisplayName", NULL, "user", "domain", FALSE }, 0 },
		{ "Display Name <user@domain>", "\"Display Name\" <user@domain>", NULL,
		  { NULL, "Display Name", NULL, "user", "domain", FALSE },
		  { NULL, "Display Name", NULL, "user", "domain", FALSE }, 0 },
		{ "\"Display Name\" <user@domain>", NULL, NULL,
		  { NULL, "Display Name", NULL, "user", "domain", FALSE },
		  { NULL, "Display Name", NULL, "user", "domain", FALSE }, 0 },
		{ "\"Display\\\"Name\" <user@domain>", NULL, NULL,
		  { NULL, "Display\"Name", NULL, "user", "domain", FALSE },
		  { NULL, "Display\"Name", NULL, "user", "domain", FALSE }, 0 },
		{ "Display Name <user>", "\"Display Name\" <user>", "\"Display Name\" <user@MISSING_DOMAIN>",
		  { NULL, "Display Name", NULL, "user", "", TRUE },
		  { NULL, "Display Name", NULL, "user", "MISSING_DOMAIN", TRUE }, 0 },
		{ "\"\" <user@domain>", "<user@domain>", NULL,
		  { NULL, NULL, NULL, "user", "domain", FALSE },
		  { NULL, NULL, NULL, "user", "domain", FALSE }, 0 },

		/* <@route:user@domain> -> <@route:user@domain> */
		{ "<@route:user@domain>", NULL, NULL,
		  { NULL, NULL, "@route", "user", "domain", FALSE },
		  { NULL, NULL, "@route", "user", "domain", FALSE }, 0 },
		{ "<@route,@route2:user@domain>", NULL, NULL,
		  { NULL, NULL, "@route,@route2", "user", "domain", FALSE },
		  { NULL, NULL, "@route,@route2", "user", "domain", FALSE }, 0 },
		{ "<@route@route2:user@domain>", "<@route,@route2:user@domain>", NULL,
		  { NULL, NULL, "@route,@route2", "user", "domain", FALSE },
		  { NULL, NULL, "@route,@route2", "user", "domain", FALSE }, 0 },
		{ "<@route@route2:user>", "<@route,@route2:user>", "<@route,@route2:user@MISSING_DOMAIN>",
		  { NULL, NULL, "@route,@route2", "user", "", TRUE },
		  { NULL, NULL, "@route,@route2", "user", "MISSING_DOMAIN", TRUE }, 0 },
		{ "<@route@route2:\"\"@domain>", "<@route,@route2:\"\"@domain>", NULL,
		  { NULL, NULL, "@route,@route2", "", "domain", FALSE },
		  { NULL, NULL, "@route,@route2", "", "domain", FALSE }, 0 },

		/* Display Name <@route:user@domain> ->
		   "Display Name" <@route:user@domain> */
		{ "Display Name <@route:user@domain>", "\"Display Name\" <@route:user@domain>", NULL,
		  { NULL, "Display Name", "@route", "user", "domain", FALSE },
		  { NULL, "Display Name", "@route", "user", "domain", FALSE }, 0 },
		{ "Display Name <@route,@route2:user@domain>", "\"Display Name\" <@route,@route2:user@domain>", NULL,
		  { NULL, "Display Name", "@route,@route2", "user", "domain", FALSE },
		  { NULL, "Display Name", "@route,@route2", "user", "domain", FALSE }, 0 },
		{ "Display Name <@route@route2:user@domain>", "\"Display Name\" <@route,@route2:user@domain>", NULL,
		  { NULL, "Display Name", "@route,@route2", "user", "domain", FALSE },
		  { NULL, "Display Name", "@route,@route2", "user", "domain", FALSE }, 0 },
		{ "Display Name <@route@route2:user>", "\"Display Name\" <@route,@route2:user>", "\"Display Name\" <@route,@route2:user@MISSING_DOMAIN>",
		  { NULL, "Display Name", "@route,@route2", "user", "", TRUE },
		  { NULL, "Display Name", "@route,@route2", "user", "MISSING_DOMAIN", TRUE }, 0 },
		{ "Display Name <@route@route2:\"\"@domain>", "\"Display Name\" <@route,@route2:\"\"@domain>", NULL,
		  { NULL, "Display Name", "@route,@route2", "", "domain", FALSE },
		  { NULL, "Display Name", "@route,@route2", "", "domain", FALSE }, 0 },

		/* other tests: */
		{ "\"foo: <a@b>;,\" <user@domain>", NULL, NULL,
		  { NULL, "foo: <a@b>;,", NULL, "user", "domain", FALSE },
		  { NULL, "foo: <a@b>;,", NULL, "user", "domain", FALSE }, 0 },
		{ "<>", "", "<MISSING_MAILBOX@MISSING_DOMAIN>",
		  { NULL, NULL, NULL, "", "", TRUE },
		  { NULL, NULL, NULL, "MISSING_MAILBOX", "MISSING_DOMAIN", TRUE }, 0 },
		{ "<@>", "", "<INVALID_ROUTE:MISSING_MAILBOX@MISSING_DOMAIN>",
		  { NULL, NULL, NULL, "", "", TRUE },
		  { NULL, NULL, "INVALID_ROUTE", "MISSING_MAILBOX", "MISSING_DOMAIN", TRUE }, 0 },

		/* Test against a out-of-bounds read bug - keep these two tests
		   together in this same order: */
		{ "aaaa@", "<aaaa>", "<aaaa@MISSING_DOMAIN>",
		  { NULL, NULL, NULL, "aaaa", "", TRUE },
		  { NULL, NULL, NULL, "aaaa", "MISSING_DOMAIN", TRUE }, 0 },
		{ "a(aa", "", "<MISSING_MAILBOX@MISSING_DOMAIN>",
		  { NULL, NULL, NULL, "", "", TRUE },
		  { NULL, NULL, NULL, "MISSING_MAILBOX", "MISSING_DOMAIN", TRUE },
		  TEST_MESSAGE_ADDRESS_FLAG_SKIP_LIST },
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

	for (i = 0; i < N_ELEMENTS(tests)*2; i++) {
		const struct test *test = &tests[i/2];
		const struct message_address *test_wanted_addr;
		bool fill_missing = i%2 != 0;

		test_wanted_addr = !fill_missing ?
			&test->addr : &test->filled_addr;
		addr = test_parse_address(test->input, fill_missing);
		test_assert_idx(addr != NULL && addr->next == NULL &&
				cmp_addr(addr, test_wanted_addr), i);

		/* test the address alone */
		str_truncate(str, 0);
		message_address_write(str, addr);
		if (fill_missing && test->wanted_filled_output != NULL)
			wanted_string = test->wanted_filled_output;
		else if (test->wanted_output != NULL)
			wanted_string = test->wanted_output;
		else
			wanted_string = test->input;
		test_assert_idx(strcmp(str_c(str), wanted_string) == 0, i);

		if ((test->flags & TEST_MESSAGE_ADDRESS_FLAG_SKIP_LIST) != 0)
			continue;

		/* test the address as a list of itself */
		for (unsigned int list_length = 2; list_length <= 5; list_length++) {
			str_truncate(group, 0);
			str_append(group, test->input);
			for (unsigned int j = 1; j < list_length; j++) {
				if ((j % 2) == 0)
					str_append(group, ",");
				else
					str_append(group, " , \n ");
				str_append(group, test->input);
			}

			addr = test_parse_address(str_c(group), fill_missing);
			for (unsigned int j = 0; j < list_length; j++) {
				test_assert_idx(addr != NULL &&
						cmp_addr(addr, test_wanted_addr), i);
				if (addr != NULL)
					addr = addr->next;
			}
			test_assert_idx(addr == NULL, i);
		}

		/* test the address as a group of itself */
		for (unsigned int list_length = 1; list_length <= 5; list_length++) {
			str_truncate(group, 0);
			str_printfa(group, "group: %s", test->input);
			for (unsigned int j = 1; j < list_length; j++) {
				if ((j % 2) == 0)
					str_append(group, ",");
				else
					str_append(group, " , \n ");
				str_append(group, test->input);
			}
			str_append_c(group, ';');

			addr = test_parse_address(str_c(group), fill_missing);
			test_assert(addr != NULL && cmp_addr(addr, &group_prefix));
			addr = addr->next;
			for (unsigned int j = 0; j < list_length; j++) {
				test_assert_idx(addr != NULL &&
						cmp_addr(addr, test_wanted_addr), i);
				if (addr != NULL)
					addr = addr->next;
			}
			test_assert_idx(addr != NULL && addr->next == NULL &&
					cmp_addr(addr, &group_suffix), i);
		}
	}
	test_end();

	test_begin("message address parsing with empty group");
	str_truncate(group, 0);
	str_append(group, "group:;");
	addr = test_parse_address(str_c(group), FALSE);
	str_truncate(str, 0);
	message_address_write(str, addr);
	test_assert(addr != NULL && cmp_addr(addr, &group_prefix));
	addr = addr->next;
	test_assert(addr != NULL && addr->next == NULL &&
		    cmp_addr(addr, &group_suffix));
	test_assert(strcmp(str_c(str), "group:;") == 0);
	test_end();

	test_begin("message address parsing empty string");
	test_assert(message_address_parse(unsafe_data_stack_pool, &uchar_nul, 0, 10, TRUE) == NULL);
	str_truncate(str, 0);
	message_address_write(str, NULL);
	test_assert(str_len(str) == 0);
	test_end();
}

static void test_message_address_nuls(void)
{
	const unsigned char input[] =
		"\"user\0nuls\"@[domain\0nuls] (comment\0nuls)";
	const struct message_address output = {
		NULL, "comment\x80nuls", NULL, "user\x80nuls",
		"[domain\x80nuls]", FALSE
	};
	const struct message_address *addr;

	test_begin("message address parsing with NULs");
	addr = message_address_parse(pool_datastack_create(),
				     input, sizeof(input)-1, UINT_MAX, FALSE);
	test_assert(addr != NULL && cmp_addr(addr, &output));
	test_end();
}

static int
test_parse_path(const char *input, const struct message_address **addr_r)
{
	struct message_address *addr;
	char *input_dup;
	int ret;

	/* duplicate the input (without trailing NUL) so valgrind notices
	   if there's any out-of-bounds access */
	size_t input_len = strlen(input);
	if (input_len > 0)
		input = input_dup = i_memdup(input, input_len);
	ret = message_address_parse_path(pool_datastack_create(),
					 (unsigned char *)input, input_len,
					 &addr);
	if (input_len > 0)
		i_free(input_dup);
	*addr_r = addr;
	return ret;
}

static void test_message_address_path(void)
{
	static const struct test {
		const char *input;
		const char *wanted_output;
		struct message_address addr;
	} tests[] = {
		{ "<>", NULL,
		  { NULL, NULL, NULL, NULL, NULL, FALSE } },
		{ " < > ", "<>",
		  { NULL, NULL, NULL, NULL, NULL, FALSE } },
		{ "<user@domain>", NULL,
		  { NULL, NULL, NULL, "user", "domain", FALSE } },
		{ "  <user@domain>  ", "<user@domain>",
		  { NULL, NULL, NULL, "user", "domain", FALSE } },
		{ "user@domain", "<user@domain>",
		  { NULL, NULL, NULL, "user", "domain", FALSE } },
		{ "  user@domain  ", "<user@domain>",
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
	};
	const struct message_address *addr;
	string_t *str;
	const char *wanted_string;
	unsigned int i;

	test_begin("message address path parsing");
	str = t_str_new(128);

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const struct test *test = &tests[i];
		const struct message_address *test_wanted_addr;
		int ret;

		test_wanted_addr = &test->addr;
		ret = test_parse_path(test->input, &addr);
		test_assert_idx(ret == 0, i);
		test_assert_idx(addr != NULL && addr->next == NULL &&
				cmp_addr(addr, test_wanted_addr), i);

		/* test the address alone */
		str_truncate(str, 0);
		message_address_write(str, addr);
		if (test->wanted_output != NULL)
			wanted_string = test->wanted_output;
		else
			wanted_string = test->input;
		test_assert_idx(strcmp(str_c(str), wanted_string) == 0, i);
	}
	test_end();
}

static void test_message_address_path_invalid(void)
{
	static const char *tests[] = {
		"",
		"<",
		" < ",
		">",
		" > ",
		"<user@domain",
		"  <user@domain  ",
		"user@domain>",
		"  user@domain>  ",
		"<user>",
		"<@route@route2:user>",
		"<@domain>",
		"@domain",
		"  @domain  ",
		"<user@>",
		"user@",
		"  user@  ",
		"<user@domain>bladiebla",
		"user@domain@"
	};
	const struct message_address *addr;
	unsigned int i;

	test_begin("message address path invalid");

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const char *test = tests[i];
		int ret;

		ret = test_parse_path(test, &addr);
		test_assert_idx(ret < 0, i);
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_address,
		test_message_address_nuls,
		test_message_address_path,
		test_message_address_path_invalid,
		NULL
	};
	return test_run(test_functions);
}
