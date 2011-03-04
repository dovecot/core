/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

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
	static const char *input[] = {
		"user@domain", NULL,
		"<user@domain>", "user@domain",
		"foo bar <user@domain>", NULL,
		"\"foo bar\" <user@domain>", "foo bar <user@domain>",
		"<@route:user@domain>", NULL,
		"<@route@route2:user@domain>", "<@route,@route2:user@domain>",
		"hello <@route ,@route2:user@domain>", "hello <@route,@route2:user@domain>",
		"user (hello)", NULL,
		"hello <user>", NULL,
		"@domain", NULL
	};
	static struct message_address group_prefix = {
		NULL, NULL, NULL, "group", NULL, FALSE
	};
	static struct message_address group_suffix = {
		NULL, NULL, NULL, NULL, NULL, FALSE
	};
	static struct message_address output[] = {
		{ NULL, NULL, NULL, "user", "domain", FALSE },
		{ NULL, NULL, NULL, "user", "domain", FALSE },
		{ NULL, "foo bar", NULL, "user", "domain", FALSE },
		{ NULL, "foo bar", NULL, "user", "domain", FALSE },
		{ NULL, NULL, "@route", "user", "domain", FALSE },
		{ NULL, NULL, "@route,@route2", "user", "domain", FALSE },
		{ NULL, "hello", "@route,@route2", "user", "domain", FALSE },
		{ NULL, "hello", NULL, "user", "", TRUE },
		{ NULL, "hello", NULL, "user", "", TRUE },
		{ NULL, NULL, NULL, "", "domain", TRUE }
	};
	struct message_address *addr;
	string_t *str, *group;
	const char *wanted_string;
	unsigned int i;

	i_assert(N_ELEMENTS(input) == N_ELEMENTS(output)*2);

	test_begin("message address parsing");
	str = t_str_new(128);
	group = t_str_new(256);
	str_append(group, "group: ");

	for (i = 0; i < N_ELEMENTS(output); i++) {
		addr = message_address_parse(pool_datastack_create(),
					     (const unsigned char *)input[i*2],
					     strlen(input[i*2]), -1U, FALSE);
		test_assert(addr != NULL && addr->next == NULL &&
			    cmp_addr(addr, &output[i]));

		if (!output[i].invalid_syntax) {
			str_truncate(str, 0);
			message_address_write(str, addr);
			wanted_string = input[i*2+1] != NULL ?
				input[i*2+1] : input[i*2];
			test_assert(strcmp(str_c(str), wanted_string) == 0);
			if (i != 0) {
				if ((i % 2) == 0)
					str_append(group, ",");
				else
					str_append(group, " , \n ");
			}
			str_append(group, input[i*2]);
		}
	}
	str_append_c(group, ';');
	test_end();

	test_begin("message address parsing with groups");
	addr = message_address_parse(pool_datastack_create(), str_data(group),
				     str_len(group), -1U, FALSE);
	test_assert(addr != NULL && cmp_addr(addr, &group_prefix));
	addr = addr->next;
	for (i = 0; i < N_ELEMENTS(output) && addr != NULL; i++) {
		if (output[i].invalid_syntax)
			continue;
		test_assert(cmp_addr(addr, &output[i]));
		addr = addr->next;
	}
	test_assert(addr != NULL && addr->next == NULL &&
		    cmp_addr(addr, &group_suffix));
	test_end();

	test_begin("message address parsing with empty group");
	str_truncate(group, 0);
	str_append(group, "group:;");
	addr = message_address_parse(pool_datastack_create(), str_data(group),
				     str_len(group), -1U, FALSE);
	test_assert(addr != NULL && cmp_addr(addr, &group_prefix));
	addr = addr->next;
	test_assert(addr != NULL && addr->next == NULL &&
		    cmp_addr(addr, &group_suffix));
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_message_address,
		NULL
	};
	return test_run(test_functions);
}
