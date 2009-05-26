/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

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
		"user@domain",
		"<user@domain>",
		"foo bar <user@domain>",
		"\"foo bar\" <user@domain>",
		"<@route:user@domain>",
		"<@route@route2:user@domain>",
		"hello <@route ,@route2:user@domain>",
		"user (hello)",
		"hello <user>",
		"@domain"
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
	string_t *group;
	unsigned int i;
	bool success;

	group = t_str_new(256);
	str_append(group, "group: ");

	for (i = 0; i < N_ELEMENTS(input); i++) {
		addr = message_address_parse(pool_datastack_create(),
					     (const unsigned char *)input[i],
					     strlen(input[i]), -1U, FALSE);
		success = addr != NULL && addr->next == NULL &&
			cmp_addr(addr, &output[i]);
		test_out(t_strdup_printf("message_address_parse(%d)", i),
			 success);

		if (!output[i].invalid_syntax) {
			if (i != 0) {
				if ((i % 2) == 0)
					str_append(group, ",");
				else
					str_append(group, " , \n ");
			}
			str_append(group, input[i]);
		}
	}
	str_append_c(group, ';');

	addr = message_address_parse(pool_datastack_create(), str_data(group),
				     str_len(group), -1U, FALSE);
	success = addr != NULL && cmp_addr(addr, &group_prefix);
	addr = addr->next;
	for (i = 0; i < N_ELEMENTS(input) && addr != NULL; i++) {
		if (output[i].invalid_syntax)
			continue;
		if (!cmp_addr(addr, &output[i])) {
			success = FALSE;
			break;
		}
		addr = addr->next;
	}
	if (addr == NULL || addr->next != NULL ||
	    !cmp_addr(addr, &group_suffix))
		success = FALSE;
	test_out("message_address_parse(group)", success);
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_message_address,
		NULL
	};
	return test_run(test_functions);
}
