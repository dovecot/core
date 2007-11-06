/* Copyright (c) 2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "message-address.h"
#include "message-date.h"
#include "test-common.h"

static bool cmp_addr(const struct message_address *a1,
		     const struct message_address *a2)
{
	return null_strcmp(a1->name, a2->name) == 0 &&
		null_strcmp(a1->route, a2->route) == 0 &&
		null_strcmp(a1->mailbox, a2->mailbox) == 0 &&
		null_strcmp(a1->domain, a2->domain) == 0;
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
		"hello <@route ,@route2:user@domain>"
	};
	static struct message_address group_prefix = {
		NULL, NULL, NULL, "group", NULL
	};
	static struct message_address group_suffix = {
		NULL, NULL, NULL, NULL, NULL
	};
	static struct message_address output[] = {
		{ NULL, NULL, NULL, "user", "domain" },
		{ NULL, NULL, NULL, "user", "domain" },
		{ NULL, "foo bar", NULL, "user", "domain" },
		{ NULL, "foo bar", NULL, "user", "domain" },
		{ NULL, NULL, "@route", "user", "domain" },
		{ NULL, NULL, "@route,@route2", "user", "domain" },
		{ NULL, "hello", "@route,@route2", "user", "domain" }
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

		if (i != 0) {
			if ((i % 2) == 0)
				str_append(group, ",");
			else
				str_append(group, " , \n ");
		}
		str_append(group, input[i]);
	}
	str_append_c(group, ';');

	addr = message_address_parse(pool_datastack_create(), str_data(group),
				     str_len(group), -1U, FALSE);
	success = addr != NULL && cmp_addr(addr, &group_prefix);
	addr = addr->next;
	for (i = 0; i < N_ELEMENTS(input) && addr != NULL; i++) {
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

struct test_message_date_output {
	time_t time;
	int tz_offset;
	bool ret;
};

static void test_message_date_parse(void)
{
	static const char *input[] = {
#ifdef TIME_T_SIGNED
		"Thu, 01 Jan 1970 01:59:59 +0200",
		"Fri, 13 Dec 1901 20:45:52 +0000",
#endif
#if TIME_T_MAX_BITS > 31
		"Sun, 07 Feb 2106 06:28:15 +0000",
#endif
		"Wed, 07 Nov 2007 01:07:20 +0200",
		"Wed, 07 Nov 2007 01:07:20",
		"Thu, 01 Jan 1970 02:00:00 +0200",
		"Tue, 19 Jan 2038 03:14:07 +0000",
		"Tue, 19 Jan 2038"
	};
	static struct test_message_date_output output[] = {
#ifdef TIME_T_SIGNED
		{ -1, 2*60, TRUE },
		{ -2147483648, 0, TRUE },
#endif
#if TIME_T_MAX_BITS > 31
		{ 4294967295, 0, TRUE },
#endif
		{ 1194390440, 2*60, TRUE },
		{ 1194397640, 0, TRUE },
		{ 0, 2*60, TRUE },
		{ 2147483647, 0, TRUE },
		{ 0, 0, FALSE }
	};
	unsigned int i;
	bool success;
	time_t t;
	int tz;
	bool ret;

	for (i = 0; i < N_ELEMENTS(input); i++) {
		ret = message_date_parse((const unsigned char *)input[i],
					 strlen(input[i]), &t, &tz);
		success = (!ret && !output[i].ret) ||
			(ret == output[i].ret && t == output[i].time &&
			 tz == output[i].tz_offset);
		test_out(t_strdup_printf("message_date_parse(%d)", i), success);
	}
}

int main(void)
{
	test_init();

	test_message_address();
	test_message_date_parse();
	return test_deinit();
}
