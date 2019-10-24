/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "mail-types.h"
#include "imap-arg.h"
#include "imap-util.h"
#include "test-common.h"

static void test_imap_parse_system_flag(void)
{
	test_begin("imap_parse_system_flag");
	test_assert(imap_parse_system_flag("\\aNswered") == MAIL_ANSWERED);
	test_assert(imap_parse_system_flag("\\fLagged") == MAIL_FLAGGED);
	test_assert(imap_parse_system_flag("\\dEleted") == MAIL_DELETED);
	test_assert(imap_parse_system_flag("\\sEen") == MAIL_SEEN);
	test_assert(imap_parse_system_flag("\\dRaft") == MAIL_DRAFT);
	test_assert(imap_parse_system_flag("\\rEcent") == MAIL_RECENT);
	test_assert(imap_parse_system_flag("answered") == 0);
	test_assert(imap_parse_system_flag("\\broken") == 0);
	test_assert(imap_parse_system_flag("\\") == 0);
	test_assert(imap_parse_system_flag("") == 0);
	test_end();
}

static void test_imap_write_arg(void)
{
	ARRAY_TYPE(imap_arg_list) list_root, list_sub;
	struct imap_arg *arg;

	t_array_init(&list_sub, 2);
	arg = array_append_space(&list_sub);
	arg->type = IMAP_ARG_ATOM;
	arg->_data.str = "foo";
	arg = array_append_space(&list_sub);
	arg->type = IMAP_ARG_EOL;

	t_array_init(&list_root, 2);
	arg = array_append_space(&list_root);
	arg->type = IMAP_ARG_LIST;
	arg->_data.list = list_sub;
	arg = array_append_space(&list_root);
	arg->type = IMAP_ARG_STRING;
	arg->_data.str = "bar";
	arg = array_append_space(&list_root);
	arg->type = IMAP_ARG_EOL;

	const struct {
		struct imap_arg input;
		const char *output;
	} tests[] = {
		{ { .type = IMAP_ARG_NIL }, "NIL" },
		{ { .type = IMAP_ARG_ATOM, ._data.str = "atom" }, "atom" },
		{ { .type = IMAP_ARG_STRING, ._data.str = "s\\t\"ring" }, "\"s\\\\t\\\"ring\"" },
		{ { .type = IMAP_ARG_LITERAL, ._data.str = "l\\i\"t\r\neral" }, "{11}\r\nl\\i\"t\r\neral" },
		{ { .type = IMAP_ARG_LITERAL_SIZE, ._data.literal_size = 12345678 }, "<12345678 byte literal>" },
		{ { .type = IMAP_ARG_LITERAL_SIZE_NONSYNC, ._data.literal_size = 12345678 }, "<12345678 byte literal>" },
		{ { .type = IMAP_ARG_LIST, ._data.list = list_root }, "((foo) \"bar\")" },
	};
	string_t *str = t_str_new(100);

	test_begin("imap_write_arg");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		imap_write_arg(str, &tests[i].input);
		test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_imap_parse_system_flag,
		test_imap_write_arg,
		NULL
	};
	return test_run(test_functions);
}
