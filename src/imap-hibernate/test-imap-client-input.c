/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
#include "test-common.h"
#include "imap-client-input.h"

static void test_imap_client_input_parse_line(void)
{
	static const struct {
		const char *line;
		enum imap_client_input_cmd cmd;
		const char *tag;
		const char *name;
	} tests[] = {
		{ "DONE", IMAP_CLIENT_INPUT_CMD_DONE, NULL, NULL },
		{ "done", IMAP_CLIENT_INPUT_CMD_DONE, NULL, NULL },
		{ "DONE ", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "DONE x", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ " DONE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "DON", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A IDLE", IMAP_CLIENT_INPUT_CMD_IDLE, "A", "IDLE" },
		{ "a1 idle", IMAP_CLIENT_INPUT_CMD_IDLE, "a1", "idle" },
		{ "A IDLE x", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A IDLE ", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A  IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A IDL", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A IDLES", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "x] Idle", IMAP_CLIENT_INPUT_CMD_IDLE, "x]", "Idle" },
		{ "A NOOP", IMAP_CLIENT_INPUT_CMD_NOOP, "A", "NOOP" },
		{ "a1 noop", IMAP_CLIENT_INPUT_CMD_NOOP, "a1", "noop" },
		{ "A NOOP x", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A CHECK", IMAP_CLIENT_INPUT_CMD_CHECK, "A", "CHECK" },
		{ "A CHECK x", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A LOGOUT", IMAP_CLIENT_INPUT_CMD_LOGOUT, "A", "LOGOUT" },
		{ "x] Logout", IMAP_CLIENT_INPUT_CMD_LOGOUT, "x]", "Logout" },
		{ "A FETCH 1 FLAGS", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A DONE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "+ IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "* IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A{ IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "\"A\" IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A\001 IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A\xff IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A IDLE\r\r", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A ID\rLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ " IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "A ", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
		{ "", IMAP_CLIENT_INPUT_CMD_OTHER, NULL, NULL },
	};
	const char *tag, *name;
	unsigned int i;

	test_begin("imap client input parse line");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const char *line = tests[i].line;
		const char *line_cr = t_strconcat(line, "\r", NULL);

		test_assert_idx(imap_client_input_parse_line(
			(const unsigned char *)line, strlen(line), &tag,
			&name) == tests[i].cmd, i);
		test_assert_strcmp_idx(tag, tests[i].tag, i);
		test_assert_strcmp_idx(name, tests[i].name, i);

		test_assert_idx(imap_client_input_parse_line(
			(const unsigned char *)line_cr, strlen(line_cr), &tag,
			&name) == tests[i].cmd, i);
		test_assert_strcmp_idx(tag, tests[i].tag, i);
		test_assert_strcmp_idx(name, tests[i].name, i);
	}
	/* NUL in the middle of the line */
	test_assert(imap_client_input_parse_line(
		(const unsigned char *)"A IDLE\0", 7, &tag, &name) ==
		IMAP_CLIENT_INPUT_CMD_OTHER);
	test_assert(imap_client_input_parse_line(
		(const unsigned char *)"DONE\0", 5, &tag, &name) ==
		IMAP_CLIENT_INPUT_CMD_OTHER);
	test_end();
}

static void test_imap_client_input_parse_line_long_tag(void)
{
	string_t *line = t_str_new(256);
	const char *tag, *name;

	test_begin("imap client input parse line: long tag");
	for (unsigned int i = 0; i < 200; i++)
		str_append_c(line, 'a');
	str_append(line, " IDLE");
	test_assert(imap_client_input_parse_line(str_data(line),
						 str_len(line), &tag, &name) ==
		    IMAP_CLIENT_INPUT_CMD_IDLE);
	test_assert(strlen(tag) == 200);
	test_assert_strcmp(name, "IDLE");
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_imap_client_input_parse_line,
		test_imap_client_input_parse_line_long_tag,
		NULL
	};
	return test_run(test_functions);
}
