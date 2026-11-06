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
	} tests[] = {
		{ "DONE", IMAP_CLIENT_INPUT_CMD_DONE, NULL },
		{ "done", IMAP_CLIENT_INPUT_CMD_DONE, NULL },
		{ "DONE ", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "DONE x", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ " DONE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "DON", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "A IDLE", IMAP_CLIENT_INPUT_CMD_IDLE, "A" },
		{ "a1 idle", IMAP_CLIENT_INPUT_CMD_IDLE, "a1" },
		{ "A IDLE x", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "A IDLE ", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "A  IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "A IDL", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "A IDLES", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "x] Idle", IMAP_CLIENT_INPUT_CMD_IDLE, "x]" },
		{ "A FETCH 1 FLAGS", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "A DONE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "+ IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "* IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "A{ IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "\"A\" IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "A\001 IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "A\xff IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "A IDLE\r\r", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "A ID\rLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ " IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "IDLE", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "A", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "A ", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
		{ "", IMAP_CLIENT_INPUT_CMD_OTHER, NULL },
	};
	const char *tag;
	unsigned int i;

	test_begin("imap client input parse line");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const char *line = tests[i].line;
		const char *line_cr = t_strconcat(line, "\r", NULL);

		test_assert_idx(imap_client_input_parse_line(
			(const unsigned char *)line, strlen(line), &tag) ==
			tests[i].cmd, i);
		test_assert_strcmp_idx(tag, tests[i].tag, i);

		test_assert_idx(imap_client_input_parse_line(
			(const unsigned char *)line_cr, strlen(line_cr), &tag) ==
			tests[i].cmd, i);
		test_assert_strcmp_idx(tag, tests[i].tag, i);
	}
	/* NUL in the middle of the line */
	test_assert(imap_client_input_parse_line(
		(const unsigned char *)"A IDLE\0", 7, &tag) ==
		IMAP_CLIENT_INPUT_CMD_OTHER);
	test_assert(imap_client_input_parse_line(
		(const unsigned char *)"DONE\0", 5, &tag) ==
		IMAP_CLIENT_INPUT_CMD_OTHER);
	test_end();
}

static void test_imap_client_input_parse_line_long_tag(void)
{
	string_t *line = t_str_new(256);
	const char *tag;

	test_begin("imap client input parse line: long tag");
	for (unsigned int i = 0; i < 200; i++)
		str_append_c(line, 'a');
	str_append(line, " IDLE");
	test_assert(imap_client_input_parse_line(str_data(line),
						 str_len(line), &tag) ==
		    IMAP_CLIENT_INPUT_CMD_IDLE);
	test_assert(strlen(tag) == 200);
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
