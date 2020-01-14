/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "array.h"
#include "buffer.h"
#include "str.h"
#include "str-sanitize.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"
#include "smtp-command-parser.h"

#include <time.h>

/*
 * Valid command tests
 */

struct smtp_command_parse_valid_test {
	const char *command;

	struct smtp_command_limits limits;

	const char *cmd_name;
	const char *cmd_params;
};

static const struct smtp_command_parse_valid_test
valid_command_parse_tests[] = {
	{
		.command = "RSET\r\n",
		.cmd_name = "RSET",
		.cmd_params = ""
	}, {
		.command = "RSET    \r\n",
		.cmd_name = "RSET",
		.cmd_params = ""
	}, {
		.command = "EHLO example.com\r\n",
		.cmd_name = "EHLO",
		.cmd_params = "example.com"
	}, {
		.command = "EHLO example.com     \r\n",
		.cmd_name = "EHLO",
		.cmd_params = "example.com"
	}, {
		.command = "MAIL FROM:<sender@example.com> ENVID=frop\r\n",
		.cmd_name = "MAIL",
		.cmd_params = "FROM:<sender@example.com> ENVID=frop"
	}, {
		.command = "VRFY \"Sherlock Holmes\"\r\n",
		.cmd_name = "VRFY",
		.cmd_params = "\"Sherlock Holmes\""
	}, {
		.command = "RCPT TO:<recipient@example.com> NOTIFY=NEVER\r\n",
		.limits = { .max_parameters_size = 39 },
		.cmd_name = "RCPT",
		.cmd_params = "TO:<recipient@example.com> NOTIFY=NEVER"
	}, {
		.command = "MAIL FROM:<f\xc3\xb6\xc3\xa4@\xc3\xb6\xc3\xa4>\r\n",
		.cmd_name = "MAIL",
		.cmd_params = "FROM:<f\xc3\xb6\xc3\xa4@\xc3\xb6\xc3\xa4>"
	}
};

unsigned int valid_command_parse_test_count =
	N_ELEMENTS(valid_command_parse_tests);

static void test_smtp_command_parse_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_command_parse_test_count; i++) T_BEGIN {
		struct istream *input;
		const struct smtp_command_parse_valid_test *test;
		struct smtp_command_parser *parser;
		const char *cmd_name = NULL, *cmd_params = NULL, *error = NULL;
		enum smtp_command_parse_error error_code;
		int ret;

		test = &valid_command_parse_tests[i];
		input = i_stream_create_from_data(test->command,
						  strlen(test->command));
		parser = smtp_command_parser_init(input, &test->limits);
		i_stream_unref(&input);

		test_begin(t_strdup_printf("smtp command valid [%d]", i));

		while ((ret=smtp_command_parse_next(parser,
			&cmd_name, &cmd_params, &error_code, &error)) > 0);

		test_out_reason("parse success", ret == -2, error);

		if (ret == 0) {
			/* verify last response only */
			test_out(t_strdup_printf("command name = `%s'",
				test->cmd_name),
				null_strcmp(cmd_name, test->cmd_name) == 0);
			test_out(t_strdup_printf("command params = `%s'",
				str_sanitize(test->cmd_params, 24)),
				null_strcmp(cmd_params, test->cmd_params) == 0);
		}
		test_end();
		smtp_command_parser_deinit(&parser);
	} T_END;
}

/*
 * Invalid command tests
 */

struct smtp_command_parse_invalid_test {
	const char *command;

	struct smtp_command_limits limits;

	enum smtp_command_parse_error error_code;
};

static const struct smtp_command_parse_invalid_test
	invalid_command_parse_tests[] = {
	{
		.command = "B52\r\n",
		.error_code = SMTP_COMMAND_PARSE_ERROR_BAD_COMMAND
	}, {
		.command = "BELL\x08\r\n",
		.error_code = SMTP_COMMAND_PARSE_ERROR_BAD_COMMAND
	}, {
		.command = "EHLO  example.com\r\n",
		.error_code = SMTP_COMMAND_PARSE_ERROR_BAD_COMMAND
	}, {
		.command = "NOOP \"\x01\x02\x03\"\r\n",
		.error_code = SMTP_COMMAND_PARSE_ERROR_BAD_COMMAND
	}, {
		.command = "RSET\rQUIT\r\n",
		.error_code = SMTP_COMMAND_PARSE_ERROR_BAD_COMMAND
	}, {
		.command = "INSANELYREDICULOUSLYLONGCOMMANDNAME\r\n",
		.error_code = SMTP_COMMAND_PARSE_ERROR_BAD_COMMAND
	}, {
		.command = "RCPT TO:<recipient@example.com> NOTIFY=NEVER\r\n",
		.limits = { .max_parameters_size = 38 },
		.error_code = SMTP_COMMAND_PARSE_ERROR_LINE_TOO_LONG
	}, {
		.command = "MAIL FROM:<f\xc3\xb6\xc3\xa4@\xc3\xb6\xc3>\r\n",
		.error_code = SMTP_COMMAND_PARSE_ERROR_BAD_COMMAND,
	}, {
		.command = "MAIL FROM:f\xc3\xb6\xc3\xa4@\xc3\xb6\xc3\r\n",
		.error_code = SMTP_COMMAND_PARSE_ERROR_BAD_COMMAND,
	}, {
		.command = "MAIL FROM:f\xc3\xb6\xc3\xa4@\xc3\xb6\xc3",
		.error_code = SMTP_COMMAND_PARSE_ERROR_BROKEN_COMMAND,
	}
};

unsigned int invalid_command_parse_test_count =
	N_ELEMENTS(invalid_command_parse_tests);

static void test_smtp_command_parse_invalid(void)
{
	unsigned int i;

	for (i = 0; i < invalid_command_parse_test_count; i++) T_BEGIN {
		const struct smtp_command_parse_invalid_test *test;
		struct istream *input;
		struct smtp_command_parser *parser;
		const char *command_text, *cmd_name, *cmd_params, *error;
		enum smtp_command_parse_error error_code;
		int ret;

		test = &invalid_command_parse_tests[i];
		command_text = test->command;
		input = i_stream_create_from_data(command_text,
						  strlen(command_text));
		parser = smtp_command_parser_init(input, &test->limits);
		i_stream_unref(&input);

		test_begin(t_strdup_printf("smtp command invalid [%d]", i));

		while ((ret=smtp_command_parse_next(parser,
			&cmd_name, &cmd_params, &error_code, &error)) > 0);
		test_out_reason(t_strdup_printf("parse(\"%s\")",
			str_sanitize(command_text, 28)), ret == -1, error);
		test_out_quiet("error code",
			error_code == test->error_code);

		test_end();
		smtp_command_parser_deinit(&parser);
	} T_END;
}

/*
 * Valid auth response tests
 */

struct smtp_auth_response_parse_valid_test {
	const char *auth_response;

	struct smtp_command_limits limits;

	const char *line;
};

static const struct smtp_auth_response_parse_valid_test
valid_auth_response_parse_tests[] = {
	{
		.auth_response = "U3R1cGlkIEJhc2U2NCB0ZXN0\r\n",
		.line = "U3R1cGlkIEJhc2U2NCB0ZXN0"
	}, {
		.auth_response = "U3R1cGlkIEJhc2U2NCB0ZXN0    \r\n",
		.line = "U3R1cGlkIEJhc2U2NCB0ZXN0"
	}, {
		.auth_response =
			"U3R1cGlkIHZlcnkgdmVyeSB2ZXJ5IHZlcnkgdmVyeS"
			"B2ZXJ5IHZlcnkgdmVyeSBsb25nIEJhc2U2NCB0ZXN0\r\n",
		.limits = { .max_auth_size = 84 },
		.line = "U3R1cGlkIHZlcnkgdmVyeSB2ZXJ5IHZlcnkgdmVyeS"
			"B2ZXJ5IHZlcnkgdmVyeSBsb25nIEJhc2U2NCB0ZXN0"
	}
};

unsigned int valid_auth_response_parse_test_count =
	N_ELEMENTS(valid_auth_response_parse_tests);

static void test_smtp_auth_response_parse_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_auth_response_parse_test_count; i++) T_BEGIN {
		struct istream *input;
		const struct smtp_auth_response_parse_valid_test *test;
		struct smtp_command_parser *parser;
		const char *line, *error = NULL;
		enum smtp_command_parse_error error_code;
		int ret;

		test = &valid_auth_response_parse_tests[i];
		input = i_stream_create_from_data(test->auth_response,
						  strlen(test->auth_response));
		parser = smtp_command_parser_init(input, &test->limits);
		i_stream_unref(&input);

		test_begin(t_strdup_printf("smtp auth_response valid [%d]", i));

		while ((ret=smtp_command_parse_auth_response(parser,
			&line, &error_code, &error)) > 0);

		test_out_reason("parse success", ret == -2, error);

		if (ret == 0) {
			/* verify last response only */
			test_out(t_strdup_printf("line = `%s'",
				str_sanitize(test->line, 24)),
				null_strcmp(line, test->line) == 0);
		}
		test_end();
		smtp_command_parser_deinit(&parser);
	} T_END;
}

/*
 * Invalid auth response tests
 */

struct smtp_auth_response_parse_invalid_test {
	const char *auth_response;

	struct smtp_command_limits limits;

	enum smtp_command_parse_error error_code;
};

static const struct smtp_auth_response_parse_invalid_test
	invalid_auth_response_parse_tests[] = {
	{
		.auth_response = "\x01\x02\x03\r\n",
		.error_code = SMTP_COMMAND_PARSE_ERROR_BAD_COMMAND
	}, {
		.auth_response = "U3R1cGlkIEJhc\r2U2NCB0ZXN0\r\n",
		.error_code = SMTP_COMMAND_PARSE_ERROR_BAD_COMMAND
	}, {
		.auth_response =
			"U3R1cGlkIHZlcnkgdmVyeSB2ZXJ5IHZlcnkgdmVyeS"
			"B2ZXJ5IHZlcnkgdmVyeSBsb25nIEJhc2U2NCB0ZXN0\r\n",
		.limits = { .max_auth_size = 83 },
		.error_code = SMTP_COMMAND_PARSE_ERROR_LINE_TOO_LONG
	}, {
		.auth_response = "\xc3\xb6\xc3\xa4\xc3\xb6\xc3\xa4\r\n",
		.error_code = SMTP_COMMAND_PARSE_ERROR_BAD_COMMAND,
	}
};

unsigned int invalid_auth_response_parse_test_count =
	N_ELEMENTS(invalid_auth_response_parse_tests);

static void test_smtp_auth_response_parse_invalid(void)
{
	unsigned int i;

	for (i = 0; i < invalid_auth_response_parse_test_count; i++) T_BEGIN {
		const struct smtp_auth_response_parse_invalid_test *test;
		struct istream *input;
		struct smtp_command_parser *parser;
		const char *response_text, *line, *error;
		enum smtp_command_parse_error error_code;
		int ret;

		test = &invalid_auth_response_parse_tests[i];
		response_text = test->auth_response;
		input = i_stream_create_from_data(response_text,
						  strlen(response_text));
		parser = smtp_command_parser_init(input, &test->limits);
		i_stream_unref(&input);

		test_begin(t_strdup_printf(
			"smtp auth response invalid [%d]", i));

		while ((ret=smtp_command_parse_auth_response(parser,
			&line, &error_code, &error)) > 0);
		test_out_reason(t_strdup_printf("parse(\"%s\")",
			str_sanitize(response_text, 28)), ret == -1, error);
		test_out_quiet("error code",
			error_code == test->error_code);

		test_end();
		smtp_command_parser_deinit(&parser);
	} T_END;
}

/*
 * Tests
 */

int main(void)
{
	static void (*test_functions[])(void) = {
		test_smtp_command_parse_valid,
		test_smtp_command_parse_invalid,
		test_smtp_auth_response_parse_valid,
		test_smtp_auth_response_parse_invalid,
		NULL
	};
	return test_run(test_functions);
}
