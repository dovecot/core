/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "array.h"
#include "buffer.h"
#include "str.h"
#include "str-sanitize.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"
#include "smtp-reply-parser.h"

#include <time.h>

struct smtp_reply_parse_valid_test {
	const char *reply;
	unsigned int status;
	bool ehlo;
	size_t max_size;
	struct {
		unsigned int x, y, z;
	} enhanced_code;
	const char *const *text_lines;
};

/* Valid reply tests */

static const struct smtp_reply_parse_valid_test
valid_reply_parse_tests[] = {
	{
		.reply = "220\r\n",
		.status = 220,
		.text_lines = (const char *[]){ "", NULL }
	},{
		.reply = "220 \r\n",
		.status = 220,
		.text_lines = (const char *[]){ "", NULL }
	},{
		.reply = "220 OK\r\n",
		.status = 220,
		.text_lines = (const char *[]){ "OK", NULL }
	},{
		.reply = "550 Requested action not taken: mailbox unavailable\r\n",
		.status = 550,
		.text_lines = (const char *[])
			{ "Requested action not taken: mailbox unavailable", NULL }
	},{
		.reply =
			"250-smtp.example.com Hello client.example.org [10.0.0.1]\r\n"
			"250-SIZE 52428800\r\n"
			"250-PIPELINING\r\n"
			"250-STARTTLS\r\n"
			"250 HELP\r\n",
		.ehlo = TRUE,
		.status = 250,
		.text_lines = (const char *[]) {
			"smtp.example.com Hello client.example.org [10.0.0.1]",
			"SIZE 52428800",
			"PIPELINING",
			"STARTTLS",
			"HELP",
			NULL
		}
	},{
		.reply =
			"250-smtp.example.com We got some nice '\x03' and '\x04'\r\n"
			"250 HELP\r\n",
		.ehlo = TRUE,
		.status = 250,
		.text_lines = (const char *[]) {
			"smtp.example.com We got some nice ' ' and ' '",
			"HELP",
			NULL
		}
	},{
		.reply =
			"250 smtp.example.com We got some nice '\x08'\r\n",
		.ehlo = TRUE,
		.status = 250,
		.text_lines = (const char *[]) {
			"smtp.example.com We got some nice ' '",
			NULL
		}
	},{
		.reply = "250 2.1.0 Originator <frop@example.com> ok\r\n",
		.status = 250,
		.enhanced_code = { 2, 1, 0 },
		.text_lines = (const char *[]){
			"Originator <frop@example.com> ok", NULL
		}
	},{
		.reply =
			"551-5.7.1 Forwarding to remote hosts disabled\r\n"
			"551 5.7.1 Select another host to act as your forwarder\r\n",
		.status = 551,
		.enhanced_code = { 5, 7, 1 },
		.text_lines = (const char *[])	{
			"Forwarding to remote hosts disabled",
			"Select another host to act as your forwarder",
			NULL
		}
	}
};

unsigned int valid_reply_parse_test_count =
	N_ELEMENTS(valid_reply_parse_tests);

static void test_smtp_reply_parse_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_reply_parse_test_count; i++) T_BEGIN {
		struct istream *input;
		const struct smtp_reply_parse_valid_test *test;
		struct smtp_reply_parser *parser;
		struct smtp_reply *reply;
		const char *error;
		int ret;

		test = &valid_reply_parse_tests[i];
		input = i_stream_create_from_data(test->reply, strlen(test->reply));
		parser = smtp_reply_parser_init(input, test->max_size);
		i_stream_unref(&input);

		test_begin(t_strdup_printf("smtp reply valid [%d]", i));

		if (test->ehlo) {
			while ((ret=smtp_reply_parse_ehlo
				(parser, &reply, &error)) > 0) {
			}
		} else {
			while ((ret=smtp_reply_parse_next
				(parser, test->enhanced_code.x > 0, &reply, &error)) > 0) {
			}
		}

		test_out_reason("parse success", ret == 0, error);

		if (ret == 0) {
			/* verify last response only */
			test_out(t_strdup_printf("reply->status = %d", test->status),
					reply->status == test->status);
			if (test->enhanced_code.x > 0) {
				test_out(t_strdup_printf("reply->enhanced_code = %d.%d.%d",
					test->enhanced_code.x, test->enhanced_code.y, test->enhanced_code.z),
					(reply->enhanced_code.x == test->enhanced_code.x &&
						reply->enhanced_code.y == test->enhanced_code.y &&
						reply->enhanced_code.z == test->enhanced_code.z));
			}
			if (test->text_lines != NULL) {
				const char *const *line = test->text_lines;
				const char *const *reply_line = reply->text_lines;
				unsigned int index = 0;

				while (*line != NULL) {
					if (*reply_line == NULL) {
						test_out(
							t_strdup_printf("reply->text_lines[%d] = NULL", index),
							FALSE);
						break;
					}
					test_out(t_strdup_printf(
						"reply->text_lines[%d] = \"%s\"", index, *reply_line),
						strcmp(*line, *reply_line) == 0);
					line++;
					reply_line++;
					index++;
				}
			} else {
				test_out("reply->text_lines = NULL", reply->text_lines == NULL);
			}
		}
		test_end();
		smtp_reply_parser_deinit(&parser);
	} T_END;
}

struct smtp_reply_parse_invalid_test {
	const char *reply;
	bool ehlo;
	size_t max_size;
};

static const struct smtp_reply_parse_invalid_test
	invalid_reply_parse_tests[] = {
	{
		.reply = "22X OK\r\n"
	},{
		.reply = "220OK\r\n"
	},{
		.reply =
			"200-This is\r\n"
			"250 inconsistent.\r\n"
	},{
		.reply = "400 This \r is wrong\r\n"
	},{
		.reply = "500 This is \x03 worse\r\n"
	},{
		.reply = "699 Obscure\r\n"
	},{
		.reply = "100 Invalid\r\n"
	},{
		.reply = "400 Interrupted\r"
	},{
		.reply = "251 example.com We got '\x04'\r\n",
		.ehlo = TRUE
	},{
		.reply =
			"250-example.com Hello\r\n"
			"250 We got some '\x08' for you\r\n",
		.ehlo = TRUE
	},{
		.reply =
			"556-This is a very long reply\r\n"
			"556 that exceeds the very low limit.\r\n",
		.max_size = 50
	}
};

unsigned int invalid_reply_parse_test_count =
	N_ELEMENTS(invalid_reply_parse_tests);

static void test_smtp_reply_parse_invalid(void)
{
	unsigned int i;

	for (i = 0; i < invalid_reply_parse_test_count; i++) T_BEGIN {
		const struct smtp_reply_parse_invalid_test *test;
		struct istream *input;
		struct smtp_reply_parser *parser;
		struct smtp_reply *reply;
		const char *reply_text, *error;
		int ret;

		test = &invalid_reply_parse_tests[i];
		reply_text = test->reply;
		input = i_stream_create_from_data(reply_text, strlen(reply_text));
		parser = smtp_reply_parser_init(input, test->max_size);
		i_stream_unref(&input);

		test_begin(t_strdup_printf("smtp reply invalid [%d]", i));

		if (test->ehlo)
			while ((ret=smtp_reply_parse_ehlo(parser, &reply, &error)) > 0);
		else
			while ((ret=smtp_reply_parse_next(parser, FALSE, &reply, &error)) > 0);
		test_out_reason(t_strdup_printf("parse(\"%s\")",
			str_sanitize(reply_text, 80)), ret < 0, error);
		test_end();
		smtp_reply_parser_deinit(&parser);
	} T_END;
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_smtp_reply_parse_valid,
		test_smtp_reply_parse_invalid,
		NULL
	};
	return test_run(test_functions);
}
