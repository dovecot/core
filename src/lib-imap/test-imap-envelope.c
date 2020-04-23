/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "message-part-data.h"
#include "message-parser.h"
#include "imap-envelope.h"
#include "test-common.h"

struct parse_test {
	const char *message;
	const char *envelope;
};

struct parse_test parse_tests[] = {
	/* Tests copied from imaptest */
	{
		.message =
			"Message-ID: <msg@id>\n"
			"In-Reply-To: <reply@to.id>\n"
			"Date: Thu, 15 Feb 2007 01:02:03 +0200\n"
			"Subject: subject header\n"
			"From: From Real <fromuser@fromdomain.org>\n"
			"To: To Real <touser@todomain.org>\n"
			"Cc: Cc Real <ccuser@ccdomain.org>\n"
			"Bcc: Bcc Real <bccuser@bccdomain.org>\n"
			"Sender: Sender Real <senderuser@senderdomain.org>\n"
			"Reply-To: ReplyTo Real <replytouser@replytodomain.org>\n"
			"\n"
			"body\n",
		.envelope =
			"\"Thu, 15 Feb 2007 01:02:03 +0200\" "
				"\"subject header\" "
				"((\"From Real\" NIL \"fromuser\" \"fromdomain.org\")) "
				"((\"Sender Real\" NIL \"senderuser\" \"senderdomain.org\")) "
				"((\"ReplyTo Real\" NIL \"replytouser\" \"replytodomain.org\")) "
				"((\"To Real\" NIL \"touser\" \"todomain.org\")) "
				"((\"Cc Real\" NIL \"ccuser\" \"ccdomain.org\")) "
				"((\"Bcc Real\" NIL \"bccuser\" \"bccdomain.org\")) "
				"\"<reply@to.id>\" \"<msg@id>\""
	}, {
		.message =
			"Date: Thu, 15 Feb 2007 01:02:03 +0200\n"
			"From: user@domain\n"
			"\n"
			"body\n",
		.envelope =
			"\"Thu, 15 Feb 2007 01:02:03 +0200\" NIL "
				"((NIL NIL \"user\" \"domain\")) "
				"((NIL NIL \"user\" \"domain\")) "
				"((NIL NIL \"user\" \"domain\")) NIL NIL NIL NIL NIL"
	}, {
		.message =
			"Date: Thu, 15 Feb 2007 01:02:03 +0200\n"
			"From: user@domain\n"
			"\n"
			"body\n",
		.envelope =
			"\"Thu, 15 Feb 2007 01:02:03 +0200\" NIL "
				"((NIL NIL \"user\" \"domain\")) "
				"((NIL NIL \"user\" \"domain\")) "
				"((NIL NIL \"user\" \"domain\")) NIL NIL NIL NIL NIL"
	}, {
		.message =
			"Date: Thu, 15 Feb 2007 01:02:03 +0200\n"
			"From: user@domain (Real Name)\n"
			"To: group: g1@d1.org, g2@d2.org;, group2: g3@d3.org;\n"
			"Cc: group:;, group2: (foo) ;\n"
			"\n"
			"body\n",
		.envelope =
			"\"Thu, 15 Feb 2007 01:02:03 +0200\" NIL "
				"((\"Real Name\" NIL \"user\" \"domain\")) "
				"((\"Real Name\" NIL \"user\" \"domain\")) "
				"((\"Real Name\" NIL \"user\" \"domain\")) "
				"((NIL NIL \"group\" NIL)"
						"(NIL NIL \"g1\" \"d1.org\")"
						"(NIL NIL \"g2\" \"d2.org\")"
						"(NIL NIL NIL NIL)"
					"(NIL NIL \"group2\" NIL)"
						"(NIL NIL \"g3\" \"d3.org\")"
						"(NIL NIL NIL NIL)) "
				"((NIL NIL \"group\" NIL)(NIL NIL NIL NIL)"
					"(NIL NIL \"group2\" NIL)(NIL NIL NIL NIL)) "
				"NIL NIL NIL"
	}, {
		.message =
			"Date: Thu, 15 Feb 2007 01:02:03 +0200\n"
			"From: user@domain (Real Name)\n"
			"Sender: \n"
			"Reply-To: \n"
			"\n"
			"body\n",
		.envelope =
			"\"Thu, 15 Feb 2007 01:02:03 +0200\" NIL "
				"((\"Real Name\" NIL \"user\" \"domain\")) "
				"((\"Real Name\" NIL \"user\" \"domain\")) "
				"((\"Real Name\" NIL \"user\" \"domain\")) "
				"NIL NIL NIL NIL NIL"
	}, {
		.message =
			"Date: Thu, 15 Feb 2007 01:02:03 +0200\n"
			"From: <@route:user@domain>\n"
			"\n"
			"body\n",
		.envelope =
			"\"Thu, 15 Feb 2007 01:02:03 +0200\" NIL "
				"((NIL \"@route\" \"user\" \"domain\")) "
				"((NIL \"@route\" \"user\" \"domain\")) "
				"((NIL \"@route\" \"user\" \"domain\")) "
				"NIL NIL NIL NIL NIL"
	}
};

static const unsigned int parse_tests_count = N_ELEMENTS(parse_tests);

static struct message_part_envelope *
msg_parse(pool_t pool, const char *message)
{
	const struct message_parser_settings parser_set = {
		.hdr_flags = MESSAGE_HEADER_PARSER_FLAG_SKIP_INITIAL_LWSP |
			MESSAGE_HEADER_PARSER_FLAG_DROP_CR,
		.flags = MESSAGE_PARSER_FLAG_SKIP_BODY_BLOCK,
	};
	struct message_parser_ctx *parser;
	struct message_part_envelope *envlp = NULL;
	struct istream *input;
	struct message_block block;
	struct message_part *parts;
	int ret;

	input = i_stream_create_from_data(message, strlen(message));
	parser = message_parser_init(pool, input, &parser_set);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) {
		i_assert(block.part->parent == NULL);
		message_part_envelope_parse_from_header(pool, &envlp, block.hdr);
	}
	test_assert(ret < 0);

	message_parser_deinit(&parser, &parts);
	i_stream_unref(&input);
	return envlp;
}

static void test_imap_envelope_write(void)
{
	struct message_part_envelope *envlp;
	unsigned int i;

	for (i = 0; i < parse_tests_count; i++) T_BEGIN {
		struct parse_test *test = &parse_tests[i];
		string_t *str = t_str_new(128);
		pool_t pool = pool_alloconly_create("imap envelope write", 1024);

		test_begin(t_strdup_printf("imap envelope write [%u]", i));
		envlp = msg_parse(pool, test->message);

		imap_envelope_write(envlp, str);
		test_assert(strcmp(str_c(str), test->envelope) == 0);

		pool_unref(&pool);
		test_end();
	} T_END;
}

static void test_imap_envelope_parse(void)
{
	struct message_part_envelope *envlp;
	const char *error;
	unsigned int i;
	bool ret;

	for (i = 0; i < parse_tests_count; i++) T_BEGIN {
		struct parse_test *test = &parse_tests[i];
		string_t *str = t_str_new(128);
		pool_t pool = pool_alloconly_create("imap envelope parse", 1024);

		test_begin(t_strdup_printf("imap envelope parser [%u]", i));

		ret = imap_envelope_parse(test->envelope, pool, &envlp, &error);
		test_assert(ret);

		if (ret) {
			str_truncate(str, 0);
			imap_envelope_write(envlp, str);
			test_assert(strcmp(str_c(str), test->envelope) == 0);
		} else {
			i_error("Invalid envelope: %s", error);
		}

		pool_unref(&pool);
		test_end();
	} T_END;
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_imap_envelope_write,
		test_imap_envelope_parse,
		NULL
	};
	return test_run(test_functions);
}
