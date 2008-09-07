/* Copyright (c) 2007-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "rfc822-parser.h"
#include "rfc2231-parser.h"
#include "message-address.h"
#include "message-date.h"
#include "message-parser.h"
#include "istream-header-filter.h"
#include "test-common.h"

static const char test_msg[] =
"Return-Path: <test@example.org>\n"
"Subject: Hello world\n"
"From: Test User <test@example.org>\n"
"To: Another User <test2@example.org>\n"
"Message-Id: <1.2.3.4@example>\n"
"Mime-Version: 1.0\n"
"Date: Sun, 23 May 2007 04:58:08 +0300\n"
"Content-Type: multipart/signed; micalg=pgp-sha1;\n"
"	protocol=\"application/pgp-signature\";\n"
"	boundary=\"=-GNQXLhuj24Pl1aCkk4/d\"\n"
"\n"
"--=-GNQXLhuj24Pl1aCkk4/d\n"
"Content-Type: text/plain\n"
"Content-Transfer-Encoding: quoted-printable\n"
"\n"
"There was a day=20\n"
"a happy=20day\n"
"\n"
"--=-GNQXLhuj24Pl1aCkk4/d\n"
"Content-Type: application/pgp-signature; name=signature.asc\n"
"\n"
"-----BEGIN PGP SIGNATURE-----\n"
"Version: GnuPG v1.2.4 (GNU/Linux)\n"
"\n"
"invalid\n"
"-----END PGP SIGNATURE-----\n"
"\n"
"--=-GNQXLhuj24Pl1aCkk4/d--\n"
"\n"
"\n";
#define TEST_MSG_LEN (sizeof(test_msg)-1)

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
		"Fri, 13 Dec 1901 20:45:53 +0000",
#endif
#if (TIME_T_MAX_BITS > 32 || !defined(TIME_T_SIGNED))
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
		{ -2147483647, 0, TRUE },
#endif
#if (TIME_T_MAX_BITS > 32 || !defined(TIME_T_SIGNED))
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

static bool msg_parts_cmp(struct message_part *p1, struct message_part *p2)
{
	while (p1 != NULL || p2 != NULL) {
		if ((p1 != NULL) != (p2 != NULL))
			return FALSE;
		if ((p1->children != NULL) != (p2->children != NULL))
			return FALSE;

		if (p1->children) {
			if (!msg_parts_cmp(p1->children, p2->children))
				return FALSE;
		}

		if (p1->physical_pos != p2->physical_pos ||
		    p1->header_size.physical_size != p2->header_size.physical_size ||
		    p1->header_size.virtual_size != p2->header_size.virtual_size ||
		    p1->header_size.lines != p2->header_size.lines ||
		    p1->body_size.physical_size != p2->body_size.physical_size ||
		    p1->body_size.virtual_size != p2->body_size.virtual_size ||
		    p1->body_size.lines != p2->body_size.lines ||
		    p1->flags != p2->flags)
			return FALSE;

		p1 = p1->next;
		p2 = p2->next;
	}
	return TRUE;
}

static void test_message_parser(void)
{
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts, *parts2;
	struct message_block block;
	unsigned int i;
	bool success = TRUE;
	pool_t pool;
	int ret;

	pool = pool_alloconly_create("message parser", 10240);
	input = i_stream_create_from_data(test_msg, TEST_MSG_LEN);

	parser = message_parser_init(pool, input, 0, 0);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) ;
	i_assert(ret < 0);
	ret = message_parser_deinit(&parser, &parts);
	i_assert(ret == 0);
	i_stream_unref(&input);

	input = test_istream_create(test_msg);
	test_istream_set_allow_eof(input, FALSE);

	parser = message_parser_init(pool, input, 0, 0);
	for (i = 1; i <= TEST_MSG_LEN*2+1; i++) {
		test_istream_set_size(input, i/2);
		if (i > TEST_MSG_LEN*2)
			test_istream_set_allow_eof(input, TRUE);
		while ((ret = message_parser_parse_next_block(parser,
							      &block)) > 0) ;
		if (ret < 0 && i < TEST_MSG_LEN*2) {
			success = FALSE;
			break;
		}
	}
	ret = message_parser_deinit(&parser, &parts2);
	i_assert(ret == 0);
	i_stream_unref(&input);

	if (!msg_parts_cmp(parts, parts2))
		success = FALSE;

	pool_unref(&pool);
	test_out("message_parser()", success);
}

static void test_rfc2231_parser(void)
{
	const char *input =
		"; key*2=ba%"
		"; key2*0=a"
		"; key3*0*=us-ascii'en'xyz"
		"; key*0=\"foo\""
		"; key2*1*=b%25"
		"; key3*1=plop%"
		"; key*1=baz";
	const char *output[] = {
		"key",
		"foobazba%",
		"key2*",
		"''ab%25",
		"key3*",
		"us-ascii'en'xyzplop%25",
		NULL
	};
	struct rfc822_parser_context parser;
	const char *const *result;
	unsigned int i;
	bool success;

	rfc822_parser_init(&parser, (const void *)input, strlen(input), NULL);
	if (rfc2231_parse(&parser, &result) < 0)
		success = FALSE;
	else {
		success = TRUE;
		for (i = 0; output[i] != NULL && result[i] != NULL; i++) {
			if (strcmp(output[i], result[i]) != 0)
				break;
		}
		if (output[i] != NULL || result[i] != NULL)
			success = FALSE;
	}
	test_out("rfc2231_parse()", success);
}

static void filter_callback(struct message_header_line *hdr,
			    bool *matched, void *context ATTR_UNUSED)
{
	if (hdr != NULL && hdr->name_offset == 0) {
		/* drop first header */
		*matched = TRUE;
	}
}

static void test_istream_filter(void)
{
	static const char *exclude_headers[] = { "To", NULL };
	const char *input = "From: foo\nFrom: abc\nTo: bar\n\nhello world\n";
	const char *output = "From: abc\n\nhello world\n";
	struct istream *istream, *filter;
	unsigned int i, input_len = strlen(input);
	unsigned int output_len = strlen(output);
	const unsigned char *data;
	size_t size;
	ssize_t ret;
	bool success = TRUE;

	istream = test_istream_create(input);
	filter = i_stream_create_header_filter(istream,
					       HEADER_FILTER_EXCLUDE |
					       HEADER_FILTER_NO_CR,
					       exclude_headers, 1,
					       filter_callback, NULL);
	for (i = 1; i <= input_len; i++) {
		test_istream_set_size(istream, i);
		ret = i_stream_read(filter);
		if (ret < 0) {
			success = FALSE;
			break;
		}
	}
	data = i_stream_get_data(filter, &size);
	if (size != output_len || memcmp(data, output, size) != 0)
		success = FALSE;

	i_stream_skip(filter, size);
	i_stream_seek(filter, 0);
	while ((ret = i_stream_read(filter)) > 0) ;
	data = i_stream_get_data(filter, &size);
	if (size != output_len || memcmp(data, output, size) != 0)
		success = FALSE;

	i_stream_unref(&filter);
	i_stream_unref(&istream);

	test_out("i_stream_create_header_filter()", success);
}

int main(void)
{
	test_init();

	test_message_address();
	test_message_date_parse();
	test_message_parser();
	test_rfc2231_parser();
	test_istream_filter();
	return test_deinit();
}
