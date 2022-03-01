/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "message-size.h"
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

static const char test_msg_with_nuls[] =
"Return-Path: <test@example.org>\n"
"Subject: Hello world\n"
"From: Test User <test@example.org>\n"
"To: Another User <test2@example.org>\n"
"Message-Id: <1.2.3.4@example>\n"
"Mime-Version: 1.0\0\n"
"Date: Sun, 23 May 2007 04:58:08 +0300\n"
"Content-Type: multipart/signed; micalg=pgp-sha1;\n"
"	protocol=\"application/pgp-signature\";\n"
"	boundary=\"=-GNQXLhuj24Pl1aCkk4/d\"\n"
"\n"
"--=-GNQXLhuj24Pl1aCkk4/d\n"
"\n"
"Content-Type: text/plain\n"
"Content-Transfer-Encoding: quoted-printable\n"
"\n"
"There was\0 a day=20\n"
"a happy=20day\n"
"\n"
"--=-GNQXLhuj24Pl1aCkk4/d\n"
"Content-Type: application/pgp-signature; name=signature.asc\n"
"\n"
"-----BEGIN PGP SIGNATURE-----\n"
"Version: GnuPG v1.2.4 (GNU/Linux)\n"
"\n"
"inva\0lid\n"
"-----END PGP SIGNATURE-----\n"
"\n"
"--=-GNQXLhuj24Pl1aCkk4/d--\n"
"\n"
"\n";

struct test_case {
	const char *test_name;
	const char *message;
	bool has_nuls;
	unsigned int body_newlines;
	unsigned int header_newlines;
	unsigned int message_len;
	unsigned int header_len;
};
static const struct test_case test_cases[] = {
	{
		.test_name = "message size",
		.message = test_msg,
		.has_nuls = FALSE,
		.body_newlines = 19,
		.header_newlines = 11,
		.message_len = sizeof(test_msg)-1,
		.header_len = 335,
	},
	{
		.test_name = "message size with nuls",
		.message = test_msg_with_nuls,
		.has_nuls = TRUE,
		.body_newlines = 20,
		.header_newlines = 11,
		.message_len = sizeof(test_msg_with_nuls)-1,
		.header_len = 336,
	},
};

static void test_message_size(void)
{
	struct istream *input;
	struct message_size body_size, header_size;
	bool has_nuls;
	bool last_cr;
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(test_cases); i++) {
		test_begin(test_cases[i].test_name);
		input = i_stream_create_from_data(test_cases[i].message,
						  test_cases[i].message_len);

		/* Read physical_size */
		message_get_header_size(input, &header_size, &has_nuls);
		test_assert_idx(has_nuls == test_cases[i].has_nuls, i);
		test_assert_idx(input->v_offset == test_cases[i].header_len, i);
		message_get_body_size(input, &body_size, &has_nuls);
		test_assert_idx(has_nuls == test_cases[i].has_nuls, i);
		test_assert_idx(input->v_offset  - body_size.physical_size ==
				test_cases[i].header_len, i);
		test_assert_idx(body_size.physical_size + header_size.physical_size ==
				test_cases[i].message_len, i);

		/* Test last_cr handling */
		i_stream_seek(input, 0);
		message_skip_virtual(input, 0, &last_cr);
		test_assert_idx(!last_cr, i);
		message_skip_virtual(input, header_size.virtual_size-1, &last_cr);
		test_assert_idx(last_cr, i);
		message_skip_virtual(input, 2, &last_cr);
		test_assert_idx(!last_cr, i);

		/* Skipped header size so read body again */
		message_get_body_size(input, &body_size, &has_nuls);
		test_assert_idx(has_nuls == test_cases[i].has_nuls, i);
		test_assert_idx(input->v_offset  - body_size.physical_size ==
				test_cases[i].header_len, i);
		test_assert_idx(body_size.physical_size + test_cases[i].body_newlines ==
				body_size.virtual_size, i);
		test_assert_idx(body_size.virtual_size + header_size.virtual_size -
				test_cases[i].body_newlines - test_cases[i].header_newlines ==
				test_cases[i].message_len, i);

		i_stream_unref(&input);
		test_end();
	}
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_size,
		NULL
	};
	return test_run(test_functions);
}
