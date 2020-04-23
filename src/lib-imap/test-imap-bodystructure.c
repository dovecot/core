/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "message-part-data.h"
#include "message-parser.h"
#include "imap-bodystructure.h"
#include "test-common.h"

struct parse_test {
	const char *message;
	const char *body;
	const char *bodystructure;
};

struct parse_test parse_tests[] = {
	{
		.message =
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: text/plain; charset=us-ascii\n"
			"\n"
			"body\n",
		.bodystructure =
			"\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 1 NIL NIL NIL NIL",
		.body =
			"\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 1"
	},{
		.message =
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: text/plain; charset=utf-8\n"
			"Content-Transfer-Encoding: 8bit\n"
			"\n"
			"body\n"
			"\n",
		.bodystructure =
			"\"text\" \"plain\" (\"charset\" \"utf-8\") NIL NIL \"8bit\" 8 2 NIL NIL NIL NIL",
		.body =
			"\"text\" \"plain\" (\"charset\" \"utf-8\") NIL NIL \"8bit\" 8 2"
	},{
		.message =
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2007 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: multipart/mixed; boundary=\"foo\n"
			" bar\"\n"
			"\n"
			"--foo bar\n"
			"Content-Type: text/x-myown; charset=us-ascii\n"
			"\n"
			"hello\n"
			"\n"
			"--foo bar--\n"
			"\n",
		.bodystructure =
			"(\"text\" \"x-myown\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 7 1 NIL NIL NIL NIL) \"mixed\" (\"boundary\" \"foo bar\") NIL NIL NIL",
		.body =
			"(\"text\" \"x-myown\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 7 1) \"mixed\""
	},{
		.message =
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: multipart/mixed; boundary=\"foo bar\"\n"
			"\n"
			"--foo bar\n"
			"Content-Type: text/plain; charset=us-ascii\n"
			"\n"
			"See attached...\n"
			"\n"
			"--foo bar\n"
			"Content-Type: message/rfc822\n"
			"\n"
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: text/plain; charset=us-ascii\n"
			"\n"
			"body\n"
			"\n"
			"--foo bar--\n"
			"\n",
		.bodystructure =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 17 1 NIL NIL NIL NIL)(\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 133 (\"Sat, 24 Mar 2017 23:00:00 +0200\" NIL ((NIL NIL \"user\" \"domain.org\")) ((NIL NIL \"user\" \"domain.org\")) ((NIL NIL \"user\" \"domain.org\")) NIL NIL NIL NIL NIL) (\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 1 NIL NIL NIL NIL) 6 NIL NIL NIL NIL) \"mixed\" (\"boundary\" \"foo bar\") NIL NIL NIL",
		.body =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 17 1)(\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 133 (\"Sat, 24 Mar 2017 23:00:00 +0200\" NIL ((NIL NIL \"user\" \"domain.org\")) ((NIL NIL \"user\" \"domain.org\")) ((NIL NIL \"user\" \"domain.org\")) NIL NIL NIL NIL NIL) (\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 1) 6) \"mixed\""
	},{
		.message =
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: multipart/mixed; boundary=\"foo bar\"\n"
			"\n"
			"--foo bar\n"
			"Content-Type: text/plain; charset=us-ascii\n"
			"Content-ID: <A.frop.example.com>\n"
			"Content-Description: Container message\n"
			"\n"
			"See attached...\n"
			"\n"
			"--foo bar\n"
			"Content-Type: message/rfc822\n"
			"Content-ID: <B.frop.example.com>\n"
			"Content-Description: Forwarded\n"
			"\n"
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: text/plain; charset=us-ascii\n"
			"\n"
			"body\n"
			"\n"
			"--foo bar--\n",
		.bodystructure =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") \"<A.frop.example.com>\" \"Container message\" \"7bit\" 17 1 NIL NIL NIL NIL)(\"message\" \"rfc822\" NIL \"<B.frop.example.com>\" \"Forwarded\" \"7bit\" 133 (\"Sat, 24 Mar 2017 23:00:00 +0200\" NIL ((NIL NIL \"user\" \"domain.org\")) ((NIL NIL \"user\" \"domain.org\")) ((NIL NIL \"user\" \"domain.org\")) NIL NIL NIL NIL NIL) (\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 1 NIL NIL NIL NIL) 6 NIL NIL NIL NIL) \"mixed\" (\"boundary\" \"foo bar\") NIL NIL NIL",
		.body =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") \"<A.frop.example.com>\" \"Container message\" \"7bit\" 17 1)(\"message\" \"rfc822\" NIL \"<B.frop.example.com>\" \"Forwarded\" \"7bit\" 133 (\"Sat, 24 Mar 2017 23:00:00 +0200\" NIL ((NIL NIL \"user\" \"domain.org\")) ((NIL NIL \"user\" \"domain.org\")) ((NIL NIL \"user\" \"domain.org\")) NIL NIL NIL NIL NIL) (\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 1) 6) \"mixed\""
	},{
		.message =
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: multipart/mixed; boundary=\"foo bar\"\n"
			"\n"
			"--foo bar\n"
			"Content-Type: text/plain; charset=us-ascii; format=\"flowed\";\n"
			"  delsp=\"no\"\n"
			"Content-Language: la\n"
			"\n"
			"Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo\n"
			"ligula eget dolor. Aenean massa. Cum sociis natoque penatibus et magnis dis\n"
			"parturient montes, nascetur ridiculus mus. Donec quam felis, ultricies nec,\n"
			"pellentesque eu, pretium quis, sem. Nulla consequat massa quis enim. Donec\n"
			"pede justo, fringilla vel, aliquet nec, vulputate eget, arcu. In enim justo,\n"
			"rhoncus ut, imperdiet a, venenatis vitae, justo. Nullam dictum felis eu pede\n"
			"mollis pretium. Integer tincidunt. Cras dapibus. Vivamus elementum semper\n"
			"nisi. Aenean vulputate eleifend tellus. Aenean leo ligula, porttitor eu,\n"
			"consequat vitae, eleifend ac, enim. Aliquam lorem ante, dapibus in, viverra\n"
			"quis, feugiat a, tellus. Phasellus viverra nulla ut metus varius laoreet.\n"
			"Quisque rutrum. Aenean imperdiet. Etiam ultricies nisi vel augue. Curabitur\n"
			"ullamcorper ultricies nisi. Nam eget dui.\n"
			"\n"
			"--foo bar\n"
			"Content-Type: image/png\n"
			"Content-Transfer-Encoding: base64\n"
			"Content-Disposition: attachment; filename=\"pigeon.png\"\n"
			"\n"
			"iVBORw0KGgoAAAANSUhEUgAAAB8AAAAfCAYAAAAfrhY5AAAABHNCSVQICAgIfAhkiAAAAAlwSFlz\n"
			"AAAGJwAABicBTVTYxwAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAN2SURB\n"
			"VEiJ7ZfdK7tvHMffZuWpKTlR1my3bTEPU0hJcsABh0QrKYUTJ5KyHCzlyPwBkpSyg1mUpB3ILYna\n"
			"lEYKcbADm4cDD7NpM2bv75HF1/az8l3fX/1+77pO7vu6rtf1/jx0X3caSeIvSfK3wP/DPykcDsNs\n"
			"NqOqqgpdXV3Y2NhIGVz6+4PJyUlcXFxAFEV4vV709fVBrVZDpVL9eTo/aGVlhXl5efT5fDw/P2c4\n"
			"HKbdbmd3dzdTIZDk6+srh4eHqdPpqNfrSZJGo5H7+/sMBoNUKpUpgUsAQCqVQq1WIxgMfgp/dXU1\n"
			"srKykJ+fD6/X+8ejHiu4wcFB2Gy2uJPq6uqwt7eXOjgAaLXahHCn05laeCKlyvmXVosnrVaLQCCA\n"
			"4uJiyOVyCIIQGyqVCoIgoKCgIDXwtLQ0HBwc4O3tDR6PB263G263G8fHx1hbW4Pb7cbNzQ1yc3Nj\n"
			"hxEEAdXV1WhoaEi88cfSf3h4iLXaR01MTFChUFChULCjo4M7OztxW8fn89HlcnF5eZlTU1Nsb29n\n"
			"W1sb/X5/3PlJwd/19vbG7e1tlpWVcXV19ftGJjk0NESbzRb33aeCy8zMhM/nSxgliUSCxsZGiKKI\n"
			"ra2tb9N1e3uLSCSC8fFxGAwGDAwMfC7c309TWFjI09PTpFwlis76+jo7OzspCAJNJhN3d3fpcDho\n"
			"tVqpUCgYCoVIkl8Krr6+Hna7HSUlJd86+yiPx4P5+XlYLBZUVFSgv78fVqsV6enpAIC7uzt4vV5E\n"
			"IhFIJJL4zp1OJ2traxmJRL51+fLywuXlZba2trK0tJRms5mXl5c8PT3l4uIix8bG2NbWRqVSyfLy\n"
			"cvb09PDw8DC2Po38eocbGRlBIBDA9PQ0pNKv3Xh2doa5uTksLCwgJycHNTU1yM3NxdHREa6vr6HR\n"
			"aKDX62NDp9MhIyPjyz5x4SQxOjoKURTR29sLmUyG7Oxs+P1+WCwW7O7uQiKRQKvVQq/Xo7KyMgaS\n"
			"y+VJpyou/F0nJydYWlqCy+XC1dUV7u/vYTQa8fT0BIfDgaWlpaRBcZVsFc/OznJsbIwkaTKZODMz\n"
			"k+zShEr6Arm5uYnm5mYAgCiKaGlp+ZnrZJ1Ho1EWFRXx+fmZj4+P1Gg0P3ZNJqj2dxkMhth3PBAI\n"
			"QCaTIRqNIhQKoamp6cc5/0d4qvXv+mn4z8B/AV1UVu6zi+zUAAAAAElFTkSuQmCC\n"
			"--foo bar--\n",
		.bodystructure =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\" \"format\" \"flowed\" \"delsp\" \"no\") NIL NIL \"7bit\" 881 12 NIL NIL (\"la\") NIL)(\"image\" \"png\" NIL NIL NIL \"base64\" 1390 NIL (\"attachment\" (\"filename\" \"pigeon.png\")) NIL NIL) \"mixed\" (\"boundary\" \"foo bar\") NIL NIL NIL",
		.body =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\" \"format\" \"flowed\" \"delsp\" \"no\") NIL NIL \"7bit\" 881 12)(\"image\" \"png\" NIL NIL NIL \"base64\" 1390) \"mixed\""
	},{
		.message =
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2007 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: multipart/mixed; boundary=\"foo\n"
			" bar\"\n"
			"\n"
			"Root MIME prologue\n"
			"\n"
			"--foo bar\n"
			"Content-Type: text/x-myown; charset=us-ascii; foo=\"quoted\\\"string\"\n"
			"Content-ID: <foo@example.com>\n"
			"Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==\n"
			"Content-Disposition: inline; foo=bar\n"
			"Content-Description: hellodescription\n"
			"Content-Language: en, fi, se\n"
			"Content-Location: http://example.com/test.txt\n"
			"\n"
			"hello\n"
			"\n"
			"--foo bar\n"
			"Content-Type: message/rfc822\n"
			"\n"
			"From: sub@domain.org\n"
			"To: sub-to1@domain.org, sub-to2@domain.org\n"
			"Date: Sun, 12 Aug 2012 12:34:56 +0300\n"
			"Subject: submsg\n"
			"Content-Type: multipart/alternative; boundary=\"sub1\"\n"
			"\n"
			"Sub MIME prologue\n"
			"--sub1\n"
			"Content-Type: text/html\n"
			"Content-Transfer-Encoding: 8bit\n"
			"\n"
			"<p>Hello world</p>\n"
			"\n"
			"--sub1\n"
			"Content-Type: text/plain\n"
			"Content-Transfer-Encoding: ?invalid\n"
			"\n"
			"Hello another world\n"
			"\n"
			"--sub1--\n"
			"Sub MIME epilogue\n"
			"\n"
			"--foo bar--\n"
			"Root MIME epilogue\n",
		.bodystructure =
			"(\"text\" \"x-myown\" (\"charset\" \"us-ascii\" \"foo\" \"quoted\\\"string\") \"<foo@example.com>\" \"hellodescription\" \"7bit\" 7 1 \"Q2hlY2sgSW50ZWdyaXR5IQ==\" (\"inline\" (\"foo\" \"bar\")) (\"en\" \"fi\" \"se\") \"http://example.com/test.txt\")(\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 412 (\"Sun, 12 Aug 2012 12:34:56 +0300\" \"submsg\" ((NIL NIL \"sub\" \"domain.org\")) ((NIL NIL \"sub\" \"domain.org\")) ((NIL NIL \"sub\" \"domain.org\")) ((NIL NIL \"sub-to1\" \"domain.org\")(NIL NIL \"sub-to2\" \"domain.org\")) NIL NIL NIL NIL) ((\"text\" \"html\" (\"charset\" \"us-ascii\") NIL NIL \"8bit\" 20 1 NIL NIL NIL NIL)(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 21 1 NIL NIL NIL NIL) \"alternative\" (\"boundary\" \"sub1\") NIL NIL NIL) 21 NIL NIL NIL NIL) \"mixed\" (\"boundary\" \"foo bar\") NIL NIL NIL",
		.body =
			"(\"text\" \"x-myown\" (\"charset\" \"us-ascii\" \"foo\" \"quoted\\\"string\") \"<foo@example.com>\" \"hellodescription\" \"7bit\" 7 1)(\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 412 (\"Sun, 12 Aug 2012 12:34:56 +0300\" \"submsg\" ((NIL NIL \"sub\" \"domain.org\")) ((NIL NIL \"sub\" \"domain.org\")) ((NIL NIL \"sub\" \"domain.org\")) ((NIL NIL \"sub-to1\" \"domain.org\")(NIL NIL \"sub-to2\" \"domain.org\")) NIL NIL NIL NIL) ((\"text\" \"html\" (\"charset\" \"us-ascii\") NIL NIL \"8bit\" 20 1)(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 21 1) \"alternative\") 21) \"mixed\""
	},{
		.message =
			"Content-Type: multipart/mixed; boundary=\"foo\"\n"
			"\n",
		.bodystructure =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 0 0 NIL NIL NIL NIL) \"mixed\" (\"boundary\" \"foo\") NIL NIL NIL",
		.body =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 0 0) \"mixed\""

	}
};

static const unsigned int parse_tests_count = N_ELEMENTS(parse_tests);

struct normalize_test {
	const char *message;
	const char *input;
	const char *output;
};

struct normalize_test normalize_tests[] = {
	{
		.message =
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: text/plain; charset=us-ascii\n"
			"\n"
			"body\n",
		.input =
			"\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 1",
		.output =
			"\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 1 NIL NIL NIL NIL",
	}, {
		.message =
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: text/plain; charset=us-ascii\n"
			"Content-MD5: ae6ba5b4c6eb1efd4a9fac3708046cbe\n"
			"\n"
			"body\n",
		.input =
			"\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 1 \"ae6ba5b4c6eb1efd4a9fac3708046cbe\"",
		.output =
			"\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 1 \"ae6ba5b4c6eb1efd4a9fac3708046cbe\" NIL NIL NIL",
	}, {
		.message =
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: multipart/mixed; boundary=\"foo bar\"\n"
			"\n"
			"--foo bar\n"
			"Content-Type: text/plain; charset=us-ascii\n"
			"\n"
			"See attached...\n"
			"\n"
			"--foo bar\n"
			"Content-Type: message/rfc822\n"
			"\n"
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: text/plain; charset=us-ascii\n"
			"\n"
			"body\n"
			"\n"
			"--foo bar--\n"
			"\n",
		.input =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 17 1)(\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 133 (\"Sat, 24 Mar 2017 23:00:00 +0200\" NIL ((NIL NIL \"user\" \"domain.org\")) ((NIL NIL \"user\" \"domain.org\")) ((NIL NIL \"user\" \"domain.org\")) NIL NIL NIL NIL NIL) (\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 1) 6) \"mixed\"",
		.output =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 17 1 NIL NIL NIL NIL)(\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 133 (\"Sat, 24 Mar 2017 23:00:00 +0200\" NIL ((NIL NIL \"user\" \"domain.org\")) ((NIL NIL \"user\" \"domain.org\")) ((NIL NIL \"user\" \"domain.org\")) NIL NIL NIL NIL NIL) (\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 1 NIL NIL NIL NIL) 6 NIL NIL NIL NIL) \"mixed\" NIL NIL NIL NIL"
	}, {
		.message =
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: multipart/mixed; boundary=\"foo bar\"\n"
			"\n"
			"--foo bar\n"
			"Content-Type: text/plain; charset=us-ascii\n"
			"\n"
			"See attached...\n"
			"\n"
			"--foo bar--\n"
			"\n",
		.input =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 17 1) \"mixed\" (\"boundary\" \"foo bar\")",
		.output =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 17 1 NIL NIL NIL NIL) \"mixed\" (\"boundary\" \"foo bar\") NIL NIL NIL"
	}, {
		.message =
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: multipart/mixed; boundary=\"foo bar\"\n"
			"\n"
			"--foo bar\n"
			"Content-Type: text/plain; charset=us-ascii\n"
			"Content-MD5: 6537bae18ed07779c9dc25f24635b0f3\n"
			"\n"
			"See attached...\n"
			"\n"
			"--foo bar--\n"
			"\n",
		.input =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 17 1 \"6537bae18ed07779c9dc25f24635b0f3\") \"mixed\" (\"boundary\" \"foo bar\")",
		.output =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 17 1 \"6537bae18ed07779c9dc25f24635b0f3\" NIL NIL NIL) \"mixed\" (\"boundary\" \"foo bar\") NIL NIL NIL"
	}, {
		.message =
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: multipart/mixed; boundary=\"foo bar\"\n"
			"\n"
			"--foo bar\n"
			"Content-Type: text/plain; charset=us-ascii\n"
			"Content-Language: en\n"
			"\n"
			"See attached...\n"
			"\n"
			"--foo bar--\n"
			"\n",
		.input =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 17 1 NIL NIL \"en\") \"mixed\" (\"boundary\" \"foo bar\")",
		.output =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 17 1 NIL NIL (\"en\") NIL) \"mixed\" (\"boundary\" \"foo bar\") NIL NIL NIL"
	}, {
		.message =
			"From: user@domain.org\n"
			"Date: Sat, 24 Mar 2017 23:00:00 +0200\n"
			"Mime-Version: 1.0\n"
			"Content-Type: multipart/mixed; boundary=\"foo bar\"\n"
			"\n"
			"--foo bar\n"
			"Content-Type: text/plain; charset=us-ascii\n"
			"Content-Location: http://www.example.com/frop.txt\n"
			"\n"
			"See attached...\n"
			"\n"
			"--foo bar--\n"
			"\n",
		.input =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 17 1 NIL NIL NIL \"http://www.example.com/frop.txt\") \"mixed\" (\"boundary\" \"foo bar\")",
		.output =
			"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 17 1 NIL NIL NIL \"http://www.example.com/frop.txt\") \"mixed\" (\"boundary\" \"foo bar\") NIL NIL NIL"
	}
};

static const unsigned int normalize_tests_count = N_ELEMENTS(normalize_tests);

static struct message_part *
msg_parse(pool_t pool, const char *message, bool parse_bodystructure)
{
	const struct message_parser_settings parser_set = {
		.hdr_flags = MESSAGE_HEADER_PARSER_FLAG_SKIP_INITIAL_LWSP |
			MESSAGE_HEADER_PARSER_FLAG_DROP_CR,
		.flags = MESSAGE_PARSER_FLAG_SKIP_BODY_BLOCK,
	};
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_block block;
	struct message_part *parts;
	int ret;

	input = i_stream_create_from_data(message, strlen(message));
	parser = message_parser_init(pool, input, &parser_set);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) {
		if (parse_bodystructure) {
			message_part_data_parse_from_header(pool, block.part,
							block.hdr);
		}
	}
	test_assert(ret < 0);

	message_parser_deinit(&parser, &parts);
	i_stream_unref(&input);
	return parts;
}

static void test_imap_bodystructure_write(void)
{
	struct message_part *parts;
	unsigned int i;

	for (i = 0; i < parse_tests_count; i++) T_BEGIN {
		struct parse_test *test = &parse_tests[i];
		string_t *str = t_str_new(128);
		pool_t pool = pool_alloconly_create("imap bodystructure write", 1024);

		test_begin(t_strdup_printf("imap bodystructure write [%u]", i));
		parts = msg_parse(pool, test->message, TRUE);

		imap_bodystructure_write(parts, str, TRUE);
		test_assert(strcmp(str_c(str), test->bodystructure) == 0);

		str_truncate(str, 0);
		imap_bodystructure_write(parts, str, FALSE);
		test_assert(strcmp(str_c(str), test->body) == 0);

		pool_unref(&pool);
		test_end();
	} T_END;
}

static void test_imap_bodystructure_parse(void)
{
	struct message_part *parts;
	const char *error;
	unsigned int i;
	int ret;

	for (i = 0; i < parse_tests_count; i++) T_BEGIN {
		struct parse_test *test = &parse_tests[i];
		string_t *str = t_str_new(128);
		pool_t pool = pool_alloconly_create("imap bodystructure parse", 1024);

		test_begin(t_strdup_printf("imap bodystructure parser [%u]", i));
		parts = msg_parse(pool, test->message, FALSE);

		test_assert(imap_body_parse_from_bodystructure(test->bodystructure,
								     str, &error) == 0);
		test_assert(strcmp(str_c(str), test->body) == 0);

		ret = imap_bodystructure_parse(test->bodystructure,
							   pool, parts, &error);
		test_assert(ret == 0);

		if (ret == 0) {
			str_truncate(str, 0);
			imap_bodystructure_write(parts, str, TRUE);
			test_assert(strcmp(str_c(str), test->bodystructure) == 0);
		} else {
			i_error("Invalid BODYSTRUCTURE: %s", error);
		}

		pool_unref(&pool);
		test_end();
	} T_END;
}

static void test_imap_bodystructure_parse_full(void)
{
	const char *error;
	unsigned int i;
	int ret;

	for (i = 0; i < parse_tests_count; i++) T_BEGIN {
		struct parse_test *test = &parse_tests[i];
		struct message_part *parts = NULL;
		string_t *str = t_str_new(128);
		pool_t pool = pool_alloconly_create("imap bodystructure parse full", 1024);

		test_begin(t_strdup_printf("imap bodystructure parser full [%u]", i));

		ret = imap_bodystructure_parse_full(test->bodystructure,
							   pool, &parts, &error);
		test_assert(ret == 0);

		if (ret == 0) {
			str_truncate(str, 0);
			imap_bodystructure_write(parts, str, TRUE);
			test_assert(strcmp(str_c(str), test->bodystructure) == 0);
		} else {
			i_error("Invalid BODYSTRUCTURE: %s", error);
		}

		pool_unref(&pool);
		test_end();
	} T_END;
}

static void test_imap_bodystructure_normalize(void)
{
	struct message_part *parts;
	const char *error;
	unsigned int i;
	int ret;

	for (i = 0; i < normalize_tests_count; i++) T_BEGIN {
		struct normalize_test *test = &normalize_tests[i];
		string_t *str = t_str_new(128);
		pool_t pool = pool_alloconly_create("imap bodystructure parse", 1024);

		test_begin(t_strdup_printf("imap bodystructure normalize [%u]", i));
		parts = msg_parse(pool, test->message, FALSE);

		ret = imap_bodystructure_parse(test->input,
							   pool, parts, &error);
		test_assert(ret == 0);

		if (ret == 0) {
			str_truncate(str, 0);
			imap_bodystructure_write(parts, str, TRUE);
			test_assert(strcmp(str_c(str), test->output) == 0);
		} else {
			i_error("Invalid BODYSTRUCTURE: %s", error);
		}

		pool_unref(&pool);
		test_end();
	} T_END;
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_imap_bodystructure_write,
		test_imap_bodystructure_parse,
		test_imap_bodystructure_normalize,
		test_imap_bodystructure_parse_full,
		NULL
	};
	return test_run(test_functions);
}
