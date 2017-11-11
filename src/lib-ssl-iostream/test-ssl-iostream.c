/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "iostream-openssl.h"

#include <stdio.h>

#ifdef HAVE_SSL_CTX_SET_MIN_PROTO_VERSION

struct test {
	/* ssl_protocols input */
	const char *s;
	/* expected output */
	int min;
	int ret;
};

static const struct test tests[] = {
	{ "!TLSv1 !TLSv1.2", SSL3_VERSION, 0 },
	{ "!SSLv3", TLS1_VERSION, 0 },
	{ "SSLv3", SSL3_VERSION, 0 },
	{ "!SSLv3 !TLSv1 !TLSv1.2", TLS1_1_VERSION, 0 },
	{ "!SSLv3 !TLSv1 !TLSv1.1 !TLSv1.2", 0, -1},
	{ "TLSv1.1 TLSv1.2", TLS1_1_VERSION, 0 },
	{ "TLSv1.1", TLS1_1_VERSION, 0 },
	{ "TLSv1.1 !SSLv3", TLS1_1_VERSION, 0 },
	{ "TLSv1.2 !TLSv1.1", TLS1_2_VERSION, 0 },
};

static
void test_ssl_protocols_to_min_protocol(void)
{
	test_begin("test_ssl_protocols_to_min_protocol");
	for (unsigned i = 0; i < N_ELEMENTS(tests); ++i) {
		const struct test *t = &tests[i];
		const char *error;
		int min, ret;
		ret = ssl_protocols_to_min_protocol(t->s, &min, &error);
		if (ret >= 0 && t->min != min)
			i_debug("%s (exp,actual): min(%d,%d) ret(%d,%d)",
				t->s, t->min, min, t->ret, ret);
		test_assert_idx(t->ret == ret, i);
		if (ret < 0)
			continue;
		test_assert_idx(t->min == min, i);
	}
	test_end();
}

int main(void) {
	static void (*test_functions[])(void) = {
		test_ssl_protocols_to_min_protocol,
		NULL,
	};
	return test_run(test_functions);
}

#else /* HAVE_SSL_CTX_SET_MIN_PROTO_VERSION */
int main(void) {
	return 0;
}
#endif /* HAVE_SSL_CTX_SET_MIN_PROTO_VERSION */
