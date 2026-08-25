/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "fuzzer.h"
#include "http-url.h"

FUZZ_BEGIN_STR(const char *input)
{
	T_BEGIN {
		const char *error ATTR_UNUSED;
		pool_t pool = pool_datastack_create();
		struct http_url *url;
		(void)http_url_parse(input, NULL,
				      HTTP_URL_ALLOW_USERINFO_PART |
				      HTTP_URL_ALLOW_FRAGMENT_PART,
				      pool, &url, &error);
	} T_END;
}
FUZZ_END
