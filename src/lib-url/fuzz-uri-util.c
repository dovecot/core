/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "fuzzer.h"
#include "uri-util.h"

FUZZ_BEGIN_STR(const char *input)
{
	T_BEGIN {
		const char *error ATTR_UNUSED;
		(void)uri_check(input, URI_PARSE_ALLOW_FRAGMENT_PART, &error);
	} T_END;
}
FUZZ_END
