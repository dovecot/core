/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "fuzzer.h"

#include "json-pointer.h"

FUZZ_BEGIN_STR(const char *input)
{
	struct json_pointer *pointer = NULL;
	const char *error ATTR_UNUSED;

	if (json_pointer_create(input, &pointer, &error) == 0)
		json_pointer_free(&pointer);
	if (json_pointer_create_uri_fragment(input, &pointer, &error) == 0)
		json_pointer_free(&pointer);
}
FUZZ_END
