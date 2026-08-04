/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "fuzzer.h"

#include "json-pointer.h"

FUZZ_BEGIN_DATA(const uint8_t *data, size_t size)
{
	struct json_pointer *pointer = NULL;
	const char *error ATTR_UNUSED;
	const char *input;

	/* String parsers expect a NUL-terminated C string. */
	input = fuzzer_t_strndup_replace_zero(data, size, '\\');
	if (json_pointer_create(input, &pointer, &error) == 0)
		json_pointer_free(&pointer);
	if (json_pointer_create_uri_fragment(input, &pointer, &error) == 0)
		json_pointer_free(&pointer);

	/* Binary parser is documented as accepting untrusted persisted
	   data - fuzz it directly on the raw bytes. */
	if (json_pointer_import(data, size, &pointer, &error) == 0)
		json_pointer_free(&pointer);
}
FUZZ_END
