/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fuzzer.h"
#include "var-expand.h"

FUZZ_BEGIN_DATA(const void *input, size_t len)
{
	struct var_expand_program *program = NULL;
	const char *error ATTR_UNUSED = NULL;

	if (var_expand_program_import_sized(input, len, &program, &error) == 0)
		var_expand_program_free(&program);
}
FUZZ_END
