/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fuzzer.h"
#include "var-expand.h"

FUZZ_BEGIN_STR(const char *input)
{
	struct var_expand_program *program = NULL;
	const char *error ATTR_UNUSED;
	if (var_expand_program_create(input, &program, &error) == 0)
		var_expand_program_free(&program);
}
FUZZ_END
