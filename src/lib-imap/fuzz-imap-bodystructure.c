/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "fuzzer.h"
#include "imap-bodystructure.c"
#include <ctype.h>

static const char *str_sanitize_binary(const char *input)
{
	string_t *dest = t_str_new(strlen(input));
	for (;*input != '\0';input++) {
		if (i_isprint(*input) == 0)
			str_printfa(dest, "<%02x>", (unsigned char)*input);
		else
			str_append_c(dest, *input);
	}
	return str_c(dest);
}

FUZZ_BEGIN_STR(const char *str)
{
	pool_t pool =
		pool_alloconly_create(MEMPOOL_GROWING"fuzz bodystructure", 1024);
	struct message_part parts;
	string_t *dest = str_new(pool, 32);
	const char *error ATTR_UNUSED;
	i_zero(&parts);

	if (imap_bodystructure_parse(str, pool, &parts, &error) == 0) {
		if (imap_bodystructure_write(&parts, dest, TRUE, &error) < 0)
			i_panic("Failed to write bodystructure: %s", error);
		/* The written bodystructure must be parseable *and*
		   it must come out exactly the same again */
		if (imap_bodystructure_parse(str_c(dest), pool, &parts, &error) != 0) {
			i_panic("Failed to reparse bodystructure '%s'",
				str_sanitize_binary(str_c(dest)));
		} else {
			const char *new_str = t_strdup(str_c(dest));
			str_truncate(dest, 0);
			if (imap_bodystructure_write(&parts, dest, TRUE, &error) < 0)
				i_panic("Failed to write reparsed bodystructure: %s", error);
			if (strcmp(str_c(dest), new_str) != 0) {
				i_panic("Parsed bodystructure '%s' does not match '%s'",
					str_sanitize_binary(new_str),
					str_sanitize_binary(str_c(dest)));
			}
		}
	}
	pool_unref(&pool);
}
FUZZ_END
