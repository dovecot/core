/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "fuzzer.h"
#include "imap-utf7.h"

FUZZ_BEGIN_STR(const char *str)
{
	string_t *dest = t_str_new(32);

	imap_utf8_to_utf7(str, dest);
	imap_utf7_to_utf8(str, dest);
}
FUZZ_END
