/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "fuzzer.h"

void fuzzer_init(void)
{
	if (!lib_is_initialized()) {
		lib_init();
		lib_signals_init();
		lib_signals_ignore(SIGPIPE, TRUE);
	}
}
