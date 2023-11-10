/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "language.h"
#include "lang-tokenizer.h"
#include "lang-filter.h"
#include "lang-library.h"

void lang_library_init(void)
{
	languages_init();
	lang_tokenizers_init();
	lang_filters_init();
}

void lang_library_deinit(void)
{
	languages_deinit();
	lang_tokenizers_deinit();
	lang_filters_deinit();
}
