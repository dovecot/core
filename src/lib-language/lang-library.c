/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "language.h"
#include "lang-tokenizer.h"
#include "lang-filter.h"
#include "lang-library.h"

void fts_library_init(void)
{
	fts_languages_init();
	fts_tokenizers_init();
	fts_filters_init();
}

void fts_library_deinit(void)
{
	fts_languages_deinit();
	fts_tokenizers_deinit();
	fts_filters_deinit();
}
