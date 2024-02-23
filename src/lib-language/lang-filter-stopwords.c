/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "strfuncs.h"
#include "hash.h"
#include "unichar.h"
#include "language.h"
#include "lang-filter-private.h"
#include "lang-settings.h"

#define STOPWORDS_FILE_FORMAT "%s/stopwords_%s.txt"

#define STOPWORDS_CUTCHARS "|#\t "
#define STOPWORDS_DISALLOWED_CHARS "/\\<>.,\":()\t\n\r"

struct lang_filter_stopwords {
	struct lang_filter filter;
	struct language *lang;
	pool_t pool;
	HASH_TABLE(const char *, const char *) stopwords;
	const char *stopwords_dir;
};

static int lang_filter_stopwords_read_list(struct lang_filter_stopwords *filter,
					   const char **error_r)
{
	struct istream *input;
	const char *line, *word, *path;
	int ret = 0;
	size_t len;

	path = t_strdup_printf(STOPWORDS_FILE_FORMAT,
			       filter->stopwords_dir, filter->lang->name);

	input = i_stream_create_file(path, IO_BLOCK_SIZE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		len = strcspn(line, STOPWORDS_CUTCHARS);
		if (len == 0)
			continue;
		if (strcspn(line, STOPWORDS_DISALLOWED_CHARS) < len)
			continue;
		word = p_strndup(filter->pool, line, len);
		hash_table_update(filter->stopwords, word, word);
	}

	if (input->stream_errno != 0) {
		*error_r = t_strdup_printf("Failed to read stopword list %s: %s",
					   path, i_stream_get_error(input));
		ret = -1;
	}

	if (ret == 0 && hash_table_count(filter->stopwords) == 0) {
		*error_r = t_strdup_printf("Stopwords list \"%s\" seems empty. "
					   "Is the file correctly formatted?",
					   path);
		ret = -1;
	}

	i_stream_destroy(&input);
	return ret;
}

static void lang_filter_stopwords_destroy(struct lang_filter *filter)
{
	struct lang_filter_stopwords *sp = (struct lang_filter_stopwords *)filter;

	hash_table_destroy(&sp->stopwords);
	pool_unref(&sp->pool);
}

static int
lang_filter_stopwords_create(const struct lang_settings *set,
			     struct event *event ATTR_UNUSED,
                             struct lang_filter **filter_r,
                             const char **error_r ATTR_UNUSED)
{
	struct lang_filter_stopwords *sp;
	pool_t pp;

	pp = pool_alloconly_create(MEMPOOL_GROWING"lang_filter_stopwords",
	                           sizeof(struct lang_filter));
	sp = p_new(pp, struct lang_filter_stopwords, 1);
	sp->filter = *lang_filter_stopwords;
	sp->pool = pp;
	sp->lang = p_malloc(sp->pool, sizeof(struct language));
	sp->lang->name = set->name;
	sp->stopwords_dir = set->filter_stopwords_dir;
	*filter_r = &sp->filter;
	return 0;
}

static int
lang_filter_stopwords_filter(struct lang_filter *filter, const char **token,
			     const char **error_r)
{
	struct lang_filter_stopwords *sp =
		(struct lang_filter_stopwords *) filter;

	if (!hash_table_is_created(sp->stopwords)) {
		hash_table_create(&sp->stopwords, sp->pool, 0, str_hash, strcmp);
		if (lang_filter_stopwords_read_list(sp, error_r) < 0)
			return -1;
	}
	return hash_table_lookup(sp->stopwords, *token) == NULL ? 1 : 0;
}

const struct lang_filter lang_filter_stopwords_real = {
	.class_name = "stopwords",
	.v = {
		lang_filter_stopwords_create,
		lang_filter_stopwords_filter,
		lang_filter_stopwords_destroy
	}
};
const struct lang_filter *lang_filter_stopwords = &lang_filter_stopwords_real;
