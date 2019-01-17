/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "strfuncs.h"
#include "hash.h"
#include "unichar.h"
#include "fts-language.h"
#include "fts-filter-private.h"

#define STOPWORDS_FILE_FORMAT "%s/stopwords_%s.txt"

#define STOPWORDS_CUTCHARS "|#\t "
#define STOPWORDS_DISALLOWED_CHARS "/\\<>.,\":()\t\n\r"

struct fts_filter_stopwords {
	struct fts_filter filter;
	struct fts_language *lang;
	pool_t pool;
	HASH_TABLE(const char *, const char *) stopwords;
	const char *stopwords_dir;
};

static int fts_filter_stopwords_read_list(struct fts_filter_stopwords *filter,
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

	if (ret == 0 && hash_table_count(filter->stopwords) == 0)
		i_warning("Stopwords list \"%s\" seems empty. Is the file correctly formatted?", path);

	i_stream_destroy(&input);
	return ret;
}

static void fts_filter_stopwords_destroy(struct fts_filter *filter)
{
	struct fts_filter_stopwords *sp = (struct fts_filter_stopwords *)filter;

	hash_table_destroy(&sp->stopwords);
	pool_unref(&sp->pool);
}

static int
fts_filter_stopwords_create(const struct fts_language *lang,
                            const char *const *settings,
                            struct fts_filter **filter_r,
                            const char **error_r)
{
	struct fts_filter_stopwords *sp;
	pool_t pp;
	const char *dir = NULL;
	unsigned int i;

	for (i = 0; settings[i] != NULL; i += 2) {
		const char *key = settings[i], *value = settings[i+1];

		if (strcmp(key, "stopwords_dir") == 0) {
			dir = value;
		} else {
			*error_r = t_strdup_printf("Unknown setting: %s", key);
			return -1;
		}
	}
	pp = pool_alloconly_create(MEMPOOL_GROWING"fts_filter_stopwords",
	                           sizeof(struct fts_filter));
	sp = p_new(pp, struct fts_filter_stopwords, 1);
	sp->filter = *fts_filter_stopwords;
	sp->pool = pp;
	sp->lang = p_malloc(sp->pool, sizeof(struct fts_language));
	sp->lang->name = p_strdup(sp->pool, lang->name);
	if (dir != NULL)
		sp->stopwords_dir = p_strdup(pp, dir);
	else
		sp->stopwords_dir = DATADIR"/stopwords";
	*filter_r = &sp->filter;
	return 0;
}

static int
fts_filter_stopwords_filter(struct fts_filter *filter, const char **token,
			    const char **error_r)
{
	struct fts_filter_stopwords *sp =
		(struct fts_filter_stopwords *) filter;

	if (!hash_table_is_created(sp->stopwords)) {
		hash_table_create(&sp->stopwords, sp->pool, 0, str_hash, strcmp);
		if (fts_filter_stopwords_read_list(sp, error_r) < 0)
			return -1;
	}
	return hash_table_lookup(sp->stopwords, *token) == NULL ? 1 : 0;
}

const struct fts_filter fts_filter_stopwords_real = {
	.class_name = "stopwords",
	.v = {
		fts_filter_stopwords_create,
		fts_filter_stopwords_filter,
		fts_filter_stopwords_destroy
	}
};
const struct fts_filter *fts_filter_stopwords = &fts_filter_stopwords_real;
