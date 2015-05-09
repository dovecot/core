/* Copyright (c) 2014-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "strfuncs.h"
#include "hash.h"
#include "unichar.h"
#include "fts-language.h"
#include "fts-filter.h"
#include "fts-filter-private.h"

#define STOPWORDS_FILE_FORMAT "%s/stopwords_%s.txt"
/* TODO: Configure special characters */
static const char stopwords_eol_comment = '|';
static const char stopwords_comment = '#';

struct fts_filter_stopwords {
	struct fts_filter filter;
	struct fts_language *lang;
	pool_t pool;
	HASH_TABLE(const char *, const char *) stopwords;
	const char *stopwords_dir;
};

/* TODO: Write this function or remove it from api. */
static bool fts_filter_stopwords_supports(const struct fts_language *lang)
{
	/* TODO: former NULL check is for unit test _fail_create() */
	if (lang == NULL || lang->name == NULL)
		return FALSE;
	return TRUE;
}

static int fts_filter_stopwords_read_list(struct fts_filter_stopwords *filter)
{
	struct istream *input;
	const char *line;
	const char **words;
	const char *list_path = NULL;
	int ret = 0;

	list_path = t_strdup_printf(STOPWORDS_FILE_FORMAT,
	                            filter->stopwords_dir, filter->lang->name);

	input = i_stream_create_file(list_path, IO_BLOCK_SIZE);
	while ((line =  i_stream_read_next_line(input)) != NULL) {

		if (uni_utf8_strlen(line) < 1)
			continue;
		if (strchr(line, stopwords_comment) != NULL)
			continue; /* TODO: support eol hashed comments */
		if (strchr(line, stopwords_eol_comment)!= NULL) {
			line = t_strcut(line, stopwords_eol_comment);
			if (line == NULL || strcmp(line, "") == 0)
			    continue;
		}
		words = t_strsplit_spaces(line, " \t");
		while (*words != NULL) {
			hash_table_insert(filter->stopwords, *words, *words);
			words++;
		}
	}
	/*
	   TODO: How to detect non-existing file?
	   TODO: istream error handling and reporting (i_error()?).
	 */
	if (input->stream_errno != 0)
		ret = -1;
	i_stream_destroy(&input);
	return ret;
}

static void fts_filter_stopwords_destroy(struct fts_filter *filter)
{
	struct fts_filter_stopwords *sp = (struct fts_filter_stopwords *)filter;
	if (hash_table_is_created(sp->stopwords))
		hash_table_destroy(&sp->stopwords);
	pool_unref(&sp->pool);
	return;
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
	sp->lang->name = str_lcase(p_strdup(sp->pool, lang->name));
	if (dir != NULL)
		sp->stopwords_dir = p_strdup(pp, dir);
	else
		sp->stopwords_dir = DATADIR"/stopwords";
	*filter_r = &sp->filter;
	return 0;
}

static int
fts_filter_stopwords_create_stopwords(struct fts_filter_stopwords *sp,
				      const char **error_r)
{
	int ret;

	hash_table_create(&sp->stopwords, sp->pool, 0, str_hash, strcmp);
	ret = fts_filter_stopwords_read_list(sp);
	if (ret < 0) {
		*error_r = t_strdup_printf("Failed to read stopword list %s",
					   sp->stopwords_dir);
	}
	return ret;
}

static int
fts_filter_stopwords_filter(struct fts_filter *filter, const char **token,
			    const char **error_r)
{
	const char *stopword;
	struct fts_filter_stopwords *sp =
		(struct fts_filter_stopwords *) filter;

	if (!hash_table_is_created(sp->stopwords))
		if (fts_filter_stopwords_create_stopwords(sp, error_r) < 0)
			return -1;
	stopword = hash_table_lookup(sp->stopwords, *token);
	if (stopword != NULL) {
		*token = NULL;
		return 0;
	}
	else
		return 1;
}

const struct fts_filter_vfuncs stopwords_filter_vfuncs = {
	fts_filter_stopwords_supports,
	fts_filter_stopwords_create,
	fts_filter_stopwords_filter,
	fts_filter_stopwords_destroy
};

const struct fts_filter fts_filter_stopwords_real = {
	.class_name = STOPWORDS_FILTER_NAME,
	.v = &stopwords_filter_vfuncs
};
const struct fts_filter *fts_filter_stopwords = &fts_filter_stopwords_real;
