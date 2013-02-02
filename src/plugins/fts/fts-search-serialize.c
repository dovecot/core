/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "mail-search.h"
#include "fts-search-serialize.h"

#define HAVE_SUBARGS(arg) \
	((arg)->type == SEARCH_SUB || (arg)->type == SEARCH_OR)

void fts_search_serialize(buffer_t *buf, const struct mail_search_arg *args)
{
	char chr;

	for (; args != NULL; args = args->next) {
		chr = (args->match_always ? 1 : 0) |
			(args->nonmatch_always ? 2 : 0);
		buffer_append_c(buf, chr);

		if (HAVE_SUBARGS(args))
			fts_search_serialize(buf, args->value.subargs);
	}
}

static void fts_search_deserialize_idx(struct mail_search_arg *args,
				       const buffer_t *buf, unsigned int *idx)
{
	const char *data = buf->data;

	for (; args != NULL; args = args->next) {
		i_assert(*idx < buf->used);

		args->match_always = (data[*idx] & 1) != 0;
		args->nonmatch_always = (data[*idx] & 2) != 0;
		args->result = args->match_always ? 1 :
			(args->nonmatch_always ? 0 : -1);
		*idx += 1;

		if (HAVE_SUBARGS(args)) {
			fts_search_deserialize_idx(args->value.subargs,
						   buf, idx);
		}
	}
}

void fts_search_deserialize(struct mail_search_arg *args,
			    const buffer_t *buf)
{
	unsigned int idx = 0;

	fts_search_deserialize_idx(args, buf, &idx);
	i_assert(idx == buf->used);
}

static void
fts_search_deserialize_add_idx(struct mail_search_arg *args,
			       const buffer_t *buf, unsigned int *idx,
			       bool matches)
{
	const char *data = buf->data;

	for (; args != NULL; args = args->next) {
		i_assert(*idx < buf->used);

		if (data[*idx] != 0) {
			if (matches) {
				args->match_always = TRUE;
				args->result = 1;
			} else {
				args->nonmatch_always = TRUE;
				args->result = 0;
			}
		}
		*idx += 1;

		if (HAVE_SUBARGS(args)) {
			fts_search_deserialize_add_idx(args->value.subargs,
						       buf, idx, matches);
		}
	}
}

void fts_search_deserialize_add_matches(struct mail_search_arg *args,
					const buffer_t *buf)
{
	unsigned int idx = 0;

	fts_search_deserialize_add_idx(args, buf, &idx, TRUE);
	i_assert(idx == buf->used);
}

void fts_search_deserialize_add_nonmatches(struct mail_search_arg *args,
					   const buffer_t *buf)
{
	unsigned int idx = 0;

	fts_search_deserialize_add_idx(args, buf, &idx, FALSE);
	i_assert(idx == buf->used);
}
