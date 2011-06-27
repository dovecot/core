/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "seq-range-array.h"
#include "mail-search.h"
#include "mail-storage-private.h"
#include "fts-api-private.h"
#include "fts-storage.h"

static void
uid_range_to_seqs(struct mailbox *box, const ARRAY_TYPE(seq_range) *uid_range,
		  ARRAY_TYPE(seq_range) *seq_range)
{
	const struct seq_range *range;
	unsigned int i, count;
	uint32_t seq1, seq2;

	range = array_get(uid_range, &count);
	i_array_init(seq_range, count);
	for (i = 0; i < count; i++) {
		mailbox_get_seq_range(box, range[i].seq1, range[i].seq2,
				      &seq1, &seq2);
		if (seq1 != 0)
			seq_range_array_add_range(seq_range, seq1, seq2);
	}
}

static void fts_uid_results_to_seq(struct fts_search_context *fctx)
{
	ARRAY_TYPE(seq_range) uid_range;

	uid_range = fctx->definite_seqs;
	uid_range_to_seqs(fctx->t->box, &uid_range, &fctx->definite_seqs);
	array_free(&uid_range);

	uid_range = fctx->maybe_seqs;
	uid_range_to_seqs(fctx->t->box, &uid_range, &fctx->maybe_seqs);
	array_free(&uid_range);
}

static int fts_search_lookup_arg(struct fts_search_context *fctx,
				 struct mail_search_arg *arg)
{
	enum fts_lookup_flags flags = 0;
	const char *key;

	switch (arg->type) {
	case SEARCH_HEADER:
	case SEARCH_HEADER_COMPRESS_LWSP:
		/* we can filter out messages that don't have the header,
		   but we can't trust definite results list. */
		flags = FTS_LOOKUP_FLAG_HEADER;
		key = arg->value.str;
		if (*key == '\0') {
			/* we're only checking the existence
			   of the header. */
			key = t_str_ucase(arg->hdr_field_name);
		}
		break;
	case SEARCH_TEXT:
		flags = FTS_LOOKUP_FLAG_HEADER;
	case SEARCH_BODY:
		flags |= FTS_LOOKUP_FLAG_BODY;
		key = arg->value.str;
		break;
	default:
		/* can't filter this */
		return 0;
	}
	if (arg->not)
		flags |= FTS_LOOKUP_FLAG_INVERT;

	if (!fctx->fbox->backend->locked &&
	    fts_backend_lock(fctx->fbox->backend) <= 0)
		return -1;

	/* note that the key is in UTF-8 decomposed titlecase */
	fctx->lookup_ctx = fts_backend_lookup_init(fctx->fbox->backend);
	fts_backend_lookup_add(fctx->lookup_ctx, key, flags);
	return 0;
}

void fts_search_lookup(struct fts_search_context *fctx)
{
	struct mail_search_arg *arg;
	int ret;

	if (fctx->best_arg == NULL)
		return;

	i_array_init(&fctx->definite_seqs, 64);
	i_array_init(&fctx->maybe_seqs, 64);
	i_array_init(&fctx->score_map, 64);

	/* start lookup with the best arg */
	T_BEGIN {
		ret = fts_search_lookup_arg(fctx, fctx->best_arg);
	} T_END;
	/* filter the rest */
	for (arg = fctx->args->args; arg != NULL && ret == 0; arg = arg->next) {
		if (arg != fctx->best_arg) {
			T_BEGIN {
				ret = fts_search_lookup_arg(fctx, arg);
			} T_END;
		}
	}

	if (fctx->fbox->backend != NULL) {
		if (fctx->lookup_ctx != NULL) {
			fts_backend_lookup_deinit(&fctx->lookup_ctx,
						  &fctx->definite_seqs,
						  &fctx->maybe_seqs,
						  &fctx->score_map);
		}
		if (fctx->fbox->backend->locked)
			fts_backend_unlock(fctx->fbox->backend);
	}

	if (ret == 0) {
		fctx->seqs_set = TRUE;
		fts_uid_results_to_seq(fctx);
	}
}

static bool arg_is_better(const struct mail_search_arg *new_arg,
			  const struct mail_search_arg *old_arg)
{
	if (old_arg == NULL)
		return TRUE;
	if (new_arg == NULL)
		return FALSE;

	/* avoid NOTs */
	if (old_arg->not && !new_arg->not)
		return TRUE;
	if (!old_arg->not && new_arg->not)
		return FALSE;

	/* prefer not to use headers. they have a larger possibility of
	   having lots of identical strings */
	if (old_arg->type == SEARCH_HEADER ||
	    old_arg->type == SEARCH_HEADER_COMPRESS_LWSP)
		return TRUE;
	else if (new_arg->type == SEARCH_HEADER ||
		 new_arg->type == SEARCH_HEADER_COMPRESS_LWSP)
		return FALSE;

	return strlen(new_arg->value.str) > strlen(old_arg->value.str);
}

static void
fts_search_args_find_best(struct mail_search_arg *args,
			  struct mail_search_arg **best_arg)
{
	for (; args != NULL; args = args->next) {
		switch (args->type) {
		case SEARCH_BODY:
		case SEARCH_TEXT:
		case SEARCH_HEADER:
		case SEARCH_HEADER_COMPRESS_LWSP:
			if (arg_is_better(args, *best_arg))
				*best_arg = args;
			break;
		default:
			break;
		}
	}
}

void fts_search_analyze(struct fts_search_context *fctx)
{
	fts_search_args_find_best(fctx->args->args, &fctx->best_arg);
}
