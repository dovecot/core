/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "seq-range-array.h"
#include "charset-utf8.h"
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
	struct fts_backend *backend;
	struct fts_backend_lookup_context **lookup_ctx_p;
	enum fts_lookup_flags flags = 0;
	const char *key;
	string_t *key_utf8;
	enum charset_result result;
	int ret;

	switch (arg->type) {
	case SEARCH_HEADER:
	case SEARCH_HEADER_COMPRESS_LWSP:
		/* we can filter out messages that don't have the header,
		   but we can't trust definite results list. */
		flags = FTS_LOOKUP_FLAG_HEADER;
		backend = fctx->fbox->backend_substr;
		key = arg->value.str;
		if (*key == '\0') {
			/* we're only checking the existence
			   of the header. */
			key = arg->hdr_field_name;
		}
		break;
	case SEARCH_TEXT:
	case SEARCH_TEXT_FAST:
		flags = FTS_LOOKUP_FLAG_HEADER;
	case SEARCH_BODY:
	case SEARCH_BODY_FAST:
		flags |= FTS_LOOKUP_FLAG_BODY;
		key = arg->value.str;
		backend = fctx->fbox->backend_fast != NULL &&
			(arg->type == SEARCH_TEXT_FAST ||
			 arg->type == SEARCH_BODY_FAST) ?
			fctx->fbox->backend_fast : fctx->fbox->backend_substr;
		if (backend == NULL)
			return 0;
		break;
	default:
		/* can't filter this */
		return 0;
	}
	if (arg->not)
		flags |= FTS_LOOKUP_FLAG_INVERT;

	/* convert key to titlecase */
	key_utf8 = t_str_new(128);
	if (charset_to_utf8_str(fctx->args->charset,
				CHARSET_FLAG_DECOMP_TITLECASE,
				key, key_utf8, &result) < 0) {
		/* unknown charset, can't handle this */
		ret = 0;
	} else if (result != CHARSET_RET_OK) {
		/* let the core code handle this error */
		ret = 0;
	} else if (!backend->locked && fts_backend_lock(backend) <= 0)
		ret = -1;
	else {
		ret = 0;
		if (backend == fctx->fbox->backend_substr)
			lookup_ctx_p = &fctx->lookup_ctx_substr;
		else
			lookup_ctx_p = &fctx->lookup_ctx_fast;

		if (*lookup_ctx_p == NULL)
			*lookup_ctx_p = fts_backend_lookup_init(backend);
		fts_backend_lookup_add(*lookup_ctx_p, str_c(key_utf8), flags);
	}
	return ret;
}

void fts_search_lookup(struct fts_search_context *fctx)
{
	struct mail_search_arg *arg;
	bool have_seqs;
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

	have_seqs = FALSE;
	if (fctx->fbox->backend_fast != NULL) {
		if (fctx->lookup_ctx_fast != NULL) {
			have_seqs = TRUE;
			fts_backend_lookup_deinit(&fctx->lookup_ctx_fast,
						  &fctx->definite_seqs,
						  &fctx->maybe_seqs,
						  &fctx->score_map);
		}
		if (fctx->fbox->backend_fast->locked)
			fts_backend_unlock(fctx->fbox->backend_fast);
	}
	if (fctx->fbox->backend_substr != NULL) {
		if (fctx->lookup_ctx_substr == NULL) {
			/* no substr lookups */
		} else if (!have_seqs) {
			fts_backend_lookup_deinit(&fctx->lookup_ctx_substr,
						  &fctx->definite_seqs,
						  &fctx->maybe_seqs,
						  &fctx->score_map);
		} else {
			/* have to merge the results */
			ARRAY_TYPE(seq_range) tmp_def, tmp_maybe;
			ARRAY_TYPE(fts_score_map) tmp_scores;

			i_array_init(&tmp_def, 64);
			i_array_init(&tmp_maybe, 64);
			i_array_init(&tmp_scores, 64);
			/* FIXME: for now we just ignore the other scores,
			   since squat doesn't support it anyway */
			fts_backend_lookup_deinit(&fctx->lookup_ctx_substr,
						  &tmp_def, &tmp_maybe,
						  &tmp_scores);
			fts_filter_uids(&fctx->definite_seqs, &tmp_def,
					&fctx->maybe_seqs, &tmp_maybe);
			array_free(&tmp_def);
			array_free(&tmp_maybe);
			array_free(&tmp_scores);
		}
		if (fctx->fbox->backend_substr->locked)
			fts_backend_unlock(fctx->fbox->backend_substr);
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
			  struct mail_search_arg **best_fast_arg,
			  struct mail_search_arg **best_substr_arg)
{
	for (; args != NULL; args = args->next) {
		switch (args->type) {
		case SEARCH_BODY_FAST:
		case SEARCH_TEXT_FAST:
			if (arg_is_better(args, *best_fast_arg))
				*best_fast_arg = args;
			break;
		case SEARCH_BODY:
		case SEARCH_TEXT:
		case SEARCH_HEADER:
		case SEARCH_HEADER_COMPRESS_LWSP:
			if (arg_is_better(args, *best_substr_arg))
				*best_substr_arg = args;
			break;
		default:
			break;
		}
	}
}

void fts_search_analyze(struct fts_search_context *fctx)
{
	struct mail_search_arg *best_fast_arg = NULL, *best_substr_arg = NULL;

	fts_search_args_find_best(fctx->args->args, &best_fast_arg,
				  &best_substr_arg);

	if (best_fast_arg != NULL && fctx->fbox->backend_fast != NULL) {
		/* use fast backend whenever possible */
		fctx->best_arg = best_fast_arg;
		fctx->build_backend = fctx->fbox->backend_fast;
	} else if (best_fast_arg != NULL || best_substr_arg != NULL) {
		fctx->build_backend = fctx->fbox->backend_substr;
		fctx->best_arg = arg_is_better(best_substr_arg, best_fast_arg) ?
			best_substr_arg : best_fast_arg;
	}
}
