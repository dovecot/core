/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "seq-range-array.h"
#include "mail-search.h"
#include "fts-api-private.h"
#include "fts-search-args.h"
#include "fts-search-serialize.h"
#include "fts-storage.h"

static void
uid_range_to_seqs(struct fts_search_context *fctx,
		  const ARRAY_TYPE(seq_range) *uid_range,
		  ARRAY_TYPE(seq_range) *seq_range)
{
	const struct seq_range *range;
	unsigned int i, count;
	uint32_t seq1, seq2;

	range = array_get(uid_range, &count);
	if (!array_is_created(seq_range))
		p_array_init(seq_range, fctx->result_pool, count);
	for (i = 0; i < count; i++) {
		if (range[i].seq1 > range[i].seq2)
			continue;
		mailbox_get_seq_range(fctx->box, range[i].seq1, range[i].seq2,
				      &seq1, &seq2);
		if (seq1 != 0)
			seq_range_array_add_range(seq_range, seq1, seq2);
	}
}

static int fts_search_lookup_level_single(struct fts_search_context *fctx,
					  struct mail_search_arg *args,
					  bool and_args)
{
	enum fts_lookup_flags flags = fctx->flags |
		(and_args ? FTS_LOOKUP_FLAG_AND_ARGS : 0);
	struct fts_search_level *level;
	struct fts_result result;

	i_zero(&result);
	p_array_init(&result.definite_uids, fctx->result_pool, 32);
	p_array_init(&result.maybe_uids, fctx->result_pool, 32);
	p_array_init(&result.scores, fctx->result_pool, 32);

	mail_search_args_reset(args, TRUE);
	if (fts_backend_lookup(fctx->backend, fctx->box, args, flags,
			       &result) < 0)
		return -1;

	level = array_append_space(&fctx->levels);
	level->args_matches = buffer_create_dynamic(fctx->result_pool, 16);
	fts_search_serialize(level->args_matches, args);

	uid_range_to_seqs(fctx, &result.definite_uids, &level->definite_seqs);
	uid_range_to_seqs(fctx, &result.maybe_uids, &level->maybe_seqs);
	level->score_map = result.scores;
	return 0;
}

static void
level_scores_add_vuids(struct mailbox *box,
		       struct fts_search_level *level, struct fts_result *br)
{
	const struct fts_score_map *scores;
	unsigned int i, count;
	ARRAY_TYPE(seq_range) backend_uids;
	ARRAY_TYPE(uint32_t) vuids_arr;
	const uint32_t *vuids;
	struct fts_score_map *score;

	scores = array_get(&br->scores, &count);
	t_array_init(&vuids_arr, count);
	t_array_init(&backend_uids, 64);
	for (i = 0; i < count; i++)
		seq_range_array_add(&backend_uids, scores[i].uid);
	box->virtual_vfuncs->get_virtual_uid_map(box, br->box,
						 &backend_uids, &vuids_arr);

	i_assert(array_count(&vuids_arr) == array_count(&br->scores));
	vuids = array_get(&vuids_arr, &count);
	for (i = 0; i < count; i++) {
		score = array_append_space(&level->score_map);
		score->uid = vuids[i];
		score->score = scores[i].score;
	}
}

static int
mailbox_cmp_fts_backend(struct mailbox *const *m1, struct mailbox *const *m2)
{
	struct fts_backend *b1, *b2;

	b1 = fts_mailbox_backend(*m1);
	b2 = fts_mailbox_backend(*m2);
	if (b1 < b2)
		return -1;
	if (b1 > b2)
		return 1;
	return 0;
}

static int
multi_add_lookup_result(struct fts_search_context *fctx,
			struct fts_search_level *level,
			struct mail_search_arg *args,
			struct fts_multi_result *result)
{
	ARRAY_TYPE(seq_range) vuids;
	size_t orig_size;
	unsigned int i;

	orig_size = level->args_matches->used;
	fts_search_serialize(level->args_matches, args);
	if (orig_size > 0) {
		if (level->args_matches->used != orig_size * 2 ||
		    memcmp(level->args_matches->data,
			   CONST_PTR_OFFSET(level->args_matches->data,
					    orig_size), orig_size) != 0)
			i_panic("incompatible fts backends for namespaces");
		buffer_set_used_size(level->args_matches, orig_size);
	}

	t_array_init(&vuids, 64);
	for (i = 0; result->box_results[i].box != NULL; i++) {
		struct fts_result *br = &result->box_results[i];

		array_clear(&vuids);
		if (array_is_created(&br->definite_uids)) {
			fctx->box->virtual_vfuncs->get_virtual_uids(fctx->box,
				br->box, &br->definite_uids, &vuids);
		}
		uid_range_to_seqs(fctx, &vuids, &level->definite_seqs);

		array_clear(&vuids);
		if (array_is_created(&br->maybe_uids)) {
			fctx->box->virtual_vfuncs->get_virtual_uids(fctx->box,
				br->box, &br->maybe_uids, &vuids);
		}
		uid_range_to_seqs(fctx, &vuids, &level->maybe_seqs);

		if (array_is_created(&br->scores))
			level_scores_add_vuids(fctx->box, level, br);
	}
	return 0;
}

static int fts_search_lookup_level_multi(struct fts_search_context *fctx,
					 struct mail_search_arg *args,
					 bool and_args)
{
	enum fts_lookup_flags flags = fctx->flags |
		(and_args ? FTS_LOOKUP_FLAG_AND_ARGS : 0);
	ARRAY_TYPE(mailboxes) mailboxes_arr, tmp_mailboxes;
	struct mailbox *const *mailboxes;
	struct fts_backend *backend;
	struct fts_search_level *level;
	struct fts_multi_result result;
	unsigned int i, j, mailbox_count;

	p_array_init(&mailboxes_arr, fctx->result_pool, 8);
	fctx->box->virtual_vfuncs->get_virtual_backend_boxes(fctx->box,
		&mailboxes_arr, TRUE);
	array_sort(&mailboxes_arr, mailbox_cmp_fts_backend);

	i_zero(&result);
	result.pool = fctx->result_pool;

	level = array_append_space(&fctx->levels);
	level->args_matches = buffer_create_dynamic(fctx->result_pool, 16);
	p_array_init(&level->score_map, fctx->result_pool, 1);

	mailboxes = array_get(&mailboxes_arr, &mailbox_count);
	t_array_init(&tmp_mailboxes, mailbox_count);
	for (i = 0; i < mailbox_count; i = j) {
		array_clear(&tmp_mailboxes);
		array_push_back(&tmp_mailboxes, &mailboxes[i]);

		backend = fts_mailbox_backend(mailboxes[i]);
		for (j = i + 1; j < mailbox_count; j++) {
			if (fts_mailbox_backend(mailboxes[j]) != backend)
				break;
			array_push_back(&tmp_mailboxes, &mailboxes[j]);
		}
		array_append_zero(&tmp_mailboxes);

		mail_search_args_reset(args, TRUE);
		if (fts_backend_lookup_multi(backend,
					     array_first(&tmp_mailboxes),
					     args, flags, &result) < 0)
			return -1;

		if (multi_add_lookup_result(fctx, level, args, &result) < 0)
			return -1;
	}
	return 0;
}

static int fts_search_lookup_level(struct fts_search_context *fctx,
				   struct mail_search_arg *args,
				   bool and_args)
{
	int ret;

	T_BEGIN {
		ret = !fctx->virtual_mailbox ?
			fts_search_lookup_level_single(fctx, args, and_args) :
			fts_search_lookup_level_multi(fctx, args, and_args);
	} T_END;
	if (ret < 0)
		return -1;

	for (; args != NULL; args = args->next) {
		if (args->type != SEARCH_OR && args->type != SEARCH_SUB)
			continue;

		if (fts_search_lookup_level(fctx, args->value.subargs,
					    args->type == SEARCH_SUB) < 0)
			return -1;
	}
	return 0;
}

static void
fts_search_merge_scores_and(ARRAY_TYPE(fts_score_map) *dest,
			    const ARRAY_TYPE(fts_score_map) *src)
{
	struct fts_score_map *dest_map;
	const struct fts_score_map *src_map;
	unsigned int desti, srci, dest_count, src_count;

	dest_map = array_get_modifiable(dest, &dest_count);
	src_map = array_get(src, &src_count);

	/* arg_scores are summed to current scores. we could drop UIDs that
	   don't exist in both, but that's just extra work so don't bother */
	for (desti = srci = 0; desti < dest_count && srci < src_count;) {
		if (dest_map[desti].uid < src_map[srci].uid)
			desti++;
		else if (dest_map[desti].uid > src_map[srci].uid)
			srci++;
		else {
			if (dest_map[desti].score < src_map[srci].score)
				dest_map[desti].score = src_map[srci].score;
			desti++; srci++;
		}
	}
}

static void
fts_search_merge_scores_or(ARRAY_TYPE(fts_score_map) *dest,
			   const ARRAY_TYPE(fts_score_map) *src)
{
	ARRAY_TYPE(fts_score_map) src2;
	const struct fts_score_map *src_map, *src2_map;
	unsigned int srci, src2i, src_count, src2_count;

	t_array_init(&src2, array_count(dest));
	array_append_array(&src2, dest);
	array_clear(dest);

	src_map = array_get(src, &src_count);
	src2_map = array_get(&src2, &src2_count);

	/* add any missing UIDs to current scores. if any existing UIDs have
	   lower scores than in arg_scores, increase them. */
	for (srci = src2i = 0; srci < src_count || src2i < src2_count;) {
		if (src2i == src2_count ||
		    src_map[srci].uid < src2_map[src2i].uid) {
			array_push_back(dest, &src_map[srci]);
			srci++;
		} else if (srci == src_count ||
			   src_map[srci].uid > src2_map[src2i].uid) {
			array_push_back(dest, &src2_map[src2i]);
			src2i++;
		} else {
			i_assert(src_map[srci].uid == src2_map[src2i].uid);
			if (src_map[srci].score > src2_map[src2i].score)
				array_push_back(dest, &src_map[srci]);
			else
				array_push_back(dest, &src2_map[src2i]);
			srci++; src2i++;
		}
	}
}

static void
fts_search_merge_scores_level(struct fts_search_context *fctx,
			      struct mail_search_arg *args, unsigned int *idx,
			      bool and_args, ARRAY_TYPE(fts_score_map) *scores)
{
	const struct fts_search_level *level;
	ARRAY_TYPE(fts_score_map) arg_scores;

	i_assert(array_count(scores) == 0);

	/*
	   The (simplified) args can look like:

	   A and B and (C or D) and (E or F) and ...
	   A or B or (C and D) or (E and F) or ...

	   The A op B part's scores are in level->scores. The child args'
	   scores are in the sub levels' scores.
	*/

	level = array_idx(&fctx->levels, *idx);
	array_append_array(scores, &level->score_map);

	t_array_init(&arg_scores, 64);
	for (; args != NULL; args = args->next) {
		if (args->type != SEARCH_OR && args->type != SEARCH_SUB)
			continue;

		*idx += 1;
		array_clear(&arg_scores);
		fts_search_merge_scores_level(fctx, args->value.subargs, idx,
					      args->type == SEARCH_OR,
					      &arg_scores);

		if (and_args)
			fts_search_merge_scores_and(scores, &arg_scores);
		else
			fts_search_merge_scores_or(scores, &arg_scores);
	}
}

static void fts_search_merge_scores(struct fts_search_context *fctx)
{
	unsigned int idx = 0;

	fts_search_merge_scores_level(fctx, fctx->args->args, &idx,
				      TRUE, &fctx->scores->score_map);
}

void fts_search_lookup(struct fts_search_context *fctx)
{
	uint32_t last_uid, seq1, seq2;

	i_assert(array_count(&fctx->levels) == 0);
	i_assert(fctx->args->simplified);

	if (fts_backend_refresh(fctx->backend) < 0)
		return;
	if (fts_backend_get_last_uid(fctx->backend, fctx->box, &last_uid) < 0)
		return;
	mailbox_get_seq_range(fctx->box, last_uid+1, (uint32_t)-1,
			      &seq1, &seq2);
	fctx->first_unindexed_seq = seq1 != 0 ? seq1 : (uint32_t)-1;

	if ((fctx->backend->flags & FTS_BACKEND_FLAG_TOKENIZED_INPUT) != 0) {
		if (fts_search_args_expand(fctx->backend, fctx->args) < 0)
			return;
	}
	fts_search_serialize(fctx->orig_matches, fctx->args->args);

	if (fts_search_lookup_level(fctx, fctx->args->args, TRUE) == 0) {
		fctx->fts_lookup_success = TRUE;
		fts_search_merge_scores(fctx);
	}

	fts_search_deserialize(fctx->args->args, fctx->orig_matches);
	fts_backend_lookup_done(fctx->backend);
}
