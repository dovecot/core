/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "mail-index.h"
#include "mail-storage.h"
#include "mail-search.h"

static void
mailbox_uidset_change(struct mail_search_arg *arg, struct mailbox *box,
		      const ARRAY_TYPE(seq_range) *search_saved_uidset)
{
	struct seq_range *uids;
	unsigned int i, count;
	uint32_t seq1, seq2;

	if (arg->value.str != NULL && strcmp(arg->value.str, "$") == 0) {
		/* SEARCHRES: Replace with saved uidset */
		array_clear(&arg->value.seqset);
		if (search_saved_uidset == NULL ||
		    !array_is_created(search_saved_uidset))
			return;

		array_append_array(&arg->value.seqset, search_saved_uidset);
		return;
	}

	arg->type = SEARCH_SEQSET;

	/* make a copy of the UIDs */
	count = array_count(&arg->value.seqset);
	if (count == 0) {
		/* empty set, keep it */
		return;
	}
	uids = t_new(struct seq_range, count);
	memcpy(uids, array_idx(&arg->value.seqset, 0), sizeof(*uids) * count);

	/* put them back to the range as sequences */
	array_clear(&arg->value.seqset);
	for (i = 0; i < count; i++) {
		mailbox_get_seq_range(box, uids[i].seq1, uids[i].seq2,
				      &seq1, &seq2);
		if (seq1 != 0) {
			seq_range_array_add_range(&arg->value.seqset,
						  seq1, seq2);
		}
		if (uids[i].seq2 == (uint32_t)-1) {
			/* make sure the last message is in the range */
			mailbox_get_seq_range(box, 1, (uint32_t)-1,
					      &seq1, &seq2);
			seq_range_array_add(&arg->value.seqset, 0, seq2);
		}
	}
}

static void
mail_search_args_init_sub(struct mail_search_arg *args,
			  struct mailbox *box, bool change_uidsets,
			  const ARRAY_TYPE(seq_range) *search_saved_uidset)
{
	const char *keywords[2];

	for (; args != NULL; args = args->next) {
		switch (args->type) {
		case SEARCH_UIDSET:
			if (change_uidsets) T_BEGIN {
				mailbox_uidset_change(args, box,
						      search_saved_uidset);
			} T_END;
			break;
		case SEARCH_MODSEQ:
			if (args->value.str == NULL)
				break;
			/* modseq with keyword */
		case SEARCH_KEYWORDS:
			keywords[0] = args->value.str;
			keywords[1] = NULL;

			i_assert(args->value.keywords == NULL);
			args->value.keywords =
				mailbox_keywords_create_valid(box, keywords);
			break;

		case SEARCH_SUB:
		case SEARCH_OR:
			mail_search_args_init_sub(args->value.subargs, box,
						  change_uidsets,
						  search_saved_uidset);
			break;
		default:
			break;
		}
	}
}

void mail_search_args_init(struct mail_search_args *args,
			   struct mailbox *box, bool change_uidsets,
			   const ARRAY_TYPE(seq_range) *search_saved_uidset)
{
	args->box = box;
	mail_search_args_init_sub(args->args, box, change_uidsets,
				  search_saved_uidset);
}

static void mail_search_args_deinit_sub(struct mail_search_args *args,
					struct mail_search_arg *arg)
{
	for (; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_MODSEQ:
		case SEARCH_KEYWORDS:
			if (arg->value.keywords == NULL)
				break;
			mailbox_keywords_free(args->box, &arg->value.keywords);
			break;
		case SEARCH_SUB:
		case SEARCH_OR:
			mail_search_args_deinit_sub(args, arg->value.subargs);
			break;
		default:
			break;
		}
	}
}

void mail_search_args_deinit(struct mail_search_args *args)
{
	if (args->refcount > 1)
		return;

	mail_search_args_deinit_sub(args, args->args);
}

static void mail_search_args_seq2uid_sub(struct mail_search_args *args,
					 struct mail_search_arg *arg,
					 ARRAY_TYPE(seq_range) *uids)
{
	for (; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_SEQSET:
			array_clear(uids);
			mailbox_get_uid_range(args->box,
					      &arg->value.seqset, uids);

			/* replace sequences with UIDs in the existing array.
			   this way it's possible to switch between uidsets and
			   seqsets constantly without leaking memory */
			arg->type = SEARCH_UIDSET;
			array_clear(&arg->value.seqset);
			array_append_array(&arg->value.seqset, uids);
			break;
		case SEARCH_SUB:
		case SEARCH_OR:
			mail_search_args_seq2uid_sub(args, arg->value.subargs,
						     uids);
			break;
		default:
			break;
		}
	}
}

void mail_search_args_seq2uid(struct mail_search_args *args)
{
	T_BEGIN {
		ARRAY_TYPE(seq_range) uids;

		t_array_init(&uids, 128);
		mail_search_args_seq2uid_sub(args, args->args, &uids);
	} T_END;
}

void mail_search_args_ref(struct mail_search_args *args)
{
	i_assert(args->refcount > 0);

	args->refcount++;
}

void mail_search_args_unref(struct mail_search_args **_args)
{
	struct mail_search_args *args = *_args;

	i_assert(args->refcount > 0);

	*_args = NULL;
	if (--args->refcount > 0)
		return;

	mail_search_args_deinit(args);
	pool_unref(&args->pool);
}

void mail_search_args_reset(struct mail_search_arg *args, bool full_reset)
{
	while (args != NULL) {
		if (args->type == SEARCH_OR || args->type == SEARCH_SUB)
			mail_search_args_reset(args->value.subargs, full_reset);

		if (!args->match_always)
			args->result = -1;
		else {
			if (!full_reset)
				args->result = 1;
			else {
				args->match_always = FALSE;
				args->result = -1;
			}
		}

		args = args->next;
	}
}

static void search_arg_foreach(struct mail_search_arg *arg,
			       mail_search_foreach_callback_t *callback,
			       void *context)
{
	struct mail_search_arg *subarg;

	if (arg->result != -1)
		return;

	if (arg->type == SEARCH_SUB) {
		/* sublist of conditions */
		i_assert(arg->value.subargs != NULL);

		arg->result = 1;
		subarg = arg->value.subargs;
		while (subarg != NULL) {
			if (subarg->result == -1)
				search_arg_foreach(subarg, callback, context);

			if (subarg->result == -1)
				arg->result = -1;
			else if (subarg->result == 0) {
				/* didn't match */
				arg->result = 0;
				break;
			}

			subarg = subarg->next;
		}
		if (arg->not && arg->result != -1)
			arg->result = !arg->result;
	} else if (arg->type == SEARCH_OR) {
		/* OR-list of conditions */
		i_assert(arg->value.subargs != NULL);

		subarg = arg->value.subargs;
		arg->result = 0;
		while (subarg != NULL) {
			if (subarg->result == -1)
				search_arg_foreach(subarg, callback, context);

			if (subarg->result == -1)
				arg->result = -1;
			else if (subarg->result > 0) {
				/* matched */
				arg->result = 1;
				break;
			}

			subarg = subarg->next;
		}
		if (arg->not && arg->result != -1)
			arg->result = !arg->result;
	} else {
		/* just a single condition */
		callback(arg, context);
	}
}

#undef mail_search_args_foreach
int mail_search_args_foreach(struct mail_search_arg *args,
			     mail_search_foreach_callback_t *callback,
			     void *context)
{
	int result;

	result = 1;
	for (; args != NULL; args = args->next) {
		search_arg_foreach(args, callback, context);

		if (args->result == 0) {
			/* didn't match */
			return 0;
		}

		if (args->result == -1)
			result = -1;
	}

	return result;
}

static void
search_arg_analyze(struct mail_search_arg *arg, buffer_t *headers,
		   bool *have_body, bool *have_text)
{
	static const char *date_hdr = "Date";
	struct mail_search_arg *subarg;

	if (arg->result != -1)
		return;

	switch (arg->type) {
	case SEARCH_OR:
	case SEARCH_SUB:
		subarg = arg->value.subargs;
		while (subarg != NULL) {
			if (subarg->result == -1) {
				search_arg_analyze(subarg, headers,
						   have_body, have_text);
			}

			subarg = subarg->next;
		}
		break;
	case SEARCH_SENTBEFORE:
	case SEARCH_SENTON:
	case SEARCH_SENTSINCE:
		buffer_append(headers, &date_hdr, sizeof(const char *));
		break;
	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
	case SEARCH_HEADER_COMPRESS_LWSP:
		buffer_append(headers, &arg->hdr_field_name,
			      sizeof(const char *));
		break;
	case SEARCH_BODY:
	case SEARCH_BODY_FAST:
		*have_body = TRUE;
		break;
	case SEARCH_TEXT:
	case SEARCH_TEXT_FAST:
		*have_text = TRUE;
		*have_body = TRUE;
		break;
	default:
		break;
	}
}

const char *const *
mail_search_args_analyze(struct mail_search_arg *args,
			 bool *have_headers, bool *have_body)
{
	const char *null = NULL;
	buffer_t *headers;
	bool have_text;

	*have_headers = *have_body = have_text = FALSE;

	headers = buffer_create_dynamic(pool_datastack_create(), 128);
	for (; args != NULL; args = args->next)
		search_arg_analyze(args, headers, have_body, &have_text);

	*have_headers = have_text || headers->used != 0;

	if (headers->used == 0 || have_text)
		return NULL;

	buffer_append(headers, &null, sizeof(const char *));
	return buffer_get_data(headers, NULL);
}

static struct mail_keywords *
mail_search_keywords_merge(struct mail_keywords **_kw1,
			   struct mail_keywords **_kw2)
{
	struct mail_keywords *kw1 = *_kw1, *kw2 = *_kw2;
	struct mail_keywords *new_kw;

	i_assert(kw1->index == kw2->index);
	T_BEGIN {
		ARRAY_TYPE(keyword_indexes) new_indexes;
		unsigned int i, j;

		t_array_init(&new_indexes, kw1->count + kw2->count + 1);
		array_append(&new_indexes, kw1->idx, kw1->count);
		for (i = 0; i < kw2->count; i++) {
			/* don't add duplicates */
			for (j = 0; j < kw1->count; j++) {
				if (kw1->idx[j] == kw2->idx[i])
					break;
			}
			if (j == kw1->count)
				array_append(&new_indexes, kw2->idx+i, 1);
		}
		new_kw = mail_index_keywords_create_from_indexes(kw1->index,
								 &new_indexes);
	} T_END;
	mail_index_keywords_free(_kw1);
	mail_index_keywords_free(_kw2);
	return new_kw;
}

static void
mail_search_args_simplify_sub(struct mail_search_arg *args, bool parent_and)
{
	struct mail_search_arg *sub, *prev = NULL;
	struct mail_search_arg *prev_flags_arg, *prev_not_flags_arg;
	struct mail_search_arg *prev_kw_arg, *prev_not_kw_arg;

	prev_flags_arg = prev_not_flags_arg = NULL;
	prev_kw_arg = prev_not_kw_arg = NULL;
	for (; args != NULL;) {
		if (args->not && (args->type == SEARCH_SUB ||
				  args->type == SEARCH_OR)) {
			/* neg(p and q and ..) == neg(p) or neg(q) or ..
			   neg(p or q or ..) == neg(p) and neg(q) and .. */
			args->type = args->type == SEARCH_SUB ?
				SEARCH_OR : SEARCH_SUB;
			args->not = FALSE;
			sub = args->value.subargs;
			for (; sub != NULL; sub = sub->next)
				sub->not = !sub->not;
		}

		if ((args->type == SEARCH_SUB && parent_and) ||
		    (args->type == SEARCH_OR && !parent_and)) {
			/* p and (q and ..) == p and q and ..
			   p or (q or ..) == p or q or .. */
			sub = args->value.subargs;
			for (; sub->next != NULL; sub = sub->next) ;
			sub->next = args->next;
			*args = *args->value.subargs;
			continue;
		}

		if (args->type == SEARCH_SUB || args->type == SEARCH_OR) {
			mail_search_args_simplify_sub(args->value.subargs,
						      args->type == SEARCH_SUB);
		}

		/* merge all flags arguments */
		if (args->type == SEARCH_FLAGS && !args->not && parent_and) {
			if (prev_flags_arg == NULL)
				prev_flags_arg = args;
			else {
				prev_flags_arg->value.flags |=
					args->value.flags;
				prev->next = args->next;
				args = args->next;
				continue;
			}
		} else if (args->type == SEARCH_FLAGS && args->not &&
			   !parent_and) {
			if (prev_not_flags_arg == NULL)
				prev_not_flags_arg = args;
			else {
				prev_not_flags_arg->value.flags |=
					args->value.flags;
				prev->next = args->next;
				args = args->next;
				continue;
			}
		}

		/* merge all keywords arguments */
		if (args->type == SEARCH_KEYWORDS && !args->not && parent_and) {
			if (prev_kw_arg == NULL)
				prev_kw_arg = args;
			else {
				prev_kw_arg->value.keywords =
					mail_search_keywords_merge(
						&prev_kw_arg->value.keywords,
						&args->value.keywords);
				prev->next = args->next;
				args = args->next;
				continue;
			}
		} else if (args->type == SEARCH_KEYWORDS && args->not &&
			   !parent_and) {
			if (prev_not_kw_arg == NULL)
				prev_not_kw_arg = args;
			else {
				prev_not_kw_arg->value.keywords =
					mail_search_keywords_merge(
					       &prev_not_kw_arg->value.keywords,
					       &args->value.keywords);
				prev->next = args->next;
				args = args->next;
				continue;
			}
		}

		prev = args;
		args = args->next;
	}
}

void mail_search_args_simplify(struct mail_search_arg *args)
{
	mail_search_args_simplify_sub(args, TRUE);
}
