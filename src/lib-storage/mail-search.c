/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "imap-match.h"
#include "mail-index.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "mail-search-build.h"
#include "mail-search.h"

static struct mail_search_arg *
mail_search_arg_dup(pool_t pool, const struct mail_search_arg *arg);
static bool mail_search_arg_equals(const struct mail_search_arg *arg1,
				   const struct mail_search_arg *arg2);

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
mail_search_args_init_sub(struct mail_search_args *args,
			  struct mail_search_arg *arg,
			  bool change_uidsets,
			  const ARRAY_TYPE(seq_range) *search_saved_uidset)
{
	struct mail_search_args *thread_args;
	const char *keywords[2];

	for (; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_UIDSET:
			if (change_uidsets) T_BEGIN {
				mailbox_uidset_change(arg, args->box,
						      search_saved_uidset);
			} T_END;
			break;
		case SEARCH_MODSEQ:
			if (arg->value.str == NULL)
				break;
			/* modseq with keyword */
		case SEARCH_KEYWORDS:
			keywords[0] = arg->value.str;
			keywords[1] = NULL;

			i_assert(arg->value.keywords == NULL);
			arg->value.keywords =
				mailbox_keywords_create_valid(args->box,
							      keywords);
			break;

		case SEARCH_MAILBOX_GLOB: {
			struct mail_namespace *ns =
				mailbox_get_namespace(args->box);

			arg->value.mailbox_glob =
				imap_match_init(default_pool, arg->value.str,
						TRUE, ns->sep);
			break;
		}
		case SEARCH_INTHREAD:
			thread_args = arg->value.search_args;
			if (thread_args == NULL) {
				arg->value.search_args = thread_args =
					p_new(args->pool,
					      struct mail_search_args, 1);
				thread_args->pool = args->pool;
				thread_args->args = arg->value.subargs;
				thread_args->charset = args->charset;
				thread_args->simplified = TRUE;
				/* simplification should have unnested all
				   inthreads, so we'll assume that
				   have_inthreads=FALSE */
			}
			thread_args->refcount++;
			thread_args->box = args->box;
			/* fall through */
		case SEARCH_SUB:
		case SEARCH_OR:
			mail_search_args_init_sub(args, arg->value.subargs,
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
	i_assert(args->init_refcount <= args->refcount);

	if (args->init_refcount++ > 0) {
		i_assert(args->box == box);
		return;
	}

	args->box = box;
	if (!args->simplified)
		mail_search_args_simplify(args);
	mail_search_args_init_sub(args, args->args, change_uidsets,
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
			mailbox_keywords_unref(args->box, &arg->value.keywords);
			break;
		case SEARCH_MAILBOX_GLOB:
			if (arg->value.mailbox_glob == NULL)
				break;

			imap_match_deinit(&arg->value.mailbox_glob);
			break;
		case SEARCH_INTHREAD:
			i_assert(arg->value.search_args->refcount > 0);
			if (args->refcount == 0 &&
			    arg->value.search_result != NULL) {
				mailbox_search_result_free(
					&arg->value.search_result);
			}
			arg->value.search_args->refcount--;
			arg->value.search_args->box = NULL;
			/* fall through */
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
	if (--args->init_refcount > 0)
		return;

	mail_search_args_deinit_sub(args, args->args);
	args->box = NULL;
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
		case SEARCH_INTHREAD:
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
	if (--args->refcount > 0) {
		i_assert(args->init_refcount <= args->refcount);
		return;
	}
	i_assert(args->init_refcount <= 1);
	if (args->init_refcount == 1)
		mail_search_args_deinit(args);
	pool_unref(&args->pool);
}

static struct mail_search_arg *
mail_search_arg_dup_one(pool_t pool, const struct mail_search_arg *arg)
{
	struct mail_search_arg *new_arg;

	new_arg = p_new(pool, struct mail_search_arg, 1);
	new_arg->type = arg->type;
	new_arg->not = arg->not;
	new_arg->match_always = arg->match_always;
	new_arg->nonmatch_always = arg->nonmatch_always;
	new_arg->value.search_flags = arg->value.search_flags;

	switch (arg->type) {
	case SEARCH_INTHREAD:
		new_arg->value.thread_type = arg->value.thread_type;
		/* fall through */
	case SEARCH_OR:
	case SEARCH_SUB:
		new_arg->value.subargs =
			mail_search_arg_dup(pool, arg->value.subargs);
		break;
	case SEARCH_ALL:
		break;
	case SEARCH_SEQSET:
	case SEARCH_UIDSET:
		p_array_init(&new_arg->value.seqset, pool,
			     array_count(&arg->value.seqset));
		array_append_array(&new_arg->value.seqset, &arg->value.seqset);
		break;
	case SEARCH_FLAGS:
		new_arg->value.flags = arg->value.flags;
		break;
	case SEARCH_BEFORE:
	case SEARCH_ON:
	case SEARCH_SINCE:
		new_arg->value.time = arg->value.time;
		new_arg->value.date_type = arg->value.date_type;
		break;
	case SEARCH_SMALLER:
	case SEARCH_LARGER:
		new_arg->value.size = arg->value.size;
		break;
	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
	case SEARCH_HEADER_COMPRESS_LWSP:
		new_arg->hdr_field_name = p_strdup(pool, arg->hdr_field_name);
		/* fall through */
	case SEARCH_KEYWORDS:
	case SEARCH_BODY:
	case SEARCH_TEXT:
	case SEARCH_BODY_FAST:
	case SEARCH_TEXT_FAST:
	case SEARCH_GUID:
	case SEARCH_MAILBOX:
	case SEARCH_MAILBOX_GUID:
	case SEARCH_MAILBOX_GLOB:
		new_arg->value.str = p_strdup(pool, arg->value.str);
		break;
	case SEARCH_MODSEQ:
		new_arg->value.modseq =
			p_new(pool, struct mail_search_modseq, 1);
		*new_arg->value.modseq = *arg->value.modseq;
		break;
	}
	return new_arg;
}

static struct mail_search_arg *
mail_search_arg_dup(pool_t pool, const struct mail_search_arg *arg)
{
	struct mail_search_arg *new_arg = NULL, **dest = &new_arg;

	for (; arg != NULL; arg = arg->next) {
		*dest = mail_search_arg_dup_one(pool, arg);
		dest = &(*dest)->next;
	}
	return new_arg;
}

struct mail_search_args *
mail_search_args_dup(const struct mail_search_args *args)
{
	struct mail_search_args *new_args;

	new_args = mail_search_build_init();
	new_args->charset = p_strdup(new_args->pool, args->charset);
	new_args->simplified = args->simplified;
	new_args->have_inthreads = args->have_inthreads;
	new_args->args = mail_search_arg_dup(new_args->pool, args->args);
	return new_args;
}

void mail_search_args_reset(struct mail_search_arg *args, bool full_reset)
{
	while (args != NULL) {
		if (args->type == SEARCH_OR || args->type == SEARCH_SUB)
			mail_search_args_reset(args->value.subargs, full_reset);

		if (args->match_always) {
			if (!full_reset)
				args->result = 1;
			else {
				args->match_always = FALSE;
				args->result = -1;
			}
		} else if (args->nonmatch_always) {
			if (!full_reset)
				args->result = 0;
			else {
				args->nonmatch_always = FALSE;
				args->result = -1;
			}
		} else {
			args->result = -1;
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
	case SEARCH_BEFORE:
	case SEARCH_ON:
	case SEARCH_SINCE:
		if (arg->value.date_type == MAIL_SEARCH_DATE_TYPE_SENT)
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

static bool
mail_search_args_match_mailbox_arg(const struct mail_search_arg *arg,
				   const char *vname, char sep)
{
	const struct mail_search_arg *subarg;
	bool ret;

	switch (arg->type) {
	case SEARCH_OR:
		subarg = arg->value.subargs;
		for (; subarg != NULL; subarg = subarg->next) {
			if (mail_search_args_match_mailbox_arg(subarg,
							       vname, sep))
				return TRUE;
		}
		return FALSE;
	case SEARCH_SUB:
	case SEARCH_INTHREAD:
		subarg = arg->value.subargs;
		for (; subarg != NULL; subarg = subarg->next) {
			if (!mail_search_args_match_mailbox_arg(subarg,
								vname, sep))
				return FALSE;
		}
		return TRUE;
	case SEARCH_MAILBOX:
		ret = strcmp(arg->value.str, vname) == 0;
		return ret != arg->not;
	case SEARCH_MAILBOX_GLOB: {
		T_BEGIN {
			struct imap_match_glob *glob;

			glob = imap_match_init(pool_datastack_create(),
					       arg->value.str, TRUE, sep);
			ret = imap_match(glob, vname) == IMAP_MATCH_YES;
		} T_END;
		return ret != arg->not;
	}
	default:
		break;
	}
	return TRUE;
}

bool mail_search_args_match_mailbox(struct mail_search_args *args,
				    const char *vname, char sep)
{
	const struct mail_search_arg *arg;

	if (!args->simplified)
		mail_search_args_simplify(args);

	for (arg = args->args; arg != NULL; arg = arg->next) {
		if (!mail_search_args_match_mailbox_arg(arg, vname, sep))
			return FALSE;
	}
	return TRUE;
}

static struct mail_keywords *
mail_search_keywords_merge(struct mailbox *box,
			   struct mail_keywords **_kw1,
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
		new_kw = mailbox_keywords_create_from_indexes(box,
							      &new_indexes);
	} T_END;
	mailbox_keywords_unref(box, _kw1);
	mailbox_keywords_unref(box, _kw2);
	return new_kw;
}

static void
mail_search_args_simplify_sub(struct mailbox *box,
			      struct mail_search_arg *args, bool parent_and)
{
	struct mail_search_arg *sub, *prev = NULL;
	struct mail_search_arg *prev_flags_arg, *prev_not_flags_arg;
	struct mail_search_arg *prev_kw_arg, *prev_not_kw_arg;

	prev_flags_arg = prev_not_flags_arg = NULL;
	prev_kw_arg = prev_not_kw_arg = NULL;
	while (args != NULL) {
		if (args->not && (args->type == SEARCH_SUB ||
				  args->type == SEARCH_OR)) {
			/* neg(p and q and ..) == neg(p) or neg(q) or ..
			   neg(p or q or ..) == neg(p) and neg(q) and .. */
			args->type = args->type == SEARCH_SUB ?
				SEARCH_OR : SEARCH_SUB;
			args->not = FALSE;
			sub = args->value.subargs;
			do {
				sub->not = !sub->not;
				sub = sub->next;
			} while (sub != NULL);
		}

		if ((args->type == SEARCH_SUB && parent_and) ||
		    (args->type == SEARCH_OR && !parent_and) ||
		    ((args->type == SEARCH_SUB || args->type == SEARCH_OR) &&
		     args->value.subargs->next == NULL)) {
			/* p and (q and ..) == p and q and ..
			   p or (q or ..) == p or q or ..
			   (p) = p */
			sub = args->value.subargs;
			for (; sub->next != NULL; sub = sub->next) ;
			sub->next = args->next;
			*args = *args->value.subargs;
			continue;
		}

		if (args->type == SEARCH_SUB ||
		    args->type == SEARCH_OR ||
		    args->type == SEARCH_INTHREAD) {
			mail_search_args_simplify_sub(box, args->value.subargs,
						      args->type != SEARCH_OR);
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
					mail_search_keywords_merge(box,
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
					mail_search_keywords_merge(box,
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

static bool
mail_search_args_unnest_inthreads(struct mail_search_args *args,
				  struct mail_search_arg **argp,
				  bool parent_inthreads, bool parent_and)
{
	struct mail_search_arg *arg, *thread_arg, *or_arg;
	bool child_inthreads = FALSE, non_inthreads = FALSE;

	for (arg = *argp; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_SUB:
		case SEARCH_OR:
			if (!mail_search_args_unnest_inthreads(args,
					&arg->value.subargs, parent_inthreads,
					arg->type != SEARCH_OR)) {
				arg->result = 1;
				child_inthreads = TRUE;
			} else {
				arg->result = 0;
				non_inthreads = TRUE;
			}
			break;
		case SEARCH_INTHREAD:
			if (mail_search_args_unnest_inthreads(args,
					&arg->value.subargs, TRUE, TRUE)) {
				/* children converted to SEARCH_INTHREADs */
				arg->type = SEARCH_SUB;
			}
			args->have_inthreads = TRUE;
			arg->result = 1;
			child_inthreads = TRUE;
			break;
		default:
			arg->result = 0;
			non_inthreads = TRUE;
			break;
		}
	}

	if (!parent_inthreads || !child_inthreads || !non_inthreads)
		return FALSE;

	/* put all non-INTHREADs under a single INTHREAD */
	thread_arg = p_new(args->pool, struct mail_search_arg, 1);
	thread_arg->type = SEARCH_INTHREAD;

	while (*argp != NULL) {
		arg = *argp;
		argp = &(*argp)->next;

		if (arg->result == 0) {
			/* not an INTHREAD or a SUB/OR with only INTHREADs */
			arg->next = thread_arg->value.subargs;
			thread_arg->value.subargs = arg;
		}
	}
	if (!parent_and) {
		/* We want to OR the args */
		or_arg = p_new(args->pool, struct mail_search_arg, 1);
		or_arg->type = SEARCH_OR;
		or_arg->value.subargs = thread_arg->value.subargs;
		thread_arg->value.subargs = or_arg;
	}
	return TRUE;
}

void mail_search_args_simplify(struct mail_search_args *args)
{
	args->simplified = TRUE;

	mail_search_args_simplify_sub(args->box, args->args, TRUE);
	if (mail_search_args_unnest_inthreads(args, &args->args,
					      FALSE, TRUE)) {
		/* we may have added some extra SUBs that could be dropped */
		mail_search_args_simplify_sub(args->box, args->args, TRUE);
	}
}

static bool mail_search_arg_one_equals(const struct mail_search_arg *arg1,
				       const struct mail_search_arg *arg2)
{
	if (arg1->type != arg2->type ||
	    arg1->not != arg2->not)
		return FALSE;

	switch (arg1->type) {
	case SEARCH_OR:
	case SEARCH_SUB:
		return mail_search_arg_equals(arg1->value.subargs,
					      arg2->value.subargs);

	case SEARCH_ALL:
		return TRUE;
	case SEARCH_SEQSET:
		/* sequences may point to different messages at different times,
		   never assume they match */
		return FALSE;
	case SEARCH_UIDSET:
		return array_cmp(&arg1->value.seqset, &arg2->value.seqset);

	case SEARCH_FLAGS:
		return arg1->value.flags == arg2->value.flags;
	case SEARCH_KEYWORDS:
		return strcasecmp(arg1->value.str, arg2->value.str);

	case SEARCH_BEFORE:
	case SEARCH_ON:
	case SEARCH_SINCE:
		return arg1->value.time == arg2->value.time &&
			arg1->value.date_type == arg2->value.date_type;

	case SEARCH_SMALLER:
	case SEARCH_LARGER:
		return arg1->value.size == arg2->value.size;

	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
	case SEARCH_HEADER_COMPRESS_LWSP:
		if (strcasecmp(arg1->hdr_field_name, arg2->hdr_field_name) != 0)
			return FALSE;
		/* fall through */
	case SEARCH_BODY:
	case SEARCH_TEXT:
	case SEARCH_BODY_FAST:
	case SEARCH_TEXT_FAST:
	case SEARCH_GUID:
	case SEARCH_MAILBOX:
	case SEARCH_MAILBOX_GUID:
	case SEARCH_MAILBOX_GLOB:
		/* don't bother doing case-insensitive comparison. it must not
		   be done for guid/mailbox, and for others we should support
		   full i18n case-insensitivity (or the active comparator
		   in future). */
		return strcmp(arg1->value.str, arg2->value.str) == 0;

	case SEARCH_MODSEQ: {
		const struct mail_search_modseq *m1 = arg1->value.modseq;
		const struct mail_search_modseq *m2 = arg2->value.modseq;

		return m1->modseq == m2->modseq &&
			m1->type == m2->type;
	}
	case SEARCH_INTHREAD:
		return mail_search_args_equal(arg1->value.search_args,
					      arg2->value.search_args);
	}
	i_unreached();
	return FALSE;
}

static bool mail_search_arg_equals(const struct mail_search_arg *arg1,
				   const struct mail_search_arg *arg2)
{
	while (arg1 != NULL && arg2 != NULL) {
		if (!mail_search_arg_one_equals(arg1, arg2))
			return FALSE;
		arg1 = arg1->next;
		arg2 = arg2->next;
	}
	return arg1 == NULL && arg2 == NULL;
}

bool mail_search_args_equal(const struct mail_search_args *args1,
			    const struct mail_search_args *args2)
{
	i_assert(args1->simplified == args2->simplified);
	i_assert(args1->box == args2->box);

	if (null_strcmp(args1->charset, args2->charset) != 0)
		return FALSE;

	return mail_search_arg_equals(args1->args, args2->args);
}
