/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "str.h"
#include "ostream.h"
#include "imap-base-subject.h"
#include "imap-thread-private.h"

#include <stdlib.h>

#define STR_FLUSH_LENGTH 512

struct mail_thread_shadow_node {
	uint32_t first_child_idx, next_sibling_idx;
};

struct mail_thread_child_node {
	uint32_t idx;
	uint32_t uid;
	time_t sort_date;
};
ARRAY_DEFINE_TYPE(mail_thread_child_node, struct mail_thread_child_node);

struct mail_thread_root_node {
	/* node.idx usually points to indexes from mail hash. However
	   REFERENCES step (5) may add temporary dummy roots. They use larger
	   index numbers than exist in the hash. */
	struct mail_thread_child_node node;

	/* Used temporarily by (5)(B) base subject gathering.
	   root_idx1 is node's index in roots[] array + 1.
	   parent_root_idx points to root_idx1, or 0 for root. */
	unsigned int root_idx1;
	uint32_t parent_root_idx1;

	/* subject contained a Re: or Fwd: */
	unsigned int reply_or_forward:1;
	/* a dummy node */
	unsigned int dummy:1;
	/* ignore this node - it's a dummy without children */
	unsigned int ignore:1;
};

struct thread_finish_context {
	struct mailbox *box;
	struct ostream *output;

	struct mail *tmp_mail;
	struct mail_hash_transaction *hash_trans;

	ARRAY_DEFINE(roots, struct mail_thread_root_node);
	ARRAY_DEFINE(shadow_nodes, struct mail_thread_shadow_node);
	unsigned int next_new_root_idx;

	unsigned int id_is_uid:1;
	unsigned int use_sent_date:1;
	unsigned int flushed:1;
};

struct subject_gather_context {
	struct thread_finish_context *ctx;

	pool_t subject_pool;
	struct hash_table *subject_hash;
};

static void
add_base_subject(struct subject_gather_context *ctx, const char *subject,
		 struct mail_thread_root_node *node)
{
	struct mail_thread_root_node *hash_node;
	char *hash_subject;
	void *key, *value;
	bool is_reply_or_forward;

	subject = imap_get_base_subject_cased(pool_datastack_create(), subject,
					      &is_reply_or_forward);
	/* (ii) If the thread subject is empty, skip this message. */
	if (*subject == '\0')
		return;

	/* (iii) Look up the message associated with the thread
	   subject in the subject table. */
	if (!hash_lookup_full(ctx->subject_hash, subject, &key, &value)) {
		/* (iv) If there is no message in the subject table with the
		   thread subject, add the current message and the thread
		   subject to the subject table. */
		hash_subject = p_strdup(ctx->subject_pool, subject);
		hash_insert(ctx->subject_hash, hash_subject, node);
	} else {
		hash_subject = key;
		hash_node = value;

		/* Otherwise, if the message in the subject table is not a
		   dummy, AND either of the following criteria are true:

		     The current message is a dummy, OR

                     The message in the subject table is a reply or forward
		     and the current message is not.

		   then replace the message in the subject table with the
		   current message. */
		if (!hash_node->dummy &&
		    (node->dummy ||
		     (hash_node->reply_or_forward && !is_reply_or_forward))) {
			hash_node->parent_root_idx1 = node->root_idx1;
			hash_update(ctx->subject_hash, hash_subject, node);
		} else {
			node->parent_root_idx1 = hash_node->root_idx1;
		}
	}

	node->reply_or_forward = is_reply_or_forward;
}

static int mail_thread_child_node_cmp(const void *p1, const void *p2)
{
	const struct mail_thread_child_node *c1 = p1, *c2 = p2;

	if (c1->sort_date < c2->sort_date)
		return -1;
	if (c1->sort_date > c2->sort_date)
		return 1;

	if (c1->uid < c2->uid)
		return -1;
	if (c1->uid > c2->uid)
		return 1;
	return 0;
}

static int
thread_child_node_fill(struct thread_finish_context *ctx,
		       struct mail_thread_child_node *child)
{
	const struct mail_thread_node *node;
	int tz;

	node = mail_hash_lookup_idx(ctx->hash_trans, child->idx);
	i_assert(node->uid != 0 && node->exists);
	child->uid = node->uid;

	if (!mail_set_uid(ctx->tmp_mail, child->uid)) {
		/* the UID should have existed. we would have rebuild
		   the thread tree otherwise. */
		mail_hash_transaction_set_corrupted(ctx->hash_trans,
			t_strdup_printf("Found expunged UID %u", child->uid));
		return -1;
	}

	/* get sent date if we want to use it and if it's valid */
	if (!ctx->use_sent_date)
		child->sort_date = 0;
	else if (mail_get_date(ctx->tmp_mail, &child->sort_date, &tz) < 0)
		child->sort_date = 0;

	if (child->sort_date == 0) {
		/* fallback to received date */
		(void)mail_get_received_date(ctx->tmp_mail, &child->sort_date);
	}
	return 0;
}

static int
thread_sort_children(struct thread_finish_context *ctx, uint32_t parent_idx,
		     ARRAY_TYPE(mail_thread_child_node) *sorted_children)
{
	const struct mail_thread_shadow_node *shadows;
	const struct mail_thread_node *node;
	struct mail_thread_child_node child, *children;
	unsigned int count;

	memset(&child, 0, sizeof(child));
	array_clear(sorted_children);

	/* add all child indexes to the array */
	shadows = array_get(&ctx->shadow_nodes, &count);
	child.idx = shadows[parent_idx].first_child_idx;
	i_assert(child.idx != 0);
	if (shadows[child.idx].next_sibling_idx == 0) {
		/* only child - don't bother setting sort date */
		node = mail_hash_lookup_idx(ctx->hash_trans, child.idx);
		i_assert(node->uid != 0 && node->exists);
		child.uid = node->uid;

		array_append(sorted_children, &child, 1);
		return 0;
	}
	while (child.idx != 0) {
		if (thread_child_node_fill(ctx, &child) < 0)
			return -1;

		array_append(sorted_children, &child, 1);
		child.idx = shadows[child.idx].next_sibling_idx;
	}

	/* sort the children */
	children = array_get_modifiable(sorted_children, &count);
	qsort(children, count, sizeof(*children), mail_thread_child_node_cmp);
	return 0;
}

static int gather_base_subjects(struct thread_finish_context *ctx)
{
	struct subject_gather_context gather_ctx;
	struct mail_thread_root_node *roots;
	const struct mail_thread_node *node;
	const char *subject;
	unsigned int i, count;
	ARRAY_TYPE(mail_thread_child_node) sorted_children;
	const struct mail_thread_child_node *children;
	uint32_t idx;
	int ret = 0;

	memset(&gather_ctx, 0, sizeof(gather_ctx));
	gather_ctx.ctx = ctx;

	roots = array_get_modifiable(&ctx->roots, &count);
	gather_ctx.subject_pool =
		pool_alloconly_create(MEMPOOL_GROWING"base subjects",
				      nearest_power(count * 20));
	gather_ctx.subject_hash =
		hash_create(default_pool, gather_ctx.subject_pool, count * 2,
			    str_hash, (hash_cmp_callback_t *)strcmp);

	i_array_init(&sorted_children, 64);
	for (i = 0; i < count; i++) {
		roots[i].root_idx1 = i + 1;
		if (!roots[i].dummy)
			idx = roots[i].node.idx;
		else if (!roots[i].ignore) {
			/* find the oldest child */
			if (thread_sort_children(ctx, roots[i].node.idx,
						 &sorted_children) < 0) {
				ret = -1;
				break;
			}
			children = array_idx(&sorted_children, 0);
			idx = children[0].idx;
		} else {
			/* dummy without children */
			continue;
		}

		node = mail_hash_lookup_idx(ctx->hash_trans, idx);
		i_assert(node->uid != 0 && node->exists);

		if (!mail_set_uid(ctx->tmp_mail, node->uid)) {
			/* the UID should have existed. we would have rebuild
			   the thread tree otherwise. */
			mail_hash_transaction_set_corrupted(
				ctx->hash_trans, "Found expunged UID");
			ret = -1;
			break;
		}
		if (mail_get_first_header(ctx->tmp_mail, HDR_SUBJECT,
					  &subject) > 0) T_BEGIN {
			add_base_subject(&gather_ctx, subject, &roots[i]);
		} T_END;
	}
	i_assert(roots[count-1].parent_root_idx1 <= count);
	array_free(&sorted_children);
	hash_destroy(&gather_ctx.subject_hash);
	pool_unref(&gather_ctx.subject_pool);

	return ret;
}

static void thread_add_shadow_child(struct thread_finish_context *ctx,
				    uint32_t parent_idx, uint32_t child_idx)
{
	struct mail_thread_shadow_node *parent_shadow, *child_shadow;

	parent_shadow = array_idx_modifiable(&ctx->shadow_nodes, parent_idx);
	child_shadow = array_idx_modifiable(&ctx->shadow_nodes, child_idx);

	child_shadow->next_sibling_idx = parent_shadow->first_child_idx;
	parent_shadow->first_child_idx = child_idx;
}

static void mail_thread_root_thread_merge(struct thread_finish_context *ctx,
					  struct mail_thread_root_node *cur)
{
	struct mail_thread_root_node *roots, *root, new_root;
	struct mail_thread_shadow_node *shadows;
	unsigned int count;
	uint32_t idx, next_idx;

	i_assert(cur->parent_root_idx1 != 0);

	/* The highest parent is the same as the current message in the
	   subject table. */
	roots = array_get_modifiable(&ctx->roots, &count);
	root = cur;
	do {
		i_assert(root->parent_root_idx1 <= count);
		root = &roots[root->parent_root_idx1 - 1];
	} while (root->parent_root_idx1 != 0);
	i_assert(!root->ignore);

	shadows = array_idx_modifiable(&ctx->shadow_nodes, 0);
	if (cur->dummy) {
		/* If both messages are dummies, append the current
                   message's children to the children of the message in
		   the subject table (the children of both messages
		   become siblings), and then delete the current message. */
		i_assert(root->dummy);

		idx = shadows[cur->node.idx].first_child_idx;
		while (idx != 0) {
			next_idx = shadows[idx].next_sibling_idx;
			thread_add_shadow_child(ctx, root->node.idx, idx);
			idx = next_idx;
		}

		shadows[cur->node.idx].first_child_idx = 0;
		cur->ignore = TRUE;
	} else if (root->dummy || (cur->reply_or_forward &&
				   !root->reply_or_forward)) {
		/* a) If the message in the subject table is a dummy and the
		   current message is not, make the current message a
		   child of the message in the subject table (a sibling
		   of its children).

		   b) If the current message is a reply or forward and the
		   message in the subject table is not, make the current
		   message a child of the message in the subject table (a
		   sibling of its children). */
		thread_add_shadow_child(ctx, root->node.idx, cur->node.idx);
		cur->ignore = TRUE;
	} else  {
		/* Otherwise, create a new dummy message and make both
		   the current message and the message in the subject
		   table children of the dummy.  Then replace the message
                   in the subject table with the dummy message. */
		memset(&new_root, 0, sizeof(new_root));
		new_root.root_idx1 = array_count(&ctx->roots) + 1;
		new_root.node.idx = ctx->next_new_root_idx++;
		new_root.dummy = TRUE;
		array_append(&ctx->roots, &new_root, 1);

		thread_add_shadow_child(ctx, new_root.node.idx, root->node.idx);
		thread_add_shadow_child(ctx, new_root.node.idx, cur->node.idx);

		root->parent_root_idx1 = new_root.root_idx1;
		root->ignore = TRUE;
		cur->ignore = TRUE;

		/* make sure all shadow indexes are accessible directly */
		(void)array_idx_modifiable(&ctx->shadow_nodes,
					   new_root.node.idx);
	}
}

static bool merge_subject_threads(struct thread_finish_context *ctx)
{
	struct mail_thread_root_node *roots;
	unsigned int i, count;
	bool changed = FALSE;

	roots = array_get_modifiable(&ctx->roots, &count);
	for (i = 0; i < count; i++) {
		if (roots[i].parent_root_idx1 != 0 && !roots[i].ignore) {
			mail_thread_root_thread_merge(ctx, &roots[i]);
			/* more roots may have been added */
			roots = array_idx_modifiable(&ctx->roots, 0);
			changed = TRUE;
		}
	}

	return changed;
}

static int sort_root_nodes(struct thread_finish_context *ctx)
{
	ARRAY_TYPE(mail_thread_child_node) sorted_children;
	const struct mail_thread_child_node *children;
	const struct mail_thread_shadow_node *shadows;
	struct mail_thread_root_node *roots;
	unsigned int i, count, child_count;
	int ret = 0;

	i_array_init(&sorted_children, 64);
	shadows = array_idx(&ctx->shadow_nodes, 0);
	roots = array_get_modifiable(&ctx->roots, &count);
	for (i = 0; i < count; i++) {
		if (roots[i].ignore)
			continue;
		if (roots[i].dummy) {
			/* sort by the first child */
			if (shadows[roots[i].node.idx].first_child_idx == 0) {
				/* childless dummy node */
				roots[i].ignore = TRUE;
				continue;
			}
			if (thread_sort_children(ctx, roots[i].node.idx,
						 &sorted_children) < 0) {
				ret = -1;
				break;
			}
			children = array_get(&sorted_children, &child_count);
			if (child_count == 1) {
				/* only one child - deferred step (3).
				   promote the child to the root. */
				roots[i].node = children[0];
				if (thread_child_node_fill(ctx,
							   &roots[i].node) < 0)
					return -1;
				roots[i].dummy = FALSE;
			} else {
				roots[i].node.uid = children[0].uid;
				roots[i].node.sort_date = children[0].sort_date;
			}
		} else {
			if (thread_child_node_fill(ctx, &roots[i].node) < 0) {
				ret = -1;
				break;
			}
		}
	}
	array_free(&sorted_children);
	if (ret < 0)
		return -1;

	qsort(roots, count, sizeof(*roots), mail_thread_child_node_cmp);
	return 0;
}

static int
str_add_id(struct thread_finish_context *ctx, string_t *str, uint32_t uid)
{
	i_assert(uid != 0);

	if (!ctx->id_is_uid) {
		mailbox_get_uids(ctx->box, uid, uid, &uid, &uid);
		if (uid == 0) {
			mail_hash_transaction_set_corrupted(ctx->hash_trans,
				t_strdup_printf("Found expunged UID %u", uid));
			return -1;
		}
	}
	str_printfa(str, "%u", uid);

	if (str_len(str) >= STR_FLUSH_LENGTH) {
		(void)o_stream_send(ctx->output, str_data(str), str_len(str));
		str_truncate(str, 0);
		ctx->flushed = TRUE;
	}
	return 0;
}

static int send_nodes(struct thread_finish_context *ctx, string_t *str,
		      uint32_t parent_idx)
{
	ARRAY_TYPE(mail_thread_child_node) sorted_children;
	const struct mail_thread_child_node *children;
	const struct mail_thread_shadow_node *shadows;
	unsigned int i, child_count;
	uint32_t idx;
	int ret;

	t_array_init(&sorted_children, 8);
	if (thread_sort_children(ctx, parent_idx, &sorted_children) < 0)
		return -1;

	shadows = array_idx(&ctx->shadow_nodes, 0);
	children = array_get(&sorted_children, &child_count);
	if (child_count == 1) {
		/* only one child - special case to avoid extra paranthesis */
		if (str_add_id(ctx, str, children[0].uid) < 0)
			return -1;
		idx = children[0].idx;
		if (shadows[idx].first_child_idx != 0) {
			str_append_c(str, ' ');
			T_BEGIN {
				ret = send_nodes(ctx, str, idx);
			} T_END;
			if (ret < 0)
				return -1;
		}
		return 0;
	}

	for (i = 0; i < child_count; i++) {
		idx = children[i].idx;

		if (shadows[idx].first_child_idx == 0) {
			/* no children */
			str_append_c(str, '(');
			if (str_add_id(ctx, str, children[i].uid) < 0)
				return -1;
			str_append_c(str, ')');
		} else {
			/* node with children */
			str_append_c(str, '(');
			if (str_add_id(ctx, str, children[i].uid) < 0)
				return -1;
			str_append_c(str, ' ');
			T_BEGIN {
				ret = send_nodes(ctx, str, idx);
			} T_END;
			if (ret < 0)
				return -1;
			str_append_c(str, ')');
		}
	}
	return 0;
}

static int send_root(struct thread_finish_context *ctx, string_t *str,
		     const struct mail_thread_root_node *root)
{
	const struct mail_thread_shadow_node *shadow;
	const struct mail_thread_node *node;
	int ret;

	str_append_c(str, '(');
	if (!root->dummy) {
		node = mail_hash_lookup_idx(ctx->hash_trans, root->node.idx);
		i_assert(node->uid != 0 && node->exists);
		if (str_add_id(ctx, str, node->uid) < 0)
			return -1;
	}

	shadow = array_idx(&ctx->shadow_nodes, root->node.idx);
	if (shadow->first_child_idx != 0) {
		if (!root->dummy)
			str_append_c(str, ' ');

		T_BEGIN {
			ret = send_nodes(ctx, str, root->node.idx);
		} T_END;
		if (ret < 0)
			return -1;
	}

	str_append_c(str, ')');
	return 0;
}

static int send_roots(struct thread_finish_context *ctx)
{
	const struct mail_thread_root_node *roots;
	unsigned int i, count;
	string_t *str;
	int ret = 0;

	str = str_new(default_pool, STR_FLUSH_LENGTH + 32);
	str_append(str, "* THREAD ");

	roots = array_get(&ctx->roots, &count);
	for (i = 0; i < count; i++) {
		if (!roots[i].ignore) {
			if (send_root(ctx, str, &roots[i]) < 0) {
				ret = -1;
				break;
			}
		}
	}

	if (ret == 0) {
		str_append(str, "\r\n");
		(void)o_stream_send(ctx->output, str_data(str), str_len(str));
	} else if (ctx->flushed) {
		o_stream_close(ctx->output);
	}
	str_free(&str);
	return ret;
}

int mail_thread_finish(struct mail *tmp_mail,
		       struct mail_hash_transaction *hash_trans,
		       enum mail_thread_type thread_type,
		       struct ostream *output, bool id_is_uid)
{
	struct thread_finish_context ctx;
	const struct mail_hash_header *hdr;
	struct mail_thread_node *node, *parent;
	struct mail_thread_root_node root;
	ARRAY_TYPE(uint32_t) free_indexes;
	const uint32_t *indexes;
	uint32_t idx, parent_idx;
	unsigned int i, count;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.box = tmp_mail->box;
	ctx.output = output;
	ctx.tmp_mail = tmp_mail;
	ctx.hash_trans = hash_trans;
	ctx.id_is_uid = id_is_uid;
	ctx.use_sent_date = thread_type == MAIL_THREAD_REFERENCES;

	hdr = mail_hash_get_header(ctx.hash_trans);
	if (hdr->record_count == 0)
		return 0;
	ctx.next_new_root_idx = hdr->record_count + 1;

	/* (2) save root nodes and (3) remove dummy messages */
	memset(&root, 0, sizeof(root));
	i_array_init(&free_indexes, 128);
	i_array_init(&ctx.roots, I_MIN(128, hdr->record_count));
	i_array_init(&ctx.shadow_nodes, hdr->record_count);
	for (idx = 1; idx < hdr->record_count; idx++) {
		node = mail_hash_lookup_idx(ctx.hash_trans, idx);
		if (MAIL_HASH_RECORD_IS_DELETED(&node->rec))
			continue;

		if (thread_node_is_root(node)) {
			/* node is a duplicate root, free it later */
			array_append(&free_indexes, &idx, 1);
			continue;
		}
		parent = node->parent_idx == 0 ? NULL :
			mail_hash_lookup_idx(ctx.hash_trans, node->parent_idx);
		if (thread_node_is_root(parent)) {
			if (parent != NULL) {
				/* parent is a duplicate root. replace it with
				   the real root. */
				node->parent_idx = 0;
				mail_hash_update(ctx.hash_trans, idx);
			}
			root.node.idx = idx;
			root.dummy = !node->exists;
			array_append(&ctx.roots, &root, 1);
		} else if (node->exists) {
			/* Find the node's first non-dummy parent and add the
			   node as its child. If there are no non-dummy
			   parents, add it as the highest dummy's child. */
			parent_idx = node->parent_idx;
			while (!parent->exists && parent->parent_idx != 0) {
				parent_idx = parent->parent_idx;
				parent = mail_hash_lookup_idx(ctx.hash_trans,
							      parent_idx);
			}
			thread_add_shadow_child(&ctx, parent_idx, idx);
		}
	}
	/* make sure all shadow indexes are accessible directly */
	(void)array_idx_modifiable(&ctx.shadow_nodes, hdr->record_count);

	indexes = array_get(&free_indexes, &count);
	for (i = 0; i < count; i++) {
		node = mail_hash_lookup_idx(ctx.hash_trans, indexes[i]);
		mail_hash_remove(ctx.hash_trans, indexes[i],
				 node->msgid_crc32);
	}
	array_free(&free_indexes);

	/* (4) */
	if (sort_root_nodes(&ctx) < 0)
		return -1;
	if (thread_type == MAIL_THREAD_REFERENCES) {
		/* (5) Gather together messages under the root that have
		   the same base subject text. */
		if (gather_base_subjects(&ctx) < 0)
			return -1;

		/* (5.C) Merge threads with the same thread subject. */
		if (merge_subject_threads(&ctx)) {
			/* root ordering may have changed, sort them again. */
			if (sort_root_nodes(&ctx) < 0)
				return -1;
		}
	}

	/* (6) Sort children and send replies */
	T_BEGIN {
		ret = send_roots(&ctx);
	} T_END;
	return ret;
}
