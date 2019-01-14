/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "imap-base-subject.h"
#include "mail-storage-private.h"
#include "index-thread-private.h"


struct mail_thread_shadow_node {
	uint32_t first_child_idx, next_sibling_idx;
};

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
	bool reply_or_forward:1;
	/* a dummy node */
	bool dummy:1;
	/* ignore this node - it's a dummy without children */
	bool ignore:1;
};

struct thread_finish_context {
	unsigned int refcount;

	struct mail *tmp_mail;
	struct mail_thread_cache *cache;

	ARRAY(struct mail_thread_root_node) roots;
	ARRAY(struct mail_thread_shadow_node) shadow_nodes;
	unsigned int next_new_root_idx;

	bool use_sent_date:1;
	bool return_seqs:1;
};

struct mail_thread_iterate_context {
	struct thread_finish_context *ctx;

	ARRAY_TYPE(mail_thread_child_node) children;
	unsigned int next_idx;
	bool failed;
};

struct subject_gather_context {
	struct thread_finish_context *ctx;

	pool_t subject_pool;
	HASH_TABLE(char *, struct mail_thread_root_node *) subject_hash;
};

static void
add_base_subject(struct subject_gather_context *ctx, const char *subject,
		 struct mail_thread_root_node *node)
{
	struct mail_thread_root_node *hash_node;
	char *hash_subject;
	bool is_reply_or_forward;

	subject = imap_get_base_subject_cased(pool_datastack_create(), subject,
					      &is_reply_or_forward);
	/* (ii) If the thread subject is empty, skip this message. */
	if (*subject == '\0')
		return;

	/* (iii) Look up the message associated with the thread
	   subject in the subject table. */
	if (!hash_table_lookup_full(ctx->subject_hash, subject, &hash_subject,
				    &hash_node)) {
		/* (iv) If there is no message in the subject table with the
		   thread subject, add the current message and the thread
		   subject to the subject table. */
		hash_subject = p_strdup(ctx->subject_pool, subject);
		hash_table_insert(ctx->subject_hash, hash_subject, node);
	} else {
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
			hash_table_update(ctx->subject_hash, hash_subject, node);
		} else {
			node->parent_root_idx1 = hash_node->root_idx1;
		}
	}

	node->reply_or_forward = is_reply_or_forward;
}

static int mail_thread_child_node_cmp(const struct mail_thread_child_node *c1,
				      const struct mail_thread_child_node *c2)
{
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

static int mail_thread_root_node_cmp(const struct mail_thread_root_node *r1,
				     const struct mail_thread_root_node *r2)
{
	return mail_thread_child_node_cmp(&r1->node, &r2->node);
}

static uint32_t
thread_lookup_existing(struct thread_finish_context *ctx, uint32_t idx)
{
	const struct mail_thread_node *node;

	node = array_idx(&ctx->cache->thread_nodes, idx);
	i_assert(MAIL_THREAD_NODE_EXISTS(node));
	i_assert(node->uid != 0);
	return node->uid;
}

static void
thread_child_node_fill(struct thread_finish_context *ctx,
		       struct mail_thread_child_node *child)
{
	int tz;

	child->uid = thread_lookup_existing(ctx, child->idx);

	if (!mail_set_uid(ctx->tmp_mail, child->uid)) {
		/* the UID should have existed. we would have rebuild
		   the thread tree otherwise. */
		i_unreached();
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
}

static void
thread_sort_children(struct thread_finish_context *ctx, uint32_t parent_idx,
		     ARRAY_TYPE(mail_thread_child_node) *sorted_children)
{
	const struct mail_thread_shadow_node *shadows;
	struct mail_thread_child_node child;
	unsigned int count;

	i_zero(&child);
	array_clear(sorted_children);

	/* add all child indexes to the array */
	shadows = array_get(&ctx->shadow_nodes, &count);
	child.idx = shadows[parent_idx].first_child_idx;
	i_assert(child.idx != 0);
	if (shadows[child.idx].next_sibling_idx == 0) {
		/* only child - don't bother setting sort date */
		child.uid = thread_lookup_existing(ctx, child.idx);

		array_push_back(sorted_children, &child);
		return;
	}
	while (child.idx != 0) {
		thread_child_node_fill(ctx, &child);

		array_push_back(sorted_children, &child);
		child.idx = shadows[child.idx].next_sibling_idx;
	}

	/* sort the children */
	array_sort(sorted_children, mail_thread_child_node_cmp);
}

static void gather_base_subjects(struct thread_finish_context *ctx)
{
	struct subject_gather_context gather_ctx;
	struct mail_thread_root_node *roots;
	const char *subject;
	unsigned int i, count;
	ARRAY_TYPE(mail_thread_child_node) sorted_children;
	const struct mail_thread_child_node *children;
	uint32_t idx, uid;

	i_zero(&gather_ctx);
	gather_ctx.ctx = ctx;

	roots = array_get_modifiable(&ctx->roots, &count);
	if (count == 0)
		return;
	gather_ctx.subject_pool =
		pool_alloconly_create(MEMPOOL_GROWING"base subjects",
				      nearest_power(count * 20));
	hash_table_create(&gather_ctx.subject_hash, gather_ctx.subject_pool,
			  count * 2, str_hash, strcmp);

	i_array_init(&sorted_children, 64);
	for (i = 0; i < count; i++) {
		roots[i].root_idx1 = i + 1;
		if (!roots[i].dummy)
			idx = roots[i].node.idx;
		else if (!roots[i].ignore) {
			/* find the oldest child */
			thread_sort_children(ctx, roots[i].node.idx,
					     &sorted_children);
			children = array_front(&sorted_children);
			idx = children[0].idx;
		} else {
			/* dummy without children */
			continue;
		}

		uid = thread_lookup_existing(ctx, idx);
		if (!mail_set_uid(ctx->tmp_mail, uid)) {
			/* the UID should have existed. we would have rebuild
			   the thread tree otherwise. */
			i_unreached();
		}
		if (mail_get_first_header(ctx->tmp_mail, HDR_SUBJECT,
					  &subject) > 0) T_BEGIN {
			add_base_subject(&gather_ctx, subject, &roots[i]);
		} T_END;
	}
	i_assert(roots[count-1].parent_root_idx1 <= count);
	array_free(&sorted_children);
	hash_table_destroy(&gather_ctx.subject_hash);
	pool_unref(&gather_ctx.subject_pool);
}

static void thread_add_shadow_child(struct thread_finish_context *ctx,
				    uint32_t parent_idx, uint32_t child_idx)
{
	struct mail_thread_shadow_node *parent_shadow, *child_shadow;

	parent_shadow = array_idx_get_space(&ctx->shadow_nodes, parent_idx);
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

	shadows = array_front_modifiable(&ctx->shadow_nodes);
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
		i_zero(&new_root);
		new_root.root_idx1 = array_count(&ctx->roots) + 1;
		new_root.node.idx = ctx->next_new_root_idx++;
		new_root.dummy = TRUE;

		thread_add_shadow_child(ctx, new_root.node.idx, root->node.idx);
		thread_add_shadow_child(ctx, new_root.node.idx, cur->node.idx);

		root->parent_root_idx1 = new_root.root_idx1;
		root->ignore = TRUE;
		cur->ignore = TRUE;

		/* append last, since it breaks root and cur pointers */
		array_push_back(&ctx->roots, &new_root);

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
			roots = array_front_modifiable(&ctx->roots);
			changed = TRUE;
		}
	}

	return changed;
}

static void sort_root_nodes(struct thread_finish_context *ctx)
{
	ARRAY_TYPE(mail_thread_child_node) sorted_children;
	const struct mail_thread_child_node *children;
	const struct mail_thread_shadow_node *shadows;
	struct mail_thread_root_node *roots;
	unsigned int i, count, child_count;

	i_array_init(&sorted_children, 64);
	shadows = array_front(&ctx->shadow_nodes);
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
			thread_sort_children(ctx, roots[i].node.idx,
					     &sorted_children);
			children = array_get(&sorted_children, &child_count);
			if (child_count == 1) {
				/* only one child - deferred step (3).
				   promote the child to the root. */
				roots[i].node = children[0];
				thread_child_node_fill(ctx, &roots[i].node);
				roots[i].dummy = FALSE;
			} else {
				roots[i].node.uid = children[0].uid;
				roots[i].node.sort_date = children[0].sort_date;
			}
		} else {
			thread_child_node_fill(ctx, &roots[i].node);
		}
	}
	array_free(&sorted_children);
	array_sort(&ctx->roots, mail_thread_root_node_cmp);
}

static int mail_thread_root_node_idx_cmp(const void *key, const void *value)
{
	const uint32_t *idx = key;
	const struct mail_thread_root_node *root = value;

	return *idx < root->node.idx ? -1 :
		*idx > root->node.idx ? 1 : 0;
}

static void sort_root_nodes_ref2(struct thread_finish_context *ctx,
				 uint32_t record_count)
{
	const struct mail_thread_node *node;
	struct mail_thread_root_node *roots, *root;
	struct mail_thread_child_node child;
	const struct mail_thread_shadow_node *shadows;
	unsigned int root_count;
	uint32_t idx, parent_idx;

	roots = array_get_modifiable(&ctx->roots, &root_count);

	/* drop childless dummy nodes */
	shadows = array_front(&ctx->shadow_nodes);
	for (idx = 1; idx < root_count; idx++) {
		if (roots[idx].dummy &&
		    shadows[roots[idx].node.idx].first_child_idx == 0)
			roots[idx].ignore = TRUE;
	}

	for (idx = 1; idx < record_count; idx++) {
		node = array_idx(&ctx->cache->thread_nodes, idx);
		if (!MAIL_THREAD_NODE_EXISTS(node))
			continue;

		child.idx = idx;
		thread_child_node_fill(ctx, &child);

		parent_idx = idx;
		while (node->parent_idx != 0) {
			parent_idx = node->parent_idx;
			node = array_idx(&ctx->cache->thread_nodes,
					 node->parent_idx);
		}
		root = bsearch(&parent_idx, roots, root_count, sizeof(*roots),
			       mail_thread_root_node_idx_cmp);
		i_assert(root != NULL);

		if (root->node.sort_date < child.sort_date)
			root->node.sort_date = child.sort_date;
	}
	array_sort(&ctx->roots, mail_thread_root_node_cmp);
}

static void mail_thread_create_shadows(struct thread_finish_context *ctx,
				       uint32_t record_count)
{
	const struct mail_thread_node *node, *parent;
	struct mail_thread_root_node root;
	struct mail_thread_child_node child;
	uint32_t idx, parent_idx;

	ctx->use_sent_date = FALSE;

	i_zero(&root);
	i_zero(&child);

	/* We may see dummy messages without parents or children. We can't
	   free them since the nodes are in an array, but they may get reused
	   later so just leave them be. With the current algorithm when this
	   happens all the struct fields are always zero at that point, so
	   we don't even have to try to zero them. */
	for (idx = 1; idx < record_count; idx++) {
		node = array_idx(&ctx->cache->thread_nodes, idx);

		if (node->parent_idx == 0) {
			/* root node - add to roots list */
			root.node.idx = idx;
			if (!MAIL_THREAD_NODE_EXISTS(node)) {
				root.dummy = TRUE;
				root.node.uid = 0;
			} else {
				root.dummy = FALSE;
				root.node.uid = node->uid;
			}
			array_push_back(&ctx->roots, &root);
			continue;
		}
		i_assert(node->parent_idx < record_count);

		if (!MAIL_THREAD_NODE_EXISTS(node)) {
			/* dummy node */
			continue;
		}

		/* Find the node's first non-dummy parent and add the
		   node as its child. If there are no non-dummy
		   parents, add it as the highest dummy's child. */
		parent_idx = node->parent_idx;
		parent = array_idx(&ctx->cache->thread_nodes, parent_idx);
		while (!MAIL_THREAD_NODE_EXISTS(parent) &&
		       parent->parent_idx != 0) {
			parent_idx = parent->parent_idx;
			parent = array_idx(&ctx->cache->thread_nodes,
					   parent_idx);
		}
		thread_add_shadow_child(ctx, parent_idx, idx);
	}
}

static void mail_thread_finish(struct thread_finish_context *ctx,
			       enum mail_thread_type thread_type)
{
	unsigned int record_count = array_count(&ctx->cache->thread_nodes);

	ctx->next_new_root_idx = record_count + 1;

	/* (2) save root nodes and (3) remove dummy messages */
	i_array_init(&ctx->roots, I_MIN(128, record_count));
	i_array_init(&ctx->shadow_nodes, record_count);
	/* make sure all shadow indexes are accessible directly. */
	(void)array_idx_get_space(&ctx->shadow_nodes, record_count);

	mail_thread_create_shadows(ctx, record_count);

	/* (4) */
	ctx->use_sent_date = TRUE;
	switch (thread_type) {
	case MAIL_THREAD_REFERENCES:
		sort_root_nodes(ctx);
		/* (5) Gather together messages under the root that have
		   the same base subject text. */
		gather_base_subjects(ctx);
		/* (5.C) Merge threads with the same thread subject. */
		if (merge_subject_threads(ctx)) {
			/* root ordering may have changed, sort them again. */
			sort_root_nodes(ctx);
		}
		break;
	case MAIL_THREAD_REFS:
		sort_root_nodes_ref2(ctx, record_count);
		break;
	default:
		i_unreached();
	}
}

static void
nodes_change_uids_to_seqs(struct mail_thread_iterate_context *iter, bool root)
{
	struct mail_thread_child_node *children;
	struct mailbox *box = iter->ctx->tmp_mail->box;
	unsigned int i, count;
	uint32_t uid, seq;

	children = array_get_modifiable(&iter->children, &count);
	for (i = 0; i < count; i++) {
		uid = children[i].uid;
		if (uid == 0) {
			/* dummy root */
			if (root)
				continue;
			i_unreached();
		} else {
			mailbox_get_seq_range(box, uid, uid, &seq, &seq);
			i_assert(seq != 0);
		}
		children[i].uid = seq;
	}
}

static void
mail_thread_iterate_fill_root(struct mail_thread_iterate_context *iter)
{
	struct mail_thread_root_node *roots;
	unsigned int i, count;

	roots = array_get_modifiable(&iter->ctx->roots, &count);
	i_array_init(&iter->children, count);
	for (i = 0; i < count; i++) {
		if (!roots[i].ignore) {
			if (roots[i].dummy)
				roots[i].node.uid = 0;
			array_push_back(&iter->children, &roots[i].node);
		}
	}
}

static struct mail_thread_iterate_context *
mail_thread_iterate_children(struct mail_thread_iterate_context *parent_iter,
			     uint32_t parent_idx)
{
	struct mail_thread_iterate_context *child_iter;

	child_iter = i_new(struct mail_thread_iterate_context, 1);
	child_iter->ctx = parent_iter->ctx;
	child_iter->ctx->refcount++;

	i_array_init(&child_iter->children, 8);
	thread_sort_children(child_iter->ctx, parent_idx,
			     &child_iter->children);
	if (child_iter->ctx->return_seqs)
		nodes_change_uids_to_seqs(child_iter, FALSE);
	return child_iter;
}

struct mail_thread_iterate_context *
mail_thread_iterate_init_full(struct mail_thread_cache *cache,
			      struct mail *tmp_mail,
			      enum mail_thread_type thread_type,
			      bool return_seqs)
{
	struct mail_thread_iterate_context *iter;
	struct thread_finish_context *ctx;

	iter = i_new(struct mail_thread_iterate_context, 1);
	ctx = iter->ctx = i_new(struct thread_finish_context, 1);
	ctx->refcount = 1;
	ctx->cache = cache;
	ctx->tmp_mail = tmp_mail;
	ctx->return_seqs = return_seqs;
	mail_thread_finish(ctx, thread_type);

	mail_thread_iterate_fill_root(iter);
	if (return_seqs)
		nodes_change_uids_to_seqs(iter, TRUE);
	return iter;
}

const struct mail_thread_child_node *
mail_thread_iterate_next(struct mail_thread_iterate_context *iter,
			 struct mail_thread_iterate_context **child_iter_r)
{
	const struct mail_thread_child_node *children, *child;
	const struct mail_thread_shadow_node *shadow;
	unsigned int count;

	children = array_get(&iter->children, &count);
	if (iter->next_idx >= count)
		return NULL;

	child = &children[iter->next_idx++];
	shadow = array_idx(&iter->ctx->shadow_nodes, child->idx);
	*child_iter_r = shadow->first_child_idx == 0 ? NULL :
		mail_thread_iterate_children(iter, child->idx);
	if (child->uid == 0 && *child_iter_r == NULL) {
		/* this is a dummy node without children,
		   there's no point in returning it */
		return mail_thread_iterate_next(iter, child_iter_r);
	}
	return child;
}

unsigned int mail_thread_iterate_count(struct mail_thread_iterate_context *iter)
{
	return array_count(&iter->children);
}

int mail_thread_iterate_deinit(struct mail_thread_iterate_context **_iter)
{
	struct mail_thread_iterate_context *iter = *_iter;

	*_iter = NULL;

	if (--iter->ctx->refcount == 0) {
		array_free(&iter->ctx->roots);
		array_free(&iter->ctx->shadow_nodes);
		i_free(iter->ctx);
	}
	array_free(&iter->children);
	i_free(iter);
	return 0;
}
