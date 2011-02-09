/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "hash.h"
#include "imap-match.h"
#include "mail-index.h"
#include "mail-storage.h"
#include "mail-storage-hooks.h"
#include "mailbox-list-subscriptions.h"
#include "index-mailbox-list.h"

struct index_mailbox_list_sync_context {
	struct index_mailbox_list *ilist;
	char sep[2];
	uint32_t next_uid;

	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
};

struct index_mailbox_list_module index_mailbox_list_module =
	MODULE_CONTEXT_INIT(&mailbox_list_module_register);

static int index_mailbox_list_read(struct index_mailbox_list *ilist,
				   struct mail_index_view *view, bool force);

static void index_mailbox_list_reset(struct index_mailbox_list *ilist)
{
	hash_table_clear(ilist->mailbox_names, FALSE);
	hash_table_clear(ilist->mailbox_hash, FALSE);
	p_clear(ilist->mailbox_pool);
	ilist->mailbox_tree = NULL;
	ilist->highest_name_id = 0;
	ilist->sync_log_file_seq = 0;
	ilist->sync_log_file_offset = 0;
}

static struct index_mailbox_node *
index_mailbox_node_find_sibling(struct index_mailbox_node *node,
				const char *name)
{
	while (node != NULL) {
		if (strcmp(node->name, name) == 0)
			return node;
		node = node->next;
	}
	return NULL;
}

static void
index_mailbox_node_add_to_index(struct index_mailbox_list_sync_context *ctx,
				struct index_mailbox_node *node,
				uint32_t *name_id_r, uint32_t *seq_r)
{
	struct mailbox_list_index_record irec;
	uint32_t seq;

	memset(&irec, 0, sizeof(irec));
	irec.name_id = node->name_id;
	if (node->parent != NULL)
		irec.parent_uid = node->parent->uid;

	mail_index_append(ctx->trans, node->uid, &seq);
	mail_index_update_flags(ctx->trans, seq, MODIFY_REPLACE,
		(enum mail_flags)MAILBOX_LIST_INDEX_FLAG_NONEXISTENT);
	mail_index_update_ext(ctx->trans, seq, ctx->ilist->ext_id, &irec, NULL);

	*name_id_r = irec.name_id;
	*seq_r = seq;
}

static struct index_mailbox_node *
index_mailbox_node_add(struct index_mailbox_list_sync_context *ctx,
		       struct index_mailbox_node *parent, const char *name,
		       uint32_t *seq_r)
{
	struct index_mailbox_node *node;
	uint32_t name_id;
	char *dup_name;

	node = p_new(ctx->ilist->mailbox_pool, struct index_mailbox_node, 1);
	node->flags = MAILBOX_LIST_INDEX_FLAG_NONEXISTENT |
		MAILBOX_LIST_INDEX_FLAG_MARKED;
	node->name = dup_name = p_strdup(ctx->ilist->mailbox_pool, name);
	node->name_id = ++ctx->ilist->highest_name_id;
	node->uid = ctx->next_uid++;

	if (parent != NULL) {
		node->parent = parent;
		node->next = parent->children;
		parent->children = node;
	} else {
		node->next = ctx->ilist->mailbox_tree;
		ctx->ilist->mailbox_tree = node;
	}

	index_mailbox_node_add_to_index(ctx, node, &name_id, seq_r);
	hash_table_insert(ctx->ilist->mailbox_hash,
			  POINTER_CAST(node->uid), node);
	hash_table_insert(ctx->ilist->mailbox_names,
			  POINTER_CAST(name_id), dup_name);
	return node;
}

struct index_mailbox_node *
index_mailbox_list_lookup(struct mailbox_list *list, const char *vname)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);
	struct index_mailbox_node *node;

	(void)index_mailbox_list_refresh(list);

	T_BEGIN {
		const char *const *path;
		unsigned int i;
		char sep[2];

		sep[0] = mail_namespace_get_sep(list->ns); sep[1] = '\0';
		path = t_strsplit(vname, sep);
		node = ilist->mailbox_tree;
		for (i = 0;; i++) {
			node = index_mailbox_node_find_sibling(node, path[i]);
			if (node == NULL || path[i+1] == NULL)
				break;
			node = node->children;
		}
	} T_END;

	return node;
}

static uint32_t
index_mailbox_list_sync_name(struct index_mailbox_list_sync_context *ctx,
			     const char *name,
			     enum mailbox_list_index_flags flags)
{
	const char *const *path;
	struct index_mailbox_node *node, *parent;
	unsigned int i;
	uint32_t seq = 0;

	path = t_strsplit(name, ctx->sep);
	node = ctx->ilist->mailbox_tree; parent = NULL;
	for (i = 0; path[i] != NULL; i++) {
		node = index_mailbox_node_find_sibling(node, path[i]);
		if (node == NULL)
			break;
		node->flags |= MAILBOX_LIST_INDEX_FLAG_MARKED;
		parent = node;
		node = node->children;
	}

	node = parent;
	if (path[i] == NULL) {
		if (!mail_index_lookup_seq(ctx->view, node->uid, &seq))
			i_panic("mailbox list index: lost uid=%u", node->uid);
	} else {
		for (; path[i] != NULL; i++)
			node = index_mailbox_node_add(ctx, node, path[i], &seq);
	}

	node->flags = flags | MAILBOX_LIST_INDEX_FLAG_MARKED;
	return seq;
}

static void get_existing_name_ids(ARRAY_TYPE(uint32_t) *ids,
				  const struct index_mailbox_node *node)
{
	for (; node != NULL; node = node->next) {
		if ((node->flags & MAILBOX_LIST_INDEX_FLAG_MARKED) != 0) {
			if (node->children != NULL)
				get_existing_name_ids(ids, node->children);
			array_append(ids, &node->name_id, 1);
		}
	}
}

static int uint32_cmp(const uint32_t *p1, const uint32_t *p2)
{
	return *p1 < *p2 ? -1 :
		(*p1 > *p2 ? 1 : 0);
}

static void
index_mailbox_list_sync_names(struct index_mailbox_list_sync_context *ctx)
{
	struct index_mailbox_list *ilist = ctx->ilist;
	ARRAY_TYPE(uint32_t) existing_name_ids;
	buffer_t *buf;
	struct mailbox_list_index_header *hdr;
	const void *ext_data;
	size_t ext_size;
	const char *name;
	const uint32_t *id_p;
	uint32_t prev_id = 0;

	t_array_init(&existing_name_ids, 64);
	get_existing_name_ids(&existing_name_ids, ilist->mailbox_tree);
	array_sort(&existing_name_ids, uint32_cmp);

	buf = buffer_create_dynamic(pool_datastack_create(), 1024);
	hdr = buffer_append_space_unsafe(buf, sizeof(*hdr));

	array_foreach(&existing_name_ids, id_p) {
		if (*id_p != prev_id) {
			buffer_append(buf, id_p, sizeof(*id_p));
			name = hash_table_lookup(ilist->mailbox_names,
						 POINTER_CAST(*id_p));
			buffer_append(buf, name, strlen(name) + 1);
			prev_id = *id_p;
		}
	}
	buffer_append_zero(buf, sizeof(*id_p));

	mail_index_get_header_ext(ctx->view, ilist->ext_id,
				  &ext_data, &ext_size);
	if (nearest_power(ext_size) != nearest_power(buf->used)) {
		mail_index_ext_resize(ctx->trans, ilist->ext_id,
				      nearest_power(buf->used),
				      sizeof(struct mailbox_list_index_record),
				      sizeof(uint32_t));
	}
	mail_index_update_header_ext(ctx->trans, ilist->ext_id,
				     0, buf->data, buf->used);
}

static void
index_mailbox_list_node_unmark_recursive(struct index_mailbox_node *node)
{
	while (node != NULL) {
		if (node->children != NULL)
			index_mailbox_list_node_unmark_recursive(node->children);

		node->flags &= ~MAILBOX_LIST_INDEX_FLAG_MARKED;
		node = node->next;
	}
}

static void
index_mailbox_node_unlink(struct index_mailbox_list_sync_context *sync_ctx,
			  struct index_mailbox_node *node)
{
	struct index_mailbox_node **prev;

	prev = node->parent == NULL ?
		&sync_ctx->ilist->mailbox_tree : &node->parent;

	while (*prev != node)
		prev = &(*prev)->next;
	*prev = node->next;
}

static void
index_mailbox_nodes_expunge(struct index_mailbox_list_sync_context *sync_ctx,
			    struct index_mailbox_node *node)
{
	uint32_t seq;

	while (node != NULL) {
		if (node->children != NULL)
			index_mailbox_nodes_expunge(sync_ctx, node->children);

		if ((node->flags & MAILBOX_LIST_INDEX_FLAG_MARKED) == 0) {
			if (mail_index_lookup_seq(sync_ctx->view, node->uid,
						  &seq))
				mail_index_expunge(sync_ctx->trans, seq);
			index_mailbox_node_unlink(sync_ctx, node);
		}
		node = node->next;
	}
}

static int index_mailbox_list_sync(struct mailbox_list *list)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);
	struct index_mailbox_list_sync_context sync_ctx;
	struct mailbox_list_iterate_context *iter;
	const struct mail_index_header *hdr;
	const struct mailbox_info *info;
	const char *patterns[2];
	enum mailbox_list_index_flags flags;
	uint32_t seq, orig_highest_name_id;
	int ret = 0;

	index_mailbox_list_reset(ilist);

	memset(&sync_ctx, 0, sizeof(sync_ctx));
	sync_ctx.ilist = ilist;
	sync_ctx.sep[0] = mail_namespace_get_sep(list->ns);
	if (mail_index_sync_begin(ilist->index, &sync_ctx.sync_ctx,
				  &sync_ctx.view, &sync_ctx.trans,
				  MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES) < 0)
		return -1;

	if (index_mailbox_list_read(ilist, sync_ctx.view, TRUE) < 0) {
		mail_index_sync_rollback(&sync_ctx.sync_ctx);
		return -1;
	}
	orig_highest_name_id = ilist->highest_name_id;

	hdr = mail_index_get_header(sync_ctx.view);
	sync_ctx.next_uid = hdr->next_uid;

	if (hdr->uid_validity == 0) {
		uint32_t uid_validity = ioloop_time;

		mail_index_update_header(sync_ctx.trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}

	index_mailbox_list_node_unmark_recursive(ilist->mailbox_tree);

	patterns[0] = "*"; patterns[1] = NULL;
	iter = ilist->module_ctx.super.iter_init(list, patterns, 0);
	while ((info = ilist->module_ctx.super.iter_next(iter)) != NULL) {
		flags = 0;
		if ((info->flags & MAILBOX_NONEXISTENT) != 0)
			flags |= MAILBOX_LIST_INDEX_FLAG_NONEXISTENT;
		if ((info->flags & MAILBOX_NOSELECT) != 0)
			flags |= MAILBOX_LIST_INDEX_FLAG_NOSELECT;
		if ((info->flags & MAILBOX_NOINFERIORS) != 0)
			flags |= MAILBOX_LIST_INDEX_FLAG_NOINFERIORS;

		T_BEGIN {
			seq = index_mailbox_list_sync_name(&sync_ctx,
					info->name, (enum mail_flags)flags);
		} T_END;

		mail_index_update_flags(sync_ctx.trans, seq,
					MODIFY_REPLACE, flags);
	}
	if (ilist->module_ctx.super.iter_deinit(iter) < 0)
		ret = -1;

	if (ret < 0) {
		mail_index_sync_rollback(&sync_ctx.sync_ctx);
		return -1;
	}

	index_mailbox_nodes_expunge(&sync_ctx, ilist->mailbox_tree);

	if (orig_highest_name_id != ilist->highest_name_id) {
		/* new names added */
		T_BEGIN {
			index_mailbox_list_sync_names(&sync_ctx);
		} T_END;
	} else {
		struct mailbox_list_index_header new_hdr;

		new_hdr.refresh_flag = 0;
		mail_index_update_header_ext(sync_ctx.trans, ilist->ext_id,
			offsetof(struct mailbox_list_index_header, refresh_flag),
			&new_hdr.refresh_flag, sizeof(new_hdr.refresh_flag));
	}

	return mail_index_sync_commit(&sync_ctx.sync_ctx);
}

static int index_mailbox_list_parse_header(struct index_mailbox_list *ilist,
					   struct mail_index_view *view)
{
	const struct mailbox_list_index_header *hdr;
	const void *data, *p;
	size_t i, len, size;
	uint32_t id, prev_id = 0;
	char *name;

	mail_index_get_header_ext(view, ilist->ext_id, &data, &size);
	if (size == 0)
		return 0;

	hdr = data;
	for (i = sizeof(*hdr); i < size; ) {
		/* get id */
		if (i + sizeof(id) > size)
			return -1;
		memcpy(&id, CONST_PTR_OFFSET(data, i), sizeof(id));
		i += sizeof(id);

		if (id <= prev_id) {
			/* allow extra space in the end as long as last id=0 */
			return id == 0 ? 0 : -1;
		}

		/* get name */
		p = memchr(CONST_PTR_OFFSET(data, i), '\0', size-i);
		if (p == NULL)
			return -1;
		len = (const char *)p -
			(const char *)(CONST_PTR_OFFSET(data, i));

		name = p_strndup(ilist->mailbox_pool,
				 CONST_PTR_OFFSET(data, i), len);
		i += len + 1;

		/* add id => name to hash table */
		hash_table_insert(ilist->mailbox_names, POINTER_CAST(id), name);
		ilist->highest_name_id = id;
	}
	i_assert(i == size);
	return 0;
}

static int index_mailbox_list_parse_records(struct index_mailbox_list *ilist,
					    struct mail_index_view *view)
{
	struct index_mailbox_node *node;
	const struct mail_index_record *rec;
	const struct mailbox_list_index_record *irec;
	const void *data;
	bool expunged;
	uint32_t seq, count;

	count = mail_index_view_get_messages_count(view);
	for (seq = 1; seq <= count; seq++) {
		node = p_new(ilist->mailbox_pool, struct index_mailbox_node, 1);
		rec = mail_index_lookup(view, seq);
		node->uid = rec->uid;
		node->flags = rec->flags;

		mail_index_lookup_ext(view, seq, ilist->ext_id,
				      &data, &expunged);
		if (data == NULL)
			return -1;
		irec = data;

		node->name_id = irec->name_id;
		node->name = hash_table_lookup(ilist->mailbox_names,
					       POINTER_CAST(irec->name_id));
		if (node->name == NULL)
			return -1;

		if (irec->parent_uid != 0) {
			node->parent = hash_table_lookup(ilist->mailbox_hash,
					POINTER_CAST(irec->parent_uid));
			if (node->parent == NULL)
				return -1;
			node->next = node->parent->children;
			node->parent->children = node;
		} else {
			node->next = ilist->mailbox_tree;
			ilist->mailbox_tree = node;
		}
		hash_table_insert(ilist->mailbox_hash,
				  POINTER_CAST(node->uid), node);
	}
	return 0;
}

static int index_mailbox_list_read(struct index_mailbox_list *ilist,
				   struct mail_index_view *view, bool force)
{
	const struct mail_index_header *hdr;
	int ret;

	hdr = mail_index_get_header(view);
	if (!force &&
	    hdr->log_file_seq == ilist->sync_log_file_seq &&
	    hdr->log_file_head_offset == ilist->sync_log_file_offset) {
		/* nothing changed */
		return 0;
	}

	index_mailbox_list_reset(ilist);
	ilist->sync_log_file_seq = hdr->log_file_seq;
	ilist->sync_log_file_offset = hdr->log_file_head_offset;

	ret = index_mailbox_list_parse_header(ilist, view);
	if (ret == 0)
		ret = index_mailbox_list_parse_records(ilist, view);
	if (ret < 0) {
		i_error("Corrupted mailbox list index %s", ilist->path);
		mail_index_mark_corrupted(ilist->index);
		return -1;
	}
	return 0;
}

static bool
index_mailbox_list_need_refresh(struct index_mailbox_list *ilist,
				struct mail_index_view *view)
{
	const struct mailbox_list_index_header *hdr;
	const void *data;
	size_t size;

	mail_index_get_header_ext(view, ilist->ext_id, &data, &size);
	hdr = data;
	return hdr != NULL && hdr->refresh_flag != 0;
}

int index_mailbox_list_refresh(struct mailbox_list *list)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);
	struct mail_index_view *view;
	int ret;

	if (ilist->iter_refcount > 0) {
		/* someone's already iterating. don't break them. */
		return 0;
	}

	if (mail_index_refresh(ilist->index) < 0)
		return -1;

	view = mail_index_view_open(ilist->index);
	if (ilist->mailbox_tree == NULL ||
	    index_mailbox_list_need_refresh(ilist, view)) {
		/* refresh list of mailboxes */
		ret = index_mailbox_list_sync(list);
	} else {
		ret = index_mailbox_list_read(ilist, view, FALSE);
	}
	mail_index_view_close(&view);
	return ret;
}

void index_mailbox_list_refresh_later(struct mailbox_list *list)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);
	struct mailbox_list_index_header new_hdr;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;

	view = mail_index_view_open(ilist->index);
	if (!index_mailbox_list_need_refresh(ilist, view)) {
		new_hdr.refresh_flag = 1;

		trans = mail_index_transaction_begin(view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
		mail_index_update_header_ext(trans, ilist->ext_id,
			offsetof(struct mailbox_list_index_header, refresh_flag),
			&new_hdr.refresh_flag, sizeof(new_hdr.refresh_flag));
		if (mail_index_transaction_commit(&trans) < 0)
			mail_index_mark_corrupted(ilist->index);

	}
	mail_index_view_close(&view);
}

static struct mailbox_list_iterate_context *
index_mailbox_list_iter_init(struct mailbox_list *list,
			     const char *const *patterns,
			     enum mailbox_list_iter_flags flags)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);
	struct index_mailbox_list_iterate_context *ctx;
	char ns_sep = mail_namespace_get_sep(list->ns);

	ctx = i_new(struct index_mailbox_list_iterate_context, 1);
	ctx->ctx.list = list;
	ctx->ctx.flags = flags;
	ctx->ctx.glob = imap_match_init_multiple(default_pool, patterns,
						 TRUE, ns_sep);
	array_create(&ctx->ctx.module_contexts, default_pool, sizeof(void *), 5);
	ctx->sep = ns_sep;

	if (index_mailbox_list_refresh(ctx->ctx.list) < 0) {
		/* no indexing */
		mail_index_mark_corrupted(ilist->index);
		ctx->backend_ctx = ilist->module_ctx.super.
			iter_init(list, patterns, flags);
	} else {
		/* listing mailboxes from index */
		ctx->info.ns = list->ns;
		ctx->path = str_new(default_pool, 128);
		ctx->next_node = ilist->mailbox_tree;
		ilist->iter_refcount++;
	}
	return &ctx->ctx;
}

static void
index_mailbox_list_update_info(struct index_mailbox_list_iterate_context *ctx)
{
	struct index_mailbox_node *node = ctx->next_node;
	struct mailbox *box;

	str_truncate(ctx->path, ctx->parent_len);
	if (str_len(ctx->path) > 0)
		str_append_c(ctx->path, ctx->sep);
	str_append(ctx->path, node->name);

	ctx->info.name = str_c(ctx->path);
	ctx->info.flags = 0;
	if ((node->flags & MAILBOX_LIST_INDEX_FLAG_NONEXISTENT) != 0)
		ctx->info.flags |= MAILBOX_NONEXISTENT;
	else if ((node->flags & MAILBOX_LIST_INDEX_FLAG_NOSELECT) != 0)
		ctx->info.flags |= MAILBOX_NOSELECT;
	if ((node->flags & MAILBOX_LIST_INDEX_FLAG_NOINFERIORS) != 0)
		ctx->info.flags |= MAILBOX_NOINFERIORS;
	ctx->info.flags |= node->children != NULL ?
		MAILBOX_CHILDREN : MAILBOX_NOCHILDREN;

	if ((ctx->ctx.flags & (MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
			       MAILBOX_LIST_ITER_RETURN_SUBSCRIBED)) != 0) {
		mailbox_list_set_subscription_flags(ctx->ctx.list,
						    ctx->info.name,
						    &ctx->info.flags);
	}

	box = mailbox_alloc(ctx->ctx.list, ctx->info.name,
			    MAILBOX_FLAG_KEEP_RECENT);
	index_mailbox_list_status_set_info_flags(box, node->uid,
						 &ctx->info.flags);
	mailbox_free(&box);
}

static void
index_mailbox_list_update_next(struct index_mailbox_list_iterate_context *ctx,
			       bool follow_children)
{
	struct index_mailbox_node *node = ctx->next_node;

	if (node->children != NULL && follow_children) {
		ctx->parent_len = str_len(ctx->path);
		ctx->next_node = node->children;
	} else {
		while (node->next == NULL) {
			node = node->parent;
			if (node != NULL) {
				ctx->parent_len -= strlen(node->name);
				if (node->parent != NULL)
					ctx->parent_len--;
			}
			if (node == NULL) {
				/* last one */
				ctx->next_node = NULL;
				return;
			}
		}
		ctx->next_node = node->next;
	}
}

static bool
iter_subscriptions_ok(struct index_mailbox_list_iterate_context *ctx)
{
	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0)
		return TRUE;

	if ((ctx->info.flags & MAILBOX_SUBSCRIBED) != 0)
		return TRUE;

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) != 0 &&
	    (ctx->info.flags & MAILBOX_CHILD_SUBSCRIBED) != 0)
		return TRUE;
	return FALSE;
}

static const struct mailbox_info *
index_mailbox_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct index_mailbox_list_iterate_context *ctx =
		(struct index_mailbox_list_iterate_context *)_ctx;
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(_ctx->list);
	bool follow_children;
	enum imap_match_result match;

	if (ctx->backend_ctx != NULL) {
		/* index isn't being used */
		return ilist->module_ctx.super.iter_next(ctx->backend_ctx);
	}

	/* listing mailboxes from index */
	while (ctx->next_node != NULL) {
		index_mailbox_list_update_info(ctx);
		match = imap_match(_ctx->glob, ctx->info.name);

		follow_children = (match & (IMAP_MATCH_YES |
					    IMAP_MATCH_CHILDREN)) != 0;
		if (match == IMAP_MATCH_YES && iter_subscriptions_ok(ctx)) {
			index_mailbox_list_update_next(ctx, TRUE);
			return &ctx->info;
		} else if ((_ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0 &&
			   (ctx->info.flags & MAILBOX_CHILD_SUBSCRIBED) == 0) {
			/* listing only subscriptions, but there are no
			   subscribed children. */
			follow_children = FALSE;
		}
		index_mailbox_list_update_next(ctx, follow_children);
	}
	return NULL;
}

static int
index_mailbox_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct index_mailbox_list_iterate_context *ctx =
		(struct index_mailbox_list_iterate_context *)_ctx;
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(_ctx->list);
	int ret = ctx->failed ? -1 : 0;

	if (ctx->backend_ctx != NULL)
		ret = ilist->module_ctx.super.iter_deinit(ctx->backend_ctx);
	else {
		i_assert(ilist->iter_refcount > 0);
		ilist->iter_refcount--;
		str_free(&ctx->path);
	}

	imap_match_deinit(&ctx->ctx.glob);
	array_free(&ctx->ctx.module_contexts);
	i_free(ctx);
	return ret;
}

static void index_mailbox_list_deinit(struct mailbox_list *list)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);

	hash_table_destroy(&ilist->mailbox_hash);
	hash_table_destroy(&ilist->mailbox_names);
	pool_unref(&ilist->mailbox_pool);
	mail_index_close(ilist->index);
	mail_index_free(&ilist->index);
	ilist->module_ctx.super.deinit(list);
}

static int index_mailbox_list_index_open(struct mailbox_list *list)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);
	const struct mail_storage_settings *set = list->mail_set;
	enum mail_index_open_flags index_flags;
	unsigned int lock_timeout;

	index_flags = mail_storage_settings_to_index_flags(set);
	lock_timeout = set->mail_max_lock_timeout == 0 ? -1U :
		set->mail_max_lock_timeout;

	mail_index_set_lock_method(ilist->index, set->parsed_lock_method,
				   lock_timeout);
	if (mail_index_open_or_create(ilist->index, index_flags) < 0) {
		if (mail_index_move_to_memory(ilist->index) < 0) {
			/* try opening once more. it should be created
			   directly into memory now. */
			if (mail_index_open_or_create(ilist->index,
						      index_flags) < 0)
				i_panic("in-memory index creation failed");
		}
	}
	return 0;
}

static int
index_mailbox_list_create_mailbox_dir(struct mailbox_list *list,
				      const char *name,
				      enum mailbox_dir_create_type type)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);

	index_mailbox_list_refresh_later(list);
	return ilist->module_ctx.super.create_mailbox_dir(list, name, type);
}

static int
index_mailbox_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);

	index_mailbox_list_refresh_later(list);
	return ilist->module_ctx.super.delete_mailbox(list, name);
}

static int
index_mailbox_list_delete_dir(struct mailbox_list *list, const char *name)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);

	index_mailbox_list_refresh_later(list);
	return ilist->module_ctx.super.delete_dir(list, name);
}

static int
index_mailbox_list_rename_mailbox(struct mailbox_list *oldlist,
				  const char *oldname,
				  struct mailbox_list *newlist,
				  const char *newname,
				  bool rename_children)
{
	struct index_mailbox_list *oldilist = INDEX_LIST_CONTEXT(oldlist);

	index_mailbox_list_refresh_later(oldlist);
	if (oldlist != newlist)
		index_mailbox_list_refresh_later(newlist);
	return oldilist->module_ctx.super.
		rename_mailbox(oldlist, oldname,
			       newlist, newname, rename_children);
}

static void index_mailbox_list_created(struct mailbox_list *list)
{
	struct index_mailbox_list *ilist;
	const char *dir;

	dir = mailbox_list_get_path(list, NULL, MAILBOX_LIST_PATH_TYPE_INDEX);
	if (*dir == '\0' || list->mail_set->mailbox_list_index) {
		/* reserve the module context anyway, so syncing code knows
		   that the index is disabled */
		ilist = NULL;
		MODULE_CONTEXT_SET(list, index_mailbox_list_module, ilist);
		return;
	}

	ilist = p_new(list->pool, struct index_mailbox_list, 1);
	ilist->module_ctx.super = list->v;

	list->v.deinit = index_mailbox_list_deinit;
	list->v.iter_init = index_mailbox_list_iter_init;
	list->v.iter_deinit = index_mailbox_list_iter_deinit;
	list->v.iter_next = index_mailbox_list_iter_next;

	list->v.create_mailbox_dir = index_mailbox_list_create_mailbox_dir;
	list->v.delete_mailbox = index_mailbox_list_delete_mailbox;
	list->v.delete_dir = index_mailbox_list_delete_dir;
	list->v.rename_mailbox = index_mailbox_list_rename_mailbox;

	MODULE_CONTEXT_SET(list, index_mailbox_list_module, ilist);

	ilist->path = p_strdup_printf(list->pool,
				      "%s/"MAILBOX_LIST_INDEX_PREFIX, dir);
	ilist->index = mail_index_alloc(dir, MAILBOX_LIST_INDEX_PREFIX);

	ilist->ext_id = mail_index_ext_register(ilist->index, "list",
				sizeof(struct mailbox_list_index_header),
				sizeof(struct mailbox_list_index_record),
				sizeof(uint32_t));

	ilist->mailbox_pool = pool_alloconly_create("mailbox list index", 4096);
	ilist->mailbox_names =
		hash_table_create(default_pool, ilist->mailbox_pool,
				  0, NULL, NULL);
	ilist->mailbox_hash =
		hash_table_create(default_pool, ilist->mailbox_pool,
				  0, NULL, NULL);

	if (index_mailbox_list_index_open(list) < 0) {
		list->v = ilist->module_ctx.super;
		mail_index_free(&ilist->index);
		MODULE_CONTEXT_UNSET(list, index_mailbox_list_module);
	}
	index_mailbox_list_status_init_list(list);
}

static struct mail_storage_hooks index_mailbox_list_hooks = {
	.mailbox_list_created = index_mailbox_list_created
};

void index_mailbox_list_init(void); /* called in mailbox-list-register.c */

void index_mailbox_list_init(void)
{
	mail_storage_hooks_add_internal(&index_mailbox_list_hooks);
	index_mailbox_list_status_init();
}
