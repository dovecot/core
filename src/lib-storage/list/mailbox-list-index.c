/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "mail-index.h"
#include "mail-storage.h"
#include "mail-storage-hooks.h"
#include "mailbox-list-index.h"

struct mailbox_list_index_sync_context {
	struct mailbox_list_index *ilist;
	char sep[2];
	uint32_t next_uid;

	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
};

struct mailbox_list_index_module mailbox_list_index_module =
	MODULE_CONTEXT_INIT(&mailbox_list_module_register);

static int mailbox_list_index_read(struct mailbox_list_index *ilist,
				   struct mail_index_view *view, bool force);

static void mailbox_list_index_reset(struct mailbox_list_index *ilist)
{
	hash_table_clear(ilist->mailbox_names, FALSE);
	hash_table_clear(ilist->mailbox_hash, FALSE);
	p_clear(ilist->mailbox_pool);
	ilist->mailbox_tree = NULL;
	ilist->highest_name_id = 0;
	ilist->sync_log_file_seq = 0;
	ilist->sync_log_file_offset = 0;
}

static struct mailbox_list_index_node *
node_find_sibling(struct mailbox_list_index_node *node, const char *name)
{
	while (node != NULL) {
		if (strcmp(node->name, name) == 0)
			return node;
		node = node->next;
	}
	return NULL;
}

static void
node_add_to_index(struct mailbox_list_index_sync_context *ctx,
		  struct mailbox_list_index_node *node,
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

static struct mailbox_list_index_node *
mailbox_list_index_node_add(struct mailbox_list_index_sync_context *ctx,
			    struct mailbox_list_index_node *parent,
			    const char *name, uint32_t *seq_r)
{
	struct mailbox_list_index_node *node;
	uint32_t name_id;
	char *dup_name;

	node = p_new(ctx->ilist->mailbox_pool,
		     struct mailbox_list_index_node, 1);
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

	node_add_to_index(ctx, node, &name_id, seq_r);
	hash_table_insert(ctx->ilist->mailbox_hash,
			  POINTER_CAST(node->uid), node);
	hash_table_insert(ctx->ilist->mailbox_names,
			  POINTER_CAST(name_id), dup_name);
	return node;
}

struct mailbox_list_index_node *
mailbox_list_index_lookup(struct mailbox_list *list, const char *name)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
	struct mailbox_list_index_node *node;

	(void)mailbox_list_index_refresh(list);

	T_BEGIN {
		const char *const *path;
		unsigned int i;
		char sep[2];

		sep[0] = mailbox_list_get_hierarchy_sep(list); sep[1] = '\0';
		path = t_strsplit(name, sep);
		node = ilist->mailbox_tree;
		for (i = 0;; i++) {
			node = node_find_sibling(node, path[i]);
			if (node == NULL || path[i+1] == NULL)
				break;
			node = node->children;
		}
	} T_END;

	return node;
}

static uint32_t
mailbox_list_index_sync_name(struct mailbox_list_index_sync_context *ctx,
			     const char *name,
			     enum mailbox_list_index_flags flags)
{
	const char *const *path;
	struct mailbox_list_index_node *node, *parent;
	unsigned int i;
	uint32_t seq = 0;

	path = t_strsplit(name, ctx->sep);
	node = ctx->ilist->mailbox_tree; parent = NULL;
	for (i = 0; path[i] != NULL; i++) {
		node = node_find_sibling(node, path[i]);
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
		for (; path[i] != NULL; i++) {
			node = mailbox_list_index_node_add(ctx, node, path[i],
							   &seq);
		}
	}

	node->flags = flags | MAILBOX_LIST_INDEX_FLAG_MARKED;
	return seq;
}

static void
get_existing_name_ids(ARRAY_TYPE(uint32_t) *ids,
		      const struct mailbox_list_index_node *node)
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
mailbox_list_index_sync_names(struct mailbox_list_index_sync_context *ctx)
{
	struct mailbox_list_index *ilist = ctx->ilist;
	ARRAY_TYPE(uint32_t) existing_name_ids;
	buffer_t *buf;
	const void *ext_data;
	size_t ext_size;
	const char *name;
	const uint32_t *id_p;
	uint32_t prev_id = 0;

	t_array_init(&existing_name_ids, 64);
	get_existing_name_ids(&existing_name_ids, ilist->mailbox_tree);
	array_sort(&existing_name_ids, uint32_cmp);

	buf = buffer_create_dynamic(pool_datastack_create(), 1024);
	buffer_append_zero(buf, sizeof(struct mailbox_list_index_header));

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
mailbox_list_index_node_unmark_recursive(struct mailbox_list_index_node *node)
{
	while (node != NULL) {
		if (node->children != NULL)
			mailbox_list_index_node_unmark_recursive(node->children);

		node->flags &= ~MAILBOX_LIST_INDEX_FLAG_MARKED;
		node = node->next;
	}
}

static void
mailbox_list_index_node_unlink(struct mailbox_list_index_sync_context *sync_ctx,
			       struct mailbox_list_index_node *node)
{
	struct mailbox_list_index_node **prev;

	prev = node->parent == NULL ?
		&sync_ctx->ilist->mailbox_tree :
		&node->parent->children;

	while (*prev != node)
		prev = &(*prev)->next;
	*prev = node->next;
}

static void
mailbox_list_index_nodes_expunge(struct mailbox_list_index_sync_context *sync_ctx,
				 struct mailbox_list_index_node *node)
{
	uint32_t seq;

	while (node != NULL) {
		if (node->children != NULL) {
			mailbox_list_index_nodes_expunge(sync_ctx,
							 node->children);
		}

		if ((node->flags & MAILBOX_LIST_INDEX_FLAG_MARKED) == 0) {
			if (mail_index_lookup_seq(sync_ctx->view, node->uid,
						  &seq))
				mail_index_expunge(sync_ctx->trans, seq);
			mailbox_list_index_node_unlink(sync_ctx, node);
		}
		node = node->next;
	}
}

static int mailbox_list_index_sync(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
	struct mailbox_list_index_sync_context sync_ctx;
	struct mailbox_list_iterate_context *iter;
	const struct mail_index_header *hdr;
	const struct mailbox_info *info;
	const char *patterns[2];
	enum mailbox_list_index_flags flags;
	uint32_t seq, orig_highest_name_id;
	int ret = 0;

	mailbox_list_index_reset(ilist);

	memset(&sync_ctx, 0, sizeof(sync_ctx));
	sync_ctx.ilist = ilist;
	sync_ctx.sep[0] = mailbox_list_get_hierarchy_sep(list);
	if (mail_index_sync_begin(ilist->index, &sync_ctx.sync_ctx,
				  &sync_ctx.view, &sync_ctx.trans,
				  MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES) < 0)
		return -1;

	if (mailbox_list_index_read(ilist, sync_ctx.view, TRUE) < 0) {
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

	mailbox_list_index_node_unmark_recursive(ilist->mailbox_tree);

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
			const char *name =
				mailbox_list_get_storage_name(info->ns->list,
							      info->name);
			seq = mailbox_list_index_sync_name(&sync_ctx,
							   name, flags);
		} T_END;

		mail_index_update_flags(sync_ctx.trans, seq,
					MODIFY_REPLACE, (enum mail_flags)flags);
	}
	if (ilist->module_ctx.super.iter_deinit(iter) < 0)
		ret = -1;

	if (ret < 0) {
		mail_index_sync_rollback(&sync_ctx.sync_ctx);
		return -1;
	}

	mailbox_list_index_nodes_expunge(&sync_ctx, ilist->mailbox_tree);

	if (orig_highest_name_id != ilist->highest_name_id) {
		/* new names added */
		T_BEGIN {
			mailbox_list_index_sync_names(&sync_ctx);
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

static int mailbox_list_index_parse_header(struct mailbox_list_index *ilist,
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

static int mailbox_list_index_parse_records(struct mailbox_list_index *ilist,
					    struct mail_index_view *view)
{
	struct mailbox_list_index_node *node;
	const struct mail_index_record *rec;
	const struct mailbox_list_index_record *irec;
	const void *data;
	bool expunged;
	uint32_t seq, count;

	count = mail_index_view_get_messages_count(view);
	for (seq = 1; seq <= count; seq++) {
		node = p_new(ilist->mailbox_pool,
			     struct mailbox_list_index_node, 1);
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

static int mailbox_list_index_read(struct mailbox_list_index *ilist,
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

	mailbox_list_index_reset(ilist);
	ilist->sync_log_file_seq = hdr->log_file_seq;
	ilist->sync_log_file_offset = hdr->log_file_head_offset;

	ret = mailbox_list_index_parse_header(ilist, view);
	if (ret == 0)
		ret = mailbox_list_index_parse_records(ilist, view);
	if (ret < 0) {
		i_error("Corrupted mailbox list index %s", ilist->path);
		mail_index_mark_corrupted(ilist->index);
		return -1;
	}
	return 0;
}

static bool
mailbox_list_index_need_refresh(struct mailbox_list_index *ilist,
				struct mail_index_view *view)
{
	const struct mailbox_list_index_header *hdr;
	const void *data;
	size_t size;

	mail_index_get_header_ext(view, ilist->ext_id, &data, &size);
	hdr = data;
	return hdr != NULL && hdr->refresh_flag != 0;
}

int mailbox_list_index_refresh(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
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
	    mailbox_list_index_need_refresh(ilist, view)) {
		/* refresh list of mailboxes */
		ret = mailbox_list_index_sync(list);
	} else {
		ret = mailbox_list_index_read(ilist, view, FALSE);
	}
	mail_index_view_close(&view);
	return ret;
}

void mailbox_list_index_refresh_later(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
	struct mailbox_list_index_header new_hdr;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;

	view = mail_index_view_open(ilist->index);
	if (!mailbox_list_index_need_refresh(ilist, view)) {
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

static void mailbox_list_index_deinit(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);

	hash_table_destroy(&ilist->mailbox_hash);
	hash_table_destroy(&ilist->mailbox_names);
	pool_unref(&ilist->mailbox_pool);
	mail_index_close(ilist->index);
	mail_index_free(&ilist->index);
	ilist->module_ctx.super.deinit(list);
}

static int mailbox_list_index_index_open(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
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
mailbox_list_index_create_mailbox_dir(struct mailbox_list *list,
				      const char *name,
				      enum mailbox_dir_create_type type)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);

	mailbox_list_index_refresh_later(list);
	return ilist->module_ctx.super.create_mailbox_dir(list, name, type);
}

static int
mailbox_list_index_delete_mailbox(struct mailbox_list *list, const char *name)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);

	mailbox_list_index_refresh_later(list);
	return ilist->module_ctx.super.delete_mailbox(list, name);
}

static int
mailbox_list_index_delete_dir(struct mailbox_list *list, const char *name)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);

	mailbox_list_index_refresh_later(list);
	return ilist->module_ctx.super.delete_dir(list, name);
}

static int
mailbox_list_index_rename_mailbox(struct mailbox_list *oldlist,
				  const char *oldname,
				  struct mailbox_list *newlist,
				  const char *newname,
				  bool rename_children)
{
	struct mailbox_list_index *oldilist = INDEX_LIST_CONTEXT(oldlist);

	mailbox_list_index_refresh_later(oldlist);
	if (oldlist != newlist)
		mailbox_list_index_refresh_later(newlist);
	return oldilist->module_ctx.super.
		rename_mailbox(oldlist, oldname,
			       newlist, newname, rename_children);
}

static void mailbox_list_index_created(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist;
	const char *dir;

	dir = mailbox_list_get_path(list, NULL, MAILBOX_LIST_PATH_TYPE_INDEX);
	if (!list->mail_set->mailbox_list_index) {
		/* reserve the module context anyway, so syncing code knows
		   that the index is disabled */
		ilist = NULL;
		MODULE_CONTEXT_SET(list, mailbox_list_index_module, ilist);
		return;
	}
	if (*dir == '\0') {
		/* in-memory indexes */
		dir = NULL;
	} else if (list->ns->type != NAMESPACE_PRIVATE) {
		/* don't create index files for shared/public mailboxes.
		   their indexes may be shared between multiple users,
		   each of which may have different ACLs */
		dir = NULL;
	}

	ilist = p_new(list->pool, struct mailbox_list_index, 1);
	ilist->module_ctx.super = list->v;

	list->v.deinit = mailbox_list_index_deinit;
	list->v.iter_init = mailbox_list_index_iter_init;
	list->v.iter_deinit = mailbox_list_index_iter_deinit;
	list->v.iter_next = mailbox_list_index_iter_next;

	list->v.create_mailbox_dir = mailbox_list_index_create_mailbox_dir;
	list->v.delete_mailbox = mailbox_list_index_delete_mailbox;
	list->v.delete_dir = mailbox_list_index_delete_dir;
	list->v.rename_mailbox = mailbox_list_index_rename_mailbox;

	MODULE_CONTEXT_SET(list, mailbox_list_index_module, ilist);

	ilist->path = dir == NULL ? "(in-memory mailbox list index)" :
		p_strdup_printf(list->pool, "%s/"MAILBOX_LIST_INDEX_PREFIX, dir);
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

	if (mailbox_list_index_index_open(list) < 0) {
		list->v = ilist->module_ctx.super;
		mail_index_free(&ilist->index);
		MODULE_CONTEXT_UNSET(list, mailbox_list_index_module);
	}
	mailbox_list_index_status_init_list(list);
}

static struct mail_storage_hooks mailbox_list_index_hooks = {
	.mailbox_list_created = mailbox_list_index_created
};

void mailbox_list_index_init(void); /* called in mailbox-list-register.c */

void mailbox_list_index_init(void)
{
	mail_storage_hooks_add_internal(&mailbox_list_index_hooks);
	mailbox_list_index_status_init();
}
