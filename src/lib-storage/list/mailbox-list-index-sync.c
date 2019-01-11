/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "sort.h"
#include "mail-index.h"
#include "mail-storage.h"
#include "mailbox-list-index-sync.h"

static void
node_lookup_guid(struct mailbox_list_index_sync_context *ctx,
		 const struct mailbox_list_index_node *node, guid_128_t guid_r)
{
	struct mailbox *box;
	struct mailbox_metadata metadata;
	const char *vname;
	string_t *str = t_str_new(128);
	char ns_sep = mailbox_list_get_hierarchy_sep(ctx->list);

	mailbox_list_index_node_get_path(node, ns_sep, str);

	vname = mailbox_list_get_vname(ctx->list, str_c(str));
	box = mailbox_alloc(ctx->list, vname, 0);
	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata) == 0)
		memcpy(guid_r, metadata.guid, GUID_128_SIZE);
	mailbox_free(&box);
}

static void
node_add_to_index(struct mailbox_list_index_sync_context *ctx,
		  const struct mailbox_list_index_node *node, uint32_t *seq_r)
{
	struct mailbox_list_index_record irec;
	uint32_t seq;

	i_zero(&irec);
	irec.name_id = node->name_id;
	if (node->parent != NULL)
		irec.parent_uid = node->parent->uid;

	/* get mailbox GUID if possible. we need to do this early in here to
	   make mailbox rename detection work in NOTIFY */
	if (ctx->syncing_list) T_BEGIN {
		node_lookup_guid(ctx, node, irec.guid);
	} T_END;

	mail_index_append(ctx->trans, node->uid, &seq);
	mail_index_update_flags(ctx->trans, seq, MODIFY_REPLACE,
		(enum mail_flags)MAILBOX_LIST_INDEX_FLAG_NONEXISTENT);
	mail_index_update_ext(ctx->trans, seq, ctx->ilist->ext_id, &irec, NULL);

	*seq_r = seq;
}

static struct mailbox_list_index_node *
mailbox_list_index_node_add(struct mailbox_list_index_sync_context *ctx,
			    struct mailbox_list_index_node *parent,
			    const char *name, uint32_t *seq_r)
{
	struct mailbox_list_index_node *node;
	char *dup_name;

	node = p_new(ctx->ilist->mailbox_pool,
		     struct mailbox_list_index_node, 1);
	node->flags = MAILBOX_LIST_INDEX_FLAG_NONEXISTENT |
		MAILBOX_LIST_INDEX_FLAG_SYNC_EXISTS;
	/* we don't bother doing name deduplication here, even though it would
	   be possible. */
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
	hash_table_insert(ctx->ilist->mailbox_hash,
			  POINTER_CAST(node->uid), node);
	hash_table_insert(ctx->ilist->mailbox_names,
			  POINTER_CAST(node->name_id), dup_name);

	node_add_to_index(ctx, node, seq_r);
	return node;
}

uint32_t mailbox_list_index_sync_name(struct mailbox_list_index_sync_context *ctx,
				      const char *name,
				      struct mailbox_list_index_node **node_r,
				      bool *created_r)
{
	const char *const *path, *empty_path[] = { "", NULL };
	struct mailbox_list_index_node *node, *parent;
	unsigned int i;
	uint32_t seq = 0;

	path = *name == '\0' ? empty_path :
		t_strsplit(name, ctx->sep);
	/* find the last node that exists in the path */
	node = ctx->ilist->mailbox_tree; parent = NULL;
	for (i = 0; path[i] != NULL; i++) {
		node = mailbox_list_index_node_find_sibling(node, path[i]);
		if (node == NULL)
			break;

		node->flags |= MAILBOX_LIST_INDEX_FLAG_SYNC_EXISTS;
		parent = node;
		node = node->children;
	}

	node = parent;
	if (path[i] == NULL) {
		/* the entire path exists */
		i_assert(node != NULL);
		if (!mail_index_lookup_seq(ctx->view, node->uid, &seq))
			i_panic("mailbox list index: lost uid=%u", node->uid);
		*created_r = FALSE;
	} else {
		/* create missing parts of the path */
		for (; path[i] != NULL; i++) {
			node = mailbox_list_index_node_add(ctx, node, path[i],
							   &seq);
		}
		*created_r = TRUE;
	}

	*node_r = node;
	return seq;
}

static void
get_existing_name_ids(ARRAY_TYPE(uint32_t) *ids,
		      const struct mailbox_list_index_node *node)
{
	for (; node != NULL; node = node->next) {
		if (node->children != NULL)
			get_existing_name_ids(ids, node->children);
		array_push_back(ids, &node->name_id);
	}
}

static void
mailbox_list_index_sync_names(struct mailbox_list_index_sync_context *ctx)
{
	struct mailbox_list_index *ilist = ctx->ilist;
	ARRAY_TYPE(uint32_t) existing_name_ids;
	buffer_t *hdr_buf;
	const void *ext_data;
	size_t ext_size;
	const char *name;
	const uint32_t *id_p;
	uint32_t prev_id = 0;

	/* get all existing name IDs sorted */
	t_array_init(&existing_name_ids, 64);
	get_existing_name_ids(&existing_name_ids, ilist->mailbox_tree);
	array_sort(&existing_name_ids, uint32_cmp);

	hdr_buf = t_buffer_create(1024);
	buffer_append_zero(hdr_buf, sizeof(struct mailbox_list_index_header));

	/* add existing names to header (with deduplication) */
	array_foreach(&existing_name_ids, id_p) {
		if (*id_p != prev_id) {
			buffer_append(hdr_buf, id_p, sizeof(*id_p));
			name = hash_table_lookup(ilist->mailbox_names,
						 POINTER_CAST(*id_p));
			i_assert(name != NULL);
			buffer_append(hdr_buf, name, strlen(name) + 1);
			prev_id = *id_p;
		}
	}
	buffer_append_zero(hdr_buf, sizeof(*id_p));

	/* make sure header size is ok in index and update it */
	mail_index_get_header_ext(ctx->view, ilist->ext_id,
				  &ext_data, &ext_size);
	if (nearest_power(ext_size) != nearest_power(hdr_buf->used)) {
		mail_index_ext_resize(ctx->trans, ilist->ext_id,
				      nearest_power(hdr_buf->used),
				      sizeof(struct mailbox_list_index_record),
				      sizeof(uint32_t));
	}
	mail_index_update_header_ext(ctx->trans, ilist->ext_id,
				     0, hdr_buf->data, hdr_buf->used);
}

static void
mailbox_list_index_node_clear_exists(struct mailbox_list_index_node *node)
{
	while (node != NULL) {
		if (node->children != NULL)
			mailbox_list_index_node_clear_exists(node->children);

		node->flags &= ~MAILBOX_LIST_INDEX_FLAG_SYNC_EXISTS;
		node = node->next;
	}
}

static void
sync_expunge_nonexistent(struct mailbox_list_index_sync_context *sync_ctx,
			 struct mailbox_list_index_node *node)
{
	uint32_t seq;

	while (node != NULL) {
		if (node->children != NULL)
			sync_expunge_nonexistent(sync_ctx, node->children);

		if ((node->flags & MAILBOX_LIST_INDEX_FLAG_SYNC_EXISTS) == 0) {
			if (mail_index_lookup_seq(sync_ctx->view, node->uid,
						  &seq))
				mail_index_expunge(sync_ctx->trans, seq);
			mailbox_list_index_node_unlink(sync_ctx->ilist, node);
		}
		node = node->next;
	}
}

int mailbox_list_index_sync_begin(struct mailbox_list *list,
				  struct mailbox_list_index_sync_context **sync_ctx_r)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);
	struct mailbox_list_index_sync_context *sync_ctx;
	struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	const struct mail_index_header *hdr;
	bool fix_attempted = FALSE;

	i_assert(!ilist->syncing);

retry:
	if (mailbox_list_index_index_open(list) < 0)
		return -1;

	if (mail_index_sync_begin(ilist->index, &index_sync_ctx, &view, &trans,
				  MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES) < 0) {
		mailbox_list_index_set_index_error(list);
		return -1;
	}
	mailbox_list_index_reset(ilist);

	/* re-parse mailbox list now that it's refreshed and locked */
	if (mailbox_list_index_parse(list, view, TRUE) < 0) {
		mail_index_sync_rollback(&index_sync_ctx);
		return -1;
	}
	if (ilist->call_corruption_callback && !fix_attempted) {
		/* unlock and resync the index */
		mail_index_sync_rollback(&index_sync_ctx);
		if (mailbox_list_index_handle_corruption(list) < 0)
			return -1;
		fix_attempted = TRUE;
		goto retry;
	}

	sync_ctx = i_new(struct mailbox_list_index_sync_context, 1);
	sync_ctx->list = list;
	sync_ctx->ilist = ilist;
	sync_ctx->sep[0] = mailbox_list_get_hierarchy_sep(list);
	sync_ctx->orig_highest_name_id = ilist->highest_name_id;
	sync_ctx->index_sync_ctx = index_sync_ctx;
	sync_ctx->trans = trans;

	hdr = mail_index_get_header(view);
	sync_ctx->next_uid = hdr->next_uid;

	if (hdr->uid_validity == 0) {
		/* first time indexing, set uidvalidity */
		uint32_t uid_validity = ioloop_time;

		mail_index_update_header(trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}
	sync_ctx->view = mail_index_transaction_open_updated_view(trans);
	ilist->sync_ctx = sync_ctx;
	ilist->syncing = TRUE;

	*sync_ctx_r = sync_ctx;
	return 0;
}

static int
mailbox_list_index_sync_list(struct mailbox_list_index_sync_context *sync_ctx)
{
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	enum mailbox_list_index_flags flags;
	const char *patterns[2];
	struct mailbox_list_index_node *node;
	uint32_t seq;
	bool created;

	/* clear EXISTS-flags, so after sync we know what can be expunged */
	mailbox_list_index_node_clear_exists(sync_ctx->ilist->mailbox_tree);

	/* don't include autocreated mailboxes in index until they're
	   actually created. this index may be used by multiple users, so
	   we also want to ignore ACLs here. */
	patterns[0] = "*"; patterns[1] = NULL;
	iter = sync_ctx->ilist->module_ctx.super.
		iter_init(sync_ctx->list, patterns,
			  MAILBOX_LIST_ITER_RAW_LIST |
			  MAILBOX_LIST_ITER_NO_AUTO_BOXES);

	sync_ctx->syncing_list = TRUE;
	while ((info = sync_ctx->ilist->module_ctx.super.iter_next(iter)) != NULL) T_BEGIN {
		flags = 0;
		if ((info->flags & MAILBOX_NONEXISTENT) != 0)
			flags |= MAILBOX_LIST_INDEX_FLAG_NONEXISTENT;
		if ((info->flags & MAILBOX_NOSELECT) != 0)
			flags |= MAILBOX_LIST_INDEX_FLAG_NOSELECT;
		if ((info->flags & MAILBOX_NOINFERIORS) != 0)
			flags |= MAILBOX_LIST_INDEX_FLAG_NOINFERIORS;

		const char *name = mailbox_list_get_storage_name(info->ns->list,
								 info->vname);
		if (strcmp(name, "INBOX") == 0 &&
		    strcmp(info->vname, "INBOX") != 0 &&
		    (info->ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
			/* prefix/INBOX - don't override INBOX with this */
		} else {
			seq = mailbox_list_index_sync_name(sync_ctx, name,
							   &node, &created);
			node->flags = flags | MAILBOX_LIST_INDEX_FLAG_SYNC_EXISTS;
			mail_index_update_flags(sync_ctx->trans, seq,
						MODIFY_REPLACE,
						(enum mail_flags)flags);
		}
	} T_END;
	sync_ctx->syncing_list = FALSE;

	if (sync_ctx->ilist->module_ctx.super.iter_deinit(iter) < 0)
		return -1;

	/* successfully listed everything, expunge any unseen mailboxes */
	sync_expunge_nonexistent(sync_ctx, sync_ctx->ilist->mailbox_tree);
	return 0;
}

static void
mailbox_list_index_sync_update_hdr(struct mailbox_list_index_sync_context *sync_ctx)
{
	if (sync_ctx->orig_highest_name_id != sync_ctx->ilist->highest_name_id ||
	    sync_ctx->ilist->corrupted_names_or_parents) {
		/* new names added. this implicitly resets refresh flag */
		T_BEGIN {
			mailbox_list_index_sync_names(sync_ctx);
		} T_END;
		sync_ctx->ilist->corrupted_names_or_parents = FALSE;
	} else if (mailbox_list_index_need_refresh(sync_ctx->ilist,
						   sync_ctx->view)) {
		/* we're synced, reset refresh flag */
		struct mailbox_list_index_header new_hdr;

		new_hdr.refresh_flag = 0;
		mail_index_update_header_ext(sync_ctx->trans, sync_ctx->ilist->ext_id,
			offsetof(struct mailbox_list_index_header, refresh_flag),
			&new_hdr.refresh_flag, sizeof(new_hdr.refresh_flag));
	}
}

static void
mailbox_list_index_sync_update_corrupted_node(struct mailbox_list_index_sync_context *sync_ctx,
					      struct mailbox_list_index_node *node)
{
	struct mailbox_list_index_record irec;
	uint32_t seq;
	const void *data;
	bool expunged;

	if (!mail_index_lookup_seq(sync_ctx->view, node->uid, &seq))
		return;

	if (node->corrupted_ext) {
		mail_index_lookup_ext(sync_ctx->view, seq,
				      sync_ctx->ilist->ext_id,
				      &data, &expunged);
		i_assert(data != NULL);

		memcpy(&irec, data, sizeof(irec));
		irec.name_id = node->name_id;
		irec.parent_uid = node->parent == NULL ? 0 : node->parent->uid;
		mail_index_update_ext(sync_ctx->trans, seq,
				      sync_ctx->ilist->ext_id, &irec, NULL);
		node->corrupted_ext = FALSE;
	}
	if (node->corrupted_flags) {
		mail_index_update_flags(sync_ctx->trans, seq, MODIFY_REPLACE,
					(enum mail_flags)node->flags);
		node->corrupted_flags = FALSE;
	} else if ((node->flags & MAILBOX_LIST_INDEX_FLAG_CORRUPTED_NAME) != 0) {
		/* rely on lib-index to drop unnecessary updates */
		mail_index_update_flags(sync_ctx->trans, seq, MODIFY_ADD,
			(enum mail_flags)MAILBOX_LIST_INDEX_FLAG_CORRUPTED_NAME);
	}
}

static void
mailbox_list_index_sync_update_corrupted_nodes(struct mailbox_list_index_sync_context *sync_ctx,
					       struct mailbox_list_index_node *node)
{
	for (; node != NULL; node = node->next) {
		mailbox_list_index_sync_update_corrupted_node(sync_ctx, node);
		mailbox_list_index_sync_update_corrupted_nodes(sync_ctx, node->children);
	}
}

static void
mailbox_list_index_sync_update_corrupted(struct mailbox_list_index_sync_context *sync_ctx)
{
	if (!sync_ctx->ilist->corrupted_names_or_parents)
		return;

	mailbox_list_index_sync_update_corrupted_nodes(sync_ctx,
		sync_ctx->ilist->mailbox_tree);
}

int mailbox_list_index_sync_end(struct mailbox_list_index_sync_context **_sync_ctx,
				bool success)
{
	struct mailbox_list_index_sync_context *sync_ctx = *_sync_ctx;
	int ret;

	*_sync_ctx = NULL;

	if (success) {
		mailbox_list_index_sync_update_corrupted(sync_ctx);
		mailbox_list_index_sync_update_hdr(sync_ctx);
	}
	mail_index_view_close(&sync_ctx->view);

	if (success) {
		struct mail_index_sync_rec sync_rec;
		while (mail_index_sync_next(sync_ctx->index_sync_ctx, &sync_rec)) ;
		if ((ret = mail_index_sync_commit(&sync_ctx->index_sync_ctx)) < 0)
			mailbox_list_index_set_index_error(sync_ctx->list);
	} else {
		mail_index_sync_rollback(&sync_ctx->index_sync_ctx);
		ret = -1;
	}
	sync_ctx->ilist->syncing = FALSE;
	sync_ctx->ilist->sync_ctx = NULL;
	i_free(sync_ctx);
	return ret;
}

int mailbox_list_index_sync(struct mailbox_list *list, bool refresh)
{
	struct mailbox_list_index_sync_context *sync_ctx;
	int ret = 0;

	if (mailbox_list_index_sync_begin(list, &sync_ctx) < 0)
		return -1;

	if (!sync_ctx->ilist->has_backing_store) {
		/* no backing store - we have nothing to sync to */
	} else if (refresh ||
		   sync_ctx->ilist->call_corruption_callback ||
		   sync_ctx->ilist->corrupted_names_or_parents ||
		   sync_ctx->ilist->highest_name_id == 0 ||
		   !sync_ctx->list->mail_set->mailbox_list_index_very_dirty_syncs) {
		/* sync the index against the backing store */
		ret = mailbox_list_index_sync_list(sync_ctx);
	}
	return mailbox_list_index_sync_end(&sync_ctx, ret == 0);
}

int mailbox_list_index_sync_delete(struct mailbox_list_index_sync_context *sync_ctx,
				   const char *name, bool delete_selectable)
{
	struct mailbox_list_index_record rec;
	struct mailbox_list_index_node *node;
	const void *data;
	bool expunged;
	uint32_t seq;

	node = mailbox_list_index_lookup(sync_ctx->list, name);
	if (node == NULL) {
		mailbox_list_set_error(sync_ctx->list, MAIL_ERROR_NOTFOUND,
				       T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		return -1;
	}
	if (!mail_index_lookup_seq(sync_ctx->view, node->uid, &seq))
		i_panic("mailbox list index: lost uid=%u", node->uid);
	if (delete_selectable) {
		/* make it at least non-selectable */
		node->flags = MAILBOX_LIST_INDEX_FLAG_NOSELECT;
		mail_index_update_flags(sync_ctx->trans, seq, MODIFY_REPLACE,
					(enum mail_flags)node->flags);

		mail_index_lookup_ext(sync_ctx->view, seq,
				      sync_ctx->ilist->ext_id,
				      &data, &expunged);
		i_assert(data != NULL && !expunged);
		memcpy(&rec, data, sizeof(rec));
		rec.uid_validity = 0;
		i_zero(&rec.guid);
		mail_index_update_ext(sync_ctx->trans, seq,
				      sync_ctx->ilist->ext_id, &rec, NULL);
	}
	if (node->children != NULL) {
		/* can't delete this directory before its children,
		   but we may have made it non-selectable already */
		return 0;
	}

	/* we can remove the entire node */
	mail_index_expunge(sync_ctx->trans, seq);
	mailbox_list_index_node_unlink(sync_ctx->ilist, node);
	return 1;
}
