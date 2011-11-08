/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "mail-index.h"
#include "mailbox-list-index.h"

struct mailbox_list_index_sync_context {
	struct mailbox_list_index *ilist;
	char sep[2];
	uint32_t next_uid;

	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
};

static void
node_add_to_index(struct mailbox_list_index_sync_context *ctx,
		  const struct mailbox_list_index_node *node, uint32_t *seq_r)
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

static uint32_t
mailbox_list_index_sync_name(struct mailbox_list_index_sync_context *ctx,
			     const char *name,
			     enum mailbox_list_index_flags flags)
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
	} else {
		/* create missing parts of the path */
		for (; path[i] != NULL; i++) {
			node = mailbox_list_index_node_add(ctx, node, path[i],
							   &seq);
		}
	}

	node->flags = flags | MAILBOX_LIST_INDEX_FLAG_SYNC_EXISTS;
	return seq;
}

static void
get_existing_name_ids(ARRAY_TYPE(uint32_t) *ids,
		      const struct mailbox_list_index_node *node)
{
	for (; node != NULL; node = node->next) {
		if ((node->flags & MAILBOX_LIST_INDEX_FLAG_SYNC_EXISTS) != 0) {
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

	hdr_buf = buffer_create_dynamic(pool_datastack_create(), 1024);
	buffer_append_zero(hdr_buf, sizeof(struct mailbox_list_index_header));

	/* add existing names to header (with deduplication) */
	array_foreach(&existing_name_ids, id_p) {
		if (*id_p != prev_id) {
			buffer_append(hdr_buf, id_p, sizeof(*id_p));
			name = hash_table_lookup(ilist->mailbox_names,
						 POINTER_CAST(*id_p));
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
mailbox_list_index_node_unlink(struct mailbox_list_index *ilist,
			       struct mailbox_list_index_node *node)
{
	struct mailbox_list_index_node **prev;

	prev = node->parent == NULL ?
		&ilist->mailbox_tree : &node->parent->children;

	while (*prev != node)
		prev = &(*prev)->next;
	*prev = node->next;
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

int mailbox_list_index_sync(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
	struct mailbox_list_index_sync_context sync_ctx;
	struct mailbox_list_iterate_context *iter;
	const struct mail_index_header *hdr;
	const struct mailbox_info *info;
	const char *patterns[2];
	enum mailbox_list_index_flags flags;
	uint32_t seq, orig_highest_name_id;

	mailbox_list_index_reset(ilist);

	memset(&sync_ctx, 0, sizeof(sync_ctx));
	sync_ctx.ilist = ilist;
	sync_ctx.sep[0] = mailbox_list_get_hierarchy_sep(list);
	if (mail_index_sync_begin(ilist->index, &sync_ctx.sync_ctx,
				  &sync_ctx.view, &sync_ctx.trans,
				  MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES) < 0) {
		mailbox_list_index_set_index_error(list);
		return -1;
	}
	/* re-parse mailbox list now that it's refreshed and locked */
	if (mailbox_list_index_parse(ilist, sync_ctx.view, TRUE) < 0) {
		mail_index_sync_rollback(&sync_ctx.sync_ctx);
		return -1;
	}
	orig_highest_name_id = ilist->highest_name_id;

	hdr = mail_index_get_header(sync_ctx.view);
	sync_ctx.next_uid = hdr->next_uid;

	if (hdr->uid_validity == 0) {
		/* first time indexing, set uidvalidity */
		uint32_t uid_validity = ioloop_time;

		mail_index_update_header(sync_ctx.trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}

	/* clear EXISTS-flags, so after sync we know what can be expunged */
	mailbox_list_index_node_clear_exists(ilist->mailbox_tree);

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
	if (ilist->module_ctx.super.iter_deinit(iter) < 0) {
		mail_index_sync_rollback(&sync_ctx.sync_ctx);
		return -1;
	}

	sync_expunge_nonexistent(&sync_ctx, ilist->mailbox_tree);

	if (orig_highest_name_id != ilist->highest_name_id) {
		/* new names added. this implicitly resets refresh flag */
		T_BEGIN {
			mailbox_list_index_sync_names(&sync_ctx);
		} T_END;
	} else {
		/* we're synced, reset refresh flag */
		struct mailbox_list_index_header new_hdr;

		new_hdr.refresh_flag = 0;
		mail_index_update_header_ext(sync_ctx.trans, ilist->ext_id,
			offsetof(struct mailbox_list_index_header, refresh_flag),
			&new_hdr.refresh_flag, sizeof(new_hdr.refresh_flag));
	}

	if (mail_index_sync_commit(&sync_ctx.sync_ctx) < 0) {
		mailbox_list_index_set_index_error(list);
		return -1;
	}
	return 0;
}
