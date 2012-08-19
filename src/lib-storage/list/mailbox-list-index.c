/* Copyright (c) 2006-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "mail-index-view-private.h"
#include "mail-storage-hooks.h"
#include "mailbox-list-index.h"

#define MAILBOX_LIST_INDEX_REFRESH_DELAY_MSECS 1000

struct mailbox_list_index_module mailbox_list_index_module =
	MODULE_CONTEXT_INIT(&mailbox_list_module_register);

void mailbox_list_index_set_index_error(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);

	mailbox_list_set_internal_error(list);
	mail_index_reset_error(ilist->index);
}

void mailbox_list_index_reset(struct mailbox_list_index *ilist)
{
	i_assert(ilist->iter_refcount == 0);

	hash_table_clear(ilist->mailbox_names, FALSE);
	hash_table_clear(ilist->mailbox_hash, FALSE);
	p_clear(ilist->mailbox_pool);
	ilist->mailbox_tree = NULL;
	ilist->highest_name_id = 0;
	ilist->sync_log_file_seq = 0;
	ilist->sync_log_file_offset = 0;
}

static void mailbox_list_index_index_open(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
	const struct mail_storage_settings *set = list->mail_set;
	enum mail_index_open_flags index_flags;
	unsigned int lock_timeout;

	if (ilist->opened)
		return;
	ilist->opened = TRUE;

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
}

struct mailbox_list_index_node *
mailbox_list_index_node_find_sibling(struct mailbox_list_index_node *node,
				     const char *name)
{
	while (node != NULL) {
		if (strcmp(node->name, name) == 0)
			return node;
		node = node->next;
	}
	return NULL;
}

static struct mailbox_list_index_node *
mailbox_list_index_lookup_real(struct mailbox_list *list, const char *name)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
	struct mailbox_list_index_node *node = ilist->mailbox_tree;
	const char *const *path;
	unsigned int i;
	char sep[2];

	if (*name == '\0')
		return mailbox_list_index_node_find_sibling(node, "");

	sep[0] = mailbox_list_get_hierarchy_sep(list); sep[1] = '\0';
	path = t_strsplit(name, sep);
	for (i = 0;; i++) {
		node = mailbox_list_index_node_find_sibling(node, path[i]);
		if (node == NULL || path[i+1] == NULL)
			break;
		node = node->children;
	}
	return node;
}

struct mailbox_list_index_node *
mailbox_list_index_lookup(struct mailbox_list *list, const char *name)
{
	struct mailbox_list_index_node *node;

	T_BEGIN {
		node = mailbox_list_index_lookup_real(list, name);
	} T_END;
	return node;
}

struct mailbox_list_index_node *
mailbox_list_index_lookup_uid(struct mailbox_list_index *ilist, uint32_t uid)
{
	return hash_table_lookup(ilist->mailbox_hash, POINTER_CAST(uid));
}

void mailbox_list_index_node_get_path(const struct mailbox_list_index_node *node,
				      char sep, string_t *str)
{
	if (node->parent != NULL) {
		mailbox_list_index_node_get_path(node->parent, sep, str);
		str_append_c(str, sep);
	}
	str_append(str, node->name);
}

static int mailbox_list_index_parse_header(struct mailbox_list_index *ilist,
					   struct mail_index_view *view)
{
	const void *data, *p;
	size_t i, len, size;
	uint32_t id, prev_id = 0;
	char *name;

	mail_index_map_get_header_ext(view, view->map, ilist->ext_id, &data, &size);
	if (size == 0)
		return 0;

	for (i = sizeof(struct mailbox_list_index_header); i < size; ) {
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
			node->parent = mailbox_list_index_lookup_uid(ilist,
							irec->parent_uid);
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

int mailbox_list_index_parse(struct mailbox_list_index *ilist,
			     struct mail_index_view *view, bool force)
{
	const struct mail_index_header *hdr;
	int ret;

	i_assert(ilist->iter_refcount == 0);

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

bool mailbox_list_index_need_refresh(struct mailbox_list_index *ilist,
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

	mailbox_list_index_index_open(list);
	if (mail_index_refresh(ilist->index) < 0) {
		mailbox_list_index_set_index_error(list);
		return -1;
	}

	view = mail_index_view_open(ilist->index);
	if (ilist->mailbox_tree == NULL ||
	    mailbox_list_index_need_refresh(ilist, view)) {
		/* refresh list of mailboxes */
		ret = mailbox_list_index_sync(list);
	} else {
		ret = mailbox_list_index_parse(ilist, view, FALSE);
	}
	mail_index_view_close(&view);
	return ret;
}

static void mailbox_list_index_refresh_timeout(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);

	timeout_remove(&ilist->to_refresh);
	(void)mailbox_list_index_refresh(list);
}

void mailbox_list_index_refresh_later(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
	struct mailbox_list_index_header new_hdr;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;

	mailbox_list_index_index_open(list);

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

	if (ilist->to_refresh == NULL) {
		ilist->to_refresh =
			timeout_add(MAILBOX_LIST_INDEX_REFRESH_DELAY_MSECS,
				    mailbox_list_index_refresh_timeout, list);
	}
}

static void mailbox_list_index_deinit(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);

	if (ilist->to_refresh != NULL)
		timeout_remove(&ilist->to_refresh);
	hash_table_destroy(&ilist->mailbox_hash);
	hash_table_destroy(&ilist->mailbox_names);
	pool_unref(&ilist->mailbox_pool);
	if (ilist->opened)
		mail_index_close(ilist->index);
	mail_index_free(&ilist->index);
	ilist->module_ctx.super.deinit(list);
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

	dir = mailbox_list_get_root_path(list, MAILBOX_LIST_PATH_TYPE_INDEX);
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

	list->v.notify_init = mailbox_list_index_notify_init;
	list->v.notify_next = mailbox_list_index_notify_next;
	list->v.notify_deinit = mailbox_list_index_notify_deinit;
	list->v.notify_wait = mailbox_list_index_notify_wait;

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
		hash_table_create(ilist->mailbox_pool, 0, NULL, NULL);
	ilist->mailbox_hash =
		hash_table_create(ilist->mailbox_pool, 0, NULL, NULL);

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
