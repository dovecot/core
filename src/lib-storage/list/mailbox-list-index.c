/* Copyright (c) 2006-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "mail-index-view-private.h"
#include "mail-storage-hooks.h"
#include "mail-storage-private.h"
#include "mailbox-list-index-storage.h"
#include "mailbox-list-index-sync.h"

#define MAILBOX_LIST_INDEX_REFRESH_DELAY_MSECS 1000

struct mailbox_list_index_module mailbox_list_index_module =
	MODULE_CONTEXT_INIT(&mailbox_list_module_register);

void mailbox_list_index_set_index_error(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);

	mailbox_list_set_internal_error(list);
	mail_index_reset_error(ilist->index);
}

static void mailbox_list_index_init_pool(struct mailbox_list_index *ilist)
{
	ilist->mailbox_pool = pool_alloconly_create("mailbox list index", 4096);
	hash_table_create_direct(&ilist->mailbox_names, ilist->mailbox_pool, 0);
	hash_table_create_direct(&ilist->mailbox_hash, ilist->mailbox_pool, 0);
}

void mailbox_list_index_reset(struct mailbox_list_index *ilist)
{
	hash_table_destroy(&ilist->mailbox_names);
	hash_table_destroy(&ilist->mailbox_hash);
	pool_unref(&ilist->mailbox_pool);

	ilist->mailbox_tree = NULL;
	ilist->highest_name_id = 0;
	ilist->sync_log_file_seq = 0;
	ilist->sync_log_file_offset = 0;

	mailbox_list_index_init_pool(ilist);
}

static int mailbox_list_index_index_open(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
	const struct mail_storage_settings *set = list->mail_set;
	struct mailbox_permissions perm;
	enum mail_index_open_flags index_flags;
	unsigned int lock_timeout;

	if (ilist->opened)
		return 0;

	if (mailbox_list_mkdir_missing_index_root(list) < 0)
		return -1;

	index_flags = mail_storage_settings_to_index_flags(set);
	if (strcmp(list->name, MAILBOX_LIST_NAME_INDEX) == 0) {
		/* LAYOUT=index. this is the only location for the mailbox
		   data, so we must never move it into memory. */
		index_flags |= MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY;
	}
	lock_timeout = set->mail_max_lock_timeout == 0 ? UINT_MAX :
		set->mail_max_lock_timeout;

	mailbox_list_get_root_permissions(list, &perm);
	mail_index_set_permissions(ilist->index, perm.file_create_mode,
				   perm.file_create_gid,
				   perm.file_create_gid_origin);

	mail_index_set_lock_method(ilist->index, set->parsed_lock_method,
				   lock_timeout);
	if (mail_index_open_or_create(ilist->index, index_flags) < 0) {
		if (mail_index_move_to_memory(ilist->index) < 0) {
			/* try opening once more. it should be created
			   directly into memory now, except if it fails with
			   LAYOUT=index backend. */
			if (mail_index_open_or_create(ilist->index,
						      index_flags) < 0) {
				mailbox_list_set_internal_error(list);
				return -1;
			}
		}
	}
	ilist->opened = TRUE;
	return 0;
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

void mailbox_list_index_node_unlink(struct mailbox_list_index *ilist,
				    struct mailbox_list_index_node *node)
{
	struct mailbox_list_index_node **prev;

	prev = node->parent == NULL ?
		&ilist->mailbox_tree : &node->parent->children;

	while (*prev != node)
		prev = &(*prev)->next;
	*prev = node->next;
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

static void
mailbox_list_index_generate_name(struct mailbox_list_index *ilist,
				 struct mailbox_list_index_node *node)
{
	guid_128_t guid;
	char *name;

	guid_128_generate(guid);
	name = p_strdup_printf(ilist->mailbox_pool, "unknown-%s",
			       guid_128_to_string(guid));
	node->name = name;

	hash_table_insert(ilist->mailbox_names,
			  POINTER_CAST(node->name_id), name);
	if (ilist->highest_name_id < node->name_id)
		ilist->highest_name_id = node->name_id;
}

static int mailbox_list_index_parse_records(struct mailbox_list_index *ilist,
					    struct mail_index_view *view,
					    const char **error_r)
{
	struct mailbox_list_index_node *node;
	const struct mail_index_record *rec;
	const struct mailbox_list_index_record *irec;
	const void *data;
	bool expunged;
	uint32_t seq, uid, count;

	*error_r = NULL;

	count = mail_index_view_get_messages_count(view);
	for (seq = 1; seq <= count; seq++) {
		node = p_new(ilist->mailbox_pool,
			     struct mailbox_list_index_node, 1);
		rec = mail_index_lookup(view, seq);
		node->uid = rec->uid;
		node->flags = rec->flags;

		mail_index_lookup_ext(view, seq, ilist->ext_id,
				      &data, &expunged);
		if (data == NULL) {
			*error_r = "Missing list extension data";
			return -1;
		}
		irec = data;

		node->name_id = irec->name_id;
		node->name = hash_table_lookup(ilist->mailbox_names,
					       POINTER_CAST(irec->name_id));
		if (node->name == NULL) {
			*error_r = "name_id not in index header";
			if (ilist->has_backing_store)
				return -1;
			/* generate a new name and use it */
			mailbox_list_index_generate_name(ilist, node);
		}
		hash_table_insert(ilist->mailbox_hash,
				  POINTER_CAST(node->uid), node);
	}

	/* do a second scan to create the actual mailbox tree hierarchy.
	   this is needed because the parent_uid may be smaller or higher than
	   the current node's uid */
	for (seq = 1; seq <= count; seq++) {
		mail_index_lookup_uid(view, seq, &uid);
		mail_index_lookup_ext(view, seq, ilist->ext_id,
				      &data, &expunged);
		irec = data;

		node = mailbox_list_index_lookup_uid(ilist, uid);
		i_assert(node != NULL);

		if (irec->parent_uid != 0) {
			/* node should have a parent */
			node->parent = mailbox_list_index_lookup_uid(ilist,
							irec->parent_uid);
			if (node->parent != NULL) {
				node->next = node->parent->children;
				node->parent->children = node;
				continue;
			}
			*error_r = "parent_uid points to nonexistent record";
			if (ilist->has_backing_store)
				return -1;
			/* just place it under the root */
		}
		node->next = ilist->mailbox_tree;
		ilist->mailbox_tree = node;
	}
	return *error_r == NULL ? 0 : -1;
}

int mailbox_list_index_parse(struct mailbox_list *list,
			     struct mail_index_view *view, bool force)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
	const struct mail_index_header *hdr;
	const char *error;

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

	if (mailbox_list_index_parse_header(ilist, view) < 0) {
		mailbox_list_set_critical(list,
			"Corrupted mailbox list index header %s", ilist->path);
		if (ilist->has_backing_store) {
			mail_index_mark_corrupted(ilist->index);
			return -1;
		}
	}
	if (mailbox_list_index_parse_records(ilist, view, &error) < 0) {
		mailbox_list_set_critical(list,
			"Corrupted mailbox list index %s: %s",
			ilist->path, error);
		if (ilist->has_backing_store) {
			mail_index_mark_corrupted(ilist->index);
			return -1;
		}
		/* FIXME: find any missing mailboxes, add them and write the
		   index back. */
	}
	return 0;
}

bool mailbox_list_index_need_refresh(struct mailbox_list_index *ilist,
				     struct mail_index_view *view)
{
	const struct mailbox_list_index_header *hdr;
	const void *data;
	size_t size;

	if (!ilist->has_backing_store)
		return FALSE;

	mail_index_get_header_ext(view, ilist->ext_id, &data, &size);
	hdr = data;
	return hdr != NULL && hdr->refresh_flag != 0;
}

int mailbox_list_index_refresh(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
	struct mail_index_view *view;
	int ret;

	if (mailbox_list_index_index_open(list) < 0)
		return -1;
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
		ret = mailbox_list_index_parse(list, view, FALSE);
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

	if (!ilist->has_backing_store)
		return;

	(void)mailbox_list_index_index_open(list);

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
	if (ilist->index != NULL) {
		hash_table_destroy(&ilist->mailbox_hash);
		hash_table_destroy(&ilist->mailbox_names);
		pool_unref(&ilist->mailbox_pool);
		if (ilist->opened)
			mail_index_close(ilist->index);
		mail_index_free(&ilist->index);
	}
	ilist->module_ctx.super.deinit(list);
}

static int
mailbox_list_index_create_mailbox(struct mailbox *box,
				  const struct mailbox_update *update,
				  bool directory)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);

	if (ibox->module_ctx.super.create_box(box, update, directory) < 0)
		return -1;
	mailbox_list_index_refresh_later(box->list);
	return 0;
}

static int
mailbox_list_index_update_mailbox(struct mailbox *box,
				  const struct mailbox_update *update)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);

	if (ibox->module_ctx.super.update_box(box, update) < 0)
		return -1;

	mailbox_list_index_update_mailbox_index(box, update);
	return 0;
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
				  const char *newname)
{
	struct mailbox_list_index *oldilist = INDEX_LIST_CONTEXT(oldlist);

	mailbox_list_index_refresh_later(oldlist);
	if (oldlist != newlist)
		mailbox_list_index_refresh_later(newlist);
	return oldilist->module_ctx.super.
		rename_mailbox(oldlist, oldname, newlist, newname);
}

static int
mailbox_list_index_set_subscribed(struct mailbox_list *_list,
				  const char *name, bool set)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(_list);
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	const void *data;
	size_t size;
	uint32_t counter;

	if (ilist->module_ctx.super.set_subscribed(_list, name, set) < 0)
		return -1;

	/* update the "subscriptions changed" counter/timestamp. its purpose
	   is to trigger NOTIFY watcher to handle SubscriptionChange events */
	if (mailbox_list_index_index_open(_list) < 0)
		return -1;
	view = mail_index_view_open(ilist->index);
	mail_index_get_header_ext(view, ilist->subs_hdr_ext_id, &data, &size);
	if (size != sizeof(counter))
		counter = ioloop_time;
	else {
		memcpy(&counter, data, size);
		if (++counter < (uint32_t)ioloop_time)
			counter = ioloop_time;
	}

	trans = mail_index_transaction_begin(view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_update_header_ext(trans, ilist->subs_hdr_ext_id,
				     0, &counter, sizeof(counter));
	(void)mail_index_transaction_commit(&trans);
	mail_index_view_close(&view);
	return 0;
}

static void mailbox_list_index_created(struct mailbox_list *list)
{
	struct mailbox_list_vfuncs *v = list->vlast;
	struct mailbox_list_index *ilist;
	bool has_backing_store;

	/* layout=index doesn't have any backing store */
	has_backing_store = strcmp(list->name, MAILBOX_LIST_NAME_INDEX) != 0;

	if (!list->mail_set->mailbox_list_index ||
	    strcmp(list->name, MAILBOX_LIST_NAME_NONE) == 0) {
		/* reserve the module context anyway, so syncing code knows
		   that the index is disabled */
		i_assert(has_backing_store);
		ilist = NULL;
		MODULE_CONTEXT_SET(list, mailbox_list_index_module, ilist);
		return;
	}

	ilist = p_new(list->pool, struct mailbox_list_index, 1);
	ilist->module_ctx.super = *v;
	list->vlast = &ilist->module_ctx.super;
	ilist->has_backing_store = has_backing_store;
	ilist->pending_init = TRUE;

	v->deinit = mailbox_list_index_deinit;
	v->iter_init = mailbox_list_index_iter_init;
	v->iter_deinit = mailbox_list_index_iter_deinit;
	v->iter_next = mailbox_list_index_iter_next;

	v->delete_mailbox = mailbox_list_index_delete_mailbox;
	v->delete_dir = mailbox_list_index_delete_dir;
	v->rename_mailbox = mailbox_list_index_rename_mailbox;
	v->set_subscribed = mailbox_list_index_set_subscribed;

	v->notify_init = mailbox_list_index_notify_init;
	v->notify_next = mailbox_list_index_notify_next;
	v->notify_deinit = mailbox_list_index_notify_deinit;
	v->notify_wait = mailbox_list_index_notify_wait;

	MODULE_CONTEXT_SET(list, mailbox_list_index_module, ilist);
}

static void mailbox_list_index_init_finish(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
	const char *dir;

	if (ilist == NULL || !ilist->pending_init)
		return;
	ilist->pending_init = FALSE;

	/* we've delayed this part of the initialization so that mbox format
	   can override the index root directory path */
	if (!mailbox_list_get_root_path(list, MAILBOX_LIST_PATH_TYPE_INDEX,
					&dir)) {
		/* in-memory indexes */
		dir = NULL;
	}
	i_assert(ilist->has_backing_store || dir != NULL);

	ilist->path = dir == NULL ? "(in-memory mailbox list index)" :
		p_strdup_printf(list->pool, "%s/"MAILBOX_LIST_INDEX_PREFIX, dir);
	ilist->index = mail_index_alloc(dir, MAILBOX_LIST_INDEX_PREFIX);

	ilist->ext_id = mail_index_ext_register(ilist->index, "list",
				sizeof(struct mailbox_list_index_header),
				sizeof(struct mailbox_list_index_record),
				sizeof(uint32_t));
	ilist->subs_hdr_ext_id = mail_index_ext_register(ilist->index, "subs",
							 sizeof(uint32_t), 0,
							 sizeof(uint32_t));
	mailbox_list_index_init_pool(ilist);

	mailbox_list_index_status_init_finish(list);
}

static void
mailbox_list_index_namespaces_added(struct mail_namespace *namespaces)
{
	struct mail_namespace *ns;

	for (ns = namespaces; ns != NULL; ns = ns->next)
		mailbox_list_index_init_finish(ns->list);
}

static void mailbox_list_index_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(box->list);
	struct index_list_mailbox *ibox;

	if (ilist == NULL)
		return;

	ibox = p_new(box->pool, struct index_list_mailbox, 1);
	ibox->module_ctx.super = box->v;
	MODULE_CONTEXT_SET(box, index_list_storage_module, ibox);

	/* for layout=index these get overridden */
	box->v.create_box = mailbox_list_index_create_mailbox;
	box->v.update_box = mailbox_list_index_update_mailbox;

	mailbox_list_index_status_init_mailbox(box);
	mailbox_list_index_backend_init_mailbox(box);
}

static struct mail_storage_hooks mailbox_list_index_hooks = {
	.mailbox_list_created = mailbox_list_index_created,
	.mail_namespaces_added = mailbox_list_index_namespaces_added,
	.mailbox_allocated = mailbox_list_index_mailbox_allocated
};

void mailbox_list_index_init(void); /* called in mailbox-list-register.c */

void mailbox_list_index_init(void)
{
	mail_storage_hooks_add_internal(&mailbox_list_index_hooks);
}
