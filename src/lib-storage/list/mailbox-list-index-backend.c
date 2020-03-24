/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "mail-index.h"
#include "subscription-file.h"
#include "mailbox-list-delete.h"
#include "mailbox-list-subscriptions.h"
#include "mailbox-list-index-storage.h"
#include "mailbox-list-index-sync.h"

#include <stdio.h>

#define GLOBAL_TEMP_PREFIX ".temp."

struct index_mailbox_list {
	struct mailbox_list list;
	const char *temp_prefix;

	const char *create_mailbox_name;
	guid_128_t create_mailbox_guid;
};

extern struct mailbox_list index_mailbox_list;

static int
index_list_rename_mailbox(struct mailbox_list *_oldlist, const char *oldname,
			  struct mailbox_list *_newlist, const char *newname);

static struct mailbox_list *index_list_alloc(void)
{
	struct index_mailbox_list *list;
	pool_t pool;

	pool = pool_alloconly_create("index list", 2048);

	list = p_new(pool, struct index_mailbox_list, 1);
	list->list = index_mailbox_list;
	list->list.pool = pool;

	list->temp_prefix = p_strconcat(pool, GLOBAL_TEMP_PREFIX,
					my_hostname, ".", my_pid, ".", NULL);
	return &list->list;
}

static int index_list_init(struct mailbox_list *_list, const char **error_r)
{
	if (!_list->mail_set->mailbox_list_index) {
		*error_r = "LAYOUT=index requires mailbox_list_index=yes";
		return -1;
	}
	return 0;
}

static void index_list_deinit(struct mailbox_list *_list)
{
	struct index_mailbox_list *list = (struct index_mailbox_list *)_list;

	pool_unref(&list->list.pool);
}

static char index_list_get_hierarchy_sep(struct mailbox_list *list)
{
	return *list->ns->set->separator != '\0' ? *list->ns->set->separator :
		MAILBOX_LIST_INDEX_HIERARCHY_SEP;
}

static int
index_list_get_refreshed_node_seq(struct index_mailbox_list *list,
				  struct mail_index_view *view,
				  const char *name,
				  struct mailbox_list_index_node **node_r,
				  uint32_t *seq_r)
{
	unsigned int i;

	*node_r = NULL;
	*seq_r = 0;

	for (i = 0; i < 2; i++) {
		*node_r = mailbox_list_index_lookup(&list->list, name);
		if (*node_r == NULL)
			return 0;
		if (mail_index_lookup_seq(view, (*node_r)->uid, seq_r))
			return 1;
		/* mailbox was just expunged. refreshing should notice it. */
		if (mailbox_list_index_refresh_force(&list->list) < 0)
			return -1;
	}
	i_panic("mailbox list index: refreshing doesn't lose expunged uid=%u",
		(*node_r)->uid);
	return -1;
}

static const char *
index_get_guid_path(struct mailbox_list *_list, const char *root_dir,
		    const guid_128_t mailbox_guid)
{
	return t_strdup_printf("%s/%s%s", root_dir,
			       _list->set.mailbox_dir_name,
			       guid_128_to_string(mailbox_guid));
}

static int
index_list_get_path(struct mailbox_list *_list, const char *name,
		    enum mailbox_list_path_type type, const char **path_r)
{
	struct index_mailbox_list *list = (struct index_mailbox_list *)_list;
	struct mail_index_view *view;
	struct mailbox_list_index_node *node;
	struct mailbox_status status;
	guid_128_t mailbox_guid;
	const char *root_dir;
	uint32_t seq;
	int ret;

	if (name == NULL) {
		/* return root directories */
		return mailbox_list_set_get_root_path(&_list->set, type,
						      path_r) ? 1 : 0;
	}
	/* consistently use mailbox_dir_name as part of all mailbox
	   directories (index/control/etc) */
	switch (type) {
	case MAILBOX_LIST_PATH_TYPE_MAILBOX:
		type = MAILBOX_LIST_PATH_TYPE_DIR;
		break;
	case MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX:
		type = MAILBOX_LIST_PATH_TYPE_ALT_DIR;
		break;
	case MAILBOX_LIST_PATH_TYPE_LIST_INDEX:
		i_unreached();
	default:
		break;
	}
	if (!mailbox_list_set_get_root_path(&_list->set, type, &root_dir))
		return 0;

	if (list->create_mailbox_name != NULL &&
	    strcmp(list->create_mailbox_name, name) == 0) {
		*path_r = index_get_guid_path(_list, root_dir,
					      list->create_mailbox_guid);
		return 1;
	}

	/* ilist is only required from this point onwards.
	   At least imapc calls index_list_get_path without this context*/
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(_list);

	if (ilist->sync_ctx != NULL) {
		/* we could get here during sync from
		   index_list_mailbox_create_selectable() */
		view = ilist->sync_ctx->view;
		node = mailbox_list_index_lookup(&list->list, name);
		if (node == NULL) {
			seq = 0;
			ret = 0;
		} else if (mail_index_lookup_seq(view, node->uid, &seq)) {
			ret = 1;
		} else {
			i_panic("mailbox list index: lost uid=%u", node->uid);
		}
	} else {
		if (mailbox_list_index_refresh(&list->list) < 0)
			return -1;
		view = mail_index_view_open(ilist->index);
		ret = index_list_get_refreshed_node_seq(list, view, name, &node, &seq);
		if (ret < 0) {
			mail_index_view_close(&view);
			return -1;
		}
	}
	i_assert(ret == 0 || seq != 0);
	if (ret == 0) {
		mailbox_list_set_error(_list, MAIL_ERROR_NOTFOUND,
				       T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		ret = -1;
	} else if (!mailbox_list_index_status(_list, view, seq, 0,
					      &status, mailbox_guid, NULL) ||
		   guid_128_is_empty(mailbox_guid)) {
		mailbox_list_set_error(_list, MAIL_ERROR_NOTFOUND,
				       T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		ret = -1;
	} else {
		*path_r = index_get_guid_path(_list, root_dir, mailbox_guid);
		ret = 1;
	}
	if (ilist->sync_ctx == NULL)
		mail_index_view_close(&view);
	return ret;
}

static const char *
index_list_get_temp_prefix(struct mailbox_list *_list, bool global)
{
	struct index_mailbox_list *list = (struct index_mailbox_list *)_list;

	return global ? GLOBAL_TEMP_PREFIX : list->temp_prefix;
}

static int index_list_set_subscribed(struct mailbox_list *_list,
				     const char *name, bool set)
{
	struct index_mailbox_list *list = (struct index_mailbox_list *)_list;
	const char *path;

	if (_list->set.subscription_fname == NULL) {
		mailbox_list_set_error(_list, MAIL_ERROR_NOTPOSSIBLE,
				       "Subscriptions not supported");
		return -1;
	}

	path = t_strconcat(_list->set.control_dir != NULL ?
			   _list->set.control_dir : _list->set.root_dir,
			   "/", _list->set.subscription_fname, NULL);
	return subsfile_set_subscribed(_list, path, list->temp_prefix,
				       name, set);
}

static int
index_list_node_exists(struct index_mailbox_list *list, const char *name,
		       enum mailbox_existence *existence_r)
{
	struct mailbox_list_index_node *node;

	*existence_r = MAILBOX_EXISTENCE_NONE;

	if (mailbox_list_index_refresh(&list->list) < 0)
		return -1;

	node = mailbox_list_index_lookup(&list->list, name);
	if (node == NULL)
		return 0;

	if ((node->flags & (MAILBOX_LIST_INDEX_FLAG_NONEXISTENT |
			    MAILBOX_LIST_INDEX_FLAG_NOSELECT)) == 0) {
		/* selectable */
		*existence_r = MAILBOX_EXISTENCE_SELECT;
	} else {
		/* non-selectable */
		*existence_r = MAILBOX_EXISTENCE_NOSELECT;
	}
	return 0;
}

static int
index_list_mailbox_create_dir(struct index_mailbox_list *list, const char *name)
{
	struct mailbox_list_index_sync_context *sync_ctx;
	struct mailbox_list_index_node *node;
	uint32_t seq;
	bool created;
	int ret;

	if (mailbox_list_index_sync_begin(&list->list, &sync_ctx) < 0)
		return -1;

	seq = mailbox_list_index_sync_name(sync_ctx, name, &node, &created);
	if (created || (node->flags & MAILBOX_LIST_INDEX_FLAG_NONEXISTENT) != 0) {
		/* didn't already exist */
		node->flags = MAILBOX_LIST_INDEX_FLAG_NOSELECT;
		mail_index_update_flags(sync_ctx->trans, seq, MODIFY_REPLACE,
					(enum mail_flags)node->flags);
		ret = 1;
	} else {
		/* already existed */
		ret = 0;
	}
	if (mailbox_list_index_sync_end(&sync_ctx, TRUE) < 0)
		ret = -1;
	return ret;
}

static int
index_list_mailbox_create_selectable(struct mailbox *box,
				     const guid_128_t mailbox_guid)
{
	struct index_mailbox_list *list =
		(struct index_mailbox_list *)box->list;
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(box->list);
	struct mailbox_list_index_sync_context *sync_ctx;
	struct mailbox_list_index_record rec;
	struct mailbox_list_index_node *node;
	const void *data;
	bool expunged, created;
	uint32_t seq;

	if (mailbox_list_index_sync_begin(&list->list, &sync_ctx) < 0)
		return -1;

	seq = mailbox_list_index_sync_name(sync_ctx, box->name, &node, &created);
	if (box->corrupted_mailbox_name) {
		/* an existing mailbox is being created with a "unknown" name.
		   opening the mailbox will hopefully find its real name and
		   rename it. */
		node->flags |= MAILBOX_LIST_INDEX_FLAG_CORRUPTED_NAME;
		mail_index_update_flags(sync_ctx->trans, seq, MODIFY_ADD,
			(enum mail_flags)MAILBOX_LIST_INDEX_FLAG_CORRUPTED_NAME);
	}
	if (!created &&
	    (node->flags & (MAILBOX_LIST_INDEX_FLAG_NONEXISTENT |
			    MAILBOX_LIST_INDEX_FLAG_NOSELECT)) == 0) {
		/* already selectable */
		(void)mailbox_list_index_sync_end(&sync_ctx, TRUE);
		return 0;
	}

	mail_index_lookup_ext(sync_ctx->view, seq, ilist->ext_id,
			      &data, &expunged);
	i_assert(data != NULL && !expunged);
	memcpy(&rec, data, sizeof(rec));
	i_assert(guid_128_is_empty(rec.guid));

	/* make it selectable */
	node->flags &= ~(MAILBOX_LIST_INDEX_FLAG_NONEXISTENT |
			 MAILBOX_LIST_INDEX_FLAG_NOSELECT |
			 MAILBOX_LIST_INDEX_FLAG_NOINFERIORS);
	mail_index_update_flags(sync_ctx->trans, seq, MODIFY_REPLACE,
				(enum mail_flags)node->flags);

	/* set UIDVALIDITY if was set by the storage */
	if (box->index != NULL) {
		struct mail_index_view *view;

		view = mail_index_view_open(box->index);
		if (mail_index_get_header(view)->uid_validity != 0)
			rec.uid_validity = mail_index_get_header(view)->uid_validity;
		mail_index_view_close(&view);
	}

	/* set GUID */
	memcpy(rec.guid, mailbox_guid, sizeof(rec.guid));
	mail_index_update_ext(sync_ctx->trans, seq, ilist->ext_id, &rec, NULL);

	if (mailbox_list_index_sync_end(&sync_ctx, TRUE) < 0) {
		/* make sure we forget any changes done internally */
		mailbox_list_index_reset(ilist);
		return -1;
	}
	return 1;
}

static int
index_list_mailbox_create(struct mailbox *box,
			  const struct mailbox_update *update, bool directory)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);
	struct index_mailbox_list *list =
		(struct index_mailbox_list *)box->list;
	struct mailbox_update new_update;
	enum mailbox_existence existence;
	int ret;

	/* first do a quick check that it doesn't exist */
	if (index_list_node_exists(list, box->name, &existence) < 0) {
		mail_storage_copy_list_error(box->storage, box->list);
		return -1;
	}
	if (existence == MAILBOX_EXISTENCE_NONE && directory) {
		/* now add the directory to index locked */
		if ((ret = index_list_mailbox_create_dir(list, box->name)) < 0) {
			mail_storage_copy_list_error(box->storage, box->list);
			return -1;
		}
	} else if (existence != MAILBOX_EXISTENCE_SELECT && !directory) {
		/* if no GUID is requested, generate it ourself. set
		   UIDVALIDITY to index sometimes later. */
		if (update == NULL)
			i_zero(&new_update);
		else
			new_update = *update;
		if (guid_128_is_empty(new_update.mailbox_guid))
			guid_128_generate(new_update.mailbox_guid);

		/* create the backend mailbox first before it exists in the
		   list. the mailbox creation wants to use get_path() though,
		   so use a bit kludgy create_mailbox_* variables during the
		   creation to return the path. we'll also support recursively
		   creating more mailboxes in here. */
		const char *old_name;
		guid_128_t old_guid;

		old_name = list->create_mailbox_name;
		guid_128_copy(old_guid, list->create_mailbox_guid);

		list->create_mailbox_name = box->name;
		guid_128_copy(list->create_mailbox_guid, new_update.mailbox_guid);

		ret = ibox->module_ctx.super.create_box(box, &new_update, FALSE);

		if (ret == 0) {
			/* backend mailbox was successfully created. now add it
			   to the list. */
			ret = index_list_mailbox_create_selectable(box, new_update.mailbox_guid);
			if (ret < 0)
				mail_storage_copy_list_error(box->storage, box->list);
			if (ret <= 0) {
				/* failed to add to list. rollback the backend
				   mailbox creation */
				bool create_error = ret < 0;

				if (create_error)
					mail_storage_last_error_push(box->storage);
				if (mailbox_delete(box) < 0)
					ret = -1;
				if (create_error)
					mail_storage_last_error_pop(box->storage);
			}
		}
		list->create_mailbox_name = old_name;
		guid_128_copy(list->create_mailbox_guid, old_guid);
		if (ret < 0)
			return ret;
	} else {
		ret = 0;
	}

	if (ret == 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
		return -1;
	}
	return 0;
}

static int
index_list_mailbox_update(struct mailbox *box,
			  const struct mailbox_update *update)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);
	const char *root_dir, *old_path, *new_path;

	if (mailbox_list_get_path(box->list, box->name,
				  MAILBOX_LIST_PATH_TYPE_MAILBOX,
				  &old_path) <= 0)
		old_path = NULL;

	if (ibox->module_ctx.super.update_box(box, update) < 0)
		return -1;

	/* rename the directory */
	if (!guid_128_is_empty(update->mailbox_guid) && old_path != NULL &&
	    mailbox_list_set_get_root_path(&box->list->set,
					   MAILBOX_LIST_PATH_TYPE_MAILBOX,
					   &root_dir)) {
		new_path = index_get_guid_path(box->list, root_dir,
					       update->mailbox_guid);
		if (strcmp(old_path, new_path) == 0)
			;
		else if (rename(old_path, new_path) == 0)
			;
		else if (errno == ENOENT) {
			mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(box->name));
			return -1;
		} else {
			mailbox_set_critical(box, "rename(%s, %s) failed: %m",
					     old_path, new_path);
			return -1;
		}
	}

	mailbox_list_index_update_mailbox_index(box, update);
	return 0;
}

static int
index_list_mailbox_exists(struct mailbox *box, bool auto_boxes ATTR_UNUSED,
			  enum mailbox_existence *existence_r)
{
	struct index_mailbox_list *list =
		(struct index_mailbox_list *)box->list;

	if (index_list_node_exists(list, box->name, existence_r) < 0) {
		mail_storage_copy_list_error(box->storage, box->list);
		return -1;
	}
	return 0;
}

static bool mailbox_has_corrupted_name(struct mailbox *box)
{
	struct mailbox_list_index_node *node;

	if (box->corrupted_mailbox_name)
		return TRUE;

	node = mailbox_list_index_lookup(box->list, box->name);
	return node != NULL &&
		(node->flags & MAILBOX_LIST_INDEX_FLAG_CORRUPTED_NAME) != 0;
}

static void index_list_rename_corrupted(struct mailbox *box, const char *newname)
{
	if (index_list_rename_mailbox(box->list, box->name,
				      box->list, newname) == 0 ||
	    box->list->error != MAIL_ERROR_EXISTS)
		return;

	/* mailbox already exists. don't give up yet, just use the newname
	   as prefix and add the "lost-xx" as suffix. */
	char sep = mailbox_list_get_hierarchy_sep(box->list);
	const char *oldname = box->name;

	/* oldname should be at the root level, but check for hierarchies
	   anyway to be safe. */
	const char *p = strrchr(oldname, sep);
	if (p != NULL)
		oldname = p+1;

	newname = t_strdup_printf("%s-%s", newname, oldname);
	(void)index_list_rename_mailbox(box->list, box->name,
					box->list, newname);
}

static int index_list_mailbox_open(struct mailbox *box)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);
	const void *data;
	const unsigned char *name_hdr;
	size_t name_hdr_size;

	if (ibox->module_ctx.super.open(box) < 0)
		return -1;

	if (box->view == NULL) {
		/* FIXME: dsync-merge is performing a delete in obox - remove
		   this check once dsync-merging is no longer used. */
		return 0;
	}

	/* if mailbox name has changed, update it to the header. Use \0
	   as the hierarchy separator in the header. This is to make sure
	   we don't keep rewriting the name just in case some backend switches
	   between separators when accessed different ways. */

	/* Get the current mailbox name with \0 separators. */
	char sep = mailbox_list_get_hierarchy_sep(box->list);
	char *box_zerosep_name = t_strdup_noconst(box->name);
	size_t box_name_len = strlen(box_zerosep_name);
	for (size_t i = 0; i < box_name_len; i++) {
		if (box_zerosep_name[i] == sep)
			box_zerosep_name[i] = '\0';
	}

	/* Does it match what's in the header now? */
	mail_index_get_header_ext(box->view, box->box_name_hdr_ext_id,
				  &data, &name_hdr_size);
	name_hdr = data;
	while (name_hdr_size > 0 && name_hdr[name_hdr_size-1] == '\0') {
		/* Remove trailing \0 - header doesn't shrink always */
		name_hdr_size--;
	}
	if (name_hdr_size == box_name_len &&
	    memcmp(box_zerosep_name, name_hdr, box_name_len) == 0) {
		/* Same mailbox name */
	} else if (!mailbox_has_corrupted_name(box)) {
		/* Mailbox name changed - update */
		struct mail_index_transaction *trans =
			mail_index_transaction_begin(box->view, 0);
		mail_index_ext_resize_hdr(trans, box->box_name_hdr_ext_id,
					  box_name_len);
		mail_index_update_header_ext(trans, box->box_name_hdr_ext_id, 0,
					     box_zerosep_name, box_name_len);
		(void)mail_index_transaction_commit(&trans);
	} else if (name_hdr_size > 0) {
		/* Mailbox name is corrupted. Rename it to the previous name. */
		char sep = mailbox_list_get_hierarchy_sep(box->list);
		char *newname = t_malloc0(name_hdr_size + 1);
		memcpy(newname, name_hdr, name_hdr_size);
		for (size_t i = 0; i < name_hdr_size; i++) {
			if (newname[i] == '\0')
				newname[i] = sep;
		}

		index_list_rename_corrupted(box, newname);
	}
	return 0;
}

void mailbox_list_index_backend_sync_init(struct mailbox *box,
					  enum mailbox_sync_flags flags)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(box->list);

	if ((flags & MAILBOX_SYNC_FLAG_FORCE_RESYNC) != 0 &&
	    !ilist->force_resynced) {
		enum mail_storage_list_index_rebuild_reason reason =
			MAIL_STORAGE_LIST_INDEX_REBUILD_REASON_FORCE_RESYNC;

		if (box->storage->v.list_index_rebuild != NULL &&
		    box->storage->v.list_index_rebuild(box->storage, reason) < 0)
			ilist->force_resync_failed = TRUE;
		/* try to rebuild list index only once - even if it failed */
		ilist->force_resynced = TRUE;
	}
}

int mailbox_list_index_backend_sync_deinit(struct mailbox *box)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(box->list);

	if (ilist->force_resync_failed) {
		/* fail this only once */
		ilist->force_resync_failed = FALSE;
		return -1;
	}
	return 0;
}

static void
index_list_try_delete(struct mailbox_list *_list, const char *name,
		      enum mailbox_list_path_type type)
{
	const char *mailbox_path, *path, *error;

	if (mailbox_list_get_path(_list, name, MAILBOX_LIST_PATH_TYPE_MAILBOX,
				  &mailbox_path) <= 0 ||
	    mailbox_list_get_path(_list, name, type, &path) <= 0 ||
	    strcmp(path, mailbox_path) == 0)
		return;

	if (*_list->set.maildir_name == '\0' &&
	    (_list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) == 0) {
		/* this directory may contain also child mailboxes' data.
		   we don't want to delete that. */
		bool rmdir_path = *_list->set.maildir_name != '\0';
		if (mailbox_list_delete_mailbox_nonrecursive(_list, name, path,
							     rmdir_path) < 0)
			return;
	} else {
		if (mailbox_list_delete_trash(path, &error) < 0 &&
		    errno != ENOTEMPTY) {
			mailbox_list_set_critical(_list,
				"unlink_directory(%s) failed: %s", path, error);
		}
	}

	/* avoid leaving empty directories lying around */
	mailbox_list_delete_until_root(_list, path, type);
}

static void
index_list_delete_finish(struct mailbox_list *list, const char *name)
{
	index_list_try_delete(list, name, MAILBOX_LIST_PATH_TYPE_INDEX);
	index_list_try_delete(list, name, MAILBOX_LIST_PATH_TYPE_CONTROL);
	index_list_try_delete(list, name, MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX);
}

static int
index_list_delete_entry(struct index_mailbox_list *list, const char *name,
			bool delete_selectable)
{
	struct mailbox_list_index_sync_context *sync_ctx;
	int ret;

	if (list->create_mailbox_name != NULL &&
	    strcmp(name, list->create_mailbox_name) == 0) {
		/* we're rolling back a failed create. if the name exists in the
		   list, it was done by somebody else so we don't want to
		   remove it. */
		return 0;
	}

	if (mailbox_list_index_sync_begin(&list->list, &sync_ctx) < 0)
		return -1;
	ret = mailbox_list_index_sync_delete(sync_ctx, name, delete_selectable);
	if (mailbox_list_index_sync_end(&sync_ctx, TRUE) < 0)
		return -1;
	return ret;
}

static int
index_list_delete_mailbox(struct mailbox_list *_list, const char *name)
{
	struct index_mailbox_list *list = (struct index_mailbox_list *)_list;
	const char *path;
	int ret;

	/* first delete the mailbox files */
	ret = mailbox_list_get_path(_list, name, MAILBOX_LIST_PATH_TYPE_MAILBOX,
				    &path);
	if (ret <= 0)
		return ret;

	if ((_list->flags & (MAILBOX_LIST_FLAG_NO_MAIL_FILES |
			     MAILBOX_LIST_FLAG_NO_DELETES)) != 0) {
		ret = 0;
	} else if ((_list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0) {
		ret = mailbox_list_delete_mailbox_file(_list, name, path);
	} else {
		ret = mailbox_list_delete_mailbox_nonrecursive(_list, name,
							       path, TRUE);
	}

	if ((ret == 0 || (_list->props & MAILBOX_LIST_PROP_AUTOCREATE_DIRS) != 0) &&
	    (_list->flags & MAILBOX_LIST_FLAG_NO_DELETES) == 0)
		index_list_delete_finish(_list, name);
	if (ret == 0) {
		if (index_list_delete_entry(list, name, TRUE) < 0)
			return -1;
	}
	return ret;
}

static int
index_list_delete_dir(struct mailbox_list *_list, const char *name)
{
	struct index_mailbox_list *list = (struct index_mailbox_list *)_list;
	int ret;

	if ((ret = index_list_delete_entry(list, name, FALSE)) < 0)
		return -1;
	if (ret == 0) {
		mailbox_list_set_error(_list, MAIL_ERROR_EXISTS,
			"Mailbox has children, delete them first");
		return -1;
	}
	return 0;
}

static int
index_list_delete_symlink(struct mailbox_list *_list,
			  const char *name ATTR_UNUSED)
{
	mailbox_list_set_error(_list, MAIL_ERROR_NOTPOSSIBLE,
			       "Symlinks not supported");
	return -1;
}

static int
index_list_rename_mailbox(struct mailbox_list *_oldlist, const char *oldname,
			  struct mailbox_list *_newlist, const char *newname)
{
	struct index_mailbox_list *list = (struct index_mailbox_list *)_oldlist;
	const size_t oldname_len = strlen(oldname);
	struct mailbox_list_index_sync_context *sync_ctx;
	struct mailbox_list_index_record oldrec, newrec;
	struct mailbox_list_index_node *oldnode, *newnode, *child;
	const void *data;
	bool created, expunged;
	uint32_t oldseq, newseq;

	if (_oldlist != _newlist) {
		mailbox_list_set_error(_oldlist, MAIL_ERROR_NOTPOSSIBLE,
			"Renaming not supported across namespaces.");
		return -1;
	}

	if (str_begins(newname, oldname) &&
	   newname[oldname_len] == mailbox_list_get_hierarchy_sep(_newlist)) {
		mailbox_list_set_error(_oldlist, MAIL_ERROR_NOTPOSSIBLE,
			"Can't rename mailbox under itself.");
		return -1;
	}

	if (mailbox_list_index_sync_begin(&list->list, &sync_ctx) < 0)
		return -1;

	oldnode = mailbox_list_index_lookup(&list->list, oldname);
	if (oldnode == NULL) {
		(void)mailbox_list_index_sync_end(&sync_ctx, FALSE);
		mailbox_list_set_error(&list->list, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(oldname));
		return -1;
	}
	if (!mail_index_lookup_seq(sync_ctx->view, oldnode->uid, &oldseq))
		i_panic("mailbox list index: lost uid=%u", oldnode->uid);

	newseq = mailbox_list_index_sync_name(sync_ctx, newname,
					      &newnode, &created);
	if (!created) {
		(void)mailbox_list_index_sync_end(&sync_ctx, FALSE);
		mailbox_list_set_error(&list->list, MAIL_ERROR_EXISTS,
				       "Target mailbox already exists");
		return -1;
	}
	i_assert(oldnode != newnode);

	/* copy all the data from old node to new node */
	newnode->uid = oldnode->uid;
	newnode->flags = oldnode->flags;
	newnode->children = oldnode->children; oldnode->children = NULL;
	for (child = newnode->children; child != NULL; child = child->next)
		child->parent = newnode;

	/* remove the old node from existence */
	mailbox_list_index_node_unlink(sync_ctx->ilist, oldnode);

	/* update the old index record to contain the new name_id/parent_uid,
	   then expunge the added index record */
	mail_index_lookup_ext(sync_ctx->view, oldseq, sync_ctx->ilist->ext_id,
			      &data, &expunged);
	i_assert(data != NULL && !expunged);
	memcpy(&oldrec, data, sizeof(oldrec));

	mail_index_lookup_ext(sync_ctx->view, newseq, sync_ctx->ilist->ext_id,
			      &data, &expunged);
	i_assert(data != NULL && !expunged);
	memcpy(&newrec, data, sizeof(newrec));

	oldrec.name_id = newrec.name_id;
	oldrec.parent_uid = newrec.parent_uid;

	if ((newnode->flags & MAILBOX_LIST_INDEX_FLAG_CORRUPTED_NAME) != 0) {
		/* mailbox is renamed - clear away the corruption flag so the
		   new name will be written to the mailbox index header. */
		newnode->flags &= ~MAILBOX_LIST_INDEX_FLAG_CORRUPTED_NAME;
		mail_index_update_flags(sync_ctx->trans, oldseq, MODIFY_REMOVE,
			(enum mail_flags)MAILBOX_LIST_INDEX_FLAG_CORRUPTED_NAME);
	}
	mail_index_update_ext(sync_ctx->trans, oldseq,
			      sync_ctx->ilist->ext_id, &oldrec, NULL);
	mail_index_expunge(sync_ctx->trans, newseq);

	return mailbox_list_index_sync_end(&sync_ctx, TRUE);
}

static struct mailbox_list_iterate_context *
index_list_iter_init(struct mailbox_list *list,
		     const char *const *patterns,
		     enum mailbox_list_iter_flags flags)
{
	struct mailbox_list_iterate_context *ctx;
	pool_t pool;

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		return mailbox_list_subscriptions_iter_init(list, patterns,
							    flags);
	}

	pool = pool_alloconly_create("mailbox list index backend iter", 1024);
	ctx = p_new(pool, struct mailbox_list_iterate_context, 1);
	ctx->pool = pool;
	ctx->list = list;
	ctx->flags = flags;
	array_create(&ctx->module_contexts, pool, sizeof(void *), 5);
	return ctx;
}

static const struct mailbox_info *
index_list_iter_next(struct mailbox_list_iterate_context *ctx)
{
	if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
		return mailbox_list_subscriptions_iter_next(ctx);
	return NULL;
}

static int index_list_iter_deinit(struct mailbox_list_iterate_context *ctx)
{
	if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
		return mailbox_list_subscriptions_iter_deinit(ctx);
	pool_unref(&ctx->pool);
	return 0;
}

struct mailbox_list index_mailbox_list = {
	.name = MAILBOX_LIST_NAME_INDEX,
	.props = MAILBOX_LIST_PROP_NO_ROOT | MAILBOX_LIST_PROP_NO_INTERNAL_NAMES,
	.mailbox_name_max_length = MAILBOX_LIST_NAME_MAX_LENGTH,

	.v = {
		.alloc = index_list_alloc,
		.init = index_list_init,
		.deinit = index_list_deinit,
		.get_hierarchy_sep = index_list_get_hierarchy_sep,
		.get_vname = mailbox_list_default_get_vname,
		.get_storage_name = mailbox_list_default_get_storage_name,
		.get_path = index_list_get_path,
		.get_temp_prefix = index_list_get_temp_prefix,
		.iter_init = index_list_iter_init,
		.iter_next = index_list_iter_next,
		.iter_deinit = index_list_iter_deinit,
		.subscriptions_refresh = mailbox_list_subscriptions_refresh,
		.set_subscribed = index_list_set_subscribed,
		.delete_mailbox = index_list_delete_mailbox,
		.delete_dir = index_list_delete_dir,
		.delete_symlink = index_list_delete_symlink,
		.rename_mailbox = index_list_rename_mailbox,
	}
};

bool mailbox_list_index_backend_init_mailbox(struct mailbox *box,
					     struct mailbox_vfuncs *v)
{
	if (strcmp(box->list->name, MAILBOX_LIST_NAME_INDEX) != 0)
		return TRUE;

	/* NOTE: this is using the same v as
	   mailbox_list_index_status_init_mailbox(), so don't have them
	   accidentally override each others. */
	v->create_box = index_list_mailbox_create;
	v->update_box = index_list_mailbox_update;
	v->exists = index_list_mailbox_exists;
	v->open = index_list_mailbox_open;
	return FALSE;
}
