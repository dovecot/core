/* Copyright (c) 2021 Dovecot Authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "guid.h"
#include "str.h"
#include "str-sanitize.h"
#include "hex-binary.h"
#include "randgen.h"
#include "fs-api.h"
#include "mailbox-list-index.h"
#include "mailbox-list-index-sync.h"
#include "mail-storage-private.h"

struct mail_storage_list_index_rebuild_mailbox {
	guid_128_t guid;
	const char *index_name;
};

struct mail_storage_list_index_rebuild_ns {
	struct mail_namespace *ns;
	struct mailbox_list_index_sync_context *list_sync_ctx;
};

struct mail_storage_list_index_rebuild_ctx {
	struct mail_storage *storage;
	pool_t pool;
	struct mailbox_list *first_list;
	HASH_TABLE(uint8_t *, struct mail_storage_list_index_rebuild_mailbox *) mailboxes;
	ARRAY(struct mail_storage_list_index_rebuild_ns) rebuild_namespaces;
};

static bool
mail_storage_list_index_rebuild_get_namespaces(struct mail_storage_list_index_rebuild_ctx *ctx)
{
	struct mail_namespace *ns;
	struct mail_storage_list_index_rebuild_ns *rebuild_ns;

	p_array_init(&ctx->rebuild_namespaces, ctx->pool, 4);
	for (ns = ctx->storage->user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->storage != ctx->storage ||
		    ns->alias_for != NULL)
			continue;

		/* ignore any non-INDEX layout */
		if (strcmp(ns->list->name, MAILBOX_LIST_NAME_INDEX) != 0)
			continue;

		/* track first list */
		if (ctx->first_list == NULL)
			ctx->first_list = ns->list;

		rebuild_ns = array_append_space(&ctx->rebuild_namespaces);
		rebuild_ns->ns = ns;
	}

	return array_count(&ctx->rebuild_namespaces) > 0;
}

static int rebuild_ns_cmp(const struct mail_storage_list_index_rebuild_ns *ns1,
			  const struct mail_storage_list_index_rebuild_ns *ns2)
{
	return strcmp(ns1->ns->prefix, ns2->ns->prefix);
}

static int
mail_storage_list_index_rebuild_lock_lists(struct mail_storage_list_index_rebuild_ctx *ctx)
{
	struct mail_storage_list_index_rebuild_ns *rebuild_ns;

	/* sort to make sure all processes lock the lists in the same order
	   to avoid deadlocks. this should be the only place that locks more
	   than one list. */
	array_sort(&ctx->rebuild_namespaces, rebuild_ns_cmp);

	array_foreach_modifiable(&ctx->rebuild_namespaces, rebuild_ns) {
		if (mailbox_list_index_sync_begin(rebuild_ns->ns->list,
						  &rebuild_ns->list_sync_ctx) < 0) {
			mail_storage_copy_list_error(ctx->storage,
						     rebuild_ns->ns->list);
			return -1;
		}
	}
	return 0;
}

static void
mail_storage_list_index_rebuild_unlock_lists(struct mail_storage_list_index_rebuild_ctx *ctx)
{
	struct mail_storage_list_index_rebuild_ns *rebuild_ns;

	array_foreach_modifiable(&ctx->rebuild_namespaces, rebuild_ns) {
		if (rebuild_ns->list_sync_ctx != NULL)
			(void)mailbox_list_index_sync_end(&rebuild_ns->list_sync_ctx, TRUE);
	}
}

static int
mail_storage_list_index_fill_storage_mailboxes(struct mail_storage_list_index_rebuild_ctx *ctx)
{
	struct mail_storage_list_index_rebuild_mailbox *box;
	struct fs_iter *iter;
	const char *path, *fname, *error;
	guid_128_t guid;
	uint8_t *guid_p;

	path = mailbox_list_get_root_forced(ctx->first_list,
					    MAILBOX_LIST_PATH_TYPE_MAILBOX);
	iter = fs_iter_init_with_event(ctx->storage->mailboxes_fs,
				       ctx->storage->event, path,
				       FS_ITER_FLAG_DIRS | FS_ITER_FLAG_NOCACHE);
	while ((fname = fs_iter_next(iter)) != NULL) {
		if (guid_128_from_string(fname, guid) < 0)
			continue;

		box = p_new(ctx->pool, struct mail_storage_list_index_rebuild_mailbox, 1);
		guid_128_copy(box->guid, guid);
		guid_p = box->guid;
		hash_table_update(ctx->mailboxes, guid_p, box);
	}

	if (fs_iter_deinit(&iter, &error) < 0) {
		mail_storage_set_critical(ctx->storage,
			"List rebuild: fs_iter_deinit(%s) failed: %s", path,
			error);
		return -1;
	}
	return 0;
}

static int
mail_storage_list_remove_duplicate(struct mail_storage_list_index_rebuild_ctx *ctx,
				   struct mail_storage_list_index_rebuild_ns *rebuild_ns,
				   struct mailbox *box,
				   struct mail_storage_list_index_rebuild_mailbox *rebuild_box)
{
	const char *delete_name, *keep_name;

	if (strcmp(box->list->name, MAILBOX_LIST_NAME_INDEX) != 0) {
		/* we're not using LAYOUT=index. not really supported now,
		   but just ignore that in here. */
		return 0;
	}
	/* we'll need to delete one of these entries. if one of them begins with
	   "lost-", remove it. otherwise just pick one of them randomly. */
	if (strncmp(box->name, ctx->storage->lost_mailbox_prefix,
		    strlen(ctx->storage->lost_mailbox_prefix)) == 0) {
		delete_name = box->name;
		keep_name = rebuild_box->index_name;
	} else {
		delete_name = rebuild_box->index_name;
		keep_name = p_strdup(ctx->pool, box->name);
	}

	e_debug(ctx->storage->event,
		"Removing duplicate mailbox '%s' in favor of mailbox '%s'",
		str_sanitize(delete_name, 128), str_sanitize(keep_name, 128));

	if (mailbox_list_index_sync_delete(rebuild_ns->list_sync_ctx,
					   delete_name, TRUE) < 0) {
		mail_storage_set_critical(ctx->storage,
			"List rebuild: Couldn't delete duplicate mailbox list index entry %s: %s",
			delete_name, mailbox_list_get_last_internal_error(box->list, NULL));
		return -1;
	}
	e_warning(box->event, "List rebuild: Duplicated mailbox GUID %s found - deleting mailbox entry %s (and keeping %s)",
		  guid_128_to_string(rebuild_box->guid), delete_name, keep_name);
	rebuild_box->index_name = keep_name;
	return 0;
}

static int
mail_storage_list_index_find_indexed_mailbox(struct mail_storage_list_index_rebuild_ctx *ctx,
					     struct mail_storage_list_index_rebuild_ns *rebuild_ns,
					     const struct mailbox_info *info)
{
	struct mail_storage_list_index_rebuild_mailbox *rebuild_box;
	struct mailbox *box;
	struct mailbox_metadata metadata;
	const uint8_t *guid_p;
	int ret = 0;

	if ((info->flags & (MAILBOX_NOSELECT | MAILBOX_NONEXISTENT)) != 0)
		return 0;

	box = mailbox_alloc(info->ns->list, info->vname, MAILBOX_FLAG_IGNORE_ACLS);
	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata) < 0) {
		mail_storage_set_critical(rebuild_ns->ns->storage,
			"List rebuild: Couldn't lookup mailbox %s GUID: %s",
			info->vname, mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	} else {
		guid_p = metadata.guid;
		rebuild_box = hash_table_lookup(ctx->mailboxes, guid_p);
		if (rebuild_box == NULL) {
			/* indexed but doesn't exist in storage. shouldn't
			   happen normally, but it'll be created when it gets
			   accessed. */
			e_debug(box->event,
				"Mailbox GUID %s exists in list index, but not in storage",
				guid_128_to_string(guid_p));
		} else if (rebuild_box->index_name == NULL) {
			rebuild_box->index_name =
				p_strdup(ctx->pool, box->name);
			e_debug(box->event,
				"Mailbox GUID %s exists in list index and in storage",
				guid_128_to_string(guid_p));
		} else {
			/* duplicate GUIDs in index. in theory this could be
			   possible because of mailbox aliases, but we don't
			   support that for now. especially dsync doesn't like
			   duplicates. */
			if (mail_storage_list_remove_duplicate(ctx, rebuild_ns,
							       box, rebuild_box) < 0)
				ret = -1;
		}
	}
	mailbox_free(&box);
	return ret;
}

static int
mail_storage_list_index_find_indexed_mailboxes(struct mail_storage_list_index_rebuild_ctx *ctx,
					       struct mail_storage_list_index_rebuild_ns *rebuild_ns)
{
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	int ret = 0;

	iter = mailbox_list_iter_init(rebuild_ns->ns->list, "*",
				      MAILBOX_LIST_ITER_RAW_LIST |
				      MAILBOX_LIST_ITER_NO_AUTO_BOXES |
				      MAILBOX_LIST_ITER_SKIP_ALIASES);
	while (ret == 0 && (info = mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		ret = mail_storage_list_index_find_indexed_mailbox(ctx, rebuild_ns, info);
	} T_END;
	if (mailbox_list_iter_deinit(&iter) < 0) {
		mail_storage_set_critical(rebuild_ns->ns->storage,
			"List rebuild: Failed to iterate mailboxes: %s",
			mailbox_list_get_last_internal_error(rebuild_ns->ns->list, NULL));
		return -1;
	}
	return ret;
}

static int
mail_storage_list_mailbox_create(struct mailbox *box,
				 const struct mailbox_update *update)
{
	e_debug(box->event, "Attempting to create mailbox");
	if (mailbox_create(box, update, FALSE) == 0)
		return 1;

	if (mailbox_get_last_mail_error(box) == MAIL_ERROR_NOTFOUND) {
		/* if this is because mailbox was marked as deleted,
		   undelete it and retry. */
		if (mailbox_mark_index_deleted(box, FALSE) < 0)
			return -1;
		if (mailbox_create(box, update, FALSE) == 0)
			return 1;
	}
	if (mailbox_get_last_mail_error(box) == MAIL_ERROR_EXISTS)
		return 0;
	mailbox_set_critical(box,
		"List rebuild: Couldn't create mailbox %s: %s",
		mailbox_get_vname(box), mailbox_get_last_internal_error(box, NULL));
	return -1;
}

static int
mail_storage_list_index_try_create(struct mail_storage_list_index_rebuild_ctx *ctx,
				   const uint8_t *guid_p,
				   bool retry)
{
	struct mail_storage *storage = ctx->storage;
	struct mailbox_list *list;
	struct mailbox *box;
	struct mailbox_update update;
	enum mailbox_existence existence;
	string_t *name = t_str_new(128);
	unsigned char randomness[8];
	int ret;

	/* FIXME: we should find out the mailbox's original namespace from the
	   mailbox index's header. */
	list = ctx->first_list;

	i_zero(&update);
	guid_128_copy(update.mailbox_guid, guid_p);

	str_printfa(name, "%s%s%s", list->ns->prefix,
		    storage->lost_mailbox_prefix, guid_128_to_string(guid_p));
	if (retry) {
		random_fill(randomness, sizeof(randomness));
		str_append_c(name, '-');
		binary_to_hex_append(name, randomness, sizeof(randomness));
	}
	/* ignore ACLs to avoid interference */
	box = mailbox_alloc(list, str_c(name), MAILBOX_FLAG_IGNORE_ACLS);
	e_debug(box->event, "Mailbox GUID %s exists in storage, but not in list index",
		guid_128_to_string(guid_p));

	box->corrupted_mailbox_name = TRUE;
	if (mailbox_exists(box, FALSE, &existence) < 0) {
		mail_storage_set_critical(storage,
			"List rebuild: Couldn't lookup mailbox %s existence: %s",
			str_c(name), mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	} else if (existence != MAILBOX_EXISTENCE_NONE) {
		ret = 0;
	} else if ((ret = mail_storage_list_mailbox_create(box, &update)) <= 0)
		;
	else if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FORCE_RESYNC) < 0) {
		mail_storage_set_critical(storage,
			"List rebuild: Couldn't force resync on created mailbox %s: %s",
			str_c(name), mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	}
	mailbox_free(&box);

	if (ret < 0)
		return ret;

	/* open a second time to rename the mailbox to its original name,
	   ignore ACLs to avoid interference. */
	box = mailbox_alloc(list, str_c(name), MAILBOX_FLAG_IGNORE_ACLS);
	e_debug(box->event, "Attempting to recover original name");
	if (mailbox_open(box) < 0 &&
	    mailbox_get_last_mail_error(box) != MAIL_ERROR_NOTFOUND) {
		mail_storage_set_critical(storage,
			"List rebuild: Couldn't open recovered mailbox %s: %s",
			str_c(name), mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	}
	mailbox_free(&box);
	return ret;
}

static int
mail_storage_list_index_create(struct mail_storage_list_index_rebuild_ctx *ctx,
			       const uint8_t *guid_p)
{
	int i, ret = 0;

	for (i = 0; i < 100; i++) {
		T_BEGIN {
			ret = mail_storage_list_index_try_create(ctx, guid_p, i > 0);
		} T_END;
		if (ret != 0)
			return ret;
	}
	mail_storage_set_critical(ctx->storage,
		"List rebuild: Failed to create a new mailbox name for GUID %s - "
		"everything seems to exist?",
		guid_128_to_string(guid_p));
	return -1;
}

static int mail_storage_list_index_add_missing(struct mail_storage_list_index_rebuild_ctx *ctx)
{
	struct hash_iterate_context *iter;
	struct mail_storage_list_index_rebuild_mailbox *box;
	uint8_t *guid_p;
	unsigned int num_created = 0;
	int ret = 0;

	iter = hash_table_iterate_init(ctx->mailboxes);
	while (hash_table_iterate(iter, ctx->mailboxes, &guid_p, &box)) T_BEGIN {
		if (box->index_name == NULL) {
			if (mail_storage_list_index_create(ctx, guid_p) < 0)
				ret = -1;
			else
				num_created++;
		}
	} T_END;
	hash_table_iterate_deinit(&iter);
	if (num_created > 0) {
		e_warning(ctx->storage->event,
			  "Mailbox list rescan found %u lost mailboxes",
			  num_created);
	}
	return ret;
}

static int mail_storage_list_index_rebuild_ctx(struct mail_storage_list_index_rebuild_ctx *ctx)
{
	struct mail_storage_list_index_rebuild_ns *rebuild_ns;

	if (mail_storage_list_index_fill_storage_mailboxes(ctx) < 0)
		return -1;

	array_foreach_modifiable(&ctx->rebuild_namespaces, rebuild_ns) {
		e_debug(ctx->storage->event,
			"Rebuilding list index for namespace '%s'",
			rebuild_ns->ns->prefix);
		if (mail_storage_list_index_find_indexed_mailboxes(ctx, rebuild_ns) < 0)
			return -1;
	}

	/* finish list syncing before creating mailboxes, because
	   mailbox_create() will internally try to re-acquire the lock.
	   (alternatively we could just add the mailbox to the list index
	   directly, but that's could cause problems as well.) */
	mail_storage_list_index_rebuild_unlock_lists(ctx);
	if (mail_storage_list_index_add_missing(ctx) < 0)
		return -1;
	return 0;
}

static int mail_storage_list_index_rebuild_int(struct mail_storage *storage)
{
	struct mail_storage_list_index_rebuild_ctx ctx;
	int ret;

	if (storage->mailboxes_fs == NULL) {
		storage->rebuild_list_index = FALSE;
		mail_storage_set_critical(storage,
					  "BUG: Can't rebuild mailbox list index: "
					  "Missing mailboxes_fs");
		return 0;
	}

	if (storage->rebuilding_list_index)
		return 0;
	storage->rebuilding_list_index = TRUE;

	i_zero(&ctx);
	ctx.storage = storage;
	ctx.pool = pool_alloconly_create("mailbox list index rebuild", 10240);
	hash_table_create(&ctx.mailboxes, ctx.pool, 0, guid_128_hash, guid_128_cmp);

	/* if no namespaces are found, do nothing */
	if (!mail_storage_list_index_rebuild_get_namespaces(&ctx)) {
		hash_table_destroy(&ctx.mailboxes);
		pool_unref(&ctx.pool);
		return 0;
	}

	/* Only perform this for INDEX layout */
	if (strcmp(ctx.first_list->name, MAILBOX_LIST_NAME_INDEX) == 0) {
		/* do this operation while keeping mailbox list index locked.
		   this avoids race conditions between other list rebuilds and also
		   makes sure that other processes creating/deleting mailboxes can't
		   cause confusion with race conditions. */
		struct event_reason *reason =
			event_reason_begin("storage:mailbox_list_rebuild");
		if ((ret = mail_storage_list_index_rebuild_lock_lists(&ctx)) == 0)
			ret = mail_storage_list_index_rebuild_ctx(&ctx);
		mail_storage_list_index_rebuild_unlock_lists(&ctx);
		event_reason_end(&reason);
	} else
		ret = 0;

	hash_table_destroy(&ctx.mailboxes);
	pool_unref(&ctx.pool);

	if (ret == 0)
		storage->rebuild_list_index = FALSE;
	storage->rebuilding_list_index = FALSE;
	return ret;
}

int mail_storage_list_index_rebuild_and_set_uncorrupted(struct mail_storage *storage)
{
	struct mail_namespace *ns;
	int ret = 0;

	/* If mailbox list index is disabled, stop any attempt already here.
	   This saves some allocations and iterating all namespaces. */
	if (!storage->set->mailbox_list_index) {
		storage->rebuild_list_index = FALSE;
		return 0;
	}

	if (mail_storage_list_index_rebuild_int(storage) < 0)
		return -1;
	for (ns = storage->user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->storage != storage || ns->alias_for != NULL)
			continue;
		if (mailbox_list_index_set_uncorrupted(ns->list) < 0)
			ret = -1;
	}
	return ret;
}

int mail_storage_list_index_rebuild(struct mail_storage *storage,
				    enum mail_storage_list_index_rebuild_reason reason)
{
	/* If mailbox list index is disabled, stop any attempt already here. */
	if (!storage->set->mailbox_list_index) {
		storage->rebuild_list_index = FALSE;
		return 0;
	}

	switch (reason) {
	case MAIL_STORAGE_LIST_INDEX_REBUILD_REASON_CORRUPTED:
		e_warning(storage->event,
			  "Mailbox list index marked corrupted - rescanning");
		break;
	case MAIL_STORAGE_LIST_INDEX_REBUILD_REASON_FORCE_RESYNC:
		e_debug(storage->event,
			"Mailbox list index rebuild due to force resync");
		break;
	case MAIL_STORAGE_LIST_INDEX_REBUILD_REASON_NO_INBOX:
		e_debug(storage->event,
			"Mailbox list index rebuild due to no INBOX");
		break;
	}
	return mail_storage_list_index_rebuild_int(storage);
}
