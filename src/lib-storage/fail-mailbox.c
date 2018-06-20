/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "fail-mail-storage.h"

#define TEST_UID_VALIDITY 1

static bool fail_mailbox_is_readonly(struct mailbox *box ATTR_UNUSED)
{
	return FALSE;
}

static int fail_mailbox_enable(struct mailbox *box,
			       enum mailbox_feature features)
{
	box->enabled_features = features;
	return -1;
}

static int fail_mailbox_exists(struct mailbox *box ATTR_UNUSED,
			       bool auto_boxes ATTR_UNUSED,
			       enum mailbox_existence *existence_r)
{
	*existence_r = MAILBOX_EXISTENCE_NONE;
	return -1;
}

static int fail_mailbox_open(struct mailbox *box)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			       T_MAIL_ERR_MAILBOX_NOT_FOUND(box->vname));
	return -1;
}

static void fail_mailbox_close(struct mailbox *box ATTR_UNUSED)
{
}

static void fail_mailbox_free(struct mailbox *box)
{
	event_unref(&box->event);
}

static int
fail_mailbox_create(struct mailbox *box,
		    const struct mailbox_update *update ATTR_UNUSED,
		    bool directory ATTR_UNUSED)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Mailbox can't be created");
	return -1;
}

static int
fail_mailbox_update(struct mailbox *box,
		    const struct mailbox_update *update ATTR_UNUSED)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Mailbox can't be updated");
	return -1;
}

static int fail_mailbox_delete(struct mailbox *box)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Mailbox can't be deleted");
	return -1;
}

static int fail_mailbox_rename(struct mailbox *src,
			       struct mailbox *dest ATTR_UNUSED)
{
	mail_storage_set_error(src->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Mailbox can't be renamed");
	return -1;
}

static int fail_mailbox_get_status(struct mailbox *box ATTR_UNUSED,
				   enum mailbox_status_items items ATTR_UNUSED,
				   struct mailbox_status *status_r)
{
	status_r->uidvalidity = TEST_UID_VALIDITY;
	status_r->uidnext = 1;
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			       T_MAIL_ERR_MAILBOX_NOT_FOUND(box->vname));
	return -1;
}

static int
fail_mailbox_get_metadata(struct mailbox *box,
			  enum mailbox_metadata_items items ATTR_UNUSED,
			  struct mailbox_metadata *metadata_r ATTR_UNUSED)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			       T_MAIL_ERR_MAILBOX_NOT_FOUND(box->vname));
	return -1;
}

static int fail_mailbox_set_subscribed(struct mailbox *box,
				       bool set ATTR_UNUSED)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Mailbox can't be subscribed");
	return -1;
}

static struct mailbox_sync_context *
fail_mailbox_sync_init(struct mailbox *box,
		       enum mailbox_sync_flags flags ATTR_UNUSED)
{
	struct mailbox_sync_context *ctx;

	ctx = i_new(struct mailbox_sync_context, 1);
	ctx->box = box;
	return ctx;
}

static bool
fail_mailbox_sync_next(struct mailbox_sync_context *ctx ATTR_UNUSED,
		       struct mailbox_sync_rec *sync_rec_r ATTR_UNUSED)
{
	return FALSE;
}

static int
fail_mailbox_sync_deinit(struct mailbox_sync_context *ctx,
			 struct mailbox_sync_status *status_r ATTR_UNUSED)
{
	mail_storage_set_error(ctx->box->storage, MAIL_ERROR_NOTFOUND,
			       T_MAIL_ERR_MAILBOX_NOT_FOUND(ctx->box->vname));
	i_free(ctx);
	return -1;
}

static void fail_mailbox_notify_changes(struct mailbox *box ATTR_UNUSED)
{
}

static struct mailbox_transaction_context *
fail_mailbox_transaction_begin(struct mailbox *box,
			       enum mailbox_transaction_flags flags,
			       const char *reason ATTR_UNUSED)
{
	struct mailbox_transaction_context *ctx;

	ctx = i_new(struct mailbox_transaction_context, 1);
	ctx->box = box;
	ctx->flags = flags;
	i_array_init(&ctx->module_contexts, 5);
	return ctx;
}

static void
fail_mailbox_transaction_rollback(struct mailbox_transaction_context *t)
{
	array_free(&t->module_contexts);
	i_free(t);
}

static int
fail_mailbox_transaction_commit(struct mailbox_transaction_context *t,
				struct mail_transaction_commit_changes *changes_r)
{
	changes_r->uid_validity = TEST_UID_VALIDITY;
	fail_mailbox_transaction_rollback(t);
	return 0;
}

static struct mail_search_context *
fail_mailbox_search_init(struct mailbox_transaction_context *t,
			 struct mail_search_args *args,
			 const enum mail_sort_type *sort_program ATTR_UNUSED,
			 enum mail_fetch_field wanted_fields ATTR_UNUSED,
			 struct mailbox_header_lookup_ctx *wanted_headers ATTR_UNUSED)
{
	struct mail_search_context *ctx;

	ctx = i_new(struct mail_search_context, 1);
	ctx->transaction = t;
	ctx->args = args;

	i_array_init(&ctx->results, 5);
	i_array_init(&ctx->module_contexts, 5);
	return ctx;
}

static int fail_mailbox_search_deinit(struct mail_search_context *ctx)
{
	array_free(&ctx->results);
	array_free(&ctx->module_contexts);
	i_free(ctx);
	return 0;
}

static bool
fail_mailbox_search_next_nonblock(struct mail_search_context *ctx ATTR_UNUSED,
				  struct mail **mail_r, bool *tryagain_r)
{
	*tryagain_r = FALSE;
	*mail_r = NULL;
	return FALSE;
}

static bool
fail_mailbox_search_next_update_seq(struct mail_search_context *ctx ATTR_UNUSED)
{
	return FALSE;
}

static struct mail_save_context *
fail_mailbox_save_alloc(struct mailbox_transaction_context *t)
{
	struct mail_save_context *ctx;

	ctx = i_new(struct mail_save_context, 1);
	ctx->transaction = t;
	return ctx;
}

static int
fail_mailbox_save_begin(struct mail_save_context *ctx ATTR_UNUSED,
			struct istream *input ATTR_UNUSED)
{
	return -1;
}

static int
fail_mailbox_save_continue(struct mail_save_context *ctx ATTR_UNUSED)
{
	return -1;
}

static int
fail_mailbox_save_finish(struct mail_save_context *ctx ATTR_UNUSED)
{
	return -1;
}

static void
fail_mailbox_save_cancel(struct mail_save_context *ctx ATTR_UNUSED)
{
}

static int
fail_mailbox_copy(struct mail_save_context *ctx ATTR_UNUSED,
		  struct mail *mail ATTR_UNUSED)
{
	return -1;
}

static bool fail_mailbox_is_inconsistent(struct mailbox *box ATTR_UNUSED)
{
	return FALSE;
}

struct mailbox fail_mailbox = {
	.v = {
		fail_mailbox_is_readonly,
		fail_mailbox_enable,
		fail_mailbox_exists,
		fail_mailbox_open,
		fail_mailbox_close,
		fail_mailbox_free,
		fail_mailbox_create,
		fail_mailbox_update,
		fail_mailbox_delete,
		fail_mailbox_rename,
		fail_mailbox_get_status,
		fail_mailbox_get_metadata,
		fail_mailbox_set_subscribed,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		fail_mailbox_sync_init,
		fail_mailbox_sync_next,
		fail_mailbox_sync_deinit,
		NULL,
		fail_mailbox_notify_changes,
		fail_mailbox_transaction_begin,
		fail_mailbox_transaction_commit,
		fail_mailbox_transaction_rollback,
		NULL,
		fail_mailbox_mail_alloc,
		fail_mailbox_search_init,
		fail_mailbox_search_deinit,
		fail_mailbox_search_next_nonblock,
		fail_mailbox_search_next_update_seq,
		fail_mailbox_save_alloc,
		fail_mailbox_save_begin,
		fail_mailbox_save_continue,
		fail_mailbox_save_finish,
		fail_mailbox_save_cancel,
		fail_mailbox_copy,
		NULL,
		NULL,
		NULL,
		fail_mailbox_is_inconsistent
	}
};

struct mailbox *
fail_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		   const char *vname, enum mailbox_flags flags)
{
	struct mailbox *box;
	pool_t pool;

	pool = pool_alloconly_create("fail mailbox", 1024+512);
	box = p_new(pool, struct mailbox, 1);
	*box = fail_mailbox;
	box->vname = p_strdup(pool, vname);
	box->name = p_strdup(pool, mailbox_list_get_storage_name(list, vname));
	box->storage = storage;
	box->list = list;

	box->pool = pool;
	box->flags = flags;

	box->event = event_create(box->storage->event);
	event_add_category(box->event, &event_category_mailbox);
	event_add_str(box->event, "name", box->vname);
	event_set_append_log_prefix(box->event,
		t_strdup_printf("Mailbox %s: ", box->vname));

	p_array_init(&box->search_results, pool, 16);
	p_array_init(&box->module_contexts, pool, 5);
	return box;
}
