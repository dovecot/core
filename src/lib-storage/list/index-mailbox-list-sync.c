/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "index-storage.h"
#include "mailbox-list-index.h"
#include "index-mailbox-list.h"
#include "maildir/maildir-sync.h"

#include <sys/stat.h>

#define INDEX_LIST_STORAGE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, index_list_storage_module)

#define CACHED_STATUS_ITEMS \
	(STATUS_MESSAGES | STATUS_UNSEEN | STATUS_RECENT | \
	 STATUS_UIDNEXT | STATUS_UIDVALIDITY)

struct index_list_mailbox {
	union mailbox_module_context module_ctx;

	uint32_t log_seq;
	uoff_t log_offset;
};

struct index_list_map {
	const char *name;
	unsigned int eid_offset;
	unsigned int status_offset;
};
#undef DEF
#define DEF(a, b, c) \
	{ a, offsetof(struct index_mailbox_list, b), \
	  offsetof(struct mailbox_status, c) }
static struct index_list_map index_list_map[] = {
	DEF("msgs", eid_messages, messages),
	DEF("unseen", eid_unseen, unseen),
	DEF("recent", eid_recent, recent),
	DEF("uid_validity", eid_uid_validity, uidvalidity),
	DEF("uidnext", eid_uidnext, uidnext),
	{ NULL, 0, 0 }
};

static MODULE_CONTEXT_DEFINE_INIT(index_list_storage_module,
				  &mail_storage_module_register);

static void index_list_box_close(struct mailbox *box)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);

	ibox->module_ctx.super.close(box);
}

static int index_list_update_mail_index(struct index_mailbox_list *ilist,
					struct mailbox *box)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);
	struct mail_index_sync_ctx *mail_sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	struct mail_index_sync_rec sync_rec;
	int ret;

	if (ibox->log_seq == 0)
		return 0;

	ret = mail_index_sync_begin_to(ilist->mail_index,
				       &mail_sync_ctx, &view, &trans,
				       ibox->log_seq, ibox->log_offset, 0);
	if (ret <= 0)
		return ret;

	/* we should have only external transactions in here, for which we
	   don't need to do anything but write them to the index */
	while (mail_index_sync_next(mail_sync_ctx, &sync_rec))
		;

	return mail_index_sync_commit(&mail_sync_ctx);
}

static int
index_list_mailbox_open_unchanged_view(struct mailbox *box,
				       struct mail_index_view **view_r,
				       uint32_t *seq_r)
{
	struct index_mailbox_list *ilist;
	struct mail_index_view *view;
	uint32_t uid, seq;
	int ret;

	ilist = INDEX_LIST_CONTEXT(box->list);

	if (ilist == NULL) {
		/* indexing disabled */
		return 0;
	}

	ret = mailbox_list_index_lookup(ilist->list_sync_view, box->name, &uid);
	if (ret <= 0)
		return ret;

	/* make sure we're synced */
	if (index_list_update_mail_index(ilist, box) < 0)
		return -1;

	/* found from list index. lookup the mail index record for it */
	view = mail_index_view_open(ilist->mail_index);
	if (!mail_index_lookup_seq(view, uid, &seq)) {
		mail_index_view_close(&view);
		return 0;
	}

	T_BEGIN {
		ret = box->v.list_index_has_changed(box, view, seq);
	} T_END;
	if (ret != 0) {
		/* error / mailbox has changed. we'll need to sync it. */
		mail_index_view_close(&view);
		return ret < 0 ? -1 : 0;
	}

	*view_r = view;
	*seq_r = seq;
	return 1;
}

static int
index_list_get_cached_status(struct mailbox *box, struct mailbox_status *status)
{
	struct index_mailbox_list *ilist;
	struct mail_index_view *view;
	const void *data;
	uint32_t seq, *ext_id_p, *counter_p;
	unsigned int i;
	bool expunged;
	int ret;

	memset(status, 0, sizeof(*status));

	ret = index_list_mailbox_open_unchanged_view(box, &view, &seq);
	if (ret <= 0)
		return ret;

	ilist = INDEX_LIST_CONTEXT(box->list);
	for (i = 0; index_list_map[i].name != NULL; i++) {
		ext_id_p = PTR_OFFSET(ilist, index_list_map[i].eid_offset);
		mail_index_lookup_ext(view, seq, *ext_id_p, &data, &expunged);
		if (expunged || data == NULL) {
			ret = 0;
			break;
		}

		counter_p = PTR_OFFSET(status, index_list_map[i].status_offset);
		*counter_p = *(const uint32_t *)data;
	}

	mail_index_view_close(&view);
	return ret;
}

static void
index_list_get_status(struct mailbox *box, enum mailbox_status_items items,
		      struct mailbox_status *status)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);

	if ((items & ~CACHED_STATUS_ITEMS) == 0) {
		if (index_list_get_cached_status(box, status) > 0)
			return;
		/* nonsynced / error, fallback to doing it the slow way */
	}

	ibox->module_ctx.super.get_status(box, items, status);
}

static int index_list_lookup_or_create(struct index_mailbox_list *ilist,
				       struct mailbox *box, uint32_t *uid_r)
{
	struct mailbox_list_index_sync_ctx *sync_ctx;
	int ret;

	ret = mailbox_list_index_lookup(ilist->list_sync_view,
					box->name, uid_r);
	if (ret > 0) {
		/* we'll need the mailbox synced since we're updating its
		   contents based on what it already contains */
		if (index_list_update_mail_index(ilist, box) < 0)
			return -1;
		return 1;
	} else if (ret < 0)
		return -1;

	/* create the mailbox by doing a partial sync with the mailbox name
	   as the sync root path */
	if (mailbox_list_index_sync_init(ilist->list_index, box->name,
					 MAILBOX_LIST_SYNC_FLAG_PARTIAL,
					 &sync_ctx) < 0)
		return -1;
	if (mailbox_list_index_sync_commit(&sync_ctx) < 0)
		return -1;

	ret = mailbox_list_index_lookup(ilist->list_sync_view,
					box->name, uid_r);
	if (ret != 0)
		return ret < 0 ? -1 : 0;

	mail_storage_set_critical(box->storage,
		"mailbox index: Created mailbox %s not found", box->name);
	return -1;
}

static int
index_list_update(struct index_mailbox_list *ilist, struct mailbox *box,
		  struct mail_index_view *view, uint32_t seq,
		  const struct mailbox_status *status)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);
	struct mail_index_transaction *trans;
	struct mail_index_transaction_commit_result result;
	const void *data;
	const uint32_t *counter_p;
	uint32_t *ext_id_p;
	unsigned int i;
	bool expunged;
	int ret = 0;

	trans = mail_index_transaction_begin(view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);

	/* update counters */
	for (i = 0; index_list_map[i].name != NULL; i++) {
		ext_id_p = PTR_OFFSET(ilist, index_list_map[i].eid_offset);
		mail_index_lookup_ext(view, seq, *ext_id_p, &data, &expunged);
		if (expunged) {
			ret = -1;
			break;
		}

		counter_p = CONST_PTR_OFFSET(status,
					     index_list_map[i].status_offset);
		if (data == NULL ||
		    *(const uint32_t *)data != *counter_p) {
			mail_index_update_ext(trans, seq, *ext_id_p,
					      counter_p, NULL);
		}
	}

	if (box->v.list_index_update_sync(box, trans, seq) < 0)
		ret = -1;
	if (ret < 0) {
		mail_index_transaction_rollback(&trans);
		return -1;
	}

	if (mail_index_transaction_commit_full(&trans, &result) < 0)
		return -1;

	ibox->log_seq = result.log_file_seq;
	ibox->log_offset = result.log_file_offset;
	return 0;
}

static struct mailbox_sync_context *
index_list_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);
	struct mailbox_sync_context *ctx;

	/* clear any cached log seq/offset */
	ibox->log_seq = (uint32_t)-1;
	ibox->log_offset = 0;

	if (!box->opened) {
		/* check using the mailbox list index if the mailbox has
		   changed. if not, we don't need to open the mailbox yet. */
		struct mail_index_view *view;
		uint32_t seq;
		int ret;

		ret = index_list_mailbox_open_unchanged_view(box, &view, &seq);
		if (ret > 0) {
			ctx = i_new(struct mailbox_sync_context, 1);
			ctx->box = box;
			mail_index_view_close(&view);

			/* no changes, so don't bother checking again before
			   next sync */
			ibox->log_seq = 0;
			return ctx;
		}
	}

	return ibox->module_ctx.super.sync_init(box, flags);
}

static bool index_list_sync_next(struct mailbox_sync_context *ctx,
				 struct mailbox_sync_rec *sync_rec_r)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(ctx->box);

	if (!ctx->box->opened)
		return FALSE;

	return ibox->module_ctx.super.sync_next(ctx, sync_rec_r);
}

static int index_list_sync_deinit(struct mailbox_sync_context *ctx,
				  struct mailbox_sync_status *status_r)
{
	struct mailbox *box = ctx->box;
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);
	struct index_mailbox_list *ilist;
	struct mail_index_view *view;
	struct mailbox_status status;
	uint32_t uid, seq;

	if (!box->opened) {
		/* nothing synced. just return the status. */
		i_free(ctx);
		return 0;
	}

	ilist = INDEX_LIST_CONTEXT(box->list);

	if (ilist == NULL) {
		/* indexing disabled */
		return ibox->module_ctx.super.sync_deinit(ctx, status_r);
	}

	if (ibox->module_ctx.super.sync_deinit(ctx, status_r) < 0)
		return -1;
	ctx = NULL;

	/* sync mailbox list index */
	if (index_list_lookup_or_create(ilist, box, &uid) < 0) {
		/* just ignore the error */
		return 0;
	}

	view = mail_index_view_open(ilist->mail_index);
	if (mail_index_lookup_seq(view, uid, &seq)) {
		mailbox_get_status(box, CACHED_STATUS_ITEMS, &status);
		(void)index_list_update(ilist, box, view, seq, &status);
	}
	mail_index_view_close(&view);
	return 0;
}

static void index_list_mail_mailbox_allocated(struct mailbox *box)
{
	struct index_mailbox_list *ilist =
		INDEX_LIST_CONTEXT(box->list);
	struct index_list_mailbox *ibox;

	if (ilist == NULL)
		return;

	ibox = p_new(box->pool, struct index_list_mailbox, 1);
	ibox->module_ctx.super = box->v;
	box->v.close = index_list_box_close;
	box->v.get_status = index_list_get_status;
	box->v.sync_init = index_list_sync_init;
	box->v.sync_next = index_list_sync_next;
	box->v.sync_deinit = index_list_sync_deinit;

	MODULE_CONTEXT_SET(box, index_list_storage_module, ibox);
}

void index_mailbox_list_sync_init_list(struct mailbox_list *list)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);
	unsigned int i;
	uint32_t *ext_id_p;

	for (i = 0; index_list_map[i].name != NULL; i++) {
		ext_id_p = PTR_OFFSET(ilist, index_list_map[i].eid_offset);
		*ext_id_p = mail_index_ext_register(ilist->mail_index,
					index_list_map[i].name, 0,
					sizeof(uint32_t), sizeof(uint32_t));
	}
}

static struct mail_storage_hooks index_mailbox_list_sync_hooks = {
	.mailbox_allocated = index_list_mail_mailbox_allocated
};

void index_mailbox_list_sync_init(void)
{
	mail_storage_hooks_add_internal(&index_mailbox_list_sync_hooks);
}
