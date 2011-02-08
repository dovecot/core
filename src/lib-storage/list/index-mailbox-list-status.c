/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-storage-private.h"
#include "index-mailbox-list.h"

#define INDEX_LIST_STORAGE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, index_list_storage_module)

#define CACHED_STATUS_ITEMS \
	(STATUS_MESSAGES | STATUS_UNSEEN | STATUS_RECENT | \
	 STATUS_UIDNEXT | STATUS_UIDVALIDITY | STATUS_HIGHESTMODSEQ)

struct index_list_mailbox {
	union mailbox_module_context module_ctx;
};

static MODULE_CONTEXT_DEFINE_INIT(index_list_storage_module,
				  &mail_storage_module_register);

static int
index_list_mailbox_open_view(struct mailbox *box,
			     struct mail_index_view **view_r, uint32_t *seq_r)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(box->list);
	struct index_mailbox_node *node;
	struct mail_index_view *view;
	uint32_t seq;

	if (index_mailbox_list_refresh(box->list) < 0)
		return -1;

	node = index_mailbox_list_lookup(box->list, box->vname);
	if (node == NULL) {
		/* mailbox not found */
		return 0;
	}

	view = mail_index_view_open(ilist->index);
	if (!mail_index_lookup_seq(view, node->uid, &seq)) {
		/* our in-memory tree is out of sync */
		index_mailbox_list_refresh_later(box->list);
		mail_index_view_close(&view);
		return 0;
	}

	*view_r = view;
	*seq_r = seq;
	return 1;
}

static bool
index_list_get_view_status(struct mailbox *box, struct mail_index_view *view,
			   uint32_t seq, enum mailbox_status_items items,
			   struct mailbox_status *status_r,
			   uint8_t *mailbox_guid)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(box->list);
	const void *data;
	bool expunged;
	bool ret = TRUE;

	if ((items & STATUS_UIDVALIDITY) != 0 || mailbox_guid != NULL) {
		const struct mailbox_list_index_record *rec;

		mail_index_lookup_ext(view, seq, ilist->ext_id,
				      &data, &expunged);
		rec = data;
		if (rec == NULL || rec->uid_validity == 0)
			ret = FALSE;
		else {
			status_r->uidvalidity = rec->uid_validity;
			memcpy(mailbox_guid, rec->guid, MAIL_GUID_128_SIZE);
		}
	}

	if ((items & (STATUS_MESSAGES | STATUS_UNSEEN |
		      STATUS_RECENT | STATUS_UIDNEXT)) != 0) {
		const struct mailbox_list_index_msgs_record *rec;

		mail_index_lookup_ext(view, seq, ilist->msgs_ext_id,
				      &data, &expunged);
		rec = data;
		if (rec == NULL || rec->uidnext == 0)
			ret = FALSE;
		else {
			status_r->messages = rec->messages;
			status_r->unseen = rec->unseen;
			status_r->recent = rec->recent;
			status_r->uidnext = rec->uidnext;
		}
	}
	if ((items & STATUS_HIGHESTMODSEQ) != 0) {
		const uint64_t *rec;

		mail_index_lookup_ext(view, seq, ilist->hmodseq_ext_id,
				      &data, &expunged);
		rec = data;
		if (rec == NULL || *rec == 0)
			ret = FALSE;
		else
			status_r->highest_modseq = *rec;
	}
	return ret;
}

static int
index_list_get_cached_status(struct mailbox *box,
			     enum mailbox_status_items items,
			     struct mailbox_status *status_r)
{
	struct mail_index_view *view;
	uint32_t seq;
	int ret;

	memset(status_r, 0, sizeof(*status_r));

	ret = index_list_mailbox_open_view(box, &view, &seq);
	if (ret <= 0)
		return ret;

	ret = index_list_get_view_status(box, view, seq, items, status_r, NULL);
	mail_index_view_close(&view);
	return ret;
}

static int
index_list_get_status(struct mailbox *box, enum mailbox_status_items items,
		      struct mailbox_status *status_r)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);

	if ((items & ~CACHED_STATUS_ITEMS) == 0 && !box->opened) {
		if (index_list_get_cached_status(box, items, status_r) > 0)
			return 0;
		/* nonsynced / error, fallback to doing it the slow way */
	}
	return ibox->module_ctx.super.get_status(box, items, status_r);
}

static int
index_list_update(struct mailbox *box, struct mail_index_view *view,
		  uint32_t seq, const struct mailbox_status *status)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(box->list);
	struct mail_index_transaction *trans;
	struct mail_index_transaction_commit_result result;
	struct mailbox_metadata metadata;
	struct mailbox_status old_status;
	uint8_t mailbox_guid[MAIL_GUID_128_SIZE];
	bool rec_changed, msgs_changed, hmodseq_changed;

	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata) < 0)
		memset(&metadata, 0, sizeof(metadata));

	memset(&old_status, 0, sizeof(old_status));
	(void)index_list_get_view_status(box, view, seq, CACHED_STATUS_ITEMS,
					 &old_status, mailbox_guid);

	rec_changed = old_status.uidvalidity != status->uidvalidity ||
		memcmp(metadata.guid, mailbox_guid, sizeof(metadata.guid)) == 0;
	msgs_changed = old_status.messages != status->messages ||
		old_status.unseen != status->unseen ||
		old_status.recent != status->recent ||
		old_status.uidnext != status->uidnext;
	/* update highest-modseq only if they're ever been used */
	if (old_status.highest_modseq == status->highest_modseq) {
		hmodseq_changed = FALSE;
	} else if ((box->enabled_features & MAILBOX_FEATURE_CONDSTORE) != 0 ||
		   old_status.highest_modseq != 0) {
		hmodseq_changed = TRUE;
	} else {
		const void *data;
		bool expunged;

		mail_index_lookup_ext(view, seq, ilist->hmodseq_ext_id,
				      &data, &expunged);
		hmodseq_changed = data != NULL;
	}

	hmodseq_changed = old_status.highest_modseq != status->highest_modseq &&
		(old_status.highest_modseq != 0 ||
		 (box->enabled_features & MAILBOX_FEATURE_CONDSTORE) != 0);

	if (!rec_changed && !msgs_changed && !hmodseq_changed)
		return 0;

	trans = mail_index_transaction_begin(view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);

	if (rec_changed) {
		struct mailbox_list_index_record rec;
		const void *old_data;
		bool expunged;

		mail_index_lookup_ext(view, seq, ilist->ext_id,
				      &old_data, &expunged);
		i_assert(old_data != NULL);
		memcpy(&rec, old_data, sizeof(rec));

		rec.uid_validity = status->uidvalidity;
		memcpy(rec.guid, mailbox_guid, sizeof(rec.guid));
		mail_index_update_ext(trans, seq, ilist->ext_id, &rec, NULL);
	}

	if (msgs_changed) {
		struct mailbox_list_index_msgs_record msgs;

		memset(&msgs, 0, sizeof(msgs));
		msgs.messages = status->messages;
		msgs.unseen = status->unseen;
		msgs.recent = status->recent;
		msgs.uidnext = status->uidnext;

		mail_index_update_ext(trans, seq, ilist->msgs_ext_id,
				      &msgs, NULL);
	}
	if (hmodseq_changed) {
		mail_index_update_ext(trans, seq, ilist->hmodseq_ext_id,
				      &status->highest_modseq, NULL);
	}

	return mail_index_transaction_commit_full(&trans, &result);
}

static int index_list_sync_deinit(struct mailbox_sync_context *ctx,
				  struct mailbox_sync_status *status_r)
{
	struct mailbox *box = ctx->box;
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(box->list);
	struct index_mailbox_node *node;
	struct mail_index_view *view;
	struct mailbox_status status;
	uint32_t seq;

	if (ibox->module_ctx.super.sync_deinit(ctx, status_r) < 0)
		return -1;
	ctx = NULL;

	/* update mailbox list index */
	node = index_mailbox_list_lookup(box->list, box->vname);
	if (node == NULL)
		index_mailbox_list_refresh_later(box->list);
	else {
		view = mail_index_view_open(ilist->index);
		if (mail_index_lookup_seq(view, node->uid, &seq)) {
			mailbox_get_open_status(box, CACHED_STATUS_ITEMS,
						&status);
			(void)index_list_update(box, view, seq, &status);
		}
		mail_index_view_close(&view);
	}
	return 0;
}

static void index_list_mail_mailbox_allocated(struct mailbox *box)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(box->list);
	struct index_list_mailbox *ibox;

	if (ilist == NULL)
		return;

	ibox = p_new(box->pool, struct index_list_mailbox, 1);
	ibox->module_ctx.super = box->v;
	box->v.get_status = index_list_get_status;
	box->v.sync_deinit = index_list_sync_deinit;

	MODULE_CONTEXT_SET(box, index_list_storage_module, ibox);
}

void index_mailbox_list_status_init_list(struct mailbox_list *list)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);

	ilist->msgs_ext_id = mail_index_ext_register(ilist->index, "msgs", 0,
		sizeof(struct mailbox_list_index_msgs_record),
		sizeof(uint32_t));

	ilist->hmodseq_ext_id =
		mail_index_ext_register(ilist->index, "msgs", 0,
					sizeof(uint64_t), sizeof(uint64_t));
}

static struct mail_storage_hooks index_mailbox_list_status_hooks = {
	.mailbox_allocated = index_list_mail_mailbox_allocated
};

void index_mailbox_list_status_init(void)
{
	mail_storage_hooks_add_internal(&index_mailbox_list_status_hooks);
}
