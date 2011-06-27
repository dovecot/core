/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

/*
   Expunging works like:

   1. Lock map index by beginning a map sync.
   2. Write map UID refcount changes to map index (=> tail != head).
   3. Expunge messages from mailbox index.
   4. Finish map sync, which updates tail=head and unlocks map index.

   If something crashes after 2 but before 4 is finished, tail != head and
   reader can do a full resync to figure out what got broken.
*/

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "hex-binary.h"
#include "str.h"
#include "mdbox-storage.h"
#include "mdbox-storage-rebuild.h"
#include "mdbox-map.h"
#include "mdbox-file.h"
#include "mdbox-sync.h"

#include <stdlib.h>

static int
dbox_sync_verify_expunge_guid(struct mdbox_sync_context *ctx, uint32_t seq,
			      const uint8_t guid_128[MAIL_GUID_128_SIZE])
{
	const void *data;
	uint32_t uid;

	mail_index_lookup_uid(ctx->sync_view, seq, &uid);
	mail_index_lookup_ext(ctx->sync_view, seq,
			      ctx->mbox->guid_ext_id, &data, NULL);
	if (mail_guid_128_is_empty(guid_128) ||
	    memcmp(data, guid_128, MAIL_GUID_128_SIZE) == 0)
		return 0;

	mail_storage_set_critical(&ctx->mbox->storage->storage.storage,
		"Mailbox %s: Expunged GUID mismatch for UID %u: %s vs %s",
		ctx->mbox->box.vname, uid,
		binary_to_hex(data, MAIL_GUID_128_SIZE),
		binary_to_hex(guid_128, MAIL_GUID_128_SIZE));
	mdbox_storage_set_corrupted(ctx->mbox->storage);
	return -1;
}

static int mdbox_sync_expunge(struct mdbox_sync_context *ctx, uint32_t seq,
			      const uint8_t guid_128[MAIL_GUID_128_SIZE])
{
	uint32_t map_uid;

	if (seq_range_array_add(&ctx->expunged_seqs, 0, seq)) {
		/* already marked as expunged in this sync */
		return 0;
	}

	if (dbox_sync_verify_expunge_guid(ctx, seq, guid_128) < 0)
		return -1;
	if (mdbox_mail_lookup(ctx->mbox, ctx->sync_view, seq, &map_uid) < 0)
		return -1;
	if (mdbox_map_update_refcount(ctx->map_trans, map_uid, -1) < 0)
		return -1;
	return 0;
}

static int mdbox_sync_rec(struct mdbox_sync_context *ctx,
			  const struct mail_index_sync_rec *sync_rec)
{
	uint32_t seq, seq1, seq2;

	if (sync_rec->type != MAIL_INDEX_SYNC_TYPE_EXPUNGE) {
		/* not interested */
		return 0;
	}

	if (!mail_index_lookup_seq_range(ctx->sync_view,
					 sync_rec->uid1, sync_rec->uid2,
					 &seq1, &seq2)) {
		/* already expunged everything. nothing to do. */
		return 0;
	}

	for (seq = seq1; seq <= seq2; seq++) {
		if (mdbox_sync_expunge(ctx, seq, sync_rec->guid_128) < 0)
			return -1;
	}
	return 0;
}

static int dbox_sync_mark_expunges(struct mdbox_sync_context *ctx)
{
	enum mail_index_transaction_flags flags =
		MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL;
	struct mailbox *box = &ctx->mbox->box;
	struct mail_index_transaction *trans;
	struct seq_range_iter iter;
	unsigned int n;
	const void *data;
	uint32_t seq, uid;

	/* use a separate transaction here so that we can commit the changes
	   during map transaction */
	trans = mail_index_transaction_begin(ctx->sync_view, flags);
	seq_range_array_iter_init(&iter, &ctx->expunged_seqs); n = 0;
	while (seq_range_array_iter_nth(&iter, n++, &seq)) {
		mail_index_lookup_uid(ctx->sync_view, seq, &uid);
		mail_index_lookup_ext(ctx->sync_view, seq,
				      ctx->mbox->guid_ext_id, &data, NULL);
		mail_index_expunge_guid(trans, seq, data);
	}
	if (mail_index_transaction_commit(&trans) < 0)
		return -1;

	if (box->v.sync_notify != NULL) {
		/* do notifications after commit finished successfully */
		seq_range_array_iter_init(&iter, &ctx->expunged_seqs); n = 0;
		while (seq_range_array_iter_nth(&iter, n++, &seq)) {
			mail_index_lookup_uid(ctx->sync_view, seq, &uid);
			box->v.sync_notify(box, uid, MAILBOX_SYNC_TYPE_EXPUNGE);
		}
	}
	return 0;
}

static int mdbox_sync_index(struct mdbox_sync_context *ctx)
{
	struct mailbox *box = &ctx->mbox->box;
	const struct mail_index_header *hdr;
	struct mail_index_sync_rec sync_rec;
	uint32_t seq1, seq2;
	int ret = 0;

	hdr = mail_index_get_header(ctx->sync_view);
	if (hdr->uid_validity == 0) {
		/* newly created index file */
		mail_storage_set_critical(box->storage,
			"Mailbox %s: Corrupted index, uidvalidity=0",
			box->vname);
		return 0;
	}

	/* mark the newly seen messages as recent */
	if (mail_index_lookup_seq_range(ctx->sync_view, hdr->first_recent_uid,
					hdr->next_uid, &seq1, &seq2)) {
		index_mailbox_set_recent_seq(&ctx->mbox->box, ctx->sync_view,
					     seq1, seq2);
	}

	/* handle syncing records without map being locked. */
	if (mdbox_map_atomic_is_locked(ctx->atomic)) {
		ctx->map_trans = mdbox_map_transaction_begin(ctx->atomic, FALSE);
		i_array_init(&ctx->expunged_seqs, 64);
	}
	while (mail_index_sync_next(ctx->index_sync_ctx, &sync_rec)) {
		if ((ret = mdbox_sync_rec(ctx, &sync_rec)) < 0)
			break;
	}

	/* write refcount changes to map index. transaction commit updates the
	   log head, while tail is left behind. */
	if (mdbox_map_atomic_is_locked(ctx->atomic)) {
		if (ret == 0)
			ret = mdbox_map_transaction_commit(ctx->map_trans);
		/* write changes to mailbox index */
		if (ret == 0)
			ret = dbox_sync_mark_expunges(ctx);

		/* finish the map changes and unlock the map. this also updates
		   map's tail -> head. */
		if (ret < 0)
			mdbox_map_atomic_set_failed(ctx->atomic);
		mdbox_map_transaction_free(&ctx->map_trans);
		array_free(&ctx->expunged_seqs);
	}

	if (box->v.sync_notify != NULL)
		box->v.sync_notify(box, 0, 0);

	return ret == 0 ? 1 :
		(ctx->mbox->storage->corrupted ? 0 : -1);
}

static int mdbox_sync_try_begin(struct mdbox_sync_context *ctx,
				enum mail_index_sync_flags sync_flags)
{
	struct mdbox_mailbox *mbox = ctx->mbox;
	int ret;

	ret = mail_index_sync_begin(mbox->box.index, &ctx->index_sync_ctx,
				    &ctx->sync_view, &ctx->trans, sync_flags);
	if (ret < 0) {
		mail_storage_set_index_error(&mbox->box);
		return -1;
	}
	if (ret == 0) {
		/* nothing to do */
		return 0;
	}

	if (!mdbox_map_atomic_is_locked(ctx->atomic) &&
	    mail_index_sync_has_expunges(ctx->index_sync_ctx)) {
		/* we have expunges, so we need to write to map.
		   it needs to be locked before mailbox index. */
		mail_index_sync_rollback(&ctx->index_sync_ctx);
		if (mdbox_map_atomic_lock(ctx->atomic) < 0)
			return -1;
		return mdbox_sync_try_begin(ctx, sync_flags);
	}
	return 1;
}

int mdbox_sync_begin(struct mdbox_mailbox *mbox, enum mdbox_sync_flags flags,
		     struct mdbox_map_atomic_context *atomic,
		     struct mdbox_sync_context **ctx_r)
{
	struct mail_storage *storage = mbox->box.storage;
	struct mdbox_sync_context *ctx;
	enum mail_index_sync_flags sync_flags;
	int ret;
	bool rebuild, storage_rebuilt = FALSE;

	*ctx_r = NULL;

	/* avoid race conditions with mailbox creation, don't check for dbox
	   headers until syncing has locked the mailbox */
	rebuild = mbox->storage->corrupted ||
		(flags & MDBOX_SYNC_FLAG_FORCE_REBUILD) != 0;
	if (rebuild) {
		if (mdbox_storage_rebuild_in_context(mbox->storage, atomic) < 0)
			return -1;
		index_mailbox_reset_uidvalidity(&mbox->box);
		storage_rebuilt = TRUE;
	}

	ctx = i_new(struct mdbox_sync_context, 1);
	ctx->mbox = mbox;
	ctx->flags = flags;
	ctx->atomic = atomic;

	sync_flags = index_storage_get_sync_flags(&mbox->box);
	if (!rebuild && (flags & MDBOX_SYNC_FLAG_FORCE) == 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES;
	if ((flags & MDBOX_SYNC_FLAG_FSYNC) != 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_FSYNC;
	/* don't write unnecessary dirty flag updates */
	sync_flags |= MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES;

	ret = mdbox_sync_try_begin(ctx, sync_flags);
	if (ret <= 0) {
		/* failed / nothing to do */
		i_free(ctx);
		return ret;
	}

	if ((ret = mdbox_sync_index(ctx)) <= 0) {
		mail_index_sync_rollback(&ctx->index_sync_ctx);
		i_free_and_null(ctx);

		if (ret < 0)
			return -1;

		/* corrupted */
		if (storage_rebuilt) {
			mail_storage_set_critical(storage,
				"mdbox %s: Storage keeps breaking",
				mbox->box.path);
			return -1;
		}

		/* we'll need to rebuild storage.
		   try again from the beginning. */
		mdbox_storage_set_corrupted(mbox->storage);
		return mdbox_sync_begin(mbox, flags, atomic, ctx_r);
	}

	*ctx_r = ctx;
	return 0;
}

int mdbox_sync_finish(struct mdbox_sync_context **_ctx, bool success)
{
	struct mdbox_sync_context *ctx = *_ctx;
	int ret = success ? 0 : -1;

	*_ctx = NULL;

	if (success) {
		if (mail_index_sync_commit(&ctx->index_sync_ctx) < 0) {
			mail_storage_set_index_error(&ctx->mbox->box);
			ret = -1;
		}
	} else {
		mail_index_sync_rollback(&ctx->index_sync_ctx);
	}

	i_free(ctx);
	return ret;
}

int mdbox_sync(struct mdbox_mailbox *mbox, enum mdbox_sync_flags flags)
{
	struct mdbox_sync_context *sync_ctx;
	struct mdbox_map_atomic_context *atomic;
	int ret;

	atomic = mdbox_map_atomic_begin(mbox->storage->map);
	ret = mdbox_sync_begin(mbox, flags, atomic, &sync_ctx);
	if (ret == 0 && sync_ctx != NULL)
		ret = mdbox_sync_finish(&sync_ctx, TRUE);
	if (ret == 0)
		mdbox_map_atomic_set_success(atomic);
	if (mdbox_map_atomic_finish(&atomic) < 0)
		ret = -1;
	return ret;
}

struct mailbox_sync_context *
mdbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct mdbox_mailbox *mbox = (struct mdbox_mailbox *)box;
	enum mdbox_sync_flags mdbox_sync_flags = 0;
	int ret = 0;

	if (!box->opened) {
		if (mailbox_open(box) < 0)
			ret = -1;
	}

	if (ret == 0 && (index_mailbox_want_full_sync(&mbox->box, flags) ||
			 mbox->storage->corrupted)) {
		if ((flags & MAILBOX_SYNC_FLAG_FORCE_RESYNC) != 0)
			mdbox_sync_flags |= MDBOX_SYNC_FLAG_FORCE_REBUILD;
		ret = mdbox_sync(mbox, mdbox_sync_flags);
	}

	return index_mailbox_sync_init(box, flags, ret < 0);
}
