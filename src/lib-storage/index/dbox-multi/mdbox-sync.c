/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

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
#include <dirent.h>

#define DBOX_REBUILD_COUNT 3

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
		ctx->mbox->ibox.box.vname, uid,
		binary_to_hex(data, MAIL_GUID_128_SIZE),
		binary_to_hex(guid_128, MAIL_GUID_128_SIZE));
	ctx->mbox->storage->storage.files_corrupted = TRUE;
	return -1;
}

static int mdbox_sync_expunge(struct mdbox_sync_context *ctx, uint32_t seq,
			      const uint8_t guid_128[MAIL_GUID_128_SIZE])
{
	uint32_t map_uid;

	if (seq_range_exists(&ctx->expunged_seqs, seq)) {
		/* already marked as expunged in this sync */
		return 0;
	}

	if (dbox_sync_verify_expunge_guid(ctx, seq, guid_128) < 0)
		return -1;

	if (mdbox_mail_lookup(ctx->mbox, ctx->sync_view, seq, &map_uid) < 0)
		return -1;

	seq_range_array_add(&ctx->expunged_seqs, 0, seq);
	array_append(&ctx->expunged_map_uids, &map_uid, 1);
	return 0;
}

static int mdbox_sync_add(struct mdbox_sync_context *ctx,
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

static void dbox_sync_mark_expunges(struct mdbox_sync_context *ctx)
{
	struct mailbox *box = &ctx->mbox->ibox.box;
	struct seq_range_iter iter;
	unsigned int n;
	const void *data;
	uint32_t seq, uid;

	seq_range_array_iter_init(&iter, &ctx->expunged_seqs); n = 0;
	while (seq_range_array_iter_nth(&iter, n++, &seq)) {
		mail_index_lookup_uid(ctx->sync_view, seq, &uid);
		mail_index_lookup_ext(ctx->sync_view, seq,
				      ctx->mbox->guid_ext_id, &data, NULL);
		mail_index_expunge_guid(ctx->trans, seq, data);

		if (box->v.sync_notify != NULL)
			box->v.sync_notify(box, uid, MAILBOX_SYNC_TYPE_EXPUNGE);
	}
}

static int mdbox_sync_index_finish_expunges(struct mdbox_sync_context *ctx)
{
	struct dbox_map_transaction_context *map_trans;
	int ret;

	map_trans = dbox_map_transaction_begin(ctx->mbox->storage->map, FALSE);
	ret = dbox_map_update_refcounts(map_trans, &ctx->expunged_map_uids, -1);
	if (ret == 0) {
		ret = dbox_map_transaction_commit(map_trans);
		if (ret == 0)
			dbox_sync_mark_expunges(ctx);
	}

	dbox_map_transaction_free(&map_trans);
	return ret;
}

static int mdbox_sync_index(struct mdbox_sync_context *ctx)
{
	struct mailbox *box = &ctx->mbox->ibox.box;
	const struct mail_index_header *hdr;
	struct mail_index_sync_rec sync_rec;
	uint32_t seq1, seq2;
	int ret = 0;

	hdr = mail_index_get_header(ctx->sync_view);
	if (hdr->uid_validity == 0) {
		/* newly created index file */
		return 0;
	}

	/* mark the newly seen messages as recent */
	if (mail_index_lookup_seq_range(ctx->sync_view, hdr->first_recent_uid,
					hdr->next_uid, &seq1, &seq2)) {
		index_mailbox_set_recent_seq(&ctx->mbox->ibox, ctx->sync_view,
					     seq1, seq2);
	}

	/* read all changes and group changes to same file_id together */
	i_array_init(&ctx->expunged_seqs, 64);
	i_array_init(&ctx->expunged_map_uids, 64);
	while (mail_index_sync_next(ctx->index_sync_ctx, &sync_rec)) {
		if ((ret = mdbox_sync_add(ctx, &sync_rec)) < 0)
			break;
	}
	if (ret == 0 && array_count(&ctx->expunged_seqs) > 0)
		ret = mdbox_sync_index_finish_expunges(ctx);

	if (box->v.sync_notify != NULL)
		box->v.sync_notify(box, 0, 0);

	array_free(&ctx->expunged_seqs);
	array_free(&ctx->expunged_map_uids);
	return ret == 0 ? 1 :
		(ctx->mbox->storage->storage.files_corrupted ? 0 : -1);
}

static int mdbox_refresh_header(struct mdbox_mailbox *mbox, bool retry)
{
	struct mail_index_view *view;
	struct mdbox_index_header hdr;
	int ret;

	view = mail_index_view_open(mbox->ibox.index);
	ret = mdbox_read_header(mbox, &hdr);
	mail_index_view_close(&view);

	if (ret == 0) {
		ret = mbox->storage->storage.files_corrupted ? -1 : 0;
	} else if (retry) {
		(void)mail_index_refresh(mbox->ibox.index);
		return mdbox_refresh_header(mbox, FALSE);
	}
	return ret;
}

int mdbox_sync_begin(struct mdbox_mailbox *mbox, enum mdbox_sync_flags flags,
		     struct mdbox_sync_context **ctx_r)
{
	struct mail_storage *storage = mbox->ibox.box.storage;
	struct mdbox_sync_context *ctx;
	enum mail_index_sync_flags sync_flags = 0;
	unsigned int i;
	int ret;
	bool rebuild, storage_rebuilt = FALSE;

	rebuild = mdbox_refresh_header(mbox, TRUE) < 0 ||
		(flags & MDBOX_SYNC_FLAG_FORCE_REBUILD) != 0;
	if (rebuild) {
		if (mdbox_storage_rebuild(mbox->storage) < 0)
			return -1;
		index_mailbox_reset_uidvalidity(&mbox->ibox);
		storage_rebuilt = TRUE;
	}

	ctx = i_new(struct mdbox_sync_context, 1);
	ctx->mbox = mbox;
	ctx->flags = flags;

	if ((mbox->ibox.box.flags & MAILBOX_FLAG_KEEP_RECENT) == 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_DROP_RECENT;
	if (!rebuild && (flags & MDBOX_SYNC_FLAG_FORCE) == 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES;
	if ((flags & MDBOX_SYNC_FLAG_FSYNC) != 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_FSYNC;
	/* don't write unnecessary dirty flag updates */
	sync_flags |= MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES;

	for (i = 0;; i++) {
		ret = mail_index_sync_begin(mbox->ibox.index,
					    &ctx->index_sync_ctx,
					    &ctx->sync_view, &ctx->trans,
					    sync_flags);
		if (ret <= 0) {
			if (ret < 0)
				mail_storage_set_index_error(&mbox->ibox);
			i_free(ctx);
			*ctx_r = NULL;
			return ret;
		}

		/* now that we're locked, check again if we want to rebuild */
		if (mdbox_refresh_header(mbox, FALSE) < 0)
			ret = 0;
		else {
			if ((ret = mdbox_sync_index(ctx)) > 0)
				break;
		}

		/* failure. keep the index locked while we're doing a
		   rebuild. */
		if (ret == 0) {
			if (!storage_rebuilt) {
				/* we'll need to rebuild storage too.
				   try again from the beginning. */
				mbox->storage->storage.files_corrupted = TRUE;
				mail_index_sync_rollback(&ctx->index_sync_ctx);
				i_free(ctx);
				return mdbox_sync_begin(mbox, flags, ctx_r);
			}
			mail_storage_set_critical(storage,
				"dbox %s: Storage keeps breaking",
				ctx->mbox->ibox.box.path);
			ret = -1;
		}
		mail_index_sync_rollback(&ctx->index_sync_ctx);
		if (ret < 0) {
			i_free(ctx);
			return -1;
		}
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
			mail_storage_set_index_error(&ctx->mbox->ibox);
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

	if (mdbox_sync_begin(mbox, flags, &sync_ctx) < 0)
		return -1;

	if (sync_ctx == NULL)
		return 0;
	return mdbox_sync_finish(&sync_ctx, TRUE);
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

	if (ret == 0 && (index_mailbox_want_full_sync(&mbox->ibox, flags) ||
			 mbox->storage->storage.files_corrupted)) {
		if ((flags & MAILBOX_SYNC_FLAG_FORCE_RESYNC) != 0)
			mdbox_sync_flags |= MDBOX_SYNC_FLAG_FORCE_REBUILD;
		ret = mdbox_sync(mbox, mdbox_sync_flags);
	}

	return index_mailbox_sync_init(box, flags, ret < 0);
}

static int mdbox_sync_altmove_add_files(struct mdbox_storage *dstorage,
					ARRAY_TYPE(seq_range) *file_ids)
{
	struct mail_storage *storage = &dstorage->storage.storage;
	DIR *dir;
	struct dirent *d;
	struct stat st;
	time_t altmove_mtime;
	string_t *path;
	unsigned int file_id, dir_len;
	int ret = 0;

	if (dstorage->set->mdbox_altmove == 0 ||
	    dstorage->alt_storage_dir == NULL)
		return 0;

	altmove_mtime = ioloop_time - dstorage->set->mdbox_altmove;

	/* we want to quickly find the latest alt file, but we also want to
	   avoid accessing the alt storage as much as possible. so we'll do
	   this by finding the lowest numbered file (n) from primary storage.
	   hopefully one of n-[1..m] is appendable in alt storage. */
	dir = opendir(dstorage->storage_dir);
	if (dir == NULL) {
		mail_storage_set_critical(storage,
			"opendir(%s) failed: %m", dstorage->storage_dir);
		return -1;
	}

	path = t_str_new(256);
	str_append(path, dstorage->storage_dir);
	str_append_c(path, '/');
	dir_len = str_len(path);

	for (errno = 0; (d = readdir(dir)) != NULL; errno = 0) {
		if (strncmp(d->d_name, MDBOX_MAIL_FILE_PREFIX,
			    strlen(MDBOX_MAIL_FILE_PREFIX)) != 0)
			continue;

		str_truncate(path, dir_len);
		str_append(path, d->d_name);

		file_id = strtoul(d->d_name + strlen(MDBOX_MAIL_FILE_PREFIX),
				  NULL, 10);

		if (stat(str_c(path), &st) < 0) {
			mail_storage_set_critical(storage,
				"stat(%s) failed: %m", str_c(path));
		} else if (st.st_mtime < altmove_mtime) {
			seq_range_array_add(file_ids, 0, file_id);
		}
	}
	if (errno != 0) {
		mail_storage_set_critical(storage,
			"readdir(%s) failed: %m", dstorage->storage_dir);
		ret = -1;
	}
	if (closedir(dir) < 0) {
		mail_storage_set_critical(storage,
			"closedir(%s) failed: %m", dstorage->storage_dir);
		ret = -1;
	}
	return ret;
}

int mdbox_sync_purge(struct mail_storage *_storage)
{
	struct mdbox_storage *storage = (struct mdbox_storage *)_storage;
	ARRAY_TYPE(seq_range) ref0_file_ids;
	struct dbox_file *file;
	struct seq_range_iter iter;
	unsigned int i = 0;
	uint32_t file_id;
	bool deleted;
	int ret = 0;

	i_array_init(&ref0_file_ids, 64);
	if (dbox_map_get_zero_ref_files(storage->map, &ref0_file_ids) < 0)
		ret = -1;

	/* add also files that can be altmoved */
	if (mdbox_sync_altmove_add_files(storage, &ref0_file_ids) < 0)
		ret = -1;

	seq_range_array_iter_init(&iter, &ref0_file_ids); i = 0;
	while (seq_range_array_iter_nth(&iter, i++, &file_id)) T_BEGIN {
		file = mdbox_file_init(storage, file_id);
		if (dbox_file_open(file, &deleted) > 0 && !deleted) {
			if (mdbox_file_purge(file) < 0)
				ret = -1;
		} else {
			dbox_map_remove_file_id(storage->map, file_id);
		}
		dbox_file_unref(&file);
	} T_END;
	array_free(&ref0_file_ids);
	return ret;
}
