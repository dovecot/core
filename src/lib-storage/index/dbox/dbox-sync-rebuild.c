/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "dbox-storage.h"
#include "maildir/maildir-uidlist.h"
#include "maildir/maildir-keywords.h"
#include "maildir/maildir-filename.h"
#include "dbox-map.h"
#include "dbox-file.h"
#include "dbox-sync.h"

#include <stdlib.h>
#include <dirent.h>

struct dbox_sync_rebuild_context {
	struct dbox_mailbox *mbox;

	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	uint32_t cache_ext_id;
	uint32_t cache_reset_id;

	struct mail_index *backup_index;
	struct mail_index_view *backup_view;

	struct maildir_uidlist_sync_ctx *maildir_sync_ctx;
	struct maildir_keywords *mk;
	struct maildir_keywords_sync_ctx *maildir_sync_keywords;

	uint32_t highest_uid;

	unsigned int cache_used:1;
	unsigned int storage_rebuild:1;
};

static void dbox_sync_set_uidvalidity(struct dbox_sync_rebuild_context *ctx)
{
	struct mailbox *box = &ctx->mbox->ibox.box;
	uint32_t uid_validity;

	/* if uidvalidity is set in the old index, use it */
	uid_validity = mail_index_get_header(ctx->view)->uid_validity;
	if (uid_validity == 0)
		uid_validity = dbox_get_uidvalidity_next(box->list);

	mail_index_update_header(ctx->trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
}

static void
dbox_sync_index_copy_cache(struct dbox_sync_rebuild_context *ctx,
			   struct mail_index_view *view,
			   uint32_t old_seq, uint32_t new_seq)
{
	struct mail_index_map *map;
	const void *data;
	uint32_t reset_id;
	bool expunged;

	if (ctx->cache_ext_id == (uint32_t)-1)
		return;

	mail_index_lookup_ext_full(view, old_seq, ctx->cache_ext_id,
				   &map, &data, &expunged);
	if (expunged)
		return;

	if (!mail_index_ext_get_reset_id(view, map, ctx->cache_ext_id,
					 &reset_id) || reset_id == 0)
		return;

	if (!ctx->cache_used) {
		/* set reset id */
		ctx->cache_used = TRUE;
		ctx->cache_reset_id = reset_id;
		mail_index_ext_reset(ctx->trans, ctx->cache_ext_id,
				     ctx->cache_reset_id, TRUE);
	}
	if (ctx->cache_reset_id == reset_id) {
		mail_index_update_ext(ctx->trans, new_seq,
				      ctx->cache_ext_id, data, NULL);
	}
}

static void
dbox_sync_index_copy_from_old(struct dbox_sync_rebuild_context *ctx,
			      struct mail_index_view *view,
			      uint32_t old_seq, uint32_t new_seq)
{
	struct mail_index *index = mail_index_view_get_index(view);
	const struct mail_index_record *rec;
	ARRAY_TYPE(keyword_indexes) old_keywords;
	struct mail_keywords *kw;

	/* copy flags */
	rec = mail_index_lookup(view, old_seq);
	mail_index_update_flags(ctx->trans, new_seq,
				MODIFY_REPLACE, rec->flags);

	/* copy keywords */
	t_array_init(&old_keywords, 32);
	mail_index_lookup_keywords(view, old_seq, &old_keywords);
	kw = mail_index_keywords_create_from_indexes(index, &old_keywords);
	mail_index_update_keywords(ctx->trans, new_seq, MODIFY_REPLACE, kw);
	mail_index_keywords_free(&kw);

	dbox_sync_index_copy_cache(ctx, view, old_seq, new_seq);
}

static void
dbox_sync_index_copy_from_maildir(struct dbox_sync_rebuild_context *ctx,
				  struct dbox_file *file, uint32_t seq)
{
	ARRAY_TYPE(keyword_indexes) keyword_indexes;
	struct mail_keywords *keywords;
	enum mail_flags flags;

	t_array_init(&keyword_indexes, 32);
	maildir_filename_get_flags(ctx->maildir_sync_keywords,
				   file->fname, &flags, &keyword_indexes);
	mail_index_update_flags(ctx->trans, seq, MODIFY_REPLACE, flags);

	keywords = mail_index_keywords_create_from_indexes(ctx->mbox->ibox.index,
							   &keyword_indexes);
	mail_index_update_keywords(ctx->trans, seq, MODIFY_REPLACE, keywords);
	mail_index_keywords_free(&keywords);
}

void dbox_sync_rebuild_index_metadata(struct dbox_sync_rebuild_context *ctx,
				      struct dbox_file *file,
				      uint32_t new_seq, uint32_t uid)
{
	uint32_t old_seq;

	if (mail_index_lookup_seq(ctx->view, uid, &old_seq)) {
		/* the message exists in the old index.
		   copy the metadata from it. */
		dbox_sync_index_copy_from_old(ctx, ctx->view, old_seq, new_seq);
	} else if (ctx->backup_view != NULL &&
		   mail_index_lookup_seq(ctx->backup_view, uid, &old_seq)) {
		/* copy the metadata from backup index. */
		dbox_sync_index_copy_from_old(ctx, ctx->backup_view,
					      old_seq, new_seq);
	} else if (file != NULL && file->maildir_file) {
		/* we're probably doing initial sync after migration from
		   maildir. preserve the old flags. */
		dbox_sync_index_copy_from_maildir(ctx, file, new_seq);
	}
}

static int dbox_sync_add_file_index(struct dbox_sync_rebuild_context *ctx,
				    struct dbox_file *file)
{
	uint32_t seq;
	uoff_t size;
	bool expunged;
	int ret;

	ret = dbox_file_get_mail_stream(file, 0, &size, NULL, &expunged);
	if (ret <= 0) {
		if (ret < 0)
			return -1;

		i_warning("dbox: Ignoring broken file: %s", file->current_path);
		return 0;
	}
	if (expunged) {
		/* the file just got deleted? */
		return 0;
	}

	mail_index_append(ctx->trans, file->uid, &seq);
	T_BEGIN {
		dbox_sync_rebuild_index_metadata(ctx, file, seq, file->uid);
	} T_END;
	return 0;
}

static int
dbox_sync_add_uid_file(struct dbox_sync_rebuild_context *ctx,
		       const char *dir, const char *fname)
{
	struct dbox_file *file;
	unsigned long uid;
	char *p;
	int ret;

	fname += sizeof(DBOX_MAIL_FILE_UID_PREFIX)-1;
	uid = strtoul(fname, &p, 10);
	if (*p != '\0' || uid == 0 || uid >= (uint32_t)-1) {
		i_warning("dbox %s: Ignoring invalid filename %s",
			  ctx->mbox->ibox.box.path, fname);
		return 0;
	}

	if (ctx->highest_uid < uid)
		ctx->highest_uid = uid;

	file = dbox_file_init_single(ctx->mbox, uid);
	file->current_path = i_strdup_printf("%s/%s", dir, fname);

	ret = dbox_sync_add_file_index(ctx, file);
	dbox_file_unref(&file);
	return ret;
}

static int
dbox_sync_add_maildir_file(struct dbox_sync_rebuild_context *ctx,
			   const char *fname)
{
	int ret;

	if (ctx->maildir_sync_ctx == NULL) {
		i_assert(ctx->mk == NULL);

		ctx->mk = maildir_keywords_init_readonly(&ctx->mbox->ibox.box);
		ctx->maildir_sync_keywords =
			maildir_keywords_sync_init(ctx->mk,
						   ctx->mbox->ibox.index);

		ret = maildir_uidlist_sync_init(ctx->mbox->maildir_uidlist,
						MAILDIR_UIDLIST_SYNC_NOLOCK,
						&ctx->maildir_sync_ctx);
		if (ret <= 0) {
			i_assert(ret < 0);
			return -1;
		}
	}

	/* sync all maildir files first and let maildir uidlist code assign
	   UIDs for unseen files. */
	ret = maildir_uidlist_sync_next(ctx->maildir_sync_ctx, fname, 0);
	if (ret == 0) {
		i_warning("%s: Ignoring duplicate maildir file: %s",
			  ctx->mbox->ibox.box.path, fname);
	}
	return ret;
}

static int
dbox_sync_add_file(struct dbox_sync_rebuild_context *ctx,
		   const char *path, const char *fname, bool primary)
{
	if (strncmp(fname, DBOX_MAIL_FILE_UID_PREFIX,
		    sizeof(DBOX_MAIL_FILE_UID_PREFIX)-1) == 0)
		return dbox_sync_add_uid_file(ctx, path, fname);

	if (primary && strstr(fname, ":2,") != NULL)
		return dbox_sync_add_maildir_file(ctx, fname);
	return 0;
}

static int dbox_sync_index_rebuild_dir(struct dbox_sync_rebuild_context *ctx,
				       const char *path, bool primary)
{
	struct mail_storage *storage = ctx->mbox->ibox.box.storage;
	DIR *dir;
	struct dirent *d;
	int ret = 0;

	dir = opendir(path);
	if (dir == NULL) {
		if (errno == ENOENT) {
			if (!primary) {
				/* alt directory doesn't exist, ignore */
				return 0;
			}
			mailbox_set_deleted(&ctx->mbox->ibox.box);
			return -1;
		}
		mail_storage_set_critical(storage,
			"opendir(%s) failed: %m", path);
		return -1;
	}
	do {
		errno = 0;
		if ((d = readdir(dir)) == NULL)
			break;

		T_BEGIN {
			ret = dbox_sync_add_file(ctx, path, d->d_name, primary);
		} T_END;
	} while (ret >= 0);
	if (errno != 0) {
		mail_storage_set_critical(storage,
			"readdir(%s) failed: %m", path);
		ret = -1;
	}

	if (closedir(dir) < 0) {
		mail_storage_set_critical(storage,
			"closedir(%s) failed: %m", path);
		ret = -1;
	}
	return ret;
}

static int dbox_sync_maildir_finish(struct dbox_sync_rebuild_context *ctx)
{
	struct dbox_mailbox *mbox = ctx->mbox;
	struct maildir_uidlist_iter_ctx *iter;
	struct mail_index_view *trans_view;
	struct dbox_file *file;
	const char *fname;
	enum maildir_uidlist_rec_flag flags;
	uint32_t uid, next_uid;
	int ret = 0;

	if (ctx->maildir_sync_ctx == NULL)
		return 0;

	/* we'll need the uidlist to contain the latest filenames.
	   since there's no easy way to figure out if they changed, just
	   recreate the uidlist always. */
	maildir_uidlist_sync_recreate(ctx->maildir_sync_ctx);

	/* update the maildir uidlist's next_uid if we have seen higher
	   dbox UIDs */
	trans_view = mail_index_transaction_open_updated_view(ctx->trans);
	next_uid = mail_index_get_header(trans_view)->next_uid;
	mail_index_view_close(&trans_view);
	maildir_uidlist_set_next_uid(mbox->maildir_uidlist, next_uid, FALSE);
	maildir_uidlist_set_next_uid(mbox->maildir_uidlist,
				     ctx->highest_uid + 1, FALSE);
	/* assign UIDs for new maildir mails before iterating */
	maildir_uidlist_sync_finish(ctx->maildir_sync_ctx);

	mbox->highest_maildir_uid =
		maildir_uidlist_get_next_uid(mbox->maildir_uidlist);

	iter = maildir_uidlist_iter_init(mbox->maildir_uidlist);
	while (maildir_uidlist_iter_next(iter, &uid, &flags, &fname)) {
		file = dbox_file_init_single(mbox, uid);
		file->current_path =
			i_strdup_printf("%s/%s", ctx->mbox->ibox.box.path,
					fname);

		ret = dbox_sync_add_file_index(ctx, file);
		dbox_file_unref(&file);
		if (ret < 0)
			break;
	}
	maildir_uidlist_iter_deinit(&iter);
	return ret < 0 ? -1 : 0;
}

static void dbox_sync_update_header(struct dbox_sync_rebuild_context *ctx)
{
	const struct dbox_index_header *hdr;
	struct dbox_index_header new_hdr;
	const void *data;
	size_t data_size;

	mail_index_get_header_ext(ctx->mbox->ibox.view,
				  ctx->mbox->dbox_hdr_ext_id,
				  &data, &data_size);
	hdr = data;
	if (data_size == sizeof(*hdr))
		new_hdr = *hdr;
	else
		memset(&new_hdr, 0, sizeof(new_hdr));
	if (new_hdr.highest_maildir_uid < ctx->mbox->highest_maildir_uid)
		new_hdr.highest_maildir_uid = ctx->mbox->highest_maildir_uid;
	new_hdr.map_uid_validity = !ctx->storage_rebuild ? 0 :
		dbox_map_get_uid_validity(ctx->mbox->storage->map);
	mail_index_update_header_ext(ctx->trans, ctx->mbox->dbox_hdr_ext_id, 0,
				     &new_hdr, sizeof(new_hdr));
}

struct dbox_sync_rebuild_context *
dbox_sync_index_rebuild_init(struct dbox_mailbox *mbox,
			     struct mail_index_view *view,
			     struct mail_index_transaction *trans,
			     bool storage_rebuild)
{
	struct mailbox *box = &mbox->ibox.box;
	struct dbox_sync_rebuild_context *ctx;
	const char *index_dir;
	enum mail_index_open_flags open_flags = MAIL_INDEX_OPEN_FLAG_READONLY;

	ctx = i_new(struct dbox_sync_rebuild_context, 1);
	ctx->mbox = mbox;
	ctx->view = view;
	ctx->trans = trans;
	ctx->storage_rebuild = storage_rebuild;
	mail_index_reset(ctx->trans);
	index_mailbox_reset_uidvalidity(&mbox->ibox);
	mail_index_ext_lookup(mbox->ibox.index, "cache", &ctx->cache_ext_id);

	/* if backup index file exists, try to use it */
	index_dir = mailbox_list_get_path(box->list, box->name,
					  MAILBOX_LIST_PATH_TYPE_INDEX);
	ctx->backup_index =
		mail_index_alloc(index_dir, DBOX_INDEX_PREFIX".backup");

#ifndef MMAP_CONFLICTS_WRITE
	if (box->storage->set->mmap_disable)
#endif
		open_flags |= MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE;
	if (mail_index_open(ctx->backup_index, open_flags,
			    box->storage->set->parsed_lock_method) <= 0)
		mail_index_free(&ctx->backup_index);
	else
		ctx->backup_view = mail_index_view_open(ctx->backup_index);
	return ctx;
}

int dbox_sync_index_rebuild_singles(struct dbox_sync_rebuild_context *ctx)
{
	int ret = 0;

	dbox_sync_set_uidvalidity(ctx);
	if (dbox_sync_index_rebuild_dir(ctx, ctx->mbox->ibox.box.path, TRUE) < 0)
		ret = -1;
	else if (ctx->mbox->alt_path != NULL) {
		if (dbox_sync_index_rebuild_dir(ctx, ctx->mbox->alt_path,
						FALSE) < 0)
			ret = -1;
	}

	if (ret == 0) {
		if (dbox_sync_maildir_finish(ctx) < 0)
			ret = -1;
	}

	if (ctx->maildir_sync_ctx != NULL) {
		if (maildir_uidlist_sync_deinit(&ctx->maildir_sync_ctx,
						ret == 0) < 0)
			ret = -1;
	}
	if (ctx->maildir_sync_keywords != NULL)
		maildir_keywords_sync_deinit(&ctx->maildir_sync_keywords);
	if (ctx->mk != NULL)
		maildir_keywords_deinit(&ctx->mk);
	return ret;
}

void dbox_sync_index_rebuild_deinit(struct dbox_sync_rebuild_context **_ctx)
{
	struct dbox_sync_rebuild_context *ctx = *_ctx;

	*_ctx = NULL;
	if (ctx->backup_index != NULL) {
		mail_index_view_close(&ctx->backup_view);
		mail_index_free(&ctx->backup_index);
	}
	dbox_sync_update_header(ctx);
	i_free(ctx);
}

int dbox_sync_index_rebuild(struct dbox_mailbox *mbox)
{
	struct dbox_sync_rebuild_context *ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	int ret;

	view = mail_index_view_open(mbox->ibox.index);
	trans = mail_index_transaction_begin(view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);

	ctx = dbox_sync_index_rebuild_init(mbox, view, trans, FALSE);
	ret = dbox_sync_index_rebuild_singles(ctx);
	dbox_sync_index_rebuild_deinit(&ctx);

	if (ret < 0)
		mail_index_transaction_rollback(&trans);
	else
		ret = mail_index_transaction_commit(&trans);
	mail_index_view_close(&view);

	if (ret == 0)
		mbox->storage->sync_rebuild = FALSE;
	return ret;
}
