/* Copyright (c) 2007-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "dbox-storage.h"
#include "../maildir/maildir-uidlist.h"
#include "../maildir/maildir-keywords.h"
#include "dbox-index.h"
#include "dbox-file.h"
#include "dbox-sync.h"

#include <stdlib.h>
#include <dirent.h>

struct dbox_sync_rebuild_context {
	struct dbox_mailbox *mbox;
	struct dbox_index_append_context *append_ctx;

	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	uint32_t cache_ext_id;
	uint32_t cache_reset_id;

	struct maildir_uidlist *maildir_uidlist;
	struct maildir_keywords *mk;

	ARRAY_DEFINE(maildir_new_files, char *);
	uint32_t maildir_new_uid;

	unsigned int cache_used:1;
};

static int dbox_sync_set_uidvalidity(struct dbox_sync_rebuild_context *ctx)
{
	uint32_t uid_validity;

	if (dbox_index_get_uid_validity(ctx->mbox->dbox_index,
					&uid_validity) < 0)
		return -1;

	mail_index_update_header(ctx->trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
	return 0;
}

static void
dbox_sync_index_copy_cache(struct dbox_sync_rebuild_context *ctx,
			   uint32_t old_seq, uint32_t new_seq)
{
	struct mail_index_map *map;
	const void *data;
	uint32_t reset_id;
	bool expunged;

	if (ctx->cache_ext_id == (uint32_t)-1)
		return;

	mail_index_lookup_ext_full(ctx->view, old_seq, ctx->cache_ext_id,
				   &map, &data, &expunged);
	if (expunged)
		return;

	if (!mail_index_ext_get_reset_id(ctx->view, map, ctx->cache_ext_id,
					 &reset_id))
		return;

	if (!ctx->cache_used) {
		/* set reset id */
		ctx->cache_used = TRUE;
		ctx->cache_reset_id = reset_id;
		mail_index_ext_reset(ctx->trans, ctx->cache_ext_id,
				     ctx->cache_reset_id);
	}
	if (ctx->cache_reset_id == reset_id) {
		mail_index_update_ext(ctx->trans, new_seq,
				      ctx->cache_ext_id, data, NULL);
	}
}

static void
dbox_sync_index_copy_from_old(struct dbox_sync_rebuild_context *ctx,
			      uint32_t old_seq, uint32_t new_seq)
{
	struct mail_index *index = mail_index_view_get_index(ctx->view);
	const struct mail_index_record *rec;
	ARRAY_TYPE(keyword_indexes) old_keywords;
	struct mail_keywords *kw;

	/* copy flags */
	rec = mail_index_lookup(ctx->view, old_seq);
	mail_index_update_flags(ctx->trans, new_seq,
				MODIFY_REPLACE, rec->flags);

	/* copy keywords */
	t_array_init(&old_keywords, 32);
	mail_index_lookup_keywords(ctx->view, old_seq, &old_keywords);
	kw = mail_index_keywords_create_from_indexes(index, &old_keywords);
	mail_index_update_keywords(ctx->trans, new_seq, MODIFY_REPLACE, kw);
	mail_index_keywords_free(&kw);

	dbox_sync_index_copy_cache(ctx, old_seq, new_seq);
}

static void
dbox_sync_index_metadata(struct dbox_sync_rebuild_context *ctx,
			 struct dbox_file *file, uint32_t seq, uint32_t uid)
{
	const char *value;
	struct mail_keywords *keywords;
	enum mail_flags flags = 0;
	uint32_t old_seq;
	unsigned int i;

	if (mail_index_lookup_seq(ctx->view, uid, &old_seq)) {
		/* the message exists in the old index.
		   copy the metadata from it. */
		dbox_sync_index_copy_from_old(ctx, old_seq, seq);
		return;
	}

	value = dbox_file_metadata_get(file, DBOX_METADATA_FLAGS);
	if (value != NULL) {
		for (i = 0; value[i] != '\0'; i++) {
			if (value[i] != '0' && i < DBOX_METADATA_FLAGS_COUNT)
				flags |= dbox_mail_flags_map[i];
		}
		mail_index_update_flags(ctx->trans, seq, MODIFY_REPLACE, flags);
	}

	value = dbox_file_metadata_get(file, DBOX_METADATA_KEYWORDS);
	if (value != NULL) T_BEGIN {
		keywords = mail_index_keywords_create(ctx->mbox->ibox.index,
						t_strsplit_spaces(value, " "));
		mail_index_update_keywords(ctx->trans, seq, MODIFY_REPLACE,
					   keywords);
		mail_index_keywords_free(&keywords);
	} T_END;
}

static int dbox_sync_index_file_next(struct dbox_sync_rebuild_context *ctx,
				     struct dbox_file *file, uoff_t *offset)
{
	uint32_t seq, uid;
	uoff_t physical_size;
	const char *path;
	bool expunged;
	int ret;

	path = dbox_file_get_path(file);
	ret = dbox_file_seek_next(file, offset, &uid, &physical_size);
	if (ret <= 0) {
		if (ret < 0)
			return -1;

		if (uid == 0 && (file->file_id & DBOX_FILE_ID_FLAG_UID) != 0) {
			/* EOF */
			return 0;
		}

		i_warning("%s: Ignoring broken file (header)", path);
		return 0;
	}
	if ((file->file_id & DBOX_FILE_ID_FLAG_UID) != 0 &&
	    uid != (file->file_id & ~DBOX_FILE_ID_FLAG_UID)) {
		i_warning("%s: Header contains wrong UID %u", path, uid);
		return 0;
	}
	if (file->maildir_file) {
		i_assert(uid == 0);
		if (!maildir_uidlist_get_uid(ctx->maildir_uidlist, file->fname,
					     &uid)) {
			if (ctx->maildir_new_uid == 0) {
				/* not in uidlist, give it an uid later */
				char *fname = i_strdup(file->fname);
				array_append(&ctx->maildir_new_files,
					     &fname, 1);
				return 0;
			}
			uid = ctx->maildir_new_uid++;
		}
		file->append_count = 1;
		file->last_append_uid = uid;
	}

	ret = dbox_file_metadata_seek_mail_offset(file, *offset, &expunged);
	if (ret <= 0) {
		if (ret < 0)
			return -1;
		i_warning("%s: Ignoring broken file (metadata)", path);
		return 0;
	}
	if (!expunged) {
		mail_index_append(ctx->trans, uid, &seq);
		file->maildir_append_seq = seq;
		dbox_sync_index_metadata(ctx, file, seq, uid);
	}
	return 1;
}

static int
dbox_sync_index_uid_file(struct dbox_sync_rebuild_context *ctx,
			 const char *dir, const char *fname)
{
	struct dbox_file *file;
	unsigned long uid;
	char *p;
	uoff_t offset = 0;
	int ret;

	fname += sizeof(DBOX_MAIL_FILE_MULTI_PREFIX)-1;
	uid = strtoul(fname, &p, 10);
	if (*p != '\0' || uid == 0 || uid >= (uint32_t)-1) {
		i_warning("dbox %s: Ignoring invalid filename %s",
			  ctx->mbox->path, fname);
		return 0;
	}

	file = dbox_file_init(ctx->mbox, uid | DBOX_FILE_ID_FLAG_UID);
	file->current_path = i_strdup_printf("%s/%s", dir, fname);

	ret = dbox_sync_index_file_next(ctx, file, &offset) < 0 ? -1 : 0;
	dbox_file_unref(&file);
	return ret;
}

static int
dbox_sync_index_multi_file(struct dbox_sync_rebuild_context *ctx,
			   const char *dir, const char *fname)
{
	/* FIXME */
	return 0;
}

static int
dbox_sync_index_maildir_file(struct dbox_sync_rebuild_context *ctx,
			     const char *fname)
{
	struct dbox_file *file;
	uoff_t offset = 0;
	int ret;

	if (ctx->mbox->maildir_sync_keywords == NULL) {
		ctx->maildir_uidlist =
			maildir_uidlist_init_readonly(&ctx->mbox->ibox);
		ctx->mk = maildir_keywords_init_readonly(&ctx->mbox->ibox.box);
		ctx->mbox->maildir_sync_keywords =
			maildir_keywords_sync_init(ctx->mk,
						   ctx->mbox->ibox.index);

		if (maildir_uidlist_refresh(ctx->maildir_uidlist) < 0)
			return -1;
	}

	file = dbox_file_init_new_maildir(ctx->mbox, fname);
	if ((ret = dbox_sync_index_file_next(ctx, file, &offset)) > 0)
		dbox_index_append_file(ctx->append_ctx, file);
	dbox_file_unref(&file);
	return ret < 0 ? -1 : 0;
}

static int
dbox_sync_index_file(struct dbox_sync_rebuild_context *ctx,
		     const char *path, const char *fname, bool primary)
{
	if (strncmp(fname, DBOX_MAIL_FILE_UID_PREFIX,
		    sizeof(DBOX_MAIL_FILE_UID_PREFIX)-1) == 0)
		return dbox_sync_index_uid_file(ctx, path, fname);

	if (strncmp(fname, DBOX_MAIL_FILE_MULTI_PREFIX,
		    sizeof(DBOX_MAIL_FILE_MULTI_PREFIX)-1) == 0)
		return dbox_sync_index_multi_file(ctx, path, fname);

	if (primary && strstr(fname, ":2,") != NULL)
		return dbox_sync_index_maildir_file(ctx, fname);
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
	for (;;) {
		errno = 0;
		if ((d = readdir(dir)) == NULL)
			break;

		T_BEGIN {
			ret = dbox_sync_index_file(ctx, path, d->d_name,
						   primary);
		} T_END;
	}
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

static int dbox_sync_new_maildir(struct dbox_sync_rebuild_context *ctx)
{
	struct mail_index_view *trans_view;
	const struct mail_index_header *hdr;
	char *const *fnames;
	unsigned int i, count;
	uint32_t next_uid, seq;
	int ret = 0;

	fnames = array_get(&ctx->maildir_new_files, &count);
	if (count == 0)
		return 0;

	/* try to give them UIDs beginning from uidlist's next_uid */
	next_uid = maildir_uidlist_get_next_uid(ctx->maildir_uidlist);
	trans_view = mail_index_transaction_open_updated_view(ctx->trans);
	for (i = 0; i < count; i++) {
		if (mail_index_lookup_seq(trans_view, next_uid, &seq))
			break;
	}

	if (i == count)
		ctx->maildir_new_uid = next_uid;
	else {
		hdr = mail_index_get_header(trans_view);
		ctx->maildir_new_uid = hdr->next_uid;
	}
	mail_index_view_close(&trans_view);

	for (i = 0; i < count && ret == 0; i++) {
		T_BEGIN {
			ret = dbox_sync_index_maildir_file(ctx, fnames[i]);
		} T_END;
	}
	return ret;
}

static int dbox_sync_index_rebuild_ctx(struct dbox_sync_rebuild_context *ctx)
{
	if (dbox_sync_set_uidvalidity(ctx) < 0)
		return -1;

	if (dbox_sync_index_rebuild_dir(ctx, ctx->mbox->path, TRUE) < 0)
		return -1;

	if (ctx->mbox->alt_path != NULL) {
		if (dbox_sync_index_rebuild_dir(ctx, ctx->mbox->alt_path,
						FALSE) < 0)
			return -1;
	}

	/* finally give UIDs to newly seen maildir files */
	return dbox_sync_new_maildir(ctx);
}

static void dbox_sync_update_maildir_ids(struct dbox_sync_rebuild_context *ctx)
{
	struct dbox_mail_index_record rec;
	struct dbox_file *const *files;
	unsigned int i, count;

	memset(&rec, 0, sizeof(rec));
	files = array_get(&ctx->mbox->open_files, &count);
	for (i = 0; i < count; i++) {
		if (!files[i]->maildir_file)
			continue;

		i_assert(files[i]->file_id != 0);
		rec.file_id = files[i]->file_id;
		mail_index_update_ext(ctx->trans, files[i]->maildir_append_seq,
				      ctx->mbox->dbox_ext_id, &rec, NULL);
	}
}

int dbox_sync_index_rebuild(struct dbox_mailbox *mbox)
{
	struct dbox_sync_rebuild_context ctx;
	uint32_t seq;
	uoff_t offset;
	char **fnames;
	unsigned int i, count;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.mbox = mbox;
	ctx.append_ctx = dbox_index_append_begin(mbox->dbox_index);
	ctx.view = mail_index_view_open(mbox->ibox.index);
	ctx.trans = mail_index_transaction_begin(ctx.view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	i_array_init(&ctx.maildir_new_files, 8);
	mail_index_reset(ctx.trans);
	index_mailbox_reset_uidvalidity(&mbox->ibox);
	mail_index_ext_lookup(mbox->ibox.index, "cache", &ctx.cache_ext_id);

	if ((ret = dbox_sync_index_rebuild_ctx(&ctx)) < 0)
		mail_index_transaction_rollback(&ctx.trans);
	else {
		ret = dbox_index_append_assign_file_ids(ctx.append_ctx);
		if (ret == 0) {
			dbox_sync_update_maildir_ids(&ctx);
			ret = mail_index_transaction_commit(&ctx.trans,
							    &seq, &offset);
		}
	}
	mail_index_view_close(&ctx.view);

	fnames = array_get_modifiable(&ctx.maildir_new_files, &count);
	for (i = 0; i < count; i++)
		i_free(fnames[i]);
	array_free(&ctx.maildir_new_files);

	if (ret == 0)
		ret = dbox_index_append_commit(&ctx.append_ctx);
	else
		dbox_index_append_rollback(&ctx.append_ctx);

	if (mbox->maildir_sync_keywords != NULL)
		maildir_keywords_sync_deinit(&mbox->maildir_sync_keywords);
	if (ctx.mk != NULL)
		maildir_keywords_deinit(&ctx.mk);
	if (ctx.maildir_uidlist != NULL)
		maildir_uidlist_deinit(&ctx.maildir_uidlist);
	return ret;
}
