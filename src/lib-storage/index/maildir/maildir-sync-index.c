/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "maildir-storage.h"
#include "index-sync-changes.h"
#include "maildir-uidlist.h"
#include "maildir-keywords.h"
#include "maildir-filename.h"
#include "maildir-sync.h"

#include <stdio.h>
#include <unistd.h>

struct maildir_index_sync_context {
        struct maildir_mailbox *mbox;
	struct maildir_sync_context *maildir_sync_ctx;

	struct mail_index_view *view;
	struct mail_index_sync_ctx *sync_ctx;
        struct maildir_keywords_sync_ctx *keywords_sync_ctx;
	struct mail_index_transaction *trans;

	struct maildir_uidlist_sync_ctx *uidlist_sync_ctx;
	struct index_sync_changes_context *sync_changes;
	enum mail_flags flags;
	ARRAY_TYPE(keyword_indexes) keywords;

	uint32_t seq, uid;

	bool changed;
};

struct maildir_keywords_sync_ctx *
maildir_sync_get_keywords_sync_ctx(struct maildir_index_sync_context *ctx)
{
	return ctx->keywords_sync_ctx;
}

static int maildir_expunge(struct maildir_mailbox *mbox, const char *path,
			   struct maildir_index_sync_context *ctx)
{
	struct mailbox *box = &mbox->ibox.box;

	if (unlink(path) == 0) {
		if (box->v.sync_notify != NULL) {
			box->v.sync_notify(box, ctx->uid,
					   MAILBOX_SYNC_TYPE_EXPUNGE);
		}
		mail_index_expunge(ctx->trans, ctx->seq);
		ctx->changed = TRUE;
		return 1;
	}
	if (errno == ENOENT)
		return 0;

	mail_storage_set_critical(&mbox->storage->storage,
				  "unlink(%s) failed: %m", path);
	return -1;
}

static int maildir_sync_flags(struct maildir_mailbox *mbox, const char *path,
			      struct maildir_index_sync_context *ctx)
{
	struct mailbox *box = &mbox->ibox.box;
	const char *dir, *fname, *newfname, *newpath;
	enum mailbox_sync_type sync_type;
	uint8_t flags8;

	fname = strrchr(path, '/');
	i_assert(fname != NULL);
	fname++;
	dir = t_strdup_until(path, fname);

	/* get the current flags and keywords */
	maildir_filename_get_flags(ctx->keywords_sync_ctx,
				   fname, &ctx->flags, &ctx->keywords);

	/* apply changes */
	flags8 = ctx->flags;
	index_sync_changes_apply(ctx->sync_changes, NULL,
				 &flags8, &ctx->keywords, &sync_type);
	ctx->flags = flags8;

	/* and try renaming with the new name */
	newfname = maildir_filename_set_flags(ctx->keywords_sync_ctx, fname,
					      ctx->flags, &ctx->keywords);
	newpath = t_strconcat(dir, newfname, NULL);
	if (rename(path, newpath) == 0) {
		if (box->v.sync_notify != NULL)
			box->v.sync_notify(box, ctx->uid, sync_type);
		ctx->changed = TRUE;
		return 1;
	}
	if (errno == ENOENT)
		return 0;

	if (!ENOSPACE(errno) && errno != EACCES) {
		mail_storage_set_critical(box->storage,
			"rename(%s, %s) failed: %m", path, newpath);
	}
	return -1;
}

static void maildir_handle_uid_insertion(struct maildir_index_sync_context *ctx,
					 enum maildir_uidlist_rec_flag uflags,
					 const char *filename, uint32_t uid)
{
	int ret;

	if ((uflags & MAILDIR_UIDLIST_REC_FLAG_NONSYNCED) != 0) {
		/* partial syncing */
		return;
	}

	/* most likely a race condition: we read the maildir, then someone else
	   expunged messages and committed changes to index. so, this message
	   shouldn't actually exist. */
	if ((uflags & MAILDIR_UIDLIST_REC_FLAG_RACING) == 0) {
		/* mark it racy and check in next sync */
		ctx->mbox->maildir_hdr.cur_check_time = 0;
		maildir_uidlist_add_flags(ctx->mbox->uidlist, filename,
					  MAILDIR_UIDLIST_REC_FLAG_RACING);
		return;
	}

	if (ctx->uidlist_sync_ctx == NULL) {
		ret = maildir_uidlist_sync_init(ctx->mbox->uidlist,
						MAILDIR_UIDLIST_SYNC_PARTIAL |
						MAILDIR_UIDLIST_SYNC_KEEP_STATE,
						&ctx->uidlist_sync_ctx);
		i_assert(ret > 0);
	}

	uflags &= MAILDIR_UIDLIST_REC_FLAG_NEW_DIR;
	maildir_uidlist_sync_remove(ctx->uidlist_sync_ctx, filename);
	ret = maildir_uidlist_sync_next(ctx->uidlist_sync_ctx,
					filename, uflags);
	i_assert(ret > 0);

	/* give the new UID to it immediately */
	maildir_uidlist_sync_finish(ctx->uidlist_sync_ctx);

	i_warning("Maildir %s: Expunged message reappeared, giving a new UID "
		  "(old uid=%u, file=%s)", ctx->mbox->path, uid, filename);
}

int maildir_sync_index_begin(struct maildir_mailbox *mbox,
			     struct maildir_sync_context *maildir_sync_ctx,
			     struct maildir_index_sync_context **ctx_r)
{
	struct maildir_index_sync_context *ctx;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	enum mail_index_sync_flags sync_flags;

	sync_flags = 0;
	/* don't drop recent messages if we're saving messages */
	if (!mbox->ibox.keep_recent && maildir_sync_ctx != NULL)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_DROP_RECENT;

	if (mail_index_sync_begin(mbox->ibox.index, &sync_ctx, &view, &trans,
				  (uint32_t)-1, (uoff_t)-1, sync_flags) <= 0) {
		mail_storage_set_index_error(&mbox->ibox);
		return -1;
	}

	ctx = i_new(struct maildir_index_sync_context, 1);
	ctx->mbox = mbox;
	ctx->maildir_sync_ctx = maildir_sync_ctx;
	ctx->sync_ctx = sync_ctx;
	ctx->view = view;
	ctx->trans = trans;
	ctx->keywords_sync_ctx =
		maildir_keywords_sync_init(mbox->keywords, mbox->ibox.index);

	ctx->sync_changes = index_sync_changes_init(&mbox->ibox, ctx->sync_ctx,
						    ctx->view, ctx->trans,
						    mbox->ibox.readonly);

	*ctx_r = ctx;
	return 0;
}

int maildir_sync_index_finish(struct maildir_index_sync_context **_ctx,
			      bool failed, bool cancel)
{
	struct maildir_index_sync_context *ctx = *_ctx;
	struct maildir_mailbox *mbox = ctx->mbox;
	int ret = failed ? -1 : 0;

	*_ctx = NULL;

	if (ret < 0 || cancel)
		mail_index_sync_rollback(&ctx->sync_ctx);
	else {
		/* Set syncing_commit=TRUE so that if any sync callbacks try
		   to access mails which got lost (eg. expunge callback trying
		   to open the file which was just unlinked) we don't try to
		   start a second index sync and crash. */
		mbox->syncing_commit = TRUE;
		if (mail_index_sync_commit(&ctx->sync_ctx) < 0) {
			mail_storage_set_index_error(&mbox->ibox);
			ret = -1;
		} else {
			mbox->ibox.commit_log_file_seq = 0;
			mbox->ibox.commit_log_file_offset = 0;
		}
		mbox->syncing_commit = FALSE;
	}

	maildir_keywords_sync_deinit(ctx->keywords_sync_ctx);
        ctx->keywords_sync_ctx = NULL;

	index_sync_changes_deinit(&ctx->sync_changes);
	i_free(ctx);
	return ret;
}

static bool
maildir_index_header_has_changed(const struct maildir_index_header *old_hdr,
				 const struct maildir_index_header *new_hdr)
{
#define DIR_DELAYED_REFRESH(hdr, name) \
	((hdr)->name ## _check_time <= \
		(hdr)->name ## _mtime + MAILDIR_SYNC_SECS)

	if (old_hdr->new_mtime != new_hdr->new_mtime ||
	    old_hdr->cur_mtime != new_hdr->cur_mtime ||
	    old_hdr->new_mtime_nsecs != new_hdr->new_mtime_nsecs ||
	    old_hdr->cur_mtime_nsecs != new_hdr->cur_mtime_nsecs)
		return TRUE;

	return DIR_DELAYED_REFRESH(old_hdr, new) !=
		DIR_DELAYED_REFRESH(new_hdr, new) ||
		DIR_DELAYED_REFRESH(old_hdr, cur) !=
		DIR_DELAYED_REFRESH(new_hdr, cur);
}

static void
maildir_index_update_ext_header(struct maildir_mailbox *mbox,
				struct mail_index_transaction *trans)
{
	const void *data;
	size_t data_size;

	if (mail_index_get_header_ext(mbox->ibox.view, mbox->maildir_ext_id,
				      &data, &data_size) < 0)
		data_size = 0;

	if (data_size == sizeof(mbox->maildir_hdr) &&
	    !maildir_index_header_has_changed(data, &mbox->maildir_hdr)) {
		/* nothing changed */
	} else {
		mail_index_update_header_ext(trans, mbox->maildir_ext_id, 0,
					     &mbox->maildir_hdr,
					     sizeof(mbox->maildir_hdr));
	}
}

int maildir_sync_index(struct maildir_index_sync_context *ctx,
		       bool partial)
{
	struct maildir_mailbox *mbox = ctx->mbox;
	struct mail_index_view *view = ctx->view;
	struct maildir_uidlist_iter_ctx *iter;
	struct mail_index_transaction *trans = ctx->trans;
	const struct mail_index_header *hdr;
	struct mail_index_header empty_hdr;
	const struct mail_index_record *rec;
	uint32_t seq, uid, prev_uid;
        enum maildir_uidlist_rec_flag uflags;
	const char *filename;
	ARRAY_TYPE(keyword_indexes) idx_keywords;
	uint32_t uid_validity, next_uid, hdr_next_uid, last_nonrecent_uid;
	unsigned int changes = 0;
	int ret = 0;
	bool recent, expunged, full_rescan = FALSE;

	i_assert(!mbox->syncing_commit);
	i_assert(maildir_uidlist_is_locked(mbox->uidlist));

	hdr = mail_index_get_header(view);
	uid_validity = maildir_uidlist_get_uid_validity(mbox->uidlist);
	if (uid_validity != hdr->uid_validity &&
	    uid_validity != 0 && hdr->uid_validity != 0) {
		/* uidvalidity changed and index isn't being synced for the
		   first time, reset the index so we can add all messages as
		   new */
		i_warning("Maildir %s: UIDVALIDITY changed (%u -> %u)",
			  mbox->path, hdr->uid_validity, uid_validity);
		mail_index_reset(trans);
		maildir_uidlist_set_next_uid(mbox->uidlist, 1, TRUE);

		memset(&empty_hdr, 0, sizeof(empty_hdr));
		empty_hdr.next_uid = 1;
		hdr = &empty_hdr;
	}
	hdr_next_uid = hdr->next_uid;

	mbox->syncing_commit = TRUE;
	seq = prev_uid = last_nonrecent_uid = 0;
	t_array_init(&ctx->keywords, MAILDIR_MAX_KEYWORDS);
	t_array_init(&idx_keywords, MAILDIR_MAX_KEYWORDS);
	iter = maildir_uidlist_iter_init(mbox->uidlist);
	while (maildir_uidlist_iter_next(iter, &uid, &uflags, &filename)) {
		maildir_filename_get_flags(ctx->keywords_sync_ctx, filename,
					   &ctx->flags, &ctx->keywords);

		i_assert(uid > prev_uid);
		prev_uid = uid;

		/* the private flags are kept only in indexes. don't use them
		   at all even for newly seen mails */
		ctx->flags &= ~mbox->ibox.box.private_flags_mask;

	__again:
		ctx->seq = ++seq;
		ctx->uid = uid;

		if ((uflags & MAILDIR_UIDLIST_REC_FLAG_RECENT) == 0 &&
		    (uflags & MAILDIR_UIDLIST_REC_FLAG_NONSYNCED) == 0)
			last_nonrecent_uid = uid;
		recent = (uflags & MAILDIR_UIDLIST_REC_FLAG_RECENT) != 0 &&
			uid >= hdr->first_recent_uid;

		if (seq > hdr->messages_count) {
			if (uid < hdr_next_uid) {
				maildir_handle_uid_insertion(ctx, uflags,
							     filename, uid);
				seq--;
				continue;
			}

			hdr_next_uid = uid + 1;
			mail_index_append(trans, uid, &seq);
			mail_index_update_flags(trans, seq, MODIFY_REPLACE,
						ctx->flags);
			if (array_count(&ctx->keywords) > 0) {
				struct mail_keywords *kw;

				kw = mail_index_keywords_create_from_indexes(
					trans, &ctx->keywords);
				mail_index_update_keywords(trans, seq,
							   MODIFY_REPLACE, kw);
				mail_index_keywords_free(&kw);
			}
			if (recent)
				index_mailbox_set_recent_uid(&mbox->ibox, uid);
			continue;
		}

		if (mail_index_lookup(view, seq, &rec) < 0) {
			mail_storage_set_index_error(&mbox->ibox);
			ret = -1;
			break;
		}

		if (uid > rec->uid) {
			/* expunged */
			mail_index_expunge(trans, seq);
			goto __again;
		}

		if (uid < rec->uid) {
			maildir_handle_uid_insertion(ctx, uflags,
						     filename, uid);
			seq--;
			continue;
		}

		if (index_sync_changes_read(ctx->sync_changes, rec->uid,
					    &expunged) < 0) {
			ret = -1;
			break;
		}

		if (expunged) {
			if (maildir_file_do(mbox, ctx->uid,
					    maildir_expunge, ctx) >= 0) {
				/* successful expunge */
				mail_index_expunge(trans, seq);
			}
			if ((++changes % MAILDIR_SLOW_MOVE_COUNT) == 0)
				maildir_sync_notify(ctx->maildir_sync_ctx);
			continue;
		}

		if (recent)
			index_mailbox_set_recent_uid(&mbox->ibox, uid);

		/* the private flags are stored only in indexes, keep them */
		ctx->flags |= rec->flags & mbox->ibox.box.private_flags_mask;

		if ((uflags & MAILDIR_UIDLIST_REC_FLAG_NONSYNCED) != 0) {
			/* partial syncing */
			if ((uflags & MAILDIR_UIDLIST_REC_FLAG_NEW_DIR) != 0) {
				/* we last saw this mail in new/, but it's
				   not there anymore. possibly expunged,
				   make sure. */
				full_rescan = TRUE;
			}
			continue;
		}

		if (index_sync_changes_have(ctx->sync_changes)) {
			/* apply flag changes to maildir */
			if (maildir_file_do(mbox, ctx->uid,
					    maildir_sync_flags, ctx) < 0)
				ctx->flags |= MAIL_INDEX_MAIL_FLAG_DIRTY;
			if ((++changes % MAILDIR_SLOW_MOVE_COUNT) == 0)
				maildir_sync_notify(ctx->maildir_sync_ctx);
		}

		if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0) {
			/* we haven't been able to update maildir with this
			   record's flag changes. don't sync them. */
			continue;
		}

		if (ctx->flags != (rec->flags & MAIL_FLAGS_NONRECENT)) {
			mail_index_update_flags(trans, seq, MODIFY_REPLACE,
						ctx->flags);
		}

		/* update keywords if they have changed */
		if (mail_index_lookup_keywords(view, seq, &idx_keywords) < 0) {
			mail_storage_set_index_error(&mbox->ibox);
			ret = -1;
			break;
		}
		if (!index_keyword_array_cmp(&ctx->keywords, &idx_keywords)) {
			struct mail_keywords *kw;

			kw = mail_index_keywords_create_from_indexes(
				trans, &ctx->keywords);
			mail_index_update_keywords(trans, seq,
						   MODIFY_REPLACE, kw);
			mail_index_keywords_free(&kw);
		}
	}
	maildir_uidlist_iter_deinit(iter);
	mbox->syncing_commit = FALSE;

	if (ctx->uidlist_sync_ctx != NULL) {
		if (maildir_uidlist_sync_deinit(&ctx->uidlist_sync_ctx) < 0)
			ret = -1;
	}

	if (mbox->ibox.box.v.sync_notify != NULL)
		mbox->ibox.box.v.sync_notify(&mbox->ibox.box, 0, 0);

	if (!partial) {
		/* expunge the rest */
		for (seq++; seq <= hdr->messages_count; seq++)
			mail_index_expunge(trans, seq);
	}

	if (ctx->changed)
		mbox->maildir_hdr.cur_mtime = time(NULL);
	maildir_index_update_ext_header(mbox, trans);

	if (uid_validity == 0) {
		uid_validity = hdr->uid_validity != 0 ?
			hdr->uid_validity : (uint32_t)ioloop_time;
		maildir_uidlist_set_uid_validity(mbox->uidlist, uid_validity);
	}
	maildir_uidlist_set_next_uid(mbox->uidlist, hdr_next_uid, FALSE);

	if (uid_validity != hdr->uid_validity) {
		mail_index_update_header(trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}

	next_uid = maildir_uidlist_get_next_uid(mbox->uidlist);
	if (hdr_next_uid < next_uid) {
		mail_index_update_header(trans,
			offsetof(struct mail_index_header, next_uid),
			&next_uid, sizeof(next_uid), FALSE);
	}

	if (ctx->mbox->ibox.keep_recent &&
	    hdr->first_recent_uid < last_nonrecent_uid + 1) {
		uint32_t first_recent_uid = last_nonrecent_uid + 1;

		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, first_recent_uid),
			&first_recent_uid, sizeof(first_recent_uid), FALSE);
	}
	return ret < 0 ? -1 : (full_rescan ? 0 : 1);
}

static unsigned int maildir_list_get_ext_id(struct maildir_storage *storage,
					    struct mail_index_view *view)
{
	if (storage->maildir_list_ext_id == (uint32_t)-1) {
		storage->maildir_list_ext_id =
			mail_index_ext_register(mail_index_view_get_index(view),
				"maildir", 0,
				sizeof(struct maildir_list_index_record),
				sizeof(uint32_t));
	}
	return storage->maildir_list_ext_id;
}

int maildir_list_index_has_changed(struct mailbox *box,
				   struct mail_index_view *list_view,
				   uint32_t seq)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;
	const struct maildir_list_index_record *rec;
	const void *data;
	const char *root_dir, *new_dir, *cur_dir;
	struct stat st;
	uint32_t ext_id;

	ext_id = maildir_list_get_ext_id(mbox->storage, list_view);
	if (mail_index_lookup_ext(list_view, seq, ext_id, &data) <= 0)
		return -1;
	rec = data;

	if (rec == NULL || rec->new_mtime == 0 || rec->cur_mtime == 0) {
		/* doesn't exist, not synced or dirty-synced */
		return 1;
	}

	root_dir = mailbox_list_get_path(mail_storage_get_list(box->storage),
					 box->name,
					 MAILBOX_LIST_PATH_TYPE_MAILBOX);

	/* check if new/ changed */
	new_dir = t_strconcat(root_dir, "/new", NULL);
	if (stat(new_dir, &st) < 0) {
		mail_storage_set_critical(box->storage,
					  "stat(%s) failed: %m", new_dir);
		return -1;
	}
	if (rec->new_mtime != st.st_mtime)
		return 1;

	/* check if cur/ changed */
	cur_dir = t_strconcat(root_dir, "/cur", NULL);
	if (stat(cur_dir, &st) < 0) {
		mail_storage_set_critical(box->storage,
					  "stat(%s) failed: %m", cur_dir);
		return -1;
	}
	if (rec->cur_mtime != st.st_mtime)
		return 1;
	return 0;
}

int maildir_list_index_update_sync(struct mailbox *box,
				   struct mail_index_transaction *trans,
				   uint32_t seq)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;
	struct mail_index_view *list_view;
	const struct maildir_index_header *mhdr = &mbox->maildir_hdr;
	const struct maildir_list_index_record *old_rec;
	struct maildir_list_index_record new_rec;
	const void *data;
	uint32_t ext_id;

	/* get the current record */
	list_view = mail_index_transaction_get_view(trans);
	ext_id = maildir_list_get_ext_id(mbox->storage, list_view);
	if (mail_index_lookup_ext(list_view, seq, ext_id, &data) <= 0)
		return -1;
	old_rec = data;

	memset(&new_rec, 0, sizeof(new_rec));
	if (mhdr->new_check_time <= mhdr->new_mtime + MAILDIR_SYNC_SECS ||
	    mhdr->cur_check_time <= mhdr->cur_mtime + MAILDIR_SYNC_SECS) {
		/* dirty, we need a refresh next time */
	} else {
		new_rec.new_mtime = mhdr->new_mtime;
		new_rec.cur_mtime = mhdr->cur_mtime;
	}

	if (old_rec == NULL ||
	    memcmp(old_rec, &new_rec, sizeof(old_rec)) != 0) {
		mail_index_update_ext(trans, seq,
				      mbox->storage->maildir_list_ext_id,
				      &new_rec, NULL);
	}
	return 0;
}
