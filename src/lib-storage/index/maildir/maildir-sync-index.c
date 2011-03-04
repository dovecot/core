/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hex-binary.h"
#include "maildir-storage.h"
#include "index-sync-changes.h"
#include "maildir-uidlist.h"
#include "maildir-keywords.h"
#include "maildir-filename.h"
#include "maildir-sync.h"

#include <stdio.h>
#include <stdlib.h>
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
	ARRAY_TYPE(keyword_indexes) keywords, idx_keywords;

	uint32_t uid;
	bool update_maildir_hdr_cur;

	time_t start_time;
	unsigned int flag_change_count, expunge_count, new_msgs_count;
};

struct maildir_keywords_sync_ctx *
maildir_sync_get_keywords_sync_ctx(struct maildir_index_sync_context *ctx)
{
	return ctx->keywords_sync_ctx;
}

void maildir_sync_set_new_msgs_count(struct maildir_index_sync_context *ctx,
				     unsigned int count)
{
	ctx->new_msgs_count = count;
}

static bool
maildir_expunge_is_valid_guid(struct maildir_index_sync_context *ctx,
			      uint32_t uid, const char *filename,
			      uint8_t expunged_guid_128[MAIL_GUID_128_SIZE])
{
	uint8_t guid_128[MAIL_GUID_128_SIZE];
	const char *guid;

	if (mail_guid_128_is_empty(expunged_guid_128)) {
		/* no GUID associated with expunge */
		return TRUE;
	}

	T_BEGIN {
		guid = maildir_uidlist_lookup_ext(ctx->mbox->uidlist, uid,
						  MAILDIR_UIDLIST_REC_EXT_GUID);
		if (guid == NULL)
			guid = t_strcut(filename, ':');
		mail_generate_guid_128_hash(guid, guid_128);
	} T_END;

	if (memcmp(guid_128, expunged_guid_128, sizeof(guid_128)) == 0)
		return TRUE;

	mail_storage_set_critical(&ctx->mbox->storage->storage,
		"Mailbox %s: Expunged GUID mismatch for UID %u: %s vs %s",
		ctx->mbox->box.vname, ctx->uid,
		binary_to_hex(guid_128, sizeof(guid_128)),
		binary_to_hex(expunged_guid_128, MAIL_GUID_128_SIZE));
	return FALSE;
}

static int maildir_expunge(struct maildir_mailbox *mbox, const char *path,
			   struct maildir_index_sync_context *ctx)
{
	struct mailbox *box = &mbox->box;

	ctx->expunge_count++;

	if (unlink(path) == 0) {
		if (box->v.sync_notify != NULL) {
			box->v.sync_notify(box, ctx->uid,
					   MAILBOX_SYNC_TYPE_EXPUNGE);
		}
		return 1;
	}
	if (errno == ENOENT)
		return 0;
	if (errno == EISDIR)
		return maildir_lose_unexpected_dir(box->storage, path);

	mail_storage_set_critical(&mbox->storage->storage,
				  "unlink(%s) failed: %m", path);
	return -1;
}

static int maildir_sync_flags(struct maildir_mailbox *mbox, const char *path,
			      struct maildir_index_sync_context *ctx)
{
	struct mailbox *box = &mbox->box;
	struct stat st;
	const char *dir, *fname, *newfname, *newpath;
	enum mail_index_sync_type sync_type;
	uint8_t flags8;

	ctx->flag_change_count++;

	fname = strrchr(path, '/');
	i_assert(fname != NULL);
	fname++;
	dir = t_strdup_until(path, fname);

	i_assert(*fname != '\0');

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
	if (strcmp(path, newpath) == 0) {
		/* just make sure that the file still exists. avoid rename()
		   here because it's slow on HFS. */
		if (stat(path, &st) < 0) {
			if (errno == ENOENT)
				return 0;
			mail_storage_set_critical(box->storage,
				"stat(%s) failed: %m", path);
			return -1;
		}
	} else {
		if (rename(path, newpath) < 0) {
			if (errno == ENOENT)
				return 0;
			if (!ENOSPACE(errno) && errno != EACCES) {
				mail_storage_set_critical(box->storage,
					"rename(%s, %s) failed: %m",
					path, newpath);
			}
			return -1;
		}
	}
	if (box->v.sync_notify != NULL) {
		box->v.sync_notify(box, ctx->uid,
				   index_sync_type_convert(sync_type));
	}
	return 1;
}

static int maildir_handle_uid_insertion(struct maildir_index_sync_context *ctx,
					enum maildir_uidlist_rec_flag uflags,
					const char *filename, uint32_t uid)
{
	int ret;

	if ((uflags & MAILDIR_UIDLIST_REC_FLAG_NONSYNCED) != 0) {
		/* partial syncing */
		return 0;
	}

	/* most likely a race condition: we read the maildir, then someone else
	   expunged messages and committed changes to index. so, this message
	   shouldn't actually exist. */
	if ((uflags & MAILDIR_UIDLIST_REC_FLAG_RACING) == 0) {
		/* mark it racy and check in next sync */
		ctx->mbox->maildir_hdr.cur_check_time = 0;
		maildir_uidlist_add_flags(ctx->mbox->uidlist, filename,
					  MAILDIR_UIDLIST_REC_FLAG_RACING);
		return 0;
	}

	if (ctx->uidlist_sync_ctx == NULL) {
		ret = maildir_uidlist_sync_init(ctx->mbox->uidlist,
						MAILDIR_UIDLIST_SYNC_PARTIAL |
						MAILDIR_UIDLIST_SYNC_KEEP_STATE,
						&ctx->uidlist_sync_ctx);
		if (ret <= 0)
			return -1;
	}

	uflags &= MAILDIR_UIDLIST_REC_FLAG_NEW_DIR;
	maildir_uidlist_sync_remove(ctx->uidlist_sync_ctx, filename);
	ret = maildir_uidlist_sync_next(ctx->uidlist_sync_ctx,
					filename, uflags);
	i_assert(ret > 0);

	/* give the new UID to it immediately */
	maildir_uidlist_sync_finish(ctx->uidlist_sync_ctx);

	i_warning("Maildir %s: Expunged message reappeared, giving a new UID "
		  "(old uid=%u, file=%s)%s", ctx->mbox->box.path,
		  uid, filename, strncmp(filename, "msg.", 4) != 0 ? "" :
		  " (Your MDA is saving MH files into Maildir?)");
	return 0;
}

int maildir_sync_index_begin(struct maildir_mailbox *mbox,
			     struct maildir_sync_context *maildir_sync_ctx,
			     struct maildir_index_sync_context **ctx_r)
{
	struct mailbox *_box = &mbox->box;
	struct maildir_index_sync_context *ctx;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	enum mail_index_sync_flags sync_flags;

	sync_flags = index_storage_get_sync_flags(&mbox->box);
	/* don't drop recent messages if we're saving messages */
	if (maildir_sync_ctx == NULL)
		sync_flags &= ~MAIL_INDEX_SYNC_FLAG_DROP_RECENT;

	if (mail_index_sync_begin(_box->index, &sync_ctx, &view,
				  &trans, sync_flags) < 0) {
		mail_storage_set_index_error(_box);
		return -1;
	}

	ctx = i_new(struct maildir_index_sync_context, 1);
	ctx->mbox = mbox;
	ctx->maildir_sync_ctx = maildir_sync_ctx;
	ctx->sync_ctx = sync_ctx;
	ctx->view = view;
	ctx->trans = trans;
	ctx->keywords_sync_ctx =
		maildir_keywords_sync_init(mbox->keywords, _box->index);
	ctx->sync_changes =
		index_sync_changes_init(ctx->sync_ctx, ctx->view, ctx->trans,
					mbox->box.backend_readonly);
	ctx->start_time = time(NULL);

	*ctx_r = ctx;
	return 0;
}

static bool
maildir_index_header_has_changed(const struct maildir_index_header *old_hdr,
				 const struct maildir_index_header *new_hdr)
{
#define DIR_DELAYED_REFRESH(hdr, name) \
	((hdr)->name ## _check_time <= \
		(hdr)->name ## _mtime + MAILDIR_SYNC_SECS)

	if (old_hdr->new_mtime != new_hdr->new_mtime ||
	    old_hdr->new_mtime_nsecs != new_hdr->new_mtime_nsecs ||
	    old_hdr->cur_mtime != new_hdr->cur_mtime ||
	    old_hdr->cur_mtime_nsecs != new_hdr->cur_mtime_nsecs ||
	    old_hdr->uidlist_mtime != new_hdr->uidlist_mtime ||
	    old_hdr->uidlist_mtime_nsecs != new_hdr->uidlist_mtime_nsecs ||
	    old_hdr->uidlist_size != new_hdr->uidlist_size)
		return TRUE;

	return DIR_DELAYED_REFRESH(old_hdr, new) !=
		DIR_DELAYED_REFRESH(new_hdr, new) ||
		DIR_DELAYED_REFRESH(old_hdr, cur) !=
		DIR_DELAYED_REFRESH(new_hdr, cur);
}

static void
maildir_sync_index_update_ext_header(struct maildir_index_sync_context *ctx)
{
	struct maildir_mailbox *mbox = ctx->mbox;
	const void *data;
	size_t data_size;
	struct stat st;

	if (ctx->update_maildir_hdr_cur &&
	    stat(t_strconcat(mbox->box.path, "/cur", NULL), &st) == 0) {
		if ((time_t)mbox->maildir_hdr.cur_check_time < st.st_mtime)
			mbox->maildir_hdr.cur_check_time = st.st_mtime;
		mbox->maildir_hdr.cur_mtime = st.st_mtime;
		mbox->maildir_hdr.cur_mtime_nsecs = ST_MTIME_NSEC(st);
	}

	mail_index_get_header_ext(mbox->box.view, mbox->maildir_ext_id,
				  &data, &data_size);
	if (data_size != sizeof(mbox->maildir_hdr) ||
	    maildir_index_header_has_changed(data, &mbox->maildir_hdr)) {
		mail_index_update_header_ext(ctx->trans, mbox->maildir_ext_id,
					     0, &mbox->maildir_hdr,
					     sizeof(mbox->maildir_hdr));
	}
}

static int maildir_sync_index_finish(struct maildir_index_sync_context *ctx,
				     bool success)
{
	struct maildir_mailbox *mbox = ctx->mbox;
	unsigned int time_diff;
	int ret = success ? 0 : -1;

	time_diff = time(NULL) - ctx->start_time;
	if (time_diff >= MAILDIR_SYNC_TIME_WARN_SECS) {
		i_warning("Maildir %s: Synchronization took %u seconds "
			  "(%u new msgs, %u flag change attempts, "
			  "%u expunge attempts)",
			  ctx->mbox->box.path, time_diff,
			  ctx->new_msgs_count, ctx->flag_change_count,
			  ctx->expunge_count);
	}

	if (ret < 0)
		mail_index_sync_rollback(&ctx->sync_ctx);
	else {
		maildir_sync_index_update_ext_header(ctx);

		/* Set syncing_commit=TRUE so that if any sync callbacks try
		   to access mails which got lost (eg. expunge callback trying
		   to open the file which was just unlinked) we don't try to
		   start a second index sync and crash. */
		mbox->syncing_commit = TRUE;
		if (mail_index_sync_commit(&ctx->sync_ctx) < 0) {
			mail_storage_set_index_error(&mbox->box);
			ret = -1;
		}
		mbox->syncing_commit = FALSE;
	}

	maildir_keywords_sync_deinit(&ctx->keywords_sync_ctx);
	index_sync_changes_deinit(&ctx->sync_changes);
	i_free(ctx);
	return ret;
}

int maildir_sync_index_commit(struct maildir_index_sync_context **_ctx)
{
	struct maildir_index_sync_context *ctx = *_ctx;

	*_ctx = NULL;
	return maildir_sync_index_finish(ctx, TRUE);
}

void maildir_sync_index_rollback(struct maildir_index_sync_context **_ctx)
{
	struct maildir_index_sync_context *ctx = *_ctx;

	*_ctx = NULL;
	(void)maildir_sync_index_finish(ctx, FALSE);
}

static int uint_cmp(const void *p1, const void *p2)
{
	const unsigned int *i1 = p1, *i2 = p2;

	if (*i1 < *i2)
		return -1;
	else if (*i1 > *i2)
		return 1;
	else
		return 0;
}

static void
maildir_sync_mail_keywords(struct maildir_index_sync_context *ctx, uint32_t seq)
{
	struct mailbox *box = &ctx->mbox->box;
	struct mail_keywords *kw;
	unsigned int i, j, old_count, new_count;
	const unsigned int *old_indexes, *new_indexes;
	bool have_indexonly_keywords;
	int diff;

	mail_index_lookup_keywords(ctx->view, seq, &ctx->idx_keywords);
	if (index_keyword_array_cmp(&ctx->keywords, &ctx->idx_keywords)) {
		/* no changes - we should get here usually */
		return;
	}

	/* sort the keywords */
	array_sort(&ctx->idx_keywords, uint_cmp);
	array_sort(&ctx->keywords, uint_cmp);

	/* drop keywords that are in index-only. we don't want to touch them. */
	old_indexes = array_get(&ctx->idx_keywords, &old_count);
	have_indexonly_keywords = FALSE;
	for (i = old_count; i > 0; i--) {
		if (old_indexes[i-1] < MAILDIR_MAX_KEYWORDS)
			break;
		have_indexonly_keywords = TRUE;
		array_delete(&ctx->idx_keywords, i-1, 1);
	}

	if (!have_indexonly_keywords) {
		/* no index-only keywords found, so something changed.
		   just replace them all. */
		kw = mail_index_keywords_create_from_indexes(box->index,
							     &ctx->keywords);
		mail_index_update_keywords(ctx->trans, seq, MODIFY_REPLACE, kw);
		mail_index_keywords_unref(&kw);
		return;
	}

	/* check again if non-index-only keywords changed */
	if (index_keyword_array_cmp(&ctx->keywords, &ctx->idx_keywords))
		return;

	/* we can't reset all the keywords or we'd drop indexonly keywords too.
	   so first remove the unwanted keywords and then add back the wanted
	   ones. we can get these lists easily by removing common elements
	   from old and new keywords. */
	new_indexes = array_get(&ctx->keywords, &new_count);
	for (i = j = 0; i < old_count && j < new_count; ) {
		diff = (int)old_indexes[i] - (int)new_indexes[j];
		if (diff == 0) {
			array_delete(&ctx->keywords, j, 1);
			array_delete(&ctx->idx_keywords, i, 1);
			old_indexes = array_get(&ctx->idx_keywords, &old_count);
			new_indexes = array_get(&ctx->keywords, &new_count);
		} else if (diff < 0) {
			i++;
		} else {
			j++;
		}
	}

	if (array_count(&ctx->idx_keywords) > 0) {
		kw = mail_index_keywords_create_from_indexes(box->index,
							     &ctx->idx_keywords);
		mail_index_update_keywords(ctx->trans, seq, MODIFY_REMOVE, kw);
		mail_index_keywords_unref(&kw);
	}

	if (array_count(&ctx->keywords) > 0) {
		kw = mail_index_keywords_create_from_indexes(box->index,
							     &ctx->keywords);
		mail_index_update_keywords(ctx->trans, seq, MODIFY_ADD, kw);
		mail_index_keywords_unref(&kw);
	}
}

int maildir_sync_index(struct maildir_index_sync_context *ctx,
		       bool partial)
{
	struct maildir_mailbox *mbox = ctx->mbox;
	struct mail_index_view *view = ctx->view;
	struct mail_index_view *view2;
	struct maildir_uidlist_iter_ctx *iter;
	struct mail_index_transaction *trans = ctx->trans;
	const struct mail_index_header *hdr;
	struct mail_index_header empty_hdr;
	const struct mail_index_record *rec;
	uint32_t seq, seq2, uid, prev_uid;
        enum maildir_uidlist_rec_flag uflags;
	const char *filename;
	uint32_t uid_validity, next_uid, hdr_next_uid, first_recent_uid;
	uint32_t first_uid;
	unsigned int changes = 0;
	int ret = 0;
	time_t time_before_sync;
	uint8_t expunged_guid_128[MAIL_GUID_128_SIZE];
	bool expunged, full_rescan = FALSE;

	i_assert(!mbox->syncing_commit);

	first_uid = 1;
	hdr = mail_index_get_header(view);
	uid_validity = maildir_uidlist_get_uid_validity(mbox->uidlist);
	if (uid_validity != hdr->uid_validity &&
	    uid_validity != 0 && hdr->uid_validity != 0) {
		/* uidvalidity changed and index isn't being synced for the
		   first time, reset the index so we can add all messages as
		   new */
		i_warning("Maildir %s: UIDVALIDITY changed (%u -> %u)",
			  mbox->box.path, hdr->uid_validity, uid_validity);
		mail_index_reset(trans);
		index_mailbox_reset_uidvalidity(&mbox->box);

		first_uid = hdr->messages_count + 1;
		memset(&empty_hdr, 0, sizeof(empty_hdr));
		empty_hdr.next_uid = 1;
		hdr = &empty_hdr;
	}
	hdr_next_uid = hdr->next_uid;

	time_before_sync = time(NULL);
	mbox->syncing_commit = TRUE;
	seq = prev_uid = 0; first_recent_uid = I_MAX(hdr->first_recent_uid, 1);
	i_array_init(&ctx->keywords, MAILDIR_MAX_KEYWORDS);
	i_array_init(&ctx->idx_keywords, MAILDIR_MAX_KEYWORDS);
	iter = maildir_uidlist_iter_init(mbox->uidlist);
	while (maildir_uidlist_iter_next(iter, &uid, &uflags, &filename)) {
		maildir_filename_get_flags(ctx->keywords_sync_ctx, filename,
					   &ctx->flags, &ctx->keywords);

		i_assert(uid > prev_uid);
		prev_uid = uid;

		/* the private flags are kept only in indexes. don't use them
		   at all even for newly seen mails */
		ctx->flags &= ~mbox->box.private_flags_mask;

	again:
		seq++;
		ctx->uid = uid;

		if (seq > hdr->messages_count) {
			if (uid < hdr_next_uid) {
				if (maildir_handle_uid_insertion(ctx, uflags,
								 filename,
								 uid) < 0)
					ret = -1;
				seq--;
				continue;
			}

			/* Trust uidlist recent flags only for newly added
			   messages. When saving/copying messages with flags
			   they're stored to cur/ and uidlist treats them
			   as non-recent. */
			if ((uflags & MAILDIR_UIDLIST_REC_FLAG_RECENT) == 0) {
				if (uid >= first_recent_uid)
					first_recent_uid = uid + 1;
			}

			hdr_next_uid = uid + 1;
			mail_index_append(trans, uid, &seq);
			mail_index_update_flags(trans, seq, MODIFY_REPLACE,
						ctx->flags);
			if (array_count(&ctx->keywords) > 0) {
				struct mail_keywords *kw;

				kw = mail_index_keywords_create_from_indexes(
					mbox->box.index, &ctx->keywords);
				mail_index_update_keywords(trans, seq,
							   MODIFY_REPLACE, kw);
				mail_index_keywords_unref(&kw);
			}
			continue;
		}

		rec = mail_index_lookup(view, seq);
		if (uid > rec->uid) {
			/* already expunged (no point in showing guid in the
			   expunge record anymore) */
			mail_index_expunge(ctx->trans, seq);
			goto again;
		}

		if (uid < rec->uid) {
			if (maildir_handle_uid_insertion(ctx, uflags,
							 filename, uid) < 0)
				ret = -1;
			seq--;
			continue;
		}

		index_sync_changes_read(ctx->sync_changes, ctx->uid, &expunged,
					expunged_guid_128);
		if (expunged) {
			if (!maildir_expunge_is_valid_guid(ctx, ctx->uid,
							   filename,
							   expunged_guid_128))
				continue;
			if (maildir_file_do(mbox, ctx->uid,
					    maildir_expunge, ctx) >= 0) {
				/* successful expunge */
				mail_index_expunge(ctx->trans, seq);
			}
			if ((++changes % MAILDIR_SLOW_MOVE_COUNT) == 0)
				maildir_sync_notify(ctx->maildir_sync_ctx);
			continue;
		}

		/* the private flags are stored only in indexes, keep them */
		ctx->flags |= rec->flags & mbox->box.private_flags_mask;

		if (index_sync_changes_have(ctx->sync_changes)) {
			/* apply flag changes to maildir */
			if (maildir_file_do(mbox, ctx->uid,
					    maildir_sync_flags, ctx) < 0)
				ctx->flags |= MAIL_INDEX_MAIL_FLAG_DIRTY;
			if ((++changes % MAILDIR_SLOW_MOVE_COUNT) == 0)
				maildir_sync_notify(ctx->maildir_sync_ctx);
		}

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

		if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0) {
			/* we haven't been able to update maildir with this
			   record's flag changes. don't sync them. */
			continue;
		}

		if (ctx->flags != (rec->flags & MAIL_FLAGS_NONRECENT)) {
			mail_index_update_flags(trans, seq, MODIFY_REPLACE,
						ctx->flags);
		}

		maildir_sync_mail_keywords(ctx, seq);
	}
	maildir_uidlist_iter_deinit(&iter);

	if (!partial) {
		/* expunge the rest */
		for (seq++; seq <= hdr->messages_count; seq++)
			mail_index_expunge(ctx->trans, seq);
	}

	/* add \Recent flags. use updated view so it contains newly
	   appended messages. */
	view2 = mail_index_transaction_open_updated_view(trans);
	if (mail_index_lookup_seq_range(view2, first_recent_uid, (uint32_t)-1,
					&seq, &seq2) && seq2 >= first_uid) {
		if (seq < first_uid) {
			/* UIDVALIDITY changed, skip over the old messages */
			seq = first_uid;
		}
		index_mailbox_set_recent_seq(&mbox->box, view2, seq, seq2);
	}
	mail_index_view_close(&view2);

	if (ctx->uidlist_sync_ctx != NULL) {
		if (maildir_uidlist_sync_deinit(&ctx->uidlist_sync_ctx,
						TRUE) < 0)
			ret = -1;
	}

	if (mbox->box.v.sync_notify != NULL)
		mbox->box.v.sync_notify(&mbox->box, 0, 0);

	/* check cur/ mtime later. if we came here from saving messages they
	   could still be moved to cur/ directory. */
	ctx->update_maildir_hdr_cur = TRUE;
	mbox->maildir_hdr.cur_check_time = time_before_sync;

	if (uid_validity == 0) {
		uid_validity = hdr->uid_validity != 0 ? hdr->uid_validity :
			maildir_get_uidvalidity_next(mbox->box.list);
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

	i_assert(hdr->first_recent_uid <= first_recent_uid);
	if (hdr->first_recent_uid < first_recent_uid) {
		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, first_recent_uid),
			&first_recent_uid, sizeof(first_recent_uid), FALSE);
	}
	array_free(&ctx->keywords);
	array_free(&ctx->idx_keywords);
	mbox->syncing_commit = FALSE;
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
	bool expunged;

	ext_id = maildir_list_get_ext_id(mbox->storage, list_view);
	mail_index_lookup_ext(list_view, seq, ext_id, &data, &expunged);
	rec = data;

	if (rec == NULL || expunged ||
	    rec->new_mtime == 0 || rec->cur_mtime == 0) {
		/* doesn't exist, not synced or dirty-synced */
		return 1;
	}

	root_dir = mailbox_list_get_path(box->list, box->name,
					 MAILBOX_LIST_PATH_TYPE_MAILBOX);

	/* check if new/ changed */
	new_dir = t_strconcat(root_dir, "/new", NULL);
	if (stat(new_dir, &st) < 0) {
		mail_storage_set_critical(box->storage,
					  "stat(%s) failed: %m", new_dir);
		return -1;
	}
	if ((time_t)rec->new_mtime != st.st_mtime)
		return 1;

	/* check if cur/ changed */
	cur_dir = t_strconcat(root_dir, "/cur", NULL);
	if (stat(cur_dir, &st) < 0) {
		mail_storage_set_critical(box->storage,
					  "stat(%s) failed: %m", cur_dir);
		return -1;
	}
	if ((time_t)rec->cur_mtime != st.st_mtime)
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
	bool expunged;

	/* get the current record */
	list_view = mail_index_transaction_get_view(trans);
	ext_id = maildir_list_get_ext_id(mbox->storage, list_view);
	mail_index_lookup_ext(list_view, seq, ext_id, &data, &expunged);
	if (expunged)
		return 0;
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
