/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "nfs-workarounds.h"
#include "index-mail.h"
#include "maildir-storage.h"
#include "maildir-filename.h"
#include "maildir-uidlist.h"
#include "maildir-sync.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

struct maildir_open_context {
	int fd;
	char *path;
};

static int
do_open(struct maildir_mailbox *mbox, const char *path,
	struct maildir_open_context *ctx)
{
	ctx->fd = nfs_safe_open(path, O_RDONLY);
	if (ctx->fd != -1) {
		ctx->path = i_strdup(path);
		return 1;
	}
	if (errno == ENOENT)
		return 0;

	if (errno == EACCES) {
		mailbox_set_critical(&mbox->box, "%s",
			mail_error_eacces_msg("open", path));
	} else {
		mailbox_set_critical(&mbox->box,
				     "open(%s) failed: %m", path);
	}
	return -1;
}

static int
do_stat(struct maildir_mailbox *mbox, const char *path, struct stat *st)
{
	if (stat(path, st) == 0)
		return 1;
	if (errno == ENOENT)
		return 0;

	if (errno == EACCES) {
		mailbox_set_critical(&mbox->box, "%s",
			mail_error_eacces_msg("stat", path));
	} else {
		mailbox_set_critical(&mbox->box, "stat(%s) failed: %m", path);
	}
	return -1;
}

static struct istream *
maildir_open_mail(struct maildir_mailbox *mbox, struct mail *mail,
		  bool *deleted_r)
{
	struct istream *input;
	const char *path;
	struct maildir_open_context ctx;

	*deleted_r = FALSE;

	ctx.fd = -1;
	ctx.path = NULL;

	mail->transaction->stats.open_lookup_count++;
	if (!mail->saving) {
		if (maildir_file_do(mbox, mail->uid, do_open, &ctx) < 0)
			return NULL;
	} else {
		path = maildir_save_file_get_path(mail->transaction, mail->seq);
		if (do_open(mbox, path, &ctx) <= 0)
			return NULL;
	}

	if (ctx.fd == -1) {
		*deleted_r = TRUE;
		return NULL;
	}

	input = i_stream_create_fd_autoclose(&ctx.fd, 0);
	if (input->stream_errno == EISDIR) {
		i_stream_destroy(&input);
		if (maildir_lose_unexpected_dir(&mbox->storage->storage,
						ctx.path) >= 0)
			*deleted_r = TRUE;
	} else {
		i_stream_set_name(input, ctx.path);
		index_mail_set_read_buffer_size(mail, input);
	}
	i_free(ctx.path);
	return input;
}

static int maildir_mail_stat(struct mail *mail, struct stat *st_r)
{
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(mail->box);
	struct index_mail *imail = INDEX_MAIL(mail);
	const char *path;
	int fd, ret;

	if (mail->lookup_abort >= MAIL_LOOKUP_ABORT_NOT_IN_CACHE) {
		mail_set_aborted(mail);
		return -1;
	}
	mail->mail_metadata_accessed = TRUE;

	if (imail->data.access_part != 0 &&
	    imail->data.stream == NULL) {
		/* we're going to open the mail anyway */
		struct istream *input;

		(void)mail_get_stream(mail, NULL, NULL, &input);
	}

	if (imail->data.stream != NULL &&
	    (fd = i_stream_get_fd(imail->data.stream)) != -1) {
		mail->transaction->stats.fstat_lookup_count++;
		if (fstat(fd, st_r) < 0) {
			mail_set_critical(mail, "fstat(%s) failed: %m",
				i_stream_get_name(imail->data.stream));
			return -1;
		}
	} else if (!mail->saving) {
		mail->transaction->stats.stat_lookup_count++;
		ret = maildir_file_do(mbox, mail->uid, do_stat, st_r);
		if (ret <= 0) {
			if (ret == 0)
				mail_set_expunged(mail);
			return -1;
		}
	} else {
		mail->transaction->stats.stat_lookup_count++;
		path = maildir_save_file_get_path(mail->transaction, mail->seq);
		if (stat(path, st_r) < 0) {
			mail_set_critical(mail, "stat(%s) failed: %m", path);
			return -1;
		}
	}
	return 0;
}

static int maildir_mail_get_received_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct index_mail_data *data = &mail->data;
	struct stat st;

	if (index_mail_get_received_date(_mail, date_r) == 0)
		return 0;

	if (maildir_mail_stat(_mail, &st) < 0)
		return -1;

	*date_r = data->received_date = st.st_mtime;
	return 0;
}

static int maildir_mail_get_save_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct index_mail_data *data = &mail->data;
	struct stat st;

	if (index_mail_get_save_date(_mail, date_r) == 0)
		return 0;

	if (maildir_mail_stat(_mail, &st) < 0)
		return -1;

	*date_r = data->save_date = st.st_ctime;
	return 0;
}

static int
maildir_mail_get_fname(struct maildir_mailbox *mbox, struct mail *mail,
		       const char **fname_r)
{
	enum maildir_uidlist_rec_flag flags;
	struct mail_index_view *view;
	uint32_t seq;
	bool exists;
	int ret;

	ret = maildir_sync_lookup(mbox, mail->uid, &flags, fname_r);
	if (ret != 0)
		return ret;

	/* file exists in index file, but not in dovecot-uidlist anymore. */
	mail_set_expunged(mail);

	/* one reason this could happen is if we delayed opening
	   dovecot-uidlist and we're trying to open a mail that got recently
	   expunged. Let's test this theory first: */
	mail_index_refresh(mbox->box.index);
	view = mail_index_view_open(mbox->box.index);
	exists = mail_index_lookup_seq(view, mail->uid, &seq);
	mail_index_view_close(&view);

	if (exists) {
		/* the message still exists in index. this means there's some
		   kind of a desync, which doesn't get fixed if cur/ mtime is
		   the same as in index. fix this by forcing a resync. */
		(void)maildir_storage_sync_force(mbox, mail->uid);
	}
	return 0;
}

static int maildir_get_pop3_state(struct index_mail *mail)
{
	struct mailbox *box = mail->mail.mail.box;
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);
	const struct mail_cache_field *fields;
	unsigned int i, count, psize_idx, vsize_idx;
	enum mail_cache_decision_type dec, vsize_dec;
	enum mail_fetch_field allowed_pop3_fields;
	bool not_pop3_only = FALSE;

	if (mail->pop3_state_set)
		return mail->pop3_state;

	/* if this mail itself has non-pop3 fields we know we're not
	   pop3-only */
	allowed_pop3_fields = MAIL_FETCH_FLAGS | MAIL_FETCH_STREAM_HEADER |
		MAIL_FETCH_STREAM_BODY | MAIL_FETCH_STORAGE_ID |
		MAIL_FETCH_VIRTUAL_SIZE;

	if (mail->data.wanted_headers != NULL ||
	    (mail->data.wanted_fields & ~allowed_pop3_fields) != 0)
		not_pop3_only = TRUE;

	/* get vsize decisions */
	psize_idx = ibox->cache_fields[MAIL_CACHE_PHYSICAL_FULL_SIZE].idx;
	vsize_idx = ibox->cache_fields[MAIL_CACHE_VIRTUAL_FULL_SIZE].idx;
	if (not_pop3_only) {
		vsize_dec = mail_cache_field_get_decision(box->cache,
							  vsize_idx);
		vsize_dec &= ~MAIL_CACHE_DECISION_FORCED;
	} else {
		/* also check if there are any non-[pv]size cached fields */
		vsize_dec = MAIL_CACHE_DECISION_NO;
		fields = mail_cache_register_get_list(box->cache,
						      pool_datastack_create(),
						      &count);
		for (i = 0; i < count; i++) {
			dec = fields[i].decision & ~MAIL_CACHE_DECISION_FORCED;
			if (fields[i].idx == vsize_idx)
				vsize_dec = dec;
			else if (dec != MAIL_CACHE_DECISION_NO &&
				 fields[i].idx != psize_idx)
				not_pop3_only = TRUE;
		}
	}

	if (index_mail_get_vsize_extension(&mail->mail.mail) != NULL) {
		/* having a vsize extension in index is the same as having
		   vsize's caching decision YES */
		vsize_dec = MAIL_CACHE_DECISION_YES;
	}

	if (!not_pop3_only) {
		/* either nothing is cached, or only vsize is cached. */
		mail->pop3_state = 1;
	} else if (vsize_dec != MAIL_CACHE_DECISION_YES &&
		   (box->flags & MAILBOX_FLAG_POP3_SESSION) == 0) {
		/* if virtual size isn't cached permanently,
		   POP3 isn't being used */
		mail->pop3_state = -1;
	} else {
		/* possibly a mixed pop3/imap */
		mail->pop3_state = 0;
	}
	mail->pop3_state_set = TRUE;
	return mail->pop3_state;
}

static int maildir_quick_size_lookup(struct index_mail *mail, bool vsize,
				     uoff_t *size_r)
{
	struct mail *_mail = &mail->mail.mail;
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(_mail->box);
	enum maildir_uidlist_rec_ext_key key;
	const char *path, *fname, *value;

	if (!_mail->saving) {
		if (maildir_mail_get_fname(mbox, _mail, &fname) <= 0)
			return -1;
	} else {
		if (maildir_save_file_get_size(_mail->transaction, _mail->seq,
					       vsize, size_r) == 0)
			return 1;

		path = maildir_save_file_get_path(_mail->transaction,
						  _mail->seq);
		fname = strrchr(path, '/');
		fname = fname != NULL ? fname + 1 : path;
	}

	/* size can be included in filename */
	if (vsize || !mbox->storage->set->maildir_broken_filename_sizes) {
		if (maildir_filename_get_size(fname,
				vsize ? MAILDIR_EXTRA_VIRTUAL_SIZE :
					MAILDIR_EXTRA_FILE_SIZE, size_r))
			return 1;
	}

	/* size can be included in uidlist entry */
	if (!_mail->saving) {
		key = vsize ? MAILDIR_UIDLIST_REC_EXT_VSIZE :
			MAILDIR_UIDLIST_REC_EXT_PSIZE;
		value = maildir_uidlist_lookup_ext(mbox->uidlist, _mail->uid,
						   key);
		if (value != NULL && str_to_uoff(value, size_r) == 0)
			return 1;
	}
	return 0;
}

static void
maildir_handle_size_caching(struct index_mail *mail, bool quick_check,
			    bool vsize)
{
	struct mailbox *box = mail->mail.mail.box;
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(box);
	enum mail_fetch_field field;
	uoff_t size;
	int pop3_state;

	field = vsize ? MAIL_FETCH_VIRTUAL_SIZE : MAIL_FETCH_PHYSICAL_SIZE;
	if ((mail->data.dont_cache_fetch_fields & field) != 0)
		return;

	if (quick_check && maildir_quick_size_lookup(mail, vsize, &size) > 0) {
		/* already in filename / uidlist. don't add it anywhere,
		   including to the uidlist if it's already in filename.
		   do some extra checks here to catch potential cache bugs. */
		if (vsize && mail->data.virtual_size != size) {
			mail_set_mail_cache_corrupted(&mail->mail.mail,
				"Corrupted virtual size: "
				"%"PRIuUOFF_T" != %"PRIuUOFF_T,
				mail->data.virtual_size, size);
			mail->data.virtual_size = size;
		} else if (!vsize && mail->data.physical_size != size) {
			mail_set_mail_cache_corrupted(&mail->mail.mail,
				"Corrupted physical size: "
				"%"PRIuUOFF_T" != %"PRIuUOFF_T,
				mail->data.physical_size, size);
			mail->data.physical_size = size;
		}
		mail->data.dont_cache_fetch_fields |= field;
		return;
	}

	/* 1 = pop3-only, 0 = mixed, -1 = no pop3 */
	pop3_state = maildir_get_pop3_state(mail);
	if (pop3_state >= 0 && mail->mail.mail.uid != 0) {
		/* if size is wanted permanently, store it to uidlist
		   so that in case cache file gets lost we can get it quickly */
		mail->data.dont_cache_fetch_fields |= field;
		size = vsize ? mail->data.virtual_size :
			mail->data.physical_size;
		maildir_uidlist_set_ext(mbox->uidlist, mail->mail.mail.uid,
					vsize ? MAILDIR_UIDLIST_REC_EXT_VSIZE :
					MAILDIR_UIDLIST_REC_EXT_PSIZE,
					dec2str(size));
	}
}

static int maildir_mail_get_virtual_size(struct mail *_mail, uoff_t *size_r)
{
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(_mail->box);
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct index_mail_data *data = &mail->data;
	struct message_size hdr_size, body_size;
	struct istream *input;
	uoff_t old_offset;

	if (maildir_uidlist_is_read(mbox->uidlist) ||
	    (_mail->box->flags & MAILBOX_FLAG_POP3_SESSION) != 0) {
		/* try to get the size from uidlist. this is especially useful
		   with pop3 to avoid unnecessarily opening the cache file. */
		if (maildir_quick_size_lookup(mail, TRUE,
					      &data->virtual_size) < 0)
			return -1;
	}

	if (data->virtual_size == (uoff_t)-1) {
		if (index_mail_get_cached_virtual_size(mail, size_r)) {
			i_assert(mail->data.virtual_size != (uoff_t)-1);
			maildir_handle_size_caching(mail, TRUE, TRUE);
			return 0;
		}
		if (maildir_quick_size_lookup(mail, TRUE,
					      &data->virtual_size) < 0)
			return -1;
	}
	if (data->virtual_size != (uoff_t)-1) {
		data->dont_cache_fetch_fields |= MAIL_FETCH_VIRTUAL_SIZE;
		*size_r = data->virtual_size;
		return 0;
	}

	/* fallback to reading the file */
	old_offset = data->stream == NULL ? 0 : data->stream->v_offset;
	if (mail_get_stream(_mail, &hdr_size, &body_size, &input) < 0)
		return -1;
	i_stream_seek(data->stream, old_offset);

	maildir_handle_size_caching(mail, FALSE, TRUE);
	*size_r = data->virtual_size;
	return 0;
}

static int maildir_mail_get_physical_size(struct mail *_mail, uoff_t *size_r)
{
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(_mail->box);
	struct index_mail_data *data = &mail->data;
	struct stat st;
	struct message_size hdr_size, body_size;
	struct istream *input;
	const char *path;
	int ret;

	if (maildir_uidlist_is_read(mbox->uidlist) ||
	    (_mail->box->flags & MAILBOX_FLAG_POP3_SESSION) != 0) {
		/* try to get the size from uidlist (see virtual size above) */
		if (maildir_quick_size_lookup(mail, FALSE,
					      &data->physical_size) < 0)
			return -1;
	}

	if (data->physical_size == (uoff_t)-1) {
		if (index_mail_get_physical_size(_mail, size_r) == 0) {
			i_assert(mail->data.physical_size != (uoff_t)-1);
			maildir_handle_size_caching(mail, TRUE, FALSE);
			return 0;
		}
		if (maildir_quick_size_lookup(mail, FALSE,
					      &data->physical_size) < 0)
			return -1;
	}
	if (data->physical_size != (uoff_t)-1) {
		data->dont_cache_fetch_fields |= MAIL_FETCH_PHYSICAL_SIZE;
		*size_r = data->physical_size;
		return 0;
	}

	if (mail->mail.v.istream_opened != NULL) {
		/* we can't use stat(), because this may be a mail that some
		   plugin has changed (e.g. zlib). need to do it the slow
		   way. */
		if (mail_get_stream(_mail, &hdr_size, &body_size, &input) < 0)
			return -1;
		st.st_size = hdr_size.physical_size + body_size.physical_size;
	} else if (!_mail->saving) {
		ret = maildir_file_do(mbox, _mail->uid, do_stat, &st);
		if (ret <= 0) {
			if (ret == 0)
				mail_set_expunged(_mail);
			return -1;
		}
	} else {
		/* saved mail which hasn't been committed yet */
		path = maildir_save_file_get_path(_mail->transaction,
						  _mail->seq);
		if (stat(path, &st) < 0) {
			mail_set_critical(_mail, "stat(%s) failed: %m", path);
			return -1;
		}
	}

	data->physical_size = st.st_size;
	maildir_handle_size_caching(mail, FALSE, FALSE);
	*size_r = st.st_size;
	return 0;
}

static int
maildir_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
			 const char **value_r)
{
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(_mail->box);
	const char *path, *fname = NULL, *end, *guid, *uidl, *order;
	struct stat st;

	switch (field) {
	case MAIL_FETCH_GUID:
		/* use GUID from uidlist if it exists */
		i_assert(!_mail->saving);

		if (mail->data.guid != NULL) {
			*value_r = mail->data.guid;
			return 0;
		}

		/* first make sure that we have a refreshed uidlist */
		if (maildir_mail_get_fname(mbox, _mail, &fname) <= 0)
			return -1;

		guid = maildir_uidlist_lookup_ext(mbox->uidlist, _mail->uid,
						  MAILDIR_UIDLIST_REC_EXT_GUID);
		if (guid != NULL) {
			if (*guid != '\0') {
				*value_r = mail->data.guid =
					p_strdup(mail->mail.data_pool, guid);
				return 0;
			}

			mail_set_critical(_mail,
				"Maildir: Corrupted dovecot-uidlist: "
				"UID had empty GUID, clearing it");
			maildir_uidlist_unset_ext(mbox->uidlist, _mail->uid,
				MAILDIR_UIDLIST_REC_EXT_GUID);
		}

		/* default to base filename: */
		if (maildir_mail_get_special(_mail, MAIL_FETCH_STORAGE_ID,
					     value_r) < 0)
			return -1;
		mail->data.guid = mail->data.filename;
		return 0;
	case MAIL_FETCH_STORAGE_ID:
		if (mail->data.filename != NULL) {
			*value_r = mail->data.filename;
			return 0;
		}
		if (fname != NULL) {
			/* we came here from MAIL_FETCH_GUID,
			   avoid a second lookup */
		} else if (!_mail->saving) {
			if (maildir_mail_get_fname(mbox, _mail, &fname) <= 0)
				return -1;
		} else {
			path = maildir_save_file_get_path(_mail->transaction,
							  _mail->seq);
			fname = strrchr(path, '/');
			fname = fname != NULL ? fname + 1 : path;
		}
		end = strchr(fname, MAILDIR_INFO_SEP);
		mail->data.filename = end == NULL ?
			p_strdup(mail->mail.data_pool, fname) :
			p_strdup_until(mail->mail.data_pool, fname, end);
		*value_r = mail->data.filename;
		return 0;
	case MAIL_FETCH_UIDL_BACKEND:
		uidl = maildir_uidlist_lookup_ext(mbox->uidlist, _mail->uid,
					MAILDIR_UIDLIST_REC_EXT_POP3_UIDL);
		if (uidl == NULL) {
			/* use the default */
			*value_r = "";
		} else if (*uidl == '\0') {
			/* special optimization case: use the base file name */
			return maildir_mail_get_special(_mail,
					MAIL_FETCH_STORAGE_ID, value_r);
		} else {
			*value_r = p_strdup(mail->mail.data_pool, uidl);
		}
		return 0;
	case MAIL_FETCH_POP3_ORDER:
		order = maildir_uidlist_lookup_ext(mbox->uidlist, _mail->uid,
					MAILDIR_UIDLIST_REC_EXT_POP3_ORDER);
		if (order == NULL) {
			*value_r = "";
		} else {
			*value_r = p_strdup(mail->mail.data_pool, order);
		}
		return 0;
	case MAIL_FETCH_REFCOUNT:
		if (maildir_mail_stat(_mail, &st) < 0)
			return -1;
		*value_r = p_strdup_printf(mail->mail.data_pool, "%lu",
					   (unsigned long)st.st_nlink);
		return 0;
	case MAIL_FETCH_REFCOUNT_ID:
		if (maildir_mail_stat(_mail, &st) < 0)
			return -1;
		*value_r = p_strdup_printf(mail->mail.data_pool, "%llu",
					   (unsigned long long)st.st_ino);
		return 0;
	default:
		return index_mail_get_special(_mail, field, value_r);
	}
}
							
static int
maildir_mail_get_stream(struct mail *_mail, bool get_body ATTR_UNUSED,
			struct message_size *hdr_size,
			struct message_size *body_size,
			struct istream **stream_r)
{
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(_mail->box);
	struct index_mail_data *data = &mail->data;
	bool deleted;

	if (data->stream == NULL) {
		data->stream = maildir_open_mail(mbox, _mail, &deleted);
		if (data->stream == NULL) {
			if (deleted)
				mail_set_expunged(_mail);
			return -1;
		}
		if (mail->mail.v.istream_opened != NULL) {
			if (mail->mail.v.istream_opened(_mail,
							&data->stream) < 0) {
				i_stream_unref(&data->stream);
				return -1;
			}
		}
	}

	return index_mail_init_stream(mail, hdr_size, body_size, stream_r);
}

static void maildir_update_pop3_uidl(struct mail *_mail, const char *uidl)
{
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(_mail->box);
	const char *fname;

	if (maildir_mail_get_special(_mail, MAIL_FETCH_STORAGE_ID,
				     &fname) == 0 &&
	    strcmp(uidl, fname) == 0) {
		/* special case optimization: empty UIDL means the same
		   as base filename */
		uidl = "";
	}

	maildir_uidlist_set_ext(mbox->uidlist, _mail->uid,
				MAILDIR_UIDLIST_REC_EXT_POP3_UIDL, uidl);
}

static void maildir_mail_remove_sizes_from_uidlist(struct mail *mail)
{
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(mail->box);

	if (maildir_uidlist_lookup_ext(mbox->uidlist, mail->uid,
				       MAILDIR_UIDLIST_REC_EXT_VSIZE) != NULL) {
		maildir_uidlist_unset_ext(mbox->uidlist, mail->uid,
					  MAILDIR_UIDLIST_REC_EXT_VSIZE);
	}
	if (maildir_uidlist_lookup_ext(mbox->uidlist, mail->uid,
				       MAILDIR_UIDLIST_REC_EXT_PSIZE) != NULL) {
		maildir_uidlist_unset_ext(mbox->uidlist, mail->uid,
					  MAILDIR_UIDLIST_REC_EXT_PSIZE);
	}
}

struct maildir_size_fix_ctx {
	uoff_t physical_size;
	char wrong_key;
};

static int
do_fix_size(struct maildir_mailbox *mbox, const char *path,
	    struct maildir_size_fix_ctx *ctx)
{
	const char *fname, *newpath, *extra, *info, *dir;
	struct stat st;

	fname = strrchr(path, '/');
	i_assert(fname != NULL);
	dir = t_strdup_until(path, fname++);

	extra = strchr(fname, MAILDIR_EXTRA_SEP);
	i_assert(extra != NULL);
	info = strchr(fname, MAILDIR_INFO_SEP);
	if (info == NULL) info = "";

	if (ctx->physical_size == (uoff_t)-1) {
		if (stat(path, &st) < 0) {
			if (errno == ENOENT)
				return 0;
			mailbox_set_critical(&mbox->box,
					     "stat(%s) failed: %m", path);
			return -1;
		}
		ctx->physical_size = st.st_size;
	}

	newpath = t_strdup_printf("%s/%s,S=%"PRIuUOFF_T"%s", dir,
				  t_strdup_until(fname, extra),
				  ctx->physical_size, info);

	if (rename(path, newpath) == 0) {
		mailbox_set_critical(&mbox->box,
			"Maildir filename has wrong %c value, "
			"renamed the file from %s to %s",
			ctx->wrong_key, path, newpath);
		return 1;
	}
	if (errno == ENOENT)
		return 0;

	mailbox_set_critical(&mbox->box, "rename(%s, %s) failed: %m",
			     path, newpath);
	return -1;
}

static void
maildir_mail_remove_sizes_from_filename(struct mail *mail,
					enum mail_fetch_field field)
{
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(mail->box);
	struct mail_private *pmail = (struct mail_private *)mail;
	enum maildir_uidlist_rec_flag flags;
	const char *fname;
	uoff_t size;
	struct maildir_size_fix_ctx ctx;

	if (mbox->storage->set->maildir_broken_filename_sizes) {
		/* never try to fix sizes in maildir filenames */
		return;
	}

	if (maildir_sync_lookup(mbox, mail->uid, &flags, &fname) <= 0)
		return;
	if (strchr(fname, MAILDIR_EXTRA_SEP) == NULL)
		return;

	i_zero(&ctx);
	ctx.physical_size = (uoff_t)-1;
	if (field == MAIL_FETCH_VIRTUAL_SIZE &&
	    maildir_filename_get_size(fname, MAILDIR_EXTRA_VIRTUAL_SIZE,
				      &size)) {
		ctx.wrong_key = 'W';
	} else if (field == MAIL_FETCH_PHYSICAL_SIZE &&
		   maildir_filename_get_size(fname, MAILDIR_EXTRA_FILE_SIZE,
					     &size)) {
		ctx.wrong_key = 'S';
	} else {
		/* the broken size isn't in filename */
		return;
	}

	if (pmail->v.istream_opened != NULL) {
		/* the mail could be e.g. compressed. get the physical size
		   the slow way by actually reading the mail. */
		struct istream *input;
		const struct stat *stp;

		if (mail_get_stream(mail, NULL, NULL, &input) < 0)
			return;
		if (i_stream_stat(input, TRUE, &stp) < 0)
			return;
		ctx.physical_size = stp->st_size;
	}

	(void)maildir_file_do(mbox, mail->uid, do_fix_size, &ctx);
}

static void maildir_mail_set_cache_corrupted(struct mail *_mail,
					     enum mail_fetch_field field,
					     const char *reason)
{
	if (field == MAIL_FETCH_PHYSICAL_SIZE ||
	    field == MAIL_FETCH_VIRTUAL_SIZE) {
		maildir_mail_remove_sizes_from_uidlist(_mail);
		maildir_mail_remove_sizes_from_filename(_mail, field);
	}
	index_mail_set_cache_corrupted(_mail, field, reason);
}

struct mail_vfuncs maildir_mail_vfuncs = {
	index_mail_close,
	index_mail_free,
	index_mail_set_seq,
	index_mail_set_uid,
	index_mail_set_uid_cache_updates,
	index_mail_prefetch,
	index_mail_precache,
	index_mail_add_temp_wanted_fields,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_keyword_indexes,
	index_mail_get_modseq,
	index_mail_get_pvt_modseq,
	index_mail_get_parts,
	index_mail_get_date,
	maildir_mail_get_received_date,
	maildir_mail_get_save_date,
	maildir_mail_get_virtual_size,
	maildir_mail_get_physical_size,
	index_mail_get_first_header,
	index_mail_get_headers,
	index_mail_get_header_stream,
	maildir_mail_get_stream,
	index_mail_get_binary_stream,
	maildir_mail_get_special,
	index_mail_get_backend_mail,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_update_modseq,
	index_mail_update_pvt_modseq,
	maildir_update_pop3_uidl,
	index_mail_expunge,
	maildir_mail_set_cache_corrupted,
	index_mail_opened,
};
