/* Copyright (c) 2003-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "index-mail.h"
#include "maildir-storage.h"
#include "maildir-filename.h"
#include "maildir-uidlist.h"
#include "maildir-sync.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static int
do_open(struct maildir_mailbox *mbox, const char *path, int *fd)
{
	*fd = open(path, O_RDONLY);
	if (*fd != -1)
		return 1;
	if (errno == ENOENT)
		return 0;

	mail_storage_set_critical(&mbox->storage->storage,
				  "open(%s) failed: %m", path);
	return -1;
}

static int
do_stat(struct maildir_mailbox *mbox, const char *path, struct stat *st)
{
	if (stat(path, st) == 0)
		return 1;
	if (errno == ENOENT)
		return 0;

	mail_storage_set_critical(&mbox->storage->storage,
				  "stat(%s) failed: %m", path);
	return -1;
}

static struct istream *
maildir_open_mail(struct maildir_mailbox *mbox, struct mail *mail,
		  bool *deleted_r)
{
	const char *path;
	int fd = -1;

	*deleted_r = FALSE;

	if (mail->uid != 0) {
		if (maildir_file_do(mbox, mail->uid, do_open, &fd) < 0)
			return NULL;
	} else {
		path = maildir_save_file_get_path(mail->transaction, mail->seq);
		if (do_open(mbox, path, &fd) <= 0)
			return NULL;
	}

	if (fd == -1) {
		*deleted_r = TRUE;
		return NULL;
	}

	return i_stream_create_fd(fd, MAIL_READ_BLOCK_SIZE, TRUE);
}

static int maildir_mail_stat(struct mail *mail, struct stat *st)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)mail->box;
	struct index_mail_data *data = &((struct index_mail *)mail)->data;
	const char *path;
	int fd, ret;

	if (data->access_part != 0 && data->stream == NULL) {
		/* we're going to open the mail anyway */
		struct istream *input;

		(void)mail_get_stream(mail, NULL, NULL, &input);
	}

	if (data->stream != NULL) {
		fd = i_stream_get_fd(data->stream);
		i_assert(fd != -1);

		if (fstat(fd, st) < 0) {
			mail_storage_set_critical(&mbox->storage->storage,
						  "fstat(maildir) failed: %m");
			return -1;
		}
	} else if (mail->uid != 0) {
		ret = maildir_file_do(mbox, mail->uid, do_stat, st);
		if (ret <= 0) {
			if (ret == 0)
				mail_set_expunged(mail);
			return -1;
		}
	} else {
		path = maildir_save_file_get_path(mail->transaction, mail->seq);
		if (stat(path, st) < 0) {
			mail_storage_set_critical(mail->box->storage,
						  "stat(%s) failed: %m", path);
			return -1;
		}
	}
	return 0;
}

static int maildir_mail_get_received_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
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
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct stat st;

	if (index_mail_get_save_date(_mail, date_r) == 0)
		return 0;

	if (maildir_mail_stat(_mail, &st) < 0)
		return -1;

	*date_r = data->save_date = st.st_ctime;
	return data->save_date;
}

static bool
maildir_mail_get_fname(struct maildir_mailbox *mbox, struct mail *mail,
		       const char **fname_r)
{
	enum maildir_uidlist_rec_flag flags;
	struct mail_index_view *view;
	uint32_t seq;
	bool exists;

	*fname_r = maildir_uidlist_lookup(mbox->uidlist, mail->uid, &flags);
	if (*fname_r != NULL)
		return TRUE;

	/* file exists in index file, but not in dovecot-uidlist anymore. */
	mail_set_expunged(mail);

	/* one reason this could happen is if we delayed opening
	   dovecot-uidlist and we're trying to open a mail that got recently
	   expunged. Let's test this theory first: */
	(void)mail_index_refresh(mbox->ibox.index);
	view = mail_index_view_open(mbox->ibox.index);
	exists = mail_index_lookup_seq(view, mail->uid, &seq);
	mail_index_view_close(&view);

	if (exists) {
		/* the message still exists in index. this means there's some
		   kind of a desync, which doesn't get fixed if cur/ mtime is
		   the same as in index. fix this by forcing a resync. */
		(void)maildir_storage_sync_force(mbox, mail->uid);
	}
	return FALSE;
}

static int maildir_get_pop3_state(struct index_mail *mail)
{
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
		MAIL_FETCH_STREAM_BODY | MAIL_FETCH_UIDL_FILE_NAME |
		MAIL_FETCH_VIRTUAL_SIZE;

	if (mail->wanted_headers != NULL ||
	    (mail->wanted_fields & ~allowed_pop3_fields) != 0)
		not_pop3_only = TRUE;

	/* get vsize decisions */
	psize_idx = mail->ibox->cache_fields[MAIL_CACHE_PHYSICAL_FULL_SIZE].idx;
	vsize_idx = mail->ibox->cache_fields[MAIL_CACHE_VIRTUAL_FULL_SIZE].idx;
	if (not_pop3_only) {
		vsize_dec = mail_cache_field_get_decision(mail->ibox->cache,
							  vsize_idx);
		vsize_dec &= ~MAIL_CACHE_DECISION_FORCED;
	} else {
		/* also check if there are any non-[pv]size cached fields */
		vsize_dec = MAIL_CACHE_DECISION_NO;
		fields = mail_cache_register_get_list(mail->ibox->cache,
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

	if (!not_pop3_only) {
		/* either nothing is cached, or only vsize is cached. */
		mail->pop3_state = 1;
	} else if (vsize_dec != MAIL_CACHE_DECISION_YES) {
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
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)mail->ibox;
	enum maildir_uidlist_rec_ext_key key;
	const char *path, *fname, *value;
	uoff_t size;
	char *p;

	if (_mail->uid != 0) {
		if (!maildir_mail_get_fname(mbox, _mail, &fname))
			return -1;
	} else {
		path = maildir_save_file_get_path(_mail->transaction,
						  _mail->seq);
		fname = strrchr(path, '/');
		fname = fname != NULL ? fname + 1 : path;
	}

	/* size can be included in filename */
	if (maildir_filename_get_size(fname,
				      vsize ? MAILDIR_EXTRA_VIRTUAL_SIZE :
				      MAILDIR_EXTRA_FILE_SIZE,
				      size_r))
		return 1;

	/* size can be included in uidlist entry */
	if (_mail->uid != 0) {
		key = vsize ? MAILDIR_UIDLIST_REC_EXT_VSIZE :
			MAILDIR_UIDLIST_REC_EXT_PSIZE;
		value = maildir_uidlist_lookup_ext(mbox->uidlist, _mail->uid,
						   key);
		if (value != NULL) {
			size = strtoull(value, &p, 10);
			if (*p == '\0') {
				*size_r = size;
				return 1;
			}
		}
	}
	return 0;
}

static void
maildir_handle_size_caching(struct index_mail *mail, bool quick_check,
			    bool vsize)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)mail->ibox;
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
			mail_cache_set_corrupted(mail->ibox->cache,
				"Corrupted virtual size for uid=%u: "
				"%"PRIuUOFF_T" != %"PRIuUOFF_T,
				mail->mail.mail.uid,
				mail->data.virtual_size, size);
			mail->data.virtual_size = size;
		} else if (!vsize && mail->data.physical_size != size) {
			mail_cache_set_corrupted(mail->ibox->cache,
				"Corrupted physical size for uid=%u: "
				"%"PRIuUOFF_T" != %"PRIuUOFF_T,
				mail->mail.mail.uid,
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
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct message_size hdr_size, body_size;
	struct istream *input;
	uoff_t old_offset;

	if (index_mail_get_cached_virtual_size(mail, size_r)) {
		i_assert(mail->data.virtual_size != (uoff_t)-1);
		maildir_handle_size_caching(mail, TRUE, TRUE);
		return 0;
	}

	if (maildir_quick_size_lookup(mail, TRUE, &data->virtual_size) < 0)
		return -1;
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
	struct index_mail *mail = (struct index_mail *)_mail;
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)mail->ibox;
	struct index_mail_data *data = &mail->data;
	struct stat st;
	const char *path;
	int ret;

	if (index_mail_get_physical_size(_mail, size_r) == 0) {
		i_assert(mail->data.physical_size != (uoff_t)-1);
		maildir_handle_size_caching(mail, TRUE, FALSE);
		return 0;
	}

	if (maildir_quick_size_lookup(mail, FALSE, &data->physical_size) < 0)
		return -1;
	if (data->physical_size != (uoff_t)-1) {
		data->dont_cache_fetch_fields |= MAIL_FETCH_PHYSICAL_SIZE;
		*size_r = data->physical_size;
		return 0;
	}

	if (_mail->uid != 0) {
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
			mail_storage_set_critical(_mail->box->storage,
						  "stat(%s) failed: %m", path);
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
	struct index_mail *mail = (struct index_mail *)_mail;
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)mail->ibox;
	const char *path, *fname, *end;

	if (field == MAIL_FETCH_UIDL_FILE_NAME) {
		if (_mail->uid != 0) {
			if (!maildir_mail_get_fname(mbox, _mail, &fname))
				return -1;
		} else {
			path = maildir_save_file_get_path(_mail->transaction,
							  _mail->seq);
			fname = strrchr(path, '/');
			fname = fname != NULL ? fname + 1 : path;
		}
		end = strchr(fname, MAILDIR_INFO_SEP);
		*value_r = end == NULL ? fname : t_strdup_until(fname, end);
		return 0;
	}

	return index_mail_get_special(_mail, field, value_r);
}
							
static int maildir_mail_get_stream(struct mail *_mail,
				   struct message_size *hdr_size,
				   struct message_size *body_size,
				   struct istream **stream_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)mail->ibox;
	struct index_mail_data *data = &mail->data;
	bool deleted;

	if (data->stream == NULL) {
		data->stream = maildir_open_mail(mbox, _mail, &deleted);
		if (data->stream == NULL) {
			if (deleted)
				mail_set_expunged(_mail);
			return -1;
		}
	}

	return index_mail_init_stream(mail, hdr_size, body_size, stream_r);
}

static void maildir_mail_set_cache_corrupted(struct mail *_mail,
					     enum mail_fetch_field field)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)mail->ibox;
	enum maildir_uidlist_rec_flag flags;
	const char *fname;
	uoff_t size;

	if (field == MAIL_FETCH_VIRTUAL_SIZE) {
		/* make sure it gets removed from uidlist.
		   if it's in file name, we can't really do more than log it. */
		fname = maildir_uidlist_lookup(mbox->uidlist,
					       _mail->uid, &flags);
		if (maildir_filename_get_size(fname, MAILDIR_EXTRA_VIRTUAL_SIZE,
					      &size)) {
			i_error("Maildir filename has wrong W value: %s/%s",
				mbox->path, fname);
		} else if (maildir_uidlist_lookup_ext(mbox->uidlist, _mail->uid,
				MAILDIR_UIDLIST_REC_EXT_VSIZE) != NULL) {
			maildir_uidlist_set_ext(mbox->uidlist, _mail->uid,
						MAILDIR_UIDLIST_REC_EXT_VSIZE,
						NULL);
		}
	}
	index_mail_set_cache_corrupted(_mail, field);
}

struct mail_vfuncs maildir_mail_vfuncs = {
	index_mail_close,
	index_mail_free,
	index_mail_set_seq,
	index_mail_set_uid,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_keyword_indexes,
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
	maildir_mail_get_special,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_expunge,
	maildir_mail_set_cache_corrupted,
	index_mail_get_index_mail
};
