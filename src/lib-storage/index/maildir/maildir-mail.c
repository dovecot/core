/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "index-mail.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static int do_open(struct index_mailbox *ibox, const char *path, void *context)
{
	int *fd = context;

	*fd = open(path, O_RDONLY);
	if (*fd != -1)
		return 1;
	if (errno == ENOENT)
		return 0;

	mail_storage_set_critical(ibox->box.storage,
				  "open(%s) failed: %m", path);
	return -1;
}

static int do_stat(struct index_mailbox *ibox, const char *path, void *context)
{
	struct stat *st = context;

	if (stat(path, st) == 0)
		return 1;
	if (errno == ENOENT)
		return 0;

	mail_storage_set_critical(ibox->box.storage,
				  "stat(%s) failed: %m", path);
	return -1;
}

static struct istream *
maildir_open_mail(struct index_mailbox *ibox, uint32_t uid, int *deleted)
{
	int fd;

	*deleted = FALSE;

	fd = -1;
	if (maildir_file_do(ibox, uid, do_open, &fd) < 0)
		return NULL;

	if (fd == -1) {
		*deleted = TRUE;
		return NULL;
	}

	if (ibox->mail_read_mmaped) {
		return i_stream_create_mmap(fd, default_pool,
					    MAIL_MMAP_BLOCK_SIZE, 0, 0, TRUE);
	} else {
		return i_stream_create_file(fd, default_pool,
					    MAIL_READ_BLOCK_SIZE, TRUE);
	}
}

static time_t maildir_mail_get_received_date(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	struct stat st;
	int fd;

	(void)index_mail_get_received_date(_mail);
	if (data->received_date != (time_t)-1)
		return data->received_date;

	if (data->open_mail && data->stream == NULL) {
		/* we're going to open the mail anyway */
		(void)_mail->get_stream(_mail, NULL, NULL);
	}

	if (data->stream != NULL) {
		fd = i_stream_get_fd(data->stream);
		i_assert(fd != -1);

		if (fstat(fd, &st) < 0) {
			mail_storage_set_critical(mail->ibox->box.storage,
						  "fstat(maildir) failed: %m");
			return (time_t)-1;
		}
	} else {
		if (maildir_file_do(mail->ibox, mail->mail.uid,
				    do_stat, &st) <= 0)
			return (time_t)-1;
	}

	data->received_date = st.st_mtime;
	mail_cache_add(mail->trans->cache_trans, mail->data.seq,
		       MAIL_CACHE_RECEIVED_DATE,
		       &data->received_date, sizeof(data->received_date));
	return data->received_date;
}

static uoff_t maildir_mail_get_virtual_size(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	const char *fname, *p;
	uoff_t virtual_size;
        enum maildir_uidlist_rec_flag flags;

	if (data->virtual_size != (uoff_t)-1)
		return data->virtual_size;

	if ((mail->wanted_fields & MAIL_FETCH_VIRTUAL_SIZE) == 0) {
		data->virtual_size = index_mail_get_cached_virtual_size(mail);
		if (data->virtual_size != (uoff_t)-1)
			return data->virtual_size;
	}

	fname = maildir_uidlist_lookup(mail->ibox->uidlist,
				       mail->mail.uid, &flags);
	if (fname == NULL)
		return (uoff_t)-1;

	/* size can be included in filename */
	p = strstr(fname, ",W=");
	if (p != NULL) {
		p += 3;
		virtual_size = 0;
		while (*p >= '0' && *p <= '9') {
			virtual_size = virtual_size * 10 + (*p - '0');
			p++;
		}

		if (*p == ':' || *p == ',' || *p == '\0') {
			mail_cache_add(mail->trans->cache_trans, mail->data.seq,
				       MAIL_CACHE_VIRTUAL_FULL_SIZE,
				       &virtual_size, sizeof(virtual_size));
			return virtual_size;
		}
	}

	return index_mail_get_virtual_size(_mail);
}

static const char *
maildir_mail_get_special(struct mail *_mail, enum mail_fetch_field field)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	enum maildir_uidlist_rec_flag flags;
	const char *fname, *end;

	if (field == MAIL_FETCH_UIDL_FILE_NAME) {
	    	fname = maildir_uidlist_lookup(mail->ibox->uidlist,
					       mail->mail.uid, &flags);
		end = strchr(fname, ':');
		return end == NULL ? fname : t_strdup_until(fname, end);
	}

	return index_mail_get_special(_mail, field);
}
							
static uoff_t maildir_mail_get_physical_size(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct stat st;
	const char *fname, *p;
	uoff_t size;
	enum maildir_uidlist_rec_flag flags;

	size = index_mail_get_physical_size(_mail);
	if (size != (uoff_t)-1)
		return size;

	fname = maildir_uidlist_lookup(mail->ibox->uidlist,
				       mail->mail.uid, &flags);
	if (fname == NULL)
		return (uoff_t)-1;

	/* size can be included in filename */
	p = strstr(fname, ",S=");
	if (p != NULL) {
		p += 3;
		size = 0;
		while (*p >= '0' && *p <= '9') {
			size = size * 10 + (*p - '0');
			p++;
		}

		if (*p != ':' && *p != ',' && *p != '\0')
			size = (uoff_t)-1;
	}

	if (size == (uoff_t)-1) {
		if (maildir_file_do(mail->ibox, mail->mail.uid,
				    do_stat, &st) <= 0)
			return (uoff_t)-1;
		size = st.st_size;
	}

	mail_cache_add(mail->trans->cache_trans, mail->data.seq,
		       MAIL_CACHE_PHYSICAL_FULL_SIZE, &size, sizeof(size));
	data->physical_size = size;
	return size;

}

static struct istream *maildir_mail_get_stream(struct mail *_mail,
					       struct message_size *hdr_size,
					       struct message_size *body_size)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	int deleted;

	if (data->stream == NULL) {
		data->stream = maildir_open_mail(mail->ibox, mail->mail.uid,
						 &deleted);
		if (data->stream == NULL) {
			data->deleted = deleted;
			return NULL;
		}
	}

	return index_mail_init_stream(mail, hdr_size, body_size);
}

struct mail maildir_mail = {
	0, 0, 0, 0, 0, 0,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_parts,
	maildir_mail_get_received_date,
	index_mail_get_date,
	maildir_mail_get_virtual_size,
	maildir_mail_get_physical_size,
	index_mail_get_header,
	index_mail_get_headers,
	maildir_mail_get_stream,
	maildir_mail_get_special,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_expunge
};
