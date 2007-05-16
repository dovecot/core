/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "index-mail.h"
#include "cydir-storage.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static const char *cydir_mail_get_path(struct mail *mail)
{
	const char *dir;

	dir = mailbox_list_get_path(mail->box->storage->list, mail->box->name,
				    MAILBOX_LIST_PATH_TYPE_MAILBOX);
	return t_strdup_printf("%s/%u.", dir, mail->uid);
}

static int cydir_mail_stat(struct mail *mail, struct stat *st_r)
{
	const char *path;

	path = cydir_mail_get_path(mail);
	if (stat(path, st_r) < 0) {
		if (errno == ENOENT)
			mail_set_expunged(mail);
		else {
			mail_storage_set_critical(mail->box->storage,
						  "stat(%s) failed: %m", path);
		}
		return -1;
	}
	return 0;
}

static time_t cydir_mail_get_received_date(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct stat st;
	uint32_t t;

	(void)index_mail_get_received_date(_mail);
	if (data->received_date != (time_t)-1)
		return data->received_date;

	if (cydir_mail_stat(_mail, &st) < 0)
		return (time_t)-1;

	data->received_date = t = st.st_mtime;
	index_mail_cache_add(mail, MAIL_CACHE_RECEIVED_DATE, &t, sizeof(t));
	return data->received_date;
}

static time_t cydir_mail_get_save_date(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct stat st;
	uint32_t t;

	(void)index_mail_get_save_date(_mail);
	if (data->save_date != (time_t)-1)
		return data->save_date;

	if (cydir_mail_stat(_mail, &st) < 0)
		return (time_t)-1;

	data->save_date = t = st.st_ctime;
	index_mail_cache_add(mail, MAIL_CACHE_SAVE_DATE, &t, sizeof(t));
	return data->save_date;
}

static uoff_t cydir_mail_get_physical_size(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct stat st;

	(void)index_mail_get_physical_size(_mail);
	if (data->physical_size != (uoff_t)-1)
		return data->physical_size;

	if (cydir_mail_stat(_mail, &st) < 0)
		return (time_t)-1;

	data->physical_size = data->virtual_size = st.st_size;
	index_mail_cache_add(mail, MAIL_CACHE_PHYSICAL_FULL_SIZE,
			     &data->physical_size, sizeof(data->physical_size));
	return data->physical_size;
}

static struct istream *
cydir_mail_get_stream(struct mail *_mail, struct message_size *hdr_size,
		      struct message_size *body_size)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	const char *path;
	int fd;

	if (mail->data.stream == NULL) {
		path = cydir_mail_get_path(_mail);
		fd = open(path, O_RDONLY);
		if (fd == -1) {
			if (errno == ENOENT)
				mail_set_expunged(_mail);
			else {
				mail_storage_set_critical(_mail->box->storage,
					"open(%s) failed: %m", path);
			}
			return NULL;
		}
		mail->data.stream =
			i_stream_create_file(fd, default_pool,
					     MAIL_READ_BLOCK_SIZE, TRUE);
	}

	return index_mail_init_stream(mail, hdr_size, body_size);
}

struct mail_vfuncs cydir_mail_vfuncs = {
	index_mail_free,
	index_mail_set_seq,
	index_mail_set_uid,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_parts,
	index_mail_get_date,
	cydir_mail_get_received_date,
	cydir_mail_get_save_date,
	cydir_mail_get_physical_size, /* physical = virtual in our case */
	cydir_mail_get_physical_size,
	index_mail_get_first_header,
	index_mail_get_headers,
	index_mail_get_header_stream,
	cydir_mail_get_stream,
	index_mail_get_special,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_expunge
};
