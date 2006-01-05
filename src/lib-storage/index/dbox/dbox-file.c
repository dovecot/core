/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "hex-dec.h"
#include "istream.h"
#include "ostream.h"
#include "read-full.h"
#include "dbox-storage.h"
#include "dbox-file.h"

int dbox_file_lookup_offset(struct dbox_mailbox *mbox,
			    struct mail_index_view *view, uint32_t seq,
			    uint32_t *file_seq_r, uoff_t *offset_r)
{
	const void *data1, *data2;
	int ret;

	ret = mail_index_lookup_ext(view, seq, mbox->dbox_file_ext_idx, &data1);
	ret = ret <= 0 ? ret :
		mail_index_lookup_ext(view, seq, mbox->dbox_offset_ext_idx,
				      &data2);
	if (ret <= 0) {
		if (ret < 0)
			mail_storage_set_index_error(&mbox->ibox);
		return ret;
	}

	if (data1 == NULL || data2 == NULL) {
		*file_seq_r = 0;
		return 1;
	}

	/* success */
	*file_seq_r = *((uint32_t *)data1);
	*offset_r = *((uint64_t *)data2);
	return 1;
}

void dbox_file_close(struct dbox_file *file)
{
	if (file->input != NULL)
		i_stream_unref(file->input);
	if (file->fd != -1) {
		if (close(file->fd) < 0)
			i_error("close(dbox) failed: %m");
	}
	i_free(file->path);
	i_free(file);
}

static int
dbox_file_read_mail_header(struct dbox_mailbox *mbox, struct dbox_file *file,
			   uoff_t offset)
{
	const struct dbox_mail_header *hdr;
	const unsigned char *data;
	size_t size;

	i_stream_seek(file->input, offset);
	(void)i_stream_read_data(file->input, &data, &size,
				 file->mail_header_size-1);
	if (size < file->mail_header_size) {
		if (file->input->stream_errno == 0)
			return 0;

		errno = file->input->stream_errno;
		mail_storage_set_critical(STORAGE(mbox->storage),
					  "read(%s) failed: %m", file->path);
		return -1;
	}
	memcpy(&file->seeked_mail_header, data,
	       sizeof(file->seeked_mail_header));
	file->seeked_offset = offset;

	hdr = &file->seeked_mail_header;
	file->seeked_mail_size =
		hex2dec(hdr->mail_size_hex, sizeof(hdr->mail_size_hex));
	file->seeked_uid = hex2dec(hdr->uid_hex, sizeof(hdr->uid_hex));

	if (memcmp(hdr->magic, DBOX_MAIL_HEADER_MAGIC,
		   sizeof(hdr->magic)) != 0) {
		mail_storage_set_critical(STORAGE(mbox->storage),
			"Corrupted mail header in dbox file %s", file->path);
		return -1;
	}
	if (file->seeked_mail_size == 0 || file->seeked_uid == 0) {
		/* could be legitimately just not written yet. we're at EOF. */
		return 0;
	}
	return 1;
}

int dbox_file_seek(struct dbox_mailbox *mbox, uint32_t file_seq, uoff_t offset)
{
	if (mbox->file != NULL && mbox->file->file_seq != file_seq) {
		dbox_file_close(mbox->file);
		mbox->file = NULL;
	}

	if (mbox->file == NULL) {
		mbox->file = i_new(struct dbox_file, 1);
		mbox->file->file_seq = file_seq;
		mbox->file->fd = -1;

		mbox->file->path =
			i_strdup_printf("%s/"DBOX_MAILDIR_NAME"/"
					DBOX_MAIL_FILE_PREFIX"%x",
					mbox->path, file_seq);
	}

	if (mbox->file->fd == -1) {
		mbox->file->fd = open(mbox->file->path, O_RDWR);
		if (mbox->file->fd == -1) {
			if (errno == ENOENT)
				return 0;
			mail_storage_set_critical(STORAGE(mbox->storage),
				"open(%s) failed: %m", mbox->file->path);
			return -1;
		}

		mbox->file->input =
			i_stream_create_file(mbox->file->fd, default_pool,
					     65536, FALSE);

		if (dbox_file_read_header(mbox, mbox->file) < 0)
			return -1;
	}

	if (offset == 0)
		offset = mbox->file->header_size;

	return dbox_file_read_mail_header(mbox, mbox->file, offset);
}

int dbox_file_seek_next_nonexpunged(struct dbox_mailbox *mbox)
{
	uoff_t offset;
	int ret;

	offset = mbox->file->seeked_offset +
		mbox->file->mail_header_size + mbox->file->seeked_mail_size;

	while ((ret = dbox_file_seek(mbox, mbox->file->file_seq, offset)) > 0) {
		if (mbox->file->seeked_mail_header.expunged != '1')
			break;

		/* marked expunged, get to next mail. */
	}
	return ret;
}

void dbox_file_header_init(struct dbox_file_header *hdr)
{
	uint16_t header_size = sizeof(*hdr);
	uint32_t append_offset = header_size;
	uint16_t mail_header_size = sizeof(struct dbox_mail_header);
	uint32_t create_time = ioloop_time;

	memset(hdr, '0', sizeof(*hdr));
	DEC2HEX(hdr->header_size_hex, header_size);
	DEC2HEX(hdr->append_offset_hex, append_offset);
	DEC2HEX(hdr->create_time_hex, create_time);
	DEC2HEX(hdr->mail_header_size_hex, mail_header_size);
	// FIXME: set keyword_count
}

int dbox_file_read_header(struct dbox_mailbox *mbox, struct dbox_file *file)
{
	struct dbox_file_header hdr;
	const unsigned char *data;
	size_t size;

	i_stream_seek(file->input, 0);
	(void)i_stream_read_data(file->input, &data, &size, sizeof(hdr)-1);
	if (size < sizeof(hdr)) {
		if (file->input->stream_errno != 0) {
			errno = file->input->stream_errno;
			mail_storage_set_critical(STORAGE(mbox->storage),
				"read(%s) failed: %m", file->path);
			return -1;
		}

		mail_storage_set_critical(STORAGE(mbox->storage),
			"dbox %s: unexpected end of file", file->path);
		return -1;
	}
	memcpy(&hdr, data, sizeof(hdr));

	/* parse the header */
	file->header_size = hex2dec(hdr.header_size_hex,
				    sizeof(hdr.header_size_hex));
	file->append_offset = hex2dec(hdr.append_offset_hex,
				      sizeof(hdr.append_offset_hex));
	file->create_time = hex2dec(hdr.create_time_hex,
				    sizeof(hdr.create_time_hex));
	file->mail_header_size = hex2dec(hdr.mail_header_size_hex,
					 sizeof(hdr.mail_header_size_hex));
	file->mail_header_padding =
		hex2dec(hdr.mail_header_padding_hex,
			sizeof(hdr.mail_header_padding_hex));
	file->keyword_count = hex2dec(hdr.keyword_count_hex,
				      sizeof(hdr.keyword_count_hex));

	if (file->header_size == 0 || file->append_offset < sizeof(hdr) ||
	    file->mail_header_size < sizeof(struct dbox_mail_header)) {
		mail_storage_set_critical(STORAGE(mbox->storage),
			"dbox %s: broken file header", file->path);
		return -1;
	}
	return 0;
}
