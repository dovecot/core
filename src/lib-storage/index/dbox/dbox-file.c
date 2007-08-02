/* Copyright (C) 2005-2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
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
	*file_seq_r = *((const uint32_t *)data1);
	*offset_r = *((const uint64_t *)data2);
	return 1;
}

void dbox_file_close(struct dbox_file *file)
{
	if (array_is_created(&file->file_idx_keywords)) {
		array_free(&file->idx_file_keywords);
		array_free(&file->file_idx_keywords);
	}

	if (file->input != NULL)
		i_stream_destroy(&file->input);
	if (file->fd != -1) {
		if (close(file->fd) < 0)
			i_error("close(dbox) failed: %m");
	}
	i_free(file->seeked_keywords);
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

	/* read the header */
	i_stream_seek(file->input, offset);
	(void)i_stream_read_data(file->input, &data, &size,
				 file->mail_header_size-1);
	if (size < file->mail_header_size) {
		if (file->input->stream_errno == 0)
			return 0;

		errno = file->input->stream_errno;
		mail_storage_set_critical(&mbox->storage->storage,
					  "read(%s) failed: %m", file->path);
		return -1;
	}

	memcpy(&file->seeked_mail_header, data,
	       sizeof(file->seeked_mail_header));
	/* @UNSAFE */
	memcpy(file->seeked_keywords, data + sizeof(file->seeked_mail_header),
	       file->keyword_count);
	file->seeked_offset = offset;

	/* parse the header */
	hdr = &file->seeked_mail_header;
	file->seeked_mail_size =
		hex2dec(hdr->mail_size_hex, sizeof(hdr->mail_size_hex));
	file->seeked_uid = hex2dec(hdr->uid_hex, sizeof(hdr->uid_hex));

	if (memcmp(hdr->magic, DBOX_MAIL_HEADER_MAGIC,
		   sizeof(hdr->magic)) != 0) {
		mail_storage_set_critical(&mbox->storage->storage,
			"Corrupted mail header at %"PRIuUOFF_T
			" in dbox file %s", offset, file->path);
		return -1;
	}
	return 1;
}

int dbox_file_seek(struct dbox_mailbox *mbox, uint32_t file_seq, uoff_t offset,
		   bool ignore_zero_uid)
{
	int ret;

	if (mbox->file != NULL && mbox->file->file_seq != file_seq) {
		dbox_file_close(mbox->file);
		mbox->file = NULL;
	}

	if (mbox->file == NULL) {
		mbox->file = i_new(struct dbox_file, 1);
		mbox->file->file_seq = file_seq;
		mbox->file->fd = -1;

		mbox->file->path =
			i_strdup_printf("%s/"DBOX_MAIL_FILE_FORMAT,
					mbox->path, file_seq);
	}

	if (mbox->file->fd == -1) {
		mbox->file->fd = open(mbox->file->path, O_RDWR);
		if (mbox->file->fd == -1) {
			if (errno == ENOENT)
				return 0;
			mail_storage_set_critical(&mbox->storage->storage,
				"open(%s) failed: %m", mbox->file->path);
			return -1;
		}

		mbox->file->input =
			i_stream_create_fd(mbox->file->fd, 65536, FALSE);

		if (dbox_file_read_header(mbox, mbox->file) < 0)
			return -1;
	} else {
		/* make sure we're not caching outdated data */
		i_stream_sync(mbox->file->input);
	}

	if (offset == 0)
		offset = mbox->file->header_size;

	if ((ret = dbox_file_read_mail_header(mbox, mbox->file, offset)) <= 0)
		return ret;

	if (mbox->file->seeked_mail_size == 0 ||
	    (mbox->file->seeked_uid == 0 && !ignore_zero_uid)) {
		/* could be legitimately just not written yet. we're at EOF. */
		return 0;
	}
	return 1;
}

int dbox_file_seek_next_nonexpunged(struct dbox_mailbox *mbox)
{
	const struct dbox_mail_header *hdr;
	uoff_t offset;
	int ret;

	for (;;) {
		offset = mbox->file->seeked_offset +
			mbox->file->mail_header_size +
			mbox->file->seeked_mail_size;

		ret = dbox_file_seek(mbox, mbox->file->file_seq, offset, FALSE);
		if (ret <= 0)
			return ret;

		hdr = &mbox->file->seeked_mail_header;
		if (hdr->expunged != '1') {
			/* non-expunged mail found */
			break;
		}
	}

	return 1;
}

void dbox_file_header_init(struct dbox_file_header *hdr)
{
	uint16_t base_header_size = sizeof(*hdr);
	uint32_t header_size =
		base_header_size + DBOX_KEYWORD_NAMES_RESERVED_SPACE;
	uint32_t append_offset = header_size;
	uint16_t keyword_count = DBOX_KEYWORD_COUNT;
	uint16_t mail_header_size =
		sizeof(struct dbox_mail_header) + keyword_count;
	uint32_t create_time = ioloop_time;

	memset(hdr, '0', sizeof(*hdr));
	DEC2HEX(hdr->base_header_size_hex, base_header_size);
	DEC2HEX(hdr->header_size_hex, header_size);
	DEC2HEX(hdr->append_offset_hex, append_offset);
	DEC2HEX(hdr->create_time_hex, create_time);
	DEC2HEX(hdr->mail_header_size_hex, mail_header_size);
	DEC2HEX(hdr->keyword_list_offset_hex, base_header_size);
	DEC2HEX(hdr->keyword_count_hex, keyword_count);
}

int dbox_file_header_parse(struct dbox_mailbox *mbox, struct dbox_file *file,
			   const struct dbox_file_header *hdr)
{
	file->hdr = *hdr;

	file->base_header_size = hex2dec(hdr->base_header_size_hex,
					 sizeof(hdr->base_header_size_hex));
	file->header_size = hex2dec(hdr->header_size_hex,
				    sizeof(hdr->header_size_hex));
	file->append_offset = hex2dec(hdr->append_offset_hex,
				      sizeof(hdr->append_offset_hex));
	file->create_time = hex2dec(hdr->create_time_hex,
				    sizeof(hdr->create_time_hex));
	file->mail_header_size = hex2dec(hdr->mail_header_size_hex,
					 sizeof(hdr->mail_header_size_hex));
	file->mail_header_align =
		hex2dec(hdr->mail_header_align_hex,
			sizeof(hdr->mail_header_align_hex));
	file->keyword_count = hex2dec(hdr->keyword_count_hex,
				      sizeof(hdr->keyword_count_hex));
	file->keyword_list_offset =
		hex2dec(hdr->keyword_list_offset_hex,
			sizeof(hdr->keyword_list_offset_hex));

	if (file->base_header_size == 0 ||
	    file->header_size < file->base_header_size ||
	    file->append_offset < file->header_size ||
            file->keyword_list_offset < file->base_header_size ||
	    file->mail_header_size < sizeof(struct dbox_mail_header) ||
	    file->keyword_count > file->mail_header_size -
	    sizeof(struct dbox_mail_header)) {
		mail_storage_set_critical(&mbox->storage->storage,
			"dbox %s: broken file header", file->path);
		return -1;
	}

	i_free(file->seeked_keywords);
	file->seeked_keywords = file->keyword_count == 0 ? NULL :
		i_malloc(file->keyword_count);
	return 0;
}

int dbox_file_read_header(struct dbox_mailbox *mbox, struct dbox_file *file)
{
	struct dbox_file_header hdr;
	const unsigned char *data;
	size_t size;

	/* read the file header */
	i_stream_seek(file->input, 0);
	(void)i_stream_read_data(file->input, &data, &size, sizeof(hdr)-1);
	if (size < sizeof(hdr)) {
		if (file->input->stream_errno != 0) {
			errno = file->input->stream_errno;
			mail_storage_set_critical(&mbox->storage->storage,
				"read(%s) failed: %m", file->path);
			return -1;
		}

		mail_storage_set_critical(&mbox->storage->storage,
			"dbox %s: unexpected end of file", file->path);
		return -1;
	}
	memcpy(&hdr, data, sizeof(hdr));

	/* parse the header */
	if (dbox_file_header_parse(mbox, file, &hdr) < 0)
		return -1;

	/* keywords may not be up to date anymore */
	if (array_is_created(&file->idx_file_keywords)) {
		array_free(&file->idx_file_keywords);
		array_free(&file->file_idx_keywords);
	}
	return 0;
}

int dbox_file_write_header(struct dbox_mailbox *mbox, struct dbox_file *file)
{
	struct dbox_file_header hdr;
	char buf[1024];
	int ret;

	dbox_file_header_init(&hdr);
	ret = dbox_file_header_parse(mbox, file, &hdr);
	i_assert(ret == 0);

	/* write header + LF to mark end-of-keywords list */
	if (o_stream_send(file->output, &hdr, sizeof(hdr)) < 0 ||
	    o_stream_send_str(file->output, "\n") < 0) {
		mail_storage_set_critical(&mbox->storage->storage,
			"write(%s) failed: %m", file->path);
		return -1;
	}

	/* fill the rest of the header with spaces */
	memset(buf, ' ', sizeof(buf));
	while (file->output->offset < file->header_size) {
		unsigned int size = I_MIN(sizeof(buf), file->header_size -
					  file->output->offset);

		if (o_stream_send(file->output, buf, size) < 0) {
			mail_storage_set_critical(&mbox->storage->storage,
				"write(%s) failed: %m", file->path);
			return -1;
		}
	}
	return 0;
}
