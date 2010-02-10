/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "hex-binary.h"
#include "mdbox-storage.h"
#include "mdbox-file.h"
#include "mdbox-map.h"
#include "mdbox-sync.h"

#include <stdlib.h>

struct dbox_mail_move {
	struct dbox_file *file;
	uint32_t offset;
};
ARRAY_DEFINE_TYPE(dbox_mail_move, struct dbox_mail_move);

static int mdbox_map_file_msg_offset_cmp(const void *p1, const void *p2)
{
	const struct dbox_map_file_msg *m1 = p1, *m2 = p2;

	if (m1->offset < m2->offset)
		return -1;
	else if (m1->offset > m2->offset)
		return 1;
	else
		return 0;
}

static int
mdbox_file_copy_metadata(struct dbox_file *file, struct ostream *output)
{
	struct dbox_metadata_header meta_hdr;
	const char *line;
	const unsigned char *data;
	size_t size;
	int ret;

	ret = i_stream_read_data(file->input, &data, &size,
				 sizeof(meta_hdr));
	if (ret <= 0) {
		i_assert(ret == -1);
		if (file->input->stream_errno == 0) {
			dbox_file_set_corrupted(file, "missing metadata");
			return 0;
		}
		mail_storage_set_critical(&file->storage->storage,
			"read(%s) failed: %m", file->cur_path);
		return -1;
	}

	memcpy(&meta_hdr, data, sizeof(meta_hdr));
	if (memcmp(meta_hdr.magic_post, DBOX_MAGIC_POST,
		   sizeof(meta_hdr.magic_post)) != 0) {
		dbox_file_set_corrupted(file, "invalid metadata magic");
		return 0;
	}
	i_stream_skip(file->input, sizeof(meta_hdr));
	if (output != NULL)
		o_stream_send(output, &meta_hdr, sizeof(meta_hdr));
	while ((line = i_stream_read_next_line(file->input)) != NULL) {
		if (*line == DBOX_METADATA_OLDV1_SPACE || *line == '\0') {
			/* end of metadata */
			break;
		}
		if (output != NULL) {
			o_stream_send_str(output, line);
			o_stream_send(output, "\n", 1);
		}
	}
	if (line == NULL) {
		dbox_file_set_corrupted(file, "missing end-of-metadata line");
		return 0;
	}
	if (output != NULL)
		o_stream_send(output, "\n", 1);
	return 1;
}

int mdbox_file_purge(struct dbox_file *file)
{
	struct mdbox_storage *dstorage = (struct mdbox_storage *)file->storage;
	struct dbox_file_append_context *out_file_append;
	struct stat st;
	struct istream *input;
	struct ostream *output = NULL;
	struct dbox_map_append_context *append_ctx;
	ARRAY_TYPE(dbox_map_file_msg) msgs_arr;
	const struct dbox_map_file_msg *msgs;
	ARRAY_TYPE(seq_range) expunged_map_uids;
	ARRAY_TYPE(uint32_t) copied_map_uids;
	unsigned int i, count;
	uoff_t offset, physical_size, msg_size;
	enum dbox_map_append_flags append_flags = 0;
	int ret;

	if ((ret = dbox_file_try_lock(file)) <= 0)
		return ret;

	/* make sure the file still exists. another process may have already
	   deleted it. */
	if (stat(file->cur_path, &st) < 0) {
		dbox_file_unlock(file);
		if (errno == ENOENT)
			return 0;

		mail_storage_set_critical(&file->storage->storage,
			"stat(%s) failed: %m", file->cur_path);
		return -1;
	}

	if (dstorage->set->mdbox_altmove > 0 &&
	    st.st_mtime + (time_t)dstorage->set->mdbox_altmove < ioloop_time &&
	    dstorage->alt_storage_dir != NULL)
		append_flags |= DBOX_MAP_APPEND_FLAG_ALT;

	i_array_init(&msgs_arr, 128);
	if (dbox_map_get_file_msgs(dstorage->map,
				   ((struct mdbox_file *)file)->file_id,
				   &msgs_arr) < 0) {
		array_free(&msgs_arr);
		dbox_file_unlock(file);
		return -1;
	}
	/* sort messages by their offset */
	array_sort(&msgs_arr, mdbox_map_file_msg_offset_cmp);

	msgs = array_get(&msgs_arr, &count);
	append_ctx = dbox_map_append_begin(dstorage->map, append_flags);
	i_array_init(&copied_map_uids, I_MIN(count, 1));
	i_array_init(&expunged_map_uids, I_MIN(count, 1));
	offset = file->file_header_size;
	for (i = 0; i < count; i++) {
		if ((ret = dbox_file_get_mail_stream(file, offset,
						     &physical_size,
						     NULL)) <= 0)
			break;
		msg_size = file->msg_header_size + physical_size;

		if (msgs[i].offset != offset) {
			/* map doesn't match file's actual contents */
			dbox_file_set_corrupted(file,
				"purging found mismatched offsets "
				"(%"PRIuUOFF_T" vs %u, %u/%u)",
				offset, msgs[i].offset, i, count);
			ret = 0;
			break;
		}

		if (msgs[i].refcount == 0) {
			seq_range_array_add(&expunged_map_uids, 0,
					    msgs[i].map_uid);
			output = NULL;
		} else {
			/* non-expunged message. write it to output file. */
			if (dbox_map_append_next(append_ctx, physical_size,
						 &out_file_append, &output) < 0) {
				ret = -1;
				break;
			}
			i_assert(file != out_file_append->file);

			i_stream_seek(file->input, offset);
			input = i_stream_create_limit(file->input, msg_size);
			ret = o_stream_send_istream(output, input);
			if (input->stream_errno != 0) {
				errno = input->stream_errno;
				mail_storage_set_critical(&file->storage->storage,
					"read(%s) failed: %m",
					file->cur_path);
				i_stream_unref(&input);
				break;
			}
			i_stream_unref(&input);
			if (output->stream_errno != 0) {
				errno = output->stream_errno;
				mail_storage_set_critical(&file->storage->storage,
					"write(%s) failed: %m",
					out_file_append->file->cur_path);
				break;
			}
			i_assert(ret == (off_t)msg_size);
		}

		/* copy/skip metadata */
		i_stream_seek(file->input, offset + msg_size);
		if ((ret = mdbox_file_copy_metadata(file, output)) <= 0)
			break;

		if (output != NULL) {
			dbox_map_append_finish(append_ctx);
			array_append(&copied_map_uids, &msgs[i].map_uid, 1);
		}
		offset = file->input->v_offset;
	}
	if (offset != (uoff_t)st.st_size && ret > 0) {
		/* file has more messages than what map tells us */
		dbox_file_set_corrupted(file,
			"more messages available than in map "
			"(%"PRIuUOFF_T" < %"PRIuUOFF_T")", offset, st.st_size);
		ret = 0;
	}
	array_free(&msgs_arr); msgs = NULL;

	if (ret <= 0) {
		dbox_map_append_free(&append_ctx);
		dbox_file_unlock(file);
		ret = -1;
	} else {
		/* assign new file_id + offset to moved messages */
		if (dbox_map_append_move(append_ctx, &copied_map_uids,
					 &expunged_map_uids) < 0 ||
		    dbox_map_append_commit(append_ctx) < 0) {
			dbox_file_unlock(file);
			ret = -1;
		} else {
			ret = 1;
			(void)dbox_file_unlink(file);
		}
		dbox_map_append_free(&append_ctx);
	}
	array_free(&copied_map_uids);
	array_free(&expunged_map_uids);
	return ret;
}
