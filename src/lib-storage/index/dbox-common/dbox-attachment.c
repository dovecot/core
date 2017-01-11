/* Copyright (c) 2010-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "dbox-file.h"
#include "dbox-save.h"
#include "dbox-attachment.h"

void dbox_attachment_save_write_metadata(struct mail_save_context *ctx,
					 string_t *str)
{
	const ARRAY_TYPE(mail_attachment_extref) *extrefs;

	extrefs = index_attachment_save_get_extrefs(ctx);
	if (extrefs == NULL || array_count(extrefs) == 0)
		return;

	str_append_c(str, DBOX_METADATA_EXT_REF);
	index_attachment_append_extrefs(str, extrefs);
	str_append_c(str, '\n');
}

static int
dbox_attachment_file_get_stream_from(struct dbox_file *file,
				     const char *ext_refs,
				     struct istream **stream,
				     const char **error_r)
{
	const char *path_suffix;
	uoff_t msg_size;

	if (*file->storage->attachment_dir == '\0') {
		mail_storage_set_critical(&file->storage->storage,
			"%s contains references to external attachments, "
			"but mail_attachment_dir is unset", file->cur_path);
		return -1;
	}

	msg_size = dbox_file_get_plaintext_size(file);
	path_suffix = file->storage->v.get_attachment_path_suffix(file);
	if (index_attachment_stream_get(file->storage->attachment_fs,
					file->storage->attachment_dir,
					path_suffix, stream, msg_size,
					ext_refs, error_r) < 0)
		return 0;
	return 1;
}

int dbox_attachment_file_get_stream(struct dbox_file *file,
				    struct istream **stream)
{
	const char *ext_refs, *error;
	int ret;

	/* need to read metadata in case there are external references */
	if ((ret = dbox_file_metadata_read(file)) <= 0)
		return ret;

	i_stream_seek(file->input, file->cur_offset + file->msg_header_size);

	ext_refs = dbox_file_metadata_get(file, DBOX_METADATA_EXT_REF);
	if (ext_refs == NULL)
		return 1;

	/* we have external references. */
	T_BEGIN {
		ret = dbox_attachment_file_get_stream_from(file, ext_refs,
							   stream, &error);
		if (ret == 0) {
			dbox_file_set_corrupted(file,
				"Corrupted ext-refs metadata %s: %s",
				ext_refs, error);
		}
	} T_END;
	return ret;
}
