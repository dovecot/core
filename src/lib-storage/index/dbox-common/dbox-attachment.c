/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "istream-attachment-connector.h"
#include "dbox-file.h"
#include "dbox-save.h"
#include "dbox-attachment.h"

enum dbox_attachment_decode_option {
	DBOX_ATTACHMENT_DECODE_OPTION_NONE = '-',
	DBOX_ATTACHMENT_DECODE_OPTION_BASE64 = 'B',
	DBOX_ATTACHMENT_DECODE_OPTION_CRLF = 'C'
};

void dbox_attachment_save_write_metadata(struct mail_save_context *ctx,
					 string_t *str)
{
	const ARRAY_TYPE(mail_attachment_extref) *extrefs;
	const struct mail_attachment_extref *extref;
	bool add_space = FALSE;
	unsigned int startpos;

	extrefs = index_attachment_save_get_extrefs(ctx);
	if (extrefs == NULL || array_count(extrefs) == 0)
		return;

	str_append_c(str, DBOX_METADATA_EXT_REF);
	array_foreach(extrefs, extref) {
		if (!add_space)
			add_space = TRUE;
		else
			str_append_c(str, ' ');
		str_printfa(str, "%"PRIuUOFF_T" %"PRIuUOFF_T" ",
			    extref->start_offset, extref->size);

		startpos = str_len(str);
		if (extref->base64_have_crlf)
			str_append_c(str, DBOX_ATTACHMENT_DECODE_OPTION_CRLF);
		if (extref->base64_blocks_per_line > 0) {
			str_printfa(str, "%c%u",
				    DBOX_ATTACHMENT_DECODE_OPTION_BASE64,
				    extref->base64_blocks_per_line * 4);
		}
		if (startpos == str_len(str)) {
			/* make it clear there are no options */
			str_append_c(str, DBOX_ATTACHMENT_DECODE_OPTION_NONE);
		}
		str_append_c(str, ' ');
		str_append(str, extref->path);
	}
	str_append_c(str, '\n');
}

static bool
parse_extref_decode_options(const char *str,
			    struct mail_attachment_extref *extref)
{
	unsigned int num;

	if (*str == DBOX_ATTACHMENT_DECODE_OPTION_NONE)
		return str[1] == '\0';

	while (*str != '\0') {
		switch (*str) {
		case DBOX_ATTACHMENT_DECODE_OPTION_BASE64:
			str++; num = 0;
			while (*str >= '0' && *str <= '9') {
				num = num*10 + (*str-'0');
				str++;
			}
			if (num == 0 || num % 4 != 0)
				return FALSE;

			extref->base64_blocks_per_line = num/4;
			break;
		case DBOX_ATTACHMENT_DECODE_OPTION_CRLF:
			extref->base64_have_crlf = TRUE;
			str++;
			break;
		default:
			return FALSE;
		}
	}
	return TRUE;
}

static bool
dbox_attachment_parse_extref_real(const char *line, pool_t pool,
				  ARRAY_TYPE(mail_attachment_extref) *extrefs)
{
	struct mail_attachment_extref extref;
	const char *const *args;
	unsigned int i, len;
	uoff_t last_voffset;

	args = t_strsplit(line, " ");
	len = str_array_length(args);
	if ((len % 4) != 0)
		return FALSE;

	last_voffset = 0;
	for (i = 0; args[i] != NULL; i += 4) {
		const char *start_offset_str = args[i+0];
		const char *size_str = args[i+1];
		const char *decode_options = args[i+2];
		const char *path = args[i+3];

		memset(&extref, 0, sizeof(extref));
		if (str_to_uoff(start_offset_str, &extref.start_offset) < 0 ||
		    str_to_uoff(size_str, &extref.size) < 0 ||
		    extref.start_offset < last_voffset ||
		    !parse_extref_decode_options(decode_options, &extref))
			return FALSE;

		last_voffset += extref.size +
			(extref.start_offset - last_voffset);

		extref.path = p_strdup(pool, path);
		array_append(extrefs, &extref, 1);
	}
	return TRUE;
}

bool dbox_attachment_parse_extref(const char *line, pool_t pool,
				  ARRAY_TYPE(mail_attachment_extref) *extrefs)
{
	bool ret;

	T_BEGIN {
		ret = dbox_attachment_parse_extref_real(line, pool, extrefs);
	} T_END;
	return ret;
}

static int
dbox_attachment_file_get_stream_from(struct dbox_file *file,
				     const char *ext_refs,
				     struct istream **stream,
				     const char **error_r)
{
	ARRAY_TYPE(mail_attachment_extref) extrefs_arr;
	const struct mail_attachment_extref *extref;
	struct istream_attachment_connector *conn;
	struct istream *input;
	const char *path, *path_suffix;
	uoff_t msg_size;
	int ret;

	*error_r = NULL;

	if (*file->storage->attachment_dir == '\0') {
		mail_storage_set_critical(&file->storage->storage,
			"%s contains references to external attachments, "
			"but mail_attachment_dir is unset", file->cur_path);
		return -1;
	}

	t_array_init(&extrefs_arr, 16);
	if (!dbox_attachment_parse_extref_real(ext_refs, pool_datastack_create(),
					       &extrefs_arr)) {
		*error_r = "Broken ext-refs string";
		return 0;
	}
	msg_size = dbox_file_get_plaintext_size(file);
	conn = istream_attachment_connector_begin(*stream, msg_size);

	path_suffix = file->storage->v.get_attachment_path_suffix(file);
	array_foreach(&extrefs_arr, extref) {
		path = t_strdup_printf("%s/%s%s", file->storage->attachment_dir,
				       extref->path, path_suffix);
		input = i_stream_create_file(path, IO_BLOCK_SIZE);

		ret = istream_attachment_connector_add(conn, input,
					extref->start_offset, extref->size,
					extref->base64_blocks_per_line,
					extref->base64_have_crlf, error_r);
		i_stream_unref(&input);
		if (ret < 0) {
			istream_attachment_connector_abort(&conn);
			return 0;
		}
	}

	input = istream_attachment_connector_finish(&conn);
	i_stream_unref(stream);
	*stream = input;
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
