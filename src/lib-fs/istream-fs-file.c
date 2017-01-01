/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "fs-api-private.h"
#include "istream-fs-file.h"

struct fs_file_istream {
	struct istream_private istream;
	struct fs_file *file;
};

static void i_stream_fs_file_close(struct iostream_private *stream,
				   bool close_parent ATTR_UNUSED)
{
	struct fs_file_istream *fstream = (struct fs_file_istream *)stream;

	if (fstream->istream.parent != NULL)
		i_stream_destroy(&fstream->istream.parent);
	fs_file_deinit(&fstream->file);
}

static ssize_t i_stream_fs_file_read(struct istream_private *stream)
{
	struct fs_file_istream *fstream = (struct fs_file_istream *)stream;
	struct istream *input;

	if (fstream->istream.parent == NULL) {
		input = fs_read_stream(fstream->file,
			i_stream_get_max_buffer_size(&stream->istream));
		i_stream_init_parent(stream, input);
		i_stream_unref(&input);
	}

	i_stream_seek(stream->parent, stream->parent_start_offset +
		      stream->istream.v_offset);
	return i_stream_read_copy_from_parent(&stream->istream);
}

struct istream *
i_stream_create_fs_file(struct fs_file **file, size_t max_buffer_size)
{
	struct fs_file_istream *fstream;
	struct istream *input;

	fstream = i_new(struct fs_file_istream, 1);
	fstream->file = *file;
	fstream->istream.iostream.close = i_stream_fs_file_close;
	fstream->istream.max_buffer_size = max_buffer_size;
	fstream->istream.read = i_stream_fs_file_read;
	fstream->istream.stream_size_passthrough = TRUE;

	fstream->istream.istream.blocking =
		((*file)->flags & FS_OPEN_FLAG_ASYNC) == 0;
	fstream->istream.istream.seekable =
		((*file)->flags & FS_OPEN_FLAG_SEEKABLE) != 0;

	input = i_stream_create(&fstream->istream, NULL, -1);
	i_stream_set_name(input, fs_file_path(*file));
	*file = NULL;
	return input;
}
