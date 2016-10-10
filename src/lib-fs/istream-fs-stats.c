/* Copyright (c) 2015-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fs-api-private.h"
#include "istream-private.h"
#include "istream-fs-stats.h"

struct fs_stats_istream {
	struct istream_private istream;
	struct fs_file *file;
};

static ssize_t
i_stream_fs_stats_read(struct istream_private *stream)
{
	struct fs_stats_istream *sstream = (struct fs_stats_istream *)stream;
	ssize_t ret;

	i_stream_seek(stream->parent, stream->parent_start_offset +
		      stream->istream.v_offset);

	ret = i_stream_read_copy_from_parent(&stream->istream);
	if (ret > 0) {
		/* count the first returned bytes as the finish time, since
		   we don't want to count the time caller spends on processing
		   this stream. (only the first fs_file_timing_end() call
		   actually does anything - the others are ignored.) */
		fs_file_timing_end(sstream->file, FS_OP_READ);
	}
	return ret;
}

struct istream *
i_stream_create_fs_stats(struct istream *input, struct fs_file *file)
{
	struct fs_stats_istream *sstream;

	sstream = i_new(struct fs_stats_istream, 1);
	sstream->file = file;
	sstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	sstream->istream.stream_size_passthrough = TRUE;
	sstream->istream.read = i_stream_fs_stats_read;
	sstream->istream.istream.blocking = input->blocking;
	sstream->istream.istream.seekable = input->seekable;
	return i_stream_create(&sstream->istream, input,
			       i_stream_get_fd(input));
}
