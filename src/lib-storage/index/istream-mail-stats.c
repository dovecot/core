/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage-private.h"
#include "istream-internal.h"
#include "istream-mail-stats.h"

struct mail_stats_istream {
	struct istream_private istream;

	struct mail_private *mail;
	unsigned int files_read_increased:1;
};

static ssize_t
i_stream_mail_stats_read_mail_stats(struct istream_private *stream)
{
	struct mail_stats_istream *mstream =
		(struct mail_stats_istream *)stream;
	ssize_t ret;

	i_stream_seek(stream->parent, stream->parent_start_offset +
		      stream->istream.v_offset);

	ret = i_stream_read_copy_from_parent(&stream->istream);
	if (ret > 0) {
		mstream->mail->stats_files_read_bytes += ret;
		if (!mstream->files_read_increased) {
			mstream->files_read_increased = TRUE;
			mstream->mail->stats_files_read_count++;
		}
	}
	return ret;
}

static void
i_stream_mail_stats_seek(struct istream_private *stream,
			 uoff_t v_offset, bool mark ATTR_UNUSED)
{
	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
}

static const struct stat *
i_stream_mail_stats_stat(struct istream_private *stream, bool exact)
{
	return i_stream_stat(stream->parent, exact);
}

struct istream *i_stream_create_mail_stats_counter(struct mail_private *mail,
						   struct istream *input)
{
	struct mail_stats_istream *mstream;

	mstream = i_new(struct mail_stats_istream, 1);
	mstream->mail = mail;
	mstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	mstream->istream.parent = input;
	mstream->istream.read = i_stream_mail_stats_read_mail_stats;
	mstream->istream.seek = i_stream_mail_stats_seek;
	mstream->istream.stat = i_stream_mail_stats_stat;

	mstream->istream.istream.blocking = input->blocking;
	mstream->istream.istream.seekable = input->seekable;
	return i_stream_create(&mstream->istream, input,
			       i_stream_get_fd(input));
}
