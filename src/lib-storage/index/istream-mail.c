/* Copyright (c) 2009-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage-private.h"
#include "istream-private.h"
#include "index-mail.h"
#include "istream-mail.h"

struct mail_istream {
	struct istream_private istream;

	struct mail *mail;
	uoff_t expected_size;
	bool files_read_increased:1;
	bool input_has_body:1;
};

static bool i_stream_mail_try_get_cached_size(struct mail_istream *mstream)
{
	struct mail *mail = mstream->mail;
	enum mail_lookup_abort orig_lookup_abort;

	if (mstream->expected_size != (uoff_t)-1)
		return TRUE;

	orig_lookup_abort = mail->lookup_abort;
	mail->lookup_abort = MAIL_LOOKUP_ABORT_NOT_IN_CACHE;
	if (mail_get_physical_size(mail, &mstream->expected_size) < 0)
		mstream->expected_size = (uoff_t)-1;
	mail->lookup_abort = orig_lookup_abort;
	return mstream->expected_size != (uoff_t)-1;
}

static const char *
i_stream_mail_get_cached_mail_id(struct mail_istream *mstream)
{
	static const char *headers[] = {
		"Message-Id",
		"Date",
		"Subject"
	};
	struct mail *mail = mstream->mail;
	enum mail_lookup_abort orig_lookup_abort;
	const char *value, *ret = "";
	unsigned int i;

	orig_lookup_abort = mail->lookup_abort;
	mail->lookup_abort = MAIL_LOOKUP_ABORT_NOT_IN_CACHE;
	for (i = 0; i < N_ELEMENTS(headers); i++) {
		if (mail_get_first_header(mail, headers[i], &value) > 0) {
			ret = t_strdup_printf("%s=%s", headers[i], value);
			break;
		}
	}
	mail->lookup_abort = orig_lookup_abort;
	return ret;
}

static void
i_stream_mail_set_size_corrupted(struct mail_istream *mstream, size_t size)
{
	uoff_t cur_size = mstream->istream.istream.v_offset + size;
	const char *str, *mail_id;
	char chr;

	if (mstream->expected_size < cur_size) {
		str = "smaller";
		chr = '<';
	} else {
		str = "larger";
		chr = '>';
	}

	mail_id = i_stream_mail_get_cached_mail_id(mstream);
	if (mail_id[0] != '\0')
		mail_id = t_strconcat(", cached ", mail_id, NULL);
	io_stream_set_error(&mstream->istream.iostream,
		"Cached message size %s than expected "
		"(%"PRIuUOFF_T" %c %"PRIuUOFF_T", box=%s, UID=%u%s)", str,
		mstream->expected_size, chr, cur_size,
		mailbox_get_vname(mstream->mail->box),
		mstream->mail->uid, mail_id);
	mail_set_cache_corrupted_reason(mstream->mail, MAIL_FETCH_PHYSICAL_SIZE,
		t_strdup_printf("read(%s) failed: %s",
				i_stream_get_name(&mstream->istream.istream),
				mstream->istream.iostream.error));
	mstream->istream.istream.stream_errno = EINVAL;
}

static ssize_t
i_stream_mail_read(struct istream_private *stream)
{
	struct mail_istream *mstream = (struct mail_istream *)stream;
	size_t size;
	ssize_t ret;

	i_stream_seek(stream->parent, stream->parent_start_offset +
		      stream->istream.v_offset);

	ret = i_stream_read_copy_from_parent(&stream->istream);
	size = i_stream_get_data_size(&stream->istream);
	if (ret > 0) {
		mstream->mail->transaction->stats.files_read_bytes += ret;
		if (!mstream->files_read_increased) {
			mstream->files_read_increased = TRUE;
			mstream->mail->transaction->stats.files_read_count++;
		}
		if (mstream->expected_size < stream->istream.v_offset + size) {
			i_stream_mail_set_size_corrupted(mstream, size);
			return -1;
		}
	} else if (ret == -1 && stream->istream.eof) {
		if (!mstream->input_has_body) {
			/* trying to read past the header, but this stream
			   doesn't have the body */
			return -1;
		}
		if (stream->istream.stream_errno != 0) {
			if (stream->istream.stream_errno == ENOENT) {
				/* update mail's expunged-flag if needed */
				index_mail_refresh_expunged(mstream->mail);
			}
			return -1;
		}
		if (i_stream_mail_try_get_cached_size(mstream) &&
		    mstream->expected_size > stream->istream.v_offset + size) {
			i_stream_mail_set_size_corrupted(mstream, size);
			return -1;
		}
	}
	return ret;
}

struct istream *i_stream_create_mail(struct mail *mail, struct istream *input,
				     bool input_has_body)
{
	struct mail_istream *mstream;

	mstream = i_new(struct mail_istream, 1);
	mstream->mail = mail;
	mstream->input_has_body = input_has_body;
	mstream->expected_size = (uoff_t)-1;
	(void)i_stream_mail_try_get_cached_size(mstream);
	mstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	mstream->istream.stream_size_passthrough = TRUE;

	mstream->istream.read = i_stream_mail_read;

	mstream->istream.istream.readable_fd = input->readable_fd;
	mstream->istream.istream.blocking = input->blocking;
	mstream->istream.istream.seekable = input->seekable;
	return i_stream_create(&mstream->istream, input,
			       i_stream_get_fd(input));
}
