/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "safe-mkstemp.h"
#include "write-full.h"
#include "istream-private.h"
#include "ostream-private.h"
#include "iostream-temp.h"

#include <unistd.h>

#define IOSTREAM_TEMP_MAX_BUF_SIZE_DEFAULT (1024*128)

struct temp_ostream {
	struct ostream_private ostream;

	char *temp_path_prefix;
	enum iostream_temp_flags flags;
	size_t max_mem_size;

	struct istream *dupstream;
	uoff_t dupstream_offset, dupstream_start_offset;
	char *name;

	buffer_t *buf;
	int fd;
	bool fd_tried;
	uoff_t fd_size;
};

static bool o_stream_temp_dup_cancel(struct temp_ostream *tstream,
				     enum ostream_send_istream_result *res_r);

static void
o_stream_temp_close(struct iostream_private *stream,
		    bool close_parent ATTR_UNUSED)
{
	struct temp_ostream *tstream = (struct temp_ostream *)stream;

	i_close_fd(&tstream->fd);
	buffer_free(&tstream->buf);
	i_free(tstream->temp_path_prefix);
	i_free(tstream->name);
}

static int o_stream_temp_move_to_fd(struct temp_ostream *tstream)
{
	string_t *path;

	if (tstream->fd_tried)
		return -1;
	tstream->fd_tried = TRUE;

	path = t_str_new(128);
	str_append(path, tstream->temp_path_prefix);
	tstream->fd = safe_mkstemp_hostpid(path, 0600, (uid_t)-1, (gid_t)-1);
	if (tstream->fd == -1) {
		i_error("safe_mkstemp(%s) failed: %m", str_c(path));
		return -1;
	}
	if (i_unlink(str_c(path)) < 0) {
		i_close_fd(&tstream->fd);
		return -1;
	}
	if (write_full(tstream->fd, tstream->buf->data, tstream->buf->used) < 0) {
		i_error("write(%s) failed: %m", str_c(path));
		i_close_fd(&tstream->fd);
		return -1;
	}
	/* make the fd available also to o_stream_get_fd(),
	   e.g. for unit tests */
	tstream->ostream.fd = tstream->fd;
	tstream->fd_size = tstream->buf->used;
	buffer_free(&tstream->buf);
	return 0;
}

int o_stream_temp_move_to_memory(struct ostream *output)
{
	struct temp_ostream *tstream =
		(struct temp_ostream *)output->real_stream;
	unsigned char buf[IO_BLOCK_SIZE];
	uoff_t offset = 0;
	ssize_t ret = 0;

	i_assert(tstream->buf == NULL);
	tstream->buf = buffer_create_dynamic(default_pool, 8192);
	while (offset < tstream->ostream.ostream.offset &&
	       (ret = pread(tstream->fd, buf, sizeof(buf), offset)) > 0) {
		if ((size_t)ret > tstream->ostream.ostream.offset - offset)
			ret = tstream->ostream.ostream.offset - offset;
		buffer_append(tstream->buf, buf, ret);
		offset += ret;
	}
	if (ret < 0) {
		/* not really expecting this to happen */
		i_error("iostream-temp %s: read(%s*) failed: %m",
			o_stream_get_name(&tstream->ostream.ostream),
			tstream->temp_path_prefix);
		tstream->ostream.ostream.stream_errno = EIO;
		return -1;
	}
	i_close_fd(&tstream->fd);
	tstream->ostream.fd = -1;
	return 0;
}

static ssize_t
o_stream_temp_fd_sendv(struct temp_ostream *tstream,
		       const struct const_iovec *iov, unsigned int iov_count)
{
	size_t bytes = 0;
	unsigned int i;

	for (i = 0; i < iov_count; i++) {
		if (write_full(tstream->fd, iov[i].iov_base, iov[i].iov_len) < 0) {
			i_error("iostream-temp %s: write(%s*) failed: %m - moving to memory",
				o_stream_get_name(&tstream->ostream.ostream),
				tstream->temp_path_prefix);
			if (o_stream_temp_move_to_memory(&tstream->ostream.ostream) < 0)
				return -1;
			for (; i < iov_count; i++) {
				buffer_append(tstream->buf, iov[i].iov_base, iov[i].iov_len);
				bytes += iov[i].iov_len;
				tstream->ostream.ostream.offset += iov[i].iov_len;
			}
			i_assert(tstream->fd_tried);
			return bytes;
		}
		bytes += iov[i].iov_len;
		tstream->ostream.ostream.offset += iov[i].iov_len;
	}
	tstream->fd_size += bytes;
	return bytes;
}

static ssize_t
o_stream_temp_sendv(struct ostream_private *stream,
		    const struct const_iovec *iov, unsigned int iov_count)
{
	struct temp_ostream *tstream = (struct temp_ostream *)stream;
	ssize_t ret = 0;
	unsigned int i;
	enum ostream_send_istream_result res;


	tstream->flags &= ~IOSTREAM_TEMP_FLAG_TRY_FD_DUP;
	if (tstream->dupstream != NULL) {
		if (o_stream_temp_dup_cancel(tstream, &res))
			return -1;
	}

	if (tstream->fd != -1)
		return o_stream_temp_fd_sendv(tstream, iov, iov_count);

	for (i = 0; i < iov_count; i++) {
		if (tstream->buf->used + iov[i].iov_len > tstream->max_mem_size) {
			if (o_stream_temp_move_to_fd(tstream) == 0) {
				i_assert(tstream->fd != -1);
				return o_stream_temp_fd_sendv(tstream, iov+i,
							      iov_count-i);
			}
			/* failed to move to temp fd, just keep it in memory */
		}
		buffer_append(tstream->buf, iov[i].iov_base, iov[i].iov_len);
		ret += iov[i].iov_len;
		stream->ostream.offset += iov[i].iov_len;
	}
	return ret;
}

static bool o_stream_temp_dup_cancel(struct temp_ostream *tstream,
				     enum ostream_send_istream_result *res_r)
{
	struct istream *input;
	uoff_t size = tstream->dupstream_offset -
		tstream->dupstream_start_offset;
	bool ret = TRUE; /* use res_r to return error */

	i_stream_seek(tstream->dupstream, tstream->dupstream_start_offset);
	tstream->ostream.ostream.offset = 0;

	input = i_stream_create_limit(tstream->dupstream, size);
	i_stream_unref(&tstream->dupstream);

	*res_r = io_stream_copy(&tstream->ostream.ostream, input);
	switch (*res_r) {
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		/* everything copied */
		ret = FALSE;
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		i_unreached();
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		tstream->ostream.ostream.stream_errno = input->stream_errno;
		io_stream_set_error(&tstream->ostream.iostream,
			"iostream-temp: read(%s) failed: %s",
			i_stream_get_name(input),
			i_stream_get_error(input));
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		break;
	}
	i_stream_destroy(&input);
	return ret;
}

static bool
o_stream_temp_dup_istream(struct temp_ostream *outstream,
			  struct istream *instream,
			  enum ostream_send_istream_result *res_r)
{
	uoff_t in_size;

	if (!instream->readable_fd || i_stream_get_fd(instream) == -1)
		return FALSE;

	if (i_stream_get_size(instream, TRUE, &in_size) <= 0) {
		if (outstream->dupstream != NULL)
			return o_stream_temp_dup_cancel(outstream, res_r);
		return FALSE;
	}
	i_assert(instream->v_offset <= in_size);

	if (outstream->dupstream == NULL) {
		outstream->dupstream = instream;
		outstream->dupstream_start_offset = instream->v_offset;
		i_stream_ref(outstream->dupstream);
	} else {
		if (outstream->dupstream != instream ||
		    outstream->dupstream_offset != instream->v_offset ||
		    outstream->dupstream_offset > in_size)
			return o_stream_temp_dup_cancel(outstream, res_r);
	}
	i_stream_seek(instream, in_size);
	/* we should be at EOF now. o_stream_send_istream() asserts if
	   eof isn't set. */
	instream->eof = TRUE;
	outstream->dupstream_offset = instream->v_offset;
	outstream->ostream.ostream.offset =
		outstream->dupstream_offset - outstream->dupstream_start_offset;
	*res_r = OSTREAM_SEND_ISTREAM_RESULT_FINISHED;
	return TRUE;
}

static enum ostream_send_istream_result
o_stream_temp_send_istream(struct ostream_private *_outstream,
			   struct istream *instream)
{
	struct temp_ostream *outstream = (struct temp_ostream *)_outstream;
	enum ostream_send_istream_result res;

	if ((outstream->flags & IOSTREAM_TEMP_FLAG_TRY_FD_DUP) != 0) {
		if (o_stream_temp_dup_istream(outstream, instream, &res))
			return res;
		outstream->flags &= ~IOSTREAM_TEMP_FLAG_TRY_FD_DUP;
	}
	return io_stream_copy(&outstream->ostream.ostream, instream);
}

static int
o_stream_temp_write_at(struct ostream_private *stream,
		       const void *data, size_t size, uoff_t offset)
{
	struct temp_ostream *tstream = (struct temp_ostream *)stream;

	if (tstream->fd == -1) {
		i_assert(stream->ostream.offset == tstream->buf->used);
		buffer_write(tstream->buf, offset, data, size);
		stream->ostream.offset = tstream->buf->used;
	} else {
		if (pwrite_full(tstream->fd, data, size, offset) < 0) {
			stream->ostream.stream_errno = errno;
			i_close_fd(&tstream->fd);
			return -1;
		}
		if (tstream->fd_size < offset + size)
			tstream->fd_size = offset + size;
	}
	return 0;
}

static int o_stream_temp_seek(struct ostream_private *_stream, uoff_t offset)
{
	_stream->ostream.offset = offset;
	return 0;
}

struct ostream *iostream_temp_create(const char *temp_path_prefix,
				     enum iostream_temp_flags flags)
{
	return iostream_temp_create_named(temp_path_prefix, flags, "");
}

struct ostream *iostream_temp_create_named(const char *temp_path_prefix,
					   enum iostream_temp_flags flags,
					   const char *name)
{
	return iostream_temp_create_sized(temp_path_prefix, flags, name,
					  IOSTREAM_TEMP_MAX_BUF_SIZE_DEFAULT);
}

struct ostream *iostream_temp_create_sized(const char *temp_path_prefix,
					   enum iostream_temp_flags flags,
					   const char *name,
					   size_t max_mem_size)
{
	struct temp_ostream *tstream;
	struct ostream *output;

	tstream = i_new(struct temp_ostream, 1);
	tstream->ostream.ostream.blocking = TRUE;
	tstream->ostream.sendv = o_stream_temp_sendv;
	tstream->ostream.send_istream = o_stream_temp_send_istream;
	tstream->ostream.write_at = o_stream_temp_write_at;
	tstream->ostream.seek = o_stream_temp_seek;
	tstream->ostream.iostream.close = o_stream_temp_close;
	tstream->temp_path_prefix = i_strdup(temp_path_prefix);
	tstream->flags = flags;
	tstream->max_mem_size = max_mem_size;
	tstream->buf = buffer_create_dynamic(default_pool, 8192);
	tstream->fd = -1;

	output = o_stream_create(&tstream->ostream, NULL, -1);
	tstream->name = i_strdup(name);
	if (name[0] == '\0') {
		o_stream_set_name(output, t_strdup_printf(
			"(temp iostream in %s)", temp_path_prefix));
	} else {
		o_stream_set_name(output, t_strdup_printf(
			"(temp iostream in %s for %s)", temp_path_prefix, name));
	}
	return output;
}

static void iostream_temp_buf_destroyed(buffer_t *buf)
{
	buffer_free(&buf);
}

struct istream *iostream_temp_finish(struct ostream **output,
				     size_t max_buffer_size)
{
	struct temp_ostream *tstream =
		(struct temp_ostream *)(*output)->real_stream;
	struct istream *input, *input2;
	uoff_t abs_offset, size;
	const char *for_path;
	int fd;

	if (tstream->name[0] == '\0')
		for_path = "";
	else
		for_path = t_strdup_printf(" for %s", tstream->name);

	if (tstream->dupstream != NULL && !tstream->dupstream->closed) {
		abs_offset = i_stream_get_absolute_offset(tstream->dupstream) -
			tstream->dupstream->v_offset +
			tstream->dupstream_start_offset;
		size = tstream->dupstream_offset -
			tstream->dupstream_start_offset;
		fd = dup(i_stream_get_fd(tstream->dupstream));
		if (fd == -1)
			input = i_stream_create_error_str(errno, "dup() failed: %m");
		else {
			input2 = i_stream_create_fd_autoclose(&fd, max_buffer_size);
			i_stream_seek(input2, abs_offset);
			input = i_stream_create_limit(input2, size);
			i_stream_unref(&input2);
		}
		i_stream_set_name(input, t_strdup_printf(
			"(Temp file in %s%s, from %s)", tstream->temp_path_prefix,
			for_path, i_stream_get_name(tstream->dupstream)));
		i_stream_unref(&tstream->dupstream);
	} else if (tstream->dupstream != NULL) {
		/* return the original failed stream. */
		input = tstream->dupstream;
	} else if (tstream->fd != -1) {
		int fd = tstream->fd;
		input = i_stream_create_fd_autoclose(&tstream->fd, max_buffer_size);
		i_stream_set_name(input, t_strdup_printf(
			"(Temp file fd %d in %s%s, %"PRIuUOFF_T" bytes)",
			fd, tstream->temp_path_prefix, for_path, tstream->fd_size));
	} else {
		input = i_stream_create_from_data(tstream->buf->data,
						  tstream->buf->used);
		i_stream_set_name(input, t_strdup_printf(
			"(Temp buffer in %s%s, %zu bytes)",
			tstream->temp_path_prefix, for_path, tstream->buf->used));
		i_stream_add_destroy_callback(input, iostream_temp_buf_destroyed,
					      tstream->buf);
		tstream->buf = NULL;
	}
	o_stream_destroy(output);
	return input;
}
