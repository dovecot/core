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
#include <sys/uio.h>

#define IOSTREAM_TEMP_MAX_BUF_SIZE_DEFAULT (1024*128)

struct temp_ostream {
	struct ostream_private ostream;

	char *temp_path_prefix;
	enum iostream_temp_flags flags;
	size_t max_mem_size;

	/* writev() wrapper - overridden for unit tests */
	ssize_t (*writev)(int fd, const struct iovec *iov,
			  unsigned int iov_count);

	struct istream *dupstream;
	uoff_t dupstream_offset, dupstream_start_offset;
	char *name;

	buffer_t *buf;
	buffer_t *fd_buf;
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
	struct temp_ostream *tstream =
		container_of(stream, struct temp_ostream, ostream.iostream);

	i_close_fd(&tstream->fd);
	buffer_free(&tstream->buf);
	buffer_free(&tstream->fd_buf);
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
	/* max_mem_size is smaller than IO_BLOCK_SIZE only in unit tests */
	size_t fd_buf_size = I_MIN(IO_BLOCK_SIZE, tstream->max_mem_size);
	tstream->fd_buf = buffer_create_dynamic_max(default_pool,
						    fd_buf_size, fd_buf_size);
	buffer_free(&tstream->buf);
	return 0;
}

static int o_stream_temp_move_to_memory(struct ostream *output)
{
	struct temp_ostream *tstream =
		container_of(output->real_stream, struct temp_ostream, ostream);
	unsigned char buf[IO_BLOCK_SIZE];
	uoff_t offset = 0;
	ssize_t ret = 0;

	i_assert(tstream->buf == NULL);
	tstream->buf = buffer_create_dynamic(default_pool, 8192);
	while ((ret = pread(tstream->fd, buf, sizeof(buf), offset)) > 0) {
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
o_stream_temp_fd_buf_sendv(struct temp_ostream *tstream,
			   const struct const_iovec *iov,
			   unsigned int iov_count, bool flush)
{
	i_assert(tstream->buf == NULL);

	/* if the amount of data fits into fd_buf, put it there */
	size_t total_size = 0;
	for (unsigned int i = 0; i < iov_count; i++)
		total_size += iov[i].iov_len;
	if (total_size + tstream->fd_buf->used <=
	    buffer_get_writable_size(tstream->fd_buf) && !flush) {
		for (unsigned int i = 0; i < iov_count; i++) {
			buffer_append(tstream->fd_buf, iov[i].iov_base,
				      iov[i].iov_len);
		}
		return total_size;
	}

	struct const_iovec iov_copy[iov_count + 1];
	struct const_iovec *new_iov = iov_copy;

	/* Use writev() to send all the pieces */
	size_t fd_buf_used = tstream->fd_buf->used;
	if (fd_buf_used == 0)
		memcpy(new_iov, iov, sizeof(*new_iov) * iov_count);
	else {
		/* Create iovec that is prefixed by the already buffered data */
		new_iov[0].iov_base = tstream->fd_buf->data;
		new_iov[0].iov_len = tstream->fd_buf->used;
		memcpy(new_iov + 1, iov, sizeof(*new_iov) * iov_count);
		iov_count++;
	}

	size_t bytes_sent = 0;
	ssize_t ret;
	while ((ret = tstream->writev(tstream->fd,
				      (const struct iovec *)new_iov,
				      I_MIN(iov_count, IOV_MAX))) > 0) {
		bytes_sent += ret;
		i_assert(bytes_sent <= total_size + fd_buf_used);
		if (bytes_sent == total_size + fd_buf_used)
			break;
		/* partial write, try again */
		while ((size_t)ret >= new_iov->iov_len) {
			ret -= new_iov->iov_len;
			new_iov++;
			iov_count--;
			i_assert(iov_count > 0);
		}
		new_iov->iov_len -= ret;
		new_iov->iov_base = CONST_PTR_OFFSET(new_iov->iov_base, ret);
	}
	if (ret == 0) {
		/* shouldn't happen - assume it's out of disk space */
		errno = ENOSPC;
		ret = -1;
	}
	if (ret < 0) {
		i_error("iostream-temp %s: write(%s*) failed: %m - moving to memory",
			o_stream_get_name(&tstream->ostream.ostream),
			tstream->temp_path_prefix);
		if (o_stream_temp_move_to_memory(&tstream->ostream.ostream) < 0)
			return -1;
		for (unsigned int i = 0; i < iov_count; i++) {
			buffer_append(tstream->buf, new_iov[i].iov_base,
				      new_iov[i].iov_len);
			bytes_sent += new_iov[i].iov_len;
		}
		i_assert(bytes_sent == total_size + fd_buf_used);
		buffer_free(&tstream->fd_buf);
	} else {
		buffer_set_used_size(tstream->fd_buf, 0);
	}
	return total_size;
}

static ssize_t
o_stream_temp_fd_sendv(struct temp_ostream *tstream,
		       const struct const_iovec *iov, unsigned int iov_count)
{
	i_assert(tstream->fd_buf != NULL);
	/* max_mem_size has been reached, and we're writing to a temp file. */
	ssize_t ret = o_stream_temp_fd_buf_sendv(tstream, iov, iov_count, FALSE);
	if (ret < 0)
		return -1;

	if (tstream->fd != -1)
		tstream->fd_size += ret;
	tstream->ostream.ostream.offset += ret;
	return ret;
}

static ssize_t
o_stream_temp_sendv(struct ostream_private *stream,
		    const struct const_iovec *iov, unsigned int iov_count)
{
	struct temp_ostream *tstream =
		container_of(stream, struct temp_ostream, ostream);
	ssize_t ret = 0;
	unsigned int i;
	enum ostream_send_istream_result res;


	tstream->flags &= ENUM_NEGATE(IOSTREAM_TEMP_FLAG_TRY_FD_DUP);
	if (tstream->dupstream != NULL) {
		if (o_stream_temp_dup_cancel(tstream, &res))
			return -1;
	}

	if (tstream->fd != -1)
		return o_stream_temp_fd_sendv(tstream, iov, iov_count);

	/* Either max_mem_size has not been reached yet, or we failed
	   to write to a temp file (e.g. out of disk space). */
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

static int o_stream_temp_flush(struct ostream_private *stream)
{
	struct temp_ostream *tstream =
		container_of(stream, struct temp_ostream, ostream);

	if (tstream->fd_buf == NULL || tstream->fd_buf->used == 0)
		return 1;

	struct const_iovec iov = { 0, 0 };
	return o_stream_temp_fd_buf_sendv(tstream, &iov, 0, TRUE) < 0 ? -1 : 1;
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
	struct temp_ostream *outstream =
		container_of(_outstream, struct temp_ostream, ostream);
	enum ostream_send_istream_result res;

	if ((outstream->flags & IOSTREAM_TEMP_FLAG_TRY_FD_DUP) != 0) {
		if (o_stream_temp_dup_istream(outstream, instream, &res))
			return res;
		outstream->flags &= ENUM_NEGATE(IOSTREAM_TEMP_FLAG_TRY_FD_DUP);
	}
	return io_stream_copy(&outstream->ostream.ostream, instream);
}

static ssize_t iostream_temp_writev(int fd, const struct iovec *iov,
				    unsigned int iov_count)
{
	return writev(fd, iov, iov_count);
}

void o_stream_temp_set_writev(struct ostream *output,
			      ssize_t (*func)(int fd, const struct iovec *iov,
					      unsigned int iov_count))
{
	struct temp_ostream *tstream =
		container_of(output->real_stream, struct temp_ostream, ostream);
	tstream->writev = func;
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
	tstream->ostream.flush = o_stream_temp_flush;
	tstream->ostream.iostream.close = o_stream_temp_close;
	tstream->temp_path_prefix = i_strdup(temp_path_prefix);
	tstream->flags = flags;
	tstream->max_mem_size = max_mem_size;
	tstream->buf = buffer_create_dynamic(default_pool, 8192);
	tstream->fd = -1;
	tstream->writev = iostream_temp_writev;

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
		container_of((*output)->real_stream, struct temp_ostream,
			     ostream);
	struct istream *input, *input2;
	uoff_t abs_offset, size;
	const char *for_path;
	int fd, ret;

	if (tstream->name[0] == '\0')
		for_path = "";
	else
		for_path = t_strdup_printf(" for %s", tstream->name);

	ret = o_stream_finish(*output);
	if (ret <= 0) {
		i_assert(ret < 0);
		input = i_stream_create_error_str((*output)->stream_errno, "%s",
						  o_stream_get_error(*output));
		i_stream_set_name(input, t_strdup_printf(
			"(Temp file in %s)", tstream->temp_path_prefix));
	} else if (tstream->dupstream != NULL && !tstream->dupstream->closed) {
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
