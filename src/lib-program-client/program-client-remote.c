/* Copyright (c) 2002-2016 Dovecot authors, see the included COPYING file
 */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "net.h"
#include "write-full.h"
#include "eacces-error.h"
#include "istream-private.h"
#include "ostream.h"

#include "program-client-private.h"

#include <unistd.h>
#include <sys/wait.h>
#include <sysexits.h>

/*
 * Script client input stream
 */

struct program_client_istream {
	struct istream_private istream;

	struct stat statbuf;

	struct program_client *client;
};

static
void program_client_istream_destroy(struct iostream_private *stream)
{
	struct program_client_istream *scstream =
		(struct program_client_istream *) stream;

	i_stream_unref(&scstream->istream.parent);
}

static ssize_t
program_client_istream_read(struct istream_private *stream)
{
	struct program_client_istream *scstream =
		(struct program_client_istream *) stream;
	size_t pos, reserved;
	ssize_t ret = 0;

	i_stream_skip(stream->parent, stream->skip);
	stream->skip = 0;

	stream->buffer = i_stream_get_data(stream->parent, &pos);

	reserved = 0;
	if (stream->buffer != NULL && pos >= 1) {
		/* retain/hide potential return code at end of buffer */
		reserved = (stream->buffer[pos - 1] == '\n' && pos > 1 ? 2 : 1);
		pos -= reserved;
	}

	if (stream->parent->eof) {
		if (pos == 0)
			i_stream_skip(stream->parent, reserved);
		stream->istream.eof = TRUE;
		ret = -1;
	} else
		do {
			if ((ret = i_stream_read(stream->parent)) == -2) {
				return -2;	/* input buffer full */
			}

			if (ret == 0 || (ret < 0 && !stream->parent->eof))
				break;

			stream->istream.stream_errno =
				stream->parent->stream_errno;
			stream->buffer =
				i_stream_get_data(stream->parent, &pos);

			if (stream->parent->eof) {
				/* Check return code at EOF */
				if (stream->buffer != NULL && pos >= 2 &&
				    stream->buffer[pos - 1] == '\n') {
					switch (stream->buffer[pos - 2]) {
					case '+':
						scstream->client->exit_code = 1;
						break;
					case '-':
						scstream->client->exit_code = 0;
						break;
					default:
						scstream->client->exit_code =
							-1;
					}
				} else {
					scstream->client->exit_code = -1;
				}
			}

			if (stream->buffer != NULL && pos >= 1) {
				/* retain/hide potential return code at end of buffer */
				size_t old_reserved = reserved;
				ssize_t reserve_mod;

				reserved = (stream->buffer[pos - 1] == '\n' &&
					    pos > 1 ? 2 : 1);
				reserve_mod = reserved - old_reserved;
				pos -= reserved;

				if (ret >= reserve_mod) {
					ret -= reserve_mod;
				}
			}

			if (ret <= 0 && stream->parent->eof) {
				/* Parent EOF and not more data to return; EOF here as well */
				if (pos == 0)
					i_stream_skip(stream->parent, reserved);
				stream->istream.eof = TRUE;
				ret = -1;
			}
		} while (ret == 0);

	stream->pos = pos;

	i_assert(ret != -1 || stream->istream.eof ||
		 stream->istream.stream_errno != 0);
	return ret;
}

static
void ATTR_NORETURN program_client_istream_sync(struct istream_private *stream ATTR_UNUSED)
{
	i_panic("program_client_istream sync() not implemented");
}

static
int program_client_istream_stat(struct istream_private *stream, bool exact)
{
	struct program_client_istream *scstream =
		(struct program_client_istream *) stream;
	const struct stat *st;
	int ret;

	/* Stat the original stream */
	ret = i_stream_stat(stream->parent, exact, &st);
	if (ret < 0 || st->st_size == -1 || !exact)
		return ret;

	scstream->statbuf = *st;
	scstream->statbuf.st_size = -1;

	return ret;
}

static
struct istream *program_client_istream_create(struct program_client *program_client,
					      struct istream *input)
{
	struct program_client_istream *scstream;

	scstream = i_new(struct program_client_istream, 1);
	scstream->client = program_client;

	scstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	scstream->istream.iostream.destroy = program_client_istream_destroy;
	scstream->istream.read = program_client_istream_read;
	scstream->istream.sync = program_client_istream_sync;
	scstream->istream.stat = program_client_istream_stat;

	scstream->istream.istream.readable_fd = FALSE;
	scstream->istream.istream.blocking = input->blocking;
	scstream->istream.istream.seekable = FALSE;

	i_stream_seek(input, 0);

	return i_stream_create(&scstream->istream, input, -1);
}

/*
 * Program client
 */

struct program_client_remote {
	struct program_client client;

	bool noreply:1;
};

static
void program_client_remote_connected(struct program_client *pclient)
{
	struct program_client_remote *slclient =
		(struct program_client_remote *) pclient;
	const char **args = pclient->args;
	string_t *str;

	io_remove(&pclient->io);
	program_client_init_streams(pclient);

	if (!slclient->noreply) {
		struct istream *is = pclient->program_input;
		pclient->program_input =
			program_client_istream_create(pclient, pclient->program_input);
		i_stream_unref(&is);
	}

	str = t_str_new(1024);
	str_append(str, "VERSION\tscript\t3\t0\n");
	if (slclient->noreply)
		str_append(str, "noreply\n");
	else
		str_append(str, "-\n");
	if (args != NULL) {
		for(; *args != NULL; args++) {
			str_append(str, *args);
			str_append_c(str, '\n');
		}
	}
	str_append_c(str, '\n');

	if (o_stream_send(pclient->program_output,
			  str_data(str), str_len(str)) < 0) {
		i_error("write(%s) failed: %s",
			o_stream_get_name(pclient->program_output),
			o_stream_get_error(pclient->program_output));
		program_client_fail(pclient, PROGRAM_CLIENT_ERROR_IO);
		return;
	}

	(void)program_client_connected(pclient);
}

static
int program_client_unix_connect(struct program_client *pclient)
{
	struct program_client_remote *slclient =
		(struct program_client_remote *) pclient;
	int fd;

	if ((fd = net_connect_unix_with_retries(pclient->path, 1000)) < 0) {
		switch (errno) {
		case EACCES:
			i_error("%s",
				eacces_error_get("net_connect_unix",
						 pclient->path));
			return -1;
		default:
			i_error("net_connect_unix(%s) failed: %m",
				pclient->path);
			return -1;
		}
	}

	net_set_nonblock(fd, TRUE);

	pclient->fd_in = (slclient->noreply && pclient->output == NULL &&
			  !pclient->output_seekable ? -1 : fd);
	pclient->fd_out = fd;
	pclient->io =
		io_add(fd, IO_WRITE, program_client_remote_connected, pclient);
	return 0;
}

static
int program_client_remote_close_output(struct program_client *pclient)
{
	int fd_out = pclient->fd_out, fd_in = pclient->fd_in;

	pclient->fd_out = -1;

	/* Shutdown output; program stdin will get EOF */
	if (fd_out >= 0) {
		if (fd_in >= 0) {
			if (shutdown(fd_out, SHUT_WR) < 0 && errno != ENOTCONN) {
				i_error("shutdown(%s, SHUT_WR) failed: %m",
					pclient->path);
				return -1;
			}
		} else if (close(fd_out) < 0) {
			i_error("close(%s) failed: %m", pclient->path);
			return -1;
		}
	}

	return 1;
}

static
int program_client_remote_disconnect(struct program_client *pclient, bool force)
{
	struct program_client_remote *slclient =
		(struct program_client_remote *)pclient;
	int ret = 0;

	if (pclient->error == PROGRAM_CLIENT_ERROR_NONE && !slclient->noreply &&
	    pclient->program_input != NULL && !force) {
		const unsigned char *data;
		size_t size;

		/* Skip any remaining program output and parse the exit code */
		while ((ret = i_stream_read_more
			(pclient->program_input, &data, &size)) > 0) {
			i_stream_skip(pclient->program_input, size);
		}

		/* Get exit code */
		if (!pclient->program_input->eof)
			ret = -1;
		else
			ret = pclient->exit_code;
	} else {
		ret = 1;
	}

	return ret;
}

struct program_client *
program_client_unix_create(const char *socket_path, const char *const *args,
			   const struct program_client_settings *set,
			   bool noreply)
{
	struct program_client_remote *pclient;
	pool_t pool;

	pool = pool_alloconly_create("program client unix", 1024);
	pclient = p_new(pool, struct program_client_remote, 1);
	program_client_init(&pclient->client, pool, socket_path, args, set);
	pclient->client.connect = program_client_unix_connect;
	pclient->client.close_output = program_client_remote_close_output;
	pclient->client.disconnect = program_client_remote_disconnect;
	pclient->noreply = noreply;

	return &pclient->client;
}
