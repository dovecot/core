/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "strescape.h"
#include "array.h"
#include "net.h"
#include "write-full.h"
#include "eacces-error.h"
#include "istream-private.h"
#include "ostream.h"
#include "dns-lookup.h"
#include "program-client-private.h"

#include <unistd.h>
#include <sys/wait.h>
#include <sysexits.h>

#define PROGRAM_CLIENT_VERSION_MAJOR "4"
#define PROGRAM_CLIENT_VERSION_MINOR "0"

#define PROGRAM_CLIENT_VERSION_STRING "VERSION\tscript\t" \
		PROGRAM_CLIENT_VERSION_MAJOR "\t" \
		PROGRAM_CLIENT_VERSION_MINOR "\n"

/*
 * Script client input stream
 */

struct program_client_istream {
	struct istream_private istream;

	struct stat statbuf;

	struct program_client *client;
};

static void
program_client_istream_destroy(struct iostream_private *stream)
{
	struct program_client_istream *scstream =
		(struct program_client_istream *) stream;

	i_stream_unref(&scstream->istream.parent);
}

static void
program_client_istream_parse_result(struct program_client_istream *scstream,
	size_t pos)
{
	struct istream_private *stream = &scstream->istream;

	if (stream->buffer == NULL || pos < 2 ||
	    stream->buffer[pos - 1] != '\n') {
		scstream->client->exit_code =
			PROGRAM_CLIENT_EXIT_INTERNAL_FAILURE;
		return;
	}

	switch (stream->buffer[pos - 2]) {
	case '+':
		scstream->client->exit_code = PROGRAM_CLIENT_EXIT_SUCCESS;
		break;
	case '-':
		scstream->client->exit_code = PROGRAM_CLIENT_EXIT_FAILURE;
		break;
	default:
		scstream->client->exit_code =
			PROGRAM_CLIENT_EXIT_INTERNAL_FAILURE;
	}
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
			ret = i_stream_read_memarea(stream->parent);
			stream->istream.stream_errno =
				stream->parent->stream_errno;
			stream->buffer =
				i_stream_get_data(stream->parent, &pos);
			if (ret == -2)
				return -2;	/* input buffer full */
			if (ret == 0 || (ret < 0 && !stream->parent->eof))
				break;

			if (stream->parent->eof) {
				/* Check return code at EOF */
				program_client_istream_parse_result(scstream, pos);
			}

			if (stream->buffer != NULL && pos >= 1) {
				/* retain/hide potential return code at end of
				   buffer */
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
				/* Parent EOF and not more data to return;
				   EOF here as well */
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

static void ATTR_NORETURN
program_client_istream_sync(struct istream_private *stream ATTR_UNUSED)
{
	i_panic("program_client_istream sync() not implemented");
}

static int
program_client_istream_stat(struct istream_private *stream, bool exact)
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

static struct istream *
program_client_istream_create(struct program_client *program_client,
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

	return i_stream_create(&scstream->istream, input,
			       i_stream_get_fd(input), 0);
}

/*
 * Program client
 */

struct program_client_remote {
	struct program_client client;

	const char *address;
	struct dns_lookup_settings dns_set;
	struct dns_lookup *lookup;
	unsigned int ips_count;
	unsigned int ips_left;
	struct ip_addr *ips;
	in_port_t port;

	struct timeout *to_retry;

	bool noreply:1;
	bool resolved:1;
	bool have_hostname:1;
};

static void
program_client_net_connect_again(struct program_client_remote *prclient);

static void
program_client_remote_connected(struct program_client_remote *prclient)
{
	struct program_client *pclient = &prclient->client;
	const char **args = pclient->args;
	string_t *str;

	timeout_remove(&pclient->to);
	io_remove(&pclient->io);
	program_client_init_streams(pclient);

	if (!prclient->noreply) {
		struct istream *is = pclient->raw_program_input;
		pclient->raw_program_input =
			program_client_istream_create(pclient, is);
		i_stream_unref(&is);
	}

	str = t_str_new(1024);
	str_append(str, PROGRAM_CLIENT_VERSION_STRING);
	if (array_is_created(&pclient->envs)) {
		const char *const *env;
		array_foreach(&pclient->envs, env) {
			str_append(str, "env_");
			str_append_tabescaped(str, *env);
			str_append_c(str, '\n');
		}
	}
	if (prclient->noreply)
		str_append(str, "noreply\n");
	else
		str_append(str, "-\n");
	if (args != NULL) {
		for(; *args != NULL; args++) {
			str_append_tabescaped(str, *args);
			str_append_c(str, '\n');
		}
	}
	str_append_c(str, '\n');

	if (o_stream_send(pclient->raw_program_output,
			  str_data(str), str_len(str)) < 0) {
		e_error(pclient->event,
			"write(%s) failed: %s",
			o_stream_get_name(pclient->raw_program_output),
			o_stream_get_error(pclient->raw_program_output));
		program_client_fail(pclient, PROGRAM_CLIENT_ERROR_IO);
		return;
	}

	program_client_connected(pclient);
}

static int
program_client_unix_connect(struct program_client *pclient);

static void
program_client_unix_reconnect(struct program_client_remote *prclient)
{
	(void)program_client_unix_connect(&prclient->client);
}

static int
program_client_unix_connect(struct program_client *pclient)
{
	struct program_client_remote *prclient =
		(struct program_client_remote *)pclient;
	int fd;

	e_debug(pclient->event, "Trying to connect");

	timeout_remove(&prclient->to_retry);

	if ((fd = net_connect_unix(prclient->address)) < 0) {
		switch (errno) {
		case EACCES:
			e_error(pclient->event, "%s",
				eacces_error_get("net_connect_unix",
						 prclient->address));
			return -1;
		case EAGAIN:
			prclient->to_retry = timeout_add_short(100,
				program_client_unix_reconnect, prclient);
			return 0;
		default:
			e_error(pclient->event,
				"net_connect_unix(%s) failed: %m",
				prclient->address);
			return -1;
		}
	}

	pclient->fd_in = (prclient->noreply && pclient->output == NULL ?
			  -1 : fd);
	pclient->fd_out = fd;
	pclient->io = io_add(fd, IO_WRITE,
			     program_client_remote_connected, prclient);
	return 0;
}

static void
program_client_net_connect_timeout(struct program_client_remote *prclient)
{
	struct program_client *pclient = &prclient->client;

	io_remove(&pclient->io);
	timeout_remove(&pclient->to);

	e_error(pclient->event, "connect(%s) failed: "
		"Timeout in %u milliseconds", prclient->address,
		pclient->set.client_connect_timeout_msecs);

	/* set error to timeout here */
	pclient->error = PROGRAM_CLIENT_ERROR_CONNECT_TIMEOUT;
	i_close_fd(&pclient->fd_out);
	pclient->fd_in = pclient->fd_out = -1;
	program_client_net_connect_again(prclient);
}

/* see if connect succeeded or not, if it did, then proceed
   normally, otherwise try reconnect to next address */
static void
program_client_net_connected(struct program_client_remote *prclient)
{
	struct program_client *pclient = &prclient->client;

	io_remove(&pclient->io);

	if ((errno = net_geterror(pclient->fd_out)) != 0) {
		e_error(pclient->event, "connect(%s) failed: %m",
			prclient->address);

		/* disconnect and try again */
		i_close_fd(&pclient->fd_out);
		pclient->fd_in = pclient->fd_out = -1;
		program_client_net_connect_again(prclient);
	} else {
		pclient->io = io_add(pclient->fd_out, IO_WRITE,
				     program_client_remote_connected, prclient);
	}
}

static void
program_client_net_connect_real(struct program_client_remote *prclient)
{
	struct program_client *pclient = &prclient->client;
	const char *address, *label;

	timeout_remove(&pclient->to);

	timeout_remove(&prclient->to_retry);

	i_assert(prclient->ips_count > 0);

	if (net_ipport2str(prclient->ips, prclient->port, &address) < 0)
		i_unreached();
	label = t_strconcat("tcp:", address, NULL);
	program_client_set_label(pclient, label);

	e_debug(pclient->event, "Trying to connect (timeout %u msecs)",
		pclient->set.client_connect_timeout_msecs);

	/* try to connect */
	int fd;
	if ((fd = net_connect_ip(prclient->ips, prclient->port,
				 (prclient->ips->family == AF_INET ?
				  &net_ip4_any : &net_ip6_any))) < 0) {
		e_error(pclient->event, "connect(%s) failed: %m", address);
		prclient->to_retry = timeout_add_short(0,
			program_client_net_connect_again, prclient);
		return;
	}

	pclient->fd_in = (prclient->noreply && pclient->output == NULL ?
			  -1 : fd);
	pclient->fd_out = fd;
	pclient->io = io_add(fd, IO_WRITE,
			     program_client_net_connected, prclient);

	if (pclient->set.client_connect_timeout_msecs != 0) {
		pclient->to = timeout_add(
			pclient->set.client_connect_timeout_msecs,
			program_client_net_connect_timeout, prclient);
	}
}

static void
program_client_net_connect_again(struct program_client_remote *prclient)
{
	struct program_client *pclient = &prclient->client;
	enum program_client_error error = pclient->error;

	pclient->error = PROGRAM_CLIENT_ERROR_NONE;

	if (--prclient->ips_left == 0) {
		if (prclient->ips_count > 1) {
			e_error(pclient->event,
				"No IP addresses left to try");
		}
		program_client_fail(pclient,
				    error != PROGRAM_CLIENT_ERROR_NONE ?
						error :
						PROGRAM_CLIENT_ERROR_OTHER);
		return;
	};

	prclient->ips++;
	program_client_net_connect_real(prclient);
}

static void
program_client_net_connect_resolved(const struct dns_lookup_result *result,
				    struct program_client_remote *prclient)
{
	struct program_client *pclient = &prclient->client;

	if (result->ret != 0) {
		e_error(pclient->event, "Cannot resolve `%s': %s",
			prclient->address, result->error);
		program_client_fail(pclient, PROGRAM_CLIENT_ERROR_OTHER);
		return;
	}

	e_debug(pclient->event, "DNS lookup successful; got %d IPs",
		result->ips_count);

	/* reduce timeout */
	if (pclient->set.client_connect_timeout_msecs > 0) {
		if (pclient->set.client_connect_timeout_msecs <= result->msecs) {
			/* we ran out of time */
			program_client_fail(pclient,
				PROGRAM_CLIENT_ERROR_CONNECT_TIMEOUT);
			return;
		}
		pclient->set.client_connect_timeout_msecs -= result->msecs;
	}

	/* then connect */
	prclient->ips_count = result->ips_count;
	prclient->ips_left = prclient->ips_count;
	prclient->ips = p_memdup(pclient->pool, result->ips,
	       sizeof(struct ip_addr)*result->ips_count);
	program_client_net_connect_real(prclient);
}

static int
program_client_net_connect_init(struct program_client *pclient)
{
	struct program_client_remote *prclient =
		(struct program_client_remote *)pclient;
	struct ip_addr ip;

	if (prclient->ips != NULL) {
		/* nothing to do */
	} else if (net_addr2ip(prclient->address, &ip) == 0) {
		prclient->resolved = TRUE;
		prclient->ips = p_new(pclient->pool, struct ip_addr, 1);
		*prclient->ips = ip;
		prclient->ips_count = 1;
	} else {
		prclient->resolved = FALSE;
		if (pclient->set.dns_client_socket_path != NULL) {
			e_debug(pclient->event,
				"Performing asynchronous DNS lookup");
			prclient->dns_set.dns_client_socket_path =
				pclient->set.dns_client_socket_path;
			prclient->dns_set.timeout_msecs =
				pclient->set.client_connect_timeout_msecs;
			dns_lookup(prclient->address, &prclient->dns_set,
				   program_client_net_connect_resolved,
				   prclient, &prclient->lookup);
			return 0;
		} else {
			struct ip_addr *ips;
			unsigned int ips_count;
			int err;
			/* guess we do it here then.. */
			if ((err = net_gethostbyname(prclient->address,
					      &ips, &ips_count)) != 0) {
				e_error(pclient->event,
					"Cannot resolve `%s': %s",
					prclient->address,
					net_gethosterror(err));
				return -1;
			}
			prclient->ips_count = ips_count;
			prclient->ips = p_memdup(pclient->pool,
						 ips, sizeof(*ips)*ips_count);

			e_debug(pclient->event,
				"DNS lookup successful; got %d IPs",
				ips_count);
		}
	}

	prclient->ips_left = prclient->ips_count;
	prclient->to_retry = timeout_add_short(0,
		program_client_net_connect_real, prclient);
	return 0;
}

static int
program_client_remote_close_output(struct program_client *pclient)
{
	int fd_out = pclient->fd_out, fd_in = pclient->fd_in;

	pclient->fd_out = -1;

	/* Shutdown output; program stdin will get EOF */
	if (fd_out >= 0) {
		if (fd_in >= 0) {
			if (shutdown(fd_out, SHUT_WR) < 0 &&
			    errno != ENOTCONN) {
				e_error(pclient->event,
					"shutdown(fd_out, SHUT_WR) failed: %m");
				return -1;
			}
		} else {
			i_close_fd(&fd_out);
		}
	}

	return 1;
}

static void
program_client_remote_disconnect(struct program_client *pclient,
				 bool force ATTR_UNUSED)
{
	struct program_client_remote *prclient =
		(struct program_client_remote *)pclient;

	timeout_remove(&prclient->to_retry);

	program_client_disconnected(pclient);
}

static void
program_client_remote_switch_ioloop(struct program_client *pclient)
{
	struct program_client_remote *prclient =
		(struct program_client_remote *)pclient;

	if (prclient->to_retry != NULL)
		prclient->to_retry = io_loop_move_timeout(&prclient->to_retry);
	if (prclient->lookup != NULL)
		dns_lookup_switch_ioloop(prclient->lookup);
}

struct program_client *
program_client_unix_create(const char *socket_path, const char *const *args,
			   const struct program_client_settings *set,
			   bool noreply)
{
	struct program_client_remote *prclient;
	const char *label;
	pool_t pool;

	label = t_strconcat("unix:", socket_path, NULL);

	pool = pool_alloconly_create("program client unix", 1024);
	prclient = p_new(pool, struct program_client_remote, 1);
	program_client_init(&prclient->client, pool, label, args, set);
	prclient->client.connect = program_client_unix_connect;
	prclient->client.close_output = program_client_remote_close_output;
	prclient->client.disconnect = program_client_remote_disconnect;
	prclient->client.switch_ioloop = program_client_remote_switch_ioloop;
	prclient->address = p_strdup(pool, socket_path);
	prclient->noreply = noreply;

	return &prclient->client;
}

struct program_client *
program_client_net_create(const char *host, in_port_t port,
			  const char *const *args,
			  const struct program_client_settings *set,
			  bool noreply)
{
	struct program_client_remote *prclient;
	const char *label;
	pool_t pool;

	label = t_strdup_printf("tcp:%s:%u", host, port);

	pool = pool_alloconly_create("program client net", 1024);
	prclient = p_new(pool, struct program_client_remote, 1);
	program_client_init(&prclient->client, pool, label, args, set);
	prclient->client.connect = program_client_net_connect_init;
	prclient->client.close_output = program_client_remote_close_output;
	prclient->client.disconnect = program_client_remote_disconnect;
	prclient->client.set.use_dotstream = TRUE;
	prclient->address = p_strdup(pool, host);
	prclient->port = port;
	prclient->have_hostname = TRUE;
	prclient->noreply = noreply;
	return &prclient->client;
}

struct program_client *
program_client_net_create_ips(const struct ip_addr *ips, size_t ips_count,
			      in_port_t port,
			      const char *const *args,
			      const struct program_client_settings *set,
			      bool noreply)
{
	struct program_client_remote *prclient;
	const char *label;
	pool_t pool;

	i_assert(ips != NULL && ips_count > 0);

	if (net_ipport2str(ips, port, &label) < 0)
		i_unreached();
	label = t_strconcat("tcp:", label, NULL);

	pool = pool_alloconly_create("program client net", 1024);
	prclient = p_new(pool, struct program_client_remote, 1);
	program_client_init(&prclient->client, pool, label, args, set);
	prclient->client.connect = program_client_net_connect_init;
	prclient->client.close_output = program_client_remote_close_output;
	prclient->client.disconnect = program_client_remote_disconnect;
	prclient->client.switch_ioloop = program_client_remote_switch_ioloop;
	prclient->client.set.use_dotstream = TRUE;
	prclient->address = p_strdup(pool, net_ip2addr(ips));
	prclient->ips = p_memdup(pool, ips,
				 sizeof(struct ip_addr)*ips_count);
	prclient->ips_count = ips_count;
	prclient->port = port;
	prclient->noreply = noreply;
	return &prclient->client;
}

