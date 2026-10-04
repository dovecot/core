/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-lib.h"
#include "buffer.h"
#include "randgen.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-openssl.h"
#include "iostream-ssl.h"
#include "iostream-ssl-test.h"

#include <sys/socket.h>

#define MAX_SENT_BYTES 10000

struct test_endpoint {
	pool_t pool;
	int fd;
	const char *hostname;
	const struct ssl_iostream_settings *set;
	struct ssl_iostream_context *ctx;
	struct ssl_iostream *iostream;
	struct istream *input;
	struct ostream *output;
	struct io *io;
	buffer_t *last_write;
	ssize_t sent;
	bool client;
	bool failed;

	struct test_endpoint *other;

	bool finished:1;
};

static void send_output(struct test_endpoint *ep)
{
	ssize_t amt = i_rand_limit(10)+1;
	char data[amt];
	random_fill(data, amt);
	buffer_append(ep->other->last_write, data, amt);
	test_assert(o_stream_send(ep->output, data, amt) == amt);
	ep->sent += amt;
}

static int flush_output(struct test_endpoint *ep, bool finish)
{
	int ret = (finish ?
		   o_stream_finish(ep->output) : o_stream_flush(ep->output));
	test_assert(ret >= 0);

	if (ret > 0) {
		if (finish)
			ep->finished = TRUE;
		if (ep->other->finished)
			io_loop_stop(current_ioloop);
	}
	return ret;
}

static void handshake_input_callback(struct test_endpoint *ep)
{
	if (ep->failed)
		return;
	if (ssl_iostream_is_handshaked(ep->iostream)) {
		if (ssl_iostream_is_handshaked(ep->other->iostream))
			io_loop_stop(current_ioloop);
		return;
	}
	if (ssl_iostream_handshake(ep->iostream) < 0) {
		ep->failed = TRUE;
		io_loop_stop(current_ioloop);
	}
}

static int bufsize_flush_callback(struct test_endpoint *ep)
{
	io_loop_stop(current_ioloop);
	return flush_output(ep, FALSE);
}

static int bufsize_finish_callback(struct test_endpoint *ep)
{
	return flush_output(ep, TRUE);
}

static void bufsize_input_callback(struct test_endpoint *ep)
{
	const unsigned char *data;
	size_t size, wanted = i_rand_limit(512);

	io_loop_stop(current_ioloop);
	if (wanted == 0)
		return;

	test_assert(i_stream_read_bytes(ep->input, &data, &size, wanted) > -1);
	i_stream_skip(ep->input, I_MIN(size, wanted));
}

static void bufsize_discard_callback(struct test_endpoint *ep)
{
	const unsigned char *data;
	size_t size;

	test_assert(i_stream_read_bytes(ep->input, &data, &size, 1) > -1 ||
		    ep->input->stream_errno == 0);
	i_stream_skip(ep->input, size);
}

static int small_packets_flush_callback(struct test_endpoint *ep)
{
	return flush_output(ep, FALSE);
}

static void small_packets_input_callback(struct test_endpoint *ep)
{
	const unsigned char *data;
	size_t size, wanted = i_rand_limit(10);
	int ret;

	if (wanted == 0) {
		i_stream_set_input_pending(ep->input, TRUE);
		return;
	}

	size = 0;
	test_assert((ret = i_stream_read_bytes(ep->input, &data, &size, wanted)) > -1 ||
		    ep->input->stream_errno == 0);

	if (size > wanted)
		i_stream_set_input_pending(ep->input, TRUE);

	size = I_MIN(size, wanted);

	i_stream_skip(ep->input, size);
	if (size > 0) {
		test_assert(ep->last_write->used >= size);
		if (ep->last_write->used >= size) {
			test_assert(memcmp(ep->last_write->data, data, size) == 0);
			/* remove the data that was wanted */
			buffer_delete(ep->last_write, 0, size);
		}
	}

	if (ep->sent > MAX_SENT_BYTES)
		(void)flush_output(ep, TRUE);
	else
		send_output(ep);
}

static struct test_endpoint *
create_test_endpoint(int fd, const struct ssl_iostream_settings *set)
{
	pool_t pool = pool_alloconly_create("ssl endpoint", 2048);
	struct test_endpoint *ep = p_new(pool, struct test_endpoint, 1);
	ep->pool = pool;
	ep->fd = fd;
	ep->input = i_stream_create_fd(ep->fd, 512);
	ep->output = o_stream_create_fd(ep->fd, 1024);
	o_stream_uncork(ep->output);
	/* We assume here that strings continue to be valid pointers */
	ep->set = p_memdup(pool, set, sizeof(*set));
	ep->last_write = buffer_create_dynamic(pool, 1024);
	return ep;
}

static void destroy_test_endpoint(struct test_endpoint **_ep)
{
	struct test_endpoint *ep = *_ep;
	_ep = NULL;

	io_remove(&ep->io);

	i_stream_unref(&ep->input);
	o_stream_unref(&ep->output);
	ssl_iostream_destroy(&ep->iostream);
	i_close_fd(&ep->fd);
	if (ep->ctx != NULL)
		ssl_iostream_context_unref(&ep->ctx);
	pool_unref(&ep->pool);
}

static int test_iostream_ssl_handshake_real(struct ssl_iostream_settings *server_set,
					    struct ssl_iostream_settings *client_set,
					    const char *hostname)
{
	const char *error;
	struct test_endpoint *server, *client;
	int fd[2], ret = 0;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0)
		i_fatal("socketpair() failed: %m");
	fd_set_nonblock(fd[0], TRUE);
	fd_set_nonblock(fd[1], TRUE);

	server = create_test_endpoint(fd[0], server_set);
	client = create_test_endpoint(fd[1], client_set);
	client->hostname = hostname;
	client->client = TRUE;

	server->other = client;
	client->other = server;

	if (ssl_iostream_context_init_server(server->set, &server->ctx,
					     &error) < 0) {
		i_error("server: %s", error);
		destroy_test_endpoint(&client);
		destroy_test_endpoint(&server);
		return -1;
	}
	if (ssl_iostream_context_init_client(client->set, &client->ctx,
					     &error) < 0) {
		i_error("client: %s", error);
		destroy_test_endpoint(&client);
		destroy_test_endpoint(&server);
		return -1;
	}

	if (io_stream_create_ssl_server(server->ctx, NULL,
					&server->input, &server->output,
					&server->iostream, &error) != 0) {
		ret = -1;
	}

	if (io_stream_create_ssl_client(client->ctx, client->hostname, NULL, 0,
					&client->input, &client->output,
					&client->iostream, &error) != 0) {
		ret = -1;
	}

	client->io = io_add_istream(client->input, handshake_input_callback, client);
	server->io = io_add_istream(server->input, handshake_input_callback, server);

	if (ssl_iostream_handshake(client->iostream) < 0)
		ret = -1;
	else
		io_loop_run(current_ioloop);

	if (client->failed || server->failed)
		ret = -1;

	if (ssl_iostream_get_state(client->iostream) != SSL_IOSTREAM_STATE_OK &&
	    ssl_iostream_get_state(client->iostream) != SSL_IOSTREAM_STATE_HANDSHAKING) {
		i_error("client: %s", ssl_iostream_get_last_error(client->iostream));
		ret = -1;
	} else if (ssl_iostream_get_state(server->iostream) != SSL_IOSTREAM_STATE_OK &&
		   ssl_iostream_get_state(server->iostream) != SSL_IOSTREAM_STATE_HANDSHAKING) {
		i_error("server: %s", ssl_iostream_get_last_error(server->iostream));
		ret = -1;
	/* check hostname */
	} else if (client->hostname != NULL &&
	    !client->set->allow_invalid_cert &&
	    ssl_iostream_check_cert_validity(client->iostream, client->hostname,
					     &error) != SSL_IOSTREAM_CERT_VALIDITY_OK) {
		i_error("client(%s): %s", client->hostname, error);
		ret = -1;
	/* client cert */
	} else if (server->set->verify_remote_cert &&
		   ssl_iostream_check_cert_validity(server->iostream, NULL,
						    &error) != SSL_IOSTREAM_CERT_VALIDITY_OK) {
		i_error("server: %s", error);
		ret = -1;
	}

	i_stream_unref(&server->input);
	o_stream_unref(&server->output);
	i_stream_unref(&client->input);
	o_stream_unref(&client->output);

	destroy_test_endpoint(&client);
	destroy_test_endpoint(&server);

	return ret;
}

static void test_iostream_ssl_handshake(void)
{
	struct ssl_iostream_settings server_set, client_set;
	struct ioloop *ioloop;
	int idx = 0;

	test_begin("ssl: handshake");

	ioloop = io_loop_create();

	/* allow invalid cert, connect to localhost */
	ssl_iostream_test_settings_server(&server_set);
	ssl_iostream_test_settings_client(&client_set);
	client_set.allow_invalid_cert = TRUE;
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "localhost") == 0, idx);
	idx++;

	/* allow invalid cert, connect to failhost */
	ssl_iostream_test_settings_server(&server_set);
	ssl_iostream_test_settings_client(&client_set);
	client_set.allow_invalid_cert = TRUE;
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "failhost") == 0, idx);
	idx++;

	/* verify remote cert */
	ssl_iostream_test_settings_server(&server_set);
	ssl_iostream_test_settings_client(&client_set);
	client_set.verify_remote_cert = TRUE;
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "127.0.0.1") == 0, idx);
	idx++;

	/* verify remote cert, missing hostname */
	ssl_iostream_test_settings_server(&server_set);
	ssl_iostream_test_settings_client(&client_set);
	client_set.verify_remote_cert = TRUE;
	test_expect_error_string("client: SSL certificate doesn't "
				 "match expected host name failhost");
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "failhost") != 0, idx);
	idx++;

	/* verify remote cert, missing CA */
	ssl_iostream_test_settings_server(&server_set);
	ssl_iostream_test_settings_client(&client_set);
	client_set.verify_remote_cert = TRUE;
	i_zero(&client_set.ca);
	test_expect_error_string("client: Received invalid SSL certificate");
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "127.0.0.1") != 0, idx);
	idx++;

	/* verify remote cert, require CRL */
	ssl_iostream_test_settings_server(&server_set);
	ssl_iostream_test_settings_client(&client_set);
	client_set.verify_remote_cert = TRUE;
	client_set.skip_crl_check = FALSE;
	test_expect_error_string("client: Received invalid SSL certificate");
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "127.0.0.1") != 0, idx);
	idx++;

	/* missing server credentials */
	ssl_iostream_test_settings_server(&server_set);
	i_zero(&server_set.cert.key);
	ssl_iostream_test_settings_client(&client_set);
	client_set.verify_remote_cert = TRUE;
	test_expect_error_string("client(failhost): SSL certificate not received");
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "failhost") != 0, idx);
	idx++;
	ssl_iostream_test_settings_server(&server_set);
	i_zero(&server_set.cert.cert);
	ssl_iostream_test_settings_client(&client_set);
	client_set.verify_remote_cert = TRUE;
	test_expect_error_string("client(failhost): SSL certificate not received");
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "failhost") != 0, idx);
	idx++;

	/* invalid client credentials: missing credentials */
	ssl_iostream_test_settings_server(&server_set);
	ssl_iostream_test_settings_client(&client_set);
	client_set.verify_remote_cert = TRUE;
	server_set.verify_remote_cert = TRUE;
	server_set.ca = client_set.ca;
	test_expect_error_string("server: SSL certificate not received");
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "127.0.0.1") != 0, idx);
	idx++;

	/* invalid client credentials: incorrect extended usage */
	ssl_iostream_test_settings_server(&server_set);
	ssl_iostream_test_settings_client(&client_set);
	client_set.verify_remote_cert = TRUE;
	server_set.verify_remote_cert = TRUE;
	server_set.ca = client_set.ca;
	client_set.cert = server_set.cert;
	test_expect_error_string("server: Received invalid SSL certificate");
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "127.0.0.1") != 0, idx);
	idx++;

	io_loop_destroy(&ioloop);
	ssl_iostream_context_cache_free();

	test_end();
}

static void test_iostream_ssl_get_buffer_avail_size(void)
{
	struct ssl_iostream_settings set;
	struct test_endpoint *server, *client;
	struct ioloop *ioloop;
	int fd[2];
	const char *error;

	test_begin("ssl: o_stream_get_buffer_avail_size");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0)
		i_fatal("socketpair() failed: %m");
	fd_set_nonblock(fd[0], TRUE);
	fd_set_nonblock(fd[1], TRUE);

	ioloop = io_loop_create();

	ssl_iostream_test_settings_server(&set);
	server = create_test_endpoint(fd[0], &set);
	ssl_iostream_test_settings_client(&set);
	set.allow_invalid_cert = TRUE;
	client = create_test_endpoint(fd[1], &set);
	client->client = TRUE;

	client->other = server;
	server->other = client;

	test_assert(ssl_iostream_context_init_server(server->set, &server->ctx,
		    &error) == 0);
	test_assert(ssl_iostream_context_init_client(client->set, &client->ctx,
		    &error) == 0);

	test_assert(io_stream_create_ssl_server(server->ctx, NULL,
						&server->input, &server->output,
						&server->iostream, &error) == 0);
	test_assert(io_stream_create_ssl_client(client->ctx, "localhost", NULL, 0,
						&client->input, &client->output,
						&client->iostream, &error) == 0);

	o_stream_set_flush_callback(server->output, bufsize_flush_callback, server);
	o_stream_set_flush_callback(client->output, bufsize_flush_callback, client);

	server->io = io_add_istream(server->input, bufsize_input_callback, server);
	client->io = io_add_istream(client->input, bufsize_input_callback, client);

	test_assert(ssl_iostream_handshake(client->iostream) == 0);
	test_assert(ssl_iostream_handshake(server->iostream) == 0);

	for (unsigned int i = 0; i < 100000 && !test_has_failed(); i++) {
		size_t avail = o_stream_get_buffer_avail_size(server->output);
		if (avail > 0) {
			void *buf = i_malloc(avail);
			random_fill(buf, avail);
			test_assert(o_stream_send(server->output, buf, avail) ==
				    (ssize_t)avail);
			i_free(buf);
		}
		avail = o_stream_get_buffer_avail_size(client->output);
		if (avail > 0) {
			void *buf = i_malloc(avail);
			random_fill(buf, avail);
			test_assert(o_stream_send(client->output, buf, avail) ==
				    (ssize_t)avail);
			i_free(buf);
		}
		io_loop_run(ioloop);
	}

	io_remove(&server->io);
	io_remove(&client->io);
	o_stream_set_flush_callback(server->output, bufsize_finish_callback, server);
	o_stream_set_flush_callback(client->output, bufsize_finish_callback, client);
	server->io = io_add_istream(server->input, bufsize_discard_callback, server);
	client->io = io_add_istream(client->input, bufsize_discard_callback, client);
	o_stream_set_flush_pending(server->output, TRUE);
	o_stream_set_flush_pending(client->output, TRUE);
	io_loop_run(ioloop);

	i_stream_unref(&server->input);
	o_stream_unref(&server->output);
	i_stream_unref(&client->input);
	o_stream_unref(&client->output);

	destroy_test_endpoint(&client);
	destroy_test_endpoint(&server);

	io_loop_destroy(&ioloop);
	ssl_iostream_context_cache_free();

	test_end();
}

static void test_iostream_ssl_small_packets(void)
{
	struct ssl_iostream_settings set;
	struct test_endpoint *server, *client;
	struct ioloop *ioloop;
	int fd[2];
	const char *error;

	test_begin("ssl: small packets");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0)
		i_fatal("socketpair() failed: %m");
	fd_set_nonblock(fd[0], TRUE);
	fd_set_nonblock(fd[1], TRUE);

	ioloop = io_loop_create();

	ssl_iostream_test_settings_server(&set);
	server = create_test_endpoint(fd[0], &set);
	ssl_iostream_test_settings_client(&set);
	set.allow_invalid_cert = TRUE;
	client = create_test_endpoint(fd[1], &set);
	client->client = TRUE;

	test_assert(ssl_iostream_context_init_server(server->set, &server->ctx,
		    &error) == 0);
	test_assert(ssl_iostream_context_init_client(client->set, &client->ctx,
		    &error) == 0);

	client->other = server;
	server->other = client;

	test_assert(io_stream_create_ssl_server(server->ctx, NULL,
						&server->input, &server->output,
						&server->iostream, &error) == 0);
	test_assert(io_stream_create_ssl_client(client->ctx, "localhost", NULL, 0,
						&client->input, &client->output,
						&client->iostream, &error) == 0);

	o_stream_set_flush_callback(server->output, small_packets_flush_callback,
				    server);
	o_stream_set_flush_callback(client->output, small_packets_flush_callback,
				    client);

	server->io = io_add_istream(server->input, small_packets_input_callback,
				    server);
	client->io = io_add_istream(client->input, small_packets_input_callback,
				    client);

	test_assert(ssl_iostream_handshake(client->iostream) == 0);
	test_assert(ssl_iostream_handshake(server->iostream) == 0);

	struct timeout *to = timeout_add(5000, io_loop_stop, ioloop);

	io_loop_run(ioloop);

	timeout_remove(&to);

	test_assert(server->sent > MAX_SENT_BYTES ||
		    client->sent > MAX_SENT_BYTES);

	i_stream_unref(&server->input);
	o_stream_unref(&server->output);
	i_stream_unref(&client->input);
	o_stream_unref(&client->output);

	destroy_test_endpoint(&server);
	destroy_test_endpoint(&client);

	io_loop_destroy(&ioloop);
	ssl_iostream_context_cache_free();

	test_end();
}

static void cork_input_callback(struct test_endpoint *ep)
{
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	while ((ret = i_stream_read_more(ep->input, &data, &size)) > 0) {
		test_assert(ep->last_write->used >= size);
		if (ep->last_write->used >= size) {
			test_assert(memcmp(ep->last_write->data, data,
					   size) == 0);
			buffer_delete(ep->last_write, 0, size);
		}
		i_stream_skip(ep->input, size);
	}
	if (ret < 0)
		test_assert(ep->input->stream_errno == 0);
	if (ep->last_write->used == 0)
		io_loop_stop(current_ioloop);
}

static void cork_timeout_callback(struct test_endpoint *ep)
{
	ep->failed = TRUE;
	io_loop_stop(current_ioloop);
}

/* Run ioloop until the client has read everything the server wrote */
static void test_iostream_ssl_cork_wait(struct test_endpoint *client)
{
	struct timeout *to;

	to = timeout_add(5000, cork_timeout_callback, client);
	io_loop_run(current_ioloop);
	timeout_remove(&to);
	test_assert(!client->failed);
	test_assert(client->last_write->used == 0);
}

static void
test_ssl_endpoints_create(struct test_endpoint **server_r,
			  struct test_endpoint **client_r)
{
	struct ssl_iostream_settings set;
	struct test_endpoint *server, *client;
	int fd[2];
	const char *error;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0)
		i_fatal("socketpair() failed: %m");
	fd_set_nonblock(fd[0], TRUE);
	fd_set_nonblock(fd[1], TRUE);

	ssl_iostream_test_settings_server(&set);
	server = create_test_endpoint(fd[0], &set);
	ssl_iostream_test_settings_client(&set);
	set.allow_invalid_cert = TRUE;
	client = create_test_endpoint(fd[1], &set);
	client->client = TRUE;

	test_assert(ssl_iostream_context_init_server(server->set, &server->ctx,
						     &error) == 0);
	test_assert(ssl_iostream_context_init_client(client->set, &client->ctx,
						     &error) == 0);

	client->other = server;
	server->other = client;

	test_assert(io_stream_create_ssl_server(server->ctx, NULL,
						&server->input, &server->output,
						&server->iostream,
						&error) == 0);
	test_assert(io_stream_create_ssl_client(client->ctx, "localhost",
						NULL, 0,
						&client->input, &client->output,
						&client->iostream,
						&error) == 0);
	o_stream_set_no_error_handling(server->output, TRUE);

	*server_r = server;
	*client_r = client;
}

static void
test_ssl_endpoints_destroy(struct test_endpoint **server,
			   struct test_endpoint **client)
{
	i_stream_unref(&(*server)->input);
	o_stream_unref(&(*server)->output);
	i_stream_unref(&(*client)->input);
	o_stream_unref(&(*client)->output);

	destroy_test_endpoint(server);
	destroy_test_endpoint(client);
	ssl_iostream_context_cache_free();
}

static void test_iostream_ssl_cork(void)
{
	static const char line[] = "hello world\n";
	static const size_t iov_lens[] = { 700, 0, 700, 8000 };
	struct test_endpoint *server, *client;
	struct ioloop *ioloop;
	struct ostream *plain_output;
	struct const_iovec iov[N_ELEMENTS(iov_lens)];
	unsigned char data[10000];
	uoff_t plain_offset;
	size_t pos;

	test_begin("ssl: o_stream_cork");

	ioloop = io_loop_create();
	test_ssl_endpoints_create(&server, &client);

	/* handshake */
	server->io = io_add_istream(server->input, handshake_input_callback,
				    server);
	client->io = io_add_istream(client->input, handshake_input_callback,
				    client);
	test_assert(ssl_iostream_handshake(client->iostream) == 0);
	io_loop_run(ioloop);
	test_assert(ssl_iostream_is_handshaked(server->iostream));
	test_assert(ssl_iostream_is_handshaked(client->iostream));
	io_remove(&server->io);
	io_remove(&client->io);
	client->io = io_add_istream(client->input, cork_input_callback, client);

	plain_output = server->iostream->plain_output;

	/* corked writes are only buffered, nothing reaches the plain ostream
	   until uncorking. (The output's max_buffer_size is 1024.) */
	plain_offset = plain_output->offset;
	o_stream_cork(server->output);
	for (unsigned int i = 0; i < 50; i++) {
		o_stream_nsend_str(server->output, line);
		buffer_append(client->last_write, line, strlen(line));
	}
	test_assert(plain_output->offset == plain_offset);
	test_assert(o_stream_get_buffer_used_size(server->output) ==
		    50 * strlen(line));
	o_stream_uncork(server->output);
	test_assert(server->output->stream_errno == 0);
	test_assert(plain_output->offset > plain_offset);
	test_assert(o_stream_get_buffer_used_size(server->output) == 0);
	test_iostream_ssl_cork_wait(client);

	/* uncorked writes are written immediately */
	plain_offset = plain_output->offset;
	o_stream_nsend_str(server->output, line);
	buffer_append(client->last_write, line, strlen(line));
	test_assert(plain_output->offset > plain_offset);
	test_iostream_ssl_cork_wait(client);

	/* a write larger than max_buffer_size doesn't overflow the stream */
	random_fill(data, sizeof(data));
	o_stream_set_max_buffer_size(server->output, 1024);
	o_stream_nsend(server->output, data, sizeof(data));
	buffer_append(client->last_write, data, sizeof(data));
	test_assert(!server->output->overflow);
	test_assert(o_stream_flush(server->output) >= 0);
	test_assert(server->output->stream_errno == 0);
	test_iostream_ssl_cork_wait(client);

	/* same while corked */
	o_stream_cork(server->output);
	o_stream_nsend(server->output, data, sizeof(data));
	buffer_append(client->last_write, data, sizeof(data));
	test_assert(!server->output->overflow);
	o_stream_uncork(server->output);
	test_assert(server->output->stream_errno == 0);
	test_iostream_ssl_cork_wait(client);

	/* same with multiple iovecs, so the full buffer is flushed in the
	   middle of an iovec. Do it uncorked and corked. */
	for (unsigned int n = 0; n < 2; n++) {
		pos = 0;
		for (unsigned int i = 0; i < N_ELEMENTS(iov_lens); i++) {
			iov[i].iov_base = data + pos;
			iov[i].iov_len = iov_lens[i];
			pos += iov_lens[i];
		}
		i_assert(pos <= sizeof(data));
		buffer_append(client->last_write, data, pos);
		if (n == 1)
			o_stream_cork(server->output);
		o_stream_nsendv(server->output, iov, N_ELEMENTS(iov));
		test_assert(!server->output->overflow);
		if (n == 1)
			o_stream_uncork(server->output);
		else
			test_assert(o_stream_flush(server->output) >= 0);
		test_assert(server->output->stream_errno == 0);
		test_iostream_ssl_cork_wait(client);
	}

	/* with unlimited max_buffer_size, corked writes don't grow the buffer
	   without limit. Full TLS records are written out. */
	o_stream_set_max_buffer_size(server->output, SIZE_MAX);
	plain_offset = plain_output->offset;
	o_stream_cork(server->output);
	for (unsigned int i = 0; i < 1000; i++) {
		o_stream_nsend(server->output, data, 100);
		buffer_append(client->last_write, data, 100);
	}
	test_assert(plain_output->offset > plain_offset);
	/* the SSL ostream's own buffer has less than one TLS record */
	test_assert(o_stream_get_buffer_used_size(server->output) -
		    o_stream_get_buffer_used_size(plain_output) <
		    SSL3_RT_MAX_PLAIN_LENGTH);
	o_stream_uncork(server->output);
	test_assert(server->output->stream_errno == 0);
	test_iostream_ssl_cork_wait(client);

	test_ssl_endpoints_destroy(&server, &client);
	io_loop_destroy(&ioloop);
	test_end();
}

static int handshake_flush_callback(struct test_endpoint *ep)
{
	ep->sent++;
	return o_stream_flush(ep->output);
}

static void handshake_server_input_callback(struct test_endpoint *ep)
{
	/* reading continues the handshake */
	test_assert(i_stream_read(ep->input) >= 0);
}

static void handshake_flush_timeout(void *context ATTR_UNUSED)
{
	io_loop_stop(current_ioloop);
}

static void test_iostream_ssl_flush_before_handshake(void)
{
	static const char line[] = "hello world\n";
	struct test_endpoint *server, *client;
	struct ioloop *ioloop;
	struct timeout *to;

	test_begin("ssl: o_stream_flush() before handshake");

	ioloop = io_loop_create();
	test_ssl_endpoints_create(&server, &client);
	o_stream_set_flush_callback(server->output, handshake_flush_callback,
				    server);

	/* The data can't be written until the handshake has finished, so
	   flushing must not return 1. */
	o_stream_nsend_str(server->output, line);
	buffer_append(client->last_write, line, strlen(line));
	test_assert(o_stream_flush(server->output) == 0);
	test_assert(o_stream_get_buffer_used_size(server->output) > 0);

	/* The client hasn't started the handshake yet. The flush callback
	   must not be called repeatedly while waiting for its input. */
	to = timeout_add_short(100, handshake_flush_timeout, NULL);
	io_loop_run(ioloop);
	timeout_remove(&to);
	test_assert(server->sent < 10);

	/* After the handshake the data is written */
	server->io = io_add_istream(server->input,
				    handshake_server_input_callback, server);
	client->io = io_add_istream(client->input, cork_input_callback,
				    client);
	test_assert(ssl_iostream_handshake(client->iostream) == 0);
	test_iostream_ssl_cork_wait(client);
	test_assert(o_stream_get_buffer_used_size(server->output) == 0);

	test_ssl_endpoints_destroy(&server, &client);
	io_loop_destroy(&ioloop);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_iostream_ssl_handshake,
		test_iostream_ssl_get_buffer_avail_size,
		test_iostream_ssl_small_packets,
		test_iostream_ssl_cork,
		test_iostream_ssl_flush_before_handshake,
		NULL
	};
	ssl_iostream_openssl_init();
	int ret = test_run(test_functions);
	ssl_iostream_openssl_deinit();
	return ret;
}
