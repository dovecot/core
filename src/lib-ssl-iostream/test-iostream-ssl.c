/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

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
};

static int bufsize_flush_callback(struct test_endpoint *ep)
{
	io_loop_stop(current_ioloop);
	int ret = o_stream_flush(ep->output);
	test_assert(ret >= 0);
	return ret;
}

static int small_packets_flush_callback(struct test_endpoint *ep)
{
	int ret = o_stream_flush(ep->output);
	test_assert(ret >= 0);
	return ret;
}

static void send_output(struct test_endpoint *ep)
{
	ssize_t amt = i_rand_limit(10)+1;
	char data[amt];
	random_fill(data, amt);
	buffer_append(ep->other->last_write, data, amt);
	test_assert(o_stream_send(ep->output, data, amt) == amt);
	ep->sent += amt;
}

static void handshake_input_callback(struct test_endpoint *ep)
{
	if (ep->failed)
		return;
	if (ssl_iostream_is_handshaked(ep->iostream)) {
		io_loop_stop(current_ioloop);
		return;
	}
	if (ssl_iostream_handshake(ep->iostream) < 0) {
		ep->failed = TRUE;
		io_loop_stop(current_ioloop);
	}
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
	test_assert((ret = i_stream_read_bytes(ep->input, &data, &size, wanted)) > -1);

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
		io_loop_stop(current_ioloop);
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
	ep->set = ssl_iostream_settings_dup(pool, set);
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

	if (io_stream_create_ssl_server(server->ctx, server->set,
					&server->input, &server->output,
					&server->iostream, &error) != 0) {
		ret = -1;
	}

	if (io_stream_create_ssl_client(client->ctx, client->hostname, client->set,
					&client->input, &client->output,
					&client->iostream, &error) != 0) {
		ret = -1;
	}

	client->io = io_add_istream(client->input, handshake_input_callback, client);
	server->io = io_add_istream(server->input, handshake_input_callback, server);

	if (ssl_iostream_handshake(client->iostream) < 0)
		return -1;

	io_loop_run(current_ioloop);

	if (client->failed || server->failed)
		ret = -1;

	if (ssl_iostream_has_handshake_failed(client->iostream)) {
		i_error("client: %s", ssl_iostream_get_last_error(client->iostream));
		ret = -1;
	} else if (ssl_iostream_has_handshake_failed(server->iostream)) {
		i_error("server: %s", ssl_iostream_get_last_error(server->iostream));
		ret = -1;
	/* check hostname */
	} else if (client->hostname != NULL &&
	    !client->set->allow_invalid_cert &&
	    ssl_iostream_check_cert_validity(client->iostream, client->hostname,
					     &error) != 0) {
		i_error("client(%s): %s", client->hostname, error);
		ret = -1;
	/* client cert */
	} else if (server->set->verify_remote_cert &&
	    ssl_iostream_check_cert_validity(server->iostream, NULL, &error) != 0) {
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
	test_expect_error_string("client(failhost): SSL certificate doesn't "
				 "match expected host name failhost");
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "failhost") != 0, idx);
	idx++;

	/* verify remote cert, missing CA */
	ssl_iostream_test_settings_server(&server_set);
	ssl_iostream_test_settings_client(&client_set);
	client_set.verify_remote_cert = TRUE;
	client_set.ca = NULL;
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
	server_set.cert.key = NULL;
	ssl_iostream_test_settings_client(&client_set);
	client_set.verify_remote_cert = TRUE;
	test_expect_error_string("client(failhost): SSL certificate not received");
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "failhost") != 0, idx);
	idx++;
	ssl_iostream_test_settings_server(&server_set);
	server_set.cert.cert = NULL;
	ssl_iostream_test_settings_client(&client_set);
	client_set.verify_remote_cert = TRUE;
	test_expect_error_string("client(failhost): SSL certificate not received");
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "failhost") != 0, idx);
	idx++;

	/* mismatch in cipher list */
	ssl_iostream_test_settings_server(&server_set);
	ssl_iostream_test_settings_client(&client_set);
	server_set.cipher_list = "ECDSA";
	client_set.cipher_list = "RSA";
	client_set.prefer_server_ciphers = TRUE;
	client_set.verify_remote_cert = TRUE;
	test_expect_error_string("client(127.0.0.1): SSL certificate not received");
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "127.0.0.1") != 0, idx);
	idx++;

	/* unsupported cipher list */
	ssl_iostream_test_settings_server(&server_set);
	ssl_iostream_test_settings_client(&client_set);
	server_set.cipher_list = "NONEXISTENT";
	client_set.prefer_server_ciphers = TRUE;
	test_expect_error_string("server: Can't set cipher list to 'NONEXISTENT'");
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "127.0.0.1") != 0, idx);
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
	test_expect_error_string("server: SSL_accept() failed: error:");
	test_assert_idx(test_iostream_ssl_handshake_real(&server_set, &client_set,
							 "127.0.0.1") != 0, idx);
	idx++;

	io_loop_destroy(&ioloop);

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

	client->other = server;
	server->other = client;

	test_assert(ssl_iostream_context_init_server(server->set, &server->ctx,
		    &error) == 0);
	test_assert(ssl_iostream_context_init_client(client->set, &client->ctx,
		    &error) == 0);

	test_assert(io_stream_create_ssl_server(server->ctx, server->set,
						&server->input, &server->output,
						&server->iostream, &error) == 0);
	test_assert(io_stream_create_ssl_client(client->ctx, "localhost", client->set,
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

	test_assert(o_stream_finish(server->output) >= 0);
	test_assert(o_stream_finish(client->output) >= 0);

	i_stream_unref(&server->input);
	o_stream_unref(&server->output);
	i_stream_unref(&client->input);
	o_stream_unref(&client->output);

	destroy_test_endpoint(&client);
	destroy_test_endpoint(&server);

	io_loop_destroy(&ioloop);

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

	test_assert(ssl_iostream_context_init_server(server->set, &server->ctx,
		    &error) == 0);
	test_assert(ssl_iostream_context_init_client(client->set, &client->ctx,
		    &error) == 0);

	client->other = server;
	server->other = client;

	test_assert(io_stream_create_ssl_server(server->ctx, server->set,
						&server->input, &server->output,
						&server->iostream, &error) == 0);
	test_assert(io_stream_create_ssl_client(client->ctx, "localhost", client->set,
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
	test_assert(o_stream_finish(server->output) >= 0);
	test_assert(o_stream_finish(client->output) >= 0);

	i_stream_unref(&server->input);
	o_stream_unref(&server->output);
	i_stream_unref(&client->input);
	o_stream_unref(&client->output);

	destroy_test_endpoint(&server);
	destroy_test_endpoint(&client);

	io_loop_destroy(&ioloop);

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_iostream_ssl_handshake,
		test_iostream_ssl_get_buffer_avail_size,
		test_iostream_ssl_small_packets,
		NULL
	};
	ssl_iostream_openssl_init();
	int ret = test_run(test_functions);
	ssl_iostream_openssl_deinit();
	return ret;
}
