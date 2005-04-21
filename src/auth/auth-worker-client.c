/* Copyright (C) 2005 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "auth-request.h"
#include "auth-worker-client.h"

#include <stdlib.h>

#define OUTBUF_THROTTLE_SIZE (1024*10)

struct auth_worker_client {
	int refcount;

        struct auth *auth;
	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
};

static void auth_worker_client_unref(struct auth_worker_client *client);

static void
auth_worker_client_check_throttle(struct auth_worker_client *client)
{
	if (o_stream_get_buffer_used_size(client->output) >=
	    OUTBUF_THROTTLE_SIZE) {
		/* stop reading new requests until client has read the pending
		   replies. */
		if (client->io != NULL) {
			io_remove(client->io);
			client->io = NULL;
		}
	}
}

static struct auth_request *
worker_auth_request_new(struct auth_worker_client *client, unsigned int id,
			const char *args)
{
	struct auth_request *auth_request;
	const char *key, *value, *const *tmp;

	auth_request = auth_request_new_dummy(client->auth);

	client->refcount++;
	auth_request->context = client;
	auth_request->id = id;

	t_push();
	for (tmp = t_strsplit(args, "\t"); *tmp != NULL; tmp++) {
		value = strchr(*tmp, '=');
		if (value == NULL)
			continue;

		key = t_strdup_until(*tmp, value);
		value++;

		if (strcmp(key, "user") == 0) {
			auth_request->user =
				p_strdup(auth_request->pool, value);
		} else if (strcmp(key, "service") == 0) {
			auth_request->service =
				p_strdup(auth_request->pool, value);
		} else if (strcmp(key, "lip") == 0)
			net_addr2ip(value, &auth_request->local_ip);
		else if (strcmp(key, "rip") == 0)
			net_addr2ip(value, &auth_request->remote_ip);
	}
	t_pop();

	return auth_request;
}

static void verify_plain_callback(enum passdb_result result,
				  struct auth_request *request)
{
	struct auth_worker_client *client = request->context;
	string_t *str;

	str = t_str_new(64);
	str_printfa(str, "%u\t", request->id);

	if (result != PASSDB_RESULT_OK)
		str_printfa(str, "FAIL\t%d", result);
	else {
		str_append(str, "OK\t");
		str_append(str, request->user);
		str_append_c(str, '\t');
		if (request->passdb_password != NULL)
			str_append(str, request->passdb_password);
		str_append_c(str, '\t');
		if (request->proxy) {
			/* we're proxying - send back the password that was
			   sent by user (not the password in passdb). */
			str_printfa(str, "pass=%s\t", request->mech_password);
		}
		if (request->extra_fields != NULL)
			str_append_str(str, request->extra_fields);
	}
	str_append_c(str, '\n');

	o_stream_send(client->output, str_data(str), str_len(str));
        auth_worker_client_check_throttle(client);
	auth_worker_client_unref(client);
}

static void
auth_worker_handle_passv(struct auth_worker_client *client,
			 unsigned int id, const char *args)
{
	/* verify plaintext password */
	struct auth_request *auth_request;
	const char *password;
	unsigned int num;

	num = atoi(t_strcut(args, '\t'));
	args = strchr(args, '\t');
	if (args == NULL) {
		i_error("BUG: Auth worker server sent us invalid PASSV");
		return;
	}
	args++;

	password = t_strcut(args, '\t');
	args = strchr(args, '\t');
	if (args != NULL) args++;

	auth_request = worker_auth_request_new(client, id, args);
	auth_request->mech_password =
		p_strdup(auth_request->pool, password);

	for (; num > 0; num--) {
		auth_request->passdb = auth_request->passdb->next;
		if (auth_request->passdb == NULL) {
			i_error("BUG: PASSV had invalid passdb num");
			return;
		}
	}

	auth_request->passdb->passdb->verify_plain(auth_request, password,
						   verify_plain_callback);
}

static void
lookup_credentials_callback(enum passdb_result result, const char *credentials,
			    struct auth_request *request)
{
	struct auth_worker_client *client = request->context;
	string_t *str;

	str = t_str_new(64);
	str_printfa(str, "%u\t", request->id);

	if (result != PASSDB_RESULT_OK)
		str_printfa(str, "FAIL\t%d", result);
	else {
		str_printfa(str, "OK\t%s\t{%s}%s\t", request->user,
			    passdb_credentials_to_str(request->credentials),
			    credentials);
		if (request->extra_fields != NULL)
			str_append_str(str, request->extra_fields);
	}
	str_append_c(str, '\n');

	o_stream_send(client->output, str_data(str), str_len(str));
        auth_worker_client_check_throttle(client);
	auth_worker_client_unref(client);
}

static void
auth_worker_handle_passl(struct auth_worker_client *client,
			 unsigned int id, const char *args)
{
	/* lookup credentials */
	struct auth_request *auth_request;
	const char *credentials_str;
        enum passdb_credentials credentials;
	unsigned int num;

	num = atoi(t_strcut(args, '\t'));
	args = strchr(args, '\t');
	if (args == NULL) {
		i_error("BUG: Auth worker server sent us invalid PASSL");
		return;
	}
	args++;

	credentials_str = t_strcut(args, '\t');
	args = strchr(args, '\t');
	if (args != NULL) args++;

	credentials = atoi(credentials_str);

	auth_request = worker_auth_request_new(client, id, args);
	auth_request->credentials = credentials;

	for (; num > 0; num--) {
		auth_request->passdb = auth_request->passdb->next;
		if (auth_request->passdb == NULL) {
			i_error("BUG: PASSL had invalid passdb num");
			return;
		}
	}

	auth_request->passdb->passdb->
		lookup_credentials(auth_request, credentials,
				   lookup_credentials_callback);
}

static void
lookup_user_callback(const char *result, struct auth_request *auth_request)
{
	struct auth_worker_client *client = auth_request->context;
	string_t *str;

	str = t_str_new(64);
	str_printfa(str, "%u\t", auth_request->id);
	if (result != NULL)
		str_append(str, result);
	str_append_c(str, '\n');

	o_stream_send(client->output, str_data(str), str_len(str));
        auth_worker_client_check_throttle(client);
	auth_worker_client_unref(client);
}

static void
auth_worker_handle_user(struct auth_worker_client *client,
			unsigned int id, const char *args)
{
	/* lookup user */
	struct auth_request *auth_request;
	unsigned int num;

	num = atoi(t_strcut(args, '\t'));
	args = strchr(args, '\t');
	if (args != NULL) args++;

	auth_request = worker_auth_request_new(client, id, args);

	for (; num > 0; num--) {
		auth_request->userdb = auth_request->userdb->next;
		if (auth_request->userdb == NULL) {
			i_error("BUG: USER had invalid userdb num");
			return;
		}
	}

	auth_request->userdb->userdb->
		lookup(auth_request, lookup_user_callback);
}

static int
auth_worker_handle_line(struct auth_worker_client *client, const char *line)
{
	const char *p;
	unsigned int id;

	p = strchr(line, '\t');
	if (p == NULL)
		return FALSE;

	id = (unsigned int)strtoul(t_strdup_until(line, p), NULL, 10);
	line = p + 1;

	if (strncmp(line, "PASSV\t", 6) == 0)
		auth_worker_handle_passv(client, id, line + 6);
	else if (strncmp(line, "PASSL\t", 6) == 0)
		auth_worker_handle_passl(client, id, line + 6);
	else if (strncmp(line, "USER\t", 5) == 0)
		auth_worker_handle_user(client, id, line + 5);

        return TRUE;
}

static void auth_worker_input(void *context)
{
	struct auth_worker_client *client = context;
	char *line;
	int ret;

	switch (i_stream_read(client->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_worker_client_destroy(client);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth worker server sent us more than %d bytes",
			(int)AUTH_WORKER_MAX_LINE_LENGTH);
		auth_worker_client_destroy(client);
		return;
	}

        client->refcount++;
	while ((line = i_stream_next_line(client->input)) != NULL) {
		t_push();
		ret = auth_worker_handle_line(client, line);
		t_pop();

		if (!ret) {
			auth_worker_client_destroy(client);
			break;
		}
	}
	auth_worker_client_unref(client);
}

static int auth_worker_output(void *context)
{
	struct auth_worker_client *client = context;

	if (o_stream_flush(client->output) < 0) {
		auth_worker_client_destroy(client);
		return 1;
	}

	if (o_stream_get_buffer_used_size(client->output) <=
	    OUTBUF_THROTTLE_SIZE/3 && client->io == NULL) {
		/* allow input again */
		client->io = io_add(client->fd, IO_READ,
				    auth_worker_input, client);
	}
	return 1;
}

struct auth_worker_client *
auth_worker_client_create(struct auth *auth, int fd)
{
        struct auth_worker_client *client;

	client = i_new(struct auth_worker_client, 1);
	client->refcount = 1;

	client->auth = auth;
	client->fd = fd;
	client->input =
		i_stream_create_file(fd, default_pool,
				     AUTH_WORKER_MAX_LINE_LENGTH, FALSE);
	client->output =
		o_stream_create_file(fd, default_pool, (size_t)-1, FALSE);
	o_stream_set_flush_callback(client->output, auth_worker_output, client);
	client->io = io_add(fd, IO_READ, auth_worker_input, client);

	return client;
}

void auth_worker_client_destroy(struct auth_worker_client *client)
{
	if (client->fd == -1)
		return;

	i_stream_close(client->input);
	o_stream_close(client->output);

	if (client->io != NULL) {
		io_remove(client->io);
		client->io = NULL;
	}

	net_disconnect(client->fd);
	client->fd = -1;

	io_loop_stop(ioloop);
        auth_worker_client_unref(client);
}

static void auth_worker_client_unref(struct auth_worker_client *client)
{
	if (--client->refcount > 0)
		return;

	i_stream_unref(client->input);
	o_stream_unref(client->output);
	i_free(client);
}
