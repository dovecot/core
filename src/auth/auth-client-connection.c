/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "network.h"
#include "base64.h"
#include "buffer.h"
#include "hash.h"
#include "str.h"
#include "str-sanitize.h"
#include "safe-memset.h"
#include "auth-request.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"

#include <stdlib.h>

/* Used only for string sanitization. */
#define MAX_MECH_NAME_LEN 64

#define MAX_OUTBUF_SIZE (1024*50)

static void auth_client_connection_unref(struct auth_client_connection *conn);
static void
auth_client_connection_destroy_wait(struct auth_client_connection *conn);

static void auth_client_send(struct auth_client_connection *conn,
			     const char *fmt, ...) __attr_format__(2, 3);
static void auth_client_send(struct auth_client_connection *conn,
			     const char *fmt, ...)
{
	va_list args;
	string_t *str;
	ssize_t ret;

	i_assert(conn->refcount > 1);

	t_push();
	va_start(args, fmt);
	str = t_str_new(256);
	str_vprintfa(str, fmt, args);
	str_append_c(str, '\n');
	ret = o_stream_send(conn->output, str_data(str), str_len(str));
	if (ret != (ssize_t)str->used) {
		i_warning("Authentication client %u: "
			  "Transmit buffer full, killing it", conn->pid);
		auth_client_connection_destroy_wait(conn);
	}
	va_end(args);
	t_pop();
}

static const char *get_client_extra_fields(struct auth_request *request)
{
	const char **fields;
	unsigned int src, dest;

	if (request->extra_fields == NULL)
		return NULL;

	/* we only wish to remove all fields prefixed with "userdb_" */
	if (strstr(request->extra_fields, "userdb_") == NULL)
		return request->extra_fields;

	fields = t_strsplit(request->extra_fields, "\t");
	for (src = dest = 0; fields[src] != NULL; src++) {
		if (strncmp(fields[src], "userdb_", 7) == 0)
			fields[dest++] = fields[src];
	}
	fields[dest] = NULL;
	return t_strarray_join(fields, "\t");
}

static void auth_callback(struct auth_request *request,
			  enum auth_client_result result,
			  const void *reply, size_t reply_size)
{
	string_t *str = NULL;
	const char *fields;
	ssize_t ret;

	t_push();

	switch (result) {
	case AUTH_CLIENT_RESULT_CONTINUE:
		str = t_str_new(32 + MAX_BASE64_ENCODED_SIZE(reply_size));
		str_printfa(str, "CONT\t%u\t", request->id);
		base64_encode(reply, reply_size, str);
                request->accept_input = TRUE;
		break;
	case AUTH_CLIENT_RESULT_SUCCESS:
		str = t_str_new(128 + MAX_BASE64_ENCODED_SIZE(reply_size));
		str_printfa(str, "OK\t%u\tuser=%s", request->id, request->user);
		if (reply_size > 0) {
			str_append(str, "\tresp=");
			base64_encode(reply, reply_size, str);
		}
		t_push();
		fields = get_client_extra_fields(request);
		if (fields != NULL) {
			str_append_c(str, '\t');
			str_append(str, fields);
		}
		t_pop();
		break;
	case AUTH_CLIENT_RESULT_FAILURE:
		str = t_str_new(128);
		str_printfa(str, "FAIL\t%u", request->id);
		if (request->user != NULL)
			str_printfa(str, "\tuser=%s", request->user);
		if (request->internal_failure)
			str_append(str, "\ttemp");
		t_push();
		fields = get_client_extra_fields(request);
		if (fields != NULL) {
			str_append_c(str, '\t');
			str_append(str, fields);
		}
		t_pop();
		break;
	}

	str_append_c(str, '\n');

	ret = o_stream_send(request->conn->output, str->data, str->used);
	if (ret < 0)
		auth_client_connection_destroy(request->conn);
	else if ((size_t)ret != str->used) {
		i_warning("Authentication client %u: "
			  "Transmit buffer full, killing it",
			  request->conn->pid);
		auth_client_connection_destroy_wait(request->conn);
	}
	t_pop();

	auth_client_connection_unref(request->conn);
}

struct auth_client_connection *
auth_client_connection_lookup(struct auth_master_connection *master,
			      unsigned int pid)
{
	struct auth_client_connection *conn;

	for (conn = master->clients; conn != NULL; conn = conn->next) {
		if (conn->pid == pid)
			return conn;
	}

	return NULL;
}

static int
auth_client_input_service(struct auth_client_connection *conn, const char *args)
{
	if (conn->default_service == NULL)
		conn->default_service = p_strdup(conn->pool, args);
	return TRUE;
}

static int
auth_client_input_cpid(struct auth_client_connection *conn, const char *args)
{
        struct auth_client_connection *old;
	unsigned int pid;

	if (conn->pid != 0) {
		i_error("BUG: Authentication client re-handshaking");
		return FALSE;
	}

	pid = (unsigned int)strtoul(args, NULL, 10);
	if (pid == 0) {
		i_error("BUG: Authentication client said it's PID 0");
		return FALSE;
	}

	old = auth_client_connection_lookup(conn->master, pid);
	if (old != NULL) {
		/* already exists. it's possible that it just reconnected,
		   see if the old connection is still there. */
		if (i_stream_read(old->input) == -1) {
                        auth_client_connection_destroy(old);
			old = NULL;
		}
	}

	if (old != NULL) {
		i_error("BUG: Authentication client gave a PID "
			"%u of existing connection", pid);
		return FALSE;
	}

	conn->pid = pid;
	return TRUE;
}

static int
auth_client_input_auth(struct auth_client_connection *conn, const char *args)
{
	struct mech_module *mech;
	struct auth_request *request;
	const char *const *list, *name, *arg, *initial_resp;
	const void *initial_resp_data;
	size_t initial_resp_len;
	unsigned int id;
	buffer_t *buf;
	int valid_client_cert;

	if (conn->pid == 0) {
		i_error("BUG: Authentication client %u didn't send handshake",
			conn->pid);
		return FALSE;
	}

	/* <id> <mechanism> [...] */
	list = t_strsplit(args, "\t");
	if (list[0] == NULL || list[1] == NULL) {
		i_error("BUG: Authentication client %u "
			"sent broken AUTH request", conn->pid);
		return FALSE;
	}

	id = (unsigned int)strtoul(list[0], NULL, 10);

	mech = mech_module_find(list[1]);
	if (mech == NULL) {
		/* unsupported mechanism */
		i_error("BUG: Authentication client %u requested unsupported "
			"authentication mechanism %s", conn->pid,
			str_sanitize(list[1], MAX_MECH_NAME_LEN));
		return FALSE;
	}

	request = auth_request_new(mech);
	if (request == NULL)
		return TRUE;
	hash_insert(conn->auth_requests, POINTER_CAST(id), request);

	request->conn = conn;
	request->id = id;

	/* parse optional parameters */
	initial_resp = NULL;
	valid_client_cert = FALSE;
	for (list += 2; *list != NULL; list++) {
		arg = strchr(*list, '=');
		if (arg == NULL) {
			name = *list;
			arg = "";
		} else {
			name = t_strdup_until(*list, arg);
			arg++;
		}

		if (strcmp(name, "lip") == 0)
			(void)net_addr2ip(arg, &request->local_ip);
		else if (strcmp(name, "rip") == 0)
			(void)net_addr2ip(arg, &request->remote_ip);
		else if (strcmp(name, "service") == 0)
			request->service = p_strdup(request->pool, arg);
		else if (strcmp(name, "resp") == 0)
			initial_resp = arg;
		else if (strcmp(name, "valid-client-cert") == 0)
			valid_client_cert = TRUE;
	}

	if (request->service == NULL)
		request->service = conn->default_service;
	if (request->service == NULL) {
		i_error("BUG: Authentication client %u "
			"didn't specify service in request", conn->pid);
		auth_request_destroy(request);
		return FALSE;
	}

	if (ssl_require_client_cert && !valid_client_cert) {
		/* we fail without valid certificate */
		if (verbose) {
			i_info("ssl-cert-check(%s): "
			       "Client didn't present valid SSL certificate",
			       get_log_prefix(request));
		}
		auth_request_destroy(request);
		auth_client_send(conn, "FAIL\t%u", id);
		return TRUE;
	}

	if (initial_resp == NULL) {
		initial_resp_data = NULL;
		initial_resp_len = 0;
	} else {
		size_t len = strlen(initial_resp);
		buf = buffer_create_dynamic(pool_datastack_create(),
					    MAX_BASE64_DECODED_SIZE(len));
		if (base64_decode(initial_resp, len, NULL, buf) < 0) {
			if (verbose) {
				i_info("%s(%s): Invalid base64 data in "
				       "initial response", mech->mech_name,
				       get_log_prefix(request));
			}
			auth_request_destroy(request);
			auth_client_send(conn, "FAIL\t%u\t"
				"reason=Invalid base64 data in initial "
				"response", id);
			return TRUE;
		}
		initial_resp_data = buf->data;
		initial_resp_len = buf->used;
	}

	/* connection is referenced only until auth_callback is called. */
	conn->refcount++;
	mech->auth_initial(request, initial_resp_data, initial_resp_len,
			   auth_callback);
	return TRUE;
}

static int
auth_client_input_cont(struct auth_client_connection *conn, const char *args)
{
	struct auth_request *request;
	const char *data;
	size_t data_len;
	buffer_t *buf;
	unsigned int id;

	data = strchr(args, '\t');
	if (data++ == NULL) {
		i_error("BUG: Authentication client %u "
			"sent broken CONT request", conn->pid);
		return FALSE;
	}

	id = (unsigned int)strtoul(args, NULL, 10);

	request = hash_lookup(conn->auth_requests, POINTER_CAST(id));
	if (request == NULL) {
		/* timeouted */
		auth_client_send(conn, "FAIL\t%u\treason=Timeouted", id);
		return TRUE;
	}

	if (!request->accept_input) {
		auth_client_send(conn, "FAIL\t%u"
				 "\treason=Unexpected continuation", id);
		auth_request_destroy(request);
		return TRUE;
	}
        request->accept_input = FALSE;

	data_len = strlen(data);
	buf = buffer_create_dynamic(pool_datastack_create(),
				    MAX_BASE64_DECODED_SIZE(data_len));
	if (base64_decode(data, data_len, NULL, buf) < 0) {
		if (verbose) {
			i_info("%s(%s): Invalid base64 data in "
			       "continued response", request->mech->mech_name,
			       get_log_prefix(request));
		}
		auth_client_send(conn, "FAIL\t%u\treason=Invalid base64 data "
				 "in continued response", id);
		auth_request_destroy(request);
		return TRUE;
	}

	conn->refcount++;
	request->mech->auth_continue(request, buf->data, buf->used,
				     auth_callback);
	return TRUE;
}

static void auth_client_input(void *context)
{
	struct auth_client_connection *conn = context;
	char *line;
	int ret;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_client_connection_destroy(conn);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth client %u sent us more than %d bytes",
			conn->pid, (int)AUTH_CLIENT_MAX_LINE_LENGTH);
		auth_client_connection_destroy_wait(conn);
		return;
	}

	if (!conn->version_received) {
		line = i_stream_next_line(conn->input);
		if (line == NULL)
			return;

		/* make sure the major version matches */
		if (strncmp(line, "VERSION\t", 8) != 0 ||
		    atoi(t_strcut(line + 8, '\t')) !=
		    AUTH_CLIENT_PROTOCOL_MAJOR_VERSION) {
			i_error("Authentication client %u "
				"not compatible with this server "
				"(mixed old and new binaries?)", conn->pid);
			auth_client_connection_destroy_wait(conn);
			return;
		}
		conn->version_received = TRUE;
	}

	conn->refcount++;
	while ((line = i_stream_next_line(conn->input)) != NULL) {
		t_push();
		if (strncmp(line, "AUTH\t", 5) == 0)
			ret = auth_client_input_auth(conn, line + 5);
		else if (strncmp(line, "CONT\t", 5) == 0)
			ret = auth_client_input_cont(conn, line + 5);
		else if (strncmp(line, "CPID\t", 5) == 0)
			ret = auth_client_input_cpid(conn, line + 5);
		else if (strncmp(line, "SERVICE\t", 6) == 0)
			ret = auth_client_input_service(conn, line + 6);
		else {
			/* ignore unknown command */
			ret = TRUE;
		}
		safe_memset(line, 0, strlen(line));
		t_pop();

		if (!ret) {
			auth_client_connection_destroy_wait(conn);
			break;
		}
	}
	auth_client_connection_unref(conn);
}

struct auth_client_connection *
auth_client_connection_create(struct auth_master_connection *master, int fd)
{
	static unsigned int connect_uid_counter = 0;
	struct auth_client_connection *conn;
	struct const_iovec iov[2];
	string_t *str;

	pool_t pool;

	pool = pool_alloconly_create("Auth client", 4096);
	conn = p_new(pool, struct auth_client_connection, 1);
	conn->pool = pool;
	conn->master = master;
	conn->refcount = 1;
	conn->connect_uid = ++connect_uid_counter;

	conn->fd = fd;
	conn->input = i_stream_create_file(fd, default_pool,
					   AUTH_CLIENT_MAX_LINE_LENGTH,
					   FALSE);
	conn->output = o_stream_create_file(fd, default_pool, MAX_OUTBUF_SIZE,
					    FALSE);
	conn->io = io_add(fd, IO_READ, auth_client_input, conn);

	conn->auth_requests = hash_create(default_pool, conn->pool,
					  0, NULL, NULL);

	conn->next = master->clients;
	master->clients = conn;

	str = t_str_new(128);
	str_printfa(str, "VERSION\t%u\t%u\nSPID\t%u\nCUID\t%u\nDONE\n",
                    AUTH_CLIENT_PROTOCOL_MAJOR_VERSION,
                    AUTH_CLIENT_PROTOCOL_MINOR_VERSION,
		    master->pid, conn->connect_uid);

	iov[0].iov_base = str_data(mech_handshake);
	iov[0].iov_len = str_len(mech_handshake);
	iov[1].iov_base = str_data(str);
	iov[1].iov_len = str_len(str);

	if (o_stream_sendv(conn->output, iov, 2) < 0) {
		auth_client_connection_destroy(conn);
		conn = NULL;
	}

	return conn;
}

void auth_client_connection_destroy(struct auth_client_connection *conn)
{
	struct auth_client_connection **pos;

	if (conn->fd == -1)
		return;

	for (pos = &conn->master->clients; *pos != NULL; pos = &(*pos)->next) {
		if (*pos == conn) {
			*pos = conn->next;
			break;
		}
	}

	i_stream_close(conn->input);
	o_stream_close(conn->output);

	if (conn->io != NULL) {
		io_remove(conn->io);
		conn->io = NULL;
	}

	net_disconnect(conn->fd);
	conn->fd = -1;

	conn->master = NULL;
        auth_client_connection_unref(conn);
}

static void
auth_client_connection_destroy_wait(struct auth_client_connection *conn)
{
        conn->delayed_destroy = TRUE;

	if (conn->io != NULL) {
		io_remove(conn->io);
		conn->io = NULL;
	}
}

static void auth_client_connection_unref(struct auth_client_connection *conn)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	if (--conn->refcount > 0)
		return;

	iter = hash_iterate_init(conn->auth_requests);
	while (hash_iterate(iter, &key, &value)) {
		struct auth_request *auth_request = value;

		auth_request->conn = NULL;
		auth_request_unref(auth_request);
	}
	hash_iterate_deinit(iter);
	hash_destroy(conn->auth_requests);

	i_stream_unref(conn->input);
	o_stream_unref(conn->output);

	pool_unref(conn->pool);
}

static void
auth_client_connection_check_timeouts(struct auth_client_connection *conn)
{
	struct hash_iterate_context *iter;
	void *key, *value;
	unsigned int secs;
	int destroy = FALSE;

	if (conn->delayed_destroy) {
		auth_client_connection_destroy(conn);
		return;
	}

	iter = hash_iterate_init(conn->auth_requests);
	while (hash_iterate(iter, &key, &value)) {
		struct auth_request *auth_request = value;

		if (auth_request->created + AUTH_REQUEST_TIMEOUT < ioloop_time) {
			secs = (unsigned int) (ioloop_time -
					       auth_request->created);
			i_warning("Login process has too old (%us) requests, "
				  "killing it.", secs);

			destroy = TRUE;
			break;
		}
	}
	hash_iterate_deinit(iter);

	if (destroy)
		auth_client_connection_destroy(conn);
}

static void request_timeout(void *context __attr_unused__)
{
        struct auth_master_connection *master = context;
	struct auth_client_connection *conn, *next;

	for (conn = master->clients; conn != NULL; conn = next) {
		next = conn->next;
		auth_client_connection_check_timeouts(conn);
	}
}

void auth_client_connections_init(struct auth_master_connection *master)
{
	master->to_clients = timeout_add(5000, request_timeout, master);
}

void auth_client_connections_deinit(struct auth_master_connection *master)
{
	struct auth_client_connection *next;

	while (master->clients != NULL) {
		next = master->clients->next;
		auth_client_connection_destroy(master->clients);
		master->clients = next;
	}

	timeout_remove(master->to_clients);
	master->to_clients = NULL;
}
