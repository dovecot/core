/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "base64.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "hex-binary.h"
#include "str.h"
#include "master-service.h"
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

	unsigned int version_received:1;
	unsigned int dbhash_received:1;
};

struct auth_worker_list_context {
	struct auth_worker_client *client;
	struct userdb_module *userdb;
	struct userdb_iterate_context *iter;
	unsigned int id;
	bool sending, sent, done;
};

struct auth_worker_client *auth_worker_client;

static void auth_worker_input(struct auth_worker_client *client);
static int auth_worker_output(struct auth_worker_client *client);

static void
auth_worker_client_check_throttle(struct auth_worker_client *client)
{
	if (o_stream_get_buffer_used_size(client->output) >=
	    OUTBUF_THROTTLE_SIZE) {
		/* stop reading new requests until client has read the pending
		   replies. */
		if (client->io != NULL)
			io_remove(&client->io);
	}
}

static struct auth_request *
worker_auth_request_new(struct auth_worker_client *client, unsigned int id,
			const char *const *args)
{
	struct auth_request *auth_request;
	const char *key, *value;

	auth_request = auth_request_new_dummy();

	client->refcount++;
	auth_request->context = client;
	auth_request->id = id;

	for (; *args != NULL; args++) {
		value = strchr(*args, '=');
		if (value != NULL) {
			key = t_strdup_until(*args, value++);
			(void)auth_request_import(auth_request, key, value);
		}
	}

	auth_request_init(auth_request);
	return auth_request;
}

static void auth_worker_send_reply(struct auth_worker_client *client,
				   string_t *str)
{
	if (shutdown_request)
		o_stream_send_str(client->output, "SHUTDOWN\n");
	o_stream_send(client->output, str_data(str), str_len(str));
}

static void verify_plain_callback(enum passdb_result result,
				  struct auth_request *request)
{
	struct auth_worker_client *client = request->context;
	struct auth_stream_reply *reply;
	string_t *str;

	if (request->passdb_failure && result == PASSDB_RESULT_OK)
		result = PASSDB_RESULT_PASSWORD_MISMATCH;

	reply = auth_stream_reply_init(pool_datastack_create());
	auth_stream_reply_add(reply, NULL, dec2str(request->id));

	if (result == PASSDB_RESULT_OK)
		auth_stream_reply_add(reply, "OK", NULL);
	else {
		auth_stream_reply_add(reply, "FAIL", NULL);
		auth_stream_reply_add(reply, NULL,
				      t_strdup_printf("%d", result));
	}
	if (result != PASSDB_RESULT_INTERNAL_FAILURE) {
		auth_stream_reply_add(reply, NULL, request->user);
		auth_stream_reply_add(reply, NULL,
				      request->passdb_password == NULL ? "" :
				      request->passdb_password);
		if (request->extra_fields != NULL) {
			const char *fields =
				auth_stream_reply_export(request->extra_fields);
			auth_stream_reply_import(reply, fields);
		}
		if (request->extra_cache_fields != NULL) {
			const char *fields =
				auth_stream_reply_export(request->extra_cache_fields);
			auth_stream_reply_import(reply, fields);
		}
	}
	str = auth_stream_reply_get_str(reply);
	str_append_c(str, '\n');
	auth_worker_send_reply(client, str);

	auth_request_unref(&request);
	auth_worker_client_check_throttle(client);
	auth_worker_client_unref(&client);
}

static bool
auth_worker_handle_passv(struct auth_worker_client *client,
			 unsigned int id, const char *const *args)
{
	/* verify plaintext password */
	struct auth_request *auth_request;
        struct auth_passdb *passdb;
	const char *password;
	unsigned int passdb_id;

	/* <passdb id> <password> [<args>] */
	if (str_to_uint(args[0], &passdb_id) < 0 || args[1] == NULL) {
		i_error("BUG: Auth worker server sent us invalid PASSV");
		return FALSE;
	}
	password = args[1];

	auth_request = worker_auth_request_new(client, id, args + 2);
	auth_request->mech_password =
		p_strdup(auth_request->pool, password);

	if (auth_request->user == NULL || auth_request->service == NULL) {
		i_error("BUG: PASSV had missing parameters");
		auth_request_unref(&auth_request);
		return FALSE;
	}

	passdb = auth_request->passdb;
	while (passdb != NULL && passdb->passdb->id != passdb_id)
		passdb = passdb->next;

	if (passdb == NULL) {
		/* could be a masterdb */
		passdb = auth_request_get_auth(auth_request)->masterdbs;
		while (passdb != NULL && passdb->passdb->id != passdb_id)
			passdb = passdb->next;

		if (passdb == NULL) {
			i_error("BUG: PASSV had invalid passdb ID");
			auth_request_unref(&auth_request);
			return FALSE;
		}
	}

	auth_request->passdb = passdb;
	passdb->passdb->iface.
		verify_plain(auth_request, password, verify_plain_callback);
	return TRUE;
}

static void
lookup_credentials_callback(enum passdb_result result,
			    const unsigned char *credentials, size_t size,
			    struct auth_request *request)
{
	struct auth_worker_client *client = request->context;
	struct auth_stream_reply *reply;
	string_t *str;

	if (request->passdb_failure && result == PASSDB_RESULT_OK)
		result = PASSDB_RESULT_PASSWORD_MISMATCH;

	reply = auth_stream_reply_init(pool_datastack_create());
	auth_stream_reply_add(reply, NULL, dec2str(request->id));

	if (result != PASSDB_RESULT_OK) {
		auth_stream_reply_add(reply, "FAIL", NULL);
		auth_stream_reply_add(reply, NULL,
				      t_strdup_printf("%d", result));
	} else {
		auth_stream_reply_add(reply, "OK", NULL);
		auth_stream_reply_add(reply, NULL, request->user);

		str = t_str_new(64);
		str_printfa(str, "{%s.b64}", request->credentials_scheme);
		base64_encode(credentials, size, str);
		auth_stream_reply_add(reply, NULL, str_c(str));

		if (request->extra_fields != NULL) {
			const char *fields =
				auth_stream_reply_export(request->extra_fields);
			auth_stream_reply_import(reply, fields);
		}
		if (request->extra_cache_fields != NULL) {
			const char *fields =
				auth_stream_reply_export(request->extra_cache_fields);
			auth_stream_reply_import(reply, fields);
		}
	}
	str = auth_stream_reply_get_str(reply);
	str_append_c(str, '\n');
	auth_worker_send_reply(client, str);

	auth_request_unref(&request);
	auth_worker_client_check_throttle(client);
	auth_worker_client_unref(&client);
}

static bool
auth_worker_handle_passl(struct auth_worker_client *client,
			 unsigned int id, const char *const *args)
{
	/* lookup credentials */
	struct auth_request *auth_request;
	const char *scheme;
	unsigned int passdb_id;

	/* <passdb id> <scheme> [<args>] */
	if (str_to_uint(args[0], &passdb_id) < 0 || args[1] == NULL) {
		i_error("BUG: Auth worker server sent us invalid PASSL");
		return FALSE;
	}
	scheme = args[1];

	auth_request = worker_auth_request_new(client, id, args + 2);
	auth_request->credentials_scheme = p_strdup(auth_request->pool, scheme);

	if (auth_request->user == NULL || auth_request->service == NULL) {
		i_error("BUG: PASSL had missing parameters");
		auth_request_unref(&auth_request);
		return FALSE;
	}

	while (auth_request->passdb->passdb->id != passdb_id) {
		auth_request->passdb = auth_request->passdb->next;
		if (auth_request->passdb == NULL) {
			i_error("BUG: PASSL had invalid passdb ID");
			auth_request_unref(&auth_request);
			return FALSE;
		}
	}

	if (auth_request->passdb->passdb->iface.lookup_credentials == NULL) {
		i_error("BUG: PASSL lookup not supported by given passdb");
		auth_request_unref(&auth_request);
		return FALSE;
	}

	auth_request->prefer_plain_credentials = TRUE;
	auth_request->passdb->passdb->iface.
		lookup_credentials(auth_request, lookup_credentials_callback);
	return TRUE;
}

static void
set_credentials_callback(bool success, struct auth_request *request)
{
	struct auth_worker_client *client = request->context;

	string_t *str;

	str = t_str_new(64);
	str_printfa(str, "%u\t%s\n", request->id, success ? "OK" : "FAIL");
	auth_worker_send_reply(client, str);

	auth_request_unref(&request);
	auth_worker_client_check_throttle(client);
	auth_worker_client_unref(&client);
}

static bool
auth_worker_handle_setcred(struct auth_worker_client *client,
			   unsigned int id, const char *const *args)
{
	struct auth_request *auth_request;
	unsigned int passdb_id;
	const char *creds;

	/* <passdb id> <credentials> [<args>] */
	if (str_to_uint(args[0], &passdb_id) < 0 || args[1] == NULL) {
		i_error("BUG: Auth worker server sent us invalid SETCRED");
		return FALSE;
	}
	creds = args[1];

	auth_request = worker_auth_request_new(client, id, args + 2);
	if (auth_request->user == NULL || auth_request->service == NULL) {
		i_error("BUG: SETCRED had missing parameters");
		auth_request_unref(&auth_request);
		return FALSE;
	}

	while (auth_request->passdb->passdb->id != passdb_id) {
		auth_request->passdb = auth_request->passdb->next;
		if (auth_request->passdb == NULL) {
			i_error("BUG: SETCRED had invalid passdb ID");
			auth_request_unref(&auth_request);
			return FALSE;
		}
	}

	auth_request->passdb->passdb->iface.
		set_credentials(auth_request, creds, set_credentials_callback);
	return TRUE;
}

static void
lookup_user_callback(enum userdb_result result,
		     struct auth_request *auth_request)
{
	struct auth_worker_client *client = auth_request->context;
	struct auth_stream_reply *reply = auth_request->userdb_reply;
	string_t *str;

	str = t_str_new(128);
	str_printfa(str, "%u\t", auth_request->id);
	switch (result) {
	case USERDB_RESULT_INTERNAL_FAILURE:
		str_append(str, "FAIL\t");
		break;
	case USERDB_RESULT_USER_UNKNOWN:
		str_append(str, "NOTFOUND\t");
		break;
	case USERDB_RESULT_OK:
		str_append(str, "OK\t");
		str_append(str, auth_stream_reply_export(reply));
		if (auth_request->userdb_lookup_failed)
			str_append(str, "\ttempfail");
		break;
	}
	str_append_c(str, '\n');

	auth_worker_send_reply(client, str);

	auth_request_unref(&auth_request);
	auth_worker_client_check_throttle(client);
	auth_worker_client_unref(&client);
}

static struct auth_userdb *
auth_userdb_find_by_id(struct auth_userdb *userdbs, unsigned int id)
{
	struct auth_userdb *db;

	for (db = userdbs; db != NULL; db = db->next) {
		if (db->userdb->id == id)
			return db;
	}
	return NULL;
}

static bool
auth_worker_handle_user(struct auth_worker_client *client,
			unsigned int id, const char *const *args)
{
	/* lookup user */
	struct auth_request *auth_request;
	unsigned int userdb_id;

	/* <userdb id> [<args>] */
	if (str_to_uint(args[0], &userdb_id) < 0) {
		i_error("BUG: Auth worker server sent us invalid USER");
		return FALSE;
	}

	auth_request = worker_auth_request_new(client, id, args + 1);
	if (auth_request->user == NULL || auth_request->service == NULL) {
		i_error("BUG: USER had missing parameters");
		auth_request_unref(&auth_request);
		return FALSE;
	}

	auth_request->userdb =
		auth_userdb_find_by_id(auth_request->userdb, userdb_id);
	if (auth_request->userdb == NULL) {
		i_error("BUG: USER had invalid userdb ID");
		auth_request_unref(&auth_request);
		return FALSE;
	}

	auth_request->userdb->userdb->iface->
		lookup(auth_request, lookup_user_callback);
	return TRUE;
}

static void list_iter_deinit(struct auth_worker_list_context *ctx)
{
	struct auth_worker_client *client = ctx->client;
	string_t *str;

	i_assert(client->io == NULL);

	str = t_str_new(32);
	if (ctx->userdb->iface->iterate_deinit(ctx->iter) < 0)
		str_printfa(str, "%u\tFAIL\n", ctx->id);
	else
		str_printfa(str, "%u\tOK\n", ctx->id);
	auth_worker_send_reply(client, str);

	client->io = io_add(client->fd, IO_READ, auth_worker_input, client);
	o_stream_set_flush_callback(client->output, auth_worker_output, client);
	auth_worker_client_unref(&client);
	i_free(ctx);
}

static void list_iter_callback(const char *user, void *context)
{
	struct auth_worker_list_context *ctx = context;
	string_t *str;

	if (user == NULL) {
		if (ctx->sending)
			ctx->done = TRUE;
		else
			list_iter_deinit(ctx);
		return;
	}

	T_BEGIN {
		str = t_str_new(128);
		str_printfa(str, "%u\t*\t%s\n", ctx->id, user);
		o_stream_send(ctx->client->output, str_data(str), str_len(str));
	} T_END;

	if (ctx->sending) {
		/* avoid recursively looping to this same function */
		ctx->sent = TRUE;
		return;
	}

	do {
		ctx->sending = TRUE;
		ctx->sent = FALSE;
		ctx->userdb->iface->iterate_next(ctx->iter);
	} while (ctx->sent &&
		 o_stream_get_buffer_used_size(ctx->client->output) == 0);
	ctx->sending = FALSE;
	if (ctx->done)
		list_iter_deinit(ctx);
}

static int auth_worker_list_output(struct auth_worker_list_context *ctx)
{
	int ret;

	if ((ret = o_stream_flush(ctx->client->output)) < 0) {
		list_iter_deinit(ctx);
		return 1;
	}
	if (ret > 0)
		ctx->userdb->iface->iterate_next(ctx->iter);
	return 1;
}

static bool
auth_worker_handle_list(struct auth_worker_client *client,
			unsigned int id, const char *const *args)
{
	struct auth_worker_list_context *ctx;
	struct auth_userdb *userdb;
	unsigned int userdb_id;

	if (str_to_uint(args[0], &userdb_id) < 0) {
		i_error("BUG: Auth worker server sent us invalid LIST");
		return FALSE;
	}

	userdb = auth_userdb_find_by_id(client->auth->userdbs, userdb_id);
	if (userdb == NULL) {
		i_error("BUG: LIST had invalid userdb ID");
		return FALSE;
	}

	ctx = i_new(struct auth_worker_list_context, 1);
	ctx->client = client;
	ctx->id = id;
	ctx->userdb = userdb->userdb;

	io_remove(&ctx->client->io);
	o_stream_set_flush_callback(ctx->client->output,
				    auth_worker_list_output, ctx);
	client->refcount++;
	ctx->iter = ctx->userdb->iface->
		iterate_init(userdb->userdb, list_iter_callback, ctx);
	ctx->userdb->iface->iterate_next(ctx->iter);
	return TRUE;
}

static bool
auth_worker_handle_line(struct auth_worker_client *client, const char *line)
{
	const char *const *args;
	unsigned int id;
	bool ret = FALSE;

	args = t_strsplit(line, "\t");
	if (args[0] == NULL || args[1] == NULL || args[2] == NULL ||
	    str_to_uint(args[0], &id) < 0) {
		i_error("BUG: Invalid input: %s", line);
		return FALSE;
	}

	if (strcmp(args[1], "PASSV") == 0)
		ret = auth_worker_handle_passv(client, id, args + 2);
	else if (strcmp(args[1], "PASSL") == 0)
		ret = auth_worker_handle_passl(client, id, args + 2);
	else if (strcmp(args[1], "SETCRED") == 0)
		ret = auth_worker_handle_setcred(client, id, args + 2);
	else if (strcmp(args[1], "USER") == 0)
		ret = auth_worker_handle_user(client, id, args + 2);
	else if (strcmp(args[1], "LIST") == 0)
		ret = auth_worker_handle_list(client, id, args + 2);
	else {
		i_error("BUG: Auth-worker received unknown command: %s",
			args[1]);
	}
        return ret;
}

static bool auth_worker_verify_db_hash(const char *line)
{
	string_t *str;
	unsigned char passdb_md5[MD5_RESULTLEN];
	unsigned char userdb_md5[MD5_RESULTLEN];

	passdbs_generate_md5(passdb_md5);
	userdbs_generate_md5(userdb_md5);

	str = t_str_new(128);
	str_append(str, "DBHASH\t");
	binary_to_hex_append(str, passdb_md5, sizeof(passdb_md5));
	str_append_c(str, '\t');
	binary_to_hex_append(str, userdb_md5, sizeof(userdb_md5));

	return strcmp(line, str_c(str)) == 0;
}

static void auth_worker_input(struct auth_worker_client *client)
{
	char *line;
	bool ret;

	switch (i_stream_read(client->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_worker_client_destroy(&client);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth worker server sent us more than %d bytes",
			(int)AUTH_WORKER_MAX_LINE_LENGTH);
		auth_worker_client_destroy(&client);
		return;
	}

	if (!client->version_received) {
		line = i_stream_next_line(client->input);
		if (line == NULL)
			return;

		if (!version_string_verify(line, "auth-worker",
				     AUTH_WORKER_PROTOCOL_MAJOR_VERSION)) {
			i_error("Auth worker not compatible with this server "
				"(mixed old and new binaries?)");
			auth_worker_client_destroy(&client);
			return;
		}
		client->version_received = TRUE;
	}
	if (!client->dbhash_received) {
		line = i_stream_next_line(client->input);
		if (line == NULL)
			return;

		if (!auth_worker_verify_db_hash(line)) {
			i_error("Auth worker sees different passdbs/userdbs "
				"than auth server. Maybe config just changed "
				"and this goes away automatically?");
			auth_worker_client_destroy(&client);
			return;
		}
		client->dbhash_received = TRUE;
	}

        client->refcount++;
	while ((line = i_stream_next_line(client->input)) != NULL) {
		T_BEGIN {
			ret = auth_worker_handle_line(client, line);
		} T_END;

		if (!ret) {
			struct auth_worker_client *client2 = client;
			auth_worker_client_destroy(&client2);
			break;
		}
	}
	auth_worker_client_unref(&client);
}

static int auth_worker_output(struct auth_worker_client *client)
{
	if (o_stream_flush(client->output) < 0) {
		auth_worker_client_destroy(&client);
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
	client->input = i_stream_create_fd(fd, AUTH_WORKER_MAX_LINE_LENGTH,
					   FALSE);
	client->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	o_stream_set_flush_callback(client->output, auth_worker_output, client);
	client->io = io_add(fd, IO_READ, auth_worker_input, client);

	auth_worker_client = client;
	return client;
}

void auth_worker_client_destroy(struct auth_worker_client **_client)
{
	struct auth_worker_client *client = *_client;

	*_client = NULL;
	if (client->fd == -1)
		return;

	i_stream_close(client->input);
	o_stream_close(client->output);

	if (client->io != NULL)
		io_remove(&client->io);

	net_disconnect(client->fd);
	client->fd = -1;
	auth_worker_client_unref(&client);

	auth_worker_client = NULL;
	master_service_client_connection_destroyed(master_service);
}

void auth_worker_client_unref(struct auth_worker_client **_client)
{
	struct auth_worker_client *client = *_client;

	*_client = NULL;

	if (--client->refcount > 0)
		return;

	i_stream_unref(&client->input);
	o_stream_unref(&client->output);
	i_free(client);
}
