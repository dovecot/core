/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "base64.h"
#include "buffer.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "temp-string.h"
#include "auth-connection.h"
#include "client.h"
#include "client-authenticate.h"
#include "master.h"

typedef struct {
	int method;
	const char *name;
	int plaintext;
} AuthMethodDesc;

static AuthMethod auth_methods = 0;
static char *auth_methods_capability = NULL;

static AuthMethodDesc auth_method_desc[AUTH_METHODS_COUNT] = {
	{ AUTH_METHOD_PLAIN,		NULL,		TRUE },
	{ AUTH_METHOD_DIGEST_MD5,	"DIGEST-MD5",	FALSE }
};

const char *client_authenticate_get_capabilities(void)
{
	TempString *str;
	int i;

	if (auth_methods == available_auth_methods)
		return auth_methods_capability;

	auth_methods = available_auth_methods;
	i_free(auth_methods_capability);

	str = t_string_new(128);

	for (i = 0; i < AUTH_METHODS_COUNT; i++) {
		if ((auth_methods & auth_method_desc[i].method) &&
		    auth_method_desc[i].name != NULL) {
			t_string_append_c(str, ' ');
			t_string_append(str, "AUTH=");
			t_string_append(str, auth_method_desc[i].name);
		}
	}

	auth_methods_capability = str->len == 1 ? NULL :
		i_strdup_empty(str->str);
	return auth_methods_capability;
}

static AuthMethodDesc *auth_method_find(const char *name)
{
	int i;

	for (i = 0; i < AUTH_METHODS_COUNT; i++) {
		if (auth_method_desc[i].name != NULL &&
		    strcasecmp(auth_method_desc[i].name, name) == 0)
			return &auth_method_desc[i];
	}

	return NULL;
}

static void client_auth_abort(Client *client, const char *msg)
{
	client->auth_request = NULL;

	client_send_tagline(client, msg != NULL ? msg :
			    "NO Authentication failed.");
	o_stream_flush(client->output);

	/* get back to normal client input */
	if (client->io != NULL)
		io_remove(client->io);
	client->io = client->fd == -1 ? NULL :
		io_add(client->fd, IO_READ, client_input, client);

	client_unref(client);
}

static void master_callback(MasterReplyResult result, void *context)
{
	Client *client = context;

	switch (result) {
	case MASTER_RESULT_SUCCESS:
		client_destroy(client, "Logged in.");
		client_unref(client);
		break;
	case MASTER_RESULT_INTERNAL_FAILURE:
		client_auth_abort(client, "Internal failure");
		break;
	default:
		client_auth_abort(client, NULL);
		break;
	}
}

static void client_send_auth_data(Client *client, const unsigned char *data,
				  size_t size)
{
	Buffer *buf;

	t_push();

	buf = buffer_create_dynamic(data_stack_pool, size*2, (size_t)-1);
	buffer_append(buf, "+ ", 2);
	base64_encode(data, size, buf);
	buffer_append(buf, "\r\n", 2);

	o_stream_send(client->output, buffer_get_data(buf, NULL),
		      buffer_get_used_size(buf));
	o_stream_flush(client->output);

	t_pop();
}

static int auth_callback(AuthRequest *request, unsigned int auth_process,
			 AuthResult result, const unsigned char *reply_data,
			 size_t reply_data_size, void *context)
{
	Client *client = context;

	switch (result) {
	case AUTH_RESULT_CONTINUE:
		client->auth_request = request;
		return TRUE;

	case AUTH_RESULT_SUCCESS:
		client->auth_request = NULL;

		master_request_imap(client->fd, auth_process, client->tag,
				    request->cookie, &client->ip,
				    master_callback, client);

		/* disable IO until we're back from master */
		if (client->io != NULL) {
			io_remove(client->io);
			client->io = NULL;
		}
		return FALSE;

	case AUTH_RESULT_FAILURE:
		/* see if we have error message */
		if (reply_data_size > 0 &&
		    reply_data[reply_data_size-1] == '\0') {
			client_auth_abort(client, t_strconcat(
				"NO Authentication failed: ",
				(const char *) reply_data, NULL));
		} else {
			/* default error message */
			client_auth_abort(client, NULL);
		}
		return FALSE;
	default:
		client_auth_abort(client, t_strconcat(
			"NO Authentication failed: ", reply_data, NULL));
		return FALSE;
	}
}

static void login_callback(AuthRequest *request, unsigned int auth_process,
			   AuthResult result, const unsigned char *reply_data,
			   size_t reply_data_size, void *context)
{
	Client *client = context;
	const void *ptr;
	size_t size;

	if (auth_callback(request, auth_process, result,
			  reply_data, reply_data_size, context)) {
                ptr = buffer_get_data(client->plain_login, &size);
		auth_continue_request(request, ptr, size);

		buffer_set_used_size(client->plain_login, 0);
	}
}

int cmd_login(Client *client, const char *user, const char *pass)
{
	const char *error;

	if (!client->tls && disable_plaintext_auth) {
		client_send_tagline(client,
				    "NO Plaintext authentication disabled.");
		return TRUE;
	}

	/* code it into user\0user\0password */
	buffer_set_used_size(client->plain_login, 0);
	buffer_append(client->plain_login, user, strlen(user));
	buffer_append_c(client->plain_login, '\0');
	buffer_append(client->plain_login, user, strlen(user));
	buffer_append_c(client->plain_login, '\0');
	buffer_append(client->plain_login, pass, strlen(pass));

	client_ref(client);
	if (auth_init_request(AUTH_METHOD_PLAIN,
			      login_callback, client, &error)) {
		/* don't read any input from client until login is finished */
		if (client->io != NULL) {
			io_remove(client->io);
			client->io = NULL;
		}
		return TRUE;
	} else {
		client_send_tagline(client, t_strconcat(
			"NO Login failed: ", error, NULL));
		client_unref(client);
		return TRUE;
	}
}

static void authenticate_callback(AuthRequest *request,
				  unsigned int auth_process, AuthResult result,
				  const unsigned char *reply_data,
				  size_t reply_data_size, void *context)
{
	Client *client = context;

	if (auth_callback(request, auth_process, result,
			  reply_data, reply_data_size, context))
		client_send_auth_data(client, reply_data, reply_data_size);
}

static void client_auth_input(void *context, int fd __attr_unused__,
			      IO io __attr_unused__)
{
	Client *client = context;
	Buffer *buf;
	char *line;
	size_t linelen, bufsize;

	if (!client_read(client))
		return;

	line = i_stream_next_line(client->input);
	if (line == NULL)
		return;

	if (strcmp(line, "*") == 0) {
		client_auth_abort(client, "NO Authentication aborted");
		return;
	}

	linelen = strlen(line);
	buf = buffer_create_static_hard(data_stack_pool, linelen);

	if (base64_decode(line, linelen, NULL, buf) <= 0) {
		/* failed */
		client_auth_abort(client, "NO Invalid base64 data");
	} else if (client->auth_request == NULL) {
		client_auth_abort(client, "NO Don't send unrequested data");
	} else {
		auth_continue_request(client->auth_request,
				      buffer_get_data(buf, NULL),
				      buffer_get_used_size(buf));
	}

	/* clear sensitive data */
	safe_memset(line, 0, linelen);

	bufsize = buffer_get_used_size(buf);
	safe_memset(buffer_free_without_data(buf), 0, bufsize);
}

int cmd_authenticate(Client *client, const char *method_name)
{
	AuthMethodDesc *method;
	const char *error;

	if (*method_name == '\0')
		return FALSE;

	method = auth_method_find(method_name);
	if (method == NULL) {
		client_send_tagline(client,
				    "NO Unsupported authentication method.");
		return TRUE;
	}

	if (!client->tls && method->plaintext && disable_plaintext_auth) {
		client_send_tagline(client,
				    "NO Plaintext authentication disabled.");
		return TRUE;
	}

	client_ref(client);
	if (auth_init_request(method->method, authenticate_callback,
			      client, &error)) {
		/* following input data will go to authentication */
		if (client->io != NULL)
			io_remove(client->io);
		client->io = io_add(client->fd, IO_READ,
				    client_auth_input, client);
	} else {
		client_send_tagline(client, t_strconcat(
			"NO Authentication failed: ", error, NULL));
		client_unref(client);
	}

	return TRUE;
}
