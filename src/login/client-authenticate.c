/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "base64.h"
#include "iobuffer.h"
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
	t_string_append_c(str, ' ');

	for (i = 0; i < AUTH_METHODS_COUNT; i++) {
		if ((auth_methods & auth_method_desc[i].method) &&
		    auth_method_desc[i].name != NULL) {
			if (str->len > 0)
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

	/* get back to normal client input */
	if (client->io != NULL)
		io_remove(client->io);
	client->io = io_add(client->fd, IO_READ, client_input, client);

	client_unref(client);
}

static void master_callback(MasterReplyResult result, void *context)
{
	Client *client = context;

	switch (result) {
	case MASTER_RESULT_SUCCESS:
		client_destroy(client, "Logged in.");
		break;
	case MASTER_RESULT_INTERNAL_FAILURE:
		client_auth_abort(client, "Internal failure");
		break;
	default:
		client_auth_abort(client, NULL);
		break;
	}

	client_unref(client);
}

static void client_send_auth_data(Client *client, const unsigned char *data,
				  unsigned int size)
{
	const char *base64_data;

	t_push();

	base64_data = base64_encode(data, size);
	io_buffer_send(client->outbuf, "+ ", 2);
	io_buffer_send(client->outbuf, base64_data, strlen(base64_data));
	io_buffer_send(client->outbuf, "\r\n", 2);

	t_pop();
}

static int auth_callback(AuthRequest *request, int auth_process,
			 AuthResult result, const unsigned char *reply_data,
			 unsigned int reply_data_size, void *context)
{
	Client *client = context;

	switch (result) {
	case AUTH_RESULT_CONTINUE:
		client->auth_request = request;
		return TRUE;

	case AUTH_RESULT_SUCCESS:
		client->auth_request = NULL;

		master_request_imap(client->fd, auth_process, client->tag,
				    request->cookie, master_callback, client);

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
				(char *) reply_data, NULL));
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

static void login_callback(AuthRequest *request, int auth_process,
			   AuthResult result, const unsigned char *reply_data,
			   unsigned int reply_data_size, void *context)
{
	Client *client = context;

	if (auth_callback(request, auth_process, result,
			  reply_data, reply_data_size, context)) {
		auth_continue_request(request, client->plain_login,
				      client->plain_login_len);

		i_free(client->plain_login);
                client->plain_login = NULL;
	}
}

int cmd_login(Client *client, const char *user, const char *pass)
{
	const char *error;
	char *p;
	unsigned int len, user_len, pass_len;

	if (disable_plaintext_auth) {
		client_send_tagline(client,
				    "NO Plaintext authentication disabled.");
		return TRUE;
	}

	/* code it into user\0user\0password */
	user_len = strlen(user);
	pass_len = strlen(pass);
	len = user_len + 1 + user_len + 1 + pass_len;

	i_free(client->plain_login);
	client->plain_login = p = i_malloc(len);
	client->plain_login_len = len;

	memcpy(p, user, user_len); p += user_len; *p++ = '\0';
	memcpy(p, user, user_len); p += user_len; *p++ = '\0';
	memcpy(p, pass, pass_len);

	client_ref(client);
	if (auth_init_request(AUTH_METHOD_PLAIN,
			      login_callback, client, &error)) {
		/* don't read any input from client until login is finished */
		io_remove(client->io);
		client->io = NULL;
		return TRUE;
	} else {
		client_send_tagline(client, t_strconcat(
			"NO Login failed: ", error, NULL));
		client_unref(client);
		return TRUE;
	}
}

static void authenticate_callback(AuthRequest *request, int auth_process,
				  AuthResult result,
				  const unsigned char *reply_data,
				  unsigned int reply_data_size, void *context)
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
	char *line;
	int size;

	if (!client_read(client))
		return;

	line = io_buffer_next_line(client->inbuf);
	if (line == NULL)
		return;

	if (strcmp(line, "*") == 0) {
		client_auth_abort(client, "NO Authentication aborted");
		return;
	}

	size = base64_decode(line);
	if (size < 0) {
		/* failed */
		client_auth_abort(client, "NO Invalid base64 data");
		return;
	}

	if (client->auth_request == NULL) {
		client_auth_abort(client, "NO Don't send unrequested data");
		return;
	}

	auth_continue_request(client->auth_request, (unsigned char *) line,
			      (unsigned int) size);
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

	if (method->plaintext && disable_plaintext_auth) {
		client_send_tagline(client,
				    "NO Plaintext authentication disabled.");
		return TRUE;
	}

	client_ref(client);
	if (auth_init_request(method->method, authenticate_callback,
			      client, &error)) {
		/* following input data will go to authentication */
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

