/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "client-common.h"
#include "auth-client.h"
#include "auth-common.h"

static const char *auth_client_get_str(struct auth_client_request_reply *reply,
				       const unsigned char *data, size_t idx)
{
	size_t stop;

	if (idx >= reply->data_size || idx >= reply->reply_idx)
		return NULL;

	stop = reply->reply_idx < reply->data_size ?
		reply->reply_idx-1 : reply->data_size;

	return t_strndup(data + idx, stop);
}

int auth_callback(struct auth_request *request,
		  struct auth_client_request_reply *reply,
		  const unsigned char *data, struct client *client,
		  master_callback_t *master_callback, const char **error_r)
{
	const char *user;

	*error_r = NULL;

	if (reply == NULL) {
		/* failed */
		client->auth_request = NULL;
		*error_r = "Authentication process died.";
		return -1;
	}

	switch (reply->result) {
	case AUTH_CLIENT_RESULT_CONTINUE:
		if (client->auth_request != NULL) {
			i_assert(client->auth_request == request);
		} else {
			i_assert(client->auth_request == NULL);

			client->auth_request = request;
		}
		return 0;

	case AUTH_CLIENT_RESULT_SUCCESS:
		client->auth_request = NULL;

		user = auth_client_get_str(reply, data, reply->username_idx);

		i_free(client->virtual_user);
		client->virtual_user = i_strdup(user);

		master_request_login(client, master_callback,
			auth_client_request_get_server_pid(request),
			auth_client_request_get_id(request));

		/* disable IO until we're back from master */
		if (client->io != NULL) {
			io_remove(client->io);
			client->io = NULL;
		}
		return 1;

	case AUTH_CLIENT_RESULT_FAILURE:
		/* see if we have error message */
		client->auth_request = NULL;

		if (reply->data_size > 0 && data[reply->data_size-1] == '\0') {
			*error_r = t_strconcat("Authentication failed: ",
					       (const char *) data, NULL);
		}
		return -1;
	}

	i_unreached();
}
