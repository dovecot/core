/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "client-common.h"
#include "auth-connection.h"
#include "auth-common.h"

static const char *auth_login_get_str(struct auth_login_reply *reply,
				      const unsigned char *data, size_t idx)
{
	size_t stop;

	if (idx >= reply->data_size || idx >= reply->reply_idx)
		return NULL;

	stop = reply->reply_idx < reply->data_size ?
		reply->reply_idx-1 : reply->data_size;

	return t_strndup(data + idx, stop);
}

int auth_callback(struct auth_request *request, struct auth_login_reply *reply,
		  const unsigned char *data, struct client *client,
		  master_callback_t *master_callback, const char **error)
{
	const char *user, *realm;

	*error = NULL;

	if (reply == NULL) {
		/* failed */
		if (client->auth_request != NULL) {
			auth_request_unref(client->auth_request);
			client->auth_request = NULL;
		}
		*error = "Authentication process died.";
		return -1;
	}

	switch (reply->result) {
	case AUTH_LOGIN_RESULT_CONTINUE:
		if (client->auth_request != NULL) {
			i_assert(client->auth_request == request);
		} else {
			i_assert(client->auth_request == NULL);

			client->auth_request = request;
			auth_request_ref(client->auth_request);
		}
		return 0;

	case AUTH_LOGIN_RESULT_SUCCESS:
                auth_request_unref(client->auth_request);
		client->auth_request = NULL;

		user = auth_login_get_str(reply, data, reply->username_idx);
		realm = auth_login_get_str(reply, data, reply->realm_idx);

		i_free(client->virtual_user);
		client->virtual_user = realm == NULL ?
			i_strdup(user) : i_strconcat(user, "@", realm, NULL);

		master_request_imap(client, master_callback,
				    request->conn->pid, request->id);

		/* disable IO until we're back from master */
		if (client->io != NULL) {
			io_remove(client->io);
			client->io = NULL;
		}
		return 1;

	case AUTH_LOGIN_RESULT_FAILURE:
		/* see if we have error message */
                auth_request_unref(client->auth_request);
		client->auth_request = NULL;

		if (reply->data_size > 0 && data[reply->data_size-1] == '\0') {
			*error = t_strconcat("Authentication failed: ",
					     (const char *) data, NULL);
		}
		return -1;
	}

	i_unreached();
}
