#ifndef __AUTH_COMMON_H
#define __AUTH_COMMON_H

int auth_callback(struct auth_request *request, struct auth_login_reply *reply,
		  const unsigned char *data, struct client *client,
		  master_callback_t *master_callback, const char **error);

#endif

