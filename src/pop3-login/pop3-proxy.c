/* Copyright (C) 2004 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "base64.h"
#include "str.h"
#include "client.h"
#include "login-proxy.h"
#include "pop3-proxy.h"

int pop3_proxy_new(struct pop3_client *client, const char *host,
		   unsigned int port, const char *user, const char *password)
{
	string_t *auth, *str;

	i_assert(user != NULL);

	if (password == NULL) {
		i_error("proxy(%s): password not given",
			client->common.virtual_user);
		return -1;
	}

	auth = t_str_new(128);
	str_append_c(auth, '\0');
	str_append(auth, user);
	str_append_c(auth, '\0');
	str_append(auth, password);

	str = t_str_new(128);
	str_append(str, "AUTH ");
	base64_encode(str_data(auth), str_len(auth), str);
	str_append(str, "\r\n");

	if (login_proxy_new(&client->common, host, port, str_c(str)) < 0)
		return -1;

	if (client->io != NULL) {
		io_remove(client->io);
		client->io = NULL;
	}

	return 0;
}
