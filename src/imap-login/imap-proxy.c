/* Copyright (C) 2004 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "str.h"
#include "client.h"
#include "imap-quote.h"
#include "login-proxy.h"
#include "imap-proxy.h"

int imap_proxy_new(struct imap_client *client, const char *host,
		   unsigned int port, const char *user, const char *password)
{
	string_t *str;

	i_assert(user != NULL);

	if (password == NULL) {
		i_error("proxy(%s): password not given",
			client->common.virtual_user);
		return -1;
	}

	str = t_str_new(128);
	str_append(str, client->cmd_tag);
	str_append(str, " LOGIN ");
	imap_quote_append_string(str, user, FALSE);
	str_append_c(str, ' ');
	imap_quote_append_string(str, password, FALSE);
	str_append(str, "\r\n");

	if (login_proxy_new(&client->common, host, port, str_c(str)) < 0)
		return -1;

	if (client->io != NULL) {
		io_remove(client->io);
		client->io = NULL;
	}

	return 0;
}
