#ifndef IMAP_URLAUTH_PRIVATE_H
#define IMAP_URLAUTH_PRIVATE_H

#include "imap-urlauth.h"

struct imap_urlauth_context {
	struct mail_user *user;
	struct imap_urlauth_connection *conn;

	char *url_host;
	in_port_t url_port;

	char *access_user;
	const char **access_applications;

	bool access_anonymous:1;
};

#endif
