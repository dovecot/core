#ifndef SUBMISSION_BACKEND_RELAY_H
#define SUBMISSION_BACKEND_RELAY_H

#include "smtp-client-connection.h"

#include "submission-backend.h"

struct client;

struct submision_backend_relay_settings {
	const char *my_hostname;

	enum smtp_protocol protocol;
	const char *path, *host;
	in_port_t port;

	const char *user, *master_user;
	const char *password;

	enum smtp_client_connection_ssl_mode ssl_mode;

	const char *rawlog_dir;
	unsigned int max_idle_time;

	unsigned int connect_timeout_msecs;
	unsigned int command_timeout_msecs;

	bool ssl_verify:1;
	bool trusted:1;
};

struct submission_backend *
submission_backend_relay_create(
	struct client *client,
	const struct submision_backend_relay_settings *set);

#endif
