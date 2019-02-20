#ifndef SUBMISSION_BACKEND_RELAY_H
#define SUBMISSION_BACKEND_RELAY_H

#include "smtp-client-connection.h"
#include "smtp-client-transaction.h"

#include "submission-backend.h"

struct client;
struct submission_backend_relay;

struct submision_backend_relay_settings {
	const char *my_hostname;

	enum smtp_protocol protocol;
	const char *path, *host;
	in_port_t port;

	const char *const *extra_capabilities;

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

struct submission_backend_relay *
submission_backend_relay_create(
	struct client *client,
	const struct submision_backend_relay_settings *set);

/* Returns the base backend object for this relay backend */
struct submission_backend *
submission_backend_relay_get(struct submission_backend_relay *backend)
	ATTR_PURE;

/* Returns the client connection for this relay backend */
struct smtp_client_connection *
submission_backend_relay_get_connection(
	struct submission_backend_relay *backend) ATTR_PURE;
/* Returns the current client transaction for this relay backend */
struct smtp_client_transaction *
submission_backend_relay_get_transaction(
	struct submission_backend_relay *backend) ATTR_PURE;

/* Initializes the client transaction manually, which allows providing
   alternative transaction flags. */
struct smtp_client_transaction *
submission_backend_relay_init_transaction(
	struct submission_backend_relay *backend,
	enum smtp_client_transaction_flags flags);

#endif
